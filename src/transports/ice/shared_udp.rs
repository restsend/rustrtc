//! Process-wide shared ICE UDP socket for single-port multiplexing.
//!
//! When `ice_udp_mux` is enabled and `ice_udp_mux_port` is set, multiple
//! PeerConnections share a single `UdpSocket` bound to that port. Incoming UDP
//! packets are demultiplexed in one of two ways:
//!
//! 1. **STUN Binding Request**: the destination server ufrag is extracted from
//!    the `USERNAME` attribute (`peer-ufrag:own-ufrag`). The peer's source
//!    address is recorded so that subsequent non-STUN packets can be routed.
//! 2. **Non-STUN packets** (DTLS/SRTP) and STUN responses: routed by the
//!    previously recorded remote source address. Outbound sends through a
//!    [`SharedUdpHandle`] also record their destination so that replies to
//!    locally-initiated checks (e.g. a controlled agent's STUN binding request)
//!    route back correctly.
//!
//! This mirrors [`super::shared_tcp`] for the UDP case.

use crate::prelude::*;
use crate::errors::{RtcError, RtcResult};
use crate::platform::sync::Mutex;
use alloc::collections::BTreeMap;
use core::net::SocketAddr;
use crate::platform::atomic64::AtomicU64;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::platform::sync::OnceLock;
use alloc::sync::Arc;
use core::time::Duration;
#[cfg(feature = "std")]
use crate::platform::net::tokio_impl;
use crate::platform::net::UdpSocket;
use crate::platform::sync::mpsc;
use tracing::{debug, trace};

/// Per-session incoming packet (bytes + source address).
pub(crate) type SharedUdpPacket = (Vec<u8>, SocketAddr);

/// Per-session demux channel depth. Bounded so that a slow or stalled session
/// cannot grow memory without bound under packet pressure (mirrors the OS
/// socket-buffer backpressure of a non-mux UDP socket). When full, new packets
/// are dropped (UDP semantics). Kept modest because one channel exists per
/// registered session on a shared mux port, so this is the dominant per-session
/// memory cost in single-port SFU deployments.
const SHARED_UDP_CHANNEL_CAPACITY: usize = 512;

/// Shared `peer_addr -> ufrag` routing table (cloned into every handle).
type PeerMap = Arc<Mutex<BTreeMap<SocketAddr, String>>>;

static SHARED_PORTS: OnceLock<Mutex<BTreeMap<SocketAddr, Arc<SharedUdpPort>>>> = OnceLock::new();

fn registry() -> &'static Mutex<BTreeMap<SocketAddr, Arc<SharedUdpPort>>> {
    SHARED_PORTS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

struct Session {
    tx: mpsc::Sender<SharedUdpPacket>,
}

struct SharedUdpPort {
    socket: Arc<dyn UdpSocket>,
    /// ufrag -> session channel
    sessions: Mutex<BTreeMap<String, Session>>,
    /// remote peer source addr -> ufrag (routing for non-STUN packets)
    peers: PeerMap,
    ref_count: AtomicUsize,
    shutting_down: AtomicBool,
    /// Packets dropped because a session's channel was full (backpressure).
    dropped_full: AtomicU64,
}

impl SharedUdpPort {
    fn new(socket: Arc<dyn UdpSocket>) -> Self {
        Self {
            socket,
            sessions: Mutex::new(BTreeMap::new()),
            peers: Arc::new(Mutex::new(BTreeMap::new())),
            ref_count: AtomicUsize::new(0),
            shutting_down: AtomicBool::new(false),
            dropped_full: AtomicU64::new(0),
        }
    }

    fn spawn_recv_loop(self: &Arc<Self>) {
        let port = Arc::clone(self);
        crate::platform::task::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                if port.shutting_down.load(Ordering::Relaxed) {
                    break;
                }
                // shutdown arm first each wake (matches the old `biased;`)
                let which = {
                    let mut shutdown_fut = core::pin::pin!(port.shutdown_signal());
                    let mut recv_fut = core::pin::pin!(port.socket.recv_from(&mut buf));
                    crate::platform::select::select2(&mut shutdown_fut, &mut recv_fut).await
                };
                match which {
                    crate::platform::select::Either::A(()) => break,
                    crate::platform::select::Either::B(res) => {
                        match res {
                            Ok((len, peer_addr)) => {
                                if len == 0 {
                                    continue;
                                }
                                port.dispatch(&buf[..len], peer_addr);
                            }
                            Err(e) => {
                                if port.shutting_down.load(Ordering::Relaxed) {
                                    break;
                                }
                                debug!("shared UDP recv error: {}", e);
                                crate::platform::task::sleep(Duration::from_millis(50)).await;
                            }
                        }
                    }
                }
            }
            debug!("shared UDP recv loop exited");
        });
    }

    /// A future that resolves when the port has been requested to shut down.
    async fn shutdown_signal(&self) {
        // Poll the shutting_down flag at a low frequency. The recv_from above
        // is the primary select arm; this just ensures we eventually notice a
        // shutdown request without blocking the recv forever.
        loop {
            if self.shutting_down.load(Ordering::Relaxed) {
                return;
            }
            crate::platform::task::sleep(Duration::from_millis(250)).await;
        }
    }

    fn dispatch(&self, packet: &[u8], peer_addr: SocketAddr) {
        let target_ufrag = if packet[0] < 2 {
            peer_ufrag_from_binding_request(packet)
        } else {
            None
        };

        let ufrag = if let Some(u) = target_ufrag {
            // Record/refresh peer routing so subsequent non-STUN packets
            // from this source reach the right session.
            self.peers.lock().insert(peer_addr, u.clone());
            Some(u)
        } else {
            self.peers.lock().get(&peer_addr).cloned()
        };

        let Some(ufrag) = ufrag else {
            trace!(
                "shared UDP: no session for peer {} (len={}, first_byte={})",
                peer_addr,
                packet.len(),
                packet[0]
            );
            return;
        };

        let tx = {
            let sessions = self.sessions.lock();
            sessions.get(&ufrag).map(|s| s.tx.clone())
        };

        if let Some(tx) = tx {
            match tx.try_send((packet.to_vec(), peer_addr)) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_)) => {
                    // Backpressure: the session's read loop is draining slower
                    // than packets arrive. Drop the newest packet (UDP semantics)
                    // and count it so operators can spot sustained overload.
                    let prev = self.dropped_full.fetch_add(1, Ordering::Relaxed);
                    if prev.is_multiple_of(1024) {
                        debug!(
                            "shared UDP: session {} channel full — dropped packet from {} \
                             (total dropped so far: {})",
                            ufrag,
                            peer_addr,
                            prev + 1
                        );
                    }
                }
                Err(mpsc::TrySendError::Closed(_)) => {
                    // Receiver dropped; the registration cleanup will follow.
                    trace!(
                        "shared UDP: session {} channel closed while forwarding packet from {}",
                        ufrag, peer_addr
                    );
                }
            }
        }
    }
}

/// Send/receive handle for one session on a shared UDP socket.
///
/// Cloning is cheap (Arc internally). The handle records outbound destinations
/// into the shared peer-routing table so that replies to locally-initiated
/// traffic (e.g. a controlled agent's STUN connectivity check) are routed back
/// to this session even though they carry no ufrag.
pub struct SharedUdpHandle {
    socket: Arc<dyn UdpSocket>,
    /// Incoming packets from the demux loop. `tokio::sync::Mutex` (not
    /// parking_lot) because the guard is held across `recv().await`. The
    /// underlying channel is bounded (`SHARED_UDP_CHANNEL_CAPACITY`).
    rx: Arc<crate::platform::sync::AsyncMutex<mpsc::Receiver<SharedUdpPacket>>>,
    peers: PeerMap,
    ufrag: String,
}

impl core::fmt::Debug for SharedUdpHandle {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedUdpHandle")
            .field("ufrag", &self.ufrag)
            .field(
                "local_addr",
                &self
                    .socket
                    .local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into()),
            )
            .finish_non_exhaustive()
    }
}

impl SharedUdpHandle {
    pub fn local_addr(&self) -> RtcResult<SocketAddr> {
        self.socket.local_addr().map_err(|e| RtcError::Internal(alloc::format!("{e}")))
    }

    pub fn socket(&self) -> &Arc<dyn UdpSocket> {
        &self.socket
    }

    /// Record `dest` as a peer belonging to this session (no send). Used by the
    /// synchronous fast-path, which writes through [`Self::socket`] directly and
    /// still needs reverse routing for the peer's replies.
    pub(crate) fn register_peer(&self, dest: SocketAddr) {
        self.peers.lock().insert(dest, self.ufrag.clone());
    }

    /// Record `dest` as a peer belonging to this session, then send.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> RtcResult<usize> {
        self.register_peer(dest);
        self.socket.send_to(data, dest).await.map_err(RtcError::from)
    }

    /// Receive the next demuxed packet for this session.
    pub async fn recv(&self) -> Option<SharedUdpPacket> {
        self.rx.lock().await.recv().await
    }
}

/// Keeps a PeerConnection registered on a shared UDP socket until dropped.
pub(crate) struct SharedUdpRegistration {
    port: Arc<SharedUdpPort>,
    listen_key: SocketAddr,
    ufrag: String,
}

impl SharedUdpRegistration {
    /// The `bind_addr` this registration lives on (the shared mux socket key).
    pub(crate) fn listen_key(&self) -> SocketAddr {
        self.listen_key
    }
}

impl core::fmt::Debug for SharedUdpRegistration {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SharedUdpRegistration")
            .field("listen_key", &self.listen_key)
            .field("ufrag", &self.ufrag)
            .finish_non_exhaustive()
    }
}

impl Drop for SharedUdpRegistration {
    fn drop(&mut self) {
        // Remove this session and any peer routing entries pointing at it.
        self.port.sessions.lock().remove(&self.ufrag);
        self.port
            .peers
            .lock()
            .retain(|_, ufrag| ufrag != &self.ufrag);
        let prev = self.port.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            self.port.shutting_down.store(true, Ordering::SeqCst);
            registry().lock().remove(&self.listen_key);
        }
    }
}

/// Bind or join the shared UDP socket at `bind_addr` and register `local_ufrag`.
///
/// Returns the bound local address, a send/receive [`SharedUdpHandle`], and an
/// RAII registration guard that deregisters on drop.
pub(crate) async fn acquire(
    bind_addr: SocketAddr,
    local_ufrag: String,
) -> RtcResult<(SocketAddr, SharedUdpHandle, SharedUdpRegistration)> {
    let maybe_existing = registry().lock().get(&bind_addr).cloned();
    let port = if let Some(existing) = maybe_existing {
        existing
    } else {
        // std: bind a real mux socket; no_std (WP3): the embedder injects a
        // Platform socket adapter — `acquire` is std-gated until then.
        #[cfg(feature = "std")]
        let socket: Arc<dyn UdpSocket> = {
            let sock = tokio::net::UdpSocket::bind(bind_addr)
                .await
                .map_err(|e| {
                    RtcError::Internal(format!("bind shared UDP socket {bind_addr}: {e}"))
                })?;
            Arc::new(tokio_impl::TokioUdpSocket::new(sock))
        };
        #[cfg(not(feature = "std"))]
        let socket: Arc<dyn UdpSocket> = unimplemented!(
            "no_std: pass an adapter implementing platform::net::UdpSocket (WP3)"
        );
        let port = Arc::new(SharedUdpPort::new(socket));
        let mut reg = registry().lock();
        if let Some(existing) = reg.get(&bind_addr) {
            existing.clone()
        } else {
            reg.insert(bind_addr, port.clone());
            port.spawn_recv_loop();
            port
        }
    };

    let local_addr = port
        .socket
        .local_addr()
        .map_err(|e| RtcError::Internal(format!("{}: {e}", "shared UDP socket local_addr")))?;

    // Reject a duplicate ufrag registration on the same shared socket — each
    // PeerConnection must own a unique ufrag so demuxing is unambiguous.
    if port.sessions.lock().contains_key(&local_ufrag) {
        return Err(RtcError::Internal(format!("ufrag {local_ufrag} already registered on shared UDP socket {bind_addr}")));
    }

    let (tx, rx) = mpsc::channel(SHARED_UDP_CHANNEL_CAPACITY);
    port.ref_count.fetch_add(1, Ordering::SeqCst);
    port.sessions
        .lock()
        .insert(local_ufrag.clone(), Session { tx });

    let handle = SharedUdpHandle {
        socket: port.socket.clone(),
        rx: Arc::new(crate::platform::sync::AsyncMutex::new(rx)),
        peers: port.peers.clone(),
        ufrag: local_ufrag.clone(),
    };

    if local_addr.ip().is_unspecified() {
        // Sanity log; the gatherer will rewrite the advertised candidate IP.
        trace!("shared UDP socket bound on wildcard: {}", local_addr);
    }

    Ok((
        local_addr,
        handle,
        SharedUdpRegistration {
            port,
            listen_key: bind_addr,
            ufrag: local_ufrag,
        },
    ))
}

/// Test helper: return the number of sessions currently registered on a shared
/// socket bound at `bind_addr` (0 if none).
#[cfg(test)]
pub(crate) fn session_count(bind_addr: SocketAddr) -> usize {
    registry()
        .lock()
        .get(&bind_addr)
        .map(|p| p.sessions.lock().len())
        .unwrap_or(0)
}

/// Look up the local ufrag registered for a given remote peer addr on a shared
/// socket. Used by tests to verify routing table state.
#[cfg(test)]
pub(crate) fn ufrag_for_peer(bind_addr: SocketAddr, peer_addr: SocketAddr) -> Option<String> {
    registry()
        .lock()
        .get(&bind_addr)?
        .peers
        .lock()
        .get(&peer_addr)
        .cloned()
}

pub(crate) fn peer_ufrag_from_binding_request(data: &[u8]) -> Option<String> {
    // Cheap header classification (Binding method + Request class) instead of a
    // full attribute decode — this runs on every STUN packet in the mux path.
    if data.len() < 20 {
        return None;
    }
    let msg_type = u16::from_be_bytes([data[0], data[1]]);
    let is_binding = (msg_type & 0x3EEF) == 0x0001;
    let is_request = (msg_type & 0x0110) == 0x0000;
    if !is_binding || !is_request {
        return None;
    }
    let username = username_from_stun_bytes(data)?;
    let (peer, _own) = username.split_once(':')?;
    Some(peer.to_string())
}

pub(crate) fn username_from_stun_bytes(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 20 {
        return None;
    }
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if length + 20 != bytes.len() {
        return None;
    }
    let mut offset = 20;
    while offset + 4 <= bytes.len() {
        let typ = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        offset += 4;
        if offset + len > bytes.len() {
            break;
        }
        if typ == 0x0006 {
            let value = &bytes[offset..offset + len];
            return core::str::from_utf8(value).ok().map(str::to_string);
        }
        offset += len;
        offset += (4 - (len % 4)) % 4;
    }
    None
}
