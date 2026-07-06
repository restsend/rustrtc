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

use super::shared_tcp::peer_ufrag_from_binding_request;
use anyhow::{Context, Result, bail};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, trace};

/// Per-session incoming packet (bytes + source address).
pub(crate) type SharedUdpPacket = (Vec<u8>, SocketAddr);

/// Per-session demux channel depth. Bounded so that a slow or stalled session
/// cannot grow memory without bound under packet pressure (mirrors the OS
/// socket-buffer backpressure of a non-mux UDP socket). When full, new packets
/// are dropped (UDP semantics).
const SHARED_UDP_CHANNEL_CAPACITY: usize = 2048;

/// Shared `peer_addr -> ufrag` routing table (cloned into every handle).
type PeerMap = Arc<Mutex<HashMap<SocketAddr, String>>>;

static SHARED_PORTS: OnceLock<Mutex<HashMap<SocketAddr, Arc<SharedUdpPort>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<SocketAddr, Arc<SharedUdpPort>>> {
    SHARED_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct Session {
    tx: mpsc::Sender<SharedUdpPacket>,
}

struct SharedUdpPort {
    socket: Arc<UdpSocket>,
    /// ufrag -> session channel
    sessions: Mutex<HashMap<String, Session>>,
    /// remote peer source addr -> ufrag (routing for non-STUN packets)
    peers: PeerMap,
    ref_count: AtomicUsize,
    shutting_down: AtomicBool,
    /// Packets dropped because a session's channel was full (backpressure).
    dropped_full: AtomicU64,
}

impl SharedUdpPort {
    fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            sessions: Mutex::new(HashMap::new()),
            peers: Arc::new(Mutex::new(HashMap::new())),
            ref_count: AtomicUsize::new(0),
            shutting_down: AtomicBool::new(false),
            dropped_full: AtomicU64::new(0),
        }
    }

    fn spawn_recv_loop(self: &Arc<Self>) {
        let port = Arc::clone(self);
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                if port.shutting_down.load(Ordering::Relaxed) {
                    break;
                }
                let recv = port.socket.recv_from(&mut buf);
                tokio::select! {
                    biased;
                    _ = port.shutdown_signal() => break,
                    res = recv => {
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
                                tokio::time::sleep(Duration::from_millis(50)).await;
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
            tokio::time::sleep(Duration::from_millis(250)).await;
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
                Err(mpsc::error::TrySendError::Full(_)) => {
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
                Err(mpsc::error::TrySendError::Closed(_)) => {
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
    socket: Arc<UdpSocket>,
    /// Incoming packets from the demux loop. `tokio::sync::Mutex` (not
    /// parking_lot) because the guard is held across `recv().await`. The
    /// underlying channel is bounded (`SHARED_UDP_CHANNEL_CAPACITY`).
    rx: Arc<tokio::sync::Mutex<mpsc::Receiver<SharedUdpPacket>>>,
    peers: PeerMap,
    ufrag: String,
}

impl std::fmt::Debug for SharedUdpHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    pub fn socket(&self) -> &Arc<UdpSocket> {
        &self.socket
    }

    /// Record `dest` as a peer belonging to this session, then send.
    pub async fn send_to(&self, data: &[u8], dest: SocketAddr) -> std::io::Result<usize> {
        self.peers.lock().insert(dest, self.ufrag.clone());
        self.socket.send_to(data, dest).await
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

impl std::fmt::Debug for SharedUdpRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
) -> Result<(SocketAddr, SharedUdpHandle, SharedUdpRegistration)> {
    let maybe_existing = registry().lock().get(&bind_addr).cloned();
    let port = if let Some(existing) = maybe_existing {
        existing
    } else {
        let socket = UdpSocket::bind(bind_addr)
            .await
            .with_context(|| format!("bind shared UDP socket {bind_addr}"))?;
        let socket = Arc::new(socket);
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
        .context("shared UDP socket local_addr")?;

    // Reject a duplicate ufrag registration on the same shared socket — each
    // PeerConnection must own a unique ufrag so demuxing is unambiguous.
    if port.sessions.lock().contains_key(&local_ufrag) {
        bail!("ufrag {local_ufrag} already registered on shared UDP socket {bind_addr}");
    }

    let (tx, rx) = mpsc::channel(SHARED_UDP_CHANNEL_CAPACITY);
    port.ref_count.fetch_add(1, Ordering::SeqCst);
    port.sessions
        .lock()
        .insert(local_ufrag.clone(), Session { tx });

    let handle = SharedUdpHandle {
        socket: port.socket.clone(),
        rx: Arc::new(tokio::sync::Mutex::new(rx)),
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
