//! Process-wide shared passive TCP listeners for single-port WHEP answerer mode.
//!
//! When `tcp_port_range_start == tcp_port_range_end`, multiple PeerConnections can
//! register on the same listen socket. Incoming connections are demuxed by the
//! server ufrag in the first STUN Binding request USERNAME attribute.

use super::{IceTransportInner, MAX_STUN_MESSAGE, attach_demuxed_tcp_stream};
use crate::transports::ice::stun::{StunClass, StunMessage, StunMethod};
use anyhow::{Context, Result, anyhow, bail};
use parking_lot::Mutex;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, Weak};
use tokio::io::AsyncReadExt;
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

static SHARED_PORTS: OnceLock<Mutex<HashMap<SocketAddr, Arc<SharedTcpPort>>>> = OnceLock::new();

fn registry() -> &'static Mutex<HashMap<SocketAddr, Arc<SharedTcpPort>>> {
    SHARED_PORTS.get_or_init(|| Mutex::new(HashMap::new()))
}

struct SharedTcpPort {
    listener: Arc<TcpListener>,
    sessions: Mutex<HashMap<String, Weak<IceTransportInner>>>,
    ref_count: AtomicUsize,
    shutting_down: AtomicBool,
}

impl SharedTcpPort {
    fn new(listener: Arc<TcpListener>) -> Self {
        Self {
            listener,
            sessions: Mutex::new(HashMap::new()),
            ref_count: AtomicUsize::new(0),
            shutting_down: AtomicBool::new(false),
        }
    }

    fn spawn_accept_loop(self: &Arc<Self>) {
        let port = Arc::clone(self);
        let listener = Arc::clone(&self.listener);
        tokio::spawn(async move {
            loop {
                if port.shutting_down.load(Ordering::Relaxed) {
                    break;
                }
                let accept = listener.accept().await;
                match accept {
                    Ok((stream, peer)) => {
                        let port = Arc::clone(&port);
                        tokio::spawn(async move {
                            if let Err(e) = dispatch_incoming(stream, peer, port).await {
                                debug!("shared TCP demux failed from {}: {}", peer, e);
                            }
                        });
                    }
                    Err(e) => {
                        if port.shutting_down.load(Ordering::Relaxed) {
                            break;
                        }
                        debug!("shared TCP accept error: {}", e);
                        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    }
                }
            }
        });
    }
}

/// Keeps a PeerConnection registered on a shared passive TCP port until dropped.
pub(crate) struct SharedTcpRegistration {
    port: Arc<SharedTcpPort>,
    listen_key: SocketAddr,
    ufrag: String,
}

impl std::fmt::Debug for SharedTcpRegistration {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedTcpRegistration")
            .field("listen_key", &self.listen_key)
            .field("ufrag", &self.ufrag)
            .finish_non_exhaustive()
    }
}

impl Drop for SharedTcpRegistration {
    fn drop(&mut self) {
        self.port.sessions.lock().remove(&self.ufrag);
        let prev = self.port.ref_count.fetch_sub(1, Ordering::SeqCst);
        if prev == 1 {
            self.port.shutting_down.store(true, Ordering::SeqCst);
            registry().lock().remove(&self.listen_key);
        }
    }
}

/// Bind or join the shared listener at `bind_addr` and register `local_ufrag`.
pub(crate) async fn acquire(
    bind_addr: SocketAddr,
    local_ufrag: String,
    inner: Weak<IceTransportInner>,
) -> Result<(SocketAddr, SharedTcpRegistration)> {
    let maybe_existing = registry().lock().get(&bind_addr).cloned();
    let port = if let Some(existing) = maybe_existing {
        existing
    } else {
        let listener = TcpListener::bind(bind_addr)
            .await
            .with_context(|| format!("bind shared TCP listener {bind_addr}"))?;
        let listener = Arc::new(listener);
        let port = Arc::new(SharedTcpPort::new(listener));

        let mut reg = registry().lock();
        if let Some(existing) = reg.get(&bind_addr) {
            existing.clone()
        } else {
            reg.insert(bind_addr, port.clone());
            port.spawn_accept_loop();
            port
        }
    };

    port.ref_count.fetch_add(1, Ordering::SeqCst);
    port.sessions.lock().insert(local_ufrag.clone(), inner);

    let local_addr = port
        .listener
        .local_addr()
        .context("shared TCP listener local_addr")?;

    Ok((
        local_addr,
        SharedTcpRegistration {
            port,
            listen_key: bind_addr,
            ufrag: local_ufrag,
        },
    ))
}

async fn dispatch_incoming(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    port: Arc<SharedTcpPort>,
) -> Result<()> {
    let first_packet = read_tcp_framed_packet(&mut stream).await?;
    let ufrag = peer_ufrag_from_binding_request(&first_packet)
        .ok_or_else(|| anyhow!("first TCP frame is not a STUN binding with USERNAME"))?;

    let inner = {
        let sessions = port.sessions.lock();
        sessions.get(&ufrag).and_then(|weak| weak.upgrade())
    };

    let inner = inner.ok_or_else(|| anyhow!("no ICE session registered for ufrag {ufrag}"))?;
    let listen_addr = port.listener.local_addr()?;

    attach_demuxed_tcp_stream(inner, stream, peer_addr, listen_addr, first_packet).await;
    Ok(())
}

async fn read_tcp_framed_packet(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 2];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read TCP STUN frame length")?;
    let len = u16::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_STUN_MESSAGE {
        bail!("invalid TCP STUN frame length {len}");
    }
    let mut buf = vec![0u8; len];
    stream
        .read_exact(&mut buf)
        .await
        .context("read TCP STUN frame body")?;
    Ok(buf)
}

/// USERNAME on an inbound Binding request is `peer-ufrag:own-ufrag` from the sender.
/// For a browser connecting to our passive listener, peer-ufrag is our local ufrag.
pub(crate) fn peer_ufrag_from_binding_request(data: &[u8]) -> Option<String> {
    let decoded = StunMessage::decode(data).ok()?;
    if decoded.class != StunClass::Request || decoded.method != StunMethod::Binding {
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
            return std::str::from_utf8(value).ok().map(str::to_string);
        }
        offset += len;
        offset += (4 - (len % 4)) % 4;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::ice::stun::{StunAttribute, random_bytes};

    #[test]
    fn extracts_peer_ufrag_from_binding_username() {
        let tx_id = random_bytes::<12>();
        let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
        msg.attributes
            .push(StunAttribute::Username("serverUfrag:clientUfrag".into()));
        let bytes = msg.encode(None, false).unwrap();
        assert_eq!(
            peer_ufrag_from_binding_request(&bytes).as_deref(),
            Some("serverUfrag")
        );
    }
}
