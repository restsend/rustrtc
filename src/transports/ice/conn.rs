use super::{IceSocketWrapper, should_drop_packet};
use crate::transports::PacketReceiver;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock, Weak};
use tokio::sync::watch;
use tracing::debug;

pub struct IceConn {
    pub socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    pub remote_addr: RwLock<SocketAddr>,
    pub remote_rtcp_addr: RwLock<Option<SocketAddr>>,
    pub dtls_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub latch_on_rtp: AtomicBool,
    pub rtp_latched: AtomicBool,
    pub rtcp_latched: AtomicBool,
}

impl IceConn {
    pub fn new(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket_rx,
            remote_addr: RwLock::new(remote_addr),
            remote_rtcp_addr: RwLock::new(None),
            dtls_receiver: RwLock::new(None),
            rtp_receiver: RwLock::new(None),
            latch_on_rtp: AtomicBool::new(false),
            rtp_latched: AtomicBool::new(false),
            rtcp_latched: AtomicBool::new(false),
        })
    }

    pub fn enable_latch_on_rtp(&self) {
        self.latch_on_rtp.store(true, Ordering::Relaxed);
    }

    pub fn set_remote_rtcp_addr(&self, addr: Option<SocketAddr>) {
        *self.remote_rtcp_addr.write().unwrap() = addr;
        self.rtcp_latched.store(false, Ordering::Relaxed);
    }

    pub fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write().unwrap() = Some(Arc::downgrade(&receiver));
    }

    pub fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write().unwrap() = Some(Arc::downgrade(&receiver));
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        if should_drop_packet() {
            return Ok(buf.len());
        }
        let socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow().clone();

        if let Some(socket) = socket_opt {
            let remote = *self.remote_addr.read().unwrap();
            if remote.port() == 0 {
                return Err(anyhow::anyhow!("Remote address not set"));
            }
            // tracing::trace!("IceConn: sending {} bytes to {}", buf.len(), remote);
            socket.send_to(buf, remote).await
        } else {
            // Fallback: try to update if None
            let mut socket_rx = self.socket_rx.clone();
            let socket_opt = socket_rx.borrow_and_update().clone();
            if let Some(socket) = socket_opt {
                let remote = *self.remote_addr.read().unwrap();
                if remote.port() == 0 {
                    return Err(anyhow::anyhow!("Remote address not set"));
                }
                // tracing::trace!("IceConn: sending {} bytes to {}", buf.len(), remote);
                socket.send_to(buf, remote).await
            } else {
                tracing::warn!("IceConn: send failed - no selected socket");
                Err(anyhow::anyhow!("No selected socket"))
            }
        }
    }

    pub async fn send_rtcp(&self, buf: &[u8]) -> Result<usize> {
        let socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow().clone();

        if let Some(socket) = socket_opt {
            let remote = if let Some(rtcp_addr) = *self.remote_rtcp_addr.read().unwrap() {
                rtcp_addr
            } else {
                *self.remote_addr.read().unwrap()
            };

            if remote.port() == 0 {
                return Err(anyhow::anyhow!("Remote address not set"));
            }
            socket.send_to(buf, remote).await
        } else {
            // Fallback
            let mut socket_rx = self.socket_rx.clone();
            let socket_opt = socket_rx.borrow_and_update().clone();
            if let Some(socket) = socket_opt {
                let remote = if let Some(rtcp_addr) = *self.remote_rtcp_addr.read().unwrap() {
                    rtcp_addr
                } else {
                    *self.remote_addr.read().unwrap()
                };

                if remote.port() == 0 {
                    return Err(anyhow::anyhow!("Remote address not set"));
                }
                socket.send_to(buf, remote).await
            } else {
                tracing::warn!("IceConn: send_rtcp failed - no selected socket");
                Err(anyhow::anyhow!("No selected socket"))
            }
        }
    }
}

#[async_trait]
impl PacketReceiver for IceConn {
    async fn receive(&self, packet: Bytes, addr: SocketAddr) {
        if packet.is_empty() {
            return;
        }

        let first_byte = packet[0];
        // Scope for read lock
        let current_remote = *self.remote_addr.read().unwrap();

        // If remote_addr is unspecified (port 0), accept and update
        if current_remote.port() == 0 {
            *self.remote_addr.write().unwrap() = addr;
        } else if addr != current_remote {
            // Note: We no longer automatically switch the remote address just by receiving
            // a packet from a new source (e.g. DTLS). This prevents "path flapping"
            // that can confuse the transport Layer. The remote address should only
            // be updated via the ICE nomination process.
            tracing::trace!(
                "IceConn: Received packet from new address {:?} (byte={}) - ignoring address change",
                addr,
                first_byte
            );
        }

        if (20..64).contains(&first_byte) {
            // DTLS
            let receiver = {
                let rx_lock = self.dtls_receiver.read().unwrap();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                // tracing::trace!("IceConn: Forwarding DTLS packet to receiver");
                strong_rx.receive(packet, addr).await;
            } else {
                debug!("IceConn: Received DTLS packet but no receiver registered");
            }
        } else if (128..192).contains(&first_byte) {
            // RTP / RTCP
            let is_rtcp = packet.len() >= 2 && (200..=211).contains(&packet[1]);

            if self.latch_on_rtp.load(Ordering::Relaxed) {
                if is_rtcp {
                    // RTCP may teach the RTCP destination in non-mux mode, but it must
                    // never override the RTP remote address.
                    let mut remote_rtcp_addr = self.remote_rtcp_addr.write().unwrap();
                    if let Some(current_rtcp_remote) = *remote_rtcp_addr
                        && addr != current_rtcp_remote
                        && !self.rtcp_latched.load(Ordering::Relaxed)
                    {
                        *remote_rtcp_addr = Some(addr);
                        self.rtcp_latched.store(true, Ordering::Relaxed);
                    }
                } else if addr != current_remote && !self.rtp_latched.load(Ordering::Relaxed) {
                    *self.remote_addr.write().unwrap() = addr;
                    self.rtp_latched.store(true, Ordering::Relaxed);
                }
            }
            let receiver = {
                let rx_lock = self.rtp_receiver.read().unwrap();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                strong_rx.receive(packet, addr).await;
            } else {
                tracing::warn!(
                    "IceConn: No RTP receiver registered for packet from {}",
                    addr
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_mux() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let conn = IceConn::new(rx, receiver_addr);

        // Send RTCP (via send_rtcp) -> should go to receiver_addr (default)
        conn.send_rtcp(b"hello").await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_no_mux() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let rtp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_addr = rtp_receiver.local_addr().unwrap();

        let rtcp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtcp_addr = rtcp_receiver.local_addr().unwrap();

        let conn = IceConn::new(rx, rtp_addr);
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        // Send RTP (via send) -> should go to rtp_addr
        conn.send(b"rtp").await.unwrap();
        let mut buf = [0u8; 1024];
        let (len, _) = rtp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtp");

        // Send RTCP (via send_rtcp) -> should go to rtcp_addr
        conn.send_rtcp(b"rtcp").await.unwrap();
        let (len, _) = rtcp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtcp");
    }

    struct NoopReceiver;

    #[async_trait]
    impl PacketReceiver for NoopReceiver {
        async fn receive(&self, _packet: Bytes, _addr: SocketAddr) {}
    }

    #[tokio::test]
    async fn test_ice_conn_latches_remote_addr_on_rtp() {
        let (_tx, rx) = watch::channel(None);
        let initial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let latched_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let conn = IceConn::new(rx, initial_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        conn.receive(Bytes::from_static(&[0x80, 0x00, 0x00, 0x00]), latched_addr)
            .await;

        assert_eq!(*conn.remote_addr.read().unwrap(), latched_addr);
    }
}
