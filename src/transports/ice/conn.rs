use super::{IceSocketWrapper, should_drop_packet};
use crate::transports::PacketReceiver;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Weak};
use tokio::sync::watch;
use tracing::{debug, warn};

pub struct IceConn {
    pub socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    pub remote_addr: RwLock<SocketAddr>,
    pub remote_rtcp_addr: RwLock<Option<SocketAddr>>,
    pub dtls_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub latch_on_rtp: AtomicBool,
    pub rtp_latched: AtomicBool,
    pub rtcp_latched: AtomicBool,
    pub expected_ssrc: AtomicU32,
    pub rtp_rx_count: AtomicU64,
}

impl IceConn {
    pub fn new(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
    ) -> Arc<Self> {
        Self::new_with_rtcp(socket_rx.clone(), socket_rx, remote_addr)
    }

    pub(crate) fn new_with_rtcp(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
    ) -> Arc<Self> {
        Arc::new(Self {
            socket_rx,
            rtcp_socket_rx,
            remote_addr: RwLock::new(remote_addr),
            remote_rtcp_addr: RwLock::new(None),
            dtls_receiver: RwLock::new(None),
            rtp_receiver: RwLock::new(None),
            latch_on_rtp: AtomicBool::new(false),
            rtp_latched: AtomicBool::new(false),
            rtcp_latched: AtomicBool::new(false),
            expected_ssrc: AtomicU32::new(0),
            rtp_rx_count: AtomicU64::new(0),
        })
    }

    pub fn enable_latch_on_rtp(&self) {
        self.latch_on_rtp.store(true, Ordering::Relaxed);
    }

    /// Set the expected SSRC from the remote answer SDP.
    /// When set, RTP latching uses SSRC match instead of source-address
    /// mismatch, allowing latch to succeed even when NAT changes the port.
    pub fn set_expected_ssrc(&self, ssrc: u32) {
        self.expected_ssrc.store(ssrc, Ordering::Relaxed);
    }

    pub fn set_remote_rtcp_addr(&self, addr: Option<SocketAddr>) {
        *self.remote_rtcp_addr.write() = addr;
        self.rtcp_latched.store(false, Ordering::Relaxed);
    }

    pub(crate) fn set_remote_addr_from_signaling(&self, addr: SocketAddr, reason: &'static str) {
        let current = *self.remote_addr.read();
        if self.latch_on_rtp.load(Ordering::Relaxed)
            && self.rtp_latched.load(Ordering::Relaxed)
            && current != addr
        {
            warn!(
                "IceConn: preserving latched RTP remote {} instead of signaling remote {} ({})",
                current, addr, reason
            );
            return;
        }

        *self.remote_addr.write() = addr;
    }

    pub fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    pub fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        if should_drop_packet() {
            return Ok(buf.len());
        }
        let socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow().clone();

        if let Some(socket) = socket_opt {
            let remote = *self.remote_addr.read();
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
                let remote = *self.remote_addr.read();
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
        let rtcp_addr = *self.remote_rtcp_addr.read();
        let remote = if let Some(rtcp_addr) = rtcp_addr {
            rtcp_addr
        } else {
            *self.remote_addr.read()
        };

        if remote.port() == 0 {
            return Err(anyhow::anyhow!("Remote address not set"));
        }

        let mut socket_rx = if rtcp_addr.is_some() {
            self.rtcp_socket_rx.clone()
        } else {
            self.socket_rx.clone()
        };
        let mut socket_opt = socket_rx.borrow().clone();
        if socket_opt.is_none() {
            socket_opt = socket_rx.borrow_and_update().clone();
        }

        if socket_opt.is_none() && rtcp_addr.is_some() {
            let mut fallback_rx = self.socket_rx.clone();
            socket_opt = fallback_rx.borrow().clone();
            if socket_opt.is_none() {
                socket_opt = fallback_rx.borrow_and_update().clone();
            }
        }

        if let Some(socket) = socket_opt {
            socket.send_to(buf, remote).await
        } else {
            tracing::debug!("IceConn: send_rtcp failed - no selected socket");
            Err(anyhow::anyhow!("No selected socket"))
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
        let current_remote = *self.remote_addr.read();

        // If remote_addr is unspecified (port 0), accept and update
        if current_remote.port() == 0 {
            *self.remote_addr.write() = addr;
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
                let rx_lock = self.dtls_receiver.read();
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
                    let mut remote_rtcp_addr = self.remote_rtcp_addr.write();
                    if let Some(current_rtcp_remote) = *remote_rtcp_addr
                        && addr != current_rtcp_remote
                        && !self.rtcp_latched.load(Ordering::Relaxed)
                    {
                        *remote_rtcp_addr = Some(addr);
                        self.rtcp_latched.store(true, Ordering::Relaxed);
                    }
                } else if !self.rtp_latched.load(Ordering::Relaxed) {
                    let expected = self.expected_ssrc.load(Ordering::Relaxed);
                    let should_latch = if expected != 0 {
                        packet.len() >= 12 && {
                            let pkt_ssrc =
                                u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);
                            pkt_ssrc == expected
                        }
                    } else {
                        addr != current_remote
                    };
                    if should_latch {
                        if addr != current_remote {
                            *self.remote_addr.write() = addr;
                        }
                        self.rtp_latched.store(true, Ordering::Relaxed);
                        tracing::info!(
                            "IceConn: RTP latched to {} (expected_ssrc={})",
                            addr,
                            expected
                        );
                    }
                }
            }
            let receiver = {
                let rx_lock = self.rtp_receiver.read();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                // Log once per connection when the first RTP packet arrives.
                let prev = self.rtp_rx_count.fetch_add(1, Ordering::Relaxed);
                if prev == 0 {
                    tracing::debug!(
                        "IceConn: first {} packet ({} bytes) from {} — forwarding to RTP receiver",
                        if is_rtcp { "RTCP" } else { "RTP" },
                        packet.len(),
                        addr,
                    );
                }
                strong_rx.receive(packet, addr).await;
            } else {
                tracing::debug!(
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
        let rtp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtp_socket_addr = rtp_socket.local_addr().unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(rtp_socket);
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let rtcp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtcp_socket_addr = rtcp_socket.local_addr().unwrap();
        let rtcp_socket_wrapper = IceSocketWrapper::Udp(rtcp_socket);
        let (_rtcp_tx, rtcp_rx) = watch::channel(Some(rtcp_socket_wrapper));

        let rtp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_addr = rtp_receiver.local_addr().unwrap();

        let rtcp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtcp_addr = rtcp_receiver.local_addr().unwrap();

        let conn = IceConn::new_with_rtcp(rx, rtcp_rx, rtp_addr);
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        // Send RTP (via send) -> should go to rtp_addr
        conn.send(b"rtp").await.unwrap();
        let mut buf = [0u8; 1024];
        let (len, rtp_src) = rtp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtp");
        assert_eq!(rtp_src, rtp_socket_addr);

        // Send RTCP (via send_rtcp) -> should go to rtcp_addr from the RTCP socket.
        conn.send_rtcp(b"rtcp").await.unwrap();
        let (len, rtcp_src) = rtcp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtcp");
        assert_eq!(rtcp_src, rtcp_socket_addr);
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

        assert_eq!(*conn.remote_addr.read(), latched_addr);
    }

    #[tokio::test]
    async fn test_rtcp_does_not_override_rtp_remote_addr() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        conn.receive(Bytes::from_static(&[0x80, 0x60, 0x00, 0x00]), rtp_src)
            .await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;

        assert_eq!(
            *conn.remote_addr.read(),
            rtp_src,
            "RTCP should not override RTP remote address"
        );
    }

    #[tokio::test]
    async fn test_rtcp_latches_rtcp_addr_in_non_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let initial_rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(initial_rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        conn.receive(Bytes::from_static(&[0x80, 0x60, 0x00, 0x00]), rtp_src)
            .await;

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should latch its own destination"
        );
        assert!(conn.rtcp_latched.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_rtcp_does_not_re_latch_after_locked() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001)));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        conn.receive(Bytes::from_static(&[0x80, 0x60, 0x00, 0x00]), rtp_src)
            .await;

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtcp_src)
            .await;
        assert_eq!(*conn.remote_rtcp_addr.read(), Some(rtcp_src));

        let rogue_rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6001);
        conn.receive(
            Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]),
            rogue_rtcp_src,
        )
        .await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should not re-latch after already latched"
        );
    }

    #[tokio::test]
    async fn test_rtcp_ignored_in_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        conn.receive(Bytes::from_static(&[0x80, 0x60, 0x00, 0x00]), rtp_src)
            .await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);

        conn.receive(Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]), rtp_src)
            .await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(
            conn.remote_rtcp_addr.read().is_none(),
            "RTCP address should remain None in mux mode"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_port_mismatch() {
        // Simulates the VoLTE/NAT scenario: the answer SDP advertises
        // remote port 4162, but real RTP arrives from port 17687.
        // Latching should succeed because the SSRC matches.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let real_addr: SocketAddr = "112.96.43.157:17687".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;

        let conn = IceConn::new(rx, sdp_addr);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Build a minimal 12-byte RTP packet with the matching SSRC.
        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&expected_ssrc.to_be_bytes()); // bytes 8-11

        conn.receive(Bytes::from(pkt), real_addr).await;

        assert_eq!(
            *conn.remote_addr.read(),
            real_addr,
            "Should latch to real NAT address when SSRC matches"
        );
        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should be set after SSRC match"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_wrong_ssrc() {
        // A stray packet with a different SSRC should not trigger latching.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let rogue_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;
        let wrong_ssrc: u32 = 99_999_999;

        let conn = IceConn::new(rx, sdp_addr);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&wrong_ssrc.to_be_bytes());

        conn.receive(Bytes::from(pkt), rogue_addr).await;

        assert_eq!(
            *conn.remote_addr.read(),
            sdp_addr,
            "Should NOT latch when SSRC does not match"
        );
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should remain false for wrong SSRC"
        );
    }

    #[tokio::test]
    async fn test_address_based_latch_fallback_when_no_expected_ssrc() {
        // When no expected SSRC is configured, latching falls back to
        // the original address-mismatch logic (current behaviour).
        let (_tx, rx) = watch::channel(None);
        let initial_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let new_addr: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        let conn = IceConn::new(rx, initial_addr);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        // expected_ssrc stays 0 — no SDP SSRC hint

        let pkt = Bytes::from_static(&[
            0x80, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0, 0x00, 0x00, 0x01, 0x23,
        ]);

        conn.receive(pkt, new_addr).await;

        assert_eq!(*conn.remote_addr.read(), new_addr);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
    }
}
