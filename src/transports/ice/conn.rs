use super::IceSocketWrapper;
use crate::transports::PacketReceiver;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::{Arc, Weak};
use tokio::sync::{RwLock, watch};
use tracing::{debug, warn};

pub struct IceConn {
    pub socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    pub remote_addr: RwLock<SocketAddr>,
    pub remote_rtcp_addr: RwLock<Option<SocketAddr>>,
    pub dtls_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
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
        })
    }

    pub async fn set_remote_rtcp_addr(&self, addr: Option<SocketAddr>) {
        *self.remote_rtcp_addr.write().await = addr;
    }

    pub async fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write().await = Some(Arc::downgrade(&receiver));
    }

    pub async fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write().await = Some(Arc::downgrade(&receiver));
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let mut socket_rx = self.socket_rx.clone();
        let mut socket_opt = socket_rx.borrow_and_update().clone();

        if socket_opt.is_none() {
            tracing::debug!("IceConn: waiting for socket... (initial check)");
            match tokio::time::timeout(std::time::Duration::from_secs(2), socket_rx.changed()).await
            {
                Ok(Ok(())) => {
                    socket_opt = socket_rx.borrow().clone();
                    if socket_opt.is_some() {
                        tracing::debug!("IceConn: socket became available");
                    } else {
                        tracing::warn!("IceConn: socket changed but is still None");
                    }
                }
                Ok(Err(_)) => {
                    tracing::warn!("IceConn: socket_rx channel closed");
                }
                Err(_) => {
                    tracing::warn!("IceConn: timeout waiting for socket");
                }
            }
        }

        if let Some(socket) = socket_opt {
            let remote = *self.remote_addr.read().await;
            if remote.port() == 0 {
                return Err(anyhow::anyhow!("Remote address not set"));
            }
            socket.send_to(buf, remote).await
        } else {
            tracing::warn!("IceConn: send failed - no selected socket");
            Err(anyhow::anyhow!("No selected socket"))
        }
    }

    pub async fn send_rtcp(&self, buf: &[u8]) -> Result<usize> {
        let mut socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow_and_update().clone();

        if let Some(socket) = socket_opt {
            let remote = if let Some(rtcp_addr) = *self.remote_rtcp_addr.read().await {
                rtcp_addr
            } else {
                *self.remote_addr.read().await
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

#[async_trait]
impl PacketReceiver for IceConn {
    async fn receive(&self, packet: Bytes, addr: SocketAddr) {
        if packet.is_empty() {
            return;
        }

        let first_byte = packet[0];
        let current_remote = *self.remote_addr.read().await;

        // If remote_addr is unspecified (port 0), accept and update
        if current_remote.port() == 0 {
            *self.remote_addr.write().await = addr;
        } else if addr != current_remote {
            // Only allow updating remote address for DTLS packets (20-63).
            // We explicitly disallow RTP (128-191) from changing the remote address
            // to prevent hijacking/race conditions during flooding.
            // In a full ICE implementation, address changes should be handled via STUN checks.
            if (20..64).contains(&first_byte) {
                debug!(
                    "IceConn: Remote address changed from {:?} to {:?} (DTLS)",
                    current_remote, addr
                );
                *self.remote_addr.write().await = addr;
            } else {
                // For RTP, we ignore the address change but still process the packet
                // (it might be from the valid peer but we haven't switched yet, or it might be junk/attack)
                // We log at trace level to avoid spamming logs during flood
                tracing::trace!(
                    "IceConn: Received packet from new address {:?} but ignoring address change (byte={})",
                    addr,
                    first_byte
                );
            }
        }

        if (20..64).contains(&first_byte) {
            // DTLS
            if let Some(rx) = &*self.dtls_receiver.read().await {
                if let Some(strong_rx) = rx.upgrade() {
                    strong_rx.receive(packet, addr).await;
                }
            } else {
                warn!("IceConn: Received DTLS packet but no receiver registered");
            }
        } else if (128..192).contains(&first_byte) {
            // RTP / RTCP
            if let Some(rx) = &*self.rtp_receiver.read().await
                && let Some(strong_rx) = rx.upgrade()
            {
                strong_rx.receive(packet, addr).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
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
        conn.set_remote_rtcp_addr(Some(rtcp_addr)).await;

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
}
