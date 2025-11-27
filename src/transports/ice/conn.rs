use super::IceSocketWrapper;
use crate::transports::PacketReceiver;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, warn};

pub struct IceConn {
    pub socket: IceSocketWrapper,
    pub remote_addr: RwLock<SocketAddr>,
    pub dtls_receiver: RwLock<Option<Arc<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Arc<dyn PacketReceiver>>>,
}

impl IceConn {
    pub fn new(socket: IceSocketWrapper, remote_addr: SocketAddr) -> Arc<Self> {
        Arc::new(Self {
            socket,
            remote_addr: RwLock::new(remote_addr),
            dtls_receiver: RwLock::new(None),
            rtp_receiver: RwLock::new(None),
        })
    }

    pub async fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write().await = Some(receiver);
    }

    pub async fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write().await = Some(receiver);
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let remote = *self.remote_addr.read().await;
        if remote.port() == 0 {
            return Err(anyhow::anyhow!("Remote address not set"));
        }
        self.socket.send_to(buf, remote).await
    }
}

#[async_trait]
impl PacketReceiver for IceConn {
    async fn receive(&self, packet: Bytes, addr: SocketAddr) {
        let current_remote = *self.remote_addr.read().await;
        // If remote_addr is unspecified (port 0), accept and update
        if current_remote.port() == 0 {
            *self.remote_addr.write().await = addr;
        } else if addr != current_remote {
            // Allow updating remote address if it changes (e.g. peer reflexive)
            // For now, just update it.
            // In a real implementation, we should validate this against valid candidates or check ICE state.
            // But since we are in a single connection state, we can assume the peer might have switched candidates.
            debug!(
                "IceConn: Remote address changed from {:?} to {:?}",
                current_remote, addr
            );
            *self.remote_addr.write().await = addr;
        }

        if packet.is_empty() {
            return;
        }

        let first_byte = packet[0];
        debug!(
            "IceConn: Received packet from {:?} len={} first_byte={}",
            addr,
            packet.len(),
            first_byte
        );

        if (20..64).contains(&first_byte) {
            // DTLS
            if let Some(rx) = &*self.dtls_receiver.read().await {
                rx.receive(packet, addr).await;
            } else {
                warn!("IceConn: Received DTLS packet but no receiver registered");
            }
        } else if (128..192).contains(&first_byte) {
            // RTP / RTCP
            if let Some(rx) = &*self.rtp_receiver.read().await {
                rx.receive(packet, addr).await;
            }
        }
    }
}
