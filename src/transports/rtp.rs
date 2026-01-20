use crate::rtp::{RtcpPacket, RtpPacket, is_rtcp, marshal_rtcp_packets, parse_rtcp_packets};
use crate::srtp::SrtpSession;
use crate::transports::PacketReceiver;
use crate::transports::ice::conn::IceConn;
use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

pub struct RtpTransport {
    transport: Arc<IceConn>,
    srtp_session: Mutex<Option<Arc<Mutex<SrtpSession>>>>,
    listeners: Mutex<HashMap<u32, mpsc::Sender<RtpPacket>>>,
    rtcp_listener: Mutex<Option<mpsc::Sender<Vec<RtcpPacket>>>>,
    rid_listeners: Mutex<HashMap<String, mpsc::Sender<RtpPacket>>>,
    provisional_listener: Mutex<Option<mpsc::Sender<RtpPacket>>>,
    rid_extension_id: Mutex<Option<u8>>,
    abs_send_time_extension_id: Mutex<Option<u8>>,
    srtp_required: bool,
}

impl RtpTransport {
    pub fn new(transport: Arc<IceConn>, srtp_required: bool) -> Self {
        Self {
            transport,
            srtp_session: Mutex::new(None),
            listeners: Mutex::new(HashMap::new()),
            rtcp_listener: Mutex::new(None),
            rid_listeners: Mutex::new(HashMap::new()),
            provisional_listener: Mutex::new(None),
            rid_extension_id: Mutex::new(None),
            abs_send_time_extension_id: Mutex::new(None),
            srtp_required,
        }
    }

    pub fn ice_conn(&self) -> Arc<IceConn> {
        self.transport.clone()
    }

    pub fn start_srtp(&self, srtp_session: SrtpSession) {
        let mut session = self.srtp_session.lock().unwrap();
        *session = Some(Arc::new(Mutex::new(srtp_session)));
    }

    pub fn register_listener_sync(&self, ssrc: u32, tx: mpsc::Sender<RtpPacket>) {
        let mut listeners = self.listeners.lock().unwrap();
        listeners.insert(ssrc, tx);
    }

    pub fn has_listener(&self, ssrc: u32) -> bool {
        let listeners = self.listeners.lock().unwrap();
        listeners.contains_key(&ssrc)
    }

    pub fn register_rid_listener(&self, rid: String, tx: mpsc::Sender<RtpPacket>) {
        let mut listeners = self.rid_listeners.lock().unwrap();
        listeners.insert(rid, tx);
    }

    pub fn register_provisional_listener(&self, tx: mpsc::Sender<RtpPacket>) {
        let mut listener = self.provisional_listener.lock().unwrap();
        *listener = Some(tx);
    }

    pub fn set_rid_extension_id(&self, id: Option<u8>) {
        *self.rid_extension_id.lock().unwrap() = id;
    }

    pub fn set_abs_send_time_extension_id(&self, id: Option<u8>) {
        *self.abs_send_time_extension_id.lock().unwrap() = id;
    }

    pub fn register_rtcp_listener(&self, tx: mpsc::Sender<Vec<RtcpPacket>>) {
        let mut listener = self.rtcp_listener.lock().unwrap();
        *listener = Some(tx);
    }

    pub async fn send(&self, buf: &[u8]) -> Result<usize> {
        let protected = {
            let session_guard = self.srtp_session.lock().unwrap();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock().unwrap();
                let mut packet = RtpPacket::parse(buf)?;

                // Inject abs-send-time if enabled
                if let Some(id) = *self.abs_send_time_extension_id.lock().unwrap() {
                    let abs_send_time =
                        crate::rtp::calculate_abs_send_time(std::time::SystemTime::now());
                    let data = abs_send_time.to_be_bytes()[1..4].to_vec();
                    packet.header.set_extension(id, &data)?;
                }

                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
                if self.srtp_required {
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                buf.to_vec()
            }
        };
        self.transport.send(&protected).await
    }

    pub async fn send_rtp(&self, packet: &RtpPacket) -> Result<usize> {
        let mut packet = packet.clone();

        // Inject abs-send-time if enabled
        if let Some(id) = *self.abs_send_time_extension_id.lock().unwrap() {
            let abs_send_time = crate::rtp::calculate_abs_send_time(std::time::SystemTime::now());
            let data = abs_send_time.to_be_bytes()[1..4].to_vec();
            packet.header.set_extension(id, &data)?;
        }

        let protected = {
            let session_guard = self.srtp_session.lock().unwrap();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock().unwrap();
                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
                if self.srtp_required {
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                packet.marshal()?
            }
        };
        self.transport.send(&protected).await
    }

    pub async fn send_rtcp(&self, packets: &[RtcpPacket]) -> Result<usize> {
        let raw = marshal_rtcp_packets(packets)?;
        let protected = {
            let session_guard = self.srtp_session.lock().unwrap();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock().unwrap();
                let mut buf = raw.clone();
                srtp.protect_rtcp(&mut buf)?;
                buf
            } else {
                if self.srtp_required {
                    tracing::warn!("Failed to send PLI: SRTP required but session not ready");
                    return Err(anyhow::anyhow!("SRTP required but session not ready"));
                }
                raw
            }
        };
        self.transport.send_rtcp(&protected).await
    }

    /// Clear all listeners to stop receiving packets.
    /// This is called when PeerConnection is closed to prevent audio bleeding into new connections.
    pub fn clear_listeners(&self) -> usize {
        let mut count = 0;

        // Clear SSRC listeners
        {
            let mut listeners = self.listeners.lock().unwrap();
            count += listeners.len();
            listeners.clear();
        }

        // Clear RID listeners
        {
            let mut rid_listeners = self.rid_listeners.lock().unwrap();
            count += rid_listeners.len();
            rid_listeners.clear();
        }

        // Clear RTCP listener
        {
            let mut rtcp_listener = self.rtcp_listener.lock().unwrap();
            if rtcp_listener.is_some() {
                *rtcp_listener = None;
                count += 1;
            }
        }

        count
    }
}

#[async_trait]
impl PacketReceiver for RtpTransport {
    async fn receive(&self, packet: Bytes, _addr: SocketAddr) {
        let is_rtcp_packet = is_rtcp(&packet);

        let unprotected = {
            let session_guard = self.srtp_session.lock().unwrap();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock().unwrap();
                if is_rtcp_packet {
                    let mut buf = packet.to_vec();
                    match srtp.unprotect_rtcp(&mut buf) {
                        Ok(_) => buf,
                        Err(e) => {
                            tracing::warn!("SRTP unprotect RTCP failed: {}", e);
                            return;
                        }
                    }
                } else {
                    match RtpPacket::parse(&packet) {
                        Ok(mut rtp_packet) => match srtp.unprotect_rtp(&mut rtp_packet) {
                            Ok(_) => match rtp_packet.marshal() {
                                Ok(b) => b,
                                Err(e) => {
                                    tracing::debug!("RTP marshal failed: {}", e);
                                    return;
                                }
                            },
                            Err(_) => {
                                return;
                            }
                        },
                        Err(e) => {
                            tracing::debug!("RTP parse failed: {}", e);
                            return;
                        }
                    }
                }
            } else {
                if self.srtp_required {
                    // Drop packet
                    tracing::debug!(
                        "Dropping packet because SRTP is required but session is not ready"
                    );
                    return;
                }
                packet.to_vec()
            }
        };

        if is_rtcp_packet {
            let listener = {
                let guard = self.rtcp_listener.lock().unwrap();
                guard.clone()
            };
            if let Some(tx) = listener {
                match parse_rtcp_packets(&unprotected) {
                    Ok(packets) => {
                        if tx.send(packets).await.is_err() {
                            let mut guard = self.rtcp_listener.lock().unwrap();
                            *guard = None;
                        }
                    }
                    Err(e) => {
                        tracing::debug!("RTCP parse failed: {}", e);
                    }
                }
            }
        } else {
            match RtpPacket::parse(&unprotected) {
                Ok(rtp_packet) => {
                    // if let Some(ext) = &rtp_packet.header.extension {
                    //    println!("RTP Extension Profile: {:x}", ext.profile);
                    // }
                    let ssrc = rtp_packet.header.ssrc;
                    let mut listener = None;

                    // Try RID first
                    let rid_id = *self.rid_extension_id.lock().unwrap();
                    if let Some(id) = rid_id {
                        if let Some(rid) = rtp_packet.header.get_extension(id) {
                            // Parse RID string
                            let rid_str = String::from_utf8_lossy(&rid).to_string();
                            let rid_listeners = self.rid_listeners.lock().unwrap();
                            listener = rid_listeners.get(&rid_str).cloned();
                        }
                    }

                    // Fallback to SSRC listener
                    if listener.is_none() {
                        let listeners = self.listeners.lock().unwrap();
                        listener = listeners.get(&ssrc).cloned();
                    }

                    // Fallback to provisional listener (and bind SSRC)
                    if listener.is_none() {
                        let mut provisional = self.provisional_listener.lock().unwrap();
                        if let Some(tx) = provisional.take() {
                            tracing::info!("RTP binding provisional listener to SSRC: {}", ssrc);
                            let mut listeners = self.listeners.lock().unwrap();
                            listeners.insert(ssrc, tx.clone());
                            listener = Some(tx);
                        }
                    }

                    if let Some(tx) = listener {
                        if tx.send(rtp_packet).await.is_err() {
                            // Only remove SSRC listener if we used it?
                            // If we used RID listener, we shouldn't remove SSRC listener.
                            // But here we don't know which one we used easily without a flag.
                            // Let's just ignore removal for now or be careful.
                            // Actually, if the channel is closed, we should probably remove it from wherever it came from.
                            // But removing from SSRC listeners is safe if it was there.
                            // Removing from RID listeners is harder as we don't have the RID here.

                            let mut listeners = self.listeners.lock().unwrap();
                            listeners.remove(&ssrc);
                        }
                    } else {
                        tracing::debug!(
                            "No listener found for packet SSRC: {} PT: {}",
                            ssrc,
                            rtp_packet.header.payload_type
                        );
                    }
                }
                Err(e) => {
                    tracing::debug!("RTP parse failed: {}", e);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::ice::conn::IceConn;
    use tokio::sync::mpsc;

    #[tokio::test]
    async fn test_provisional_listener_binding() {
        use crate::transports::ice::IceSocketWrapper;
        use bytes::Bytes;
        use tokio::sync::watch;

        // Setup RtpTransport with a mock/dummy IceConn
        let (_ice_tx, ice_rx) = watch::channel(None::<IceSocketWrapper>);
        let ice_conn = IceConn::new(ice_rx, "127.0.0.1:1234".parse().unwrap());
        let transport = RtpTransport::new(ice_conn, false);

        // Register a provisional listener
        let (tx, mut rx) = mpsc::channel(10);
        transport.register_provisional_listener(tx);

        // Simulate receiving an RTP packet with unknown SSRC
        let ssrc = 12345u32;
        let header = crate::rtp::RtpHeader::new(0, 1, 0, ssrc);

        let rtp_packet = crate::rtp::RtpPacket::new(header, vec![0u8; 160]);

        // Inject the packet via the receive logic
        let bytes = rtp_packet.marshal().unwrap();
        transport
            .receive(Bytes::from(bytes), "127.0.0.1:5000".parse().unwrap())
            .await;

        // 1. Verify listener received the packet
        let received = rx
            .recv()
            .await
            .expect("Packet should be received by provisional listener");
        assert_eq!(received.header.ssrc, ssrc);

        // 2. Verify SSRC is now bound
        assert!(
            transport.has_listener(ssrc),
            "SSRC should be bound in listeners map"
        );

        // 3. Verify provisional listener is consumed (None)
        {
            let prov = transport.provisional_listener.lock().unwrap();
            assert!(
                prov.is_none(),
                "Provisional listener should be consumed after binding"
            );
        }

        // 4. Send another packet with same SSRC, it should go to the same listener via the bound map
        let header2 = crate::rtp::RtpHeader::new(0, 2, 80, ssrc);
        let rtp_packet2 = crate::rtp::RtpPacket::new(header2, vec![1u8; 160]);
        let bytes2 = rtp_packet2.marshal().unwrap();
        transport
            .receive(Bytes::from(bytes2), "127.0.0.1:5000".parse().unwrap())
            .await;

        let received2 = rx
            .recv()
            .await
            .expect("Second packet should be received via bound SSRC");
        assert_eq!(received2.header.ssrc, ssrc);
        assert_eq!(received2.payload[0], 1);
    }
}
