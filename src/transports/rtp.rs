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
}

impl RtpTransport {
    pub fn new(transport: Arc<IceConn>) -> Self {
        Self {
            transport,
            srtp_session: Mutex::new(None),
            listeners: Mutex::new(HashMap::new()),
            rtcp_listener: Mutex::new(None),
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
                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
                buf.to_vec()
            }
        };
        self.transport.send(&protected).await
    }

    pub async fn send_rtp(&self, packet: &RtpPacket) -> Result<usize> {
        let mut packet = packet.clone();
        let protected = {
            let session_guard = self.srtp_session.lock().unwrap();
            if let Some(session) = &*session_guard {
                let mut srtp = session.lock().unwrap();
                srtp.protect_rtp(&mut packet)?;
                packet.marshal()?
            } else {
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
                raw
            }
        };
        self.transport.send_rtcp(&protected).await
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
                                    tracing::warn!("RTP marshal failed: {}", e);
                                    return;
                                }
                            },
                            Err(e) => {
                                tracing::warn!("SRTP unprotect RTP failed: {}", e);
                                return;
                            }
                        },
                        Err(e) => {
                            tracing::warn!("RTP parse failed: {}", e);
                            return;
                        }
                    }
                }
            } else {
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
                        tracing::warn!("RTCP parse failed: {}", e);
                    }
                }
            }
        } else {
            match RtpPacket::parse(&unprotected) {
                Ok(rtp_packet) => {
                    let ssrc = rtp_packet.header.ssrc;
                    let listener = {
                        let listeners = self.listeners.lock().unwrap();
                        listeners.get(&ssrc).cloned()
                    };
                    if let Some(tx) = listener {
                        if tx.send(rtp_packet).await.is_err() {
                            let mut listeners = self.listeners.lock().unwrap();
                            listeners.remove(&ssrc);
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("RTP parse failed: {}", e);
                }
            }
        }
    }
}
