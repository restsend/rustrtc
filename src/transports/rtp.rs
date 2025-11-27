use std::collections::HashMap;
use std::{net::SocketAddr, sync::Arc};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex, mpsc};
use tracing::{debug, warn};

use crate::rtp::{RtcpPacket, RtpPacket, is_rtcp, marshal_rtcp_packets, parse_rtcp_packets};
use crate::srtp::SrtpSession;
use crate::transports::PacketReceiver;
use crate::transports::ice::conn::IceConn;

#[derive(Debug)]
pub enum ReceivedPacket {
    Rtp(RtpPacket),
    Rtcp(Vec<RtcpPacket>),
    Stun(Vec<u8>),
}

fn is_stun(packet: &[u8]) -> bool {
    // RFC 7983: STUN packets have a first byte in range 0..3
    packet.len() >= 20 && packet[0] < 4
}

#[derive(Clone)]
pub struct UdpRtpEndpoint {
    rtp_socket: Arc<UdpSocket>,
    rtcp_socket: Option<Arc<UdpSocket>>,
}

pub struct RtpTransport {
    ice_conn: Mutex<Option<Arc<IceConn>>>,
    listeners: Mutex<HashMap<u32, mpsc::Sender<RtpPacket>>>,
    srtp_session: Mutex<Option<SrtpSession>>,
}

impl RtpTransport {
    pub fn new(ice_conn: Arc<IceConn>) -> Self {
        Self {
            ice_conn: Mutex::new(Some(ice_conn)),
            listeners: Mutex::new(HashMap::new()),
            srtp_session: Mutex::new(None),
        }
    }

    pub async fn start_srtp(&self, session: SrtpSession) {
        *self.srtp_session.lock().await = Some(session);
    }

    pub async fn register_listener(&self, ssrc: u32, sender: mpsc::Sender<RtpPacket>) {
        self.listeners.lock().await.insert(ssrc, sender);
    }

    pub async fn send_rtp(&self, packet: &RtpPacket) -> Result<()> {
        let mut packet = packet.clone();
        {
            let mut session = self.srtp_session.lock().await;
            if let Some(s) = &mut *session {
                s.protect_rtp(&mut packet)
                    .map_err(|e| anyhow::anyhow!("SRTP protect failed: {:?}", e))?;
            }
        }
        let bytes = packet.marshal().context("marshal RTP")?;
        if let Some(conn) = &*self.ice_conn.lock().await {
            debug!("RtpTransport sending {} bytes via ICE", bytes.len());
            conn.send(&bytes).await.context("send RTP via ICE")?;
            Ok(())
        } else {
            warn!("ICE connection not set when sending RTP");
            Err(anyhow::anyhow!("ICE connection not set"))
        }
    }
}

#[async_trait]
impl PacketReceiver for RtpTransport {
    async fn receive(&self, packet: Bytes, _addr: SocketAddr) {
        if let Ok(mut rtp) = RtpPacket::parse(&packet) {
            {
                let mut session = self.srtp_session.lock().await;
                if let Some(s) = &mut *session {
                    if let Err(e) = s.unprotect_rtp(&mut rtp) {
                        debug!("SRTP unprotect failed: {:?}", e);
                        return;
                    }
                }
            }

            let ssrc = rtp.header.ssrc;
            let listeners = self.listeners.lock().await;
            if let Some(sender) = listeners.get(&ssrc) {
                debug!(
                    "RtpTransport dispatching RTP packet ssrc={} to listener",
                    ssrc
                );
                let _ = sender.send(rtp).await;
            } else {
                debug!(
                    "RtpTransport received RTP packet ssrc={} but no listener found",
                    ssrc
                );
            }
        } else {
            debug!("RtpTransport received non-RTP packet len={}", packet.len());
        }
    }
}

impl UdpRtpEndpoint {
    pub fn rtcp_mux(&self) -> bool {
        self.rtcp_socket.is_none()
    }

    pub async fn connect(
        rtp_socket: UdpSocket,
        rtcp_socket: Option<UdpSocket>,
        remote_rtp: SocketAddr,
        remote_rtcp: Option<SocketAddr>,
    ) -> Result<Self> {
        rtp_socket
            .connect(remote_rtp)
            .await
            .context("connect RTP socket")?;
        if let Some(sock) = &rtcp_socket {
            let addr = remote_rtcp.unwrap_or(remote_rtp);
            sock.connect(addr).await.context("connect RTCP socket")?;
        }

        Ok(Self {
            rtp_socket: Arc::new(rtp_socket),
            rtcp_socket: rtcp_socket.map(Arc::new),
        })
    }

    pub async fn send_rtp(&self, packet: &RtpPacket) -> Result<()> {
        let bytes = packet.marshal().context("marshal RTP")?;
        self.rtp_socket.send(&bytes).await.context("send RTP")?;
        Ok(())
    }

    pub async fn recv(&self) -> Result<ReceivedPacket> {
        let mut buf_rtp = vec![0u8; 1500];
        let mut buf_rtcp = vec![0u8; 1500];

        if let Some(rtcp_socket) = &self.rtcp_socket {
            tokio::select! {
                res = self.rtp_socket.recv(&mut buf_rtp) => {
                    let len = res.context("recv RTP")?;
                    let data = &buf_rtp[..len];
                    if is_stun(data) {
                        Ok(ReceivedPacket::Stun(data.to_vec()))
                    } else {
                        let packet = RtpPacket::parse(data).context("parse RTP")?;
                        Ok(ReceivedPacket::Rtp(packet))
                    }
                }
                res = rtcp_socket.recv(&mut buf_rtcp) => {
                    let len = res.context("recv RTCP")?;
                    let data = &buf_rtcp[..len];
                    if is_stun(data) {
                        Ok(ReceivedPacket::Stun(data.to_vec()))
                    } else {
                        let packets = parse_rtcp_packets(data).context("parse RTCP")?;
                        Ok(ReceivedPacket::Rtcp(packets))
                    }
                }
            }
        } else {
            let len = self
                .rtp_socket
                .recv(&mut buf_rtp)
                .await
                .context("recv RTP/RTCP mux")?;
            let data = &buf_rtp[..len];
            if is_stun(data) {
                Ok(ReceivedPacket::Stun(data.to_vec()))
            } else if is_rtcp(data) {
                let packets = parse_rtcp_packets(data).context("parse RTCP mux")?;
                Ok(ReceivedPacket::Rtcp(packets))
            } else {
                let packet = RtpPacket::parse(data).context("parse RTP mux")?;
                Ok(ReceivedPacket::Rtp(packet))
            }
        }
    }

    pub async fn send_rtcp(&self, packets: &[RtcpPacket]) -> Result<()> {
        let bytes = marshal_rtcp_packets(packets).context("marshal RTCP")?;
        if let Some(socket) = &self.rtcp_socket {
            socket.send(&bytes).await.context("send RTCP")?;
        } else {
            self.rtp_socket
                .send(&bytes)
                .await
                .context("send RTCP mux")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::{PictureLossIndication, RtcpPacket, RtpHeader, RtpPacket};
    use crate::srtp::{SrtpKeyingMaterial, SrtpProfile, SrtpSession};

    fn sample_rtp(seq: u16) -> RtpPacket {
        let header = RtpHeader::new(96, seq, 1234, 0x0102_0304);
        RtpPacket::new(header, vec![1, 2, 3])
    }

    async fn loopback_pair(mux: bool) -> Result<(UdpRtpEndpoint, UdpRtpEndpoint)> {
        let a_rtp = UdpSocket::bind("127.0.0.1:0").await?;
        let b_rtp = UdpSocket::bind("127.0.0.1:0").await?;
        let a_addr = a_rtp.local_addr()?;
        let b_addr = b_rtp.local_addr()?;

        if mux {
            let a = UdpRtpEndpoint::connect(a_rtp, None, b_addr, None).await?;
            let b = UdpRtpEndpoint::connect(b_rtp, None, a_addr, None).await?;
            Ok((a, b))
        } else {
            let a_rtcp = UdpSocket::bind("127.0.0.1:0").await?;
            let b_rtcp = UdpSocket::bind("127.0.0.1:0").await?;
            let a_rtcp_addr = a_rtcp.local_addr()?;
            let b_rtcp_addr = b_rtcp.local_addr()?;
            let a = UdpRtpEndpoint::connect(a_rtp, Some(a_rtcp), b_addr, Some(b_rtcp_addr)).await?;
            let b = UdpRtpEndpoint::connect(b_rtp, Some(b_rtcp), a_addr, Some(a_rtcp_addr)).await?;
            Ok((a, b))
        }
    }

    #[tokio::test]
    async fn rtp_send_receive_with_rtcp_mux() -> Result<()> {
        let (a, b) = loopback_pair(true).await?;
        let packet = sample_rtp(1);
        a.send_rtp(&packet).await?;
        let received = match b.recv().await? {
            ReceivedPacket::Rtp(p) => p,
            _ => panic!("expected RTP"),
        };
        assert_eq!(received.header.sequence_number, 1);

        let pli = RtcpPacket::PictureLossIndication(PictureLossIndication {
            sender_ssrc: 10,
            media_ssrc: 11,
        });
        b.send_rtcp(&[pli.clone()]).await?;
        let parsed = match a.recv().await? {
            ReceivedPacket::Rtcp(p) => p,
            _ => panic!("expected RTCP"),
        };
        assert!(matches!(parsed[0], RtcpPacket::PictureLossIndication(_)));
        Ok(())
    }

    #[tokio::test]
    async fn rtp_and_rtcp_on_separate_ports() -> Result<()> {
        let (a, b) = loopback_pair(false).await?;
        assert!(!a.rtcp_mux());
        let packet = sample_rtp(22);
        a.send_rtp(&packet).await?;
        let received = match b.recv().await? {
            ReceivedPacket::Rtp(p) => p,
            _ => panic!("expected RTP"),
        };
        assert_eq!(received.header.sequence_number, 22);

        let pli = RtcpPacket::PictureLossIndication(PictureLossIndication {
            sender_ssrc: 10,
            media_ssrc: 11,
        });
        b.send_rtcp(&[pli.clone()]).await?;
        let parsed = match a.recv().await? {
            ReceivedPacket::Rtcp(p) => p,
            _ => panic!("expected RTCP"),
        };
        assert!(matches!(parsed[0], RtcpPacket::PictureLossIndication(_)));
        Ok(())
    }

    #[tokio::test]
    async fn srtp_over_udp_roundtrip() -> Result<()> {
        let (a, b) = loopback_pair(true).await?;
        let mut tx_session = SrtpSession::new(
            SrtpProfile::Aes128Sha1_80,
            SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]),
            SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]),
        )?;
        let mut rx_session = SrtpSession::new(
            SrtpProfile::Aes128Sha1_80,
            SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]),
            SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]),
        )?;

        let mut packet = sample_rtp(77);
        tx_session.protect_rtp(&mut packet).unwrap();
        a.send_rtp(&packet).await?;
        let mut received = match b.recv().await? {
            ReceivedPacket::Rtp(p) => p,
            _ => panic!("expected RTP"),
        };
        rx_session.unprotect_rtp(&mut received).unwrap();
        assert_eq!(received.payload, vec![1, 2, 3]);
        Ok(())
    }

    #[tokio::test]
    async fn recv_stun_packet() -> Result<()> {
        // Fake STUN Binding Request
        // Type: 0x0001 (Binding Request)
        // Length: 0x0000
        // Magic Cookie: 0x2112A442
        // Transaction ID: 12 bytes
        let mut stun_packet = vec![0u8; 20];
        stun_packet[0] = 0x00;
        stun_packet[1] = 0x01;
        stun_packet[4] = 0x21;
        stun_packet[5] = 0x12;
        stun_packet[6] = 0xA4;
        stun_packet[7] = 0x42;

        let sender = UdpSocket::bind("127.0.0.1:0").await?;
        let sender_addr = sender.local_addr()?;

        let b_socket = UdpSocket::bind("127.0.0.1:0").await?;
        let b_addr = b_socket.local_addr()?;
        let b = UdpRtpEndpoint::connect(b_socket, None, sender_addr, None).await?;

        sender.send_to(&stun_packet, b_addr).await?;

        let received = b.recv().await?;
        if let ReceivedPacket::Stun(data) = received {
            assert_eq!(data, stun_packet);
        } else {
            panic!("expected STUN");
        }
        Ok(())
    }
}
