#![cfg(feature = "std")]
//! RTCP towards a plain SIP peer without rtcp-mux (a trunk): the BYE goes
//! to its RTCP port, and every compound packet starts with a report (RFC
//! 3550 §6.1).

use anyhow::{Result, anyhow};
use bytes::Bytes;
use rustrtc::media::frame::{AudioFrame, MediaKind as FrameKind};
use rustrtc::media::track::sample_track;
use rustrtc::peer_connection::RtpSender;
use rustrtc::rtp::{RtcpPacket, is_rtcp, parse_rtcp_packets};
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters, SdpType, SessionDescription};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::time::{Instant, timeout};

/// A SIP peer: RTP on an even port, RTCP on the next one (RFC 3550 §11).
struct Peer {
    rtp: UdpSocket,
    rtcp: UdpSocket,
}

impl Peer {
    async fn new() -> Self {
        for _ in 0..50 {
            let rtp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let port = rtp.local_addr().unwrap().port();
            if port % 2 == 0
                && let Ok(rtcp) = UdpSocket::bind(("127.0.0.1", port + 1)).await
            {
                return Self { rtp, rtcp };
            }
        }
        panic!("no free RTP/RTCP port pair");
    }

    /// An offer without a=rtcp-mux, as Netelip's.
    fn offer(&self) -> String {
        let port = self.rtp.local_addr().unwrap().port();
        format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {port} RTP/AVP 8 101\r\na=rtpmap:8 PCMA/8000\r\n\
             a=rtpmap:101 telephone-event/8000\r\na=ptime:20\r\na=sendrecv\r\n"
        )
    }

    /// Our RTP and RTCP ports from the answer.
    fn ports(answer: &SessionDescription) -> (u16, u16) {
        let m = &answer.media_sections[0];
        let rtcp = (m.attributes.iter())
            .find(|a| a.key == "rtcp")
            .and_then(|a| a.value.as_deref()?.split_whitespace().next()?.parse().ok())
            .unwrap_or(m.port + 1);
        (m.port, rtcp)
    }

    fn rtp_packet(seq: u16, ssrc: u32) -> Vec<u8> {
        let mut p = vec![0x80, 8];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&(seq as u32 * 160).to_be_bytes());
        p.extend_from_slice(&ssrc.to_be_bytes());
        p.extend(std::iter::repeat_n(0xd5, 160));
        p
    }

    /// Everything that comes on `socket` for `d`: RTCP compounds (as
    /// packet types) and the number of RTP packets.
    async fn collect(socket: &UdpSocket, d: Duration) -> (Vec<Vec<u8>>, usize) {
        let mut rtcp = Vec::new();
        let mut rtp = 0;
        let end = Instant::now() + d;
        let mut buf = [0u8; 1500];
        while let Ok(Ok(n)) = timeout(
            end.saturating_duration_since(Instant::now()),
            socket.recv(&mut buf),
        )
        .await
        {
            if is_rtcp(&buf[..n]) {
                rtcp.push(packet_types(&buf[..n]));
            } else {
                rtp += 1;
            }
        }
        (rtcp, rtp)
    }
}

fn packet_types(raw: &[u8]) -> Vec<u8> {
    parse_rtcp_packets(raw, None)
        .unwrap()
        .iter()
        .map(|p| match p {
            RtcpPacket::SenderReport(_) => 200,
            RtcpPacket::ReceiverReport(_) => 201,
            RtcpPacket::SourceDescription(_) => 202,
            RtcpPacket::Goodbye(_) => 203,
            _ => 0,
        })
        .collect()
}

/// A SIP leg that answers `peer`, with a PCMA track. Returns the leg, the
/// track's source, and the sender.
async fn answer(
    peer: &Peer,
) -> Result<(
    PeerConnection,
    rustrtc::media::track::SampleStreamSource,
    Arc<RtpSender>,
)> {
    let mut config = RtcConfiguration::sip();
    config.bind_ips = vec![std::net::Ipv4Addr::LOCALHOST.into()];
    let pc = PeerConnection::new(config);
    let (source, track, _) = sample_track(FrameKind::Audio, 100);
    let params = RtpCodecParameters {
        payload_type: 8,
        clock_rate: 8000,
        channels: 1,
        ..Default::default()
    };
    let sender = pc.add_track(track, params)?;
    let offer = SessionDescription::parse(SdpType::Offer, &peer.offer())?;
    pc.set_remote_description(offer).await?;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;
    let (rtp, rtcp) = Peer::ports(&answer);
    assert_ne!(rtp, rtcp, "no rtcp-mux: an RTCP port of its own");
    peer.rtp.connect(("127.0.0.1", rtp)).await?;
    peer.rtcp.connect(("127.0.0.1", rtcp)).await?;
    Ok((pc, source, sender))
}

fn pcma(seq: u16) -> AudioFrame {
    AudioFrame {
        rtp_timestamp: seq as u32 * 160,
        clock_rate: 8000,
        data: Bytes::from(vec![0xd5; 160]),
        ..AudioFrame::default()
    }
}

/// Media both ways for `d`: the peer sends RTP, and `source` (if any)
/// sends samples.
async fn talk(
    peer: &Peer,
    source: Option<&rustrtc::media::track::SampleStreamSource>,
    d: Duration,
) {
    let packets = (d.as_millis() / 20) as u16;
    for seq in 0..packets {
        peer.rtp
            .send(&Peer::rtp_packet(seq, 0x1234_5678))
            .await
            .unwrap();
        if let Some(source) = source {
            source.send_audio(pcma(seq)).unwrap();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// At close: one compound RR + SDES + BYE, on the peer's RTCP port, not
/// on its RTP port.
#[tokio::test]
async fn bye_goes_to_the_rtcp_port_as_a_compound() -> Result<()> {
    let peer = Peer::new().await;
    let (pc, source, _) = answer(&peer).await?;
    talk(&peer, Some(&source), Duration::from_millis(500)).await;
    // Drain what came so far.
    Peer::collect(&peer.rtp, Duration::from_millis(100)).await;
    Peer::collect(&peer.rtcp, Duration::from_millis(100)).await;

    pc.close();
    let (on_rtcp, _) = Peer::collect(&peer.rtcp, Duration::from_millis(500)).await;
    let (on_rtp, _) = Peer::collect(&peer.rtp, Duration::from_millis(100)).await;
    assert!(on_rtp.is_empty(), "no RTCP on the RTP port: {on_rtp:?}");
    let bye = on_rtcp
        .iter()
        .find(|r| r.contains(&203))
        .ok_or_else(|| anyhow!("no BYE on the RTCP port: {on_rtcp:?}"))?;
    assert_eq!(bye, &vec![201, 202, 203], "RR, SDES, BYE (RFC 3550 §6.1)");
    Ok(())
}
