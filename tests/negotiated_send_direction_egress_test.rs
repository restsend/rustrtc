//! The negotiated send direction (RFC 3264 §6.1 / §7, RFC 8829 §5.11)
//! applies to every RTP egress path, not only the RtpSender's sample loop:
//! `send_raw_rtp` (e.g. RFC 4733 DTMF) and the rewrite-bridge relay stop
//! while the remote does not receive, and resume when it does.
use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::frame::{AudioFrame, MediaSample};
use rustrtc::media::track::{SampleStreamSource, sample_track};
use rustrtc::peer_connection::RtpObserver;
use rustrtc::rtp::{RtpHeader, RtpPacket};
use rustrtc::sdp::Direction;
use rustrtc::transports::rtp::RtpRewriteBridgeParams;
use rustrtc::{
    PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection, TransportMode,
};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

fn pcmu() -> RtpCodecParameters {
    RtpCodecParameters {
        payload_type: 0,
        name: "PCMU".to_string(),
        clock_rate: 8000,
        channels: 1,
    }
}

fn pc(mode: TransportMode) -> PeerConnection {
    PeerConnection::new(RtcConfiguration {
        transport_mode: mode,
        ..RtcConfiguration::default()
    })
}

#[derive(Default)]
struct Ingress(AtomicUsize);

impl RtpObserver for Ingress {
    fn on_ingress(&self, _packet: &RtpPacket, _src: std::net::SocketAddr) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

impl Ingress {
    fn count(&self) -> usize {
        self.0.load(Ordering::Relaxed)
    }
}

/// `offerer` offers, `answerer` answers with `answer_direction` on its m-line.
async fn negotiate(
    offerer: &PeerConnection,
    answerer: &PeerConnection,
    answer_direction: Direction,
) -> Result<()> {
    let _ = offerer.create_offer().await?;
    offerer.wait_for_gathering_complete().await;
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    answerer.wait_for_gathering_complete().await;
    let mut answer = answerer.create_answer().await?;
    answer.media_sections[0].direction = answer_direction;
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    tokio::try_join!(offerer.wait_for_connected(), answerer.wait_for_connected())?;
    Ok(())
}

/// A connected pair: `local` sends audio, `remote` answered `direction` and
/// counts the RTP it receives.
async fn pair(
    mode: TransportMode,
    direction: Direction,
) -> Result<(PeerConnection, PeerConnection, Arc<Ingress>)> {
    let local = pc(mode.clone());
    let remote = pc(mode);
    let (_source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    local.add_track(track, pcmu())?;
    let ingress = Arc::new(Ingress::default());
    remote.add_observer(ingress.clone());
    negotiate(&local, &remote, direction).await?;
    Ok((local, remote, ingress))
}

async fn send_dtmf_like_packets(pc: &PeerConnection) {
    let ssrc = pc.get_transceivers()[0].sender().expect("sender").ssrc();
    for seq in 0..20u16 {
        let packet = RtpPacket::new(RtpHeader::new(101, seq, 160 * seq as u32, ssrc), vec![0; 4]);
        pc.send_raw_rtp(packet).await.expect("send_raw_rtp");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn send_raw_rtp_follows_the_negotiated_direction() -> Result<()> {
    for mode in [
        TransportMode::Rtp,
        TransportMode::Srtp,
        TransportMode::WebRtc,
    ] {
        for (direction, delivered) in [
            (Direction::SendRecv, true),
            (Direction::RecvOnly, true),
            (Direction::SendOnly, false),
            (Direction::Inactive, false),
        ] {
            let (local, _remote, ingress) = pair(mode.clone(), direction).await?;
            send_dtmf_like_packets(&local).await;
            assert_eq!(
                ingress.count() > 0,
                delivered,
                "{mode:?}: remote answered {direction:?}: raw RTP delivered = {}",
                ingress.count()
            );
        }
    }
    Ok(())
}

/// source → relay_in ==rewrite bridge==> relay_out → sink. The sink's
/// answer decides whether relayed RTP may leave relay_out.
struct Relay {
    _pcs: (PeerConnection, PeerConnection),
    out: PeerConnection,
    sink: PeerConnection,
    feed: SampleStreamSource,
    ingress: Arc<Ingress>,
}

async fn relay(out_mode: TransportMode, sink_direction: Direction) -> Result<Relay> {
    let (source, relay_in) = (pc(TransportMode::Rtp), pc(TransportMode::Rtp));
    let (feed, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    source.add_track(track, pcmu())?;
    negotiate(&source, &relay_in, Direction::SendRecv).await?;

    let (out, sink) = (pc(out_mode.clone()), pc(out_mode));
    for side in [&out, &sink] {
        let (_unused, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
        side.add_track(track, pcmu())?;
    }
    let ingress = Arc::new(Ingress::default());
    sink.add_observer(ingress.clone());
    negotiate(&out, &sink, sink_direction).await?;

    let out_ssrc = out.get_transceivers()[0].sender().expect("sender").ssrc();
    relay_in.bridge_rtp_with_rewrite_to(
        &out,
        RtpRewriteBridgeParams {
            fixed_out_ssrc: Some(out_ssrc),
            ..Default::default()
        },
    )?;
    Ok(Relay {
        _pcs: (source, relay_in),
        out,
        sink,
        feed,
        ingress,
    })
}

async fn relayed_packets(sink_direction: Direction) -> Result<usize> {
    let relay = relay(TransportMode::Rtp, sink_direction).await?;
    feed_frames(&relay.feed).await;
    Ok(relay.ingress.count())
}

async fn feed_frames(feed: &SampleStreamSource) {
    for _ in 0..25 {
        let frame = AudioFrame {
            data: Bytes::from_static(&[0xFF; 160]),
            ..AudioFrame::default()
        };
        let _ = feed.send(MediaSample::Audio(frame));
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
}

#[tokio::test]
async fn relay_reaches_a_receiving_sink() -> Result<()> {
    assert!(relayed_packets(Direction::SendRecv).await? > 0);
    Ok(())
}

#[tokio::test]
async fn relay_stops_when_the_sink_does_not_receive() -> Result<()> {
    for direction in [Direction::SendOnly, Direction::Inactive] {
        assert_eq!(
            relayed_packets(direction).await?,
            0,
            "sink answered {direction:?}, yet relayed RTP reached it"
        );
    }
    Ok(())
}

/// The gate lifts again when a later answer allows sending.
#[tokio::test]
async fn send_raw_rtp_resumes_after_the_hold_is_released() -> Result<()> {
    let (local, remote, ingress) = pair(TransportMode::Rtp, Direction::Inactive).await?;
    send_dtmf_like_packets(&local).await;
    assert_eq!(ingress.count(), 0);

    // Offer sendrecv explicitly (independent of how re-offers pick their
    // direction).
    local.get_transceivers()[0].set_direction(rustrtc::TransceiverDirection::SendRecv);
    negotiate(&local, &remote, Direction::SendRecv).await?;
    send_dtmf_like_packets(&local).await;
    assert!(ingress.count() > 0, "raw RTP must flow after the resume");
    Ok(())
}

/// The sink holds relay_out (WebRtc) with a `sendonly` re-offer: raw and
/// relayed RTP stop, stay stopped across an ICE restart, and flow again once
/// the sink resumes.
#[tokio::test]
async fn remote_hold_stops_raw_and_relayed_rtp_until_resumed() -> Result<()> {
    let Relay {
        out,
        sink,
        feed,
        ingress,
        ..
    } = relay(TransportMode::WebRtc, Direction::SendRecv).await?;
    let raw_and_relayed = || async {
        let before = ingress.count();
        send_dtmf_like_packets(&out).await;
        let raw = ingress.count() - before;
        feed_frames(&feed).await;
        (raw, ingress.count() - before - raw)
    };

    let hold = sink.get_transceivers()[0].clone();
    hold.set_direction(TransceiverDirection::SendOnly);
    negotiate(&sink, &out, Direction::RecvOnly).await?;
    out.restart_ice().await?;
    negotiate(&out, &sink, Direction::SendOnly).await?;
    assert_eq!(raw_and_relayed().await, (0, 0), "held: (raw, relayed)");

    hold.set_direction(TransceiverDirection::SendRecv);
    negotiate(&sink, &out, Direction::SendRecv).await?;
    let (raw, relayed) = raw_and_relayed().await;
    assert!(
        raw > 0 && relayed > 0,
        "resumed: raw {raw}, relayed {relayed}"
    );
    Ok(())
}

/// Two bundled audio m-lines, only the first held: raw RTP on the held
/// stream's SSRC stops, the other stream keeps flowing on the shared
/// transport.
#[tokio::test]
async fn a_held_stream_inside_a_bundle_is_gated_by_ssrc() -> Result<()> {
    held_stream_is_gated_by_ssrc(RtcConfiguration::default(), 0).await
}

/// Without BUNDLE each m-line has its own transport; RTP with the held
/// second stream's SSRC must not leave on the first stream's transport either.
#[tokio::test]
async fn a_held_stream_is_gated_on_every_transport_without_bundle() -> Result<()> {
    let config = RtcConfiguration {
        transport_mode: TransportMode::Rtp,
        sdp_compatibility: rustrtc::SdpCompatibilityMode::LegacySip,
        ..RtcConfiguration::default()
    };
    held_stream_is_gated_by_ssrc(config, 1).await
}

/// Two audio m-lines, `held` answered inactive and the other recvonly;
/// send_raw_rtp sends both SSRCs on the first m-line's transport.
async fn held_stream_is_gated_by_ssrc(config: RtcConfiguration, held: usize) -> Result<()> {
    let local = PeerConnection::new(config.clone());
    let remote = PeerConnection::new(config);
    for _ in 0..2 {
        let (_source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
        local.add_track(
            track,
            RtpCodecParameters {
                payload_type: 111,
                name: "opus".to_string(),
                clock_rate: 48000,
                channels: 2,
            },
        )?;
    }
    let ingress = Arc::new(SsrcIngress::default());
    remote.add_observer(ingress.clone());

    let _ = local.create_offer().await?;
    local.wait_for_gathering_complete().await;
    let offer = local.create_offer().await?;
    local.set_local_description(offer.clone())?;
    remote.set_remote_description(offer).await?;
    let _ = remote.create_answer().await?;
    remote.wait_for_gathering_complete().await;
    let mut answer = remote.create_answer().await?;
    answer.media_sections[held].direction = Direction::Inactive;
    answer.media_sections[1 - held].direction = Direction::RecvOnly;
    remote.set_local_description(answer.clone())?;
    local.set_remote_description(answer).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(local.wait_for_connected(), remote.wait_for_connected())
    })
    .await??;

    let ssrcs: Vec<u32> = local
        .get_transceivers()
        .iter()
        .map(|t| t.sender().expect("sender").ssrc())
        .collect();
    for seq in 0..20u16 {
        for ssrc in &ssrcs {
            let packet = RtpPacket::new(
                RtpHeader::new(111, seq, 960 * seq as u32, *ssrc),
                vec![0; 4],
            );
            local.send_raw_rtp(packet).await?;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(ingress.count(ssrcs[held]), 0, "the held stream sent RTP");
    assert!(
        ingress.count(ssrcs[1 - held]) > 0,
        "the other stream must keep flowing"
    );
    Ok(())
}

#[derive(Default)]
struct SsrcIngress(std::sync::Mutex<std::collections::HashMap<u32, usize>>);

impl RtpObserver for SsrcIngress {
    fn on_ingress(&self, packet: &RtpPacket, _src: std::net::SocketAddr) {
        *self
            .0
            .lock()
            .unwrap()
            .entry(packet.header.ssrc)
            .or_default() += 1;
    }
}

impl SsrcIngress {
    fn count(&self, ssrc: u32) -> usize {
        self.0.lock().unwrap().get(&ssrc).copied().unwrap_or(0)
    }
}
