//! A sender transmits RTP only while the negotiated direction allows it
//! (RFC 3264 §6.1 / §7, RFC 8829 §5.11): not after the remote answered
//! `recvonly` / `inactive`, and not after we answered a remote `sendonly` /
//! `inactive` offer. Sending resumes when a later negotiation allows it.
use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{AudioFrame, MediaSample};
use rustrtc::media::track::{SampleStreamSource, sample_track};
use rustrtc::peer_connection::RtpTransceiver;
use rustrtc::sdp::Direction;
use rustrtc::{
    PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection, TransportMode,
};
use std::sync::Arc;
use std::time::Duration;

fn opus() -> RtpCodecParameters {
    RtpCodecParameters {
        payload_type: 111,
        name: "opus".to_string(),
        clock_rate: 48000,
        channels: 2,
    }
}

fn pc(mode: TransportMode) -> PeerConnection {
    PeerConnection::new(RtcConfiguration {
        transport_mode: mode,
        ..RtcConfiguration::default()
    })
}

/// One offer/answer exchange. `answer_direction`, when set, is the direction
/// the answer states for the first m-line.
async fn exchange(
    offerer: &PeerConnection,
    answerer: &PeerConnection,
    answer_direction: Option<Direction>,
) -> Result<()> {
    let _ = offerer.create_offer().await?;
    offerer.wait_for_gathering_complete().await;
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    answerer.wait_for_gathering_complete().await;
    let mut answer = answerer.create_answer().await?;
    if let Some(direction) = answer_direction {
        answer.media_sections[0].direction = direction;
    }
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    Ok(())
}

/// Sends audio frames from `source` in the background until dropped.
struct Pump(tokio::task::JoinHandle<()>);

impl Pump {
    fn start(source: SampleStreamSource) -> Self {
        Self(tokio::spawn(async move {
            loop {
                let frame = AudioFrame {
                    data: Bytes::from_static(&[0xAA; 20]),
                    ..AudioFrame::default()
                };
                if source.send(MediaSample::Audio(frame)).is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }))
    }
}

impl Drop for Pump {
    fn drop(&mut self) {
        self.0.abort();
    }
}

fn packets_sent(transceiver: &Arc<RtpTransceiver>) -> u32 {
    transceiver.sender().expect("sender").packets_sent()
}

/// Whether `transceiver`'s sender puts RTP on the wire within `window`.
async fn sends_within(transceiver: &Arc<RtpTransceiver>, window: Duration) -> bool {
    let before = packets_sent(transceiver);
    tokio::time::sleep(window).await;
    packets_sent(transceiver) > before
}

async fn remote_receives(transceiver: &Arc<RtpTransceiver>) -> bool {
    let track = transceiver.receiver().expect("receiver").track();
    matches!(
        tokio::time::timeout(Duration::from_secs(3), track.recv()).await,
        Ok(Ok(MediaSample::Audio(_)))
    )
}

async fn no_rtp_after_remote_answers(mode: TransportMode, direction: Direction) -> Result<()> {
    let pc1 = pc(mode.clone());
    let pc2 = pc(mode.clone());
    let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    exchange(&pc1, &pc2, Some(direction)).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    let _pump = Pump::start(source);

    let t1 = pc1.get_transceivers()[0].clone();
    assert!(
        !sends_within(&t1, Duration::from_millis(1500)).await,
        "{mode:?}: the remote answered {direction:?}, yet our sender sent RTP"
    );
    let t2 = pc2.get_transceivers()[0].clone();
    assert!(
        !remote_receives(&t2).await,
        "{mode:?}: the remote answered {direction:?}, yet it received RTP"
    );
    Ok(())
}

#[tokio::test]
async fn no_rtp_after_remote_answers_inactive_webrtc() -> Result<()> {
    no_rtp_after_remote_answers(TransportMode::WebRtc, Direction::Inactive).await
}

#[tokio::test]
async fn rtp_flows_when_the_remote_answers_recvonly_webrtc() -> Result<()> {
    // Guard: `recvonly` from the answerer means it receives — we send.
    let pc1 = pc(TransportMode::WebRtc);
    let pc2 = pc(TransportMode::WebRtc);
    let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    exchange(&pc1, &pc2, Some(Direction::RecvOnly)).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    let _pump = Pump::start(source);
    let t2 = pc2.get_transceivers()[0].clone();
    assert!(
        remote_receives(&t2).await,
        "a recvonly answerer must get RTP"
    );
    Ok(())
}

#[tokio::test]
async fn no_rtp_after_remote_answers_sendonly_rtp() -> Result<()> {
    no_rtp_after_remote_answers(TransportMode::Rtp, Direction::SendOnly).await
}

#[tokio::test]
async fn no_rtp_after_remote_answers_inactive_rtp() -> Result<()> {
    no_rtp_after_remote_answers(TransportMode::Rtp, Direction::Inactive).await
}

/// The remote holds us (`sendonly` re-offer), we answer `recvonly` and stop
/// sending; the remote resumes (`sendrecv` re-offer) and we send again.
async fn remote_hold_and_resume(mode: TransportMode) -> Result<()> {
    let pc1 = pc(mode.clone());
    let pc2 = pc(mode.clone());
    let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    let (_back, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc2.add_track(track, opus())?;
    exchange(&pc1, &pc2, None).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    let _pump = Pump::start(source);

    let t1 = pc1.get_transceivers()[0].clone();
    let t2 = pc2.get_transceivers()[0].clone();
    assert!(remote_receives(&t2).await, "{mode:?}: media before hold");

    // pc2 puts pc1 on hold.
    t2.set_direction(TransceiverDirection::SendOnly);
    exchange(&pc2, &pc1, None).await?;
    assert!(
        !sends_within(&t1, Duration::from_millis(1500)).await,
        "{mode:?}: we answered a sendonly hold, yet our sender sent RTP"
    );

    // pc2 resumes.
    t2.set_direction(TransceiverDirection::SendRecv);
    exchange(&pc2, &pc1, None).await?;
    assert!(
        sends_within(&t1, Duration::from_millis(1500)).await,
        "{mode:?}: the hold was released, but our sender did not resume"
    );
    Ok(())
}

#[tokio::test]
async fn no_rtp_after_remote_answers_inactive_srtp() -> Result<()> {
    no_rtp_after_remote_answers(TransportMode::Srtp, Direction::Inactive).await
}

#[tokio::test]
async fn remote_hold_and_resume_rtp() -> Result<()> {
    remote_hold_and_resume(TransportMode::Rtp).await
}

#[tokio::test]
async fn remote_hold_and_resume_webrtc() -> Result<()> {
    remote_hold_and_resume(TransportMode::WebRtc).await
}

/// A transceiver whose negotiation forbids sending also gates a sender
/// installed on it afterwards.
#[tokio::test]
async fn a_sender_installed_after_an_inactive_answer_stays_quiet() -> Result<()> {
    let pc1 = pc(TransportMode::Rtp);
    let pc2 = pc(TransportMode::Rtp);
    let (_first, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    exchange(&pc1, &pc2, Some(Direction::Inactive)).await?;

    let t1 = pc1.get_transceivers()[0].clone();
    let ssrc = t1.sender().expect("sender").ssrc();
    let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    let sender = rustrtc::peer_connection::RtpSender::builder(track, ssrc)
        .params(opus())
        .build();
    t1.set_sender(Some(sender));
    let _pump = Pump::start(source);
    assert!(!sends_within(&t1, Duration::from_millis(1500)).await);
    Ok(())
}

/// Inside a BUNDLE group only the held m= line stops; its sibling on the same
/// transport keeps sending.
#[tokio::test]
async fn one_held_stream_in_a_bundle_stops_alone() -> Result<()> {
    let pc1 = pc(TransportMode::WebRtc);
    let pc2 = pc(TransportMode::WebRtc);
    let (held, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    let (open, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    exchange(&pc1, &pc2, Some(Direction::Inactive)).await?;
    let answer = pc1.remote_description().expect("answer").to_sdp_string();
    assert!(answer.contains("a=group:BUNDLE 0 1"), "{answer}");
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    let (_held, _open) = (Pump::start(held), Pump::start(open));

    let t1 = pc1.get_transceivers();
    assert!(!sends_within(&t1[0], Duration::from_millis(1500)).await);
    assert!(sends_within(&t1[1], Duration::from_millis(1500)).await);
    Ok(())
}

/// The remote holds us; our ICE restart re-offer keeps the hold in force
/// (the answer still says `sendonly` for the remote); the remote resumes and
/// we send again over the restarted ICE session.
#[tokio::test]
async fn remote_hold_survives_our_ice_restart() -> Result<()> {
    let pc1 = pc(TransportMode::WebRtc);
    let pc2 = pc(TransportMode::WebRtc);
    let (source, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    let (_back, track, _) = sample_track(rustrtc::media::MediaKind::Audio, 100);
    pc2.add_track(track, opus())?;
    exchange(&pc1, &pc2, None).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    let _pump = Pump::start(source);
    let t1 = pc1.get_transceivers()[0].clone();
    let t2 = pc2.get_transceivers()[0].clone();

    t2.set_direction(TransceiverDirection::SendOnly);
    exchange(&pc2, &pc1, None).await?;
    pc1.restart_ice().await?;
    exchange(&pc1, &pc2, None).await?;
    assert!(
        !sends_within(&t1, Duration::from_millis(1500)).await,
        "an ICE restart re-offer lifted the remote's hold"
    );

    t2.set_direction(TransceiverDirection::SendRecv);
    exchange(&pc2, &pc1, None).await?;
    assert!(
        sends_within(&t1, Duration::from_millis(3000)).await,
        "no RTP after the remote resumed"
    );
    Ok(())
}
