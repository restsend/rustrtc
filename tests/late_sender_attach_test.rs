//! A sender installed with `RtpTransceiver::set_sender` must reach the wire no
//! matter when it is installed relative to transport setup:
//!
//! * before the transport exists (connected later by the transport-up path),
//! * after the transport is up on a transceiver from the initial negotiation,
//! * on a transceiver created while the transport is already up, either from
//!   a remote re-offer or by a local `add_transceiver` before re-offering.
use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{AudioFrame, MediaSample};
use rustrtc::media::track::{SampleStreamSource, sample_track};
use rustrtc::peer_connection::{RtpSender, RtpTransceiver};
use rustrtc::{
    MediaKind, PeerConnection, RtcConfiguration, RtpCodecParameters, TransceiverDirection,
    TransportMode,
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

/// Build a standalone sender and install it on `transceiver` via `set_sender`.
fn install_sender(transceiver: &Arc<RtpTransceiver>, ssrc: u32) -> SampleStreamSource {
    let (source, track, _) = sample_track(rustrtc::media::frame::MediaKind::Audio, 100);
    let sender = RtpSender::builder(track, ssrc)
        .stream_id("stream".to_string())
        .params(opus())
        .build();
    transceiver.set_sender(Some(sender));
    source
}

async fn negotiate_initial(offerer: &PeerConnection, answerer: &PeerConnection) -> Result<()> {
    let _ = offerer.create_offer().await?;
    offerer.wait_for_gathering_complete().await;
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;
    let _ = answerer.create_answer().await?;
    answerer.wait_for_gathering_complete().await;
    let answer = answerer.create_answer().await?;
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    tokio::try_join!(offerer.wait_for_connected(), answerer.wait_for_connected())?;
    Ok(())
}

/// Push frames from `source` until one arrives on `transceiver`'s receiver.
async fn assert_media_flows(
    source: SampleStreamSource,
    transceiver: &Arc<RtpTransceiver>,
    what: &str,
) {
    let track = transceiver.receiver().expect("receiver").track();
    let pump = tokio::spawn(async move {
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
    });
    let received = tokio::time::timeout(Duration::from_secs(3), track.recv()).await;
    pump.abort();
    assert!(
        matches!(received, Ok(Ok(MediaSample::Audio(_)))),
        "{what}: no RTP from the sender installed via set_sender reached the remote peer"
    );
}

async fn sender_installed_before_transport_up(mode: TransportMode) -> Result<()> {
    let config = || RtcConfiguration {
        transport_mode: mode.clone(),
        ..RtcConfiguration::default()
    };
    let pc1 = PeerConnection::new(config());
    let pc2 = PeerConnection::new(config());

    let t1 = pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let source = install_sender(&t1, 11111);
    pc2.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

    negotiate_initial(&pc1, &pc2).await?;

    let t2 = pc2.get_transceivers()[0].clone();
    assert_media_flows(source, &t2, &format!("{mode:?} pre-transport sender")).await;
    Ok(())
}

#[tokio::test]
async fn sender_installed_before_transport_up_webrtc() -> Result<()> {
    sender_installed_before_transport_up(TransportMode::WebRtc).await
}

#[tokio::test]
async fn sender_installed_before_transport_up_rtp() -> Result<()> {
    sender_installed_before_transport_up(TransportMode::Rtp).await
}

#[tokio::test]
async fn sender_replaced_after_transport_up() -> Result<()> {
    let pc1 = PeerConnection::new(RtcConfiguration::default());
    let pc2 = PeerConnection::new(RtcConfiguration::default());

    let (_initial, track, _) = sample_track(rustrtc::media::frame::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    pc2.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
    negotiate_initial(&pc1, &pc2).await?;

    // Replace-track on a live transceiver keeps the SSRC the remote expects.
    let t1 = pc1.get_transceivers()[0].clone();
    let ssrc = t1.sender().expect("sender").ssrc();
    let source = install_sender(&t1, ssrc);

    let t2 = pc2.get_transceivers()[0].clone();
    assert_media_flows(source, &t2, "replacement on live transceiver").await;
    Ok(())
}

/// A remote re-offer adds an m-line while the transport is already up. The
/// answerer installs its sender on the transceiver created from that offer
/// (echo/SFU style) — it must be connected to the running transport.
async fn sender_installed_on_transceiver_from_reoffer(mode: TransportMode) -> Result<()> {
    let config = || RtcConfiguration {
        transport_mode: mode.clone(),
        ..RtcConfiguration::default()
    };
    let pc1 = PeerConnection::new(config());
    let pc2 = PeerConnection::new(config());

    let (_first, track, _) = sample_track(rustrtc::media::frame::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    // pc2 sends on the first m-line too, so each pc1 receiver has a known SSRC.
    let t2 = pc2.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _first_back = install_sender(&t2, 11111);
    negotiate_initial(&pc1, &pc2).await?;
    assert_eq!(pc2.get_transceivers().len(), 1);

    // Re-offer with a second audio m-line.
    let (_second, track, _) = sample_track(rustrtc::media::frame::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    let second = pc1.get_transceivers()[1].clone();
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;

    let created = pc2.get_transceivers();
    assert_eq!(created.len(), 2, "re-offer should create a transceiver");
    let source = install_sender(&created[1], 22222);

    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    assert_media_flows(source, &second, &format!("{mode:?} re-offer transceiver")).await;
    Ok(())
}

#[tokio::test]
async fn sender_installed_on_transceiver_from_reoffer_webrtc() -> Result<()> {
    sender_installed_on_transceiver_from_reoffer(TransportMode::WebRtc).await
}

#[tokio::test]
async fn sender_installed_on_transceiver_from_reoffer_srtp() -> Result<()> {
    sender_installed_on_transceiver_from_reoffer(TransportMode::Srtp).await
}

#[tokio::test]
async fn sender_installed_on_transceiver_from_reoffer_rtp() -> Result<()> {
    sender_installed_on_transceiver_from_reoffer(TransportMode::Rtp).await
}

/// The local side adds a transceiver after the transport is up and installs
/// its sender via `set_sender` before re-offering.
async fn sender_installed_on_transceiver_added_after_connect(mode: TransportMode) -> Result<()> {
    let config = || RtcConfiguration {
        transport_mode: mode.clone(),
        ..RtcConfiguration::default()
    };
    let pc1 = PeerConnection::new(config());
    let pc2 = PeerConnection::new(config());

    let (_first, track, _) = sample_track(rustrtc::media::frame::MediaKind::Audio, 100);
    pc1.add_track(track, opus())?;
    negotiate_initial(&pc1, &pc2).await?;

    let added = pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let source = install_sender(&added, 33333);

    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    let created = pc2.get_transceivers();
    assert_eq!(created.len(), 2, "re-offer should create a transceiver");
    assert_media_flows(
        source,
        &created[1],
        &format!("{mode:?} transceiver added after connect"),
    )
    .await;
    Ok(())
}

#[tokio::test]
async fn sender_installed_on_transceiver_added_after_connect_webrtc() -> Result<()> {
    sender_installed_on_transceiver_added_after_connect(TransportMode::WebRtc).await
}

#[tokio::test]
async fn sender_installed_on_transceiver_added_after_connect_srtp() -> Result<()> {
    sender_installed_on_transceiver_added_after_connect(TransportMode::Srtp).await
}

#[tokio::test]
async fn sender_installed_on_transceiver_added_after_connect_rtp() -> Result<()> {
    sender_installed_on_transceiver_added_after_connect(TransportMode::Rtp).await
}
