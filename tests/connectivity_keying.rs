#![cfg(feature = "std")]

//! Every `Connectivity` with every `Keying`, end to end: two peer
//! connections negotiate on loopback and send media both ways. ICE-lite is
//! tested against ICE-lite and against full ICE, offering and answering.
use anyhow::Result;
use bytes::Bytes;
use rustrtc::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode, VideoCapability};
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{AudioFrame, MediaSample, VideoFrame};
use rustrtc::media::track::{SampleStreamSource, sample_track};
use rustrtc::peer_connection::{RtpSender, RtpTransceiver};
use rustrtc::{
    Connectivity, Keying, MediaKind, PeerConnection, RtcConfiguration, RtpCodecParameters, SdpType,
    SessionDescription, TransceiverDirection,
};
use std::sync::Arc;
use std::time::Duration;

fn config(connectivity: Connectivity, keying: Keying) -> RtcConfiguration {
    RtcConfiguration {
        connectivity,
        keying,
        webrtc_extensions: false,
        bind_ips: vec!["127.0.0.1".parse().unwrap()],
        media_capabilities: Some(MediaCapabilities {
            audio: vec![AudioCapability::pcmu()],
            video: vec![VideoCapability {
                rtcp_fbs: vec![],
                ..VideoCapability::default()
            }],
            application: None,
            image: vec![],
        }),
        ..RtcConfiguration::default()
    }
}

fn params(kind: MediaKind) -> RtpCodecParameters {
    match kind {
        MediaKind::Video => RtpCodecParameters {
            payload_type: 96,
            name: "VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
        },
        _ => RtpCodecParameters {
            payload_type: 0,
            name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: 1,
        },
    }
}

fn track_kind(kind: MediaKind) -> rustrtc::media::frame::MediaKind {
    match kind {
        MediaKind::Video => rustrtc::media::frame::MediaKind::Video,
        _ => rustrtc::media::frame::MediaKind::Audio,
    }
}

fn install_sender(transceiver: &Arc<RtpTransceiver>, ssrc: u32) -> SampleStreamSource {
    let kind = transceiver.kind();
    let (source, track, _) = sample_track(track_kind(kind), 100);
    let sender = RtpSender::builder(track, ssrc)
        .stream_id("stream".to_string())
        .params(params(kind))
        .build();
    transceiver.set_sender(Some(sender));
    source
}

/// Push frames from `source` until one arrives on `transceiver`'s receiver.
async fn media_flows(source: SampleStreamSource, transceiver: &Arc<RtpTransceiver>) -> bool {
    let kind = transceiver.kind();
    let track = transceiver.receiver().expect("receiver").track();
    let pump = tokio::spawn(async move {
        for n in 0u32.. {
            let sample = match kind {
                MediaKind::Video => MediaSample::Video(VideoFrame {
                    rtp_timestamp: n * 3000,
                    data: Bytes::from(vec![0u8; 100]),
                    is_last_packet: true,
                    ..VideoFrame::default()
                }),
                _ => MediaSample::Audio(AudioFrame {
                    data: Bytes::from_static(&[0xAA; 160]),
                    ..AudioFrame::default()
                }),
            };
            if source.send(sample).is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });
    let received = tokio::time::timeout(Duration::from_secs(5), track.recv()).await;
    pump.abort();
    matches!(received, Ok(Ok(_)))
}

fn has_attr(sdp: &str, attr: &str) -> bool {
    sdp.lines().any(|line| line.starts_with(attr))
}

/// What a description of `connectivity` and `keying` must carry.
fn check_description(sdp: &str, connectivity: Connectivity, keying: Keying, what: &str) {
    let profile = match keying {
        Keying::None => "RTP/AVP",
        Keying::Sdes => "RTP/SAVP",
        Keying::Dtls => "UDP/TLS/RTP/SAVPF",
    };
    for line in sdp.lines().filter(|line| line.starts_with("m=")) {
        assert_eq!(
            line.split_whitespace().nth(2),
            Some(profile),
            "{what}: profile:\n{sdp}"
        );
    }
    assert_eq!(
        has_attr(sdp, "a=crypto:"),
        keying == Keying::Sdes,
        "{what}: a=crypto:\n{sdp}"
    );
    assert_eq!(
        has_attr(sdp, "a=fingerprint:"),
        keying == Keying::Dtls,
        "{what}: a=fingerprint:\n{sdp}"
    );
    assert_eq!(
        has_attr(sdp, "a=ice-ufrag:"),
        connectivity != Connectivity::Sdp,
        "{what}: a=ice-ufrag:\n{sdp}"
    );
    assert_eq!(
        has_attr(sdp, "a=ice-lite"),
        connectivity == Connectivity::IceLite,
        "{what}: a=ice-lite:\n{sdp}"
    );
}

/// The offerer adds `kinds`, one m-line each; both sides negotiate, check
/// their descriptions, connect, and send media both ways on every m-line.
async fn call_with(
    offerer: Connectivity,
    answerer: Connectivity,
    keying: Keying,
    kinds: &[MediaKind],
    sdp_compatibility: SdpCompatibilityMode,
) -> Result<()> {
    let what = format!("{offerer:?} offers to {answerer:?}, {keying:?}");
    let mut config1 = config(offerer, keying);
    let mut config2 = config(answerer, keying);
    config1.sdp_compatibility = sdp_compatibility.clone();
    config2.sdp_compatibility = sdp_compatibility;
    let pc1 = PeerConnection::new(config1);
    let pc2 = PeerConnection::new(config2);
    for &kind in kinds {
        pc1.add_transceiver(kind, TransceiverDirection::SendRecv);
        pc2.add_transceiver(kind, TransceiverDirection::SendRecv);
    }

    let _ = pc1.create_offer().await?;
    pc1.wait_for_gathering_complete().await;
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    let offer = offer.to_sdp_string();
    check_description(&offer, offerer, keying, &format!("{what}: offer"));
    pc2.set_remote_description(SessionDescription::parse(SdpType::Offer, &offer)?)
        .await?;
    let _ = pc2.create_answer().await?;
    pc2.wait_for_gathering_complete().await;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    let answer = answer.to_sdp_string();
    check_description(&answer, answerer, keying, &format!("{what}: answer"));
    pc1.set_remote_description(SessionDescription::parse(SdpType::Answer, &answer)?)
        .await?;

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())
    })
    .await
    .map_err(|_| anyhow::anyhow!("{what}: not connected"))??;

    let transceivers1 = pc1.get_transceivers();
    let transceivers2 = pc2.get_transceivers();
    assert_eq!(transceivers1.len(), kinds.len(), "{what}");
    assert_eq!(transceivers2.len(), kinds.len(), "{what}");
    for (index, (t1, t2)) in transceivers1.iter().zip(&transceivers2).enumerate() {
        let ssrc = 1000 * (index as u32 + 1);
        let source1 = install_sender(t1, ssrc + 1);
        let source2 = install_sender(t2, ssrc + 2);
        let kind = t1.kind();
        assert!(
            media_flows(source1, t2).await,
            "{what}: {kind:?} offerer to answerer"
        );
        assert!(
            media_flows(source2, t1).await,
            "{what}: {kind:?} answerer to offerer"
        );
    }
    pc1.close();
    pc2.close();
    Ok(())
}

async fn call(offerer: Connectivity, answerer: Connectivity, keying: Keying) -> Result<()> {
    call_with(
        offerer,
        answerer,
        keying,
        &[MediaKind::Audio],
        SdpCompatibilityMode::Standard,
    )
    .await
}

/// Audio and video, each on its own transport: no BUNDLE.
async fn call_without_bundle(keying: Keying) -> Result<()> {
    call_with(
        Connectivity::Sdp,
        Connectivity::Sdp,
        keying,
        &[MediaKind::Audio, MediaKind::Video],
        SdpCompatibilityMode::LegacySip,
    )
    .await
}

#[tokio::test]
async fn sdp_none() -> Result<()> {
    call(Connectivity::Sdp, Connectivity::Sdp, Keying::None).await
}

#[tokio::test]
async fn sdp_sdes() -> Result<()> {
    call(Connectivity::Sdp, Connectivity::Sdp, Keying::Sdes).await
}

#[tokio::test]
#[ignore = "DTLS does not run on direct transports yet"]
async fn sdp_dtls() -> Result<()> {
    call(Connectivity::Sdp, Connectivity::Sdp, Keying::Dtls).await
}

#[tokio::test]
async fn ice_lite_none() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::IceLite, Keying::None).await
}

#[tokio::test]
async fn ice_lite_sdes() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::IceLite, Keying::Sdes).await
}

#[tokio::test]
#[ignore = "DTLS does not run on direct transports yet"]
async fn ice_lite_dtls() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::IceLite, Keying::Dtls).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_none() -> Result<()> {
    call(Connectivity::Ice, Connectivity::Ice, Keying::None).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_sdes() -> Result<()> {
    call(Connectivity::Ice, Connectivity::Ice, Keying::Sdes).await
}

#[tokio::test]
async fn ice_dtls() -> Result<()> {
    call(Connectivity::Ice, Connectivity::Ice, Keying::Dtls).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_offers_to_ice_lite_none() -> Result<()> {
    call(Connectivity::Ice, Connectivity::IceLite, Keying::None).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_offers_to_ice_lite_sdes() -> Result<()> {
    call(Connectivity::Ice, Connectivity::IceLite, Keying::Sdes).await
}

#[tokio::test]
#[ignore = "DTLS does not run on direct transports yet"]
async fn ice_offers_to_ice_lite_dtls() -> Result<()> {
    call(Connectivity::Ice, Connectivity::IceLite, Keying::Dtls).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_lite_offers_to_ice_none() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::Ice, Keying::None).await
}

#[tokio::test]
#[ignore = "full ICE always runs DTLS"]
async fn ice_lite_offers_to_ice_sdes() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::Ice, Keying::Sdes).await
}

#[tokio::test]
#[ignore = "DTLS does not run on direct transports yet"]
async fn ice_lite_offers_to_ice_dtls() -> Result<()> {
    call(Connectivity::IceLite, Connectivity::Ice, Keying::Dtls).await
}

#[tokio::test]
async fn without_bundle_none() -> Result<()> {
    call_without_bundle(Keying::None).await
}

#[tokio::test]
async fn without_bundle_sdes() -> Result<()> {
    call_without_bundle(Keying::Sdes).await
}

#[tokio::test]
#[ignore = "DTLS does not run on direct transports yet"]
async fn without_bundle_dtls() -> Result<()> {
    call_without_bundle(Keying::Dtls).await
}
