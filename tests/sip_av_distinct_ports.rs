//! Regression test: a plain RTP UAC offer with two media sections must keep
//! one distinct RTP port per m-line in the *local description*. It proposes
//! BUNDLE, but a peer without BUNDLE needs a port per m-line (RFC 8843 §7.2).
//!
//! rustpbx plain-RTP repro for the 0.4.11 regression: `set_local_description`
//! ran `update_local_description_on_gather`, whose non-WebRTC branch stamped
//! the primary (audio) transport's port onto every m-line — clobbering the
//! per-m-line direct transport ports (video advertised the audio port, while
//! its own transport listened elsewhere → strict SIP phones get a 488 /
//! media blackhole).

use rustrtc::config::{AudioCapability, MediaCapabilities, VideoCapability};
use rustrtc::media::MediaKind;
use rustrtc::media::track::sample_track;
use rustrtc::peer_connection::RtpCodecParameters;
use rustrtc::{PeerConnection, RtcConfiguration};

fn av_config() -> RtcConfiguration {
    let mut config = RtcConfiguration::sip();
    config.rtp_start_port = Some(20000);
    config.rtp_end_port = Some(20100);
    config.external_ips = vec!["127.0.0.1".parse().unwrap()];
    config.bind_ips = vec!["127.0.0.1".parse().unwrap()];
    config.media_capabilities = Some(MediaCapabilities {
        audio: vec![AudioCapability {
            payload_type: 0,
            codec_name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        }],
        video: vec![VideoCapability {
            payload_type: 99,
            codec_name: "H264".to_string(),
            clock_rate: 90000,
            fmtp: Some("packetization-mode=1;profile-level-id=42e01f".to_string()),
            rtcp_fbs: vec![],
            rtx_payload_type: None,
        }],
        application: None,
        image: vec![],
    });
    config
}

/// Mirror rustpbx-media's `LegInner` setup + UAC offer flow:
/// add_track (audio+video senders) → create_offer (prime gathering) →
/// create_offer (final) → set_local_description → local_description.
/// `label` selects which description the assertions run against.
async fn uac_local_sdp() -> (String, String) {
    let pc = PeerConnection::new(av_config());

    let (_, audio_track, _) = sample_track(MediaKind::Audio, 8);
    let _ = pc.add_track(
        audio_track,
        RtpCodecParameters {
            payload_type: 0,
            name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: 1,
        },
    );
    let (_, video_track, _) = sample_track(MediaKind::Video, 8);
    let _ = pc.add_track(
        video_track,
        RtpCodecParameters {
            payload_type: 99,
            name: "H264".to_string(),
            clock_rate: 90000,
            channels: 0,
        },
    );

    // prepare_offer(): first call primes ICE gathering, second builds the SDP.
    let _ = pc.create_offer().await.expect("prime offer");
    pc.wait_for_gathering_complete().await;
    let offer = pc.create_offer().await.expect("offer");
    let offer_sdp = offer.to_sdp_string();

    pc.set_local_description(offer).expect("set local");
    let local_sdp = pc
        .local_description()
        .expect("local description")
        .to_sdp_string();
    (offer_sdp, local_sdp)
}

fn ports_of(sdp: &str) -> (u16, u16) {
    let parse = |prefix: &str| {
        sdp.lines()
            .find(|l| l.starts_with(prefix))
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or_else(|| panic!("no {prefix} m-line in SDP:\n{sdp}"))
    };
    (parse("m=audio "), parse("m=video "))
}

fn assert_distinct_ports(sdp: &str, what: &str) {
    let (audio, video) = ports_of(sdp);
    assert_ne!(
        audio, video,
        "{what}: audio and video m-lines must use distinct ports:\n{sdp}"
    );
    assert!(
        (20000..=20100).contains(&audio) && (20000..=20100).contains(&video),
        "{what}: ports outside the configured range (audio={audio} video={video}):\n{sdp}"
    );
    assert!(
        sdp.contains("a=group:BUNDLE") && !sdp.contains("a=bundle-only"),
        "{what}: the offer proposes BUNDLE, with a transport per m-line:\n{sdp}"
    );
}

#[tokio::test]
async fn rtp_range_av_local_description_keeps_distinct_ports() {
    for round in 0..10 {
        let (offer_sdp, local_sdp) = uac_local_sdp().await;
        let what = format!("round {round}");
        assert_distinct_ports(&offer_sdp, &what);
        // The committed local description is what goes on the wire — the
        // 0.4.11 regression corrupted exactly this one.
        assert_distinct_ports(&local_sdp, &what);
    }
}
