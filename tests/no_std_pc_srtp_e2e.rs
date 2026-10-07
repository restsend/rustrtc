#![cfg(not(feature = "std"))]

//! G1 capstone: the PeerConnection delivery surface rtcembed targets —
//! `TransportMode::Srtp` (SDES-SRTP, plan D6's embedded surface) — driven
//! end to end over the mock runtime: offer/answer with `a=crypto`
//! negotiation, direct transport through the UDP bind factory, then SRTP
//! protected media flowing PC1 → PC2 with payloads verified after
//! decryption.
//!
//! Mirrors the std-side `tests/rtp_mode_test.rs` flow, minus tokio.

mod common;

use std::sync::Arc;

use common::{drive, drive_until, install_mock_platform};
use rustrtc::config::{RtcConfiguration, TransportMode};
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::media::MediaKind as TrackMediaKind;
use rustrtc::media::MediaStreamTrack;
use rustrtc::peer_connection::{
    PeerConnection, PeerConnectionState, RtpCodecParameters, RtpSender, TransceiverDirection,
};
use rustrtc::sdp::MediaKind;

fn srtp_agent(start: u16, end: u16) -> PeerConnection {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Srtp;
    config.bind_ip = Some("127.0.0.1".to_string());
    config.rtp_start_port = Some(start);
    config.rtp_end_port = Some(end);
    PeerConnection::new(config)
}

#[test]
fn two_no_std_pcs_exchange_srtp_media_over_the_seams() {
    let _ = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .try_init();
    install_mock_platform();

    let pc1 = srtp_agent(50_000, 50_020);
    let pc2 = srtp_agent(51_000, 51_020);

    // PC1 sends video; PC2 receives.
    let (source, track, _) =
        rustrtc::media::track::sample_track(TrackMediaKind::Video, 100);
    let source = Arc::new(source);
    let _sender: Arc<RtpSender> = pc1
        .add_track(
            track.clone(),
            RtpCodecParameters {
                payload_type: 96,
                name: "VP8".to_string(),
                clock_rate: 90_000,
                channels: 0,
            },
        )
        .expect("add sender track");
    pc2.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    // O/A exchange. Each step is a short future driven against the shared
    // runtime (polls PC internals + advances the logical clock).
    let _ = drive(pc1.create_offer(), 5_000).expect("trigger offer");
    let offer = drive(pc1.create_offer(), 5_000)
        .expect("offer")
        .expect("offer result");
    let offer_sdp = offer.to_sdp_string();
    assert!(
        offer_sdp.contains("a=crypto"),
        "Srtp mode offers must carry SDES keying (a=crypto):\n{offer_sdp}"
    );
    eprintln!("=== OFFER SDP ===\n{offer_sdp}");
    pc1.set_local_description(offer.clone()).expect("set local offer");
    drive(pc2.set_remote_description(offer), 5_000)
        .expect("set remote offer")
        .expect("set remote offer result");

    let _ = drive(pc2.create_answer(), 5_000).expect("trigger answer");
    let answer = drive(pc2.create_answer(), 5_000)
        .expect("answer")
        .expect("answer result");
    let answer_sdp = answer.to_sdp_string();
    assert!(
        answer_sdp.contains("a=crypto"),
        "Srtp mode answers must carry SDES keying (a=crypto):\n{answer_sdp}"
    );
    eprintln!("=== ANSWER SDP ===\n{answer_sdp}");
    pc2.set_local_description(answer.clone()).expect("set local answer");
    drive(pc1.set_remote_description(answer), 5_000)
        .expect("set remote answer")
        .expect("set remote answer result");

    // Both PCs must reach Connected (SDES keys exchanged, transports up).
    let state1 = pc1.subscribe_peer_state();
    let state2 = pc2.subscribe_peer_state();
    let connected = drive_until(
        || {
            *state1.borrow() == PeerConnectionState::Connected
                && *state2.borrow() == PeerConnectionState::Connected
        },
        30_000,
    );
    eprintln!(
        "states after drive: pc1={:?} pc2={:?}",
        *state1.borrow(),
        *state2.borrow()
    );
    assert!(connected, "both PCs must reach Connected");

    // PC1 streams 40 marked video frames; PC2 must decrypt and deliver them.
    let sender_source = source.clone();
    common::keep_task(Box::new(async move {
        for seq in 0..40u8 {
            let frame = VideoFrame {
                rtp_timestamp: seq as u32 * 3000,
                data: bytes::Bytes::from(vec![seq; 100]),
                is_last_packet: true,
                ..Default::default()
            };
            if let Err(e) = sender_source.send(MediaSample::Video(frame)) {
                eprintln!("[send] source.send failed at seq={seq}: {e}");
                break;
            }
            // Yield to the driver between packets (pacing like a real track).
            rustrtc::platform::task::sleep(std::time::Duration::from_millis(10)).await;
        }
        eprintln!("[send] send loop finished");
    }));

    let transceivers = pc2.get_transceivers();
    let receiver = transceivers[0].receiver().expect("receiver");
    let track_remote = receiver.track();
    let received: Arc<std::sync::Mutex<Vec<(u8, u32)>>> =
        Arc::new(std::sync::Mutex::new(Vec::new()));
    let seen = received.clone();
    common::keep_task(Box::new(async move {
        while let Ok(sample) = track_remote.recv().await {
            if let MediaSample::Video(frame) = sample {
                let marker = frame.data.first().copied().unwrap_or(0xFF);
                seen.lock().unwrap().push((marker, frame.rtp_timestamp));
                if seen.lock().unwrap().len() >= 20 {
                    break;
                }
            }
        }
    }));

    let got = drive_until(
        || received.lock().unwrap().len() >= 20,
        30_000,
    );
    let packets = received.lock().unwrap().clone();
    eprintln!(
        "srtp e2e: got={got} packets={} first_markers={:?} sim_clock={}ms",
        packets.len(),
        &packets[..packets.len().min(5)],
        common::clock(),
    );
    assert!(got, "PC2 must receive ≥20 decrypted media packets");
    // Payloads survive the SRTP round-trip in order: markers 0,1,2,...
    for (i, (marker, _)) in packets.iter().enumerate() {
        assert_eq!(
            *marker, i as u8,
            "decrypted payload marker must match the sent sequence"
        );
    }
}
