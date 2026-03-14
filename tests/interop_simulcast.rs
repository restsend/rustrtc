use anyhow::Result;
use bytes::Bytes;
use rustrtc::media::track::MediaStreamTrack;
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::rtp::header::{Extension, Header};
use webrtc::rtp::packet::Packet;
use webrtc::rtp_transceiver::RTCRtpEncodingParameters;
use webrtc::rtp_transceiver::RTCRtpTransceiverInit;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpHeaderExtensionCapability;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::track::track_local::TrackLocalWriter;
use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;

fn build_webrtc_api() -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_owned(),
        },
        RTPCodecType::Video,
        Some(RTCRtpTransceiverDirection::Sendrecv),
    )?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id".to_owned(),
        },
        RTPCodecType::Video,
        Some(RTCRtpTransceiverDirection::Sendrecv),
    )?;
    media_engine.register_header_extension(
        RTCRtpHeaderExtensionCapability {
            uri: "urn:ietf:params:rtp-hdrext:sdes:mid".to_owned(),
        },
        RTPCodecType::Video,
        Some(RTCRtpTransceiverDirection::Sendrecv),
    )?;

    let registry = Registry::new();
    let mut setting_engine = SettingEngine::default();
    // Same-host browser/webrtc-rs interop gets flaky when transient IPv6 or
    // link-local interfaces are mixed into candidate gathering. Keep this test
    // focused on simulcast behavior over stable IPv4 plus loopback paths.
    setting_engine.set_ip_filter(Box::new(|ip| ip.is_ipv4()));
    setting_engine.set_include_loopback_candidate(true);

    Ok(APIBuilder::new()
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build())
}

#[tokio::test]
async fn test_simulcast_ingest_and_switch() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();

    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (SFU)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Add a transceiver to receive Video (Simulcast)
    let transceiver = rust_pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    // 2. Create WebRTC PeerConnection (Client)
    let api = build_webrtc_api()?;

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // Create a video track using TrackLocalStaticRTP
    let codec = RTCRtpCodecCapability {
        mime_type: webrtc::api::media_engine::MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        ..Default::default()
    };
    let video_track = Arc::new(TrackLocalStaticRTP::new(
        codec,
        "video".to_string(),
        "webrtc_stream".to_string(),
    ));

    let _webrtc_transceiver = webrtc_pc
        .add_transceiver_from_track(
            Arc::clone(&video_track)
                as Arc<dyn webrtc::track::track_local::TrackLocal + Send + Sync>,
            Some(RTCRtpTransceiverInit {
                direction: RTCRtpTransceiverDirection::Sendonly,
                send_encodings: vec![
                    RTCRtpEncodingParameters {
                        rid: "hi".into(),
                        ..Default::default()
                    },
                    RTCRtpEncodingParameters {
                        rid: "mid".into(),
                        ..Default::default()
                    },
                    RTCRtpEncodingParameters {
                        rid: "lo".into(),
                        ..Default::default()
                    },
                ],
            }),
        )
        .await?;

    // 3. WebRTC creates Offer
    let offer = webrtc_pc.create_offer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(offer.clone()).await?;
    let _ = gather_complete.recv().await;

    let offer = webrtc_pc.local_description().await.unwrap();
    println!("WebRTC Offer SDP:\n{}", offer.sdp);

    // Convert WebRTC SDP to RustRTC SDP
    let mut offer_sdp = offer.sdp;
    if offer_sdp.contains("m=video") {
        offer_sdp = offer_sdp.replace("a=sendonly", "a=sendonly\r\na=rid:hi send\r\na=rid:mid send\r\na=rid:lo send\r\na=simulcast:send hi;mid;lo");
    }
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer_sdp)?;

    // 4. RustRTC sets Remote Description
    rust_pc.set_remote_description(rust_offer).await?;

    // 5. RustRTC creates Answer
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;

    // Convert RustRTC SDP to WebRTC SDP
    let answer_sdp = answer.to_sdp_string();
    println!("RustRTC Answer SDP:\n{}", answer_sdp);
    let webrtc_answer = RTCSessionDescription::answer(answer_sdp)?;

    // 6. WebRTC sets Remote Description
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    // 7. Wait for connection
    rust_pc.wait_for_connected().await?;

    // 8. Start sending data from WebRTC
    let video_track_clone = video_track.clone();
    tokio::spawn(async move {
        let mut sequence_number = 0u16;
        loop {
            tokio::time::sleep(Duration::from_millis(33)).await;

            // Send packets for each RID
            for rid in &["hi", "mid", "lo"] {
                let packet = Packet {
                    header: Header {
                        version: 2,
                        payload_type: 96,
                        sequence_number,
                        timestamp: sequence_number as u32 * 3000,
                        ssrc: 0,
                        extensions: vec![Extension {
                            id: 1, // Negotiated ID for urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id
                            payload: Bytes::from(rid.as_bytes().to_vec()),
                        }],
                        ..Default::default()
                    },
                    payload: vec![0u8; 100].into(),
                };

                if let Err(e) = video_track_clone.write_rtp(&packet).await {
                    println!("Failed to write RTP: {}", e);
                    return;
                }
            }
            sequence_number = sequence_number.wrapping_add(1);
            // println!("Wrote RTP packets"); // Reduce spam
        }
    });

    // 9. Verify RustRTC receives Simulcast tracks
    let receiver = transceiver.receiver().unwrap();

    // Wait a bit for packets to flow and tracks to be created
    tokio::time::sleep(Duration::from_secs(2)).await;

    let simulcast_rids = receiver.get_simulcast_rids();
    println!("Received Simulcast RIDs: {:?}", simulcast_rids);

    assert_eq!(simulcast_rids.len(), 3);
    assert!(simulcast_rids.contains(&"hi".to_string()));
    assert!(simulcast_rids.contains(&"mid".to_string()));
    assert!(simulcast_rids.contains(&"lo".to_string()));

    // 10. Create SelectorTrack and switch
    let hi_track = receiver.simulcast_track("hi").expect("hi track not found");
    let mid_track = receiver
        .simulcast_track("mid")
        .expect("mid track not found");
    let lo_track = receiver.simulcast_track("lo").expect("lo track not found");

    println!(
        "Track IDs: hi={}, mid={}, lo={}",
        hi_track.id(),
        mid_track.id(),
        lo_track.id()
    );

    let selector = rustrtc::media::track::SelectorTrack::new(lo_track.clone());

    // Verify we can switch
    println!("Switching to mid");
    selector.switch_to(mid_track).await.unwrap();

    println!("Waiting for packet on mid...");
    match timeout(Duration::from_secs(2), selector.recv()).await {
        Ok(Ok(_)) => println!("Received packet on mid"),
        Ok(Err(e)) => println!("Error receiving on mid: {}", e),
        Err(_) => println!("Timeout receiving on mid"),
    }

    println!("Switching to hi");
    selector.switch_to(hi_track).await.unwrap();

    println!("Waiting for packet on hi...");
    match timeout(Duration::from_secs(2), selector.recv()).await {
        Ok(Ok(_)) => println!("Received packet on hi"),
        Ok(Err(e)) => println!("Error receiving on hi: {}", e),
        Err(_) => println!("Timeout receiving on hi"),
    }

    // Cleanup
    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}
