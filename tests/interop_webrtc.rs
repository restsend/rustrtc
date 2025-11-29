use anyhow::Result;
use rustrtc::transports::ice::IceGathererState;
use rustrtc::{MediaKind, RtcConfiguration};
use rustrtc::{PeerConnection, TransceiverDirection};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[tokio::test]
async fn interop_ice_dtls_handshake() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Add a transceiver to trigger ICE gathering
    rust_pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    // 2. Create WebRTC PeerConnection (Answerer)
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // 3. RustRTC creates Offer
    // Trigger gathering
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete
    loop {
        if rust_pc.ice_transport().gather_state().await == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let offer = rust_pc.create_offer().await?;
    println!("RustRTC Offer SDP:\n{}", offer.to_sdp_string());
    rust_pc.set_local_description(offer.clone())?;

    // Convert RustRTC SDP to WebRTC SDP
    let offer_sdp = offer.to_sdp_string();
    let webrtc_desc = RTCSessionDescription::offer(offer_sdp)?;

    // 4. WebRTC sets Remote Description
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    // 5. WebRTC creates Answer
    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();
    println!("WebRTC Answer SDP:\n{}", answer.sdp);

    // Convert WebRTC SDP to RustRTC SDP
    // We need to parse the SDP string into rustrtc_core::SessionDescription
    let answer_sdp = answer.sdp;
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer_sdp)?;

    // 6. RustRTC sets Remote Description
    rust_pc.set_remote_description(rust_answer).await?;

    // 7. Wait for connection
    rust_pc.wait_for_connection().await?;

    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let done_tx = Arc::new(done_tx);

    let done_tx_clone = done_tx.clone();
    webrtc_pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
        if s == RTCPeerConnectionState::Connected {
            let _ = done_tx_clone.try_send(());
        }
        Box::pin(async {})
    }));

    if webrtc_pc.connection_state() == RTCPeerConnectionState::Connected {
        let _ = done_tx.try_send(());
    }

    timeout(Duration::from_secs(10), done_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Connection timed out"))?;

    // Cleanup
    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}

#[tokio::test]
async fn interop_vp8_echo() -> Result<()> {
    use rustrtc::media::track::MediaStreamTrack;
    use webrtc::track::track_local::TrackLocalWriter;

    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Add a transceiver for Video
    let transceiver = rust_pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

    // Create a sample track to send data
    let (source, track) = rustrtc::media::sample_track(rustrtc::media::MediaKind::Video, 10);
    let sender = Arc::new(rustrtc::peer_connection::RtpSender::new(
        track, 12345, // SSRC
    ));
    transceiver.set_sender(Some(sender));

    // 2. Create WebRTC PeerConnection (Answerer)
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // Setup Echo on WebRTC side
    // Create a TrackLocalStaticRTP to send back data
    let codec = webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
        mime_type: webrtc::api::media_engine::MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        ..Default::default()
    };
    let video_track = Arc::new(
        webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP::new(
            codec,
            "video_echo".to_string(),
            "webrtc_stream".to_string(),
        ),
    );

    let _rtp_sender = webrtc_pc.add_track(video_track.clone()).await?;

    // Handle incoming track on WebRTC
    let video_track_clone = video_track.clone();
    webrtc_pc.on_track(Box::new(
        move |track: Arc<webrtc::track::track_remote::TrackRemote>,
              _receiver: Arc<webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver>,
              _transceiver: Arc<webrtc::rtp_transceiver::RTCRtpTransceiver>| {
            if track.codec().capability.mime_type == webrtc::api::media_engine::MIME_TYPE_VP8 {
                let video_track = video_track_clone.clone();
                tokio::spawn(async move {
                    loop {
                        match track.read_rtp().await {
                            Ok((packet, _)) => {
                                if let Err(_) = video_track.write_rtp(&packet).await {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            Box::pin(async {})
        },
    ));

    // 3. RustRTC creates Offer
    // Trigger gathering
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete
    loop {
        if rust_pc.ice_transport().gather_state().await == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let offer = rust_pc.create_offer().await?;
    rust_pc.set_local_description(offer.clone())?;

    // Convert RustRTC SDP to WebRTC SDP
    let offer_sdp = offer.to_sdp_string();
    let webrtc_desc = RTCSessionDescription::offer(offer_sdp)?;

    // 4. WebRTC sets Remote Description
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    // 5. WebRTC creates Answer
    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();

    // Convert WebRTC SDP to RustRTC SDP
    let answer_sdp = answer.sdp;
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer_sdp)?;

    // 6. RustRTC sets Remote Description
    rust_pc.set_remote_description(rust_answer).await?;

    // Wait for connection
    rust_pc.wait_for_connection().await?;

    // 7. Start sending data from RustRTC
    let source_clone = source.clone();
    tokio::spawn(async move {
        for i in 0..20 {
            let mut data = bytes::BytesMut::with_capacity(4);
            data.extend_from_slice(&u32::to_be_bytes(i));
            let frame = rustrtc::media::VideoFrame {
                timestamp: Duration::from_millis(i as u64 * 33),
                data: data.freeze(),
                is_last_packet: true,
                payload_type: None,
                ..Default::default()
            };
            if let Err(_) = source_clone.send_video(frame).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    });

    // 8. Verify Echo on RustRTC
    let receiver = transceiver.receiver().unwrap();
    let track = receiver.track();

    let mut received_count = 0;
    let mut received_indices = std::collections::HashSet::new();
    let timeout_duration = Duration::from_secs(10);

    let receive_task = async {
        loop {
            match track.recv().await {
                Ok(sample) => {
                    if let rustrtc::media::MediaSample::Video(frame) = sample {
                        if frame.data.len() == 4 {
                            let mut buf = [0u8; 4];
                            buf.copy_from_slice(&frame.data);
                            let index = u32::from_be_bytes(buf);
                            received_indices.insert(index);
                            received_count += 1;
                        }

                        if received_count >= 10 {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    timeout(timeout_duration, receive_task).await??;

    // Verify we received valid indices
    assert!(received_indices.iter().all(|&i| i < 20));
    assert!(received_indices.len() >= 10);

    // Cleanup
    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}

#[tokio::test]
async fn interop_vp8_echo_with_pli() -> Result<()> {
    use rustrtc::media::track::MediaStreamTrack;
    use webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication;
    use webrtc::track::track_local::TrackLocalWriter;

    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Add a transceiver for Video
    let transceiver = rust_pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

    // Create a sample track to send data
    let (source, track) = rustrtc::media::sample_track(rustrtc::media::MediaKind::Video, 10);
    let sender = Arc::new(rustrtc::peer_connection::RtpSender::new(
        track, 12345, // SSRC
    ));
    transceiver.set_sender(Some(sender));

    // 2. Create WebRTC PeerConnection (Answerer)
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = Arc::new(api.new_peer_connection(webrtc_config).await?);

    // Setup Echo on WebRTC side
    let codec = webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability {
        mime_type: webrtc::api::media_engine::MIME_TYPE_VP8.to_owned(),
        clock_rate: 90000,
        channels: 0,
        ..Default::default()
    };
    let video_track = Arc::new(
        webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP::new(
            codec,
            "video_echo".to_string(),
            "webrtc_stream".to_string(),
        ),
    );

    let _rtp_sender = webrtc_pc.add_track(video_track.clone()).await?;

    // Handle incoming track on WebRTC
    let video_track_clone = video_track.clone();
    let webrtc_pc_clone = webrtc_pc.clone();
    webrtc_pc.on_track(Box::new(
        move |track: Arc<webrtc::track::track_remote::TrackRemote>,
              _receiver: Arc<webrtc::rtp_transceiver::rtp_receiver::RTCRtpReceiver>,
              _transceiver: Arc<webrtc::rtp_transceiver::RTCRtpTransceiver>| {
            if track.codec().capability.mime_type == webrtc::api::media_engine::MIME_TYPE_VP8 {
                let video_track = video_track_clone.clone();
                let pc = webrtc_pc_clone.clone();
                tokio::spawn(async move {
                    let mut packet_count = 0;
                    loop {
                        match track.read_rtp().await {
                            Ok((packet, _)) => {
                                packet_count += 1;
                                if let Err(_) = video_track.write_rtp(&packet).await {
                                    break;
                                }

                                // Send PLI after 5 packets
                                if packet_count == 5 {
                                    println!("Sending PLI from WebRTC");
                                    let pli = PictureLossIndication {
                                        sender_ssrc: 0,
                                        media_ssrc: track.ssrc(),
                                    };
                                    if let Err(e) = pc.write_rtcp(&[Box::new(pli)]).await {
                                        println!("Failed to send PLI: {}", e);
                                    }
                                }
                            }
                            Err(_) => break,
                        }
                    }
                });
            }
            Box::pin(async {})
        },
    ));

    // 3. RustRTC creates Offer
    // Trigger gathering
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete
    loop {
        if rust_pc.ice_transport().gather_state().await == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let offer = rust_pc.create_offer().await?;
    rust_pc.set_local_description(offer.clone())?;

    // Convert RustRTC SDP to WebRTC SDP
    let offer_sdp = offer.to_sdp_string();
    let webrtc_desc = RTCSessionDescription::offer(offer_sdp)?;

    // 4. WebRTC sets Remote Description
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    // 5. WebRTC creates Answer
    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();

    // Convert WebRTC SDP to RustRTC SDP
    let answer_sdp = answer.sdp;
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer_sdp)?;

    // 6. RustRTC sets Remote Description
    rust_pc.set_remote_description(rust_answer).await?;

    // Wait for connection
    rust_pc.wait_for_connection().await?;

    // 7. Start sending data from RustRTC
    let source_clone = source.clone();
    tokio::spawn(async move {
        for i in 0..50 {
            let mut data = bytes::BytesMut::with_capacity(4);
            data.extend_from_slice(&u32::to_be_bytes(i));
            let frame = rustrtc::media::VideoFrame {
                timestamp: Duration::from_millis(i as u64 * 33),
                data: data.freeze(),
                is_last_packet: true,
                payload_type: None,
                ..Default::default()
            };
            if let Err(_) = source_clone.send_video(frame).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    });

    // 8. Verify Echo on RustRTC
    let receiver = transceiver.receiver().unwrap();
    let track = receiver.track();

    let mut received_count = 0;
    let timeout_duration = Duration::from_secs(10);

    let receive_task = async {
        loop {
            match track.recv().await {
                Ok(sample) => {
                    if let rustrtc::media::MediaSample::Video(_frame) = sample {
                        received_count += 1;
                        if received_count >= 20 {
                            break;
                        }
                    }
                }
                Err(_) => break,
            }
        }
        Ok::<(), anyhow::Error>(())
    };

    timeout(timeout_duration, receive_task).await??;

    // Cleanup
    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}

#[tokio::test]
async fn interop_ice_close_triggers_pc_close() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Add a transceiver to trigger ICE gathering
    rust_pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    // 2. Create WebRTC PeerConnection (Answerer)
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // 3. RustRTC creates Offer
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete
    loop {
        if rust_pc.ice_transport().gather_state().await == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let offer = rust_pc.create_offer().await?;
    rust_pc.set_local_description(offer.clone())?;

    let offer_sdp = offer.to_sdp_string();
    let webrtc_desc = RTCSessionDescription::offer(offer_sdp)?;

    // 4. WebRTC sets Remote Description
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    // 5. WebRTC creates Answer
    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();
    let answer_sdp = answer.sdp;
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer_sdp)?;

    // 6. RustRTC sets Remote Description
    rust_pc.set_remote_description(rust_answer).await?;

    // 7. Wait for connection
    rust_pc.wait_for_connection().await?;

    // 8. Close WebRTC side
    webrtc_pc.close().await?;

    // 9. Verify RustRTC detects close
    let mut state_rx = rust_pc.subscribe_peer_state();
    let timeout_duration = Duration::from_secs(10);

    let check_close = async {
        loop {
            let state = *state_rx.borrow_and_update();
            if state == rustrtc::PeerConnectionState::Closed
                || state == rustrtc::PeerConnectionState::Failed
                || state == rustrtc::PeerConnectionState::Disconnected
            {
                return Ok(());
            }
            if state_rx.changed().await.is_err() {
                return Err(anyhow::anyhow!("State channel closed"));
            }
        }
    };

    timeout(timeout_duration, check_close).await??;

    Ok(())
}
