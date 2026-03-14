use anyhow::Result;
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[tokio::test]
async fn interop_datachannel_stress_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();

    let _ = env_logger::builder().is_test(true).try_init();
    // --- WebRTC Setup (Client/Offerer) ---
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

    // Create DataChannel on WebRTC side
    let dc = webrtc_pc.create_data_channel("stress-test", None).await?;

    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let done_tx = Arc::new(done_tx);
    let total_bytes_received = Arc::new(Mutex::new(0usize));
    let chunk_count = 256;
    let total_bytes_expected = 62208 * chunk_count;

    let total_bytes_received_clone = total_bytes_received.clone();
    let done_tx_clone = done_tx.clone();

    dc.on_message(Box::new(move |msg: DataChannelMessage| {
        let total_bytes_received_clone = total_bytes_received_clone.clone();
        let done_tx_clone = done_tx_clone.clone();
        Box::pin(async move {
            let mut received = total_bytes_received_clone.lock().await;
            *received += msg.data.len();

            if *received >= total_bytes_expected {
                let _ = done_tx_clone.try_send(());
            }
        })
    }));

    // --- RustRTC Setup (Server/Answerer) ---
    let rust_config = RtcConfiguration::default();
    let rust_pc = Arc::new(PeerConnection::new(rust_config));

    // --- Signaling ---

    // WebRTC creates Offer
    let offer = webrtc_pc.create_offer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(offer.clone()).await?;
    let _ = gather_complete.recv().await;

    let offer = webrtc_pc.local_description().await.unwrap();
    // RustRTC handles Offer
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer.sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    // RustRTC creates Answer
    let _ = rust_pc.create_answer().await?;
    // Wait for gathering
    rust_pc.wait_for_gathering_complete().await;
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;
    // println!("RustRTC Answer SDP:\n{}", answer.to_sdp_string());

    // WebRTC handles Answer
    let webrtc_answer = RTCSessionDescription::answer(answer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    // --- RustRTC Event Loop & Sending ---
    let rust_pc_clone = rust_pc.clone();
    tokio::spawn(async move {
        while let Some(ev) = rust_pc_clone.recv().await {
            match ev {
                PeerConnectionEvent::DataChannel(dc) => {
                    println!("RustRTC received DataChannel: {}", dc.id);
                    let channel_id = dc.id;

                    // Send data as requested
                    let data = [0u8; 62208];
                    for i in 0..chunk_count {
                        if let Err(e) = rust_pc_clone.send_data(channel_id, &data).await {
                            eprintln!("Failed to send data packet {}: {}", i, e);
                            break;
                        }
                        // println!("Sent packet {}", i);
                    }
                    println!("RustRTC finished sending data");
                }
                _ => {}
            }
        }
    });

    // Wait for completion
    timeout(Duration::from_secs(30), done_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Test timed out"))?;

    let received = *total_bytes_received.lock().await;
    assert_eq!(received, total_bytes_expected, "Did not receive all data");

    // Cleanup
    webrtc_pc.close().await?;

    Ok(())
}
