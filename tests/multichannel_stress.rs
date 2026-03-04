use anyhow::Result;
use rustrtc::{DataChannelEvent, PeerConnection, RtcConfiguration};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{Mutex, oneshot, watch};
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[tokio::test]
async fn multichannel_stress_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    const NUM_CHANNELS: usize = 2;
    const CHUNK_COUNT: usize = 256;
    const CHUNK_SIZE: usize = 1000;
    const TOTAL_EXPECTED_PER_CHANNEL: usize = CHUNK_SIZE * CHUNK_COUNT;

    let (offer_tx, offer_rx) = oneshot::channel();
    let (answer_tx, answer_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (webrtc_ready_tx, webrtc_ready_rx) = watch::channel(false);

    let bytes_received_per_channel = Arc::new(Mutex::new(HashMap::<usize, usize>::new()));
    let message_count_per_channel = Arc::new(Mutex::new(HashMap::<usize, usize>::new()));

    let bytes_received_clone = bytes_received_per_channel.clone();
    let message_count_clone = message_count_per_channel.clone();

    // --- WebRTC Setup (Client/Offerer) in a separate thread/runtime ---
    let webrtc_handle = std::thread::spawn(move || -> Result<()> {
        let rt = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        rt.block_on(async move {
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

            // Create multiple DataChannels on WebRTC side
            let mut data_channels = Vec::new();
            let done_tx = Arc::new(done_tx);
            let open_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let webrtc_ready_tx = webrtc_ready_tx.clone();

            for i in 0..NUM_CHANNELS {
                let mut dc_init = RTCDataChannelInit::default();
                let id = (i as u16) * 2;
                dc_init.negotiated = Some(id);
                let dc = webrtc_pc
                    .create_data_channel(&format!("stress-test-{}", i), Some(dc_init))
                    .await?;

                let bytes_received = bytes_received_clone.clone();
                let message_count = message_count_clone.clone();
                let done_tx_clone = done_tx.clone();
                let channel_idx = i;

                let open_count_clone = open_count.clone();
                let webrtc_ready_tx_clone = webrtc_ready_tx.clone();

                dc.on_open(Box::new(move || {
                    let open_count_clone = open_count_clone.clone();
                    let webrtc_ready_tx_clone = webrtc_ready_tx_clone.clone();
                    Box::pin(async move {
                        let count =
                            open_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                        if count == NUM_CHANNELS {
                            let _ = webrtc_ready_tx_clone.send(true);
                        }
                    })
                }));

                dc.on_message(Box::new(move |msg: DataChannelMessage| {
                    let bytes_received = bytes_received.clone();
                    let message_count = message_count.clone();
                    let done_tx_clone = done_tx_clone.clone();

                    Box::pin(async move {
                        let msg_len = msg.data.len();

                        // Update byte and message counters
                        {
                            let mut map = bytes_received.lock().await;
                            let entry = map.entry(channel_idx).or_insert(0);
                            *entry += msg_len;
                        }

                        {
                            let mut map = message_count.lock().await;
                            let entry = map.entry(channel_idx).or_insert(0);
                            *entry += 1;

                            if *entry % 10 == 1 {
                                println!(
                                    "WebRTC Channel {} received message #{}, {} bytes",
                                    channel_idx, entry, msg_len
                                );
                            }
                        }

                        // Check if all channels have received all data
                        let map = bytes_received.lock().await;
                        let total_received: usize = map.values().sum();
                        let expected_total = NUM_CHANNELS * TOTAL_EXPECTED_PER_CHANNEL;

                        if total_received >= expected_total {
                            println!("All data received across all channels!");
                            let _ = done_tx_clone.try_send(());
                        }
                    })
                }));

                data_channels.push(dc);
            }

            // WebRTC creates Offer
            let offer = webrtc_pc.create_offer(None).await?;
            let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
            webrtc_pc.set_local_description(offer.clone()).await?;
            let _ = gather_complete.recv().await;

            let offer = webrtc_pc.local_description().await.unwrap();
            let _ = offer_tx.send(offer.sdp);

            // Wait for Answer from RustRTC
            let answer_sdp = answer_rx
                .await
                .map_err(|e| anyhow::anyhow!("Failed to receive answer: {}", e))?;
            let webrtc_answer = RTCSessionDescription::answer(answer_sdp)?;
            webrtc_pc.set_remote_description(webrtc_answer).await?;

            // Wait for shutdown signal
            let _ = shutdown_rx.await;

            webrtc_pc.close().await?;
            Ok(())
        })
    });

    // --- RustRTC Setup (Server/Answerer) ---
    let rust_config = RtcConfiguration::default();
    let rust_pc = Arc::new(PeerConnection::new(rust_config));

    // Create negotiated DataChannels on RustRTC side
    let mut rust_channels = Vec::new();
    for i in 0..NUM_CHANNELS {
        let id = (i as u16) * 2;
        let dc = rust_pc.create_data_channel(
            &format!("stress-test-{}", i),
            Some(rustrtc::transports::sctp::DataChannelConfig {
                negotiated: Some(id),
                ..Default::default()
            }),
        )?;
        rust_channels.push(dc);
    }

    // --- Signaling ---
    let offer_sdp = offer_rx.await?;
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer_sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    // RustRTC creates Answer
    let _ = rust_pc.create_answer().await?;
    rust_pc.wait_for_gathering_complete().await;
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;

    let _ = answer_tx.send(answer.to_sdp_string());

    // Ensure ICE/DTLS is connected before sending data
    rust_pc.wait_for_connected().await?;

    // --- RustRTC Sending ---
    let mut webrtc_ready_rx = webrtc_ready_rx.clone();

    // Wait for all RustRTC channels to open before sending
    for (idx, dc) in rust_channels.iter().enumerate() {
        loop {
            match dc.recv().await {
                Some(DataChannelEvent::Open) => {
                    println!("Channel {} is open", idx);
                    break;
                }
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Channel {} closed before open", idx)),
            }
        }
    }

    // Wait for WebRTC side to report channels open
    while !*webrtc_ready_rx.borrow() {
        if webrtc_ready_rx.changed().await.is_err() {
            return Err(anyhow::anyhow!("WebRTC ready signal dropped"));
        }
    }

    // Now send data on all channels in parallel
    let mut send_tasks = Vec::new();
    for (idx, dc) in rust_channels.iter().cloned().enumerate() {
        let pc = rust_pc.clone();

        let task = tokio::spawn(async move {
            let data = vec![0u8; CHUNK_SIZE];
            for i in 0..CHUNK_COUNT {
                if let Err(e) = pc.send_data(dc.id, &data).await {
                    eprintln!("Channel {} failed to send data packet {}: {}", idx, i, e);
                    return Err(anyhow::anyhow!("Send failed: {}", e));
                }
                if i % 10 == 0 {
                    println!("Channel {} sent packet {}/{}", idx, i, CHUNK_COUNT);
                }
            }
            println!(
                "Channel {} finished sending all {} packets",
                idx, CHUNK_COUNT
            );
            Ok(())
        });

        send_tasks.push(task);
    }

    // Wait for all sends to complete
    for (idx, task) in send_tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok(())) => println!("Channel {} send task completed successfully", idx),
            Ok(Err(e)) => eprintln!("Channel {} send task failed: {}", idx, e),
            Err(e) => eprintln!("Channel {} task panicked: {}", idx, e),
        }
    }

    // Wait for completion with a timeout
    let result = timeout(Duration::from_secs(30), done_rx.recv()).await;

    match result {
        Ok(Some(())) => {
            println!("Test completed successfully!");
        }
        Ok(None) => {
            return Err(anyhow::anyhow!("Channel closed unexpectedly"));
        }
        Err(_) => {
            let bytes_map = bytes_received_per_channel.lock().await;
            eprintln!("Test timed out after 30 seconds");
            eprintln!("Bytes received per channel:");
            for i in 0..NUM_CHANNELS {
                let received = bytes_map.get(&i).copied().unwrap_or(0);
                let percent = (received as f64 / TOTAL_EXPECTED_PER_CHANNEL as f64) * 100.0;
                eprintln!(
                    "  Channel {}: {} / {} bytes ({:.1}%)",
                    i, received, TOTAL_EXPECTED_PER_CHANNEL, percent
                );
            }

            if !rust_channels.is_empty() {
                let ids: Vec<u16> = rust_channels.iter().map(|dc| dc.id).collect();
                eprintln!("Channel IDs: {:?}", ids);
            }

            return Err(anyhow::anyhow!("Test timed out - data transfer stalled"));
        }
    }

    let bytes_map = bytes_received_per_channel.lock().await;
    for i in 0..NUM_CHANNELS {
        let received = bytes_map.get(&i).copied().unwrap_or(0);
        assert_eq!(
            received, TOTAL_EXPECTED_PER_CHANNEL,
            "Channel {} did not receive all data: {} / {}",
            i, received, TOTAL_EXPECTED_PER_CHANNEL
        );
    }

    // Cleanup
    let _ = shutdown_tx.send(());
    let _ = webrtc_handle.join();

    Ok(())
}
