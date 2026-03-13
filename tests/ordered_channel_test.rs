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
async fn default_create_data_channel_none_is_ordered() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    let pc = PeerConnection::new(RtcConfiguration::default());
    let dc = pc.create_data_channel("default-ordered", None)?;

    assert!(
        dc.ordered,
        "default channel should match browser ordered semantics"
    );
    assert!(
        dc.max_retransmits.is_none(),
        "default channel should remain fully reliable"
    );
    assert!(
        dc.max_packet_life_time.is_none(),
        "default channel should not set a lifetime limit"
    );

    pc.close();
    Ok(())
}

/// Test: ordered channels with negotiated mode
/// This mimics the browser scenario where channels are ordered.
/// Sends data from RustRTC to webrtc-rs via ordered channels.
#[tokio::test]
async fn ordered_negotiated_channel_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    const NUM_CHANNELS: usize = 2;
    const CHUNK_COUNT: usize = 50;
    const CHUNK_SIZE: usize = 1000;
    const TOTAL_EXPECTED_PER_CHANNEL: usize = CHUNK_SIZE * CHUNK_COUNT;

    let (offer_tx, offer_rx) = oneshot::channel();
    let (answer_tx, answer_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (webrtc_ready_tx, webrtc_ready_rx) = watch::channel(false);

    let bytes_received_per_channel = Arc::new(Mutex::new(HashMap::<usize, usize>::new()));

    let bytes_received_clone = bytes_received_per_channel.clone();

    // --- WebRTC Setup (Client/Offerer) ---
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

            let open_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            for i in 0..NUM_CHANNELS {
                let mut dc_init = RTCDataChannelInit::default();
                let id = (i as u16) * 2;
                dc_init.negotiated = Some(id);
                // ordered is None by default = ordered:true in webrtc-rs
                let dc = webrtc_pc
                    .create_data_channel(&format!("ordered-test-{}", i), Some(dc_init))
                    .await?;

                let bytes_received = bytes_received_clone.clone();
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
                    let done_tx_clone = done_tx_clone.clone();

                    Box::pin(async move {
                        let msg_len = msg.data.len();
                        let mut map = bytes_received.lock().await;
                        let entry = map.entry(channel_idx).or_insert(0);
                        *entry += msg_len;

                        let total_received: usize = map.values().sum();
                        let expected_total = NUM_CHANNELS * TOTAL_EXPECTED_PER_CHANNEL;

                        if total_received >= expected_total {
                            println!("All data received across all channels!");
                            let _ = done_tx_clone.try_send(());
                        }
                    })
                }));
            }

            // WebRTC creates Offer
            let offer = webrtc_pc.create_offer(None).await?;
            let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
            webrtc_pc.set_local_description(offer.clone()).await?;
            let _ = gather_complete.recv().await;

            let offer = webrtc_pc.local_description().await.unwrap();
            let _ = offer_tx.send(offer.sdp);

            let answer_sdp = answer_rx
                .await
                .map_err(|e| anyhow::anyhow!("Failed to receive answer: {}", e))?;
            let webrtc_answer = RTCSessionDescription::answer(answer_sdp)?;
            webrtc_pc.set_remote_description(webrtc_answer).await?;

            let _ = shutdown_rx.await;
            webrtc_pc.close().await?;
            Ok(())
        })
    });

    // --- RustRTC Setup (Server/Answerer) ---
    let rust_config = RtcConfiguration::default();
    let rust_pc = Arc::new(PeerConnection::new(rust_config));

    // Create negotiated DataChannels with ordered=TRUE
    let mut rust_channels = Vec::new();
    for i in 0..NUM_CHANNELS {
        let id = (i as u16) * 2;
        let dc = rust_pc.create_data_channel(
            &format!("ordered-test-{}", i),
            Some(rustrtc::transports::sctp::DataChannelConfig {
                negotiated: Some(id),
                ordered: true, // <-- KEY DIFFERENCE: ordered channels
                ..Default::default()
            }),
        )?;
        rust_channels.push(dc);
    }

    // --- Signaling ---
    let offer_sdp = offer_rx.await?;
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer_sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    let _ = rust_pc.create_answer().await?;
    rust_pc.wait_for_gathering_complete().await;
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;
    let _ = answer_tx.send(answer.to_sdp_string());

    rust_pc.wait_for_connected().await?;

    // Wait for all RustRTC channels to open
    for (idx, dc) in rust_channels.iter().enumerate() {
        loop {
            match dc.recv().await {
                Some(DataChannelEvent::Open) => {
                    println!("RustRTC Channel {} is open", idx);
                    break;
                }
                Some(_) => continue,
                None => return Err(anyhow::anyhow!("Channel {} closed before open", idx)),
            }
        }
    }

    // Wait for WebRTC side to report channels open
    let mut webrtc_ready_rx = webrtc_ready_rx.clone();
    while !*webrtc_ready_rx.borrow() {
        if webrtc_ready_rx.changed().await.is_err() {
            return Err(anyhow::anyhow!("WebRTC ready signal dropped"));
        }
    }

    // Now send data from RustRTC to WebRTC on ordered channels
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

    for (idx, task) in send_tasks.into_iter().enumerate() {
        match task.await {
            Ok(Ok(())) => println!("Channel {} send task completed successfully", idx),
            Ok(Err(e)) => eprintln!("Channel {} send task failed: {}", idx, e),
            Err(e) => eprintln!("Channel {} task panicked: {}", idx, e),
        }
    }

    // Wait for completion
    let result = timeout(Duration::from_secs(30), done_rx.recv()).await;

    match result {
        Ok(Some(())) => {
            println!("✅ Ordered channel test completed successfully!");
        }
        Ok(None) => {
            return Err(anyhow::anyhow!("Channel closed unexpectedly"));
        }
        Err(_) => {
            let bytes_map = bytes_received_per_channel.lock().await;
            eprintln!("❌ Test timed out after 30 seconds");
            for i in 0..NUM_CHANNELS {
                let received = bytes_map.get(&i).copied().unwrap_or(0);
                let percent = (received as f64 / TOTAL_EXPECTED_PER_CHANNEL as f64) * 100.0;
                eprintln!(
                    "  Channel {}: {} / {} bytes ({:.1}%)",
                    i, received, TOTAL_EXPECTED_PER_CHANNEL, percent
                );
            }
            return Err(anyhow::anyhow!(
                "Test timed out - ordered data transfer stalled"
            ));
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

    let _ = shutdown_tx.send(());
    let _ = webrtc_handle.join();
    Ok(())
}

/// Test: WebRTC creates DCEP channels (non-negotiated) and sends data to RustRTC
/// This mimics the browser stress test scenario exactly.
#[tokio::test]
async fn dcep_ordered_channel_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    const CHUNK_COUNT: usize = 20;
    const CHUNK_SIZE: usize = 1000;
    const TOTAL_EXPECTED: usize = CHUNK_SIZE * CHUNK_COUNT;

    let (offer_tx, offer_rx) = oneshot::channel();
    let (answer_tx, answer_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let bytes_received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes_received_clone = bytes_received.clone();

    // --- WebRTC Setup: creates a non-negotiated (DCEP) ordered data channel ---
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

            // Create a non-negotiated data channel (this will use DCEP)
            // Default: ordered=true
            let dc = webrtc_pc.create_data_channel("dcep-test", None).await?;

            dc.on_open(Box::new(move || {
                Box::pin(async move {
                    println!("WebRTC: DCEP channel open");
                })
            }));

            dc.on_message(Box::new(move |msg: DataChannelMessage| {
                let bytes_received = bytes_received_clone.clone();
                let done_tx = done_tx.clone();
                Box::pin(async move {
                    let prev = bytes_received
                        .fetch_add(msg.data.len(), std::sync::atomic::Ordering::SeqCst);
                    let total = prev + msg.data.len();
                    if total >= TOTAL_EXPECTED {
                        println!("WebRTC: All data received! {} bytes", total);
                        let _ = done_tx.try_send(());
                    }
                })
            }));

            // WebRTC creates Offer
            let offer = webrtc_pc.create_offer(None).await?;
            let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
            webrtc_pc.set_local_description(offer.clone()).await?;
            let _ = gather_complete.recv().await;

            let offer = webrtc_pc.local_description().await.unwrap();
            let _ = offer_tx.send(offer.sdp);

            let answer_sdp = answer_rx
                .await
                .map_err(|e| anyhow::anyhow!("Failed to receive answer: {}", e))?;
            let webrtc_answer = RTCSessionDescription::answer(answer_sdp)?;
            webrtc_pc.set_remote_description(webrtc_answer).await?;

            let _ = shutdown_rx.await;
            webrtc_pc.close().await?;
            Ok(())
        })
    });

    // --- RustRTC Setup (Server/Answerer) ---
    let rust_config = RtcConfiguration::default();
    let rust_pc = Arc::new(PeerConnection::new(rust_config));

    // --- Signaling ---
    let offer_sdp = offer_rx.await?;
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer_sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    let _ = rust_pc.create_answer().await?;
    rust_pc.wait_for_gathering_complete().await;
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;
    let _ = answer_tx.send(answer.to_sdp_string());

    rust_pc.wait_for_connected().await?;

    // Wait for DCEP channel to arrive from WebRTC side
    println!("RustRTC: Waiting for DCEP channel...");
    let dc = match timeout(Duration::from_secs(10), rust_pc.recv()).await {
        Ok(Some(rustrtc::PeerConnectionEvent::DataChannel(dc))) => {
            println!(
                "RustRTC: Got DCEP channel: id={} label={} ordered={}",
                dc.id, dc.label, dc.ordered
            );
            dc
        }
        Ok(Some(_other)) => {
            return Err(anyhow::anyhow!("Unexpected event received"));
        }
        Ok(None) => {
            return Err(anyhow::anyhow!("PC closed before channel arrived"));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Timed out waiting for DCEP channel"));
        }
    };

    // Wait for Open event
    println!("RustRTC: Waiting for channel Open event...");
    match timeout(Duration::from_secs(5), dc.recv()).await {
        Ok(Some(DataChannelEvent::Open)) => {
            println!("RustRTC: DCEP channel open! ordered={}", dc.ordered);
        }
        Ok(Some(other)) => {
            println!("RustRTC: Got unexpected event: {:?}", other);
        }
        Ok(None) => {
            return Err(anyhow::anyhow!("Channel closed before open"));
        }
        Err(_) => {
            return Err(anyhow::anyhow!("Timed out waiting for channel open"));
        }
    }

    // Send data from RustRTC back to WebRTC
    println!(
        "RustRTC: Sending {} chunks of {} bytes...",
        CHUNK_COUNT, CHUNK_SIZE
    );
    let data = vec![0u8; CHUNK_SIZE];
    for i in 0..CHUNK_COUNT {
        if let Err(e) = rust_pc.send_data(dc.id, &data).await {
            eprintln!("RustRTC: Failed to send data packet {}: {}", i, e);
            break;
        }
    }
    println!("RustRTC: All data sent");

    // Wait for completion
    let result = timeout(Duration::from_secs(30), done_rx.recv()).await;

    match result {
        Ok(Some(())) => {
            println!("✅ DCEP ordered channel test completed successfully!");
        }
        Ok(None) => {
            return Err(anyhow::anyhow!("Channel closed unexpectedly"));
        }
        Err(_) => {
            let received = bytes_received.load(std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "❌ Test timed out. Received {} / {} bytes ({:.1}%)",
                received,
                TOTAL_EXPECTED,
                (received as f64 / TOTAL_EXPECTED as f64) * 100.0
            );
            return Err(anyhow::anyhow!(
                "Test timed out - DCEP ordered data transfer stalled"
            ));
        }
    }

    let _ = shutdown_tx.send(());
    let _ = webrtc_handle.join();
    Ok(())
}

/// Test: WebRTC sends data TO RustRTC via DCEP ordered channels (bidirectional)
/// This mimics the browser stress test: browser sends "ping", server receives it,
/// sends "pong" back, then sends bulk data.
#[tokio::test]
async fn dcep_ordered_bidirectional_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

    const CHUNK_COUNT: usize = 20;
    const CHUNK_SIZE: usize = 1000;
    const TOTAL_EXPECTED: usize = CHUNK_SIZE * CHUNK_COUNT;

    let (offer_tx, offer_rx) = oneshot::channel();
    let (answer_tx, answer_rx) = oneshot::channel();
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let (shutdown_tx, shutdown_rx) = oneshot::channel();

    let bytes_received = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let bytes_received_clone = bytes_received.clone();

    // --- WebRTC Setup: creates DCEP channel, sends "ping", receives bulk data ---
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

            let dc = webrtc_pc
                .create_data_channel("ping-pong-test", None)
                .await?;

            let dc_clone = dc.clone();
            dc.on_open(Box::new(move || {
                let dc = dc_clone.clone();
                Box::pin(async move {
                    println!("WebRTC: Channel open, sending ping...");
                    dc.send_text("ping".to_string()).await.unwrap();
                })
            }));

            dc.on_message(Box::new(move |msg: DataChannelMessage| {
                let bytes_received = bytes_received_clone.clone();
                let done_tx = done_tx.clone();
                Box::pin(async move {
                    // Check for "pong" response
                    if msg.data.len() == 4 {
                        if let Ok(text) = std::str::from_utf8(&msg.data) {
                            if text == "pong" {
                                println!("WebRTC: Received pong!");
                                return;
                            }
                        }
                    }

                    let prev = bytes_received
                        .fetch_add(msg.data.len(), std::sync::atomic::Ordering::SeqCst);
                    let total = prev + msg.data.len();
                    if total >= TOTAL_EXPECTED {
                        println!("WebRTC: All data received! {} bytes", total);
                        let _ = done_tx.try_send(());
                    }
                })
            }));

            let offer = webrtc_pc.create_offer(None).await?;
            let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
            webrtc_pc.set_local_description(offer.clone()).await?;
            let _ = gather_complete.recv().await;

            let offer = webrtc_pc.local_description().await.unwrap();
            let _ = offer_tx.send(offer.sdp);

            let answer_sdp = answer_rx
                .await
                .map_err(|e| anyhow::anyhow!("Failed to receive answer: {}", e))?;
            let webrtc_answer = RTCSessionDescription::answer(answer_sdp)?;
            webrtc_pc.set_remote_description(webrtc_answer).await?;

            let _ = shutdown_rx.await;
            webrtc_pc.close().await?;
            Ok(())
        })
    });

    // --- RustRTC Setup ---
    let rust_config = RtcConfiguration::default();
    let rust_pc = Arc::new(PeerConnection::new(rust_config));

    let offer_sdp = offer_rx.await?;
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer_sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    let _ = rust_pc.create_answer().await?;
    rust_pc.wait_for_gathering_complete().await;
    let answer = rust_pc.create_answer().await?;
    rust_pc.set_local_description(answer.clone())?;
    let _ = answer_tx.send(answer.to_sdp_string());

    rust_pc.wait_for_connected().await?;

    // Wait for DCEP channel
    println!("RustRTC: Waiting for DCEP channel...");
    let dc = match timeout(Duration::from_secs(10), rust_pc.recv()).await {
        Ok(Some(rustrtc::PeerConnectionEvent::DataChannel(dc))) => {
            println!(
                "RustRTC: Got DCEP channel: id={} label={} ordered={}",
                dc.id, dc.label, dc.ordered
            );
            dc
        }
        _ => return Err(anyhow::anyhow!("Failed to get DCEP channel")),
    };

    // Wait for "ping" message from WebRTC
    println!("RustRTC: Waiting for ping...");
    loop {
        match timeout(Duration::from_secs(10), dc.recv()).await {
            Ok(Some(DataChannelEvent::Open)) => {
                println!("RustRTC: Channel open event");
                continue;
            }
            Ok(Some(DataChannelEvent::Message(msg))) => {
                if msg.as_ref() == b"ping" {
                    println!("RustRTC: Received ping!");
                    break;
                } else {
                    println!("RustRTC: Got message: {:?}", String::from_utf8_lossy(&msg));
                }
            }
            Ok(Some(DataChannelEvent::Close)) => {
                return Err(anyhow::anyhow!("Channel closed before ping"));
            }
            Ok(None) => {
                return Err(anyhow::anyhow!("Channel recv returned None"));
            }
            Err(_) => {
                return Err(anyhow::anyhow!("Timed out waiting for ping"));
            }
        }
    }

    // Send "pong" back
    rust_pc.send_text(dc.id, "pong").await?;
    println!("RustRTC: Sent pong");

    // Send bulk data
    tokio::time::sleep(Duration::from_millis(100)).await;
    println!(
        "RustRTC: Sending {} chunks of {} bytes...",
        CHUNK_COUNT, CHUNK_SIZE
    );
    let data = vec![0u8; CHUNK_SIZE];
    for _i in 0..CHUNK_COUNT {
        rust_pc.send_data(dc.id, &data).await?;
    }
    println!("RustRTC: All data sent");

    let result = timeout(Duration::from_secs(30), done_rx.recv()).await;

    match result {
        Ok(Some(())) => {
            println!("✅ DCEP ordered bidirectional test completed successfully!");
        }
        Err(_) => {
            let received = bytes_received.load(std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "❌ Test timed out. Received {} / {} bytes ({:.1}%)",
                received,
                TOTAL_EXPECTED,
                (received as f64 / TOTAL_EXPECTED as f64) * 100.0
            );
            return Err(anyhow::anyhow!("Test timed out"));
        }
        _ => return Err(anyhow::anyhow!("Channel error")),
    }

    let _ = shutdown_tx.send(());
    let _ = webrtc_handle.join();
    Ok(())
}
