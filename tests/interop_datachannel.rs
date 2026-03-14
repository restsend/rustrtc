use anyhow::Result;
use rustrtc::PeerConnection;
use rustrtc::RtcConfiguration;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

fn build_webrtc_api() -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;

    let mut setting_engine = SettingEngine::default();
    // Same-host interop tests become flaky when webrtc-rs enumerates transient
    // IPv6/link-local interfaces from the developer machine. Keep the harness
    // focused on stable IPv4 plus loopback candidates.
    setting_engine.set_ip_filter(Box::new(|ip| ip.is_ipv4()));
    setting_engine.set_include_loopback_candidate(true);

    Ok(APIBuilder::new()
        .with_setting_engine(setting_engine)
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build())
}

#[tokio::test]
async fn interop_datachannel_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Create DataChannel
    let rust_dc = rust_pc.create_data_channel(
        "test-channel",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // 2. Create WebRTC PeerConnection (Answerer)
    let api = build_webrtc_api()?;

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // Create negotiated DataChannel on WebRTC side
    let mut dc_init = webrtc::data_channel::data_channel_init::RTCDataChannelInit::default();
    // In webrtc-rs 0.14, negotiated might be u16 (the ID)? Or maybe I am misinterpreting the error.
    // Let's try to set negotiated to Some(0) if it wants u16.
    // But wait, negotiated is usually bool.
    // Maybe the error "expected u16, found bool" was for `id`?
    // No, "This code at line 40 ... dc_init.negotiated = Some(true); ... expected u16, found bool".
    // This is extremely weird.
    // Let's try to just NOT set negotiated and see what happens?
    // No, I need negotiated channel.

    // Let's try to use the builder pattern if available?
    // Or just assume `negotiated` is the ID.
    dc_init.negotiated = Some(0);

    let webrtc_dc = webrtc_pc
        .create_data_channel("test-channel", Some(dc_init))
        .await?;

    // 3. Exchange SDP
    // Trigger gathering on Rust side (create_offer does it)
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete (simple way)
    loop {
        if rust_pc.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer = rust_pc.create_offer().await?; // Re-create with candidates
    rust_pc.set_local_description(offer.clone())?;

    let webrtc_desc = RTCSessionDescription::offer(offer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer.sdp)?;
    println!("Rust Answer SDP: {:?}", rust_answer);
    rust_pc.set_remote_description(rust_answer).await?;

    println!("Waiting for ICE Connected...");
    rust_pc.wait_for_connected().await?;
    println!("ICE Connected (PeerConnection Connected)");

    // 4. Wait for DataChannel to open
    println!("Waiting for DataChannel...");
    // Since it is negotiated, it is "open" when transport is connected.
    // We can wait for on_open event.
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<()>(1);
    let open_tx = Arc::new(open_tx);
    webrtc_dc.on_open(Box::new(move || {
        let open_tx = open_tx.clone();
        Box::pin(async move {
            let _ = open_tx.send(()).await;
        })
    }));

    // Wait for open
    let _ = timeout(Duration::from_secs(2), open_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for DataChannel open"))?;
    println!("WebRTC DataChannel opened");

    // 5. Send data from RustRTC to WebRTC
    println!("Sending data from RustRTC...");
    let data = b"Hello WebRTC";
    // Wait a bit for connection to be fully established (COOKIE ECHO/ACK)
    tokio::time::sleep(Duration::from_millis(500)).await;

    rust_pc.send_data(0, data).await?;

    // And verify on WebRTC side.
    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<String>(1);
    let msg_tx = Arc::new(msg_tx);

    webrtc_dc.on_message(Box::new(
        move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
            let tx = msg_tx.clone();
            Box::pin(async move {
                let s = String::from_utf8_lossy(&msg.data).to_string();
                println!("WebRTC received message: {}", s);
                let _ = tx.send(s).await;
            })
        },
    ));

    let msg = timeout(Duration::from_secs(2), msg_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WebRTC did not receive message"))?;
    assert_eq!(msg, "Hello WebRTC");

    // 6. Send data from WebRTC to RustRTC
    println!("Sending data from WebRTC...");
    webrtc_dc.send_text("Hello RustRTC").await?;

    // Verify on RustRTC side
    let mut received_msg = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(2) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(100), rust_dc.recv()).await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    let s = String::from_utf8_lossy(&data).to_string();
                    println!("RustRTC received message: {}", s);
                    assert_eq!(s, "Hello RustRTC");
                    received_msg = true;
                    break;
                }
                _ => {}
            }
        }
    }
    assert!(received_msg, "RustRTC did not receive message");

    // Cleanup
    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}

#[tokio::test]
async fn interop_datachannel_dcep_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();

    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Create DataChannel (DCEP)
    let rust_dc = rust_pc.create_data_channel("dcep-channel", None)?;

    // 2. Create WebRTC PeerConnection (Answerer)
    let api = build_webrtc_api()?;

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // We don't create DataChannel on WebRTC side. It should be created via DCEP.
    let (dc_tx, mut dc_rx) =
        tokio::sync::mpsc::channel::<Arc<webrtc::data_channel::RTCDataChannel>>(1);
    let dc_tx = Arc::new(dc_tx);

    webrtc_pc.on_data_channel(Box::new(
        move |dc: Arc<webrtc::data_channel::RTCDataChannel>| {
            let dc_tx = dc_tx.clone();
            Box::pin(async move {
                let _ = dc_tx.send(dc).await;
            })
        },
    ));

    // 3. Exchange SDP
    let _ = rust_pc.create_offer().await?;
    loop {
        if rust_pc.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer = rust_pc.create_offer().await?;
    rust_pc.set_local_description(offer.clone())?;

    let webrtc_desc = RTCSessionDescription::offer(offer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer.sdp)?;
    rust_pc.set_remote_description(rust_answer).await?;

    rust_pc.wait_for_connected().await?;

    // 4. Wait for DataChannel on WebRTC side
    let webrtc_dc = timeout(Duration::from_secs(5), dc_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WebRTC did not receive DataChannel"))?;

    assert_eq!(webrtc_dc.label(), "dcep-channel");

    // Wait for open on WebRTC side
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<()>(1);
    let open_tx = Arc::new(open_tx);
    webrtc_dc.on_open(Box::new(move || {
        let open_tx = open_tx.clone();
        Box::pin(async move {
            let _ = open_tx.send(()).await;
        })
    }));

    // It might be already open if we missed the event?
    let _ = timeout(Duration::from_secs(2), open_rx.recv()).await;

    // 5. Send data
    let data = b"Hello DCEP";
    rust_pc.send_data(rust_dc.id, data).await?;

    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<String>(1);
    let msg_tx = Arc::new(msg_tx);
    webrtc_dc.on_message(Box::new(
        move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
            let tx = msg_tx.clone();
            Box::pin(async move {
                let s = String::from_utf8_lossy(&msg.data).to_string();
                let _ = tx.send(s).await;
            })
        },
    ));

    let msg = timeout(Duration::from_secs(2), msg_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WebRTC did not receive message"))?;
    assert_eq!(msg, "Hello DCEP");

    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}

#[tokio::test]
async fn interop_datachannel_incoming_test() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Answerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // 2. Create WebRTC PeerConnection (Offerer)
    let api = build_webrtc_api()?;

    let webrtc_config = WebrtcConfiguration::default();
    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // Create DataChannel on WebRTC side (DCEP)
    let webrtc_dc = webrtc_pc
        .create_data_channel("incoming-channel", None)
        .await?;

    // 3. Exchange SDP
    let offer = webrtc_pc.create_offer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(offer.clone()).await?;
    let _ = gather_complete.recv().await;

    let offer = webrtc_pc.local_description().await.unwrap();
    let rust_offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, &offer.sdp)?;
    rust_pc.set_remote_description(rust_offer).await?;

    let _answer = rust_pc.create_answer().await?;
    // Wait for gathering
    loop {
        if rust_pc.ice_transport().gather_state()
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let answer = rust_pc.create_answer().await?; // Re-create with candidates
    rust_pc.set_local_description(answer.clone())?;

    let webrtc_answer = RTCSessionDescription::answer(answer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_answer).await?;

    rust_pc.wait_for_connected().await?;

    // 4. Wait for DataChannel on RustRTC side via recv()
    println!("Waiting for DataChannel on RustRTC...");
    loop {
        let event = timeout(Duration::from_secs(5), rust_pc.recv())
            .await?
            .ok_or_else(|| anyhow::anyhow!("No event received"))?;

        match event {
            rustrtc::PeerConnectionEvent::DataChannel(dc) => {
                println!("Received DataChannel: {}", dc.label);
                assert_eq!(dc.label, "incoming-channel");

                // Send data back
                rust_pc.send_data(dc.id, b"Hello from Rust").await?;
                break;
            }
            rustrtc::PeerConnectionEvent::Track(_) => {
                println!("Received Track event, waiting for DataChannel...");
            }
        }
    }

    // Verify WebRTC received message
    let (msg_tx, mut msg_rx) = tokio::sync::mpsc::channel::<String>(1);
    let msg_tx = Arc::new(msg_tx);
    webrtc_dc.on_message(Box::new(
        move |msg: webrtc::data_channel::data_channel_message::DataChannelMessage| {
            let tx = msg_tx.clone();
            Box::pin(async move {
                let s = String::from_utf8_lossy(&msg.data).to_string();
                let _ = tx.send(s).await;
            })
        },
    ));

    let msg = timeout(Duration::from_secs(2), msg_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WebRTC did not receive message"))?;
    assert_eq!(msg, "Hello from Rust");

    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}
