use anyhow::Result;
use rustrtc::PeerConnection;
use rustrtc::RtcConfiguration;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[tokio::test]
async fn interop_datachannel_test() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Create RustRTC PeerConnection (Offerer)
    let rust_config = RtcConfiguration::default();
    let rust_pc = PeerConnection::new(rust_config);

    // Create DataChannel
    let rust_dc = rust_pc.create_data_channel("test-channel").await?;

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
        if rust_pc.ice_transport().gather_state().await
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer = rust_pc.create_offer().await?; // Re-create with candidates
    rust_pc.set_local_description(offer.clone()).await?;

    let webrtc_desc = RTCSessionDescription::offer(offer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_desc).await?;

    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer.clone()).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc.local_description().await.unwrap();
    let rust_answer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Answer, &answer.sdp)?;
    rust_pc.set_remote_description(rust_answer).await?;

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
    rust_pc.close().await;
    webrtc_pc.close().await?;

    Ok(())
}
