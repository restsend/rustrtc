// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use anyhow::Result;
use rustrtc::{IceCandidateType, IceServer, IceTransportPolicy, PeerConnection, RtcConfiguration};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::ice_transport::ice_server::RTCIceServer;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[derive(serde::Deserialize, Debug)]
struct IceServerConfig {
    urls: Vec<String>,
    username: Option<String>,
    credential: Option<String>,
}

fn fetch_ice_servers() -> Result<Option<Vec<IceServerConfig>>> {
    let url = match std::env::var("ICE_SERVER") {
        Ok(url) => url,
        Err(_) => return Ok(None),
    };
    let output = std::process::Command::new("curl")
        .arg("-s")
        .arg(url)
        .output()?;
    let json: Vec<IceServerConfig> = serde_json::from_slice(&output.stdout)?;
    Ok(Some(json))
}

#[tokio::test]
async fn interop_turn_datachannel_test() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Fetch ICE servers
    let ice_servers_config = match fetch_ice_servers()? {
        Some(c) => c,
        None => {
            println!("ICE_SERVER env not set, skipping test");
            return Ok(());
        }
    };
    println!("Fetched ICE servers: {:?}", ice_servers_config);

    // 2. Create RustRTC PeerConnection (Offerer) with TURN
    let mut rust_config = RtcConfiguration::default();
    for server in &ice_servers_config {
        let mut s = IceServer::new(server.urls.clone());
        if let (Some(u), Some(c)) = (&server.username, &server.credential) {
            s = s.with_credential(u, c);
        }
        rust_config.ice_servers.push(s);
    }
    // Force Relay to ensure TURN is used
    rust_config.ice_transport_policy = IceTransportPolicy::Relay;

    let rust_pc = PeerConnection::new(rust_config);

    // Create DataChannel
    let rust_dc = rust_pc.create_data_channel(
        "turn-channel",
        Some(rustrtc::transports::sctp::DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // 3. Create WebRTC PeerConnection (Answerer)
    let mut m = MediaEngine::default();
    m.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m)?;
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let mut webrtc_config = WebrtcConfiguration::default();
    for server in &ice_servers_config {
        let mut s = RTCIceServer {
            urls: server.urls.clone(),
            ..Default::default()
        };
        if let (Some(u), Some(c)) = (&server.username, &server.credential) {
            s.username = u.clone();
            s.credential = c.clone();
            // s.credential_type = webrtc::ice_transport::ice_credential_type::RTCIceCredentialType::Password;
        }
        webrtc_config.ice_servers.push(s);
    }
    webrtc_config.ice_transport_policy = RTCIceTransportPolicy::Relay;

    let webrtc_pc = api.new_peer_connection(webrtc_config).await?;

    // Create negotiated DataChannel on WebRTC side
    let mut dc_init = webrtc::data_channel::data_channel_init::RTCDataChannelInit::default();
    dc_init.negotiated = Some(0);
    let webrtc_dc = webrtc_pc
        .create_data_channel("turn-channel", Some(dc_init))
        .await?;

    // 4. Exchange SDP
    let _ = rust_pc.create_offer().await?;

    // Wait for gathering to complete
    loop {
        if rust_pc.ice_transport().gather_state() == rustrtc::IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer = rust_pc.create_offer().await?;

    // Verify we have relay candidates
    let candidates = rust_pc.ice_transport().local_candidates();
    println!("RustRTC gathered candidates:");
    for c in &candidates {
        println!("  {:?} {} {}", c.typ, c.address, c.transport);
    }
    let has_relay = candidates.iter().any(|c| c.typ == IceCandidateType::Relay);
    assert!(has_relay, "RustRTC should have gathered relay candidates");
    println!("RustRTC gathered relay candidates");

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

    println!("Waiting for ICE Connected...");
    rust_pc.wait_for_connected().await?;
    println!("ICE Connected");

    // Check selected pair
    if let Some(pair) = rust_pc.ice_transport().get_selected_pair().await {
        println!("Selected ICE Pair:");
        println!("  Local: {:?} {}", pair.local.typ, pair.local.address);
        println!("  Remote: {:?} {}", pair.remote.typ, pair.remote.address);
        assert_eq!(
            pair.local.typ,
            IceCandidateType::Relay,
            "Selected local candidate must be Relay"
        );
    } else {
        panic!("No selected ICE pair found!");
    }

    // 5. Wait for DataChannel open
    let (open_tx, mut open_rx) = tokio::sync::mpsc::channel::<()>(1);
    let open_tx = Arc::new(open_tx);
    webrtc_dc.on_open(Box::new(move || {
        let open_tx = open_tx.clone();
        Box::pin(async move {
            let _ = open_tx.send(()).await;
        })
    }));

    let _ = timeout(Duration::from_secs(10), open_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("Timeout waiting for DataChannel open"))?;
    println!("WebRTC DataChannel opened");

    // 6. Send data Rust -> WebRTC
    tokio::time::sleep(Duration::from_millis(500)).await;
    let data = b"Hello via TURN";
    rust_pc.send_data(0, data).await?;

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

    let msg = timeout(Duration::from_secs(10), msg_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("WebRTC did not receive message"))?;
    assert_eq!(msg, "Hello via TURN");
    println!("WebRTC received: {}", msg);

    // 7. Send data WebRTC -> Rust
    webrtc_dc.send_text("Hello back via TURN").await?;

    let mut received_msg = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(event)) = timeout(Duration::from_millis(100), rust_dc.recv()).await
            && let rustrtc::DataChannelEvent::Message(data) = event
        {
            let s = String::from_utf8_lossy(&data).to_string();
            println!("RustRTC received: {}", s);
            assert_eq!(s, "Hello back via TURN");
            received_msg = true;
            break;
        }
    }
    assert!(received_msg, "RustRTC did not receive message");

    rust_pc.close();
    webrtc_pc.close().await?;

    Ok(())
}
