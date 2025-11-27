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
    rust_pc
        .add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv)
        .await;

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
    rust_pc.set_local_description(offer.clone()).await?;

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
    let (done_tx, mut done_rx) = tokio::sync::mpsc::channel::<()>(1);
    let done_tx = Arc::new(done_tx);

    webrtc_pc.on_peer_connection_state_change(Box::new(move |s: RTCPeerConnectionState| {
        if s == RTCPeerConnectionState::Connected {
            let _ = done_tx.try_send(());
        }
        Box::pin(async {})
    }));

    // Also check RustRTC state
    let rust_pc_clone = rust_pc.clone();
    tokio::spawn(async move {
        loop {
            let _state = rust_pc_clone.signaling_state().await; // This is signaling, we want connection state
            // But PeerConnection exposes ice_transport state via subscription
            // Or we can check internal state if exposed.
            // For now, let's rely on WebRTC side reporting connected, which implies RustRTC side worked.
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    });

    timeout(Duration::from_secs(10), done_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Connection timed out"))?;

    // Cleanup
    rust_pc.close().await;
    webrtc_pc.close().await?;

    Ok(())
}
