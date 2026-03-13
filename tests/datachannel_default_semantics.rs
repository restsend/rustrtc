use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use rustrtc::transports::datachannel::{DataChannel, DataChannelConfig, DataChannelEvent};
use rustrtc::{PeerConnection, RtcConfiguration, SdpType, SessionDescription};
use tokio::sync::mpsc;
use tokio::time::timeout;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::RTCDataChannel;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::peer_connection::configuration::RTCConfiguration as WebrtcConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

const CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);

fn init_test_runtime() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    let _ = env_logger::builder().is_test(true).try_init();
}

async fn create_webrtc_peer() -> Result<Arc<RTCPeerConnection>> {
    let mut media_engine = MediaEngine::default();
    media_engine.register_default_codecs()?;
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)?;
    let api = APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .build();

    api.new_peer_connection(WebrtcConfiguration::default())
        .await
        .map(Arc::new)
        .context("failed to create webrtc-rs peer connection")
}

async fn negotiate_rust_offer(
    rust_pc: &Arc<PeerConnection>,
    webrtc_pc: &Arc<RTCPeerConnection>,
) -> Result<()> {
    let offer = rust_pc.create_offer().await?;
    rust_pc.set_local_description(offer)?;
    rust_pc.wait_for_gathering_complete().await;
    let offer = rust_pc
        .local_description()
        .context("missing Rust offer after gathering")?;

    let webrtc_offer = RTCSessionDescription::offer(offer.to_sdp_string())?;
    webrtc_pc.set_remote_description(webrtc_offer).await?;

    let answer = webrtc_pc.create_answer(None).await?;
    let mut gather_complete = webrtc_pc.gathering_complete_promise().await;
    webrtc_pc.set_local_description(answer).await?;
    let _ = gather_complete.recv().await;

    let answer = webrtc_pc
        .local_description()
        .await
        .context("missing webrtc-rs local answer")?;
    let rust_answer = SessionDescription::parse(SdpType::Answer, &answer.sdp)?;
    rust_pc.set_remote_description(rust_answer).await?;

    rust_pc.wait_for_connected().await?;
    Ok(())
}

async fn wait_for_remote_channel(
    rx: &mut mpsc::Receiver<Arc<RTCDataChannel>>,
    label: &str,
) -> Result<Arc<RTCDataChannel>> {
    loop {
        let channel = timeout(CHANNEL_TIMEOUT, rx.recv())
            .await
            .context("timed out waiting for remote data channel")?
            .ok_or_else(|| anyhow!("remote data channel stream closed"))?;
        if channel.label() == label {
            return Ok(channel);
        }
    }
}

async fn wait_for_webrtc_channel_open(channel: &Arc<RTCDataChannel>) -> Result<()> {
    let started = std::time::Instant::now();
    while channel.ready_state() != RTCDataChannelState::Open {
        if started.elapsed() > CHANNEL_TIMEOUT {
            return Err(anyhow!("timed out waiting for webrtc-rs channel to open"));
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    Ok(())
}

async fn wait_for_rust_channel_open(channel: &Arc<DataChannel>) -> Result<()> {
    loop {
        let event = timeout(CHANNEL_TIMEOUT, channel.recv())
            .await
            .context("timed out waiting for Rust data channel open")?
            .ok_or_else(|| anyhow!("Rust data channel closed before opening"))?;
        match event {
            DataChannelEvent::Open => return Ok(()),
            DataChannelEvent::Close => {
                return Err(anyhow!("Rust data channel closed before opening"));
            }
            DataChannelEvent::Message(_) => {}
        }
    }
}

async fn wait_for_rust_message(channel: &Arc<DataChannel>, expected: &str) -> Result<()> {
    loop {
        let event = timeout(CHANNEL_TIMEOUT, channel.recv())
            .await
            .context("timed out waiting for Rust data channel message")?
            .ok_or_else(|| anyhow!("Rust data channel closed before receiving a message"))?;
        match event {
            DataChannelEvent::Message(message) => {
                if message.as_ref() == expected.as_bytes() {
                    return Ok(());
                }
            }
            DataChannelEvent::Close => {
                return Err(anyhow!(
                    "Rust data channel closed before receiving a message"
                ));
            }
            DataChannelEvent::Open => {}
        }
    }
}

#[tokio::test]
async fn default_channel_is_ordered_reliable() -> Result<()> {
    init_test_runtime();

    let rust_pc = Arc::new(PeerConnection::new(RtcConfiguration::default()));
    let rust_dc = rust_pc.create_data_channel("default-channel", None)?;
    assert!(rust_dc.ordered);
    assert_eq!(rust_dc.max_retransmits, None);
    assert_eq!(rust_dc.max_packet_life_time, None);

    let webrtc_pc = create_webrtc_peer().await?;
    let (remote_dc_tx, mut remote_dc_rx) = mpsc::channel(1);
    webrtc_pc.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
        let remote_dc_tx = remote_dc_tx.clone();
        Box::pin(async move {
            let _ = remote_dc_tx.send(channel).await;
        })
    }));

    negotiate_rust_offer(&rust_pc, &webrtc_pc).await?;

    let remote_dc = wait_for_remote_channel(&mut remote_dc_rx, "default-channel").await?;
    wait_for_rust_channel_open(&rust_dc).await?;
    wait_for_webrtc_channel_open(&remote_dc).await?;

    assert!(
        remote_dc.ordered(),
        "webrtc-rs should observe an ordered channel"
    );
    assert_eq!(remote_dc.max_retransmits(), None);
    assert_eq!(remote_dc.max_packet_lifetime(), None);

    let (message_tx, mut message_rx) = mpsc::channel(1);
    remote_dc.on_message(Box::new(move |message: DataChannelMessage| {
        let message_tx = message_tx.clone();
        Box::pin(async move {
            let _ = message_tx
                .send(String::from_utf8_lossy(&message.data).to_string())
                .await;
        })
    }));

    rust_pc.send_text(rust_dc.id, "ordered-default").await?;
    let message = timeout(CHANNEL_TIMEOUT, message_rx.recv())
        .await
        .context("timed out waiting for ordered message on webrtc-rs side")?
        .ok_or_else(|| anyhow!("webrtc-rs message channel closed"))?;
    assert_eq!(message, "ordered-default");

    rust_pc.close();
    webrtc_pc.close().await?;
    Ok(())
}

#[tokio::test]
async fn explicit_unordered_still_supported() -> Result<()> {
    init_test_runtime();

    let rust_pc = Arc::new(PeerConnection::new(RtcConfiguration::default()));
    let rust_dc = rust_pc.create_data_channel(
        "unordered-channel",
        Some(DataChannelConfig {
            ordered: false,
            ..Default::default()
        }),
    )?;
    assert!(!rust_dc.ordered);
    assert_eq!(rust_dc.max_retransmits, None);
    assert_eq!(rust_dc.max_packet_life_time, None);

    let webrtc_pc = create_webrtc_peer().await?;
    let (remote_dc_tx, mut remote_dc_rx) = mpsc::channel(1);
    webrtc_pc.on_data_channel(Box::new(move |channel: Arc<RTCDataChannel>| {
        let remote_dc_tx = remote_dc_tx.clone();
        Box::pin(async move {
            let _ = remote_dc_tx.send(channel).await;
        })
    }));

    negotiate_rust_offer(&rust_pc, &webrtc_pc).await?;

    let remote_dc = wait_for_remote_channel(&mut remote_dc_rx, "unordered-channel").await?;
    wait_for_rust_channel_open(&rust_dc).await?;
    wait_for_webrtc_channel_open(&remote_dc).await?;

    assert!(
        !remote_dc.ordered(),
        "webrtc-rs should observe the explicit unordered override"
    );
    assert_eq!(remote_dc.max_retransmits(), None);
    assert_eq!(remote_dc.max_packet_lifetime(), None);

    remote_dc.send_text("unordered-reply").await?;
    wait_for_rust_message(&rust_dc, "unordered-reply").await?;

    rust_pc.close();
    webrtc_pc.close().await?;
    Ok(())
}
