use anyhow::{Result, anyhow};
use rustrtc::{
    DataChannelEvent, IceCandidateType, IceServer, IceTransportPolicy, PeerConnection,
    PeerConnectionEvent, RtcConfiguration,
};
use std::sync::Arc;
use std::time::{Duration, Instant};

const TEST_USERNAME: &str = "turn-user";
const TEST_PASSWORD: &str = "turn-password";

pub async fn run_turn_datachannel_roundtrip(
    turn_url: String,
    allow_insecure_turn_tls: bool,
) -> Result<()> {
    let pc1 = PeerConnection::new(build_turn_config(turn_url.clone(), allow_insecure_turn_tls));
    let pc2 = PeerConnection::new(build_turn_config(turn_url, allow_insecure_turn_tls));

    let dc1 = pc1.create_data_channel("turn-roundtrip", None)?;

    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc1.wait_for_gathering_complete().await;
    let offer = pc1.local_description().unwrap();

    pc2.set_remote_description(offer).await?;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc2.wait_for_gathering_complete().await;
    let answer = pc2.local_description().unwrap();

    pc1.set_remote_description(answer).await?;

    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;

    assert_selected_relay_pair(&pc1).await?;
    assert_selected_relay_pair(&pc2).await?;

    wait_for_open(&dc1).await?;
    let dc2 = wait_for_incoming_channel(&pc2).await?;
    wait_for_open(&dc2).await?;

    pc1.send_data(dc1.id, b"hello over local turn").await?;
    expect_message(&dc2, b"hello over local turn").await?;

    pc2.send_data(dc2.id, b"hello back over local turn").await?;
    expect_message(&dc1, b"hello back over local turn").await?;

    pc1.close();
    pc2.close();
    Ok(())
}

fn build_turn_config(turn_url: String, allow_insecure_turn_tls: bool) -> RtcConfiguration {
    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.allow_insecure_turn_tls = allow_insecure_turn_tls;
    config
        .ice_servers
        .push(IceServer::new(vec![turn_url]).with_credential(TEST_USERNAME, TEST_PASSWORD));
    config
}

async fn assert_selected_relay_pair(pc: &PeerConnection) -> Result<()> {
    let pair = pc
        .ice_transport()
        .get_selected_pair()
        .await
        .ok_or_else(|| anyhow!("selected ICE pair missing"))?;
    if pair.local.typ != IceCandidateType::Relay {
        return Err(anyhow!(
            "expected relay candidate, got {:?} {}",
            pair.local.typ,
            pair.local.address
        ));
    }
    Ok(())
}

async fn wait_for_open(dc: &rustrtc::transports::sctp::DataChannel) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), dc.recv()).await
            && matches!(event, DataChannelEvent::Open)
        {
            return Ok(());
        }
    }
    Err(anyhow!("timed out waiting for data channel open"))
}

async fn wait_for_incoming_channel(
    pc: &PeerConnection,
) -> Result<Arc<rustrtc::transports::datachannel::DataChannel>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), pc.recv()).await
            && let PeerConnectionEvent::DataChannel(dc) = event
        {
            return Ok(dc);
        }
    }
    Err(anyhow!("timed out waiting for incoming data channel"))
}

async fn expect_message(
    dc: &rustrtc::transports::sctp::DataChannel,
    expected: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if let Ok(Some(event)) = tokio::time::timeout(Duration::from_millis(200), dc.recv()).await
            && let DataChannelEvent::Message(message) = event
        {
            if message.as_ref() == expected {
                return Ok(());
            }
        }
    }
    Err(anyhow!(
        "timed out waiting for expected data channel payload {:?}",
        expected
    ))
}
