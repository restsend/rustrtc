use anyhow::{Result, anyhow};
use rustrtc::transports::sctp::{DataChannel, DataChannelConfig, DataChannelEvent};
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

const NEAR_LIMIT_MESSAGE_SIZE: usize = 63 * 1024;
const OVERSIZED_MESSAGE_SIZE: usize = 65 * 1024;

async fn wait_for_channel_open(dc: &Arc<DataChannel>) -> Result<()> {
    loop {
        match timeout(Duration::from_secs(10), dc.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for data channel open"))?
        {
            Some(DataChannelEvent::Open) => return Ok(()),
            Some(_) => continue,
            None => return Err(anyhow!("data channel closed before open")),
        }
    }
}

async fn wait_for_remote_data_channel(pc: &PeerConnection) -> Result<Arc<DataChannel>> {
    loop {
        match timeout(Duration::from_secs(10), pc.recv())
            .await
            .map_err(|_| anyhow!("timed out waiting for remote data channel"))?
        {
            Some(PeerConnectionEvent::DataChannel(dc)) => return Ok(dc),
            Some(_) => continue,
            None => return Err(anyhow!("peer connection closed before remote data channel")),
        }
    }
}

async fn connect_data_channel(
    ordered: bool,
) -> Result<(
    PeerConnection,
    PeerConnection,
    Arc<DataChannel>,
    Arc<DataChannel>,
)> {
    let config = RtcConfiguration::default();
    let pc1 = PeerConnection::new(config.clone());
    let pc2 = PeerConnection::new(config);

    let dc1 = pc1.create_data_channel(
        "limit-test",
        Some(DataChannelConfig {
            ordered,
            ..Default::default()
        }),
    )?;

    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer)?;
    pc1.wait_for_gathering_complete().await;
    let offer = pc1
        .local_description()
        .ok_or_else(|| anyhow!("missing local offer"))?;

    pc2.set_remote_description(offer).await?;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer)?;
    pc2.wait_for_gathering_complete().await;
    let answer = pc2
        .local_description()
        .ok_or_else(|| anyhow!("missing local answer"))?;

    pc1.set_remote_description(answer).await?;
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;

    let dc2 = wait_for_remote_data_channel(&pc2).await?;
    wait_for_channel_open(&dc1).await?;
    wait_for_channel_open(&dc2).await?;

    Ok((pc1, pc2, dc1, dc2))
}

#[tokio::test]
async fn near_limit_message_accepted() -> Result<()> {
    let (pc1, pc2, dc1, dc2) = connect_data_channel(true).await?;
    let payload = vec![0x2A; NEAR_LIMIT_MESSAGE_SIZE];

    pc1.send_data(dc1.id, &payload).await?;

    match timeout(Duration::from_secs(10), dc2.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for near-limit message"))?
    {
        Some(DataChannelEvent::Message(msg)) => assert_eq!(msg.len(), payload.len()),
        Some(DataChannelEvent::Close) => {
            return Err(anyhow!(
                "near-limit message should not close the data channel"
            ));
        }
        Some(DataChannelEvent::Open) => return Err(anyhow!("unexpected extra open event")),
        None => return Err(anyhow!("remote data channel closed unexpectedly")),
    }

    pc1.close();
    pc2.close();
    Ok(())
}

#[tokio::test]
async fn oversized_ordered_message_rejected() -> Result<()> {
    let (pc1, pc2, dc1, dc2) = connect_data_channel(true).await?;
    let payload = vec![0x55; OVERSIZED_MESSAGE_SIZE];

    pc1.send_data(dc1.id, &payload).await?;

    match timeout(Duration::from_secs(10), dc2.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for ordered channel close"))?
    {
        Some(DataChannelEvent::Close) => {}
        Some(DataChannelEvent::Message(msg)) => {
            return Err(anyhow!(
                "oversized ordered message should be rejected, got {} bytes",
                msg.len()
            ));
        }
        Some(DataChannelEvent::Open) => return Err(anyhow!("unexpected extra open event")),
        None => return Err(anyhow!("remote data channel closed without close event")),
    }

    pc1.close();
    pc2.close();
    Ok(())
}

#[tokio::test]
async fn oversized_unordered_message_rejected() -> Result<()> {
    let (pc1, pc2, dc1, dc2) = connect_data_channel(false).await?;
    let payload = vec![0x7E; OVERSIZED_MESSAGE_SIZE];

    pc1.send_data(dc1.id, &payload).await?;

    match timeout(Duration::from_secs(10), dc2.recv())
        .await
        .map_err(|_| anyhow!("timed out waiting for unordered channel close"))?
    {
        Some(DataChannelEvent::Close) => {}
        Some(DataChannelEvent::Message(msg)) => {
            return Err(anyhow!(
                "oversized unordered message should be rejected, got {} bytes",
                msg.len()
            ));
        }
        Some(DataChannelEvent::Open) => return Err(anyhow!("unexpected extra open event")),
        None => return Err(anyhow!("remote data channel closed without close event")),
    }

    pc1.close();
    pc2.close();
    Ok(())
}
