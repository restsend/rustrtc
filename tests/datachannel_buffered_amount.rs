#![cfg(feature = "std")]

// E2E tests: DataChannel per-channel buffered amount + BufferedAmountLow
// event (W3C `bufferedAmount` / `bufferedamountlow`).
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::transports::ice::IceGathererState;
use rustrtc::transports::sctp::{DataChannelConfig, DataChannelEvent};
use rustrtc::{PeerConnection, RtcConfiguration};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

async fn wait_gather_complete(pc: &PeerConnection) {
    loop {
        if pc.ice_transport().gather_state() == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

async fn signal_loopback(offerer: &PeerConnection, answerer: &PeerConnection) -> Result<()> {
    let _ = offerer.create_offer().await?;
    wait_gather_complete(offerer).await;
    let offer = offerer.create_offer().await?;
    offerer.set_local_description(offer.clone())?;
    answerer.set_remote_description(offer).await?;

    let _ = answerer.create_answer().await?;
    wait_gather_complete(answerer).await;
    let answer = answerer.create_answer().await?;
    answerer.set_local_description(answer.clone())?;
    offerer.set_remote_description(answer).await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn buffered_amount_low_fires_once_after_drain() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc_a = PeerConnection::new(RtcConfiguration::default());
    let pc_b = PeerConnection::new(RtcConfiguration::default());

    const THRESHOLD: usize = 64 * 1024;
    let dc_a = pc_a.create_data_channel(
        "low-water",
        Some(DataChannelConfig {
            negotiated: Some(0),
            buffered_amount_low_threshold: THRESHOLD,
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "low-water",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // Drain everything on B.
    tokio::spawn(async move {
        loop {
            match dc_b.recv().await {
                Some(DataChannelEvent::Message(_)) => continue,
                Some(DataChannelEvent::Close) | None => break,
                _ => continue,
            }
        }
    });

    signal_loopback(&pc_a, &pc_b).await?;

    // Event channel for BufferedAmountLow on A.
    let (low_tx, mut low_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let watcher = Arc::clone(&dc_a);
    tokio::spawn(async move {
        loop {
            match watcher.recv().await {
                Some(DataChannelEvent::BufferedAmountLow(amount)) => {
                    if low_tx.send(amount).is_err() {
                        break;
                    }
                }
                Some(DataChannelEvent::Close) | None => break,
                _ => continue,
            }
        }
    });

    // Wait for the association to be live.
    let state_rx = pc_a.subscribe_peer_state();
    let mut connected = false;
    for _ in 0..100 {
        if *state_rx.borrow() == rustrtc::PeerConnectionState::Connected {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(connected, "pair must connect");

    // Arm the edge: push well above the threshold. Queued bytes are counted
    // synchronously, so sample right after each send — sleeping lets a fast
    // loopback drain everything before we look.
    let burst = vec![0xABu8; THRESHOLD * 3];
    let mut peak = 0usize;
    for _ in 0..4 {
        pc_a.send_data(dc_a.id, &burst).await?;
        peak = peak.max(dc_a.buffered_amount());
    }
    assert!(
        peak > THRESHOLD,
        "buffered_amount should exceed the threshold during a large burst, peak {peak}"
    );

    // Wait for the drain edge event.
    let amount = timeout(Duration::from_secs(15), low_rx.recv())
        .await
        .map_err(|_| anyhow::anyhow!("BufferedAmountLow event did not fire"))?
        .ok_or_else(|| anyhow::anyhow!("event channel closed"))?;
    assert!(
        amount <= THRESHOLD,
        "event amount {amount} must be at or below the threshold {THRESHOLD}"
    );

    // The edge is one-shot: no second event until we exceed again.
    let second = timeout(Duration::from_millis(1500), low_rx.recv()).await;
    assert!(
        second.is_err(),
        "BufferedAmountLow must not re-fire without re-arming"
    );

    // After full drain the buffered amount is zero.
    for _ in 0..50 {
        if dc_a.buffered_amount() == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(dc_a.buffered_amount(), 0, "buffered amount must drain to 0");
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn buffered_amount_zero_threshold_never_fires() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc_a = PeerConnection::new(RtcConfiguration::default());
    let pc_b = PeerConnection::new(RtcConfiguration::default());

    let dc_a = pc_a.create_data_channel(
        "no-threshold",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "no-threshold",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    tokio::spawn(async move {
        loop {
            match dc_b.recv().await {
                Some(DataChannelEvent::Message(_)) => continue,
                Some(DataChannelEvent::Close) | None => break,
                _ => continue,
            }
        }
    });

    signal_loopback(&pc_a, &pc_b).await?;

    let (low_tx, mut low_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
    let watcher = Arc::clone(&dc_a);
    tokio::spawn(async move {
        loop {
            match watcher.recv().await {
                Some(DataChannelEvent::BufferedAmountLow(amount)) => {
                    if low_tx.send(amount).is_err() {
                        break;
                    }
                }
                Some(DataChannelEvent::Close) | None => break,
                _ => continue,
            }
        }
    });

    // Wait for the association to be live before sending.
    let state_rx = pc_a.subscribe_peer_state();
    let mut connected = false;
    for _ in 0..100 {
        if *state_rx.borrow() == rustrtc::PeerConnectionState::Connected {
            connected = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(connected, "pair must connect");

    // Traffic with threshold 0 must not produce events.
    let burst = vec![0xCDu8; 128 * 1024];
    for _ in 0..4 {
        pc_a.send_data(dc_a.id, &burst).await?;
    }
    let fired = timeout(Duration::from_millis(1500), low_rx.recv()).await;
    assert!(
        fired.is_err(),
        "threshold 0 must never fire BufferedAmountLow"
    );
    Ok(())
}
