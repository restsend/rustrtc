// E2E test: rustrtc<->rustrtc loopback data-channel transfer.
// Exercises the full WebRTC stack (PeerConnection <-> ICE <-> DTLS <-> SCTP
// <-> DataChannel) and specifically the SCTP robustness/congestion-control
// paths: reliable ordered delivery of a large payload, fragmentation,
// congestion-window growth, SACK delay under bidirectional traffic, fast
// recovery inflation, receiver backpressure, and TLP.
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::transports::sctp::{DataChannelConfig, DataChannelEvent};
use rustrtc::transports::ice::IceGathererState;
use rustrtc::{PeerConnection, RtcConfiguration};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::timeout;

/// Deterministic payload: each 6-byte record is [be32 index, i*31, i*17] so we
/// can verify both byte-ordering and content of the received stream.
fn make_payload(n: usize) -> Vec<u8> {
    let mut v = Vec::with_capacity(n);
    let mut i = 0u32;
    while v.len() < n {
        v.extend_from_slice(&i.to_be_bytes());
        v.push(i.wrapping_mul(31) as u8);
        v.push(i.wrapping_mul(17) as u8);
        i += 1;
    }
    v.truncate(n);
    v
}

async fn wait_gather_complete(pc: &PeerConnection) {
    loop {
        if pc.ice_transport().gather_state() == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Exchange SDP between two rustrtc PeerConnections (non-trickle).
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

/// Receive exactly `total` bytes on a DataChannel as ordered reliable messages.
async fn drain_until(
    dc: &rustrtc::transports::sctp::DataChannel,
    total: usize,
    deadline: Duration,
) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(total);
    let start = std::time::Instant::now();
    while buf.len() < total {
        if start.elapsed() > deadline {
            anyhow::bail!(
                "receive timeout: got {} / {} bytes",
                buf.len(),
                total
            );
        }
        match timeout(Duration::from_secs(5), dc.recv()).await {
            Ok(Some(DataChannelEvent::Message(b))) => buf.extend_from_slice(&b),
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("data channel closed after {} bytes", buf.len()),
            Err(_) => continue, // per-call timeout; loop checks overall deadline
        }
    }
    Ok(buf)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_loopback_large_bidirectional_transfer() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc1 = Arc::new(PeerConnection::new(RtcConfiguration::default()));
    let pc2 = Arc::new(PeerConnection::new(RtcConfiguration::default()));

    let dc1 = pc1.create_data_channel(
        "e2e",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc2 = pc2.create_data_channel(
        "e2e",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let id1 = dc1.id;
    let id2 = dc2.id;

    signal_loopback(&pc1, &pc2).await?;
    pc1.wait_for_connected().await?;
    pc2.wait_for_connected().await?;
    // Let SCTP finish bring-up (COOKIE ECHO/ACK + DCEP/open).
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 8 MB each direction, 8 KB messages (1024 msgs/dir): exercises
    // fragmentation, cwnd growth/slow-start, SACK delay, fast recovery, and
    // receiver backpressure under sustained bidirectional transfer.
    const TOTAL: usize = 8 * 1024 * 1024;
    const CHUNK: usize = 8 * 1024;
    let payload_a = Arc::new(make_payload(TOTAL));
    let payload_b = Arc::new(make_payload(TOTAL));

    // Senders: stream the payload in CHUNK-sized reliable ordered messages.
    let pc1s = pc1.clone();
    let payload_a_send = payload_a.clone();
    let send_a = tokio::spawn(async move {
        let mut off = 0usize;
        while off < TOTAL {
            let end = (off + CHUNK).min(TOTAL);
            pc1s.send_data(id1, &payload_a_send[off..end]).await?;
            off = end;
        }
        Ok::<_, anyhow::Error>(())
    });
    let pc2s = pc2.clone();
    let payload_b_send = payload_b.clone();
    let send_b = tokio::spawn(async move {
        let mut off = 0usize;
        while off < TOTAL {
            let end = (off + CHUNK).min(TOTAL);
            pc2s.send_data(id2, &payload_b_send[off..end]).await?;
            off = end;
        }
        Ok::<_, anyhow::Error>(())
    });

    // Receivers: drain the opposite-direction payload.
    let recv_a =
        tokio::spawn(async move { drain_until(&dc1, TOTAL, Duration::from_secs(120)).await });
    let recv_b =
        tokio::spawn(async move { drain_until(&dc2, TOTAL, Duration::from_secs(120)).await });

    send_a.await??;
    send_b.await??;
    let got_at_a = recv_a.await??; // pc1 receives what pc2 sent (payload_b)
    let got_at_b = recv_b.await??; // pc2 receives what pc1 sent (payload_a)

    assert_eq!(got_at_a.len(), TOTAL, "B->A: short delivery");
    assert_eq!(got_at_b.len(), TOTAL, "A->B: short delivery");
    assert_eq!(*payload_b, got_at_a, "B->A: byte-for-byte integrity/order failed");
    assert_eq!(*payload_a, got_at_b, "A->B: byte-for-byte integrity/order failed");

    pc1.close();
    pc2.close();
    Ok(())
}

/// E2E for C.13 (receiver backpressure under chunk pressure): a burst of many
/// SMALL ordered messages (like SSH keystrokes) must all be delivered reliably
/// — no silent drops even when the receiver's reassembly queue is stressed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn e2e_loopback_many_small_messages_no_loss() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc1 = Arc::new(PeerConnection::new(RtcConfiguration::default()));
    let pc2 = Arc::new(PeerConnection::new(RtcConfiguration::default()));

    let dc1 = pc1.create_data_channel(
        "small",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc2 = pc2.create_data_channel(
        "small",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let id1 = dc1.id;

    signal_loopback(&pc1, &pc2).await?;
    pc1.wait_for_connected().await?;
    pc2.wait_for_connected().await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // 4000 tiny messages back-to-back. Each carries its index so we can verify
    // ordering and completeness exactly.
    const COUNT: usize = 4000;
    let pc1s = pc1.clone();
    let sender = tokio::spawn(async move {
        for i in 0u32..COUNT as u32 {
            pc1s.send_data(id1, &i.to_be_bytes()).await?;
        }
        Ok::<_, anyhow::Error>(())
    });

    // Receiver: collect COUNT messages, verify they are 0..COUNT in order.
    let mut got = Vec::<u32>::with_capacity(COUNT);
    let start = std::time::Instant::now();
    while got.len() < COUNT {
        if start.elapsed() > Duration::from_secs(60) {
            anyhow::bail!("small-msg: got {} / {}", got.len(), COUNT);
        }
        match timeout(Duration::from_secs(5), dc2.recv()).await {
            Ok(Some(DataChannelEvent::Message(b))) => {
                if b.len() == 4 {
                    got.push(u32::from_be_bytes(b.as_ref().try_into().unwrap()));
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("dc closed at {}/{}", got.len(), COUNT),
            Err(_) => continue,
        }
    }
    sender.await??;

    // Must be exactly 0,1,2,...,COUNT-1 in order, with no gaps.
    for (idx, val) in got.iter().enumerate() {
        assert_eq!(*val, idx as u32, "small-msg: out-of-order/missing at {}", idx);
    }
    assert_eq!(got.len(), COUNT, "small-msg: must deliver all with zero loss");

    pc1.close();
    pc2.close();
    Ok(())
}

