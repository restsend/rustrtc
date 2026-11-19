#![cfg(feature = "std")]

//! `PeerConnection::recv()` must end when the connection is closed: pending
//! events are delivered first, then `None` — and a blocked call must wake up.
//!
//! Before this behaviour existed, the loop `while let Some(ev) = pc.recv()`
//! (used by the examples) parked forever after `close()` and pinned the whole
//! `PeerConnectionInner` for as long as the task lived.

use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration};
use std::time::Duration;
use tokio::time::timeout;

fn new_pc() -> PeerConnection {
    PeerConnection::new(RtcConfiguration::webrtc())
}

async fn recv_within(pc: &PeerConnection, ms: u64) -> Option<PeerConnectionEvent> {
    timeout(Duration::from_millis(ms), pc.recv())
        .await
        .unwrap_or_else(|_| panic!("recv() did not return within {ms} ms"))
}

#[tokio::test]
async fn recv_after_close_is_none_immediately_and_stays_none() {
    let pc = new_pc();
    pc.close();
    assert!(recv_within(&pc, 500).await.is_none());
    // Repeated calls must not block or panic either.
    for _ in 0..10 {
        assert!(recv_within(&pc, 100).await.is_none());
    }
}

#[tokio::test]
async fn blocked_recv_wakes_on_close() {
    let pc = new_pc();
    let waiter = {
        let pc = pc.clone();
        tokio::spawn(async move { pc.recv().await })
    };
    // Let the waiter park on the event channel.
    tokio::time::sleep(Duration::from_millis(50)).await;
    pc.close();
    let result = timeout(Duration::from_secs(2), waiter)
        .await
        .expect("recv() did not wake after close()")
        .expect("recv() task panicked");
    assert!(result.is_none(), "recv() returned an event after close()");
}

#[tokio::test]
async fn every_concurrent_waiter_wakes_on_close() {
    let pc = new_pc();
    let mut waiters = Vec::new();
    for _ in 0..4 {
        let pc = pc.clone();
        waiters.push(tokio::spawn(async move { pc.recv().await }));
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    pc.close();
    for (i, waiter) in waiters.into_iter().enumerate() {
        let result = timeout(Duration::from_secs(2), waiter)
            .await
            .unwrap_or_else(|_| panic!("waiter {i} did not wake after close()"))
            .expect("waiter task panicked");
        assert!(
            result.is_none(),
            "waiter {i} returned an event after close()"
        );
    }
}

/// Events queued before `close()` (an incoming data channel here) are handed
/// out before the stream reports its end.
#[tokio::test]
async fn queued_events_are_delivered_before_none() {
    let (pc1, pc2) = (new_pc(), new_pc());
    let dc = pc1.create_data_channel("bench", None).unwrap();

    let _ = pc1.create_offer().await.unwrap();
    pc1.wait_for_gathering_complete().await;
    let offer = pc1.create_offer().await.unwrap();
    pc1.set_local_description(offer.clone()).unwrap();
    pc2.set_remote_description(offer).await.unwrap();
    let _ = pc2.create_answer().await.unwrap();
    pc2.wait_for_gathering_complete().await;
    let answer = pc2.create_answer().await.unwrap();
    pc2.set_local_description(answer.clone()).unwrap();
    pc1.set_remote_description(answer).await.unwrap();

    // Wait until the channel is fully open; pc2's incoming-channel event is
    // queued at the same point, and is deliberately never consumed before the
    // close below.
    timeout(Duration::from_secs(5), async {
        loop {
            if let Some(rustrtc::DataChannelEvent::Open) = dc.recv().await {
                break;
            }
        }
    })
    .await
    .expect("data channel did not open");
    tokio::time::sleep(Duration::from_millis(100)).await;

    pc1.close();
    pc2.close();

    let first = recv_within(&pc2, 1000).await;
    assert!(
        matches!(first, Some(PeerConnectionEvent::DataChannel(_))),
        "the queued incoming data channel must be delivered before None"
    );
    let second = recv_within(&pc2, 1000).await;
    assert!(
        second.is_none(),
        "recv() must end after the backlog is drained"
    );
}
