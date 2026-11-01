#![cfg(feature = "std")]

//! Closing a `PeerConnection` must release every task it spawned — the ICE,
//! DTLS and RTCP loops, each receiver's receive loop and (with GCC) its TWCC
//! flush loop — even when the application still holds the transceivers or
//! receiver tracks it obtained from the connection.
//!
//! Regression guard for the leaks fixed in `fix/drop-closes-connected-pc` and
//! `fix/twcc-flush-loop-exits`: the monitors used to hold a strong
//! `Arc<PeerConnectionInner>`, and the flush loop a strong `Arc<RtpTransport>`,
//! so a connected connection (or just its handles) could outlive `close()`.

use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};
use std::time::Duration;
use tokio::time::timeout;

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

/// Wait up to `secs` for every task on this runtime to end.
async fn wait_no_tasks(secs: u64) -> bool {
    timeout(Duration::from_secs(secs), async {
        while alive_tasks() > 0 {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .is_ok()
}

async fn connected_pair(mode: TransportMode, with_video: bool) -> (PeerConnection, PeerConnection) {
    let config = || RtcConfiguration {
        transport_mode: mode.clone(),
        ..RtcConfiguration::default()
    };
    let (pc1, pc2) = (PeerConnection::new(config()), PeerConnection::new(config()));
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    if with_video {
        pc1.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);
    }
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
    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected()).unwrap();
    (pc1, pc2)
}

#[tokio::test]
async fn close_without_held_handles_releases_all_tasks() {
    let (pc1, pc2) = connected_pair(TransportMode::WebRtc, true).await;
    pc1.close();
    pc2.close();
    drop((pc1, pc2));
    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after close and drop",
        alive_tasks()
    );
}

#[tokio::test]
async fn close_releases_all_tasks_while_transceivers_held() {
    let (pc1, pc2) = connected_pair(TransportMode::WebRtc, true).await;

    // Keep handles the application is entitled to hold after closing.
    let t1 = pc1.get_transceivers()[0].clone();
    let track1 = t1.receiver().map(|r| r.track());
    let t2 = pc2.get_transceivers()[0].clone();
    let track2 = t2.receiver().map(|r| r.track());

    pc1.close();
    pc2.close();
    drop((pc1, pc2));

    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after close while transceivers are held",
        alive_tasks()
    );

    drop((t1, t2, track1, track2));
}

#[tokio::test]
async fn close_releases_all_tasks_while_transceivers_held_rtp_and_srtp() {
    for mode in [TransportMode::Rtp, TransportMode::Srtp] {
        let (pc1, pc2) = connected_pair(mode.clone(), false).await;
        let t1 = pc1.get_transceivers()[0].clone();
        let track1 = t1.receiver().map(|r| r.track());
        let t2 = pc2.get_transceivers()[0].clone();
        let track2 = t2.receiver().map(|r| r.track());

        let packet = rustrtc::rtp::RtpPacket::new(
            rustrtc::rtp::RtpHeader::new(0, 1, 0, 0x12345678),
            vec![0; 160],
        );
        pc1.wait_for_rtp_transport_ready(Duration::from_secs(3))
            .await
            .unwrap();
        pc2.wait_for_rtp_transport_ready(Duration::from_secs(3))
            .await
            .unwrap();
        pc1.send_raw_rtp(packet).await.unwrap();
        timeout(Duration::from_secs(3), async {
            while pc2.received_rtp_packets() == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the peer must receive actual UDP media before closing");
        let received = pc2.received_rtp_packets();
        {
            let report = pc2.get_transport_stats().await.unwrap();
            let stages = report
                .entries
                .iter()
                .find_map(|entry| entry.values.get("packetStages"))
                .expect("real UDP ingress must be visible through transport stats");
            assert_eq!(stages["enabled"], true);
            let transports = stages["transports"].as_array().unwrap();
            let accepted: u64 = transports
                .iter()
                .map(|transport| transport["rtp_accepted"]["packets"].as_u64().unwrap())
                .sum();
            assert_eq!(accepted, 1);
            let transport = transports
                .iter()
                .find(|transport| transport["rtp_accepted"]["packets"] == 1)
                .unwrap();
            assert!(transport["rtp_accepted"]["last_age_ms"].is_u64());
            assert!(transport["conn"]["received"]["packets"].as_u64().unwrap() >= 1);
            assert!(transport["conn"]["received"]["bytes"].as_u64().unwrap() >= 172);
            assert_eq!(transport["srtp_required"], mode == TransportMode::Srtp);
            assert!(transport["conn"]["selected_socket"].is_string());
        }

        let reading = pc2.clone();
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let done = stop.clone();
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let ready = barrier.clone();
        let reader = std::thread::spawn(move || {
            let mut previous = received;
            ready.wait();
            loop {
                let current = reading.received_rtp_packets();
                assert!(
                    current >= previous,
                    "closing must not reset the received packet count"
                );
                previous = current;
                if done.load(std::sync::atomic::Ordering::Acquire) {
                    return current;
                }
            }
        });
        barrier.wait();
        pc1.close();
        pc2.close();
        pc2.close();
        stop.store(true, std::sync::atomic::Ordering::Release);
        assert_eq!(reader.join().unwrap(), received);
        assert_eq!(pc2.received_rtp_packets(), received);
        drop((pc1, pc2));

        assert!(
            wait_no_tasks(3).await,
            "{mode:?}: {} tasks still alive after close while transceivers are held",
            alive_tasks()
        );

        drop((t1, t2, track1, track2));
    }
}
