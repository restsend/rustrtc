#![cfg(feature = "std")]

//! Lifecycle leaks: after `close()` or dropping the last `PeerConnection`
//! handle, every task the connection spawned must stop — including the
//! gathering loop, the ICE/DTLS transport loop and the ICE runner.
//!
//! These tests deliberately go through the real call lifecycle (offer/answer,
//! ICE, DTLS, media) instead of an artificially parked SDP-only branch. The
//! common-mode matrix and the 20-call sequential runs also cover the case where
//! an application keeps its `PeerConnection` handles (a session map) after
//! closing each call.

use rustrtc::{
    BundlePolicy, Connectivity, IceConnectionState, Keying, MediaKind, PeerConnection,
    PeerConnectionState, RtcConfiguration, TransceiverDirection,
};
use std::time::Duration;
use tokio::time::timeout;

fn alive_tasks() -> usize {
    tokio::runtime::Handle::current()
        .metrics()
        .num_alive_tasks()
}

async fn wait_no_tasks(secs: u64) -> bool {
    timeout(Duration::from_secs(secs), async {
        while alive_tasks() > 0 {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
    })
    .await
    .is_ok()
}

fn config(mode: (Connectivity, Keying)) -> RtcConfiguration {
    RtcConfiguration {
        connectivity: mode.0,
        keying: mode.1,
        webrtc_extensions: mode.0 == Connectivity::Ice,
        bind_ips: vec!["127.0.0.1".parse().unwrap()],
        ..RtcConfiguration::sip()
    }
}

async fn connected_pair(
    mode: (Connectivity, Keying),
    with_video: bool,
    with_data: bool,
) -> (PeerConnection, PeerConnection) {
    let (pc1, pc2) = (
        PeerConnection::new(config(mode)),
        PeerConnection::new(config(mode)),
    );
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    if with_video {
        pc1.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);
    }
    if with_data {
        pc1.create_data_channel("reclaim", None).unwrap();
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
    timeout(Duration::from_secs(10), async {
        tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected()).unwrap();
    })
    .await
    .expect("connect timeout");
    (pc1, pc2)
}

/// All connectivity/keying combinations used by a normal call, closed while
/// the application still holds the handles.
#[tokio::test(flavor = "current_thread")]
async fn common_modes_close_release_all_tasks_while_handles_held() {
    for mode in [
        (Connectivity::Ice, Keying::Dtls),
        (Connectivity::Ice, Keying::Sdes),
        (Connectivity::Ice, Keying::None),
        (Connectivity::Sdp, Keying::Dtls),
        (Connectivity::IceLite, Keying::Dtls),
    ] {
        let (pc1, pc2) = connected_pair(mode.clone(), false, false).await;
        // Application handles that commonly outlive the call.
        let t1 = pc1.get_transceivers()[0].clone();
        let track1 = t1.receiver().map(|r| r.track());

        pc1.close();
        pc2.close();
        assert!(
            wait_no_tasks(3).await,
            "{mode:?}: {} tasks still alive after close with live handles",
            alive_tasks()
        );

        drop((t1, track1, pc1, pc2));
    }
}

/// Connected audio+video+data call: every loop (including SCTP/DC listeners)
/// must be gone after close and drop.
#[tokio::test(flavor = "current_thread")]
async fn connected_av_datachannel_close_drop_releases_all_tasks() {
    let (pc1, pc2) = connected_pair((Connectivity::Ice, Keying::Dtls), true, true).await;
    pc1.close();
    pc2.close();
    drop((pc1, pc2));
    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after connected A/V/data close",
        alive_tasks()
    );
}

/// Hang up while the call is still connecting (ICE checks / DTLS start).
#[tokio::test(flavor = "current_thread")]
async fn hangup_while_connecting_releases_all_tasks() {
    for mode in [
        (Connectivity::Ice, Keying::Dtls),
        (Connectivity::Sdp, Keying::Sdes),
    ] {
        let (pc1, pc2) = (
            PeerConnection::new(config(mode.clone())),
            PeerConnection::new(config(mode.clone())),
        );
        pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let _ = pc1.create_offer().await.unwrap();
        pc1.wait_for_gathering_complete().await;
        let offer = pc1.create_offer().await.unwrap();
        pc1.set_local_description(offer.clone()).unwrap();
        pc2.set_remote_description(offer).await.unwrap();
        // No answer / wait_for_connected: tear down mid-negotiation.
        pc1.close();
        pc2.close();
        drop((pc1, pc2));
        assert!(
            wait_no_tasks(3).await,
            "{mode:?}: {} tasks still alive after mid-connect hangup",
            alive_tasks()
        );
    }
}

/// The answerer has the remote offer but no local answer yet, so its direct
/// transport is Connected while the transport loop waits for the answer's
/// SDES keys. That wait does not observe the ICE `Closed` watch; close() must
/// cancel it instead of leaving the loop to its own timeout.
#[tokio::test(flavor = "current_thread")]
async fn close_releases_sdes_answerer_parked_before_transport_start() {
    let (pc1, pc2) = (
        PeerConnection::new(config((Connectivity::Sdp, Keying::Sdes))),
        PeerConnection::new(config((Connectivity::Sdp, Keying::Sdes))),
    );
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _ = pc1.create_offer().await.unwrap();
    pc1.wait_for_gathering_complete().await;
    let offer = pc1.create_offer().await.unwrap();
    pc1.set_local_description(offer.clone()).unwrap();
    pc2.set_remote_description(offer).await.unwrap();

    let mut ice_state = pc2.subscribe_ice_connection_state();
    timeout(Duration::from_secs(3), async {
        loop {
            if matches!(
                *ice_state.borrow_and_update(),
                IceConnectionState::Connected | IceConnectionState::Completed
            ) {
                return;
            }
            ice_state.changed().await.unwrap();
        }
    })
    .await
    .expect("answerer ICE did not reach Connected");
    // Let the transport loop enter wait_for_sdes_attributes.
    tokio::time::sleep(Duration::from_millis(100)).await;

    pc1.close();
    pc2.close();
    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after closing a parked SDES answerer",
        alive_tasks()
    );
    drop((pc1, pc2));
}

/// 20 sequential calls, closing and dropping each leg (the normal hangup).
#[tokio::test(flavor = "current_thread")]
async fn twenty_sequential_calls_close_drop_release_all_tasks() {
    for i in 0..20 {
        let (pc1, pc2) = connected_pair((Connectivity::Ice, Keying::Dtls), false, false).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        pc1.close();
        pc2.close();
        drop((pc1, pc2));
        assert!(
            wait_no_tasks(3).await,
            "call {i}: {} tasks still alive after close+drop",
            alive_tasks()
        );
    }
}

/// 20 sequential calls where a session map keeps both handles after hangup.
/// close() alone must stop every loop; retaining the handles must not keep a
/// transport loop (and its IceTransportInner) alive.
#[tokio::test(flavor = "current_thread")]
async fn twenty_sequential_calls_close_release_all_tasks_with_live_handles() {
    let mut calls = Vec::with_capacity(20);
    for _ in 0..20 {
        let (pc1, pc2) = connected_pair((Connectivity::Ice, Keying::Dtls), false, false).await;
        pc1.close();
        pc2.close();
        calls.push((pc1, pc2));
    }
    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after closing 20 calls with live handles",
        alive_tasks()
    );
    drop(calls);
}

/// No BUNDLE: the direct transport of each m-line (including the extra video
/// transport) must be released with the connection.
#[tokio::test(flavor = "current_thread")]
async fn no_bundle_extra_transports_release_all_tasks() {
    let make = || RtcConfiguration {
        connectivity: Connectivity::Sdp,
        keying: Keying::Dtls,
        bundle_policy: BundlePolicy::Disabled,
        bind_ips: vec!["127.0.0.1".parse().unwrap()],
        ..RtcConfiguration::sip()
    };
    let (pc1, pc2) = (PeerConnection::new(make()), PeerConnection::new(make()));
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    pc1.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);
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
    timeout(Duration::from_secs(10), async {
        tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected()).unwrap();
    })
    .await
    .expect("no-bundle connect timeout");

    pc1.close();
    pc2.close();
    drop((pc1, pc2));
    assert!(
        wait_no_tasks(3).await,
        "{} tasks still alive after no-BUNDLE close",
        alive_tasks()
    );
}

/// Exchange offer/answer but do not wait for connectivity: the caller can
/// close while ICE is checking or DTLS is still handshaking.
async fn half_connected_pair(mode: (Connectivity, Keying)) -> (PeerConnection, PeerConnection) {
    let (pc1, pc2) = (
        PeerConnection::new(config(mode.clone())),
        PeerConnection::new(config(mode)),
    );
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
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
    (pc1, pc2)
}

async fn wait_ice_connected(pc: &PeerConnection) {
    let mut ice = pc.subscribe_ice_connection_state();
    timeout(Duration::from_secs(3), async {
        loop {
            if matches!(
                *ice.borrow_and_update(),
                IceConnectionState::Connected | IceConnectionState::Completed
            ) {
                return;
            }
            ice.changed().await.unwrap();
        }
    })
    .await
    .expect("ICE did not connect");
}

/// Close 20 calls right after ICE connects but before DTLS finishes. This is
/// the hangup-during-handshake path: close() must cancel the ICE check rounds
/// and the DTLS handshake runner, not leave them (and `IceTransportInner`)
/// parked behind their own long timeouts.
#[tokio::test(flavor = "current_thread")]
async fn close_during_dtls_start_releases_all_tasks() {
    let mut calls = Vec::with_capacity(20);
    let mut closed_before_connected = 0;
    for _ in 0..20 {
        let (pc1, pc2) = half_connected_pair((Connectivity::Ice, Keying::Dtls)).await;
        wait_ice_connected(&pc1).await;
        if *pc1.subscribe_peer_state().borrow() != PeerConnectionState::Connected {
            closed_before_connected += 1;
        }
        pc1.close();
        pc2.close();
        calls.push((pc1, pc2));
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        closed_before_connected > 0,
        "test never closed during the DTLS start window"
    );
    // Connectivity-check rounds have their own per-pair timeouts (up to the
    // default nomination timeout), so allow them to drain. The transport loop
    // itself must not survive close(): on the old code it waited forever on the
    // DTLS state watch.
    assert!(
        wait_no_tasks(20).await,
        "{} tasks still alive after closing during DTLS start",
        alive_tasks()
    );
    drop(calls);
}
