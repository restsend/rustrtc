#![cfg(feature = "std")]

//! Dropping the last `PeerConnection` handle closes the connection, also once
//! it is connected (`PeerConnectionInner`'s Drop runs `close`).
use rustrtc::config::MediaCapabilities;
use rustrtc::{
    MediaKind, PeerConnection, PeerConnectionState, RtcConfiguration, TransceiverDirection,
    TransportMode,
};
use std::time::Duration;

async fn connected_pair(
    config: impl Fn() -> RtcConfiguration,
    setup: impl Fn(&PeerConnection),
) -> (PeerConnection, PeerConnection) {
    let (pc1, pc2) = (PeerConnection::new(config()), PeerConnection::new(config()));
    setup(&pc1);
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
    let connected = async { tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected()) };
    tokio::time::timeout(Duration::from_secs(10), connected)
        .await
        .expect("connect timed out")
        .unwrap();
    (pc1, pc2)
}

/// Drop `pc` and wait for its state to reach `Closed`.
async fn assert_drop_closes(pc: PeerConnection, what: &str) {
    let mut state = pc.subscribe_peer_state();
    assert_eq!(*state.borrow(), PeerConnectionState::Connected, "{what}");
    drop(pc);
    let closed = state.wait_for(|s| *s == PeerConnectionState::Closed);
    let closed = tokio::time::timeout(Duration::from_secs(3), closed).await;
    assert!(
        matches!(closed, Ok(Ok(_))),
        "{what}: dropped connected PeerConnection never closed"
    );
}

#[tokio::test]
async fn dropping_a_connected_peer_connection_closes_it() {
    let audio = |pc: &PeerConnection| {
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    };
    let video = |pc: &PeerConnection| {
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);
    };
    let audio_and_data = |pc: &PeerConnection| {
        audio(pc);
        pc.create_data_channel("dc", None).unwrap();
    };
    #[allow(unused_mut)]
    let mut cases: Vec<(TransportMode, &dyn Fn(&PeerConnection), &str)> = vec![
        (TransportMode::WebRtc, &audio, "audio"),
        (TransportMode::WebRtc, &video, "video"),
        (TransportMode::WebRtc, &audio_and_data, "audio+datachannel"),
        (TransportMode::Rtp, &audio, "audio"),
        (TransportMode::Srtp, &audio, "audio"),
    ];
    #[cfg(feature = "t38")]
    let audio_and_image = |pc: &PeerConnection| {
        audio(pc);
        pc.add_transceiver(MediaKind::Image, TransceiverDirection::SendRecv);
    };
    #[cfg(feature = "t38")]
    cases.push((TransportMode::Rtp, &audio_and_image, "audio+image"));
    for (mode, setup, kind) in cases {
        let config = || RtcConfiguration {
            transport_mode: mode.clone(),
            media_capabilities: (kind == "audio+image").then(|| MediaCapabilities {
                image: vec![Default::default()],
                ..Default::default()
            }),
            ..RtcConfiguration::default()
        };
        let (pc1, pc2) = connected_pair(config, setup).await;
        // Handles the application may still hold do not keep the PC alive.
        let transceiver = pc1.get_transceivers()[0].clone();
        let track = transceiver.receiver().map(|r| r.track());
        assert_drop_closes(pc1, &format!("{mode:?} {kind} offerer")).await;
        assert_drop_closes(pc2, &format!("{mode:?} {kind} answerer")).await;
        drop((transceiver, track));
    }
}
