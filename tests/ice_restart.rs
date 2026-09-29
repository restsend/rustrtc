// E2E tests: ICE restart (RFC 8445 §9).
//
// 1. Local restart: the offerer calls `restart_ice()`, the new offer carries
//    fresh ice-ufrag/ice-pwd, the answerer auto-detects the remote restart,
//    and the DataChannel keeps working after the new pair is nominated.
// 2. Remote-initiated restart: the original answerer restarts by offering new
//    credentials; the offerer detects the credential change in
//    `set_remote_description` and restarts its own side transparently.
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::transports::sctp::{DataChannelConfig, DataChannelEvent};
use rustrtc::{PeerConnection, RtcConfiguration};
use std::time::Duration;
use tokio::time::timeout;

async fn wait_gather_complete(pc: &PeerConnection) {
    loop {
        if pc.ice_transport().gather_state() == rustrtc::transports::ice::IceGathererState::Complete
        {
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

/// Restart flow with `restarted` as the side that rolls credentials and offers.
async fn signal_restart(restarted: &PeerConnection, other: &PeerConnection) -> Result<()> {
    restarted.restart_ice().await?;

    let before = restarted.local_description().unwrap();
    let offer = restarted.create_offer().await?;
    restarted.set_local_description(offer.clone())?;

    // The restart offer must carry fresh credentials...
    assert_ne!(
        extract_ufrag(&before),
        extract_ufrag(&offer),
        "restart offer must rotate ice-ufrag"
    );
    assert_ne!(
        extract_pwd(&before),
        extract_pwd(&offer),
        "restart offer must rotate ice-pwd"
    );

    // The peer detects the credential change and restarts its own side; its
    // answer must also carry fresh credentials.
    let other_before = other.local_description().unwrap();
    other.set_remote_description(offer).await?;
    let answer = other.create_answer().await?;
    other.set_local_description(answer.clone())?;
    assert_ne!(
        extract_ufrag(&other_before),
        extract_ufrag(&answer),
        "peer must mirror the restart (fresh ufrag in answer)"
    );
    restarted.set_remote_description(answer).await?;
    Ok(())
}

fn extract_ufrag(desc: &rustrtc::SessionDescription) -> String {
    desc.session
        .attributes
        .iter()
        .find(|a| a.key == "ice-ufrag")
        .and_then(|a| a.value.clone())
        .or_else(|| {
            desc.media_sections
                .iter()
                .find_map(|m| {
                    m.attributes
                        .iter()
                        .find(|a| a.key == "ice-ufrag")
                        .and_then(|a| a.value.clone())
                })
        })
        .expect("ice-ufrag missing")
}

fn extract_pwd(desc: &rustrtc::SessionDescription) -> String {
    desc.session
        .attributes
        .iter()
        .find(|a| a.key == "ice-pwd")
        .and_then(|a| a.value.clone())
        .or_else(|| {
            desc.media_sections
                .iter()
                .find_map(|m| {
                    m.attributes
                        .iter()
                        .find(|a| a.key == "ice-pwd")
                        .and_then(|a| a.value.clone())
                })
        })
        .expect("ice-pwd missing")
}

/// Send `payload` on `dc` (via `pc`) and expect the same bytes echoed back.
async fn ping_pong(
    pc: &PeerConnection,
    dc: &rustrtc::transports::sctp::DataChannel,
    payload: &[u8],
) -> Result<()> {
    pc.send_data(dc.id, payload)
        .await
        .map_err(|e| anyhow::anyhow!("send failed: {e}"))?;
    let start = std::time::Instant::now();
    loop {
        if start.elapsed() > Duration::from_secs(5) {
            anyhow::bail!("ping_pong timeout");
        }
        match timeout(Duration::from_secs(2), dc.recv()).await {
            Ok(Some(DataChannelEvent::Message(b))) => {
                if b.as_ref() == payload {
                    return Ok(());
                }
            }
            Ok(Some(_)) => continue,
            Ok(None) => anyhow::bail!("data channel closed"),
            Err(_) => continue,
        }
    }
}

async fn setup_echo_pair() -> Result<(
    PeerConnection,
    PeerConnection,
    std::sync::Arc<rustrtc::transports::sctp::DataChannel>,
    std::sync::Arc<rustrtc::transports::sctp::DataChannel>,
)> {
    let pc_a = PeerConnection::new(RtcConfiguration::default());
    let pc_b = PeerConnection::new(RtcConfiguration::default());

    let dc_a = pc_a.create_data_channel(
        "restart",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "restart",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    // Echo loop on B (sends go through the PeerConnection).
    let echo_pc = pc_b.clone();
    let echo_dc = dc_b.clone();
    tokio::spawn(async move {
        loop {
            match echo_dc.recv().await {
                Some(DataChannelEvent::Message(data)) => {
                    if echo_pc.send_data(echo_dc.id, &data).await.is_err() {
                        break;
                    }
                }
                Some(DataChannelEvent::Close) | None => break,
                _ => continue,
            }
        }
    });

    signal_loopback(&pc_a, &pc_b).await?;
    pc_a.wait_for_connected().await?;
    pc_b.wait_for_connected().await?;
    // Let SCTP finish bring-up (COOKIE ECHO/ACK + DCEP/open).
    tokio::time::sleep(Duration::from_millis(400)).await;
    Ok((pc_a, pc_b, dc_a, dc_b))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ice_restart_local_recovers_datachannel() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let (pc_a, _pc_b, dc_a, _dc_b) = setup_echo_pair().await?;

    // Sanity: path works before restart.
    ping_pong(&pc_a, &dc_a, b"before-restart").await?;

    // Restart from the offerer side and re-signal.
    signal_restart(&pc_a, &_pc_b).await?;

    // DataChannel (SCTP/DTLS) survives the restart; media must flow again.
    let mut reconnected = false;
    for _ in 0..10 {
        match ping_pong(&pc_a, &dc_a, b"after-restart").await {
            Ok(()) => {
                reconnected = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    assert!(reconnected, "data channel must recover after ICE restart");

    // And keeps working afterwards.
    ping_pong(&pc_a, &dc_a, b"stable-after-restart").await?;
    Ok(())
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn ice_restart_from_answerer_side_recovers() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let (pc_a, pc_b, dc_a, _dc_b) = setup_echo_pair().await?;
    ping_pong(&pc_a, &dc_a, b"before-remote-restart").await?;

    // B (original answerer) rolls credentials and offers; A must detect the
    // remote restart in set_remote_description and mirror it in its answer.
    signal_restart(&pc_b, &pc_a).await?;

    let mut reconnected = false;
    for _ in 0..10 {
        match ping_pong(&pc_a, &dc_a, b"after-remote-restart").await {
            Ok(()) => {
                reconnected = true;
                break;
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    assert!(
        reconnected,
        "data channel must recover after answerer-initiated ICE restart"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restart_ice_rejects_non_stable_state() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let pc = PeerConnection::new(RtcConfiguration::default());
    // Need an application transceiver so an offer can be built.
    pc.create_data_channel("x", None)?;
    // Drive to HaveLocalOffer via create_offer + set_local, where restart must
    // be rejected.
    let offer = pc.create_offer().await?;
    pc.set_local_description(offer)?;
    let err = pc.restart_ice().await;
    assert!(err.is_err(), "restart_ice must reject HaveLocalOffer state");
    Ok(())
}
