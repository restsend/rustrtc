#![cfg(feature = "std")]
// E2E regression: SIP hold/resume renegotiation must not disturb the live ICE
// session.
//
// A hold re-INVITE re-signals the SAME ice-ufrag/ice-pwd. The media library
// used to force `IceTransportState::Checking` on every renegotiation and never
// restored `Connected`: the connectivity checks early-return when a pair is
// already selected. Stranded in `Checking` on both sides, the keepalive and
// TURN-refresh timers (gated on Connected/Disconnected) stopped running, so
// both TURN allocations were deleted after 600 s without renewal and media
// died mid-call; the softphone then hung up after 30 s without media.
//
// Repro (pre-fix): connect two real PeerConnections, re-run offer/answer with
// unchanged credentials → ICE state flapped Connected → Checking on both sides
// and stayed there.
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::transports::ice::IceTransportState;
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
///
/// Used both for the initial setup and for the "hold" renegotiation: a
/// plain re-offer/re-answer keeps the ICE credentials unchanged (only
/// `restart_ice()` rotates them).
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

async fn setup_echo_pair(
    prefix: &str,
) -> Result<(
    PeerConnection,
    PeerConnection,
    std::sync::Arc<rustrtc::transports::sctp::DataChannel>,
    std::sync::Arc<rustrtc::transports::sctp::DataChannel>,
)> {
    let pc_a = PeerConnection::new({
        let mut c = RtcConfiguration::webrtc();
        c.label = Some(format!("{prefix}-A-offerer").into());
        c
    });
    let pc_b = PeerConnection::new({
        let mut c = RtcConfiguration::webrtc();
        c.label = Some(format!("{prefix}-B-answerer").into());
        c
    });

    let dc_a = pc_a.create_data_channel(
        "hold",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "hold",
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

fn assert_live_session(pc: &PeerConnection, side: &str) {
    let state = pc.ice_transport().state();
    assert!(
        matches!(
            state,
            IceTransportState::Connected | IceTransportState::Completed
        ),
        "{side}: ICE state is {state:?} after hold renegotiation, expected Connected/Completed"
    );
}

/// Continuously records whether the PC-level ICE connection state ever drops
/// to `Checking` while the monitor runs.
///
/// End-state sampling alone is not enough to prevent regressions here: the
/// keepalive invariant watchdog self-heals a stranded `Checking` within one
/// tick (~1 s), which would mask a reintroduced defect. A renegotiation of a
/// connected session must produce NO Checking transition at all — that
/// invariant is what this monitor pins down.
fn spawn_checking_flap_monitor(pc: &PeerConnection) -> tokio::task::JoinHandle<bool> {
    let mut rx = pc.subscribe_ice_connection_state();
    tokio::spawn(async move {
        let mut saw_checking = false;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
        loop {
            tokio::select! {
                changed = rx.changed() => {
                    if changed.is_ok()
                        && matches!(*rx.borrow(), rustrtc::IceConnectionState::Checking)
                    {
                        saw_checking = true;
                    }
                }
                _ = tokio::time::sleep_until(deadline) => break,
            }
        }
        saw_checking
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hold_renegotiation_keeps_ice_connected() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let (pc_a, pc_b, dc_a, _dc_b) = setup_echo_pair("t1").await?;

    // Sanity: path works before the hold.
    ping_pong(&pc_a, &dc_a, b"before-hold").await?;

    // Watch for ANY Checking flap on both sides from here on: a renegotiation
    // of an established session must not re-enter Checking even transiently.
    let monitor_a = spawn_checking_flap_monitor(&pc_a);
    let monitor_b = spawn_checking_flap_monitor(&pc_b);

    // Hold: re-run the full offer/answer exchange. Both sides re-enter
    // set_remote_description with UNCHANGED ICE credentials (the PBX calls
    // ICE start(params) again here).
    signal_loopback(&pc_a, &pc_b).await?;

    // Give any (buggy) state flap time to surface: the defect left both
    // transports stranded in Checking forever.
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_live_session(&pc_a, "offerer");
    assert_live_session(&pc_b, "answerer");

    // The session must still carry data — media keeps flowing during hold.
    ping_pong(&pc_a, &dc_a, b"during-hold").await?;

    // Sustained-stability window: the state must stay live (keepalives and
    // TURN refresh keep running) for a stretch after the renegotiation, not
    // just at the instant of sampling.
    for i in 0..8 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_live_session(&pc_a, "offerer");
        assert_live_session(&pc_b, "answerer");
        ping_pong(&pc_a, &dc_a, format!("hold-window-{i}").as_bytes()).await?;
    }

    // Resume: another identical renegotiation must behave the same way.
    signal_loopback(&pc_a, &pc_b).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_live_session(&pc_a, "offerer");
    assert_live_session(&pc_b, "answerer");
    ping_pong(&pc_a, &dc_a, b"after-resume").await?;

    assert!(
        !monitor_a.await.unwrap(),
        "offerer: ICE connection state flapped to Checking during renegotiation"
    );
    assert!(
        !monitor_b.await.unwrap(),
        "answerer: ICE connection state flapped to Checking during renegotiation"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hold_renegotiation_from_answerer_side_keeps_ice_connected() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let (pc_a, pc_b, dc_a, _dc_b) = setup_echo_pair("t2").await?;
    ping_pong(&pc_a, &dc_a, b"before-hold").await?;

    let monitor_a = spawn_checking_flap_monitor(&pc_a);
    let monitor_b = spawn_checking_flap_monitor(&pc_b);

    // The PBX (original answerer in some deployments) re-offers the hold; the
    // offerer answers with unchanged credentials.
    signal_loopback(&pc_b, &pc_a).await?;
    tokio::time::sleep(Duration::from_millis(500)).await;

    assert_live_session(&pc_a, "offerer");
    assert_live_session(&pc_b, "answerer");
    ping_pong(&pc_a, &dc_a, b"during-hold").await?;

    assert!(
        !monitor_a.await.unwrap(),
        "offerer: ICE connection state flapped to Checking during renegotiation"
    );
    assert!(
        !monitor_b.await.unwrap(),
        "answerer: ICE connection state flapped to Checking during renegotiation"
    );
    Ok(())
}
