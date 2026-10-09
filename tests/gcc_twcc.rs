#![cfg(feature = "std")]

// E2E tests: TWCC feedback + GCC bandwidth adaptation loop.
//
// PC1 sends video (transport-cc sequence numbers stamped on the wire when the
// extension is negotiated); PC2 generates TWCC feedback; PC1's GCC estimator
// consumes it and moves `target_bitrate` off its start value.
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::MediaKind;
use rustrtc::media::MediaSample;
use rustrtc::transports::ice::IceGathererState;
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters};
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

fn video_params() -> RtpCodecParameters {
    RtpCodecParameters {
        payload_type: 96,
        name: "VP8".to_string(),
        clock_rate: 90000,
        channels: 0,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gcc_loop_runs_over_loopback() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc1 = PeerConnection::new(RtcConfiguration {
        enable_gcc: true,
        ..Default::default()
    });
    let pc2 = PeerConnection::new(RtcConfiguration {
        enable_gcc: true,
        ..Default::default()
    });

    // PC1: sender with a live video source.
    let (source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::MediaKind::Video, 100);
    let sender = pc1.add_track(track.clone(), video_params())?;

    // PC2: receive-only video.
    pc2.add_transceiver(MediaKind::Video, rustrtc::TransceiverDirection::RecvOnly);

    // Signal.
    let _ = pc1.create_offer().await?;
    wait_gather_complete(&pc1).await;
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;
    let _ = pc2.create_answer().await?;
    wait_gather_complete(&pc2).await;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // The offer must have negotiated the transport-cc extension.
    let extmap = pc1
        .get_transceivers()
        .first()
        .map(|t| t.get_extmap())
        .unwrap_or_default();
    let tcc_id = extmap
        .iter()
        .find(|(_, uri)| uri.as_str() == rustrtc::sdp::TRANSPORT_CC_URI)
        .map(|(id, _)| *id);
    assert!(
        tcc_id.is_some(),
        "transport-cc extmap must be negotiated, got {extmap:?}"
    );

    // Pump frames.
    let send_task = tokio::spawn(async move {
        let mut seq = 0u32;
        loop {
            let frame = rustrtc::media::VideoFrame {
                rtp_timestamp: seq.wrapping_mul(3000),
                data: bytes::Bytes::from(vec![0u8; 200]),
                is_last_packet: true,
                ..Default::default()
            };
            if source.send(MediaSample::Video(frame)).is_err() {
                break;
            }
            seq += 1;
            tokio::time::sleep(Duration::from_millis(33)).await;
        }
    });

    // Wait for the estimator to observe feedback and move off the start value.
    let moved = timeout(Duration::from_secs(20), async {
        loop {
            if let Some(bitrate) = sender.target_bitrate()
                && bitrate != rustrtc::media::gcc::START_BITRATE_BPS
            {
                break bitrate;
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await;
    send_task.abort();

    let bitrate = moved.map_err(|_| {
        anyhow::anyhow!(
            "GCC target_bitrate never moved off {} — TWCC feedback did not reach the estimator",
            rustrtc::media::gcc::START_BITRATE_BPS
        )
    })?;
    assert!(
        (rustrtc::media::gcc::MIN_BITRATE_BPS..=rustrtc::media::gcc::MAX_BITRATE_BPS)
            .contains(&bitrate),
        "target bitrate {bitrate} out of bounds"
    );

    // The subscription API must observe the same estimate.
    let rx = sender
        .subscribe_target_bitrate()
        .expect("estimator must be installed");
    assert_eq!(*rx.borrow(), bitrate);
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gcc_disabled_skips_transport_cc_extmap() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let pc1 = PeerConnection::new(RtcConfiguration {
        enable_gcc: false,
        ..Default::default()
    });
    let pc2 = PeerConnection::new(RtcConfiguration::default());

    let (_source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::MediaKind::Video, 10);
    let _sender = pc1.add_track(track, video_params())?;
    pc2.add_transceiver(MediaKind::Video, rustrtc::TransceiverDirection::RecvOnly);

    let _ = pc1.create_offer().await?;
    wait_gather_complete(&pc1).await;
    let offer = pc1.create_offer().await?;
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;
    let _ = pc2.create_answer().await?;
    wait_gather_complete(&pc2).await;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;

    let extmap = pc1
        .get_transceivers()
        .first()
        .map(|t| t.get_extmap())
        .unwrap_or_default();
    assert!(
        !extmap
            .values()
            .any(|uri| uri.as_str() == rustrtc::sdp::TRANSPORT_CC_URI),
        "enable_gcc=false must not advertise transport-cc, got {extmap:?}"
    );
    Ok(())
}

/// The per-receiver TWCC feedback flush loop ends with its transport: once
/// both peers are closed and dropped, no task is left on the runtime.
#[tokio::test]
async fn twcc_flush_loop_ends_with_the_connection() -> Result<()> {
    let metrics = tokio::runtime::Handle::current().metrics();
    for enable_gcc in [true, false] {
        let config = || RtcConfiguration {
            enable_gcc,
            ..Default::default()
        };
        let (pc1, pc2) = (PeerConnection::new(config()), PeerConnection::new(config()));
        pc1.add_transceiver(MediaKind::Audio, rustrtc::TransceiverDirection::SendRecv);
        pc1.add_transceiver(MediaKind::Video, rustrtc::TransceiverDirection::SendRecv);

        let _ = pc1.create_offer().await?;
        wait_gather_complete(&pc1).await;
        let offer = pc1.create_offer().await?;
        pc1.set_local_description(offer.clone())?;
        pc2.set_remote_description(offer).await?;
        let _ = pc2.create_answer().await?;
        wait_gather_complete(&pc2).await;
        let answer = pc2.create_answer().await?;
        pc2.set_local_description(answer.clone())?;
        pc1.set_remote_description(answer).await?;
        tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())?;

        pc1.close();
        pc2.close();
        drop((pc1, pc2));
        let drained = timeout(Duration::from_secs(3), async {
            while metrics.num_alive_tasks() > 0 {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        })
        .await;
        assert!(
            drained.is_ok(),
            "enable_gcc={enable_gcc}: {} tasks still alive after close and drop",
            metrics.num_alive_tasks()
        );
    }
    Ok(())
}
