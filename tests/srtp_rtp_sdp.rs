// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use anyhow::Result;
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};

#[tokio::test]
async fn test_srtp_local_sdp_port() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Srtp;

    let pc = PeerConnection::new(config);

    // Add a transceiver so we have a media section
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

    // Trigger gathering by creating an offer (or just wait if it starts automatically,
    // but usually we need to create offer to establish what we are gathering for)
    // In rustrtc, create_offer triggers gathering if not started?
    // Let's check create_offer implementation or just call it.
    let offer = pc.create_offer().await?;
    pc.set_local_description(offer)?;

    pc.wait_for_gathering_complete().await;

    let local_desc = pc
        .local_description()
        .expect("Local description should be set");
    // Check if we have media sections
    assert!(
        !local_desc.media_sections.is_empty(),
        "Should have media sections"
    );

    for media in &local_desc.media_sections {
        println!("Media: {}, Port: {}", media.mid, media.port);
        assert!(media.port > 0, "Port should be non-zero for SRTP");
        let conn = media
            .connection
            .as_ref()
            .or(local_desc.session.connection.as_ref())
            .expect("Connection line (c=) should be present in session or media section");
        assert!(
            conn.contains("IP4") || conn.contains("IP6"),
            "Connection should contain IP address"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_rtp_local_sdp_port() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;

    let pc = PeerConnection::new(config);

    // Add a transceiver so we have a media section
    pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

    let offer = pc.create_offer().await?;
    pc.set_local_description(offer)?;

    pc.wait_for_gathering_complete().await;

    let local_desc = pc
        .local_description()
        .expect("Local description should be set");

    assert!(
        !local_desc.media_sections.is_empty(),
        "Should have media sections"
    );

    for media in &local_desc.media_sections {
        println!("Media: {}, Port: {}", media.mid, media.port);
        assert!(media.port > 0, "Port should be non-zero for RTP");
        assert!(
            media.connection.is_some() || local_desc.session.connection.is_some(),
            "Connection line (c=) should be present in session or media section"
        );
    }

    Ok(())
}

#[tokio::test]
async fn test_ssrc_negotiation_without_track() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::WebRtc;

    let pc = PeerConnection::new(config);

    // Add a transceiver without adding a track
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendOnly);

    let offer = pc.create_offer().await?;

    // Check if the offer contains a=ssrc
    let sdp = offer.to_sdp_string();
    assert!(
        sdp.contains("a=ssrc:"),
        "SDP should contain a=ssrc even without a track"
    );
    assert!(sdp.contains("a=sendonly"), "SDP should contain a=sendonly");
    assert!(
        sdp.contains("a=msid:"),
        "SDP should contain a=msid in WebRTC mode"
    );

    Ok(())
}
