use rustrtc::sdp::{
    Attribute, Direction, MediaSection, SdpType, SessionDescription, SessionSection,
};
/// Comprehensive tests for reinvite functionality with proper WebRTC flow
/// Tests cover: Offerer/Answerer timing, SSRC changes, Direction changes, parameter validation
use rustrtc::*;

/// Helper to create a minimal valid SDP
fn create_minimal_sdp(sdp_type: SdpType, mid: &str, direction: Direction) -> SessionDescription {
    let mut desc = SessionDescription::new(sdp_type);
    desc.session = SessionSection::default();

    let mut section = MediaSection::new(MediaKind::Audio, mid);
    section.direction = direction;
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some("111 opus/48000/2".to_string()),
    ));
    section.attributes.push(Attribute::new(
        "extmap",
        Some("1 urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string()),
    ));
    section
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    desc.media_sections.push(section);
    desc
}

/// Test 1: Offerer timing - parameters should apply when answer is received
#[tokio::test]
async fn test_reinvite_offerer_timing() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    pc.add_transceiver(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    );

    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_local_description(initial_offer.clone()).unwrap();

    // Simulate initial answer
    let initial_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_answer).await.unwrap();

    // Now established. Initiate reinvite with PT change
    let mut reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    reinvite_offer.media_sections[0].attributes.clear();
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("120 opus/48000/2".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    pc.set_local_description(reinvite_offer.clone()).unwrap();

    // At this point, Offerer SHOULD have applied the change (own intent)
    let transceivers = pc.get_transceivers();
    let payload_map_after_offer = transceivers[0].get_payload_map();
    assert!(
        payload_map_after_offer.contains_key(&120),
        "Payload map should contain PT 120 after sending offer"
    );

    // Receive answer confirming the change
    let mut reinvite_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    reinvite_answer.media_sections[0].attributes.clear();
    reinvite_answer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("120 opus/48000/2".to_string()),
        ));
    reinvite_answer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    pc.set_remote_description(reinvite_answer).await.unwrap();

    // Still should have PT 120
    let transceivers = pc.get_transceivers();
    assert_eq!(transceivers.len(), 1);

    let payload_map = transceivers[0].get_payload_map();
    assert!(
        payload_map.contains_key(&120),
        "Payload map should still contain PT 120 after answer"
    );
}

/// Test 2: Answerer timing - parameters should apply when offer is received
#[tokio::test]
async fn test_reinvite_answerer_timing() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Simulate being the answerer - receive initial offer
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_offer).await.unwrap();

    // Create answer
    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Now established. Receive reinvite offer with PT change
    let mut reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    reinvite_offer.media_sections[0].attributes.clear();
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("120 opus/48000/2".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    // Answerer should apply changes immediately when receiving offer
    pc.set_remote_description(reinvite_offer).await.unwrap();

    // Verify changes applied
    let transceivers = pc.get_transceivers();
    assert_eq!(transceivers.len(), 1);

    let payload_map = transceivers[0].get_payload_map();
    assert!(payload_map.contains_key(&120));
    assert!(!payload_map.contains_key(&111));
}

/// Test 3: SSRC change detection
#[tokio::test]
async fn test_ssrc_change_detection() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Reinvite with SSRC change (should log warning)
    let mut reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    reinvite_offer.media_sections[0].attributes.clear();
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("111 opus/48000/2".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("99999 cname:test".to_string()))); // Changed SSRC

    // Should not fail, but should log warning
    let result = pc.set_remote_description(reinvite_offer).await;
    assert!(result.is_ok());

    // In full implementation, this would create a new receiver
    // For now, we just verify it doesn't crash
}

/// Test 4: Direction change - SendRecv to SendOnly (hold)
#[tokio::test]
async fn test_direction_change_hold() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    pc.add_transceiver(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    );

    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_local_description(initial_offer).unwrap();

    let initial_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_answer).await.unwrap();

    let reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    pc.set_remote_description(reinvite_offer).await.unwrap();

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer).unwrap();

    let transceivers = pc.get_transceivers();
    assert_eq!(
        transceivers[0].direction(),
        peer_connection::TransceiverDirection::SendOnly
    );
}

/// Test 5: Direction change - SendOnly to SendRecv (unhold)
#[tokio::test]
async fn test_direction_change_unhold() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation with SendOnly
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Reinvite to resume (SendRecv)
    let reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(reinvite_offer).await.unwrap();

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer).unwrap();

    // Direction should be updated to SendRecv
    let transceivers = pc.get_transceivers();
    assert_eq!(
        transceivers[0].direction(),
        peer_connection::TransceiverDirection::SendRecv
    );
}

/// Test 6: Direction change - SendRecv to Inactive
#[tokio::test]
async fn test_direction_change_inactive() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Reinvite to inactive
    let reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::Inactive);
    pc.set_remote_description(reinvite_offer).await.unwrap();

    // Direction should be inactive
    let transceivers = pc.get_transceivers();
    assert_eq!(
        transceivers[0].direction(),
        peer_connection::TransceiverDirection::Inactive
    );
}

/// Test 7: Multiple parameter changes in one reinvite
#[tokio::test]
async fn test_combined_parameter_changes() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Reinvite with multiple changes
    let mut reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    reinvite_offer.media_sections[0].attributes.clear();
    // Change PT
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("120 opus/48000/2".to_string()),
        ));
    // Change extmap ID
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "extmap",
            Some("5 urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string()),
        ));
    // Keep SSRC same
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    pc.set_remote_description(reinvite_offer).await.unwrap();

    // Verify all changes applied
    let transceivers = pc.get_transceivers();
    let t = &transceivers[0];

    // Check direction
    assert_eq!(
        t.direction(),
        peer_connection::TransceiverDirection::SendOnly
    );

    // Check payload map
    let payload_map = t.get_payload_map();
    assert!(payload_map.contains_key(&120));
    assert!(!payload_map.contains_key(&111));

    // Check extmap
    let extmap = t.get_extmap();
    assert!(extmap.contains_key(&5));
    assert!(!extmap.contains_key(&1));
}

/// Test 8: Reject reinvite in invalid state (glare detection)
#[tokio::test]
async fn test_glare_detection() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    pc.add_transceiver(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    );

    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_local_description(initial_offer).unwrap();

    let initial_answer = create_minimal_sdp(SdpType::Answer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_answer).await.unwrap();

    // Start local reinvite (state becomes HaveLocalOffer)
    let local_reinvite = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_local_description(local_reinvite).unwrap();

    // Now receive remote reinvite while in HaveLocalOffer state (glare!)
    let remote_reinvite = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    let result = pc.set_remote_description(remote_reinvite).await;

    // Should fail with InvalidState
    assert!(result.is_err());
    if let Err(e) = result {
        assert!(matches!(e, RtcError::InvalidState(_)));
    }
}

/// Test 9: Multiple sequential reinvites
#[tokio::test]
async fn test_sequential_reinvites() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Initial negotiation
    let initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // First reinvite: PT 111 -> 120
    let mut reinvite1 = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    reinvite1.media_sections[0].attributes.clear();
    reinvite1.media_sections[0].attributes.push(Attribute::new(
        "rtpmap",
        Some("120 opus/48000/2".to_string()),
    ));
    reinvite1.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));
    pc.set_remote_description(reinvite1).await.unwrap();

    // Need to create and send answer to return to stable state
    let answer1 = pc.create_answer().await.unwrap();
    pc.set_local_description(answer1).unwrap();

    let transceivers = pc.get_transceivers();
    assert!(transceivers[0].get_payload_map().contains_key(&120));

    // Second reinvite: PT 120 -> 96
    let mut reinvite2 = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    reinvite2.media_sections[0].attributes.clear();
    reinvite2.media_sections[0].attributes.push(Attribute::new(
        "rtpmap",
        Some("96 opus/48000/2".to_string()),
    ));
    reinvite2.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));
    pc.set_remote_description(reinvite2).await.unwrap();

    let answer2 = pc.create_answer().await.unwrap();
    pc.set_local_description(answer2).unwrap();

    let transceivers = pc.get_transceivers();
    let payload_map = transceivers[0].get_payload_map();
    assert!(payload_map.contains_key(&96));
    assert!(!payload_map.contains_key(&120));
    assert_eq!(
        transceivers[0].direction(),
        peer_connection::TransceiverDirection::SendOnly
    );
}

/// Test 10: Extmap ID changes
#[tokio::test]
async fn test_extmap_changes_in_reinvite() {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Add transceiver first (answerer must have transceiver to receive remote offer)
    pc.add_transceiver(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    );

    // Initial negotiation
    let mut initial_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    initial_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "extmap",
            Some("3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string()),
        ));
    pc.set_remote_description(initial_offer).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    let transceivers = pc.get_transceivers();
    let initial_extmap = transceivers[0].get_extmap();
    // Initial extmap will have what was extracted from SDP
    assert!(
        initial_extmap.len() >= 1,
        "Should have at least one extmap entry"
    );

    // Reinvite: change extmap IDs
    let mut reinvite_offer = create_minimal_sdp(SdpType::Offer, "0", Direction::SendRecv);
    reinvite_offer.media_sections[0].attributes.clear();
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "rtpmap",
            Some("111 opus/48000/2".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "extmap",
            Some("2 urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new(
            "extmap",
            Some("7 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string()),
        ));
    reinvite_offer.media_sections[0]
        .attributes
        .push(Attribute::new("ssrc", Some("12345 cname:test".to_string())));

    pc.set_remote_description(reinvite_offer).await.unwrap();

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer).unwrap();

    let transceivers = pc.get_transceivers();
    let new_extmap = transceivers[0].get_extmap();
    // Verify new extmap IDs
    assert!(
        new_extmap.contains_key(&2),
        "Should contain new extmap ID 2"
    );
    assert!(
        new_extmap.contains_key(&7),
        "Should contain new extmap ID 7"
    );
}
