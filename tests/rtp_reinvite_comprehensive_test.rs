// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
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
        !initial_extmap.is_empty(),
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

/// Test 11: Reinvite updates RTP remote address
#[tokio::test]
async fn test_reinvite_updates_remote_addr() {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);

    // Initial negotiation as answerer
    let initial_offer = "v=0\r\n\
        o=- 1 1 IN IP4 10.0.0.1\r\n\
        s=-\r\n\
        t=0 0\r\n\
        c=IN IP4 10.0.0.1\r\n\
        m=audio 8000 RTP/AVP 0\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=sendrecv\r\n";

    let initial_offer_desc = SessionDescription::parse(SdpType::Offer, initial_offer).unwrap();
    pc.set_remote_description(initial_offer_desc).await.unwrap();

    let initial_answer = pc.create_answer().await.unwrap();
    pc.set_local_description(initial_answer).unwrap();

    // Verify initial remote address
    let initial_pair: Option<rustrtc::transports::ice::IceCandidatePair> =
        pc.ice_transport().get_selected_pair();
    assert!(initial_pair.is_some());
    assert_eq!(
        initial_pair.unwrap().remote.address,
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            8000
        )
    );

    // Reinvite with changed address
    let reinvite_offer = "v=0\r\n\
        o=- 1 2 IN IP4 192.168.1.50\r\n\
        s=-\r\n\
        t=0 0\r\n\
        c=IN IP4 192.168.1.50\r\n\
        m=audio 9000 RTP/AVP 0\r\n\
        a=rtpmap:0 PCMU/8000\r\n\
        a=sendrecv\r\n";

    let reinvite_desc = SessionDescription::parse(SdpType::Offer, reinvite_offer).unwrap();
    pc.set_remote_description(reinvite_desc).await.unwrap();

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer).unwrap();

    // Verify selected_pair reflects new remote address after reinvite
    let updated_pair: Option<rustrtc::transports::ice::IceCandidatePair> =
        pc.ice_transport().get_selected_pair();
    assert!(updated_pair.is_some());
    assert_eq!(
        updated_pair.unwrap().remote.address,
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50)),
            9000
        ),
        "reinvite should update RTP remote address"
    );
}

/// Helper: an RTP-mode peer connection with an audio sender, so offers are
/// not downgraded for lack of a track.
fn rtp_pc_with_audio_sender() -> PeerConnection {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);
    let (_source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::MediaKind::Audio, 10);
    let params = RtpCodecParameters {
        payload_type: 111,
        name: "opus".to_string(),
        clock_rate: 48000,
        channels: 2,
    };
    pc.add_track(track, params).unwrap();
    pc
}

/// Remote offers `direction`; we answer and return the answer's direction.
async fn answer_remote_offer(pc: &PeerConnection, direction: Direction) -> Direction {
    let offer = create_minimal_sdp(SdpType::Offer, "0", direction);
    pc.set_remote_description(offer).await.unwrap();
    let answer = pc.create_answer().await.unwrap();
    let answered = answer.media_sections[0].direction;
    pc.set_local_description(answer).unwrap();
    answered
}

/// We offer and the remote answers `direction`; returns our offer's direction.
async fn reoffer(pc: &PeerConnection, remote_answer: Direction) -> Direction {
    let offer = pc.create_offer().await.unwrap();
    let offered = offer.media_sections[0].direction;
    pc.set_local_description(offer).unwrap();
    let answer = create_minimal_sdp(SdpType::Answer, "0", remote_answer);
    pc.set_remote_description(answer).await.unwrap();
    offered
}

/// Test 11: after answering a remote hold (`sendonly` answered `recvonly`),
/// our next offer (e.g. for a re-INVITE without SDP) must carry OUR direction,
/// never echo the remote's `sendonly`. We did not initiate the hold, so we
/// offer `sendrecv` (RFC 3264 §6.1, RFC 6337 §5.3); the remote keeps its hold
/// by answering `sendonly`.
#[tokio::test]
async fn test_reoffer_after_remote_hold_uses_local_direction() {
    let pc = rtp_pc_with_audio_sender();
    assert_eq!(
        answer_remote_offer(&pc, Direction::SendRecv).await,
        Direction::SendRecv
    );
    assert_eq!(
        answer_remote_offer(&pc, Direction::SendOnly).await,
        Direction::RecvOnly,
        "a remote hold is answered recvonly"
    );

    let offered = reoffer(&pc, Direction::SendOnly).await;
    assert_ne!(
        offered,
        Direction::SendOnly,
        "re-offer must not echo the remote's sendonly"
    );
    assert_eq!(offered, Direction::SendRecv, "re-offer after remote hold");

    // The remote kept its hold (answered sendonly); offering again still
    // expresses our own direction rather than mirroring the answer.
    assert_eq!(
        reoffer(&pc, Direction::SendOnly).await,
        Direction::SendRecv,
        "re-offer after the remote answered sendonly"
    );
}

/// Test 12: after the remote resumes (`sendrecv`), our re-offer is `sendrecv`.
#[tokio::test]
async fn test_reoffer_after_remote_resume_is_sendrecv() {
    let pc = rtp_pc_with_audio_sender();
    answer_remote_offer(&pc, Direction::SendRecv).await;
    answer_remote_offer(&pc, Direction::SendOnly).await;
    assert_eq!(
        answer_remote_offer(&pc, Direction::SendRecv).await,
        Direction::SendRecv
    );
    assert_eq!(reoffer(&pc, Direction::SendRecv).await, Direction::SendRecv);
}

/// Test 13: after answering a remote `inactive` hold, our re-offer carries
/// our own direction, not `inactive`.
#[tokio::test]
async fn test_reoffer_after_remote_inactive_uses_local_direction() {
    let pc = rtp_pc_with_audio_sender();
    answer_remote_offer(&pc, Direction::SendRecv).await;
    assert_eq!(
        answer_remote_offer(&pc, Direction::Inactive).await,
        Direction::Inactive
    );
    assert_eq!(reoffer(&pc, Direction::Inactive).await, Direction::SendRecv);
}

/// Test 14: a hold WE initiated (`sendonly`, answered `recvonly`) is offered
/// again on the next re-offer (RFC 6337 §5.3), not flipped to the remote's
/// `recvonly`; clearing it offers `sendrecv` again.
#[tokio::test]
async fn test_reoffer_keeps_locally_initiated_hold() {
    let pc = rtp_pc_with_audio_sender();
    answer_remote_offer(&pc, Direction::SendRecv).await;

    let t = pc.get_transceivers()[0].clone();
    t.set_direction(peer_connection::TransceiverDirection::SendOnly);
    assert_eq!(reoffer(&pc, Direction::RecvOnly).await, Direction::SendOnly);
    assert_eq!(
        reoffer(&pc, Direction::RecvOnly).await,
        Direction::SendOnly,
        "a locally initiated hold is offered again"
    );

    t.set_direction(peer_connection::TransceiverDirection::SendRecv);
    assert_eq!(reoffer(&pc, Direction::SendRecv).await, Direction::SendRecv);
}

/// Test 15: a transceiver created by a remote `sendonly` offer, with no local
/// track, re-offers `recvonly` (what we can do), not `sendonly` or `inactive`.
#[tokio::test]
async fn test_reoffer_from_remote_created_transceiver_without_sender() {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);
    assert_eq!(
        answer_remote_offer(&pc, Direction::SendOnly).await,
        Direction::RecvOnly
    );
    assert_eq!(reoffer(&pc, Direction::SendOnly).await, Direction::RecvOnly);
}

/// Test 16: guard — initial offers still carry the transceiver's direction,
/// and answers still mirror the remote offer, for every direction.
#[tokio::test]
async fn test_initial_offer_and_answer_directions_unchanged() {
    use peer_connection::TransceiverDirection as TD;
    for (local, offered) in [
        (TD::SendRecv, Direction::SendRecv),
        (TD::SendOnly, Direction::SendOnly),
        (TD::RecvOnly, Direction::RecvOnly),
        (TD::Inactive, Direction::Inactive),
    ] {
        let pc = rtp_pc_with_audio_sender();
        pc.get_transceivers()[0].set_direction(local);
        let offer = pc.create_offer().await.unwrap();
        assert_eq!(offer.media_sections[0].direction, offered, "{local:?}");
    }

    for (remote, answered) in [
        (Direction::SendRecv, Direction::SendRecv),
        (Direction::SendOnly, Direction::RecvOnly),
        (Direction::RecvOnly, Direction::SendOnly),
        (Direction::Inactive, Direction::Inactive),
    ] {
        let pc = rtp_pc_with_audio_sender();
        assert_eq!(
            answer_remote_offer(&pc, remote).await,
            answered,
            "{remote:?}"
        );
    }
}

/// Test 17: whatever direction the remote last offered or answered, our next
/// offer carries our own (default sendrecv) direction.
#[tokio::test]
async fn test_reoffer_direction_independent_of_remote_direction() {
    let all = [
        Direction::SendRecv,
        Direction::SendOnly,
        Direction::RecvOnly,
        Direction::Inactive,
    ];
    for remote in all {
        // Remote offered `remote`, we answered.
        let pc = rtp_pc_with_audio_sender();
        answer_remote_offer(&pc, remote).await;
        assert_eq!(
            reoffer(&pc, Direction::SendRecv).await,
            Direction::SendRecv,
            "after remote offer {remote:?}"
        );

        // We offered, remote answered `remote`.
        let pc = rtp_pc_with_audio_sender();
        assert_eq!(reoffer(&pc, remote).await, Direction::SendRecv);
        assert_eq!(
            reoffer(&pc, Direction::SendRecv).await,
            Direction::SendRecv,
            "after remote answer {remote:?}"
        );
    }
}

/// A hold we start with a hand-built offer (`set_local_description` without
/// `create_offer`) is kept by later re-offers, like one set with
/// `set_direction` (RFC 6337 §5.3).
#[tokio::test]
async fn test_reoffer_keeps_hold_from_hand_built_local_offer() {
    let pc = rtp_pc_with_audio_sender();
    answer_remote_offer(&pc, Direction::SendRecv).await;

    let mut hold = pc.create_offer().await.unwrap();
    hold.media_sections[0].direction = Direction::SendOnly;
    pc.set_local_description(hold).unwrap();
    let answer = create_minimal_sdp(SdpType::Answer, "0", Direction::RecvOnly);
    pc.set_remote_description(answer).await.unwrap();

    assert_eq!(
        reoffer(&pc, Direction::RecvOnly).await,
        Direction::SendOnly,
        "a hand-built hold is offered again"
    );
}

/// The same for the very first offer, hand-built without `create_offer`
/// (the transceiver has no MID until this offer assigns one).
#[tokio::test]
async fn test_reoffer_keeps_hold_from_hand_built_initial_offer() {
    let pc = rtp_pc_with_audio_sender();
    let hold = create_minimal_sdp(SdpType::Offer, "0", Direction::SendOnly);
    pc.set_local_description(hold).unwrap();
    let answer = create_minimal_sdp(SdpType::Answer, "0", Direction::RecvOnly);
    pc.set_remote_description(answer).await.unwrap();
    assert_eq!(reoffer(&pc, Direction::RecvOnly).await, Direction::SendOnly);
}
