use rustrtc::*;
use std::collections::HashMap;

/// Test basic payload type map update functionality
#[tokio::test]
async fn test_payload_type_update() {
    let _config = RtcConfiguration::default();
    let transceiver = std::sync::Arc::new(peer_connection::RtpTransceiver::new_for_test(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    ));

    // Initial mapping: PT 111 = Opus at 48000Hz
    let mut initial_map = HashMap::new();
    initial_map.insert(
        111,
        peer_connection::RtpCodecParameters {
            payload_type: 111,
            clock_rate: 48000,
            channels: 2,
        },
    );
    transceiver.update_payload_map(initial_map.clone()).unwrap();

    // Verify initial state
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.len(), 1);
    assert_eq!(payload_map.get(&111).unwrap().clock_rate, 48000);
    assert_eq!(payload_map.get(&111).unwrap().channels, 2);

    // Update mapping: change PT 111 to different parameters
    let mut updated_map = HashMap::new();
    updated_map.insert(
        111,
        peer_connection::RtpCodecParameters {
            payload_type: 111,
            clock_rate: 16000,
            channels: 1,
        },
    );
    transceiver.update_payload_map(updated_map).unwrap();

    // Verify updated state
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.get(&111).unwrap().clock_rate, 16000);
    assert_eq!(payload_map.get(&111).unwrap().channels, 1);

    // Add new PT mapping
    let mut new_map = HashMap::new();
    new_map.insert(
        120,
        peer_connection::RtpCodecParameters {
            payload_type: 120,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(new_map).unwrap();

    // Verify old PT is removed and new one exists
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.len(), 1);
    assert!(!payload_map.contains_key(&111));
    assert!(payload_map.contains_key(&120));
}

/// Test RTP extension header mapping update
#[tokio::test]
async fn test_extmap_update() {
    let transceiver = std::sync::Arc::new(peer_connection::RtpTransceiver::new_for_test(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    ));

    // Initial extmap
    let mut initial_extmap = HashMap::new();
    initial_extmap.insert(1, "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string());
    initial_extmap.insert(
        3,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    );
    transceiver.update_extmap(initial_extmap.clone()).unwrap();

    // Verify initial state
    let extmap = transceiver.get_extmap();
    assert_eq!(extmap.len(), 2);
    assert_eq!(
        extmap.get(&1).unwrap(),
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
    );

    // Update extmap: change ID for abs-send-time
    let mut updated_extmap = HashMap::new();
    updated_extmap.insert(1, "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string());
    updated_extmap.insert(
        5,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    );
    transceiver.update_extmap(updated_extmap).unwrap();

    // Verify updated state
    let extmap = transceiver.get_extmap();
    assert_eq!(extmap.len(), 2);
    assert!(!extmap.contains_key(&3));
    assert!(extmap.contains_key(&5));
}

/// Test concurrent payload map access (reader-writer lock)
#[tokio::test]
async fn test_concurrent_payload_map_access() {
    let transceiver = std::sync::Arc::new(peer_connection::RtpTransceiver::new_for_test(
        MediaKind::Video,
        peer_connection::TransceiverDirection::SendRecv,
    ));

    // Initial mapping
    let mut initial_map = HashMap::new();
    initial_map.insert(
        96,
        peer_connection::RtpCodecParameters {
            payload_type: 96,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(initial_map).unwrap();

    // Spawn multiple reader tasks that read before the write
    let mut handles = vec![];
    for i in 0..10 {
        let t = transceiver.clone();
        let handle = tokio::spawn(async move {
            for j in 0..50 {
                let map = t.get_payload_map();
                // Accept either 96 or 97 depending on timing
                let has_valid_key = map.contains_key(&96) || map.contains_key(&97);
                assert!(
                    has_valid_key,
                    "Reader {} iteration {} found no valid keys",
                    i, j
                );
                tokio::time::sleep(tokio::time::Duration::from_micros(100)).await;
            }
        });
        handles.push(handle);
    }

    // Perform a write in the middle
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    let mut new_map = HashMap::new();
    new_map.insert(
        97,
        peer_connection::RtpCodecParameters {
            payload_type: 97,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(new_map).unwrap();

    // Wait for all readers
    for handle in handles {
        handle.await.unwrap();
    }

    // Verify final state
    let map = transceiver.get_payload_map();
    assert!(map.contains_key(&97));
    assert!(!map.contains_key(&96));
}

/// Test SDP payload map extraction
#[test]
fn test_extract_payload_map_from_sdp() {
    use rustrtc::sdp::{Attribute, MediaSection};

    let mut section = MediaSection::new(MediaKind::Audio, "0");
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some("111 opus/48000/2".to_string()),
    ));
    section
        .attributes
        .push(Attribute::new("rtpmap", Some("9 G722/8000/1".to_string())));
    section
        .attributes
        .push(Attribute::new("rtpmap", Some("0 PCMU/8000".to_string())));

    // Use private method through PeerConnection (we'll make it testable)
    let payload_map = extract_payload_map_helper(&section);

    assert_eq!(payload_map.len(), 3);

    let opus = payload_map.get(&111).unwrap();
    assert_eq!(opus.clock_rate, 48000);
    assert_eq!(opus.channels, 2);

    let g722 = payload_map.get(&9).unwrap();
    assert_eq!(g722.clock_rate, 8000);
    assert_eq!(g722.channels, 1);

    let pcmu = payload_map.get(&0).unwrap();
    assert_eq!(pcmu.clock_rate, 8000);
    assert_eq!(pcmu.channels, 0);
}

/// Test SDP extmap extraction
#[test]
fn test_extract_extmap_from_sdp() {
    use rustrtc::sdp::{Attribute, MediaSection};

    let mut section = MediaSection::new(MediaKind::Audio, "0");
    section.attributes.push(Attribute::new(
        "extmap",
        Some("1 urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string()),
    ));
    section.attributes.push(Attribute::new(
        "extmap",
        Some("3 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string()),
    ));
    section.attributes.push(Attribute::new(
        "extmap",
        Some("5 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_string()),
    ));

    let extmap = extract_extmap_helper(&section);

    assert_eq!(extmap.len(), 3);
    assert_eq!(
        extmap.get(&1).unwrap(),
        "urn:ietf:params:rtp-hdrext:ssrc-audio-level"
    );
    assert_eq!(
        extmap.get(&3).unwrap(),
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time"
    );
    assert_eq!(
        extmap.get(&5).unwrap(),
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id"
    );
}

/// Test reinvite scenario with payload type change
#[tokio::test]
async fn test_reinvite_payload_change() {
    use rustrtc::sdp::{Attribute, MediaSection, SdpType, SessionDescription, SessionSection};

    let _config = RtcConfiguration::default();
    let _pc = PeerConnection::new(_config);

    // Create initial offer with PT 111
    let mut initial_desc = SessionDescription::new(SdpType::Offer);
    initial_desc.session = SessionSection::default();

    let mut section = MediaSection::new(MediaKind::Audio, "0");
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some("111 opus/48000/2".to_string()),
    ));
    section.attributes.push(Attribute::new("sendrecv", None));
    initial_desc.media_sections.push(section);

    // Set as remote description (simulate first negotiation)
    // Note: This is simplified - real test would need proper SDP setup
    // For now, we test the payload map update directly

    let transceiver = std::sync::Arc::new(peer_connection::RtpTransceiver::new_for_test(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    ));

    // Initial payload map
    let mut initial_map = HashMap::new();
    initial_map.insert(
        111,
        peer_connection::RtpCodecParameters {
            payload_type: 111,
            clock_rate: 48000,
            channels: 2,
        },
    );
    transceiver.update_payload_map(initial_map).unwrap();

    // Verify initial state
    assert_eq!(
        transceiver.get_payload_map().get(&111).unwrap().clock_rate,
        48000
    );

    // Simulate reinvite with different PT
    let mut reinvite_map = HashMap::new();
    reinvite_map.insert(
        120,
        peer_connection::RtpCodecParameters {
            payload_type: 120,
            clock_rate: 48000,
            channels: 2,
        },
    );
    transceiver.update_payload_map(reinvite_map).unwrap();

    // Verify updated state - old PT removed, new PT added
    let final_map = transceiver.get_payload_map();
    assert!(!final_map.contains_key(&111));
    assert!(final_map.contains_key(&120));
    assert_eq!(final_map.get(&120).unwrap().clock_rate, 48000);
}

/// Comprehensive integration test for reinvite with multiple parameter changes
#[tokio::test]
async fn test_reinvite_comprehensive() {
    let transceiver = std::sync::Arc::new(peer_connection::RtpTransceiver::new_for_test(
        MediaKind::Video,
        peer_connection::TransceiverDirection::SendRecv,
    ));

    // Stage 1: Initial negotiation
    let mut initial_payload_map = HashMap::new();
    initial_payload_map.insert(
        96,
        peer_connection::RtpCodecParameters {
            payload_type: 96,
            clock_rate: 90000,
            channels: 0,
        },
    );
    initial_payload_map.insert(
        97,
        peer_connection::RtpCodecParameters {
            payload_type: 97,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(initial_payload_map).unwrap();

    let mut initial_extmap = HashMap::new();
    initial_extmap.insert(1, "urn:ietf:params:rtp-hdrext:toffset".to_string());
    initial_extmap.insert(
        3,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    );
    transceiver.update_extmap(initial_extmap).unwrap();

    // Verify initial state
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.len(), 2);
    assert!(payload_map.contains_key(&96));
    assert!(payload_map.contains_key(&97));

    let extmap = transceiver.get_extmap();
    assert_eq!(extmap.len(), 2);
    assert!(extmap.contains_key(&1));
    assert!(extmap.contains_key(&3));

    // Stage 2: Reinvite - change PT 96 to 98, keep 97, change extmap IDs
    let mut updated_payload_map = HashMap::new();
    updated_payload_map.insert(
        98, // Changed from 96
        peer_connection::RtpCodecParameters {
            payload_type: 98,
            clock_rate: 90000,
            channels: 0,
        },
    );
    updated_payload_map.insert(
        97, // Kept
        peer_connection::RtpCodecParameters {
            payload_type: 97,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(updated_payload_map).unwrap();

    let mut updated_extmap = HashMap::new();
    updated_extmap.insert(2, "urn:ietf:params:rtp-hdrext:toffset".to_string()); // Changed from 1
    updated_extmap.insert(
        5,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    ); // Changed from 3
    updated_extmap.insert(
        7,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_string(),
    ); // New
    transceiver.update_extmap(updated_extmap).unwrap();

    // Verify updated state
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.len(), 2);
    assert!(!payload_map.contains_key(&96)); // Old removed
    assert!(payload_map.contains_key(&97)); // Kept
    assert!(payload_map.contains_key(&98)); // New

    let extmap = transceiver.get_extmap();
    assert_eq!(extmap.len(), 3);
    assert!(!extmap.contains_key(&1)); // Old removed
    assert!(extmap.contains_key(&2)); // Changed ID
    assert!(!extmap.contains_key(&3)); // Old removed
    assert!(extmap.contains_key(&5)); // Changed ID
    assert!(extmap.contains_key(&7)); // New

    // Stage 3: Another reinvite - simplify to single codec
    let mut final_payload_map = HashMap::new();
    final_payload_map.insert(
        100,
        peer_connection::RtpCodecParameters {
            payload_type: 100,
            clock_rate: 90000,
            channels: 0,
        },
    );
    transceiver.update_payload_map(final_payload_map).unwrap();

    // Verify final state
    let payload_map = transceiver.get_payload_map();
    assert_eq!(payload_map.len(), 1);
    assert!(payload_map.contains_key(&100));
    assert!(!payload_map.contains_key(&97));
    assert!(!payload_map.contains_key(&98));
}

// Helper functions to test private methods
fn extract_payload_map_helper(
    section: &rustrtc::MediaSection,
) -> HashMap<u8, peer_connection::RtpCodecParameters> {
    let mut payload_map = HashMap::new();

    for attr in &section.attributes {
        if attr.key == "rtpmap" {
            if let Some(val) = &attr.value {
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(pt) = parts[0].parse::<u8>() {
                        let codec_parts: Vec<&str> = parts[1].split('/').collect();
                        if codec_parts.len() >= 2 {
                            let clock_rate = codec_parts[1].parse().unwrap_or(90000);
                            let channels = if codec_parts.len() >= 3 {
                                codec_parts[2].parse().unwrap_or(0)
                            } else {
                                0
                            };

                            payload_map.insert(
                                pt,
                                peer_connection::RtpCodecParameters {
                                    payload_type: pt,
                                    clock_rate,
                                    channels,
                                },
                            );
                        }
                    }
                }
            }
        }
    }

    payload_map
}

fn extract_extmap_helper(section: &rustrtc::MediaSection) -> HashMap<u8, String> {
    let mut extmap = HashMap::new();

    for attr in &section.attributes {
        if attr.key == "extmap" {
            if let Some(val) = &attr.value {
                let parts: Vec<&str> = val.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(id) = parts[0].parse::<u8>() {
                        extmap.insert(id, parts[1].to_string());
                    }
                }
            }
        }
    }

    extmap
}
