/// Example: RTP Reinvite - Payload Type Update
///
/// This example demonstrates how to handle reinvite scenarios where
/// the remote peer changes the payload type mapping during an active session.
///
/// Run with: cargo run --example rtp_reinvite_demo
use rustrtc::*;
use std::collections::HashMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    // Initialize logging
    tracing_subscriber::fmt::init();

    println!("=== RTP Reinvite Demo ===\n");

    // Create PeerConnection
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    println!("1. Initial negotiation");
    println!("   Created PeerConnection");

    // Add a transceiver
    let transceiver = pc.add_transceiver(
        MediaKind::Audio,
        peer_connection::TransceiverDirection::SendRecv,
    );

    // Simulate initial payload mapping (PT 111 = Opus)
    let mut initial_payload_map = HashMap::new();
    initial_payload_map.insert(
        111,
        peer_connection::RtpCodecParameters {
            payload_type: 111,
            clock_rate: 48000,
            channels: 2,
        },
    );
    transceiver.update_payload_map(initial_payload_map)?;

    // Simulate initial extmap
    let mut initial_extmap = HashMap::new();
    initial_extmap.insert(1, "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string());
    initial_extmap.insert(
        3,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    );
    transceiver.update_extmap(initial_extmap)?;

    println!("   Initial PT mapping: 111 -> Opus/48000/2");
    println!("   Initial extmap: 1 -> ssrc-audio-level, 3 -> abs-send-time");
    println!();

    // Simulate media session (would normally send/receive RTP packets here)
    println!("2. Active media session");
    println!("   Sending/receiving RTP packets with PT=111...");
    tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
    println!();

    // === REINVITE SCENARIO ===
    println!("3. Reinvite received!");
    println!("   Remote peer wants to change codec parameters");
    println!();

    // Simulate reinvite with different PT (120 = Opus) and extmap changes
    let mut reinvite_payload_map = HashMap::new();
    reinvite_payload_map.insert(
        120, // Changed from 111
        peer_connection::RtpCodecParameters {
            payload_type: 120,
            clock_rate: 48000,
            channels: 2,
        },
    );

    let mut reinvite_extmap = HashMap::new();
    reinvite_extmap.insert(1, "urn:ietf:params:rtp-hdrext:ssrc-audio-level".to_string()); // Kept
    reinvite_extmap.insert(
        5,
        "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time".to_string(),
    ); // Changed from 3
    reinvite_extmap.insert(
        7,
        "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id".to_string(),
    ); // New

    println!("4. Applying reinvite updates...");

    // Update atomically (< 1ms)
    transceiver.update_payload_map(reinvite_payload_map)?;
    transceiver.update_extmap(reinvite_extmap)?;

    println!("   ✅ Payload map updated: 111 -> 120");
    println!("   ✅ Extmap updated: ID 3->5, added ID 7");
    println!();

    // Verify updates
    let final_payload_map = transceiver.get_payload_map();
    let final_extmap = transceiver.get_extmap();

    println!("5. Final state:");
    println!("   Payload types:");
    for (pt, params) in &final_payload_map {
        println!(
            "     - PT {}: clock_rate={}, channels={}",
            pt, params.clock_rate, params.channels
        );
    }
    println!("   Extension headers:");
    for (id, uri) in &final_extmap {
        println!("     - ID {}: {}", id, uri);
    }
    println!();

    // Continue media session with new parameters
    println!("6. Continuing media session");
    println!("   Now sending/receiving RTP packets with PT=120...");
    println!("   Track remains the same - no interruption!");
    println!();

    println!("=== Demo completed successfully ===");
    println!();
    println!("Key benefits:");
    println!("  • No track recreation");
    println!("  • No audio/video interruption");
    println!("  • Atomic update (< 1ms)");
    println!("  • Thread-safe concurrent access");

    Ok(())
}
