// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use rustrtc::media::MediaStreamTrack;
/// Example demonstrating RTP mode with SSRC latching and Track events
/// This simulates a SIP call scenario where:
/// 1. Initial SDP negotiation creates provisional SSRC
/// 2. When actual RTP packets arrive, SSRC latching occurs
/// 3. Track event is fired after SSRC latching completes
///
/// Run with: cargo run --example rtp_track_event
use rustrtc::*;
use std::sync::Arc;
use std::time::Duration;
use tokio::time::sleep;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::DEBUG)
        .init();

    println!("=== RTP Mode Track Event Example ===\n");

    // Configure PeerConnection for RTP mode (like SIP)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;

    let pc = Arc::new(PeerConnection::new(config));
    println!("✓ Created PeerConnection in RTP mode");

    // Add audio transceiver (simulating SIP call setup)
    let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
    println!("✓ Added audio transceiver (RecvOnly for incoming call)");

    // Simulate remote SDP (from SIP INVITE)
    let remote_sdp = "\
v=0
o=- 123456 123456 IN IP4 10.0.1.100
s=SIP Call
c=IN IP4 10.0.1.100
t=0 0
m=audio 5004 RTP/AVP 8 101
a=rtpmap:8 PCMA/8000
a=rtpmap:101 telephone-event/8000
a=fmtp:101 0-15
a=sendonly
a=mid:0
";

    println!("\n📥 Received remote SDP (simulated SIP INVITE):");
    println!("{}", remote_sdp);

    let remote_offer = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
    pc.set_remote_description(remote_offer).await.unwrap();
    println!("✓ Set remote description");

    // Check initial provisional SSRC
    if let Some(receiver) = transceiver.receiver() {
        let ssrc = receiver.ssrc();
        println!("\n📊 Initial SSRC: {} (provisional, range 2000-2999)", ssrc);
        assert!((2000..3000).contains(&ssrc), "Should be provisional SSRC");
    }

    // Create answer
    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).unwrap();
    println!("\n📤 Created and set local answer (200 OK):");
    println!("{}\n", answer.to_sdp_string());

    // Start event monitoring
    println!("🎧 Starting event loop to monitor Track events...");
    println!("   In real SIP scenario:");
    println!("   1. Caller sends RTP packets with actual SSRC (e.g., 4233615230)");
    println!("   2. rustrtc performs SSRC latching");
    println!("   3. PeerConnectionEvent::Track is fired");
    println!("   4. Application spawns track handler to process audio");

    // Spawn event listener
    let pc_clone = pc.clone();
    let event_task = tokio::spawn(async move {
        let mut event_count = 0;
        loop {
            if let Some(event) = pc_clone.recv().await {
                event_count += 1;
                match event {
                    PeerConnectionEvent::Track(transceiver) => {
                        println!("\n🎉 EVENT: Track event received! (event #{})", event_count);
                        if let Some(receiver) = transceiver.receiver() {
                            let track = receiver.track();
                            let ssrc = receiver.ssrc();
                            println!("   Track kind: {:?}", track.kind());
                            println!("   Final SSRC: {} (latched from RTP packet)", ssrc);
                            println!("   ✓ Application can now spawn track handler");
                            return;
                        }
                    }
                    PeerConnectionEvent::DataChannel(_) => {
                        // Not relevant for RTP mode
                    }
                }
            } else {
                break;
            }
        }
    });

    println!("\n⏳ Waiting for RTP packets (in real scenario)...");
    println!("   Note: This example doesn't send actual RTP packets");
    println!("   In production:");
    println!("   - SIP endpoint sends RTP to our address");
    println!("   - rustrtc receives packets and performs SSRC latching");
    println!("   - Track event fires automatically");

    // Simulate waiting
    sleep(Duration::from_secs(2)).await;

    println!("\n✅ Example complete!");
    println!("\nKey Takeaways:");
    println!("  • RTP mode uses provisional SSRC (2000-2999) initially");
    println!("  • Actual SSRC is learned from first RTP packet (SSRC latching)");
    println!("  • Track event fires AFTER latching completes");
    println!("  • Application should wait for Track event before spawning handlers");

    // Cleanup
    event_task.abort();
}
