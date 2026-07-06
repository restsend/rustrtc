// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use rustrtc::{MediaKind, PeerConnection, RtcConfiguration, TransceiverDirection, TransportMode};

#[tokio::main]
async fn main() {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::WebRtc;

    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    pc.create_data_channel("test", None).unwrap();

    let offer = pc.create_offer().await.unwrap();
    println!("SDP:\n{}", offer.to_sdp_string());
}
