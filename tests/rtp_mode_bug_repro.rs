use anyhow::Result;
use rustrtc::media::MediaStreamTrack;
use rustrtc::{
    MediaKind, PeerConnection, PeerConnectionEvent, RtcConfiguration, RtpCodecParameters, SdpType,
    SessionDescription, TransceiverDirection, TransportMode,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

fn strip_ssrc(sdp: &str) -> String {
    sdp.lines()
        .filter(|line| !line.starts_with("a=ssrc:") && !line.starts_with("a=msid:"))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

fn create_rtp_packet(seq: u16, ssrc: u32, payload_type: u8) -> Vec<u8> {
    let mut packet = Vec::with_capacity(1500);
    // Version 2, No Padding, No Extension, No CSCC
    packet.push(0x80);
    // Marker (bit 7) + Payload Type
    packet.push(payload_type | 0x80); // Marker set
    // Sequence Number
    packet.extend_from_slice(&seq.to_be_bytes());
    // Timestamp
    packet.extend_from_slice(&(seq as u32 * 3000).to_be_bytes());
    // SSRC
    packet.extend_from_slice(&ssrc.to_be_bytes());
    // Payload
    packet.extend(std::iter::repeat(0xAB).take(10));
    packet
}

#[tokio::test]
async fn test_rtp_mode_missing_data_bug_repro() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup Receiver PC (RTP Mode, Late Binding)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    let (track_tx, mut track_rx) = tokio::sync::mpsc::unbounded_channel();
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = pc_clone.recv().await {
            if let PeerConnectionEvent::Track(transceiver) = event {
                let _ = track_tx.send(transceiver);
            }
        }
    });

    // 2. Create No-SSRC Offer to force latching
    let mut config_fake = RtcConfiguration::default();
    config_fake.transport_mode = TransportMode::Rtp;
    let pc_fake = PeerConnection::new(config_fake);
    let (_source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::frame::MediaKind::Video, 100);
    let params = RtpCodecParameters {
        payload_type: 96,
        clock_rate: 90000,
        channels: 0,
    };
    pc_fake.add_track(track, params)?;

    let _ = pc_fake.create_offer().await?;
    pc_fake.wait_for_gathering_complete().await;
    let offer = pc_fake.create_offer().await?;

    let offer_no_ssrc_sdp = strip_ssrc(&offer.to_sdp_string());
    let offer_desc = SessionDescription::parse(SdpType::Offer, &offer_no_ssrc_sdp)?;

    pc.set_remote_description(offer_desc).await?; // This usually sets default receiver SSRC (0 or 2000 etc)

    let _ = pc.create_answer().await?;
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer)?;

    let candidates = pc.ice_transport().local_candidates();
    assert!(!candidates.is_empty(), "PC should have local candidates");
    let pc_addr = candidates[0].address;

    // 3. Setup Sender Socket
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(pc_addr).await?;

    let ssrc = 0x12345678; // Random SSRC
    let payload_type = 96;

    // 4. Send packets
    let packet_count = 10;
    println!("Sending {} packets with SSRC {}", packet_count, ssrc);

    for i in 0..packet_count {
        let packet = create_rtp_packet(i, ssrc, payload_type);
        socket.send(&packet).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // 5. Wait for latching and Verify Data Reception
    let transceiver = tokio::time::timeout(Duration::from_secs(2), track_rx.recv())
        .await?
        .expect("Should receive Track event");

    let track = transceiver.receiver().unwrap().track();

    let received_count = Arc::new(Mutex::new(0));
    let received_count_clone = received_count.clone();

    // Consume track
    tokio::spawn(async move {
        while let Ok(_sample) = track.recv().await {
            let mut c = received_count_clone.lock().await;
            *c += 1;
        }
    });

    // Wait a bit for processing
    tokio::time::sleep(Duration::from_secs(1)).await;

    let count = *received_count.lock().await;
    println!("Received {} packets on track", count);

    // If bug exists, count will be 1 (the first ONE triggered Latching via Provisional Listener)
    // If fixed, count should be near packet_count (some might drop during startup/latching race, but definitely > 1)

    if count <= 1 {
        // This confirms the bug: only the latching packet got through
        return Err(anyhow::anyhow!(
            "Bug Reproduced: Only {} packet received. Subsequence packets lost.",
            count
        ));
    }

    Ok(())
}
