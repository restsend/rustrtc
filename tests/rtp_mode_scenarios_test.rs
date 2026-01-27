use anyhow::Result;
use rustrtc::{
    MediaKind, PeerConnection, PeerConnectionEvent, RtcConfiguration, RtpCodecParameters, SdpType,
    SessionDescription, TransceiverDirection, TransportMode,
};
use std::time::Duration;
use tokio::net::UdpSocket;

fn strip_ssrc(sdp: &str) -> String {
    sdp.lines()
        .filter(|line| !line.starts_with("a=ssrc:") && !line.starts_with("a=msid:"))
        .collect::<Vec<_>>()
        .join("\r\n")
        + "\r\n"
}

// Generate a simple STUN binding request packet
fn create_stun_binding_request() -> Vec<u8> {
    let mut packet = vec![0u8; 20];
    packet[0] = 0x00;
    packet[1] = 0x01; // Binding Request
    // Length 0
    packet[2] = 0x00;
    packet[3] = 0x00;
    // Magic Cookie
    packet[4] = 0x21;
    packet[5] = 0x12;
    packet[6] = 0xA4;
    packet[7] = 0x42;
    // Transaction ID (random)
    for i in 8..20 {
        packet[i] = rand::random();
    }
    packet
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
    packet.extend(std::iter::repeat(0xAB).take(100));
    packet
}

#[tokio::test]
async fn test_rtp_mode_callee_no_ssrc_signaled() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC: Receiver (RTP Mode)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);

    // Add a transceiver to receive
    pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    // Setup track event listener
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = pc_clone.recv().await {
            if let PeerConnectionEvent::Track(transceiver) = event {
                let _ = tx.send(transceiver);
            }
        }
    });

    // 1. Create Offer from a fake remote peer (we construct SDP manually or use a helper PC)
    // We'll use a helper PC to generate valid SDP, then strip SSRC
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

    // Trigger gathering on fake PC to get SDP
    let _ = pc_fake.create_offer().await?;
    pc_fake.wait_for_gathering_complete().await;
    let offer = pc_fake.create_offer().await?;

    // Strip SSRC from offer
    let offer_sdp = offer.to_sdp_string();
    let offer_no_ssrc_sdp = strip_ssrc(&offer_sdp);
    println!("Offer without SSRC:\n{}", offer_no_ssrc_sdp);

    let offer_desc = SessionDescription::parse(SdpType::Offer, &offer_no_ssrc_sdp)?;

    // Set remote description on our DUT PC
    pc.set_remote_description(offer_desc).await?;

    // Create Answer
    let _ = pc.create_answer().await?;
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;

    // Wait for connection (Start UDP listener)
    // In RTP mode, we need to know where to send packets to the PC
    // PC should have gathered a candidate
    let candidates = pc.ice_transport().local_candidates();
    assert!(!candidates.is_empty(), "PC should have local candidates");
    let pc_addr = candidates[0].address;
    println!("PC listening on {}", pc_addr);

    // Send RTP packets from a raw socket
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(pc_addr).await?;

    let ssrc = 123456;
    let payload_type = 96;

    // Send a burst of packets
    for i in 0..50 {
        let packet = create_rtp_packet(i, ssrc, payload_type);
        socket.send(&packet).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    // Expect track event
    match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        Ok(Some(transceiver)) => {
            println!("Received track!");
            if let Some(receiver) = transceiver.receiver() {
                // Wait for latching. Sometimes receiver.ssrc() is updated async or after first packet processed.
                // The Track event might be sent *after* latching in this scenario.
                // Let's verify.
                assert_eq!(receiver.ssrc(), ssrc);
            } else {
                panic!("Transceiver should have a receiver");
            }
        }
        Ok(None) => panic!("Channel closed"),
        Err(_) => panic!("Timeout waiting for track event"),
    }

    Ok(())
}

#[tokio::test]
async fn test_rtp_mode_callee_no_ssrc_signaled_stun_first() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC: Receiver (RTP Mode)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);

    pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = pc_clone.recv().await {
            if let PeerConnectionEvent::Track(transceiver) = event {
                let _ = tx.send(transceiver);
            }
        }
    });

    // Create No-SSRC Offer
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

    pc.set_remote_description(offer_desc).await?;

    let _ = pc.create_answer().await?;
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer)?;

    let candidates = pc.ice_transport().local_candidates();
    assert!(!candidates.is_empty(), "PC should have local candidates");
    let pc_addr = candidates[0].address;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(pc_addr).await?;

    // SEND STUN FIRST
    let stun_packet = create_stun_binding_request();
    socket.send(&stun_packet).await?;
    println!("Sent STUN packet");

    tokio::time::sleep(Duration::from_millis(50)).await;

    let ssrc = 987654;
    let payload_type = 96;

    for i in 0..50 {
        let packet = create_rtp_packet(i, ssrc, payload_type);
        socket.send(&packet).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        Ok(Some(transceiver)) => {
            println!("Received track!");
            if let Some(receiver) = transceiver.receiver() {
                assert_eq!(receiver.ssrc(), ssrc);
            } else {
                panic!("Transceiver should have a receiver");
            }
        }
        Ok(None) => panic!("Channel closed"),
        Err(_) => panic!("Timeout waiting for track event"),
    }

    Ok(())
}

#[tokio::test]
async fn test_rtp_mode_caller_no_ssrc_signaled() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // PC: Caller (RTP Mode)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    let pc = PeerConnection::new(config);

    // Add a transceiver to receive (SendRecv or RecvOnly)
    pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel();
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = pc_clone.recv().await {
            if let PeerConnectionEvent::Track(transceiver) = event {
                let _ = tx.send(transceiver);
            }
        }
    });

    // 1. Create Offer
    let _ = pc.create_offer().await?;
    pc.wait_for_gathering_complete().await;
    let offer = pc.create_offer().await?;
    println!("Caller Offer:\n{}", offer.to_sdp_string());
    pc.set_local_description(offer.clone())?;

    // 2. Create Fake Answer (Remote Peer)
    let mut config_fake = RtcConfiguration::default();
    config_fake.transport_mode = TransportMode::Rtp;
    let pc_fake = PeerConnection::new(config_fake);
    let (_source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::frame::MediaKind::Video, 100);
    // Fake peer needs to offer a track so the answer contains the media section
    let _ = pc_fake.add_track(track, RtpCodecParameters::default())?;

    // Fake peer receives offer
    // Use the offer we generated
    let offer_desc = SessionDescription::parse(SdpType::Offer, &offer.to_sdp_string())?; // Should parse fine since it has SSRC
    pc_fake.set_remote_description(offer_desc).await?;

    let _ = pc_fake.create_answer().await?;
    pc_fake.wait_for_gathering_complete().await;
    let answer = pc_fake.create_answer().await?;

    // Strip SSRC from Answer
    let answer_sdp = answer.to_sdp_string();
    let answer_no_ssrc = strip_ssrc(&answer_sdp);
    println!("Remote Answer without SSRC:\n{}", answer_no_ssrc);

    let answer_desc = SessionDescription::parse(SdpType::Answer, &answer_no_ssrc)?;

    // Set Remote on Caller
    pc.set_remote_description(answer_desc).await?;

    // Connection
    let candidates = pc.ice_transport().local_candidates();
    assert!(!candidates.is_empty());
    let pc_addr = candidates[0].address;

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket.connect(pc_addr).await?;

    let ssrc = 555666;
    let payload_type = 96;

    for i in 0..50 {
        let packet = create_rtp_packet(i, ssrc, payload_type);
        socket.send(&packet).await?;
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    match tokio::time::timeout(Duration::from_secs(5), rx.recv()).await {
        Ok(Some(transceiver)) => {
            println!("Received track!");
            if let Some(receiver) = transceiver.receiver() {
                assert_eq!(receiver.ssrc(), ssrc);
            }
        }
        Ok(None) => panic!("Channel closed"),
        Err(_) => panic!("Timeout waiting for track event"),
    }

    Ok(())
}
