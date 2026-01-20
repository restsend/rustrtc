use anyhow::Result;
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters, SdpType, TransportMode};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_rtp_mode_no_default_extensions() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup PeerConnection (PC) with RTP Mode
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.bind_ip = Some("127.0.0.1".to_string());
    config.rtp_start_port = Some(40200);
    config.rtp_end_port = Some(40300);

    let pc = PeerConnection::new(config);

    // Add track (Video)
    let (source, track_video, _) =
        rustrtc::media::track::sample_track(rustrtc::media::frame::MediaKind::Video, 90000);
    let source = Arc::new(source);

    let params_video = RtpCodecParameters {
        payload_type: 96,
        clock_rate: 90000,
        channels: 0,
    };
    pc.add_track(track_video, params_video)?;

    // 2. Create Offer
    let offer = pc.create_offer().await?;

    // 3. Inspect SDP (Verification Step 1: No extensions in Offer)
    for section in &offer.media_sections {
        for attr in &section.attributes {
            if attr.key == "extmap" {
                if let Some(val) = &attr.value {
                    println!("Found extmap: {}", val);
                    if val.contains("http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time") {
                        panic!("Found abs-send-time extension in RTP mode offer!");
                    }
                    if val.contains("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id") {
                        panic!("Found rid extension in RTP mode offer!");
                    }
                    if val.contains("urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id") {
                        panic!("Found repaired-rid extension in RTP mode offer!");
                    }
                }
            }
        }
    }

    pc.set_local_description(offer.clone())?;

    // 4. Setup Remote Socket & Answer
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let remote_addr = socket.local_addr()?;

    // We clone the offer to make an answer. Since the offer is confirmed clean of extensions,
    // the answer will also be clean. This simulates a detailed negotiation where both sides
    // agree to NO extensions.
    let mut answer = offer.clone();
    answer.sdp_type = SdpType::Answer;

    // Rewrite connection info to point to our socket
    let ip_str = remote_addr.ip().to_string();
    for section in &mut answer.media_sections {
        section.connection = Some(format!("IN IP4 {}", ip_str));
        section.port = remote_addr.port();
        // Remove candidates to ensure it relies on c= line
        section.attributes.retain(|a| a.key != "candidate");
    }

    // Set remote description. This should configure RtpTransport w/o extensions
    pc.set_remote_description(answer).await?;

    // Wait for connection
    let connected = pc.wait_for_connected();
    match tokio::time::timeout(Duration::from_secs(5), connected).await {
        Ok(_) => println!("PC API reports Connected"),
        Err(_) => panic!("PC failed to connect"),
    }

    // 5. Send Media
    let source_clone = source.clone();
    tokio::spawn(async move {
        // Send a few frames
        for i in 0..5 {
            let frame = VideoFrame {
                rtp_timestamp: i * 3000,
                data: bytes::Bytes::from(vec![0u8; 100]),
                is_last_packet: true,
                ..Default::default()
            };
            if source_clone.send(MediaSample::Video(frame)).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    // 6. Receive and Inspect Packet (Verification Step 2: X bit is 0)
    let mut buf = [0u8; 1500];
    // Wait for a packet
    let (len, _) = tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .expect("Timeout waiting for packet")?;

    println!("Received packet len {}", len);

    // RTP Header:
    // Byte 0: V=2, P, X, CC
    // X is bit 4 (0x10)
    let b0 = buf[0];
    let x_bit = b0 & 0x10;

    println!("Byte0: {:08b} (0x{:02x}), X-bit: {}", b0, b0, x_bit > 0);

    if x_bit != 0 {
        panic!(
            "RTP Header Extension bit (X) is SET! Packet header Dump: {:02x?}",
            &buf[0..12]
        );
    }

    println!("SUCCESS: RTP Header Extension bit is NOT set.");
    Ok(())
}
