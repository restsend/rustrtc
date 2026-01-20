use anyhow::Result;
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::transports::ice::stun::StunMessage;
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters, SdpType, TransportMode};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_rtp_latching() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 1. Setup PeerConnection (PC) with RTP Mode & Latching
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.enable_latching = true;
    config.bind_ip = Some("127.0.0.1".to_string());
    config.rtp_start_port = Some(40000);
    config.rtp_end_port = Some(40100);
    let pc = PeerConnection::new(config);

    // Add track to send
    let (source, track, _) =
        rustrtc::media::track::sample_track(rustrtc::media::frame::MediaKind::Video, 90000);
    let source = Arc::new(source);
    let params = RtpCodecParameters {
        payload_type: 96,
        clock_rate: 90000,
        channels: 0,
    };
    let _sender = pc.add_track(track.clone(), params.clone())?;

    // 2. Prepare Remote (Initial)
    let socket1 = UdpSocket::bind("127.0.0.1:0").await?;
    let addr1 = socket1.local_addr()?;
    println!("Remote 1 (Initial) at {}", addr1);

    // 3. Signaling
    let _ = pc.create_offer().await?; // trigger gathering
    pc.wait_for_gathering_complete().await;
    let offer = pc.create_offer().await?;

    pc.set_local_description(offer.clone())?;

    // Construct Answer pointing to addr1
    let mut answer = offer.clone();
    answer.sdp_type = SdpType::Answer;

    // Modify media section connection address and port
    let ip_str = addr1.ip().to_string();
    for section in &mut answer.media_sections {
        section.connection = Some(format!("IN IP4 {}", ip_str));
        section.port = addr1.port();
        // Remove candidates to ensure it relies on c= line
        section.attributes.retain(|a| a.key != "candidate");
    }

    pc.set_remote_description(answer).await?;

    // Wait for connected
    // In RTP mode with explicit remote address, it should connect.
    let connected = pc.wait_for_connected();

    // Safety timeout
    match tokio::time::timeout(Duration::from_secs(5), connected).await {
        Ok(_) => println!("PC Connected"),
        Err(_) => panic!("PC failed to connect"),
    }

    // 4. Verify PC sends to addr1
    let source_clone = source.clone();
    tokio::spawn(async move {
        let mut seq = 0;
        loop {
            let frame = VideoFrame {
                rtp_timestamp: seq * 3000,
                data: bytes::Bytes::from(vec![0u8; 100]),
                is_last_packet: true,
                ..Default::default()
            };
            if source_clone.send(MediaSample::Video(frame)).await.is_err() {
                break;
            }
            seq += 1;
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let mut buf = [0u8; 1500];
    let (len, _) = socket1.recv_from(&mut buf).await?;
    println!("Received packet on addr1, len={}", len);
    assert!(len > 0);

    // 5. Migrate to addr2
    let socket2 = UdpSocket::bind("127.0.0.1:0").await?;
    let addr2 = socket2.local_addr()?;
    println!("Remote 2 (Migrated) at {}", addr2);

    // Retrieve PC's listening address
    // We assume the first media section's port is binding
    let local_desc = pc.local_description().unwrap();
    let pc_port = local_desc.media_sections[0].port;
    if pc_port == 0 {
        panic!("PC port is 0, gathering failed?");
    }
    let pc_addr: SocketAddr = format!("127.0.0.1:{}", pc_port).parse()?;
    println!("PC listening at {}", pc_addr);

    // Send STUN Binding Request from socket2 to PC to trigger latching
    let tx_id = [2u8; 12];
    let req = StunMessage::binding_request(tx_id, Some("rustrtc_latch"));
    let req_bytes = req.encode(None, false)?; // No auth

    println!("Sending STUN Binding Request from {} to {}", addr2, pc_addr);
    socket2.send_to(&req_bytes, pc_addr).await?;

    // 6. Verify PC sends to addr2
    println!("Waiting for packets on addr2...");
    let timeout = Duration::from_secs(3);

    // We might need to receive a few times as some might still go to addr1 or logic takes time
    let mut received_on_2 = false;
    let start = std::time::Instant::now();

    while start.elapsed() < timeout {
        match tokio::time::timeout(Duration::from_millis(500), socket2.recv_from(&mut buf)).await {
            Ok(Ok((len, src))) => {
                println!("Received packet on addr2 from {}, len={}", src, len);
                if len > 0 {
                    // Check if it is RTP. RTP v2 usually starts with 0x80..0xBF (top bits 10)
                    // STUN starts with 0x00..0x3F (top bits 00)
                    if (buf[0] & 0xC0) == 0x80 {
                        println!("Verified RTP packet on addr2. Latching success!");
                        received_on_2 = true;
                        break;
                    } else {
                        println!(
                            "Received possible STUN response (byte 0: {:#x}), continuing to wait for RTP",
                            buf[0]
                        );
                    }
                }
            }
            Ok(Err(e)) => {
                println!("Socket2 recv error: {}", e);
                break;
            }
            Err(_) => {
                println!("Retrying recv on addr2...");
                // Resend STUN just in case packet loss
                let _ = socket2.send_to(&req_bytes, pc_addr).await;
            }
        }
    }

    assert!(
        received_on_2,
        "Failed to receive RTP on new address after latching"
    );

    // Also verify we stop receiving on addr1? (Optional, but nice)
    // Actually PC might continue sending to old address for a split second, updating is async.
    // But eventually it should switch.

    Ok(())
}
