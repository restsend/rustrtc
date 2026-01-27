use anyhow::Result;
use network_interface::{NetworkInterface, NetworkInterfaceConfig};
use rustrtc::media::frame::{MediaSample, VideoFrame};
use rustrtc::transports::ice::stun::StunMessage;
use rustrtc::{PeerConnection, RtcConfiguration, RtpCodecParameters, SdpType, TransportMode};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

#[tokio::test]
async fn test_rtp_latching() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // 0. Find distinct local IPs
    let interfaces = NetworkInterface::show().unwrap();
    let mut ips = HashSet::new();
    for itf in interfaces {
        for addr in itf.addr {
            let ip = addr.ip();
            if ip.is_ipv4() && !ip.is_multicast() && !ip.is_unspecified() {
                // Try to bind to it to see if it's usable
                if std::net::UdpSocket::bind(SocketAddr::new(ip, 0)).is_ok() {
                    ips.insert(ip);
                }
            }
        }
    }

    let ipv4_ips: Vec<_> = ips.into_iter().collect();
    if ipv4_ips.len() < 2 {
        println!(
            "Skipping test_rtp_latching: Need at least 2 distinct local IPv4s, found {:?}",
            ipv4_ips
        );
        return Ok(());
    }

    // Try to find a pair of IPs that can talk to each other
    let mut selected_pair = None;
    for i in 0..ipv4_ips.len() {
        for j in 0..ipv4_ips.len() {
            if i == j {
                continue;
            }
            let ip_a = ipv4_ips[i];
            let ip_b = ipv4_ips[j];

            // Verify connectivity from B to A
            let socket_a = UdpSocket::bind(SocketAddr::new(ip_a, 0)).await?;
            let socket_b = UdpSocket::bind(SocketAddr::new(ip_b, 0)).await?;
            let addr_a = socket_a.local_addr()?;

            socket_b.send_to(b"PING", addr_a).await?;

            let mut buf = [0u8; 10];
            if let Ok(Ok((_, src_b))) =
                tokio::time::timeout(Duration::from_millis(100), socket_a.recv_from(&mut buf)).await
            {
                // Verify return path A -> B
                socket_a.send_to(b"PONG", src_b).await?;
                if let Ok(Ok(_)) =
                    tokio::time::timeout(Duration::from_millis(100), socket_b.recv_from(&mut buf))
                        .await
                {
                    selected_pair = Some((ip_a, ip_b));
                    break;
                }
            }
        }
        if selected_pair.is_some() {
            break;
        }
    }

    let (ip1, ip2) = if let Some(pair) = selected_pair {
        pair
    } else {
        println!("Skipping test_rtp_latching: No two local IPs can reach each other via UDP.");
        return Ok(());
    };

    println!("Selected IPs: IP1={}, IP2={}", ip1, ip2);

    // 1. Setup PeerConnection (PC) with RTP Mode & Latching
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.enable_latching = true;
    config.bind_ip = Some("0.0.0.0".to_string());
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
    let socket1 = UdpSocket::bind(SocketAddr::new(ip1, 0)).await?;
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

    // 5. Migrate to addr2 (Different IP, SAME port)
    let addr2 = SocketAddr::new(ip2, addr1.port());
    let socket2 = match UdpSocket::bind(addr2).await {
        Ok(s) => s,
        Err(e) => {
            println!(
                "Skipping test: Could not bind another socket to same port on different IP ({}): {}",
                addr2, e
            );
            return Ok(());
        }
    };
    println!("Remote 2 (Migrated) at {}", addr2);

    // Retrieve PC's listening address
    // We assume the first media section's port is binding
    let local_desc = pc.local_description().unwrap();
    let pc_port = local_desc.media_sections[0].port;
    if pc_port == 0 {
        panic!("PC port is 0, gathering failed?");
    }
    // Since PC is bound to 0.0.0.0, it should be reachable on all local IPs
    let pc_addr: SocketAddr = SocketAddr::new(ip1, pc_port);
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

    // 7. Verify that different port DOES NOT latch
    let socket3 = UdpSocket::bind(SocketAddr::new(ip2, 0)).await?;
    let addr3 = socket3.local_addr()?;
    println!("Remote 3 (Different Port) at {}", addr3);

    // Send STUN Binding Request from socket3 to PC
    println!("Sending STUN Binding Request from {} to {}", addr3, pc_addr);
    socket3.send_to(&req_bytes, pc_addr).await?;

    // Wait and verify we DO NOT receive RTP on socket3
    println!("Verifying no RTP on socket3 (different port)...");
    match tokio::time::timeout(Duration::from_secs(2), socket3.recv_from(&mut buf)).await {
        Ok(Ok((_len, _))) => {
            if (buf[0] & 0xC0) == 0x80 {
                panic!("RTP should NOT have latched to different port!");
            }
        }
        _ => {
            println!("Correctly did not latch to different port");
        }
    }

    Ok(())
}
