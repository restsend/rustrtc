use rustrtc::rtp::{RtpHeader, RtpPacket};
use serde::{Deserialize, Serialize};
use std::net::{SocketAddr, UdpSocket};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Serialize)]
struct OfferRequest {
    sdp: String,
}

#[derive(Deserialize)]
struct OfferResponse {
    sdp: String,
}

fn generate_sdp(num_tracks: usize, _local_addr: SocketAddr) -> String {
    let mut sdp = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n"
    );

    for i in 0..num_tracks {
        let ssrc = 1000 + i as u32;
        sdp.push_str(&format!(
            "m=audio 7000 RTP/AVP 0\r\n\
             c=IN IP4 127.0.0.1\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=mid:{}\r\n\
             a=sendrecv\r\n\
             a=ssrc:{} cname:bench\r\n",
            i, ssrc
        ));
    }
    sdp
}

async fn post_offer(sdp: String) -> Result<String, Box<dyn std::error::Error>> {
    let mut stream = tokio::net::TcpStream::connect("127.0.0.1:3000").await?;
    let body = serde_json::to_string(&OfferRequest { sdp })?;
    let request = format!(
        "POST /offer HTTP/1.1\r\n\
         Host: 127.0.0.1:3000\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;

    let json_start = response.find("{").ok_or("No JSON found")?;
    let resp: OfferResponse = serde_json::from_str(&response[json_start..])?;
    Ok(resp.sdp)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    let num_tracks = if args.len() > 1 {
        args[1].parse().unwrap_or(4)
    } else {
        4
    };

    let pps_per_track = 50; // 50 pps for 20ms G.711 packets
    let local_addr: SocketAddr = "127.0.0.1:7000".parse().unwrap();

    let socket = UdpSocket::bind(local_addr)?;
    socket.set_nonblocking(true)?;

    println!("Generator starting with {} tracks", num_tracks);

    let answer_sdp = post_offer(generate_sdp(num_tracks, local_addr)).await?;

    let mut remote_ip: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    let mut remote_port: u16 = 0;

    for line in answer_sdp.lines() {
        if line.starts_with("c=IN IP4") {
            if let Some(ip_str) = line.split_whitespace().last() {
                if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
                    remote_ip = ip;
                }
            }
        }
        if line.starts_with("m=audio") || line.starts_with("m=video") {
            if let Some(port_str) = line.split_whitespace().nth(1) {
                if let Ok(p) = port_str.parse::<u16>() {
                    remote_port = p;
                }
            }
        }
    }

    if remote_port == 0 {
        panic!("Failed to find port in Answer");
    }

    let expected_pps = num_tracks as u64 * pps_per_track as u64;
    println!(
        "Generator starting with {} tracks (target {} PPS)",
        num_tracks, expected_pps
    );
    let remote_addr = SocketAddr::new(remote_ip, remote_port);
    println!("SUT RTP address: {}", remote_addr);

    let socket_clone = socket.try_clone()?;
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut count = 0;
        let mut last_report = Instant::now();
        let mut total_latency = 0u64;
        let mut latency_count = 0u64;

        loop {
            if let Ok((size, _)) = socket_clone.recv_from(&mut buf) {
                if let Ok(packet) = RtpPacket::parse(&buf[..size]) {
                    count += 1;
                    if packet.payload.len() >= 8 {
                        let sent_at = u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
                        let now = SystemTime::now()
                            .duration_since(UNIX_EPOCH)
                            .unwrap()
                            .as_micros() as u64;
                        if now >= sent_at {
                            total_latency += now - sent_at;
                            latency_count += 1;
                        }
                    }
                }
            }
            if last_report.elapsed() > Duration::from_secs(1) {
                let avg_latency = if latency_count > 0 {
                    total_latency / latency_count
                } else {
                    0
                };
                println!(
                    "Received {}/{} packets/s ({:.1}%), Avg Latency: {} us",
                    count,
                    expected_pps,
                    if expected_pps > 0 {
                        (count as f64 / expected_pps as f64) * 100.0
                    } else {
                        0.0
                    },
                    avg_latency
                );
                count = 0;
                total_latency = 0;
                latency_count = 0;
                last_report = Instant::now();
            }
            tokio::task::yield_now().await;
        }
    });

    println!("Sending RTP...");
    let mut seqs = vec![0u16; num_tracks];
    let interval_dur = Duration::from_micros(1000000 / (num_tracks as u64 * pps_per_track as u64));
    let mut interval = tokio::time::interval(interval_dur);

    loop {
        for i in 0..num_tracks {
            interval.tick().await;
            let ssrc = 1000 + i as u32;
            let mut payload = vec![0u8; 160]; // 160 bytes for 20ms G.711
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as u64;
            payload[..8].copy_from_slice(&now.to_be_bytes());

            let header = RtpHeader {
                marker: false,
                payload_type: 0, // PCMU
                sequence_number: seqs[i],
                timestamp: (now / 1000) as u32,
                ssrc,
                csrcs: vec![],
                extension: None,
            };
            let packet = RtpPacket::new(header, payload);

            let buf = packet.marshal()?;
            let _ = socket.send_to(&buf, remote_addr);
            seqs[i] = seqs[i].wrapping_add(1);
        }
    }
}
