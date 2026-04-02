use anyhow::{Context, Result, bail};
use rustrtc::media::track::sample_track;
use rustrtc::media::{MediaKind, MediaStreamTrack};
use rustrtc::peer_connection::RtpSender;
use rustrtc::rtp::{RtpHeader, RtpPacket};
use rustrtc::{
    PeerConnection, RtcConfiguration, RtpRewriteBridgeParams, SdpType, SessionDescription,
    TransceiverDirection,
    TransportMode,
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

const DEFAULT_HTTP_ADDR: &str = "127.0.0.1:3300";
const DEFAULT_RAW_UDP_ADDR: &str = "127.0.0.1:13300";

#[derive(Default)]
struct ServerCounters {
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
    active_tracks: AtomicU64,
}

#[derive(Default)]
struct RawServerCounters {
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
}

#[derive(Default)]
struct ClientCounters {
    sent_packets: AtomicU64,
    recv_packets: AtomicU64,
    total_latency_us: AtomicU64,
}

#[derive(Clone, Copy)]
struct BenchConfig {
    tracks: usize,
    pps_per_track: u64,
    duration_secs: u64,
    payload_bytes: usize,
}

#[derive(Deserialize, Serialize)]
struct OfferRequest {
    sdp: String,
}

#[derive(Deserialize, Serialize)]
struct OfferResponse {
    sdp: String,
}

#[derive(Clone, Copy)]
struct RemoteRtpTarget {
    ip: std::net::IpAddr,
    port: u16,
}

#[derive(Clone, Copy)]
struct BenchClock {
    start_instant: Instant,
    start_unix_us: u64,
}

impl BenchClock {
    fn new() -> Result<Self> {
        Ok(Self {
            start_instant: Instant::now(),
            start_unix_us: UNIX_EPOCH.elapsed()?.as_micros() as u64,
        })
    }

    fn now_micros(&self) -> u64 {
        self.start_unix_us + self.start_instant.elapsed().as_micros() as u64
    }
}

fn packets_per_tick(total_pps: u64) -> usize {
    total_pps.div_ceil(1_000).clamp(1, 256) as usize
}

fn make_server_config() -> RtcConfiguration {
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;

    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.audio = vec![rustrtc::config::AudioCapability {
        payload_type: 0,
        codec_name: "PCMU".to_string(),
        clock_rate: 8000,
        channels: 1,
        fmtp: None,
        rtcp_fbs: vec![],
    }];
    config.media_capabilities = Some(caps);
    config
}

fn generate_offer(tracks: usize, local_addr: SocketAddr) -> String {
    let mut sdp = format!(
        "v=0\r\n\
         o=- 0 0 IN IP4 127.0.0.1\r\n\
         s=-\r\n\
         t=0 0\r\n"
    );

    for i in 0..tracks {
        let ssrc = 1000 + i as u32;
        sdp.push_str(&format!(
            "m=audio {} RTP/AVP 0\r\n\
             c=IN IP4 {}\r\n\
             a=rtpmap:0 PCMU/8000\r\n\
             a=mid:{}\r\n\
             a=sendrecv\r\n\
             a=ssrc:{} cname:bench\r\n",
            local_addr.port(),
            local_addr.ip(),
            i,
            ssrc
        ));
    }
    sdp
}

fn parse_answer_target(answer_sdp: &str) -> Result<RemoteRtpTarget> {
    let mut remote_ip: Option<std::net::IpAddr> = None;
    let mut remote_port: Option<u16> = None;

    for line in answer_sdp.lines() {
        if line.starts_with("c=IN IP4") {
            if let Some(ip_str) = line.split_whitespace().last() {
                remote_ip = Some(ip_str.parse().context("parse answer IP")?);
            }
        }
        if line.starts_with("m=audio") {
            if let Some(port_str) = line.split_whitespace().nth(1) {
                remote_port = Some(port_str.parse().context("parse answer RTP port")?);
                break;
            }
        }
    }

    match (remote_ip, remote_port) {
        (Some(ip), Some(port)) => Ok(RemoteRtpTarget { ip, port }),
        _ => bail!("failed to find RTP target in SDP answer"),
    }
}

async fn post_offer(server_addr: &str, sdp: String) -> Result<String> {
    let mut stream = tokio::net::TcpStream::connect(server_addr)
        .await
        .with_context(|| format!("connect to signaling server {server_addr}"))?;
    let body = serde_json::to_string(&OfferRequest { sdp })?;
    let request = format!(
        "POST /offer HTTP/1.1\r\n\
         Host: {}\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        server_addr,
        body.len(),
        body
    );
    stream.write_all(request.as_bytes()).await?;

    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    let json_start = response
        .find('{')
        .context("no JSON found in HTTP response")?;
    let response: OfferResponse = serde_json::from_str(&response[json_start..])?;
    Ok(response.sdp)
}

async fn start_echo_tracks(pc: PeerConnection, counters: Arc<ServerCounters>) {
    for transceiver in pc.get_transceivers() {
        if transceiver.kind() != rustrtc::MediaKind::Audio {
            continue;
        }

        transceiver.set_direction(TransceiverDirection::SendRecv);
        let Some(receiver) = transceiver.receiver() else {
            continue;
        };
        let incoming_track = receiver.track();
        let (sample_source, outgoing_track, _) = sample_track(MediaKind::Audio, 1024);
        let sender = RtpSender::builder(outgoing_track, 5000 + transceiver.id() as u32)
            .params(rustrtc::RtpCodecParameters {
                payload_type: 0,
                clock_rate: 8000,
                channels: 1,
            })
            .build();
        transceiver.set_sender(Some(sender));

        let pc_ref = pc.clone();
        let counters_ref = counters.clone();
        tokio::spawn(async move {
            let _keep_pc_alive = pc_ref;
            counters_ref.active_tracks.fetch_add(1, Ordering::Relaxed);
            loop {
                match incoming_track.recv().await {
                    Ok(sample) => {
                        counters_ref.rx_packets.fetch_add(1, Ordering::Relaxed);
                        if sample_source.send(sample).await.is_err() {
                            break;
                        }
                        counters_ref.tx_packets.fetch_add(1, Ordering::Relaxed);
                    }
                    Err(_) => break,
                }
            }
            counters_ref.active_tracks.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

async fn process_offer(
    payload: OfferRequest,
    counters: Arc<ServerCounters>,
    bridge_mode: bool,
) -> Result<OfferResponse> {
    let pc = PeerConnection::new(make_server_config());
    let offer = SessionDescription::parse(SdpType::Offer, &payload.sdp)?;

    pc.set_remote_description(offer).await?;

    if !bridge_mode {
        tokio::spawn(start_echo_tracks(pc.clone(), counters));
    }

    let _ = pc.create_answer().await?;
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;

    if bridge_mode {
        pc.wait_for_rtp_transport_ready(Duration::from_secs(2)).await?;
        pc.bridge_rtp_with_rewrite_to_self(RtpRewriteBridgeParams {
            ssrc_offset: 10_000,
            payload_type: Some(0),
            initial_sequence_number: None,
            initial_timestamp_offset: None,
        })?;
    }

    Ok(OfferResponse {
        sdp: answer.to_sdp_string(),
    })
}

async fn handle_connection(
    mut stream: tokio::net::TcpStream,
    counters: Arc<ServerCounters>,
    bridge_mode: bool,
) -> Result<()> {
    let mut request = Vec::with_capacity(8192);
    let (header_end, content_length) = loop {
        let mut chunk = [0u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("connection closed before complete request was received");
        }
        request.extend_from_slice(&chunk[..read]);

        if let Some(header_end) = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .map(|idx| idx + 4)
        {
            let headers = std::str::from_utf8(&request[..header_end])
                .context("request headers were not valid UTF-8")?;
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .context("missing content-length header")?;

            if request.len() >= header_end + content_length {
                break (header_end, content_length);
            }
        }
    };

    while request.len() < header_end + content_length {
        let mut chunk = [0u8; 2048];
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            bail!("connection closed before request body was complete");
        }
        request.extend_from_slice(&chunk[..read]);
    }

    let body = std::str::from_utf8(&request[header_end..header_end + content_length])
        .context("request body was not valid UTF-8")?;
    let payload: OfferRequest = serde_json::from_str(body)?;
    let response = process_offer(payload, counters, bridge_mode).await?;
    let body = serde_json::to_string(&response)?;
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    stream.write_all(response.as_bytes()).await?;
    Ok(())
}

async fn print_server_stats(counters: Arc<ServerCounters>) {
    let mut last_rx = 0;
    let mut last_tx = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let rx = counters.rx_packets.load(Ordering::Relaxed);
        let tx = counters.tx_packets.load(Ordering::Relaxed);
        let active = counters.active_tracks.load(Ordering::Relaxed);
        println!(
            "server packets rx/s={} tx/s={} active_tracks={}",
            rx.saturating_sub(last_rx),
            tx.saturating_sub(last_tx),
            active
        );
        last_rx = rx;
        last_tx = tx;
    }
}

async fn run_server(listen_addr: &str) -> Result<()> {
    run_server_with_mode(listen_addr, false).await
}

async fn run_server_with_mode(listen_addr: &str, bridge_mode: bool) -> Result<()> {
    let counters = Arc::new(ServerCounters::default());
    tokio::spawn(print_server_stats(counters.clone()));

    let listener = TcpListener::bind(listen_addr)
        .await
        .with_context(|| format!("bind signaling listener on {listen_addr}"))?;
    println!("signaling listening on http://{listen_addr}");

    loop {
        let (stream, _) = listener.accept().await?;
        let counters = counters.clone();
        tokio::spawn(async move {
            if let Err(err) = handle_connection(stream, counters, bridge_mode).await {
                eprintln!("signaling request failed: {err}");
            }
        });
    }

    #[allow(unreachable_code)]
    Ok(())
}

async fn run_client(server_addr: &str, config: BenchConfig) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let clock = BenchClock::new()?;
    let local_addr = socket.local_addr()?;
    let answer_sdp = post_offer(server_addr, generate_offer(config.tracks, local_addr)).await?;
    let remote = parse_answer_target(&answer_sdp)?;
    let remote_addr = SocketAddr::new(remote.ip, remote.port);

    println!(
        "client target={} tracks={} pps_per_track={} duration={}s payload={}B",
        remote_addr,
        config.tracks,
        config.pps_per_track,
        config.duration_secs,
        config.payload_bytes
    );

    let counters = Arc::new(ClientCounters::default());
    let stop = Arc::new(AtomicBool::new(false));
    let recv_socket = socket.clone();
    let recv_counters = counters.clone();
    let recv_stop = stop.clone();
    let recv_clock = clock;

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while !recv_stop.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(100), recv_socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok((size, _))) => {
                    if let Ok(packet) = RtpPacket::parse(&buf[..size]) {
                        recv_counters.recv_packets.fetch_add(1, Ordering::Relaxed);
                        if packet.payload.len() >= 8 {
                            let sent_at =
                                u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
                            let now = recv_clock.now_micros();
                            if now >= sent_at {
                                recv_counters
                                    .total_latency_us
                                    .fetch_add(now - sent_at, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    });

    let total_pps = config.tracks as u64 * config.pps_per_track;
    let packets_per_tick = packets_per_tick(total_pps.max(1));
    let tick_us = 1_000_000u64
        .saturating_mul(packets_per_tick as u64)
        .div_ceil(total_pps.max(1))
        .max(1);
    let mut interval = tokio::time::interval(Duration::from_micros(tick_us));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(config.duration_secs);
    let mut sequence_numbers = vec![0u16; config.tracks];
    let mut next_report_at = start + Duration::from_secs(1);
    let mut last_sent = 0;
    let mut last_recv = 0;
    let mut track_index = 0usize;

    while Instant::now() < deadline {
        interval.tick().await;

        for _ in 0..packets_per_tick {
            let now = clock.now_micros();
            let seq = &mut sequence_numbers[track_index];
            let mut payload = vec![0u8; config.payload_bytes.max(8)];
            payload[..8].copy_from_slice(&now.to_be_bytes());
            let header = RtpHeader {
                marker: false,
                payload_type: 0,
                sequence_number: *seq,
                timestamp: (now / 125) as u32,
                ssrc: 1000 + track_index as u32,
                csrcs: vec![],
                extension: None,
            };
            let packet = RtpPacket::new(header, payload);
            let buf = packet.marshal()?;
            socket.send_to(&buf, remote_addr).await?;
            *seq = seq.wrapping_add(1);
            track_index += 1;
            if track_index == config.tracks {
                track_index = 0;
            }
            counters.sent_packets.fetch_add(1, Ordering::Relaxed);

            if Instant::now() >= deadline {
                break;
            }
        }

        let now = Instant::now();
        if now >= next_report_at {
            let sent = counters.sent_packets.load(Ordering::Relaxed);
            let recv = counters.recv_packets.load(Ordering::Relaxed);
            println!(
                "client packets sent/s={} recv/s={} target_total_pps={}",
                sent.saturating_sub(last_sent),
                recv.saturating_sub(last_recv),
                total_pps
            );
            last_sent = sent;
            last_recv = recv;
            next_report_at = now + Duration::from_secs(1);
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    stop.store(true, Ordering::Relaxed);
    recv_task.await?;

    let sent = counters.sent_packets.load(Ordering::Relaxed);
    let recv = counters.recv_packets.load(Ordering::Relaxed);
    let total_latency = counters.total_latency_us.load(Ordering::Relaxed);
    let avg_latency_us = if recv > 0 { total_latency / recv } else { 0 };
    let loss = sent.saturating_sub(recv);
    let elapsed = start.elapsed().as_secs_f64();

    println!(
        "summary sent={} recv={} loss={} avg_latency_us={}",
        sent, recv, loss, avg_latency_us
    );
    println!(
        "summary tx_pps={:.1} rx_pps={:.1}",
        sent as f64 / elapsed,
        recv as f64 / elapsed
    );

    Ok(())
}

// ---------------------------------------------------------------------------
// Raw UDP echo server — no rustrtc stack, pure recv_from + send_to.
// ---------------------------------------------------------------------------

async fn print_raw_server_stats(counters: Arc<RawServerCounters>) {
    let mut last_rx = 0;
    let mut last_tx = 0;
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
        let rx = counters.rx_packets.load(Ordering::Relaxed);
        let tx = counters.tx_packets.load(Ordering::Relaxed);
        println!(
            "raw_server packets rx/s={} tx/s={}",
            rx.saturating_sub(last_rx),
            tx.saturating_sub(last_tx),
        );
        last_rx = rx;
        last_tx = tx;
    }
}

async fn run_raw_server(listen_addr: &str) -> Result<()> {
    let socket = UdpSocket::bind(listen_addr)
        .await
        .with_context(|| format!("bind raw UDP echo socket on {listen_addr}"))?;
    println!("raw_server listening on udp://{listen_addr}");

    let counters = Arc::new(RawServerCounters::default());
    tokio::spawn(print_raw_server_stats(counters.clone()));

    let mut buf = vec![0u8; 4096];
    loop {
        let (size, peer) = socket.recv_from(&mut buf).await?;
        counters.rx_packets.fetch_add(1, Ordering::Relaxed);
        socket.send_to(&buf[..size], peer).await?;
        counters.tx_packets.fetch_add(1, Ordering::Relaxed);
    }

    #[allow(unreachable_code)]
    Ok(())
}

// ---------------------------------------------------------------------------
// Raw client — same send/recv logic as run_client but targets a fixed UDP
// address instead of going through SDP/HTTP signaling.
// ---------------------------------------------------------------------------

async fn run_client_raw(raw_addr: SocketAddr, config: BenchConfig) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let clock = BenchClock::new()?;

    println!(
        "client (raw) target={} tracks={} pps_per_track={} duration={}s payload={}B",
        raw_addr,
        config.tracks,
        config.pps_per_track,
        config.duration_secs,
        config.payload_bytes
    );

    let counters = Arc::new(ClientCounters::default());
    let stop = Arc::new(AtomicBool::new(false));
    let recv_socket = socket.clone();
    let recv_counters = counters.clone();
    let recv_stop = stop.clone();
    let recv_clock = clock;

    let recv_task = tokio::spawn(async move {
        let mut buf = vec![0u8; 4096];
        while !recv_stop.load(Ordering::Relaxed) {
            match tokio::time::timeout(Duration::from_millis(100), recv_socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok((size, _))) => {
                    if let Ok(packet) = RtpPacket::parse(&buf[..size]) {
                        recv_counters.recv_packets.fetch_add(1, Ordering::Relaxed);
                        if packet.payload.len() >= 8 {
                            let sent_at =
                                u64::from_be_bytes(packet.payload[..8].try_into().unwrap());
                            let now = recv_clock.now_micros();
                            if now >= sent_at {
                                recv_counters
                                    .total_latency_us
                                    .fetch_add(now - sent_at, Ordering::Relaxed);
                            }
                        }
                    }
                }
                Ok(Err(_)) => break,
                Err(_) => continue,
            }
        }
    });

    let total_pps = config.tracks as u64 * config.pps_per_track;
    let packets_per_tick = packets_per_tick(total_pps.max(1));
    let tick_us = 1_000_000u64
        .saturating_mul(packets_per_tick as u64)
        .div_ceil(total_pps.max(1))
        .max(1);
    let mut interval = tokio::time::interval(Duration::from_micros(tick_us));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(config.duration_secs);
    let mut sequence_numbers = vec![0u16; config.tracks];
    let mut next_report_at = start + Duration::from_secs(1);
    let mut last_sent = 0;
    let mut last_recv = 0;
    let mut track_index = 0usize;

    while Instant::now() < deadline {
        interval.tick().await;

        for _ in 0..packets_per_tick {
            let now = clock.now_micros();
            let seq = &mut sequence_numbers[track_index];
            let mut payload = vec![0u8; config.payload_bytes.max(8)];
            payload[..8].copy_from_slice(&now.to_be_bytes());
            let header = RtpHeader {
                marker: false,
                payload_type: 0,
                sequence_number: *seq,
                timestamp: (now / 125) as u32,
                ssrc: 1000 + track_index as u32,
                csrcs: vec![],
                extension: None,
            };
            let packet = RtpPacket::new(header, payload);
            let buf = packet.marshal()?;
            socket.send_to(&buf, raw_addr).await?;
            *seq = seq.wrapping_add(1);
            track_index += 1;
            if track_index == config.tracks {
                track_index = 0;
            }
            counters.sent_packets.fetch_add(1, Ordering::Relaxed);

            if Instant::now() >= deadline {
                break;
            }
        }

        let now = Instant::now();
        if now >= next_report_at {
            let sent = counters.sent_packets.load(Ordering::Relaxed);
            let recv = counters.recv_packets.load(Ordering::Relaxed);
            println!(
                "client packets sent/s={} recv/s={} target_total_pps={}",
                sent.saturating_sub(last_sent),
                recv.saturating_sub(last_recv),
                total_pps
            );
            last_sent = sent;
            last_recv = recv;
            next_report_at = now + Duration::from_secs(1);
        }
    }

    tokio::time::sleep(Duration::from_millis(500)).await;
    stop.store(true, Ordering::Relaxed);
    recv_task.await?;

    let sent = counters.sent_packets.load(Ordering::Relaxed);
    let recv = counters.recv_packets.load(Ordering::Relaxed);
    let total_latency = counters.total_latency_us.load(Ordering::Relaxed);
    let avg_latency_us = if recv > 0 { total_latency / recv } else { 0 };
    let loss = sent.saturating_sub(recv);
    let elapsed = start.elapsed().as_secs_f64();

    println!(
        "summary sent={} recv={} loss={} avg_latency_us={}",
        sent, recv, loss, avg_latency_us
    );
    println!(
        "summary tx_pps={:.1} rx_pps={:.1}",
        sent as f64 / elapsed,
        recv as f64 / elapsed
    );

    Ok(())
}

fn parse_bench_config(args: &[String], offset: usize) -> Result<BenchConfig> {
    Ok(BenchConfig {
        tracks: args
            .get(offset)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(4),
        pps_per_track: args
            .get(offset + 1)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(1000),
        duration_secs: args
            .get(offset + 2)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(10),
        payload_bytes: args
            .get(offset + 3)
            .map(|s| s.parse())
            .transpose()?
            .unwrap_or(160),
    })
}

fn print_usage() {
    println!("Usage:");
    println!("  rtp_pc_echo_bench server [listen_addr]");
    println!("  rtp_pc_echo_bench bridge_server [listen_addr]");
    println!(
        "  rtp_pc_echo_bench client [server_addr] [tracks] [pps_per_track] [duration_secs] [payload_bytes]"
    );
    println!("  rtp_pc_echo_bench all [tracks] [pps_per_track] [duration_secs] [payload_bytes]");
    println!("  rtp_pc_echo_bench bridge_all [tracks] [pps_per_track] [duration_secs] [payload_bytes]");
    println!("  rtp_pc_echo_bench raw_server [udp_addr]");
    println!(
        "  rtp_pc_echo_bench raw_all [tracks] [pps_per_track] [duration_secs] [payload_bytes]"
    );
    println!();
    println!("Defaults:");
    println!("  listen_addr / server_addr : {DEFAULT_HTTP_ADDR}");
    println!("  udp_addr (raw_server)     : {DEFAULT_RAW_UDP_ADDR}");
    println!("  tracks=4  pps_per_track=1000  duration_secs=10  payload_bytes=160");
}

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let Some(mode) = args.get(1).map(String::as_str) else {
        print_usage();
        return Ok(());
    };

    match mode {
        "server" => {
            let listen_addr = args.get(2).map(String::as_str).unwrap_or(DEFAULT_HTTP_ADDR);
            run_server(listen_addr).await
        }
        "bridge_server" => {
            let listen_addr = args.get(2).map(String::as_str).unwrap_or(DEFAULT_HTTP_ADDR);
            run_server_with_mode(listen_addr, true).await
        }
        "client" => {
            let server_addr = args.get(2).map(String::as_str).unwrap_or(DEFAULT_HTTP_ADDR);
            let config = parse_bench_config(&args, 3)?;
            run_client(server_addr, config).await
        }
        "all" => {
            let config = parse_bench_config(&args, 2)?;
            let listen_addr = DEFAULT_HTTP_ADDR;
            let server = tokio::spawn(run_server(listen_addr));
            tokio::time::sleep(Duration::from_millis(500)).await;
            let client_result = run_client(listen_addr, config).await;
            server.abort();
            client_result
        }
        "bridge_all" => {
            let config = parse_bench_config(&args, 2)?;
            let listen_addr = DEFAULT_HTTP_ADDR;
            let server = tokio::spawn(run_server_with_mode(listen_addr, true));
            tokio::time::sleep(Duration::from_millis(500)).await;
            let client_result = run_client(listen_addr, config).await;
            server.abort();
            client_result
        }
        "raw_server" => {
            let udp_addr = args
                .get(2)
                .map(String::as_str)
                .unwrap_or(DEFAULT_RAW_UDP_ADDR);
            run_raw_server(udp_addr).await
        }
        "raw_all" => {
            let config = parse_bench_config(&args, 2)?;
            let raw_addr: SocketAddr = DEFAULT_RAW_UDP_ADDR
                .parse()
                .context("parse default raw UDP addr")?;
            let server = tokio::spawn(run_raw_server(DEFAULT_RAW_UDP_ADDR));
            tokio::time::sleep(Duration::from_millis(100)).await;
            let client_result = run_client_raw(raw_addr, config).await;
            server.abort();
            client_result
        }
        _ => {
            print_usage();
            Ok(())
        }
    }
}
