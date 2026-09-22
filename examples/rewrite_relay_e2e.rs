//! E2E: real Chrome ↔ RewriteBridge with a source-SSRC switch (A→B→A),
//! reproducing the production trunk topology: a ringback generator takes over
//! mid-call on a second SSRC, then the main stream resumes.
//!
//! The browser POSTs its offer to /offer; we answer, then pump a plain-RTP
//! stream into a source transport with a RewriteBridge installed — the exact
//! component rustpbx's fast-path relay uses. The page measures audio
//! continuity (RMS gaps + getStats discarded packets).
//!
//! Run: cargo run --example rewrite_relay_e2e -- --port 3000
use anyhow::Result;
use rustrtc::{
    SdpType, SessionDescription, transports::ice::conn::IceConn, transports::rtp::RtpTransport,
};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::watch;

const SSRC_A: u32 = 0xAAAA_0001;
const SSRC_B: u32 = 0xBBBB_0002;

fn rtp_packet(ssrc: u32, seq: u16, ts: u32, payload: &[u8], marker: bool) -> Vec<u8> {
    let mut v = Vec::with_capacity(12 + payload.len());
    v.push(0x80);
    v.push(if marker { 0x80 } else { 0x00 }); // PT 0 = PCMU
    v.extend_from_slice(&(seq & 0xFFFF).to_be_bytes());
    v.extend_from_slice(&ts.to_be_bytes());
    v.extend_from_slice(&ssrc.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn ulaw_encode(sample: i16) -> u8 {
    const BIAS: i32 = 0x84;
    let mut x = sample as i32;
    let sign = if x < 0 { 0x80 } else { 0x00 };
    if x < 0 {
        x = -x;
    }
    x = x.min(0x1FFF);
    let mut exponent = 7;
    let mut mask = 0x4000;
    while exponent > 0 && (x & mask) == 0 {
        exponent -= 1;
        mask >>= 1;
    }
    let mantissa = ((x >> (if exponent == 0 { 4 } else { exponent + 3 })) & 0x0F) as u8;
    (!(sign | ((exponent as u8) << 4) | mantissa)) & 0xFF
}

fn pcmu_sine(freq: f32, amp: i16, seconds: f32) -> Vec<u8> {
    let sr = 8000.0;
    let total = (sr * seconds) as usize;
    let mut out = Vec::with_capacity(total);
    for i in 0..total {
        let s = (amp as f32 * (2.0 * std::f32::consts::PI * freq * i as f32 / sr).sin()) as i16;
        out.push(ulaw_encode(s));
    }
    out
}

async fn pump_source(source: Arc<RtpTransport>, src_addr: std::net::SocketAddr) -> Result<()> {
    let a1 = pcmu_sine(440.0, 9000, 1.0);
    let b = pcmu_sine(880.0, 9000, 2.0);
    let a2 = pcmu_sine(440.0, 9000, 600.0);

    // Phase A1: main SSRC, seq 100..149, ts 8000.. (1s loud 440 Hz)
    eprintln!("[e2e] phase A1 (main SSRC)");
    for i in 0..50u16 {
        source
            .feed_packet(
                bytes::Bytes::from(rtp_packet(
                    SSRC_A,
                    100 + i,
                    8000 + 160 * i as u32,
                    &a1[160 * i as usize..160 * i as usize + 160],
                    i == 0,
                )),
                src_addr,
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Phase B: ringback generator — SSRC switch, seq RESTARTS at 100
    eprintln!("[e2e] phase B (SSRC switch)");
    for i in 0..100u16 {
        source
            .feed_packet(
                bytes::Bytes::from(rtp_packet(
                    SSRC_B,
                    100 + i,
                    500_000 + 160 * i as u32,
                    &b[160 * i as usize..160 * i as usize + 160],
                    i == 0,
                )),
                src_addr,
            )
            .await;
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    // Phase A2: main SSRC resumes — seq 150.., ts continues A1's timeline
    eprintln!("[e2e] phase A2 (SSRC switch back)");
    let mut seq: u16 = 150;
    let mut ts: u32 = 8000 + 50 * 160;
    let mut off: usize = 0;
    loop {
        source
            .feed_packet(
                bytes::Bytes::from(rtp_packet(SSRC_A, seq, ts, &a2[off..off + 160], false)),
                src_addr,
            )
            .await;
        seq = seq.wrapping_add(1);
        ts = ts.wrapping_add(160);
        off = (off + 160) % (a2.len() - 160);
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
}

async fn wait_audio_transport(pc: &rustrtc::PeerConnection) -> Option<Arc<RtpTransport>> {
    for _ in 0..50 {
        let t = pc
            .get_transceivers()
            .into_iter()
            .find(|t| t.kind() == rustrtc::MediaKind::Audio)
            .and_then(|t| t.sender())
            .and_then(|s| s.transport());
        if t.is_some() {
            return t;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    None
}

async fn handle_offer(
    offer_sdp: String,
    source: Arc<RtpTransport>,
    source_addr: std::net::SocketAddr,
) -> Result<String> {
    let offer = SessionDescription::parse(SdpType::Offer, &offer_sdp)?;
    let mut config = rustrtc::RtcConfiguration::default();
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.audio = vec![rustrtc::config::AudioCapability {
        payload_type: 0,
        codec_name: "PCMU".to_string(),
        clock_rate: 8000,
        channels: 1,
        ..Default::default()
    }];
    config.media_capabilities = Some(caps);
    let pc = rustrtc::PeerConnection::new(config);
    eprintln!("[e2e] setting remote description");
    pc.set_remote_description(offer).await?;
    // Attach a sender to the offered audio m-line (PCMU/8000, PT 0) so the
    // answer is sendrecv and the browser gets a playout track.
    let (_source_queue, track, _fb) =
        rustrtc::media::sample_track(rustrtc::media::MediaKind::Audio, 64);
    let params = rustrtc::RtpCodecParameters {
        payload_type: 0,
        name: "PCMU".to_string(),
        clock_rate: 8000,
        channels: 0,
    };
    pc.add_track(track, params).expect("add_track");
    eprintln!("[e2e] remote set; create_answer");
    let _ = pc.create_answer().await?;
    eprintln!("[e2e] answer created; waiting gathering");
    pc.wait_for_gathering_complete().await;
    eprintln!("[e2e] gathering done");
    let answer = pc.create_answer().await?;
    pc.set_local_description(answer.clone())?;
    eprintln!("[e2e] ANSWER SDP:\n{}", answer.to_sdp_string());

    // Ensure the browser may RECEIVE: flip our direction to sendrecv and
    // signal the shared outbound SSRC, mirroring what rustpbx answers.
    let mut sdp = answer.to_sdp_string();
    sdp = sdp.replace("a=recvonly", "a=sendrecv");
    if let Some(pos) = sdp.find("a=rtcp-mux") {
        let inject = format!("a=ssrc:10000 cname:e2e-bridge\r\n");
        sdp.insert_str(pos, &inject);
    }
    eprintln!(
        "[e2e] final answer to browser: recvonly={} sendrecv={} ssrc={}",
        sdp.contains("a=recvonly"),
        sdp.contains("a=sendrecv"),
        sdp.contains("a=ssrc:10000")
    );

    // Arm the RewriteBridge once DTLS/SRTP completes with the browser (the
    // per-sender transport only exists after connect), then pump.
    tokio::spawn(async move {
        let mut state_rx = pc.subscribe_ice_connection_state();
        tokio::spawn(async move {
            loop {
                if state_rx.changed().await.is_err() {
                    break;
                }
                eprintln!("[e2e] ice state: {:?}", *state_rx.borrow());
            }
        });
        let _ = pc.wait_for_connected().await;
        eprintln!("[e2e] pc connected");
        match wait_audio_transport(&pc).await {
            Some(dst) => {
                struct CountObserver(std::sync::atomic::AtomicUsize);
                impl rustrtc::peer_connection::RtpObserver for CountObserver {
                    fn on_ingress(
                        &self,
                        packet: &rustrtc::rtp::RtpPacket,
                        _addr: std::net::SocketAddr,
                    ) {
                        let n = self.0.fetch_add(1, Ordering::SeqCst);
                        if n % 50 == 0 {
                            eprintln!(
                                "[e2e][obs] src ingress #{} ssrc={} seq={}",
                                n, packet.header.ssrc, packet.header.sequence_number
                            );
                        }
                    }
                }
                source.add_observer(Arc::new(CountObserver(
                    std::sync::atomic::AtomicUsize::new(0),
                )));
                struct EgressObserver(std::sync::atomic::AtomicUsize);
                impl rustrtc::peer_connection::RtpObserver for EgressObserver {
                    fn on_egress(
                        &self,
                        packet: &rustrtc::rtp::RtpPacket,
                        addr: std::net::SocketAddr,
                    ) {
                        let n = self.0.fetch_add(1, Ordering::SeqCst);
                        if n % 50 == 0 {
                            eprintln!(
                                "[e2e][obs] dst egress #{} -> {} ssrc={} seq={}",
                                n, addr, packet.header.ssrc, packet.header.sequence_number
                            );
                        }
                    }
                }
                dst.add_observer(Arc::new(EgressObserver(
                    std::sync::atomic::AtomicUsize::new(0),
                )));
                source.bridge_rewrite_rules_to(
                    dst,
                    rustrtc::RtpRewriteBridgeOptions {
                        strip_extensions: true,
                        initial_sequence_number: Some(1000),
                        initial_timestamp_offset: None,
                        initial_output_timestamp: None,
                    },
                    vec![rustrtc::RtpRewriteRule {
                        match_payload_type: None,
                        fixed_out_ssrc: Some(10_000),
                        ssrc_offset: 0,
                        out_payload_type: None,
                        sdes_mid_extension_id: None,
                        sdes_mid: None,
                    }],
                );
                eprintln!("[e2e] rewrite bridge armed");
                let _ = pump_source(source.clone(), source_addr).await;
            }
            None => eprintln!("[e2e] ERROR: no audio rtp transport on pc"),
        }
    });

    Ok(sdp)
}

fn extract_json_string(s: &str, key: &str) -> Option<String> {
    let pat = format!("\"{key}\":\"");
    let start = s.find(&pat)? + pat.len();
    let mut out = String::new();
    let mut chars = s[start..].chars();
    while let Some(c) = chars.next() {
        match c {
            '"' => break,
            '\\' => match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('\\') => out.push('\\'),
                Some('"') => out.push('"'),
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => break,
            },
            other => out.push(other),
        }
    }
    Some(out)
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
    let port: u16 = std::env::args()
        .collect::<Vec<_>>()
        .windows(2)
        .find(|w| w[0] == "--port")
        .and_then(|w| w[1].parse().ok())
        .unwrap_or(3000);

    let listener = TcpListener::bind(("127.0.0.1", port)).await?;
    eprintln!("[e2e] listening on 127.0.0.1:{port}");

    let src_udp = UdpSocket::bind("127.0.0.1:0").await?;
    let source_addr = src_udp.local_addr()?;
    let (_tx, rx) = watch::channel(Some(rustrtc::transports::ice::IceSocketWrapper::Udp(
        Arc::new(src_udp),
    )));
    let src_conn = IceConn::new(rx, "127.0.0.1:9".parse().unwrap(), None);
    let source = Arc::new(RtpTransport::new(src_conn, false));

    loop {
        let (mut stream, _) = listener.accept().await?;
        let source = source.clone();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let mut total = Vec::new();
            loop {
                use tokio::io::AsyncReadExt;
                let n = stream.read(&mut buf).await.unwrap_or(0);
                if n == 0 {
                    return;
                }
                total.extend_from_slice(&buf[..n]);
                if let Some(pos) = total.windows(4).position(|w| w == b"\r\n\r\n") {
                    let cl: usize = String::from_utf8_lossy(&total[..pos])
                        .to_lowercase()
                        .lines()
                        .find_map(|l| {
                            l.strip_prefix("content-length:")
                                .map(|v| v.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    if total.len() >= pos + 4 + cl {
                        break;
                    }
                }
            }
            if total.starts_with(b"OPTIONS") {
                use tokio::io::AsyncWriteExt;
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: POST, OPTIONS\r\nAccess-Control-Allow-Headers: content-type\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = stream.shutdown().await;
                return;
            }
            let text = String::from_utf8_lossy(&total).to_string();
            let body = text.split("\r\n\r\n").nth(1).unwrap_or("").to_string();
            let body = if body.trim_start().starts_with('{') {
                extract_json_string(&body, "sdp").unwrap_or(body)
            } else {
                body
            };
            eprintln!("[e2e] offer received, {} bytes", body.len());

            match handle_offer(body, source, source_addr).await {
                Ok(answer_sdp) => {
                    let resp = format!(
                        "{{\"type\":\"answer\",\"sdp\":{}}}",
                        json_escape(&answer_sdp)
                    );
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nAccess-Control-Allow-Origin: *\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                        resp.len(),
                        resp
                    );
                    use tokio::io::AsyncWriteExt;
                    let _ = stream.write_all(http.as_bytes()).await;
                    let _ = stream.shutdown().await;
                }
                Err(e) => eprintln!("[e2e] offer handling failed: {e:#}"),
            }
        });
    }
}
