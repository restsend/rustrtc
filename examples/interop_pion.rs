// Test/example crate: relax pedantic style lints that are noisy in fixtures.
#![allow(clippy::field_reassign_with_default)]
#![allow(clippy::redundant_pattern_matching)]
#![allow(clippy::while_let_loop)]
#![allow(clippy::manual_checked_ops)]
#![allow(clippy::needless_range_loop)]
#![allow(clippy::explicit_counter_loop)]
#![allow(clippy::cloned_ref_to_slice_refs)]
#![allow(clippy::zombie_processes)]
use axum::{Router, extract::Json, response::IntoResponse, routing::post};
use rustrtc::media::track::MediaStreamTrack;
use rustrtc::media::{MediaSample, VideoFrame};
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

/// Routes all video through the VP9 depacketizer (RFC 9628). Fine for this
/// example, where the client sends a single VP8-or-VP9 track; VP8 packets
/// would need pass-through, so production code should key on payload type.
#[derive(Debug)]
struct Vp9VideoDepacketizerFactory;

impl rustrtc::media::depacketizer::DepacketizerFactory for Vp9VideoDepacketizerFactory {
    fn create(&self, kind: rustrtc::media::MediaKind) -> Box<dyn rustrtc::media::Depacketizer> {
        use rustrtc::media::MediaKind;
        match kind {
            MediaKind::Video => Box::new(rustrtc::media::Vp9Depacketizer::new()),
            _ => Box::new(rustrtc::media::PassThroughDepacketizer),
        }
    }
}

/// Video frames received per payload type (for the interop assertions).
static RECV_PER_PT: std::sync::Mutex<Option<std::collections::HashMap<u8, usize>>> =
    std::sync::Mutex::new(None);

fn note_video_packet(pt: u8) {
    let mut guard = RECV_PER_PT.lock().unwrap();
    let map = guard.get_or_insert_with(std::collections::HashMap::new);
    let n = map.entry(pt).or_insert(0);
    *n += 1;
    if *n == 50 {
        info!("VIDEO-OK-PT{} (50+ frames received)", pt);
    }
}

/// The session established by the last /offer, kept alive so /restart can
/// exercise ICE restart on the *same* PeerConnection.
static LAST_PC: std::sync::Mutex<Option<PeerConnection>> = std::sync::Mutex::new(None);
/// Set once the post-restart answer has been applied.
static RESTART_ANSWERED: AtomicBool = AtomicBool::new(false);
/// Messages echoed after the restart answer.
static POST_RESTART_MSGS: AtomicUsize = AtomicUsize::new(0);

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt()
        .with_env_filter(std::env::var("RUST_LOG").unwrap_or_else(|_| "info,rustrtc=debug".into()))
        .init();

    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("server");
    let addr_str = args.get(2).map(|s| s.as_str()).unwrap_or("127.0.0.1:3000");

    match mode {
        "server" => run_server(addr_str).await,
        "client" => run_client(addr_str).await,
        _ => {
            eprintln!("Usage: interop_pion [server|client] [addr]");
            std::process::exit(1);
        }
    }
}

#[derive(Deserialize, Serialize)]
struct OfferRequest {
    sdp: String,
    #[serde(rename = "type")]
    type_: String,
}

async fn run_server(addr_str: &str) {
    let app = Router::new()
        .route("/offer", post(handle_offer))
        .route("/restart", post(handle_restart))
        .route("/answer", post(handle_answer))
        .layer(axum::middleware::from_fn(
            |req: axum::http::Request<axum::body::Body>, next: axum::middleware::Next| async move {
                let mut res = next.run(req).await;
                res.headers_mut().insert(
                    "Access-Control-Allow-Origin",
                    axum::http::HeaderValue::from_static("*"),
                );
                res.headers_mut().insert(
                    "Access-Control-Allow-Methods",
                    axum::http::HeaderValue::from_static("POST, OPTIONS"),
                );
                res.headers_mut().insert(
                    "Access-Control-Allow-Headers",
                    axum::http::HeaderValue::from_static("Content-Type"),
                );
                res
            },
        ));

    let addr: SocketAddr = addr_str.parse().expect("Invalid address");
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer");

    let mut config = RtcConfiguration::default();
    // Enable VP8 + VP9 negotiation (RFC 9628).
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.video = vec![
        rustrtc::config::VideoCapability {
            payload_type: 96,
            codec_name: "VP8".to_string(),
            clock_rate: 90000,
            rtcp_fbs: vec!["nack".to_string(), "pli".to_string()],
            ..Default::default()
        },
        rustrtc::config::VideoCapability::vp9(),
    ];
    // The interop client sends either VP8 or VP9 (-codec flag). Switch the
    // depacketizer with RUSTRTC_VP9_DEPACK=1 for VP9 tests (a production
    // deployment would use a payload-type-routing factory instead).
    if std::env::var("RUSTRTC_VP9_DEPACK").is_ok() {
        config.depacketizer_strategy = rustrtc::config::DepacketizerStrategy {
            factory: std::sync::Arc::new(Vp9VideoDepacketizerFactory),
        };
    }
    config.media_capabilities = Some(caps);

    // Optional STUN/TURN for browser interop tests. Credentials are read from
    // the environment only — never baked into the source. Comma-separated URLs
    // are accepted, e.g. RTC_ICE_URL="stun:host:3478,turn:host:3478".
    if let Ok(url) = std::env::var("RTC_ICE_URL") {
        let urls: Vec<String> = url
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !urls.is_empty() {
            let mut server = rustrtc::IceServer::new(urls);
            let user = std::env::var("RTC_ICE_USER").unwrap_or_default();
            let pass = std::env::var("RTC_ICE_PASS").unwrap_or_default();
            if !user.is_empty() {
                server = server.with_credential(&user, &pass);
            }
            config.ice_servers.push(server);
            info!("ICE server configured from environment (RTC_ICE_URL)");
        }
    }

    let pc = PeerConnection::new(config);

    // Handle Events
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = pc_clone.recv().await {
            match event {
                PeerConnectionEvent::DataChannel(dc) => {
                    info!("New DataChannel: {}", dc.label);
                    let dc_clone = dc.clone();
                    let pc_clone_2 = pc_clone.clone();
                    tokio::spawn(async move {
                        while let Some(event) = dc_clone.recv().await {
                            match event {
                                rustrtc::DataChannelEvent::Message(data) => {
                                    info!("Received: {:?}", String::from_utf8_lossy(&data));
                                    // Echo
                                    let _ = pc_clone_2.send_data(dc_clone.id, &data).await;
                                    if RESTART_ANSWERED.load(Ordering::SeqCst) {
                                        let n = POST_RESTART_MSGS.fetch_add(1, Ordering::SeqCst);
                                        if n + 1 == 2 {
                                            info!("RESTART-OK after ICE restart");
                                        }
                                    }
                                }
                                rustrtc::DataChannelEvent::Open => info!("DataChannel open"),
                                rustrtc::DataChannelEvent::Close => {
                                    info!("DataChannel closed");
                                    break;
                                }
                                rustrtc::DataChannelEvent::BufferedAmountLow(_) => {}
                            }
                        }
                    });
                }
                PeerConnectionEvent::Track(transceiver) => {
                    if let Some(receiver) = transceiver.receiver() {
                        let track = receiver.track();
                        tokio::spawn(async move {
                            while let Ok(sample) = track.recv().await {
                                if let MediaSample::Video(f) = sample {
                                    // Count per payload type; the interop
                                    // test greps VIDEO-OK-PT98 for VP9.
                                    if let Some(pt) = f.payload_type {
                                        note_video_packet(pt);
                                    }
                                }
                            }
                        });
                    }
                }
            }
        }
    });

    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    pc.set_remote_description(offer_sdp).await.unwrap();

    let _ = pc.create_answer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    // Keep the session alive for /restart + /answer.
    *LAST_PC.lock().unwrap() = Some(pc);
    RESTART_ANSWERED.store(false, Ordering::SeqCst);
    POST_RESTART_MSGS.store(0, Ordering::SeqCst);

    Json(OfferRequest {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}

/// ICE restart interop: roll fresh credentials on the stored session and hand
/// the restart offer to the peer (pion), which mirrors the restart in its
/// answer (delivered via /answer).
async fn handle_restart() -> impl IntoResponse {
    info!("ICE restart requested");
    let pc = LAST_PC
        .lock()
        .unwrap()
        .clone()
        .expect("no active session; POST /offer first");

    let before = pc.local_description().expect("local description");
    pc.restart_ice().await.expect("restart_ice failed");
    let offer = pc.create_offer().await.expect("create_offer failed");
    pc.set_local_description(offer.clone())
        .expect("set_local_description failed");

    let ufrag_before = extract_attr(&before, "ice-ufrag");
    let ufrag_after = extract_attr(&offer, "ice-ufrag");
    info!(
        "restart offer: ice-ufrag {} -> {} (rotated: {})",
        ufrag_before,
        ufrag_after,
        ufrag_before != ufrag_after
    );
    assert_ne!(
        ufrag_before, ufrag_after,
        "restart offer must rotate ice-ufrag"
    );

    Json(OfferRequest {
        sdp: offer.to_sdp_string(),
        type_: "offer".to_string(),
    })
}

/// Apply the peer's post-restart answer.
async fn handle_answer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received post-restart answer");
    let pc = LAST_PC
        .lock()
        .unwrap()
        .clone()
        .expect("no active session; POST /offer first");
    let answer = SessionDescription::parse(SdpType::Answer, &payload.sdp).unwrap();
    pc.set_remote_description(answer).await.unwrap();
    RESTART_ANSWERED.store(true, Ordering::SeqCst);
    info!("Post-restart answer applied; awaiting media");
}

fn extract_attr(desc: &SessionDescription, key: &str) -> String {
    desc.session
        .attributes
        .iter()
        .find(|a| a.key == key)
        .and_then(|a| a.value.clone())
        .or_else(|| {
            desc.media_sections
                .iter()
                .find_map(|m| {
                    m.attributes
                        .iter()
                        .find(|a| a.key == key)
                        .and_then(|a| a.value.clone())
                })
        })
        .unwrap_or_default()
}

async fn run_client(addr_str: &str) {
    let mut config = RtcConfiguration::default();
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.video = vec![rustrtc::config::VideoCapability {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        rtcp_fbs: vec!["nack".to_string(), "pli".to_string()],
        ..Default::default()
    }];
    config.media_capabilities = Some(caps);

    let pc = PeerConnection::new(config);

    // Create DataChannel
    let dc = pc.create_data_channel("data", None).unwrap();
    let dc_clone = dc.clone();
    let pc_clone = pc.clone();
    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            match event {
                rustrtc::DataChannelEvent::Message(data) => {
                    info!("Received: {:?}", String::from_utf8_lossy(&data));
                }
                rustrtc::DataChannelEvent::Open => {
                    info!("DataChannel open");
                    let pc = pc_clone.clone();
                    let dc_id = dc_clone.id;
                    tokio::spawn(async move {
                        let mut count = 0;
                        loop {
                            count += 1;
                            if count > 5 {
                                info!("SUCCESS: Client finished");
                                std::process::exit(0);
                            }
                            let msg = format!(
                                "Ping from Rust {}",
                                std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .unwrap()
                                    .as_secs()
                            );
                            info!("Sending: {}", msg);
                            let _ = pc.send_text(dc_id, &msg).await;
                            sleep(Duration::from_secs(1)).await;
                        }
                    });
                }
                _ => {}
            }
        }
    });

    // Create Video Track
    let (source, track, _) = rustrtc::media::sample_track(rustrtc::media::MediaKind::Video, 96);
    let sender = rustrtc::peer_connection::RtpSender::builder(track, 12345)
        .stream_id("stream".to_string())
        .params(rustrtc::RtpCodecParameters {
            payload_type: 96,
            name: "VP8".to_string(),
            clock_rate: 90000,
            channels: 0,
        })
        .nack(200)
        .interceptor(std::sync::Arc::new(
            rustrtc::media::gcc::GccBandwidthEstimator::new(),
        ))
        .build();

    let transceiver = pc.add_transceiver(
        rustrtc::MediaKind::Video,
        rustrtc::TransceiverDirection::SendOnly,
    );
    transceiver.set_sender(Some(sender.clone()));

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(33)).await;
            let frame = VideoFrame {
                data: bytes::Bytes::from_static(&[0u8; 100]),
                ..Default::default()
            };
            let _ = source.send_video(frame);
        }
    });

    // GCC watcher: pion (with TWCC interceptors) feeds back on our video
    // stream; the estimator must move off its start value.
    tokio::spawn(async move {
        let start = std::time::Instant::now();
        loop {
            sleep(Duration::from_millis(500)).await;
            match sender.target_bitrate() {
                Some(bitrate) if bitrate != rustrtc::media::gcc::START_BITRATE_BPS => {
                    info!("GCC-TWCC-OK target_bitrate={} bps", bitrate);
                    break;
                }
                _ => {}
            }
            if start.elapsed() > Duration::from_secs(20) {
                info!("GCC-TWCC-TIMEOUT no feedback-driven estimate change");
                break;
            }
        }
    });

    let _ = pc.create_offer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let offer = pc.create_offer().await.unwrap();
    pc.set_local_description(offer.clone()).unwrap();

    let client = reqwest::Client::new();
    let url = format!("http://{}/offer", addr_str);
    let res = client
        .post(&url)
        .json(&OfferRequest {
            sdp: offer.to_sdp_string(),
            type_: "offer".to_string(),
        })
        .send()
        .await
        .unwrap();

    let answer_resp: OfferRequest = res.json().await.unwrap();
    let answer_sdp = SessionDescription::parse(SdpType::Answer, &answer_resp.sdp).unwrap();
    pc.set_remote_description(answer_sdp).await.unwrap();

    // Keep alive
    tokio::signal::ctrl_c().await.unwrap();
}
