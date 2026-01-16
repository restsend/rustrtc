use axum::{Router, extract::Json, response::IntoResponse, routing::post};
use rustrtc::media::track::MediaStreamTrack;
use rustrtc::media::{MediaSample, VideoFrame};
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::time::sleep;
use tracing::info;

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt()
        .with_env_filter("info,rustrtc=debug")
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
    let app = Router::new().route("/offer", post(handle_offer));

    let addr: SocketAddr = addr_str.parse().expect("Invalid address");
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn handle_offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer");

    let mut config = RtcConfiguration::default();
    // Enable VP8
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.video = vec![rustrtc::config::VideoCapability {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        rtcp_fbs: vec!["nack".to_string(), "pli".to_string()],
    }];
    config.media_capabilities = Some(caps);

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
                                }
                                rustrtc::DataChannelEvent::Open => info!("DataChannel open"),
                                rustrtc::DataChannelEvent::Close => {
                                    info!("DataChannel closed");
                                    break;
                                }
                            }
                        }
                    });
                }
                PeerConnectionEvent::Track(transceiver) => {
                    if let Some(receiver) = transceiver.receiver() {
                        let track = receiver.track();
                        tokio::spawn(async move {
                            while let Ok(sample) = track.recv().await {
                                if let MediaSample::Video(_f) = sample {
                                    // Just consume
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

    Json(OfferRequest {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}

async fn run_client(addr_str: &str) {
    let mut config = RtcConfiguration::default();
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.video = vec![rustrtc::config::VideoCapability {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        rtcp_fbs: vec!["nack".to_string(), "pli".to_string()],
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
            clock_rate: 90000,
            channels: 0,
        })
        .build();

    let transceiver = pc.add_transceiver(
        rustrtc::MediaKind::Video,
        rustrtc::TransceiverDirection::SendOnly,
    );
    transceiver.set_sender(Some(sender));

    tokio::spawn(async move {
        loop {
            sleep(Duration::from_millis(33)).await;
            let frame = VideoFrame {
                data: bytes::Bytes::from_static(&[0u8; 100]),
                ..Default::default()
            };
            let _ = source.send_video(frame).await;
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
