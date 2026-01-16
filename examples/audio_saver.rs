use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::{
    PeerConnection, RtcConfiguration, SdpType, SessionDescription,
    media::{MediaSample, MediaStreamTrack},
};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use tokio::fs::File;
use tokio::io::AsyncWriteExt;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=debug")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/offer", post(offer))
        .nest_service("/static", ServeDir::new("examples/static"));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/audio.html"))
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
    #[serde(rename = "type")]
    type_: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();

    let mut config = RtcConfiguration::default();
    // Support both PCMU and OPUS to ensure we can negotiate something
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.audio = vec![
        rustrtc::config::AudioCapability {
            payload_type: 0,
            codec_name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        },
        rustrtc::config::AudioCapability {
            payload_type: 111,
            codec_name: "OPUS".to_string(),
            clock_rate: 48000,
            channels: 2,
            fmtp: Some("minptime=10;useinbandfec=1".to_string()),
            rtcp_fbs: vec![],
        },
    ];
    config.media_capabilities = Some(caps);

    let pc = PeerConnection::new(config);

    pc.set_remote_description(offer_sdp).await.unwrap();

    let transceivers = pc.get_transceivers();
    info!("Found {} transceivers", transceivers.len());

    for transceiver in transceivers {
        if transceiver.kind() == rustrtc::MediaKind::Audio {
            // Workaround: rustrtc's create_answer logic seems to flip RecvOnly to SendOnly in SDP.
            // We use SendRecv to ensure the Answer contains a=sendrecv (or similar) so the browser sends audio.
            info!("Found Audio Transceiver, setting to SendRecv");
            transceiver.set_direction(rustrtc::TransceiverDirection::SendRecv);

            if let Some(receiver) = transceiver.receiver() {
                let track = receiver.track();
                let pc_clone = pc.clone();
                tokio::spawn(async move {
                    info!("Starting audio recording loop");
                    let mut file = File::create("output.ulaw").await.unwrap();
                    let mut ice_state_rx = pc_clone.subscribe_ice_connection_state();
                    let mut packets_received = 0;

                    loop {
                        tokio::select! {
                            result = track.recv() => {
                                match result {
                                    Ok(sample) => {
                                        if let MediaSample::Audio(frame) = sample {
                                            packets_received += 1;
                                            if packets_received == 1 {
                                                info!("Received first audio packet: {} bytes, PT: {:?}", frame.data.len(), frame.payload_type);
                                            }
                                            // Note: If this is OPUS, writing it directly to .ulaw file will result in noise,
                                            // but at least we verify data reception.
                                            if let Err(e) = file.write_all(&frame.data).await {
                                                warn!("Failed to write audio: {}", e);
                                                break;
                                            }
                                        }
                                    }
                                    Err(e) => {
                                        info!("Track ended: {}", e);
                                        break;
                                    }
                                }
                            }
                            res = ice_state_rx.changed() => {
                                if res.is_ok() {
                                    let state = *ice_state_rx.borrow();
                                    info!("ICE State changed: {:?}", state);
                                    if state == rustrtc::IceConnectionState::Disconnected
                                        || state == rustrtc::IceConnectionState::Failed
                                        || state == rustrtc::IceConnectionState::Closed
                                    {
                                        info!("ICE connection ended: {:?}", state);
                                        break;
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    info!(
                        "Audio recording stopped. Total packets: {}",
                        packets_received
                    );
                });
            } else {
                warn!("Audio transceiver has no receiver!");
            }
        }
    }

    let _ = pc.create_answer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await.unwrap();

    info!("Generated Answer SDP:\n{}", answer.to_sdp_string());

    pc.set_local_description(answer.clone()).unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}
