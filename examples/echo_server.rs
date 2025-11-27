use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::PeerConnection;
use rustrtc::{RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[tokio::main]
async fn main() {
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
    Html(include_str!("static/index.html"))
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
    #[allow(unused)]
    r#type: String,
    #[serde(default)]
    backend: String,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
    #[serde(rename = "type")]
    type_: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer with backend: {}", payload.backend);

    if payload.backend == "webrtc-rs" {
        handle_webrtc_rs_offer(payload).await
    } else {
        handle_rustrtc_offer(payload).await
    }
}

async fn handle_webrtc_rs_offer(payload: OfferRequest) -> Json<OfferResponse> {
    use webrtc::api::APIBuilder;
    use webrtc::api::interceptor_registry::register_default_interceptors;
    use webrtc::api::media_engine::MediaEngine;
    use webrtc::ice_transport::ice_server::RTCIceServer;
    use webrtc::interceptor::registry::Registry;
    use webrtc::peer_connection::configuration::RTCConfiguration;
    use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
    use webrtc::track::track_local::track_local_static_rtp::TrackLocalStaticRTP;
    use webrtc::track::track_local::{TrackLocal, TrackLocalWriter};

    let mut m = MediaEngine::default();
    m.register_default_codecs().unwrap();

    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m).unwrap();

    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    let config = RTCConfiguration {
        ice_servers: vec![RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }],
        ..Default::default()
    };

    let pc = Arc::new(api.new_peer_connection(config).await.unwrap());

    // Handle DataChannel
    pc.on_data_channel(Box::new(move |dc| {
        let dc_label = dc.label().to_owned();
        let dc_id = dc.id();
        info!("New DataChannel {} {}", dc_label, dc_id);

        let dc_clone = dc.clone();
        Box::pin(async move {
            let dc2 = dc_clone.clone();
            dc_clone.on_message(Box::new(move |msg| {
                let msg_data = String::from_utf8_lossy(&msg.data).to_string();
                info!("Message from DataChannel '{}': '{}'", dc_label, msg_data);
                let dc3 = dc2.clone();
                Box::pin(async move {
                    if let Err(err) = dc3.send(&msg.data).await {
                        warn!("Failed to send message: {}", err);
                    }
                })
            }));
        })
    }));

    // Handle Track (Video Echo)
    let pc_clone = pc.clone();
    pc.on_track(Box::new(move |track, _, _| {
        let pc2 = pc_clone.clone();
        Box::pin(async move {
            if track.kind() == webrtc::rtp_transceiver::rtp_codec::RTPCodecType::Video {
                info!("Track has started, of type Video");
                let local_track = Arc::new(TrackLocalStaticRTP::new(
                    track.codec().capability.clone(),
                    "video_echo".to_owned(),
                    "webrtc-rs".to_owned(),
                ));

                let rtp_sender = pc2
                    .add_track(Arc::clone(&local_track) as Arc<dyn TrackLocal + Send + Sync>)
                    .await
                    .unwrap();

                // Read RTCP packets sent to this TrackLocal
                let pc3 = pc2.clone();
                let media_ssrc = track.ssrc();
                tokio::spawn(async move {
                    let mut rtcp_buf = vec![0u8; 1500];
                    while let Ok((_, _)) = rtp_sender.read(&mut rtcp_buf).await {
                        if let Err(err) = pc3
                            .write_rtcp(&[Box::new(
                                webrtc::rtcp::payload_feedbacks::picture_loss_indication::PictureLossIndication {
                                    sender_ssrc: 0,
                                    media_ssrc,
                                },
                            )])
                            .await
                        {
                            warn!("Failed to write RTCP PLI: {}", err);
                        }
                    }
                });

                // Read from remote track and write to local track
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 1500];
                    while let Ok((rtp, _)) = track.read(&mut buf).await {
                        if let Err(err) = local_track.write_rtp(&rtp).await {
                            warn!("Failed to write RTP: {}", err);
                        }
                    }
                });
            }
        })
    }));

    let offer = RTCSessionDescription::offer(payload.sdp).unwrap();
    pc.set_remote_description(offer).await.unwrap();

    let answer = pc.create_answer(None).await.unwrap();
    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(answer).await.unwrap();
    let _ = gather_complete.recv().await;

    let local_desc = pc.local_description().await.unwrap();

    Json(OfferResponse {
        sdp: local_desc.sdp,
        type_: "answer".to_string(),
    })
}

async fn handle_rustrtc_offer(payload: OfferRequest) -> Json<OfferResponse> {
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Create DataChannel (negotiated id=0)
    let dc = pc.create_data_channel("echo").await.unwrap();

    // Setup echo
    let pc_clone = pc.clone();
    let dc_clone = dc.clone();

    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            match event {
                rustrtc::transports::sctp::DataChannelEvent::Message(data) => {
                    info!("Received message: {:?}", String::from_utf8_lossy(&data));
                    let pc = pc_clone.clone();
                    tokio::spawn(async move {
                        // Echo back
                        if let Err(e) = pc.send_data(0, &data).await {
                            warn!("Failed to send data: {}", e);
                        } else {
                            info!("Sent echo");
                        }
                    });
                }
                rustrtc::transports::sctp::DataChannelEvent::Open => {
                    info!("Data channel opened");
                }
                rustrtc::transports::sctp::DataChannelEvent::Close => {
                    info!("Data channel closed");
                    break;
                }
            }
        }
    });

    // Handle SDP
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    pc.set_remote_description(offer_sdp).await.unwrap();

    // Setup video echo
    let transceivers = pc.get_transceivers().await;
    for t in transceivers {
        if t.kind() == rustrtc::MediaKind::Video {
            t.set_direction(rustrtc::TransceiverDirection::SendRecv)
                .await;
            let receiver = t.receiver.lock().await.clone();
            if let Some(rx) = receiver {
                let track = rx.track();
                let sender =
                    std::sync::Arc::new(rustrtc::peer_connection::RtpSender::new(track, 55555));
                *t.sender.lock().await = Some(sender);
                info!("Added video echo");
            }
        }
    }

    // Create answer and wait for gathering
    let _ = pc.create_answer().await.unwrap();

    // Wait for gathering to complete
    loop {
        if pc.ice_transport().gather_state().await
            == rustrtc::transports::ice::IceGathererState::Complete
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).await.unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}
