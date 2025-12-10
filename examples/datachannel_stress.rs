use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::{PeerConnection, PeerConnectionEvent, RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::services::ServeDir;
use tracing::info;
use webrtc::api::APIBuilder;
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=info")
        .init();

    let app = Router::new()
        .route("/", get(index))
        .route("/offer", post(offer))
        .nest_service("/static", ServeDir::new("examples/static"));

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/datachannel_stress.html"))
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
    #[serde(default)]
    ping_pong: bool,
    chunk_count: Option<usize>,
    chunk_size: Option<usize>,
    #[serde(default)]
    backend: String,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    if payload.backend == "webrtc-rs" {
        return offer_webrtc(payload).await;
    }

    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    let config = RtcConfiguration::default();
    let pc = Arc::new(PeerConnection::new(config));
    let use_ping_pong = payload.ping_pong;

    pc.set_remote_description(offer_sdp).await.unwrap();

    // Create answer
    let _ = pc.create_answer().unwrap();

    // Wait for gathering to complete (simple approach for example)
    pc.wait_for_gathering_complete().await;

    let answer = pc.create_answer().unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    let pc_clone = pc.clone();
    let chunk_count = payload.chunk_count.unwrap_or(256);
    let chunk_size = payload.chunk_size.unwrap_or(62208);

    tokio::spawn(async move {
        while let Some(ev) = pc_clone.recv().await {
            match ev {
                PeerConnectionEvent::DataChannel(dc) => {
                    info!("Received DataChannel: {} label: {}", dc.id, dc.label);
                    let channel_id = dc.id;
                    let pc_sender = pc_clone.clone();
                    let dc_clone = dc.clone();

                    tokio::spawn(async move {
                        if use_ping_pong {
                            info!("Waiting for ping...");
                            while let Some(event) = dc_clone.recv().await {
                                match event {
                                    rustrtc::DataChannelEvent::Message(msg) => {
                                        if msg == "ping".as_bytes() {
                                            info!("Received ping, sending pong...");
                                            if let Err(e) =
                                                pc_sender.send_data(channel_id, b"pong").await
                                            {
                                                info!("Failed to send pong: {}", e);
                                                return;
                                            }

                                            // Give client a moment to process pong
                                            tokio::time::sleep(std::time::Duration::from_millis(
                                                100,
                                            ))
                                            .await;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        } else {
                            info!("Ping-pong disabled, waiting 1s before sending...");
                            tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        }

                        info!(
                            "Starting to send data... chunk_count={} chunk_size={}",
                            chunk_count, chunk_size
                        );
                        let data = vec![0u8; chunk_size];
                        for i in 0..chunk_count {
                            if let Err(e) = pc_sender.send_data(channel_id, &data).await {
                                info!("Failed to send data packet {}: {}", i, e);
                                break;
                            }
                        }
                        info!("Finished sending data");
                        // Keep channel open for a bit to ensure delivery
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    });
                }
                _ => {}
            }
        }
    });

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
    })
}

async fn offer_webrtc(payload: OfferRequest) -> Json<OfferResponse> {
    // Create a MediaEngine object to configure the supported codec
    let mut m = MediaEngine::default();
    m.register_default_codecs().unwrap();

    // Create a InterceptorRegistry. This is the user configurable RTP/RTCP Pipeline.
    // This provides NACKs, RTCP Reports and other features. If you use `webrtc.NewPeerConnection`
    // this is enabled by default. If you are manually managing You MUST create a InterceptorRegistry
    // for each PeerConnection.
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut m).unwrap();

    // Create the API object with the MediaEngine
    let api = APIBuilder::new()
        .with_media_engine(m)
        .with_interceptor_registry(registry)
        .build();

    // Prepare the configuration
    let config = RTCConfiguration {
        ice_servers: vec![webrtc::ice_transport::ice_server::RTCIceServer {
            urls: vec!["stun:stun.l.google.com:19302".to_owned()],
            ..Default::default()
        }],
        ..Default::default()
    };

    // Create a new RTCPeerConnection
    let pc = Arc::new(api.new_peer_connection(config).await.unwrap());

    let use_ping_pong = payload.ping_pong;
    let chunk_count = payload.chunk_count.unwrap_or(256);
    let chunk_size = payload.chunk_size.unwrap_or(62208);

    pc.on_data_channel(Box::new(
        move |d: Arc<webrtc::data_channel::RTCDataChannel>| {
            let d_label = d.label().to_owned();
            let d_id = d.id();
            info!("New DataChannel {} {}", d_label, d_id);

            Box::pin(async move {
                let d2 = d.clone();
                let d_label2 = d_label.clone();

                d.on_open(Box::new(move || {
                    info!("Data channel '{}'-'{}' open", d_label2, d_id);
                    Box::pin(async move {
                        let d_clone = d2.clone();
                        tokio::spawn(async move {
                            if !use_ping_pong {
                                info!("Ping-pong disabled, waiting 1s before sending...");
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                                send_stress_data(d_clone, chunk_count, chunk_size).await;
                            }
                        });
                    })
                }));

                let d3 = d.clone();
                d.on_message(Box::new(move |msg: DataChannelMessage| {
                    let msg_data = msg.data.clone();
                    let d_clone = d3.clone();
                    Box::pin(async move {
                        if use_ping_pong {
                            if msg_data == "ping".as_bytes() {
                                info!("Received ping, sending pong...");
                                if let Err(e) =
                                    d_clone.send(&bytes::Bytes::from_static(b"pong")).await
                                {
                                    info!("Failed to send pong: {}", e);
                                    return;
                                }
                                // Give client a moment to process pong
                                tokio::time::sleep(std::time::Duration::from_millis(100)).await;

                                send_stress_data(d_clone, chunk_count, chunk_size).await;
                            }
                        }
                    })
                }));
            })
        },
    ));

    // Set the remote SessionDescription
    let desc = RTCSessionDescription::offer(payload.sdp.clone()).unwrap();
    pc.set_remote_description(desc).await.unwrap();

    // Create an answer
    let answer = pc.create_answer(None).await.unwrap();

    // Sets the LocalDescription, and starts our UDP listeners
    let mut gather_complete = pc.gathering_complete_promise().await;
    pc.set_local_description(answer).await.unwrap();
    let _ = gather_complete.recv().await;

    let local_desc = pc.local_description().await.unwrap();

    Json(OfferResponse {
        sdp: local_desc.sdp,
    })
}

async fn send_stress_data(
    dc: Arc<webrtc::data_channel::RTCDataChannel>,
    chunk_count: usize,
    chunk_size: usize,
) {
    info!(
        "Starting to send data... chunk_count={} chunk_size={}",
        chunk_count, chunk_size
    );
    let data = bytes::Bytes::from(vec![0u8; chunk_size]);
    for i in 0..chunk_count {
        if let Err(e) = dc.send(&data).await {
            info!("Failed to send data packet {}: {}", i, e);
            break;
        }
    }
    info!("Finished sending data");
}
