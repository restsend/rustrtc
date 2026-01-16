use axum::{
    Router,
    extract::{Json, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::{DataChannelEvent, PeerConnection, RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use tokio::sync::broadcast;
use tower_http::services::ServeDir;
use tracing::{info, warn};

#[derive(Clone)]
struct AppState {
    tx: broadcast::Sender<InternalMessage>,
    next_id: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
struct InternalMessage {
    sender_id: usize,
    text: String,
}

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=debug")
        .init();

    let (tx, _rx) = broadcast::channel(100);
    let state = AppState {
        tx,
        next_id: Arc::new(AtomicUsize::new(1)),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/offer", post(offer))
        .nest_service("/static", ServeDir::new("examples/static"))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(include_str!("static/chat.html"))
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

#[derive(Deserialize)]
#[serde(tag = "type")]
enum ClientMessage {
    #[serde(rename = "login")]
    Login { name: String },
    #[serde(rename = "chat")]
    Chat { content: String },
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum ServerMessage {
    #[serde(rename = "chat")]
    Chat { sender: String, content: String },
    #[serde(rename = "system")]
    System { content: String },
}

async fn offer(
    State(state): State<AppState>,
    Json(payload): Json<OfferRequest>,
) -> impl IntoResponse {
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    let config = RtcConfiguration::default();
    let pc = PeerConnection::new(config);

    // Use negotiated data channel with ID 0
    let dc = pc
        .create_data_channel(
            "chat",
            Some(rustrtc::transports::sctp::DataChannelConfig {
                negotiated: Some(0),
                ..Default::default()
            }),
        )
        .unwrap();
    let dc_clone = dc.clone();
    let pc_clone = pc.clone();

    let my_id = state.next_id.fetch_add(1, Ordering::Relaxed);
    let tx = state.tx.clone();
    let mut rx = state.tx.subscribe();

    tokio::spawn(async move {
        let mut my_name: Option<String> = None;

        // Task to forward broadcast messages to this client
        let pc_sender = pc_clone.clone();
        let sender_task = tokio::spawn(async move {
            while let Ok(msg) = rx.recv().await {
                if msg.sender_id != my_id {
                    if let Err(e) = pc_sender.send_text(0, msg.text).await {
                        warn!("Failed to send data to client {}: {}", my_id, e);
                        break;
                    }
                }
            }
        });

        let mut ice_state_rx = pc_clone.subscribe_ice_connection_state();

        loop {
            tokio::select! {
                event = dc_clone.recv() => {
                    match event {
                        Some(DataChannelEvent::Message(data)) => {
                            if let Ok(msg) = serde_json::from_slice::<ClientMessage>(&data) {
                                match msg {
                                    ClientMessage::Login { name } => {
                                        my_name = Some(name.clone());
                                        info!("Client {} logged in as {}", my_id, name);
                                        let sys_msg = ServerMessage::System {
                                            content: format!("{} joined the chat", name),
                                        };
                                        let _ = tx.send(InternalMessage {
                                            sender_id: my_id,
                                            text: serde_json::to_string(&sys_msg).unwrap(),
                                        });
                                    }
                                    ClientMessage::Chat { content } => {
                                        if let Some(name) = &my_name {
                                            let chat_msg = ServerMessage::Chat {
                                                sender: name.clone(),
                                                content,
                                            };
                                            let _ = tx.send(InternalMessage {
                                                sender_id: my_id,
                                                text: serde_json::to_string(&chat_msg).unwrap(),
                                            });
                                        }
                                    }
                                }
                            }
                        }
                        Some(DataChannelEvent::Open) => info!("Data channel opened for client {}", my_id),
                        Some(DataChannelEvent::Close) | None => {
                            info!("Data channel closed for client {}", my_id);
                            break;
                        }
                    }
                }
                res = ice_state_rx.changed() => {
                    if res.is_ok() {
                        let state = *ice_state_rx.borrow();
                        if state == rustrtc::IceConnectionState::Disconnected
                            || state == rustrtc::IceConnectionState::Failed
                            || state == rustrtc::IceConnectionState::Closed
                        {
                            info!("ICE connection ended for client {}: {:?}", my_id, state);
                            break;
                        }
                    } else {
                        break;
                    }
                }
            }
        }

        sender_task.abort();

        if let Some(name) = my_name {
            let sys_msg = ServerMessage::System {
                content: format!("{} left the chat", name),
            };
            let _ = tx.send(InternalMessage {
                sender_id: my_id,
                text: serde_json::to_string(&sys_msg).unwrap(),
            });
        }
    });

    pc.set_remote_description(offer_sdp).await.unwrap();
    let _ = pc.create_answer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}
