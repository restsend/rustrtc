use axum::{
    Router,
    extract::{Json, State},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::{
    RtcConfiguration, RtpCodecParameters, SdpType, SessionDescription,
    media::track::MediaRelay,
    media::{self, MediaKind, MediaStreamTrack},
    peer_connection::{PeerConnection, PeerConnectionEvent},
    rtp::RtcpPacket,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::sync::RwLock;
use tracing::{error, info, warn};

#[derive(Clone)]
struct AppState {
    rooms: Rooms,
}

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    tracing_subscriber::fmt()
        .with_env_filter("debug,rustrtc=debug")
        .init();

    let state = AppState {
        rooms: Arc::new(RwLock::new(HashMap::new())),
    };

    let app = Router::new()
        .route("/", get(index))
        .route("/session", post(session))
        .route("/candidate", post(add_candidate))
        .with_state(state);

    let addr = SocketAddr::from(([127, 0, 0, 1], 8081));
    info!("Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<String> {
    let content = tokio::fs::read_to_string("examples/static/sfu.html")
        .await
        .unwrap_or_else(|_| "<h1>Error: examples/static/sfu.html not found</h1>".to_string());
    Html(content)
}

#[derive(Deserialize, Serialize, Debug, Clone)]
struct SdpDto {
    #[serde(rename = "type")]
    sdp_type: String,
    sdp: String,
}

#[derive(Deserialize, Debug)]
struct SessionRequest {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "roomId")]
    room_id: String,
    sdp: SdpDto,
}

#[derive(Serialize)]
struct SessionResponse {
    #[serde(rename = "type")]
    type_: String,
    sdp: String,
}

#[derive(Deserialize, Debug)]
struct CandidateRequest {
    #[serde(rename = "userId")]
    user_id: String,
    #[serde(rename = "roomId")]
    room_id: String,
    candidate: String,
}

// Global state
type Rooms = Arc<RwLock<HashMap<String, Arc<Room>>>>;

struct TrackInfo {
    relay: MediaRelay,
    remote_track: Arc<dyn MediaStreamTrack>,
    user_id: String,
    peer_id: u64,
    kind: MediaKind,
    params: RtpCodecParameters,
}

struct Room {
    _id: String,
    peers: RwLock<HashMap<String, Arc<Peer>>>,
    tracks: RwLock<Vec<Arc<TrackInfo>>>,
}

struct Peer {
    id: u64,
    user_id: String,
    pc: PeerConnection,
    dc: RwLock<Option<Arc<rustrtc::transports::sctp::DataChannel>>>,
    negotiation_pending: Arc<AtomicBool>,
    added_sources: RwLock<HashSet<String>>, // tracks already added to this peer
}

async fn session(
    State(state): State<AppState>,
    Json(req): Json<SessionRequest>,
) -> impl IntoResponse {
    info!(
        "Session request: user={}, room={}",
        req.user_id, req.room_id
    );

    let room = {
        let mut rooms = state.rooms.write().await;
        rooms
            .entry(req.room_id.clone())
            .or_insert_with(|| {
                Arc::new(Room {
                    _id: req.room_id.clone(),
                    peers: RwLock::new(HashMap::new()),
                    tracks: RwLock::new(Vec::new()),
                })
            })
            .clone()
    };

    let (pc, peer_arc) = {
        let mut peers = room.peers.write().await;
        if let Some(peer) = peers.remove(&req.user_id) {
            warn!(
                "!!! DUPLICATE USER ID DETECTED !!! Replacing session for user {}. The previous connection will be closed.",
                req.user_id
            );
            peer.pc.close();
        }

        // New connection
        info!("New connection for user {}", req.user_id);
        let config = RtcConfiguration::default();
        let pc = PeerConnection::new(config);

        let peer_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64;

        let peer = Arc::new(Peer {
            id: peer_id,
            user_id: req.user_id.clone(),
            pc: pc.clone(),
            dc: RwLock::new(None),
            negotiation_pending: Arc::new(AtomicBool::new(false)),
            added_sources: RwLock::new(HashSet::new()),
        });
        peers.insert(req.user_id.clone(), peer.clone());
        info!("Total peers in room {}: {}", req.room_id, peers.len());

        // Handle new peer setup
        setup_new_peer(peer.clone(), room.clone()).await;

        (pc, peer)
    };

    // Add existing room tracks to this new peer before answering,
    // so the first answer already advertises all media like the Pion SFU example.
    add_existing_tracks(peer_arc.clone(), room.clone(), false).await;

    let sdp_type = match req.sdp.sdp_type.as_str() {
        "offer" => SdpType::Offer,
        "answer" => SdpType::Answer,
        "pranswer" => SdpType::Pranswer,
        "rollback" => SdpType::Rollback,
        _ => {
            warn!("Invalid SDP type: {}", req.sdp.sdp_type);
            return axum::http::StatusCode::BAD_REQUEST.into_response();
        }
    };

    let sdp = match SessionDescription::parse(sdp_type, &req.sdp.sdp) {
        Ok(s) => {
            info!("Received SDP ({:?}): {:?}", sdp_type, req.sdp.sdp);
            s
        }
        Err(e) => {
            warn!("Failed to parse SDP: {}", e);
            return axum::http::StatusCode::BAD_REQUEST.into_response();
        }
    };

    // Handle SDP
    if let Err(e) = pc.set_remote_description(sdp).await {
        warn!("Failed to set remote description: {}", e);
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    // Wait for at least one candidate with 3s timeout
    {
        let mut rx = pc.subscribe_ice_candidates();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(3), rx.recv()).await;
    }

    let answer = match pc.create_answer().await {
        Ok(a) => a,
        Err(e) => {
            warn!("Failed to create answer: {}", e);
            return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
    };

    if let Err(e) = pc.set_local_description(answer.clone()) {
        warn!("Failed to set local description: {}", e);
        return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }

    let answer = pc
        .local_description()
        .expect("Local description should be set");

    info!(
        "Returning answer with {} candidates for user {}",
        answer.to_sdp_string().matches("a=candidate:").count(),
        req.user_id
    );

    let response = SessionResponse {
        type_: answer.sdp_type.as_str().to_string(),
        sdp: answer.to_sdp_string(),
    };

    Json(response).into_response()
}

/// ICE Lite: Receive ICE candidate from client
async fn add_candidate(
    State(state): State<AppState>,
    Json(req): Json<CandidateRequest>,
) -> impl IntoResponse {
    // Skip empty candidates (end-of-candidates signal)
    if req.candidate.is_empty() {
        return axum::http::StatusCode::OK.into_response();
    }

    info!(
        "Received ICE candidate from user={} room={}: {}",
        req.user_id,
        req.room_id,
        req.candidate.split(' ').nth(4).unwrap_or(&req.candidate)
    );

    // Find the room and peer
    let rooms = state.rooms.read().await;
    let room = match rooms.get(&req.room_id) {
        Some(r) => r.clone(),
        None => {
            warn!("Room not found: {}", req.room_id);
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
    };
    drop(rooms);

    let peers = room.peers.read().await;
    let peer = match peers.get(&req.user_id) {
        Some(p) => p.clone(),
        None => {
            warn!("Peer not found: {}", req.user_id);
            return axum::http::StatusCode::NOT_FOUND.into_response();
        }
    };
    drop(peers);

    // Parse and add the ICE candidate
    match rustrtc::transports::ice::IceCandidate::from_sdp(&req.candidate) {
        Ok(candidate) => {
            if let Err(e) = peer.pc.add_ice_candidate(candidate) {
                warn!("Failed to add ICE candidate: {}", e);
                return axum::http::StatusCode::BAD_REQUEST.into_response();
            }
            axum::http::StatusCode::OK.into_response()
        }
        Err(e) => {
            warn!("Failed to parse ICE candidate '{}': {}", req.candidate, e);
            axum::http::StatusCode::BAD_REQUEST.into_response()
        }
    }
}

async fn setup_new_peer(peer: Arc<Peer>, room: Arc<Room>) {
    let pc = peer.pc.clone();
    let user_id = peer.user_id.clone();
    let room_clone = room.clone();
    let peer_clone = peer.clone();

    // Monitor ICE connection state
    let mut ice_state_rx = pc.subscribe_ice_connection_state();
    let pc_clone_for_ice = pc.clone();
    let user_id_ice = user_id.clone();
    tokio::spawn(async move {
        while let Ok(()) = ice_state_rx.changed().await {
            let state = *ice_state_rx.borrow();
            info!("ICE connection state for {}: {:?}", user_id_ice, state);
            if state == rustrtc::IceConnectionState::Disconnected
                || state == rustrtc::IceConnectionState::Failed
                || state == rustrtc::IceConnectionState::Closed
            {
                info!(
                    "Closing connection for {} due to ICE state {:?}",
                    user_id_ice, state
                );
                pc_clone_for_ice.close();
                break;
            }
        }
    });

    // Handle events
    tokio::spawn(async move {
        while let Some(event) = pc.recv().await {
            match event {
                PeerConnectionEvent::Track(transceiver) => {
                    let receiver = transceiver.receiver();
                    if let Some(receiver) = receiver {
                        let track = receiver.track();
                        info!(
                            "Track received from {}: {:?} {}",
                            user_id,
                            track.kind(),
                            track.id()
                        );

                        // Deduplicate: only keep one track per (user, kind) to avoid
                        // generating duplicate mids/SSRCs that browsers reject.
                        {
                            let tracks = room_clone.tracks.read().await;
                            if tracks
                                .iter()
                                .any(|t| t.user_id == user_id && t.kind == track.kind())
                            {
                                info!(
                                    "Duplicate track for user {:?} kind {:?}, ignoring",
                                    user_id,
                                    track.kind()
                                );
                                continue;
                            }
                        }

                        // Create a relay so each subscriber gets its own track/IDs
                        let kind = track.kind();
                        let (clock_rate, payload_type, channels) = if kind == MediaKind::Video {
                            (90000, 96, 0)
                        } else {
                            (48000, 111, 2)
                        };

                        let (source, local_track, _) = media::sample_track(kind, clock_rate);
                        // Use larger capacity for relay to avoid Lagged errors
                        let relay = MediaRelay::with_capacity(local_track.clone(), 500);

                        let params = RtpCodecParameters {
                            payload_type,
                            clock_rate: clock_rate as u32,
                            channels,
                        };

                        let track_info = Arc::new(TrackInfo {
                            relay,
                            remote_track: track.clone(),
                            user_id: user_id.clone(),
                            peer_id: peer_clone.id,
                            kind,
                            params,
                        });

                        // Add to room
                        {
                            let mut tracks = room_clone.tracks.write().await;
                            tracks.push(track_info.clone());
                        }

                        // Add to other peers
                        {
                            let peers = room_clone.peers.read().await;
                            println!("!!! setup_new_peer: peers={:?}", peers.keys());
                            info!("setup_new_peer: peers={:?}", peers.keys());
                            for (other_id, other_peer) in peers.iter() {
                                if *other_id != user_id {
                                    // Avoid adding the same user's track of the same kind twice
                                    let source_key = format!(
                                        "{}:{}:{:?}",
                                        track_info.user_id, track_info.peer_id, track_info.kind
                                    );
                                    {
                                        let added = other_peer.added_sources.read().await;
                                        if added.contains(&source_key) {
                                            info!(
                                                "skip add: already added source_key={} to peer {}",
                                                source_key, other_id
                                            );
                                            continue;
                                        }
                                    }

                                    let relay_track = track_info.relay.subscribe();

                                    match other_peer.pc.add_track_with_stream_id(
                                        relay_track,
                                        track_info.user_id.clone(),
                                        track_info.params.clone(),
                                    ) {
                                        Ok(sender) => {
                                            {
                                                let mut added =
                                                    other_peer.added_sources.write().await;
                                                added.insert(source_key.clone());
                                            }
                                            info!(
                                                "added track to peer={} from user={} kind={:?}",
                                                other_id, track_info.user_id, track_info.kind
                                            );
                                            // Forward PLI
                                            let remote_track = track.clone();
                                            let mut rtcp_rx = sender.subscribe_rtcp();
                                            let other_id_log = other_id.clone();
                                            tokio::spawn(async move {
                                                while let Ok(packet) = rtcp_rx.recv().await {
                                                    match packet {
                                                        RtcpPacket::PictureLossIndication(_)
                                                        | RtcpPacket::FullIntraRequest(_) => {
                                                            info!(
                                                                "Forwarding PLI from {} to source",
                                                                other_id_log
                                                            );
                                                            if let Err(e) = remote_track
                                                                .request_key_frame()
                                                                .await
                                                            {
                                                                warn!(
                                                                    "Failed to forward PLI from {} to source: {}",
                                                                    other_id_log, e
                                                                );
                                                            }
                                                        }
                                                        _ => {}
                                                    }
                                                }
                                            });

                                            // Trigger renegotiation
                                            info!(
                                                "trigger renegotiation for peer={} due to new track",
                                                other_id
                                            );
                                            negotiate(other_peer).await;
                                        }
                                        Err(e) => {
                                            warn!("Failed to add track to peer {}: {}", other_id, e)
                                        }
                                    }
                                }
                            }
                        }

                        // Forward loop
                        let incoming_track = track.clone();
                        let user_id_log = user_id.clone();
                        let kind_log = kind;
                        tokio::spawn(async move {
                            while let Ok(mut sample) = incoming_track.recv().await {
                                // Strip header extensions and payload type to avoid mismatches
                                match &mut sample {
                                    media::MediaSample::Video(f) => {
                                        f.header_extension = None;
                                        f.payload_type = None;
                                        // Ensure we are not forwarding empty frames
                                        if f.data.is_empty() {
                                            continue;
                                        }
                                    }
                                    media::MediaSample::Audio(f) => {
                                        f.payload_type = None;
                                        if f.data.is_empty() {
                                            continue;
                                        }
                                    }
                                }

                                if let Err(_) = source.send(sample).await {
                                    break;
                                }
                            }
                            info!("Forward loop ended for {} {:?}", user_id_log, kind_log);
                        });

                        // Periodic PLI to source (every 3s)
                        let incoming_track_pli = track.clone();
                        let user_id_pli = user_id.clone();
                        tokio::spawn(async move {
                            // Wait a bit for connection to stabilize
                            tokio::time::sleep(Duration::from_secs(2)).await;
                            let mut interval = tokio::time::interval(Duration::from_secs(3));
                            loop {
                                interval.tick().await;
                                match incoming_track_pli.request_key_frame().await {
                                    Ok(_) => (),
                                    Err(e) => warn!("Failed to send PLI to {}: {}", user_id_pli, e),
                                }
                            }
                        });
                    }
                }
                PeerConnectionEvent::DataChannel(dc) => {
                    if dc.label == "chat" {
                        // Store DC
                        {
                            let mut peer_dc = peer_clone.dc.write().await;
                            *peer_dc = Some(dc.clone());
                        }
                        handle_chat_datachannel(dc, peer_clone.clone(), room_clone.clone()).await;
                    }
                }
            }
        }

        info!("Peer {} disconnected loop end", user_id);

        // 1. Identify tracks to remove
        let mut tracks_to_remove = Vec::new();
        {
            let mut tracks = room_clone.tracks.write().await;
            // Collect IDs of tracks being removed
            for t in tracks.iter() {
                if t.user_id == user_id && t.peer_id == peer_clone.id {
                    tracks_to_remove.push(t.remote_track.id().to_string());
                }
            }
            // Remove from room
            tracks.retain(|t| !(t.user_id == user_id && t.peer_id == peer_clone.id));
        }

        // 2. Remove peer and clean up others
        {
            let mut peers = room_clone.peers.write().await;
            if let Some(current_peer) = peers.get(&user_id) {
                if current_peer.id == peer_clone.id {
                    peers.remove(&user_id);
                }
            }

            for (other_id, other_peer) in peers.iter() {
                // Clean added_sources
                {
                    let mut added = other_peer.added_sources.write().await;
                    added.retain(|k| !k.starts_with(&format!("{}:{}:", user_id, peer_clone.id)));
                }

                // Stop transceivers sending these tracks
                let transceivers = other_peer.pc.get_transceivers();
                for t in transceivers {
                    if let Some(sender) = t.sender() {
                        let track_id = sender.track_id();
                        // Check if this relay track corresponds to any of the removed tracks
                        // Relay ID format: "{base}-relay-{suffix}"
                        for base_id in &tracks_to_remove {
                            if track_id.starts_with(&format!("{}-relay-", base_id)) {
                                info!(
                                    "Stopping ghost transceiver for peer {} track {}",
                                    other_id, track_id
                                );
                                t.set_sender(None);
                            }
                        }
                    }
                }
            }
        }

        // Notify others
        let msg = Message {
            type_: "notification".to_string(),
            text: Some(format!("User {} left", user_id)),
            ..Default::default()
        };
        broadcast(&room_clone, msg, None).await;
    });
}

async fn add_existing_tracks(peer: Arc<Peer>, room: Arc<Room>, trigger_negotiation: bool) {
    let user_id = peer.user_id.clone();
    let pc = peer.pc.clone();

    let tracks = room.tracks.read().await;
    let mut added_any = false;

    for track_info in tracks.iter() {
        if track_info.user_id == user_id {
            continue;
        }

        let source_key = format!(
            "{}:{}:{:?}",
            track_info.user_id, track_info.peer_id, track_info.kind
        );

        {
            let added = peer.added_sources.read().await;
            if added.contains(&source_key) {
                info!(
                    "add_existing_tracks skip peer={} source_key={} (already added)",
                    user_id, source_key
                );
                continue;
            }
        }

        let relay_track = track_info.relay.subscribe();

        match pc.add_track_with_stream_id(
            relay_track,
            track_info.user_id.clone(),
            track_info.params.clone(),
        ) {
            Ok(sender) => {
                added_any = true;
                {
                    let mut added = peer.added_sources.write().await;
                    added.insert(source_key);
                }
                info!(
                    "add_existing_tracks added to peer={} from user={} kind={:?}",
                    user_id, track_info.user_id, track_info.kind
                );
                // Forward PLI from this peer to the source of the track
                let remote_track = track_info.remote_track.clone();
                let mut rtcp_rx = sender.subscribe_rtcp();
                let user_id_pli = user_id.clone();
                tokio::spawn(async move {
                    while let Ok(packet) = rtcp_rx.recv().await {
                        match packet {
                            RtcpPacket::PictureLossIndication(_)
                            | RtcpPacket::FullIntraRequest(_) => {
                                info!("Forwarding PLI from {} to source", user_id_pli);
                                if let Err(e) = remote_track.request_key_frame().await {
                                    warn!(
                                        "Failed to forward PLI from {} to source: {}",
                                        user_id_pli, e
                                    );
                                }
                            }
                            _ => {}
                        }
                    }
                });
            }
            Err(e) => warn!("Failed to add existing track to new peer: {}", e),
        }
    }

    if added_any && trigger_negotiation {
        negotiate(&peer).await;
    }
}

async fn handle_chat_datachannel(
    dc: Arc<rustrtc::transports::sctp::DataChannel>,
    peer: Arc<Peer>,
    room: Arc<Room>,
) {
    let dc_clone = dc.clone();
    let room_clone = room.clone();
    let user_id = peer.user_id.clone();
    let peer_clone = peer.clone();

    tokio::spawn(async move {
        while let Some(event) = dc_clone.recv().await {
            match event {
                rustrtc::DataChannelEvent::Open => {
                    info!("Data channel open for {}", user_id);

                    // Send a welcome message to verify DC
                    let msg = Message {
                        type_: "chat".to_string(),
                        from: Some("System".to_string()),
                        text: Some("Welcome! DataChannel is working.".to_string()),
                        ..Default::default()
                    };
                    if let Ok(data) = serde_json::to_string(&msg) {
                        let _ = peer_clone.pc.send_text(dc_clone.id, &data).await;
                    }

                    // Notify join
                    let msg = Message {
                        type_: "notification".to_string(),
                        text: Some(format!("User {} joined", user_id)),
                        ..Default::default()
                    };
                    broadcast(&room_clone, msg, Some(&user_id)).await;

                    // Add existing tracks and negotiate
                    add_existing_tracks(peer_clone.clone(), room_clone.clone(), true).await;

                    // Force negotiation to ensure any tracks added during session setup
                    // (but not included in the initial Answer due to m-line limits) are negotiated.
                    negotiate(&peer_clone).await;

                    // Check if there was a pending negotiation that failed due to missing DC
                    if peer_clone.negotiation_pending.load(Ordering::SeqCst) {
                        info!(
                            "Triggering pending negotiation for {} after DC open",
                            user_id
                        );
                        negotiate(&peer_clone).await;
                    }
                }
                rustrtc::DataChannelEvent::Message(data) => {
                    info!(
                        "DataChannelEvent::Message from {} len={}",
                        user_id,
                        data.len()
                    );
                    if let Ok(text) = String::from_utf8(data.to_vec()) {
                        info!("Received DC message from {}: {}", user_id, text);
                        if let Ok(msg) = serde_json::from_str::<Message>(&text) {
                            match msg.type_.as_str() {
                                "chat" => {
                                    let broadcast_msg = Message {
                                        type_: "chat".to_string(),
                                        from: Some(user_id.clone()),
                                        text: msg.text,
                                        ..Default::default()
                                    };
                                    broadcast(&room_clone, broadcast_msg, Some(&user_id)).await;
                                }
                                "sdp" => {
                                    if let Some(sdp_dto) = msg.sdp {
                                        let sdp_type = match sdp_dto.sdp_type.as_str() {
                                            "offer" => SdpType::Offer,
                                            "answer" => SdpType::Answer,
                                            _ => {
                                                warn!("Unknown SDP type: {}", sdp_dto.sdp_type);
                                                continue;
                                            }
                                        };
                                        let sdp =
                                            match SessionDescription::parse(sdp_type, &sdp_dto.sdp)
                                            {
                                                Ok(s) => s,
                                                Err(e) => {
                                                    warn!("Failed to parse SDP: {}", e);
                                                    continue;
                                                }
                                            };

                                        info!(
                                            "Received SDP via DataChannel from {} type={:?}",
                                            user_id, sdp.sdp_type
                                        );

                                        if sdp.sdp_type == SdpType::Offer {
                                            if let Err(e) =
                                                peer_clone.pc.set_remote_description(sdp).await
                                            {
                                                warn!(
                                                    "Failed to set remote description from DC: {}",
                                                    e
                                                );
                                                continue;
                                            }

                                            let answer = match peer_clone.pc.create_answer().await {
                                                Ok(a) => a,
                                                Err(e) => {
                                                    warn!("Failed to create answer from DC: {}", e);
                                                    continue;
                                                }
                                            };

                                            if let Err(e) =
                                                peer_clone.pc.set_local_description(answer.clone())
                                            {
                                                warn!(
                                                    "Failed to set local description from DC: {}",
                                                    e
                                                );
                                                continue;
                                            }

                                            // Send answer back via DC
                                            let answer_dto = SdpDto {
                                                sdp_type: "answer".to_string(),
                                                sdp: answer.to_sdp_string(),
                                            };
                                            let response = Message {
                                                type_: "sdp".to_string(),
                                                sdp: Some(answer_dto),
                                                ..Default::default()
                                            };

                                            if let Ok(resp_data) = serde_json::to_string(&response)
                                            {
                                                let _ = peer_clone
                                                    .pc
                                                    .send_text(dc_clone.id, &resp_data)
                                                    .await;
                                            }
                                        } else if sdp.sdp_type == SdpType::Answer {
                                            info!("Received Answer from {}", user_id);
                                            if let Err(e) =
                                                peer_clone.pc.set_remote_description(sdp).await
                                            {
                                                warn!("Failed to set remote answer: {}", e);
                                                continue;
                                            }

                                            if peer_clone.negotiation_pending.load(Ordering::SeqCst)
                                            {
                                                info!(
                                                    "Negotiation pending for {}, triggering now",
                                                    user_id
                                                );
                                                negotiate(&peer_clone).await;
                                            }
                                        }
                                    }
                                }
                                _ => {}
                            }
                        }
                    }
                }
                _ => {}
            }
        }
    });
}

async fn negotiate(peer: &Peer) {
    info!("negotiate called for {}", peer.user_id);
    // Check signaling state
    use rustrtc::peer_connection::SignalingState;

    let signaling_state = peer.pc.signaling_state();
    if signaling_state != SignalingState::Stable {
        // If we are in HaveLocalOffer and negotiation is pending, it might mean we failed to send the offer.
        // Try to resend the current local description.
        if signaling_state == SignalingState::HaveLocalOffer
            && peer.negotiation_pending.load(Ordering::SeqCst)
        {
            if let Some(local_desc) = peer.pc.local_description() {
                info!("Resending pending offer for {}", peer.user_id);

                let sdp_dto = SdpDto {
                    sdp_type: "offer".to_string(),
                    sdp: local_desc.to_sdp_string(),
                };

                let msg = Message {
                    type_: "sdp".to_string(),
                    sdp: Some(sdp_dto),
                    ..Default::default()
                };

                if let Some(dc) = peer.dc.read().await.as_ref() {
                    if let Ok(data) = serde_json::to_string(&msg) {
                        info!("Sending JSON Offer (Resend) to {}: {}", peer.user_id, data);
                        if let Err(e) = peer.pc.send_text(dc.id, &data).await {
                            error!("Failed to send offer via DC: {}", e);
                            // Keep pending
                            return;
                        } else {
                            info!("Sent offer via DC to {}", peer.user_id);
                            // We successfully sent the offer, so we are waiting for answer.
                            // We DO NOT clear pending flag here, because we might have accumulated
                            // more changes (like new tracks) while we were waiting for DC.
                            // If we keep pending=true, then when the Answer arrives, handle_chat_datachannel
                            // will trigger negotiate() again, which will generate a NEW offer with the new tracks.
                            // peer.negotiation_pending.store(false, Ordering::SeqCst);
                            return;
                        }
                    }
                } else {
                    warn!(
                        "Cannot negotiate (Resend): DataChannel not ready for user {}",
                        peer.user_id
                    );
                    // Keep pending
                    return;
                }
            }
        }

        info!(
            "Signaling state is not stable ({:?}), marking negotiation pending for {}",
            signaling_state, peer.user_id
        );
        peer.negotiation_pending.store(true, Ordering::SeqCst);
        return;
    }

    peer.negotiation_pending.store(false, Ordering::SeqCst);

    match peer.pc.create_offer().await {
        Ok(offer) => {
            info!(
                "Created offer for {}, sending via DC. SDP:\n{}",
                peer.user_id,
                offer.to_sdp_string()
            );
            if let Err(e) = peer.pc.set_local_description(offer.clone()) {
                warn!("Failed to set local description during negotiation: {}", e);
                // If we failed to set local description, it might be due to state change.
                // Mark pending to retry.
                peer.negotiation_pending.store(true, Ordering::SeqCst);
                return;
            }

            let sdp_dto = SdpDto {
                sdp_type: "offer".to_string(),
                sdp: offer.to_sdp_string(),
            };

            let msg = Message {
                type_: "sdp".to_string(),
                sdp: Some(sdp_dto),
                ..Default::default()
            };

            if let Some(dc) = peer.dc.read().await.as_ref() {
                if let Ok(data) = serde_json::to_string(&msg) {
                    info!("Sending JSON Offer to {}: {}", peer.user_id, data);
                    if let Err(e) = peer.pc.send_text(dc.id, &data).await {
                        error!("Failed to send offer via DC: {}", e);
                    } else {
                        info!("Sent offer via DC to {}", peer.user_id);
                    }
                }
            } else {
                warn!(
                    "Cannot negotiate: DataChannel not ready for user {}",
                    peer.user_id
                );
                peer.negotiation_pending.store(true, Ordering::SeqCst);
            }
        }
        Err(e) => {
            warn!("Failed to create offer during negotiation: {}", e);
            // If we failed to create offer (likely due to state), mark pending.
            peer.negotiation_pending.store(true, Ordering::SeqCst);
        }
    }
}
async fn broadcast(room: &Room, msg: Message, exclude_user_id: Option<&str>) {
    let peers = room.peers.read().await;
    info!(
        "Broadcasting to {} peers (excluding {:?})",
        peers.len(),
        exclude_user_id
    );
    let data = match serde_json::to_string(&msg) {
        Ok(d) => d,
        Err(_) => return,
    };

    for (uid, peer) in peers.iter() {
        if let Some(exclude) = exclude_user_id {
            if uid == exclude {
                continue;
            }
        }
        if let Some(dc) = peer.dc.read().await.as_ref() {
            info!("Broadcasting to {}: {}", uid, data);
            if let Err(e) = peer.pc.send_text(dc.id, &data).await {
                warn!("Failed to broadcast to {}: {}", uid, e);
            } else {
                info!("Broadcast sent to {}", uid);
            }
        } else {
            warn!("Skipping broadcast to {}: No DataChannel", uid);
        }
    }
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct Message {
    #[serde(rename = "type")]
    type_: String,
    #[serde(rename = "userId", skip_serializing_if = "Option::is_none")]
    user_id: Option<String>,
    #[serde(rename = "roomId", skip_serializing_if = "Option::is_none")]
    room_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    from: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sdp: Option<SdpDto>,
}
