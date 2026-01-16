use axum::{Router, extract::Json, response::IntoResponse, routing::post};
use rustrtc::media::MediaStreamTrack;
use rustrtc::{PeerConnection, RtcConfiguration, SdpType, SessionDescription, TransportMode};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tracing::{info, warn};

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
}

async fn start_forwarding(pc: PeerConnection, pt: u8, echo_addr: SocketAddr) {
    let transceivers = pc.get_transceivers();
    let (kind, clock_rate) = if pt == 0 {
        (rustrtc::media::MediaKind::Audio, 8000)
    } else {
        (rustrtc::media::MediaKind::Video, 90000)
    };

    info!(
        "Starting forwarding for {} transceivers (PT {}, Kind {:?})",
        transceivers.len(),
        pt,
        kind
    );
    for transceiver in transceivers {
        let transceiver_kind = match transceiver.kind() {
            rustrtc::MediaKind::Audio => rustrtc::media::MediaKind::Audio,
            rustrtc::MediaKind::Video => rustrtc::media::MediaKind::Video,
            _ => continue,
        };
        if transceiver_kind != kind {
            continue;
        }

        transceiver.set_direction(rustrtc::TransceiverDirection::SendRecv);

        let receiver = transceiver.receiver().unwrap();
        let incoming_track = receiver.track();
        let transceiver_id = transceiver.id();

        let (sample_source, outgoing_track, _) = rustrtc::media::sample_track(kind, 100);
        let ssrc = 5000 + transceiver_id as u32;
        let sender = rustrtc::peer_connection::RtpSender::builder(outgoing_track, ssrc)
            .params(rustrtc::RtpCodecParameters {
                payload_type: pt,
                clock_rate,
                channels: if pt == 0 { 1 } else { 0 },
            })
            .build();
        transceiver.set_sender(Some(sender));

        let echo_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await.unwrap());
        let sample_source = Arc::new(sample_source);

        info!(
            "Transceiver {} SSRC {} linked to Echo",
            transceiver_id, ssrc
        );

        // Task to receive from PC (from Generator), send to Echo
        let incoming_track_clone = incoming_track.clone();
        let echo_socket_clone = echo_socket.clone();
        let pc_clone = pc.clone();
        tokio::spawn(async move {
            let _pc = pc_clone; // Keep PC alive
            let mut count = 0;
            loop {
                match incoming_track_clone.recv().await {
                    Ok(sample) => {
                        count += 1;
                        if count % 100 == 0 {
                            info!("SUT received {} packets for track {} from PC", count, ssrc);
                        }
                        let data = match sample {
                            rustrtc::media::MediaSample::Video(frame) => frame.data,
                            rustrtc::media::MediaSample::Audio(frame) => frame.data,
                        };
                        if !data.is_empty() {
                            let _ = echo_socket_clone.send_to(&data, echo_addr).await;
                        }
                    }
                    Err(e) => {
                        warn!("Incoming track {} ended: {}", ssrc, e);
                        break;
                    }
                }
            }
        });

        // Task to receive from Echo, send back to sender (to Generator)
        let echo_socket_clone = echo_socket.clone();
        let sample_source_clone = sample_source.clone();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            let mut count = 0;
            loop {
                match echo_socket_clone.recv_from(&mut buf).await {
                    Ok((size, _)) => {
                        count += 1;
                        if count % 100 == 0 {
                            info!(
                                "SUT received {} packets from ECHO for track {}",
                                count, ssrc
                            );
                        }
                        let sample = if pt == 0 {
                            rustrtc::media::MediaSample::Audio(rustrtc::media::AudioFrame {
                                data: buf[..size].to_vec().into(),
                                rtp_timestamp: 0,
                                payload_type: Some(pt),
                                ..Default::default()
                            })
                        } else {
                            rustrtc::media::MediaSample::Video(rustrtc::media::VideoFrame {
                                data: buf[..size].to_vec().into(),
                                rtp_timestamp: 0,
                                payload_type: Some(pt),
                                ..Default::default()
                            })
                        };
                        if let Err(e) = sample_source_clone.send(sample).await {
                            warn!("Sample source for {} error: {}", ssrc, e);
                            break;
                        }
                    }
                    Err(e) => {
                        warn!("Echo socket for {} error: {}", ssrc, e);
                        break;
                    }
                }
            }
        });
    }
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer");

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
    caps.video = vec![rustrtc::config::VideoCapability {
        payload_type: 96,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        rtcp_fbs: vec![],
    }];
    config.media_capabilities = Some(caps);

    let pc = PeerConnection::new(config);

    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();

    // Check if offer has audio or video
    let mut pt = 96;
    for section in &offer_sdp.media_sections {
        if section.kind == rustrtc::MediaKind::Audio {
            pt = 0;
            break;
        }
    }

    pc.set_remote_description(offer_sdp).await.unwrap();

    let echo_addr: SocketAddr = "127.0.0.1:6000".parse().unwrap();

    // Start forwarding tasks
    tokio::spawn(start_forwarding(pc.clone(), pt, echo_addr));

    let _ = pc.create_answer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
    })
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let app = Router::new().route("/offer", post(offer));
    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    info!("SUT Listening on http://{}", addr);
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}
