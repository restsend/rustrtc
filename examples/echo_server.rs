use async_trait::async_trait;
use axum::{
    Router,
    extract::Json,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use rustrtc::PeerConnection;
use rustrtc::media::{self, MediaKind as MediaStreamKind, MediaStreamTrack};
use rustrtc::media::{
    MediaError, MediaKind, MediaResult, MediaSample, MediaSource, Packetizer, TrackMediaSink,
    VideoFrame, Vp8Payloader, spawn_media_pump,
};
use rustrtc::sdp::MediaKind as SdpMediaKind;
use rustrtc::{RtcConfiguration, SdpType, SessionDescription};
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;
use tokio::time::Interval;
use tower_http::services::ServeDir;
use tracing::{info, warn};
use webrtc::media::io::ivf_reader::IVFReader;

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
    Html(include_str!("static/index.html"))
}

#[derive(Deserialize, Debug)]
enum Mode {
    #[serde(rename = "echo")]
    Echo,
    #[serde(rename = "datachannel")]
    Datachannel,
    #[serde(rename = "video")]
    Video,
    #[serde(rename = "video-only")]
    VideoOnly,
}

#[derive(Deserialize)]
struct OfferRequest {
    sdp: String,
    #[allow(unused)]
    r#type: String,
    #[serde(default = "default_mode")]
    mode: Mode,
}

fn default_mode() -> Mode {
    Mode::Echo
}

fn find_vp8_payload_type(desc: &SessionDescription) -> Option<u8> {
    for media in &desc.media_sections {
        if media.kind != SdpMediaKind::Video {
            continue;
        }

        for attr in &media.attributes {
            if attr.key != "rtpmap" {
                continue;
            }

            if let Some(value) = &attr.value {
                let mut parts = value.split_whitespace();
                if let (Some(pt_str), Some(codec_part)) = (parts.next(), parts.next()) {
                    let codec_name = codec_part.split('/').next().unwrap_or("");
                    if codec_name.eq_ignore_ascii_case("VP8") {
                        if let Ok(pt) = pt_str.parse::<u8>() {
                            return Some(pt);
                        }
                    }
                }
            }
        }
    }

    None
}

#[derive(Serialize)]
struct OfferResponse {
    sdp: String,
    #[serde(rename = "type")]
    type_: String,
}

async fn offer(Json(payload): Json<OfferRequest>) -> impl IntoResponse {
    info!("Received offer with mode: {:?}", payload.mode);

    handle_rustrtc_offer(payload).await
}

async fn handle_rustrtc_offer(payload: OfferRequest) -> Json<OfferResponse> {
    info!("Offer SDP:\n{}", payload.sdp);
    // Handle SDP first to extract capabilities
    let offer_sdp = SessionDescription::parse(SdpType::Offer, &payload.sdp).unwrap();
    let vp8_pt = find_vp8_payload_type(&offer_sdp).unwrap_or(96);
    info!("Determined VP8 Payload Type: {}", vp8_pt);
    let mut config = RtcConfiguration::default();
    // Configure media capabilities with the found PT
    let mut caps = rustrtc::config::MediaCapabilities::default();
    caps.video = vec![rustrtc::config::VideoCapability {
        payload_type: vp8_pt,
        codec_name: "VP8".to_string(),
        clock_rate: 90000,
        rtcp_fbs: vec!["nack pli".to_string(), "transport-cc".to_string()],
    }];
    config.media_capabilities = Some(caps);

    let pc = PeerConnection::new(config);

    let mut ice_state_rx = pc.subscribe_ice_connection_state();
    tokio::spawn(async move {
        while let Ok(()) = ice_state_rx.changed().await {
            let state = *ice_state_rx.borrow();
            if state == rustrtc::IceConnectionState::Disconnected {
                info!("ICE connection disconnected");
            }
        }
    });

    // Create DataChannel (negotiated id=0)
    if !matches!(payload.mode, Mode::VideoOnly) {
        let dc = pc.create_data_channel("echo", None).unwrap();

        // Setup echo
        let pc_clone = pc.clone();
        let dc_clone = dc.clone();

        tokio::spawn(async move {
            while let Some(event) = dc_clone.recv().await {
                match event {
                    rustrtc::DataChannelEvent::Message(data) => {
                        info!("Received message: {:?}", String::from_utf8_lossy(&data));
                        let pc = pc_clone.clone();
                        tokio::spawn(async move {
                            // Echo back
                            let res = if let Ok(text) = String::from_utf8(data.to_vec()) {
                                pc.send_text(0, &text).await
                            } else {
                                pc.send_data(0, &data).await
                            };

                            if let Err(e) = res {
                                warn!("Failed to send data: {}", e);
                            } else {
                                info!("Sent echo");
                            }
                        });
                    }
                    rustrtc::DataChannelEvent::Open => {
                        info!("Data channel opened");
                    }
                    rustrtc::DataChannelEvent::Close => {
                        info!("Data channel closed");
                        break;
                    }
                }
            }
        });
    }

    pc.set_remote_description(offer_sdp).await.unwrap();

    match payload.mode {
        Mode::Echo => start_echo(pc.clone(), vp8_pt).await,
        Mode::Video | Mode::VideoOnly => start_video_playback(pc.clone(), vp8_pt).await,
        Mode::Datachannel => {
            // Do nothing for video
        }
    }
    // Create answer and wait for gathering
    let _ = pc.create_answer().await.unwrap();

    // Wait for gathering to complete
    pc.wait_for_gathering_complete().await;

    let answer = pc.create_answer().await.unwrap();
    pc.set_local_description(answer.clone()).unwrap();

    Json(OfferResponse {
        sdp: answer.to_sdp_string(),
        type_: "answer".to_string(),
    })
}

async fn start_echo(pc: PeerConnection, vp8_pt: u8) {
    let transceivers = pc.get_transceivers();
    for transceiver in transceivers {
        if transceiver.kind() != rustrtc::MediaKind::Video {
            continue;
        }

        transceiver.set_direction(rustrtc::TransceiverDirection::SendRecv);

        let receiver = transceiver.receiver();
        let Some(receiver) = receiver else {
            warn!("Video transceiver {} missing receiver", transceiver.id());
            continue;
        };

        let incoming_track = receiver.track();
        // Check for simulcast
        let simulcast_rids = receiver.get_simulcast_rids();
        let incoming_track = if !simulcast_rids.is_empty() {
            // Prefer "lo" (low resolution) as it's most likely to be sent first/always
            let rid = if simulcast_rids.contains(&"lo".to_string()) {
                "lo"
            } else if simulcast_rids.contains(&"mid".to_string()) {
                "mid"
            } else {
                simulcast_rids.first().unwrap()
            };
            info!("Using simulcast track: {}", rid);
            receiver.simulcast_track(rid).unwrap()
        } else {
            incoming_track
        };

        let (sample_source, outgoing_track, _) = media::sample_track(MediaStreamKind::Video, 120);

        let ssrc = 5000 + transceiver.id() as u32;
        let sender = rustrtc::peer_connection::RtpSender::builder(outgoing_track.clone(), ssrc)
            .stream_id("stream".to_string())
            .params(rustrtc::RtpCodecParameters {
                payload_type: vp8_pt,
                clock_rate: 90000,
                channels: 0,
            })
            .build();

        let mut rtcp_rx = sender.subscribe_rtcp();
        let incoming_track_clone = incoming_track.clone();
        tokio::spawn(async move {
            while let Ok(packet) = rtcp_rx.recv().await {
                match packet {
                    rustrtc::rtp::RtcpPacket::PictureLossIndication(_)
                    | rustrtc::rtp::RtcpPacket::FullIntraRequest(_) => {
                        if let Err(e) = incoming_track_clone.request_key_frame().await {
                            warn!("Failed to request key frame: {}", e);
                        } else {
                            info!("Forwarded PLI/FIR to incoming track");
                        }
                    }
                    _ => {}
                }
            }
        });

        transceiver.set_sender(Some(sender));

        let pc_clone = pc.clone();
        tokio::spawn(async move {
            // Keep PC alive
            let _pc = pc_clone;
            loop {
                match incoming_track.recv().await {
                    Ok(sample) => {
                        let is_empty = match &sample {
                            MediaSample::Video(f) => f.data.is_empty(),
                            MediaSample::Audio(f) => f.data.is_empty(),
                        };
                        if is_empty {
                            continue;
                        }

                        // Modify sample to strip extensions and ensure PT matches
                        let mut sample = sample;
                        if let MediaSample::Video(ref mut f) = sample {
                            // Filter out non-VP8 packets (e.g. RTX)
                            if let Some(pt) = f.payload_type {
                                if pt != vp8_pt {
                                    info!("Dropping video packet with PT: {}", pt);
                                    continue;
                                }
                            }
                            // Strip extensions to avoid sending bad transport-cc
                            f.header_extension = None;
                        }

                        if let Err(err) = sample_source.send(sample).await {
                            warn!("Video echo forwarder stopped: {}", err);
                            break;
                        }
                    }
                    Err(err) => {
                        warn!("Video ingress track ended: {}", err);
                        break;
                    }
                }
            }
        });
    }
}

#[allow(unused)]
struct IvfHeader {
    width: u16,
    height: u16,
    num_frames: u32,
    timebase_numerator: u32,
    timebase_denominator: u32,
}

struct IvfSource {
    reader: IVFReader<BufReader<File>>,
    header: IvfHeader,
    interval: Interval,
    rtp_timestamp_offset: u32,
    last_timestamp_state: Arc<AtomicU32>,
}

impl IvfSource {
    fn new(
        reader: IVFReader<BufReader<File>>,
        header: IvfHeader,
        rtp_timestamp_offset: u32,
        last_timestamp_state: Arc<AtomicU32>,
    ) -> Self {
        let mut interval = tokio::time::interval(Duration::from_millis(33));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        Self {
            reader,
            header,
            interval,
            rtp_timestamp_offset,
            last_timestamp_state,
        }
    }
}

#[async_trait]
impl MediaSource for IvfSource {
    fn id(&self) -> &str {
        "ivf-source"
    }
    fn kind(&self) -> MediaKind {
        MediaKind::Video
    }
    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        self.interval.tick().await;
        match self.reader.parse_next_frame() {
            Ok((frame, meta)) => {
                let timestamp_sec = meta.timestamp as f64 * self.header.timebase_numerator as f64
                    / self.header.timebase_denominator as f64;
                let rtp_samples = (timestamp_sec * 90000.0) as u32;
                let current_rtp_time = self.rtp_timestamp_offset.wrapping_add(rtp_samples);

                self.last_timestamp_state
                    .store(current_rtp_time, Ordering::SeqCst);

                let vf = VideoFrame {
                    rtp_timestamp: current_rtp_time,
                    data: frame.freeze(),
                    ..Default::default()
                };
                Ok(MediaSample::Video(vf))
            }
            Err(_) => Err(MediaError::EndOfStream),
        }
    }
}

async fn start_video_playback(pc: PeerConnection, vp8_pt: u8) {
    let transceivers = pc.get_transceivers();
    info!(
        "start_video_playback: found {} transceivers",
        transceivers.len()
    );
    for (i, t) in transceivers.iter().enumerate() {
        info!("Transceiver {}: kind={:?} mid={:?}", i, t.kind(), t.mid());
    }

    let mut video_playing = false;
    for transceiver in transceivers {
        if transceiver.kind() != rustrtc::MediaKind::Video {
            continue;
        }

        transceiver.set_direction(rustrtc::TransceiverDirection::SendRecv);

        // Drain incoming track to prevent backpressure blocking the connection
        if let Some(receiver) = transceiver.receiver() {
            let incoming_track = receiver.track();
            tokio::spawn(async move {
                while let Ok(_) = incoming_track.recv().await {
                    // Discard
                }
            });
        }

        if video_playing {
            info!("Skipping additional video transceiver for playback");
            continue;
        }
        video_playing = true;

        let (sample_source, outgoing_track, _) = media::sample_track(MediaStreamKind::Video, 120);

        let ssrc = 5000 + transceiver.id() as u32;
        let sender = rustrtc::peer_connection::RtpSender::builder(outgoing_track.clone(), ssrc)
            .stream_id("stream".to_string())
            .params(rustrtc::RtpCodecParameters {
                payload_type: vp8_pt,
                clock_rate: 90000,
                channels: 0,
            })
            .build();

        let mut rtcp_rx = sender.subscribe_rtcp();
        transceiver.set_sender(Some(sender));

        let sample_source = sample_source.clone();
        let pc_clone = pc.clone();
        tokio::spawn(async move {
            if let Err(e) = pc_clone.wait_for_connected().await {
                warn!("Peer connection failed: {}", e);
                return;
            }
            info!("Peer connection established, starting video playback");
            let mut ice_state_rx_loop = pc_clone.subscribe_ice_connection_state();

            let last_rtp_timestamp = Arc::new(AtomicU32::new(0));
            let mut rtp_timestamp_offset = 0u32;

            loop {
                let file = match File::open("examples/static/output.ivf") {
                    Ok(f) => f,
                    Err(e) => {
                        warn!("Failed to open output.ivf: {}", e);
                        return;
                    }
                };
                let reader = BufReader::new(file);
                let (ivf, header) = match IVFReader::new(reader) {
                    Ok(r) => r,
                    Err(e) => {
                        warn!("Failed to create IVF reader: {}", e);
                        return;
                    }
                };

                info!(
                    "Playing IVF file: {}x{} {} frames",
                    header.width, header.height, header.num_frames
                );

                let ivf_header = IvfHeader {
                    width: header.width,
                    height: header.height,
                    num_frames: header.num_frames,
                    timebase_numerator: header.timebase_numerator,
                    timebase_denominator: header.timebase_denominator,
                };

                let source = Box::new(IvfSource::new(
                    ivf,
                    ivf_header,
                    rtp_timestamp_offset,
                    last_rtp_timestamp.clone(),
                ));
                let packetizer = Box::new(Packetizer::new(source, 1200, Box::new(Vp8Payloader)));
                let sink = Arc::new(TrackMediaSink::new(Arc::new(sample_source.clone())));

                let pump = spawn_media_pump(packetizer, sink).unwrap();

                tokio::select! {
                    _ = pump => {
                        info!("Play done");
                        // Finished naturally
                        let last = last_rtp_timestamp.load(Ordering::SeqCst);
                        rtp_timestamp_offset = last.wrapping_add(3000);
                    }
                    result = rtcp_rx.recv() => {
                        if let Ok(rustrtc::rtp::RtcpPacket::PictureLossIndication(_)) = result {
                            info!("Received PLI, restarting video to send keyframe");
                            let last = last_rtp_timestamp.load(Ordering::SeqCst);
                            rtp_timestamp_offset = last.wrapping_add(3000);
                            // Pump will be dropped and aborted when we loop
                        }
                    }
                    res = ice_state_rx_loop.changed() => {
                        if res.is_ok() {
                            let state = *ice_state_rx_loop.borrow();
                            if state == rustrtc::IceConnectionState::Disconnected || state == rustrtc::IceConnectionState::Failed || state == rustrtc::IceConnectionState::Closed {
                                info!("Stopping playback due to connection state: {:?}", state);
                                return;
                            }
                            // Ignore other state changes (e.g. Connected -> Completed)
                        } else {
                            return;
                        }
                    }
                }
            }
        });
    }
}
