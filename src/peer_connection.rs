use crate::media::track::{MediaStreamTrack, SampleStreamSource, SampleStreamTrack, sample_track};
use crate::rtp::{
    FirRequest, FullIntraRequest, GenericNack, PictureLossIndication, RtcpPacket, RtpPacket,
};
use crate::stats::{StatsReport, gather_once};
use crate::stats_collector::StatsCollector;
use crate::transports::dtls::{self, DtlsTransport};
use crate::transports::get_local_ip;
use crate::transports::ice::stun::random_u32;
use crate::transports::ice::{IceCandidate, IceGathererState, IceTransport, conn::IceConn};
use crate::transports::rtp::RtpTransport;
use crate::transports::sctp::SctpTransport;
use crate::{
    Attribute, AudioCapability, Direction, MediaKind, MediaSection, Origin, RtcConfiguration,
    RtcError, RtcResult, SdpType, SessionDescription, TransportMode, VideoCapability,
};
use base64::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, trace, warn};
// use tracing::{debug, trace, warn};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use std::future::Future;
use std::pin::Pin;
use std::sync::Weak;

#[async_trait]
pub trait RtpSenderInterceptor: Send + Sync {
    async fn on_packet_sent(&self, _packet: &RtpPacket) {}
    async fn on_rtcp_received(&self, _packet: &RtcpPacket, _transport: Arc<RtpTransport>) {}
    fn as_nack_stats(self: Arc<Self>) -> Option<Arc<dyn NackStats>> {
        None
    }
}

#[async_trait]
pub trait RtpReceiverInterceptor: Send + Sync {
    async fn on_packet_received(&self, _packet: &RtpPacket) -> Option<RtcpPacket> {
        None
    }
    async fn on_rtcp_received(&self, _packet: &RtcpPacket, _transport: Arc<RtpTransport>) {}
    fn as_nack_stats(self: Arc<Self>) -> Option<Arc<dyn NackStats>> {
        None
    }
}

pub trait NackStats: Send + Sync {
    fn get_nack_count(&self) -> u64;
    fn get_recovered_count(&self) -> u64 {
        0
    }
}

pub struct DefaultRtpSenderNackHandler {
    buffer: Mutex<VecDeque<RtpPacket>>,
    max_size: usize,
    pub nack_recv_count: AtomicU64,
}

pub struct DefaultRtpSenderBitrateHandler;

impl DefaultRtpSenderBitrateHandler {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl RtpSenderInterceptor for DefaultRtpSenderBitrateHandler {
    async fn on_rtcp_received(&self, packet: &RtcpPacket, _transport: Arc<RtpTransport>) {
        if let RtcpPacket::RemoteBitrateEstimate(remb) = packet {
            debug!("Received REMB: {} bps", remb.bitrate_bps);
        }
    }
}

impl DefaultRtpSenderNackHandler {
    pub fn new(max_size: usize) -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(max_size)),
            max_size,
            nack_recv_count: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl RtpSenderInterceptor for DefaultRtpSenderNackHandler {
    async fn on_packet_sent(&self, packet: &RtpPacket) {
        let mut buffer = self.buffer.lock().unwrap();
        buffer.push_back(packet.clone());
        if buffer.len() > self.max_size {
            buffer.pop_front();
        }
    }

    async fn on_rtcp_received(&self, packet: &RtcpPacket, transport: Arc<RtpTransport>) {
        if let RtcpPacket::GenericNack(nack) = packet {
            debug!(
                "NACK: received NACK for {} packets",
                nack.lost_packets.len()
            );
            self.nack_recv_count
                .fetch_add(nack.lost_packets.len() as u64, Ordering::Relaxed);

            let to_resend = {
                let buffer = self.buffer.lock().unwrap();
                let mut packets = Vec::new();
                for seq in &nack.lost_packets {
                    if let Some(packet) = buffer.iter().find(|p| p.header.sequence_number == *seq) {
                        packets.push(packet.clone());
                    }
                }
                packets
            };

            for packet in to_resend {
                let seq_num = packet.header.sequence_number;
                debug!("NACK: retransmitting packet seq={}", seq_num);
                let _ = transport.send_rtp(&packet).await;
            }
        }
    }

    fn as_nack_stats(self: Arc<Self>) -> Option<Arc<dyn NackStats>> {
        Some(self)
    }
}

impl NackStats for DefaultRtpSenderNackHandler {
    fn get_nack_count(&self) -> u64 {
        self.nack_recv_count.load(Ordering::Relaxed)
    }
}

pub struct DefaultRtpReceiverNackHandler {
    last_seq: AtomicU16,
    initialized: std::sync::atomic::AtomicBool,
    pub nack_sent_count: AtomicU64,
    pub nack_recovered_count: AtomicU64,
}

impl DefaultRtpReceiverNackHandler {
    pub fn new() -> Self {
        Self {
            last_seq: AtomicU16::new(0),
            initialized: std::sync::atomic::AtomicBool::new(false),
            nack_sent_count: AtomicU64::new(0),
            nack_recovered_count: AtomicU64::new(0),
        }
    }
}

#[async_trait]
impl RtpReceiverInterceptor for DefaultRtpReceiverNackHandler {
    async fn on_packet_received(&self, packet: &RtpPacket) -> Option<RtcpPacket> {
        let seq = packet.header.sequence_number;
        if !self.initialized.swap(true, Ordering::SeqCst) {
            self.last_seq.store(seq, Ordering::SeqCst);
            return None;
        }

        let last = self.last_seq.load(Ordering::SeqCst);
        let diff = seq.wrapping_sub(last);

        if diff > 1 && diff < 32768 {
            let mut lost = Vec::new();
            let mut s = last.wrapping_add(1);
            while s != seq {
                lost.push(s);
                s = s.wrapping_add(1);
            }
            debug!(
                "NACK: detected gap from {} to {}, lost {} packets",
                last,
                seq,
                lost.len()
            );
            self.nack_sent_count
                .fetch_add(lost.len() as u64, Ordering::Relaxed);
            self.last_seq.store(seq, Ordering::SeqCst);
            return Some(RtcpPacket::GenericNack(GenericNack {
                sender_ssrc: 0, // Will be filled by receiver
                media_ssrc: packet.header.ssrc,
                lost_packets: lost,
            }));
        }

        if diff < 32768 {
            self.last_seq.store(seq, Ordering::SeqCst);
        } else if diff > 32768 {
            debug!("NACK: received old packet seq={}, last={}", seq, last);
            self.nack_recovered_count.fetch_add(1, Ordering::Relaxed);
        }
        None
    }

    fn as_nack_stats(self: Arc<Self>) -> Option<Arc<dyn NackStats>> {
        Some(self)
    }
}

impl NackStats for DefaultRtpReceiverNackHandler {
    fn get_nack_count(&self) -> u64 {
        self.nack_sent_count.load(Ordering::Relaxed)
    }

    fn get_recovered_count(&self) -> u64 {
        self.nack_recovered_count.load(Ordering::Relaxed)
    }
}

enum ReceiverCommand {
    AddTrack {
        rid: Option<String>,
        packet_rx: mpsc::Receiver<(crate::rtp::RtpPacket, std::net::SocketAddr)>,
        feedback_rx:
            std::sync::Arc<tokio::sync::Mutex<mpsc::Receiver<crate::media::track::FeedbackEvent>>>,
        source: std::sync::Arc<crate::media::track::SampleStreamSource>,
        simulcast_ssrc: std::sync::Arc<std::sync::Mutex<Option<u32>>>,
    },
}

enum LoopEvent {
    Packet(
        Option<(crate::rtp::RtpPacket, std::net::SocketAddr)>,
        Option<String>,
        mpsc::Receiver<(crate::rtp::RtpPacket, std::net::SocketAddr)>,
    ),
    Feedback(Option<crate::media::track::FeedbackEvent>, Option<String>),
}

#[derive(Clone)]
pub enum PeerConnectionEvent {
    DataChannel(Arc<crate::transports::sctp::DataChannel>),
    Track(Arc<RtpTransceiver>),
}

#[derive(Clone)]
pub struct PeerConnection {
    inner: Arc<PeerConnectionInner>,
}

struct PeerConnectionInner {
    config: RtcConfiguration,
    signaling_state: watch::Sender<SignalingState>,
    _signaling_state_rx: watch::Receiver<SignalingState>,
    peer_state: watch::Sender<PeerConnectionState>,
    _peer_state_rx: watch::Receiver<PeerConnectionState>,
    ice_connection_state: watch::Sender<IceConnectionState>,
    _ice_connection_state_rx: watch::Receiver<IceConnectionState>,
    ice_gathering_state: watch::Sender<IceGatheringState>,
    _ice_gathering_state_rx: watch::Receiver<IceGatheringState>,
    local_description: Mutex<Option<SessionDescription>>,
    remote_description: Mutex<Option<SessionDescription>>,
    transceivers: Mutex<Vec<Arc<RtpTransceiver>>>,
    next_mid: AtomicU16,
    ice_transport: IceTransport,
    certificate: Arc<dtls::Certificate>,
    dtls_fingerprint: String,
    dtls_transport: Mutex<Option<Arc<DtlsTransport>>>,
    rtp_transport: Mutex<Option<Arc<RtpTransport>>>,
    sctp_transport: Mutex<Option<Arc<SctpTransport>>>,
    data_channels: Arc<Mutex<Vec<std::sync::Weak<crate::transports::sctp::DataChannel>>>>,
    event_tx: mpsc::UnboundedSender<PeerConnectionEvent>,
    event_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<PeerConnectionEvent>>,
    dtls_role: watch::Sender<Option<bool>>,
    _dtls_role_rx: watch::Receiver<Option<bool>>,
    stats_collector: Arc<StatsCollector>,
    ssrc_generator: AtomicU32,
}

fn generate_sdes_key_params() -> String {
    let mut key_salt = [0u8; 30];
    rand::fill(&mut key_salt);
    let encoded = BASE64_STANDARD.encode(&key_salt);
    format!("inline:{}", encoded)
}

fn parse_sdes_key_params(params: &str) -> RtcResult<Vec<u8>> {
    if !params.starts_with("inline:") {
        return Err(RtcError::Internal("Unsupported key params".into()));
    }
    let key_salt_base64 = &params[7..];
    let key_salt_base64 = key_salt_base64.split('|').next().unwrap();
    BASE64_STANDARD
        .decode(key_salt_base64)
        .map_err(|e| RtcError::Internal(format!("Invalid base64 key: {}", e)))
}

fn map_crypto_suite(suite: &str) -> RtcResult<crate::srtp::SrtpProfile> {
    match suite {
        "AES_CM_128_HMAC_SHA1_80" => Ok(crate::srtp::SrtpProfile::Aes128Sha1_80),
        "AES_CM_128_HMAC_SHA1_32" => Ok(crate::srtp::SrtpProfile::Aes128Sha1_32),
        "AEAD_AES_128_GCM" => Ok(crate::srtp::SrtpProfile::AeadAes128Gcm),
        _ => Err(RtcError::Internal(format!(
            "Unsupported crypto suite: {}",
            suite
        ))),
    }
}

impl PeerConnection {
    pub fn new(config: RtcConfiguration) -> Self {
        let (ice_transport, ice_runner) = IceTransport::new(config.clone());
        let certificate =
            Arc::new(dtls::generate_certificate().expect("failed to generate certificate"));
        let dtls_fingerprint = dtls::fingerprint(&certificate);

        let (signaling_state_tx, signaling_state_rx) = watch::channel(SignalingState::Stable);
        let (peer_state_tx, peer_state_rx) = watch::channel(PeerConnectionState::New);
        let (ice_connection_state_tx, ice_connection_state_rx) =
            watch::channel(IceConnectionState::New);
        let (ice_gathering_state_tx, ice_gathering_state_rx) =
            watch::channel(IceGatheringState::New);
        let (dtls_role_tx, dtls_role_rx) = watch::channel(None);

        let ssrc_generator = AtomicU32::new(config.ssrc_start);

        let (event_tx, event_rx) = mpsc::unbounded_channel();

        let inner = PeerConnectionInner {
            config,
            signaling_state: signaling_state_tx,
            _signaling_state_rx: signaling_state_rx,
            peer_state: peer_state_tx,
            _peer_state_rx: peer_state_rx,
            ice_connection_state: ice_connection_state_tx,
            _ice_connection_state_rx: ice_connection_state_rx,
            ice_gathering_state: ice_gathering_state_tx,
            _ice_gathering_state_rx: ice_gathering_state_rx,
            local_description: Mutex::new(None),
            remote_description: Mutex::new(None),
            transceivers: Mutex::new(Vec::new()),
            next_mid: AtomicU16::new(0),
            ice_transport,
            certificate,
            dtls_fingerprint,
            dtls_transport: Mutex::new(None),
            rtp_transport: Mutex::new(None),
            sctp_transport: Mutex::new(None),
            data_channels: Arc::new(Mutex::new(Vec::new())),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            dtls_role: dtls_role_tx,
            _dtls_role_rx: dtls_role_rx.clone(),
            stats_collector: Arc::new(StatsCollector::new()),
            ssrc_generator,
        };
        let pc = Self {
            inner: Arc::new(inner),
        };

        let inner_weak = Arc::downgrade(&pc.inner);
        let ice_transport = pc.inner.ice_transport.clone();
        let dtls_role_rx = dtls_role_rx;
        let ice_connection_state_tx = pc.inner.ice_connection_state.clone();

        let ice_transport_gathering = ice_transport.clone();
        let ice_gathering_state_tx = pc.inner.ice_gathering_state.clone();
        let inner_weak_gathering = inner_weak.clone();
        tokio::spawn(async move {
            let gathering_loop = run_gathering_loop(
                ice_transport_gathering,
                ice_gathering_state_tx,
                inner_weak_gathering,
            );

            let dtls_loop = run_ice_dtls_loop(
                ice_transport,
                ice_connection_state_tx,
                dtls_role_rx,
                inner_weak,
            );

            tokio::join!(gathering_loop, dtls_loop, ice_runner);
        });
        pc
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub fn ice_transport(&self) -> IceTransport {
        self.inner.ice_transport.clone()
    }

    pub fn add_transceiver(
        &self,
        kind: MediaKind,
        direction: TransceiverDirection,
    ) -> Arc<RtpTransceiver> {
        let index = self
            .inner
            .transceivers
            .lock()
            .map(|list| list.len())
            .unwrap_or(0);
        let ssrc = 2000 + index as u32;
        let mut builder = RtpReceiverBuilder::new(kind, ssrc);

        let nack_enabled = if let Some(caps) = &self.inner.config.media_capabilities {
            match kind {
                MediaKind::Audio => caps
                    .audio
                    .iter()
                    .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                MediaKind::Video => caps
                    .video
                    .iter()
                    .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                MediaKind::Application => false,
            }
        } else {
            match kind {
                MediaKind::Audio => AudioCapability::default()
                    .rtcp_fbs
                    .contains(&"nack".to_string()),
                MediaKind::Video => VideoCapability::default()
                    .rtcp_fbs
                    .contains(&"nack".to_string()),
                MediaKind::Application => false,
            }
        };

        if nack_enabled {
            builder = builder.nack();
        }
        let receiver = builder.build();

        let transceiver = Arc::new(RtpTransceiver::new(kind, direction));
        if direction.sends() {
            let rand_val = random_u32();
            let ssrc = self
                .inner
                .ssrc_generator
                .fetch_add(1 + rand_val, Ordering::Relaxed);
            *transceiver.sender_ssrc.lock().unwrap() = Some(ssrc);
            *transceiver.sender_stream_id.lock().unwrap() = Some("default".to_string());
            *transceiver.sender_track_id.lock().unwrap() =
                Some(format!("track-{}", transceiver.id()));
        }
        *transceiver.receiver.lock().unwrap() = Some(receiver);

        let mut list = self.inner.transceivers.lock().unwrap();
        list.push(transceiver.clone());
        transceiver
    }

    pub fn add_track(
        &self,
        track: Arc<dyn MediaStreamTrack>,
        params: RtpCodecParameters,
    ) -> RtcResult<Arc<RtpSender>> {
        let stream_id = format!("{}", track.id());
        self.add_track_with_stream_id(track, stream_id, params)
    }

    pub fn add_track_with_stream_id(
        &self,
        track: Arc<dyn MediaStreamTrack>,
        stream_id: String,
        params: RtpCodecParameters,
    ) -> RtcResult<Arc<RtpSender>> {
        let kind = match track.kind() {
            crate::media::frame::MediaKind::Audio => MediaKind::Audio,
            crate::media::frame::MediaKind::Video => MediaKind::Video,
        };
        let transceiver = self.add_transceiver(kind, TransceiverDirection::SendRecv);
        let ssrc = transceiver
            .sender_ssrc
            .lock()
            .unwrap()
            .unwrap_or_else(|| self.inner.ssrc_generator.fetch_add(1, Ordering::Relaxed));

        let mut builder = RtpSenderBuilder::new(track, ssrc)
            .stream_id(stream_id)
            .params(params);

        let nack_enabled = if let Some(caps) = &self.inner.config.media_capabilities {
            match kind {
                MediaKind::Audio => caps
                    .audio
                    .iter()
                    .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                MediaKind::Video => caps
                    .video
                    .iter()
                    .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                MediaKind::Application => false,
            }
        } else {
            match kind {
                MediaKind::Audio => AudioCapability::default()
                    .rtcp_fbs
                    .contains(&"nack".to_string()),
                MediaKind::Video => VideoCapability::default()
                    .rtcp_fbs
                    .contains(&"nack".to_string()),
                MediaKind::Application => false,
            }
        };

        if nack_enabled {
            builder = builder
                .nack(self.inner.config.nack_buffer_size)
                .bitrate_controller();
        }

        let sender = builder.build();

        // Update transceiver's pre-allocated info to match the actual sender
        *transceiver.sender_ssrc.lock().unwrap() = Some(sender.ssrc());
        *transceiver.sender_stream_id.lock().unwrap() = Some(sender.stream_id().to_string());
        *transceiver.sender_track_id.lock().unwrap() = Some(sender.track_id().to_string());

        // If transport is already established, set it on the sender immediately
        if let Some(transport) = self.inner.rtp_transport.lock().unwrap().as_ref() {
            sender.set_transport(transport.clone());
        }

        transceiver.set_sender(Some(sender.clone()));
        Ok(sender)
    }

    pub fn get_transceivers(&self) -> Vec<Arc<RtpTransceiver>> {
        self.inner.transceivers.lock().unwrap().clone()
    }

    pub async fn create_offer(&self) -> RtcResult<SessionDescription> {
        let state = &self.inner.signaling_state;
        if *state.borrow() != SignalingState::Stable {
            return Err(RtcError::InvalidState(format!(
                "cannot create offer while in state {:?}",
                *state.borrow()
            )));
        }
        let should_set_controlling = {
            let local = self.inner.local_description.lock().unwrap();
            let remote = self.inner.remote_description.lock().unwrap();
            local.is_none() && remote.is_none()
        };

        if should_set_controlling {
            self.inner
                .ice_transport
                .set_role(crate::transports::ice::IceRole::Controlling);
        }
        self.inner
            .build_description(SdpType::Offer, |dir| dir)
            .await
    }

    pub async fn create_answer(&self) -> RtcResult<SessionDescription> {
        let state = &self.inner.signaling_state;
        if *state.borrow() != SignalingState::HaveRemoteOffer {
            return Err(RtcError::InvalidState(
                "create_answer requires remote offer".into(),
            ));
        }
        self.inner
            .ice_transport
            .set_role(crate::transports::ice::IceRole::Controlled);
        self.inner
            .build_description(SdpType::Answer, |dir| dir.answer_direction())
            .await
    }

    pub fn set_local_description(&self, desc: SessionDescription) -> RtcResult<()> {
        self.inner.validate_sdp_type(&desc.sdp_type)?;

        // For Offerer: extract parameters from local offer (our intended changes)
        // This allows Offerer to immediately update transceivers with new parameters
        // that will be confirmed when answer is received
        if desc.sdp_type == SdpType::Offer {
            let is_reinvite = {
                let local = self.inner.local_description.lock().unwrap();
                local.is_some()
            };
            if is_reinvite {
                debug!("Offerer: extracting parameters from local reinvite offer");
                // Extract parameters from our offer for transceivers
                let transceivers = self.inner.transceivers.lock().unwrap().clone();
                for section in &desc.media_sections {
                    let mut matched_transceiver = transceivers
                        .iter()
                        .find(|t| t.mid().as_ref() == Some(&section.mid))
                        .map(|t| t.clone());

                    // If not found by MID, try to match with mid-less transceiver (e.g. manual SDP)
                    if matched_transceiver.is_none() {
                        if let Some(t) = transceivers
                            .iter()
                            .find(|t| t.mid().is_none() && t.kind() == section.kind)
                        {
                            t.set_mid(section.mid.clone());
                            matched_transceiver = Some(t.clone());
                        }
                    }

                    if let Some(t) = matched_transceiver {
                        let payload_map = Self::extract_payload_map(section);
                        if !payload_map.is_empty() {
                            let _ = t.update_payload_map(payload_map);
                        }
                        let extmap = Self::extract_extmap(section);
                        let _ = t.update_extmap(extmap);
                    }
                }
            } else {
                // Initial offer: ensure MIDs are assigned if we match unassigned transceivers
                // This covers manual SDP creation (skipped create_offer)
                let transceivers = self.inner.transceivers.lock().unwrap().clone();
                for section in &desc.media_sections {
                    if transceivers
                        .iter()
                        .any(|t| t.mid().as_ref() == Some(&section.mid))
                    {
                        continue;
                    }
                    // Assign to first matching unassigned transceiver
                    if let Some(t) = transceivers
                        .iter()
                        .find(|t| t.mid().is_none() && t.kind() == section.kind)
                    {
                        t.set_mid(section.mid.clone());
                    }
                }
            }
        }

        {
            let state = &self.inner.signaling_state;
            match desc.sdp_type {
                SdpType::Offer => {
                    if *state.borrow() != SignalingState::Stable {
                        return Err(RtcError::InvalidState(
                            "set_local_description(offer) requires stable signaling state".into(),
                        ));
                    }
                    let _ = state.send(SignalingState::HaveLocalOffer);
                }
                SdpType::Answer => {
                    if *state.borrow() != SignalingState::HaveRemoteOffer {
                        return Err(RtcError::InvalidState(
                            "set_local_description(answer) requires remote offer".into(),
                        ));
                    }
                    let _ = state.send(SignalingState::Stable);
                }
                SdpType::Rollback | SdpType::Pranswer => {
                    return Err(RtcError::NotImplemented("pranswer/rollback"));
                }
            }
        }
        let mut local = self.inner.local_description.lock().unwrap();
        *local = Some(desc);
        Ok(())
    }

    pub async fn set_remote_description(&self, desc: SessionDescription) -> RtcResult<()> {
        self.inner.validate_sdp_type(&desc.sdp_type)?;

        // Check if this is a reinvite (not first negotiation)
        let is_reinvite = {
            let remote = self.inner.remote_description.lock().unwrap();
            remote.is_some()
        };

        if is_reinvite {
            // Apply reinvite at correct timing based on role
            let current_state = *self.inner.signaling_state.borrow();
            match (desc.sdp_type, current_state) {
                // Answerer receiving offer: apply immediately
                (SdpType::Offer, SignalingState::Stable) => {
                    debug!("Answerer: applying reinvite from offer");
                    self.handle_reinvite(&desc).await?;
                }
                // Offerer receiving answer: apply now (was pending since we sent offer)
                (SdpType::Answer, SignalingState::HaveLocalOffer) => {
                    debug!("Offerer: applying reinvite from answer");
                    self.handle_reinvite(&desc).await?;
                }
                // Invalid states for reinvite
                (SdpType::Offer, _) => {
                    return Err(RtcError::InvalidState(
                        "Cannot handle reinvite offer in non-stable state (glare?)".into(),
                    ));
                }
                _ => {}
            }
        }

        // Update next_mid to avoid collisions with remote MIDs
        for section in &desc.media_sections {
            if let Ok(mid_val) = section.mid.parse::<u16>() {
                self.inner.next_mid.fetch_max(mid_val + 1, Ordering::SeqCst);
            }
        }

        {
            let state = &self.inner.signaling_state;
            match desc.sdp_type {
                SdpType::Offer => {
                    if *state.borrow() != SignalingState::Stable {
                        return Err(RtcError::InvalidState(
                            "set_remote_description(offer) requires stable signaling state".into(),
                        ));
                    }
                    let _ = state.send(SignalingState::HaveRemoteOffer);
                }
                SdpType::Answer => {
                    if *state.borrow() != SignalingState::HaveLocalOffer {
                        return Err(RtcError::InvalidState(
                            "set_remote_description(answer) requires local offer".into(),
                        ));
                    }
                    let _ = state.send(SignalingState::Stable);
                }
                SdpType::Rollback | SdpType::Pranswer => {
                    return Err(RtcError::NotImplemented("pranswer/rollback"));
                }
            }
        }

        {
            let current_role = *self.inner.dtls_role.borrow();
            if current_role.is_none() {
                let mut new_role = None;
                if self.config().transport_mode == TransportMode::Rtp
                    || self.config().transport_mode == TransportMode::Srtp
                {
                    new_role = Some(true);
                } else {
                    for section in &desc.media_sections {
                        for attr in &section.attributes {
                            if attr.key == "setup"
                                && let Some(val) = &attr.value
                            {
                                let is_client = match val.as_str() {
                                    "active" => false,
                                    "passive" => true,
                                    "actpass" => false,
                                    _ => true,
                                };
                                new_role = Some(is_client);
                                break;
                            }
                        }
                        if new_role.is_some() {
                            break;
                        }
                    }
                }
                if let Some(r) = new_role {
                    let _ = self.inner.dtls_role.send(Some(r));
                }
            }
        }

        // Start ICE
        let mut ufrag = None;
        let mut pwd = None;
        let mut candidates = Vec::new();
        let mut remote_addr = None;

        // Check session-level attributes for ICE credentials
        for attr in &desc.session.attributes {
            if attr.key == "ice-ufrag" {
                ufrag = attr.value.clone();
            } else if attr.key == "ice-pwd" {
                pwd = attr.value.clone();
            }
        }

        for section in &desc.media_sections {
            if self.config().transport_mode != TransportMode::WebRtc {
                let conn_opt = section
                    .connection
                    .as_ref()
                    .or(desc.session.connection.as_ref());
                if let Some(conn) = conn_opt {
                    let parts: Vec<&str> = conn.split_whitespace().collect();
                    if parts.len() >= 3
                        && parts[0] == "IN"
                        && parts[1] == "IP4"
                        && let Ok(ip) = parts[2].parse::<std::net::IpAddr>()
                    {
                        remote_addr = Some(std::net::SocketAddr::new(ip, section.port));
                    }
                }
            }

            for attr in &section.attributes {
                if attr.key == "ice-ufrag" {
                    ufrag = attr.value.clone();
                } else if attr.key == "ice-pwd" {
                    pwd = attr.value.clone();
                } else if attr.key == "candidate"
                    && let Some(val) = &attr.value
                    && let Ok(c) = crate::transports::ice::IceCandidate::from_sdp(val)
                {
                    candidates.push(c);
                }
            }
        }

        if self.config().transport_mode == TransportMode::WebRtc {
            if let (Some(u), Some(p)) = (ufrag, pwd) {
                let params = crate::transports::ice::IceParameters {
                    username_fragment: u,
                    password: p,
                    ice_lite: false,
                    tie_breaker: 0,
                };
                self.inner
                    .ice_transport
                    .start(params)
                    .map_err(|e| crate::RtcError::Internal(format!("ICE error: {}", e)))?;

                for candidate in candidates {
                    self.inner.ice_transport.add_remote_candidate(candidate);
                }
            }
        } else if let Some(addr) = remote_addr {
            self.inner
                .ice_transport
                .start_direct(addr)
                .await
                .map_err(|e| crate::RtcError::Internal(format!("ICE direct error: {}", e)))?;
        }

        // Create transceivers for new media sections in Offer
        if desc.sdp_type == SdpType::Offer {
            let mut transceivers = self.inner.transceivers.lock().unwrap();
            for section in &desc.media_sections {
                let mid = &section.mid;
                let mut found_transceiver = None;
                let mut newly_matched = false;

                for t in transceivers.iter() {
                    if let Some(t_mid) = t.mid()
                        && t_mid == *mid
                    {
                        found_transceiver = Some(t.clone());
                        break;
                    }
                }

                if found_transceiver.is_none() {
                    // Try to find a transceiver with no MID and same kind
                    for t in transceivers.iter() {
                        if t.mid().is_none() && t.kind() == section.kind {
                            t.set_mid(mid.clone());
                            found_transceiver = Some(t.clone());
                            newly_matched = true;
                            break;
                        }
                    }
                }

                let mut ssrc = None;
                let mut simulcast = None;
                let mut rids = Vec::new();
                let mut rid_ext_id = None;
                let mut abs_send_time_ext_id = None;
                let mut fid_group = None;
                let mut rtx_ssrc = None;

                // First pass: check for ssrc-group FID
                for attr in &section.attributes {
                    if attr.key == "ssrc-group"
                        && let Some(val) = &attr.value
                        && val.starts_with("FID")
                    {
                        // Format: FID <primary> <rtx>
                        let parts: Vec<&str> = val.split_whitespace().collect();
                        if parts.len() >= 3 {
                            if let Ok(primary) = parts[1].parse::<u32>() {
                                fid_group = Some(primary);
                                if let Ok(rtx) = parts[2].parse::<u32>() {
                                    rtx_ssrc = Some(rtx);
                                }
                            }
                        }
                    }
                }

                for attr in &section.attributes {
                    if attr.key == "ssrc" {
                        if let Some(val) = &attr.value
                            && let Some(ssrc_str) = val.split_whitespace().next()
                            && let Ok(parsed) = ssrc_str.parse::<u32>()
                        {
                            // If we found a FID group, only accept the primary SSRC
                            if let Some(primary) = fid_group {
                                if parsed == primary {
                                    ssrc = Some(parsed);
                                }
                            } else if ssrc.is_none() {
                                // No FID group, take the first one
                                ssrc = Some(parsed);
                            }
                        }
                    } else if attr.key == "simulcast"
                        && let Some(val) = &attr.value
                    {
                        simulcast = crate::sdp::Simulcast::parse(val);
                    } else if attr.key == "rid"
                        && let Some(val) = &attr.value
                    {
                        if let Some(rid) = crate::sdp::Rid::parse(val) {
                            rids.push(rid);
                        }
                    } else if attr.key == "extmap"
                        && let Some(val) = &attr.value
                    {
                        if val.contains("urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id") {
                            if let Some(id_str) = val.split_whitespace().next() {
                                if let Ok(id) = id_str.parse::<u8>() {
                                    rid_ext_id = Some(id);
                                }
                            }
                        } else if val.contains(crate::sdp::ABS_SEND_TIME_URI) {
                            if let Some(id_str) = val.split_whitespace().next() {
                                if let Ok(id) = id_str.parse::<u8>() {
                                    abs_send_time_ext_id = Some(id);
                                }
                            }
                        }
                    }
                }

                if let Some(id) = rid_ext_id {
                    if let Some(transport) = self.inner.rtp_transport.lock().unwrap().as_ref() {
                        transport.set_rid_extension_id(Some(id));
                    }
                }

                if let Some(id) = abs_send_time_ext_id {
                    if let Some(transport) = self.inner.rtp_transport.lock().unwrap().as_ref() {
                        transport.set_abs_send_time_extension_id(Some(id));
                    }
                }

                if let Some(t) = found_transceiver {
                    // Update transceiver parameters
                    let payload_map = Self::extract_payload_map(section);
                    if !payload_map.is_empty() {
                        let _ = t.update_payload_map(payload_map);
                    }
                    let extmap = Self::extract_extmap(section);
                    let _ = t.update_extmap(extmap);
                    let direction: TransceiverDirection = section.direction.into();
                    t.set_direction(direction);

                    if let Some(ssrc_val) = ssrc {
                        if let Some(rx) = t.receiver.lock().unwrap().as_ref() {
                            rx.set_ssrc(ssrc_val);
                            if let Some(rtx) = rtx_ssrc {
                                rx.set_rtx_ssrc(rtx);
                            }

                            // Handle Simulcast
                            if let Some(sim) = &simulcast {
                                // For Offer, we look at 'send' direction (remote sends to us)
                                for rid_id in &sim.send {
                                    let _ = rx.add_simulcast_track(rid_id.clone());
                                }
                            }
                        }
                    }

                    if newly_matched {
                        let _ = self.inner.event_tx.send(PeerConnectionEvent::Track(t));
                    }
                } else {
                    let kind = section.kind;
                    let direction = if kind == MediaKind::Application {
                        TransceiverDirection::SendRecv
                    } else {
                        TransceiverDirection::RecvOnly
                    };
                    let t = Arc::new(RtpTransceiver::new(kind, direction));
                    t.set_mid(mid.clone());

                    let receiver_ssrc = ssrc.unwrap_or_else(|| 2000 + transceivers.len() as u32);

                    let mut builder = RtpReceiverBuilder::new(kind, receiver_ssrc);

                    let nack_enabled = if let Some(caps) = &self.inner.config.media_capabilities {
                        match kind {
                            MediaKind::Audio => caps
                                .audio
                                .iter()
                                .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                            MediaKind::Video => caps
                                .video
                                .iter()
                                .any(|c| c.rtcp_fbs.contains(&"nack".to_string())),
                            _ => false,
                        }
                    } else {
                        match kind {
                            MediaKind::Audio => AudioCapability::default()
                                .rtcp_fbs
                                .contains(&"nack".to_string()),
                            MediaKind::Video => VideoCapability::default()
                                .rtcp_fbs
                                .contains(&"nack".to_string()),
                            _ => false,
                        }
                    };

                    if nack_enabled {
                        debug!("NACK: enabled for new receiver mid={}", mid);
                        builder = builder.nack();
                    } else {
                        debug!("NACK: disabled for new receiver mid={}", mid);
                    }
                    let receiver = builder.build();
                    if let Some(rtx) = rtx_ssrc {
                        receiver.set_rtx_ssrc(rtx);
                    }

                    // If transport is already active (renegotiation), attach it to the new receiver
                    {
                        let transport_guard = self.inner.rtp_transport.lock().unwrap();
                        if let Some(transport) = &*transport_guard {
                            receiver.set_transport(transport.clone());
                        } else {
                            debug!(
                                "No existing transport to attach to new receiver mid={}",
                                mid
                            );
                        }
                    }

                    // Handle Simulcast for new transceiver
                    if let Some(sim) = &simulcast {
                        for rid_id in &sim.send {
                            let _ = receiver.add_simulcast_track(rid_id.clone());
                        }
                    }

                    *t.receiver.lock().unwrap() = Some(receiver);

                    transceivers.push(t.clone());
                    let _ = self.inner.event_tx.send(PeerConnectionEvent::Track(t));
                }
            }
        } else if desc.sdp_type == SdpType::Answer {
            let transceivers = self.inner.transceivers.lock().unwrap();
            for section in &desc.media_sections {
                let mid = &section.mid;
                let mut found_transceiver = None;
                for t in transceivers.iter() {
                    if let Some(t_mid) = t.mid()
                        && t_mid == *mid
                    {
                        found_transceiver = Some(t);
                        break;
                    }
                }

                if let Some(t) = found_transceiver {
                    // Update transceiver parameters
                    let payload_map = Self::extract_payload_map(section);
                    if !payload_map.is_empty() {
                        let _ = t.update_payload_map(payload_map);
                    }
                    let extmap = Self::extract_extmap(section);
                    let _ = t.update_extmap(extmap);
                    let direction: TransceiverDirection = section.direction.into();
                    t.set_direction(direction);

                    let mut ssrc = None;
                    for attr in &section.attributes {
                        if attr.key == "ssrc"
                            && ssrc.is_none()
                            && let Some(val) = &attr.value
                            && let Some(ssrc_str) = val.split_whitespace().next()
                            && let Ok(parsed) = ssrc_str.parse::<u32>()
                        {
                            ssrc = Some(parsed);
                            break;
                        }
                    }

                    if let Some(ssrc_val) = ssrc
                        && let Some(rx) = t.receiver.lock().unwrap().as_ref()
                    {
                        rx.set_ssrc(ssrc_val);
                    }
                }
            }
        }

        let mut remote = self.inner.remote_description.lock().unwrap();
        *remote = Some(desc);

        Ok(())
    }

    pub(crate) async fn start_dtls(
        &self,
        is_client: bool,
    ) -> RtcResult<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
        debug!("start_dtls: starting with is_client={}", is_client);
        let pair = self
            .inner
            .ice_transport
            .get_selected_pair()
            .await
            .ok_or(RtcError::Internal("No selected pair".into()))?;

        let socket_rx = self.inner.ice_transport.subscribe_selected_socket();

        // Create IceConn and register it immediately to avoid dropping packets
        let ice_conn = IceConn::new(socket_rx.clone(), pair.remote.address);

        // Monitor selected pair changes to update remote address
        let mut pair_rx = self.inner.ice_transport.subscribe_selected_pair();
        let ice_conn_monitor = ice_conn.clone();

        if self.config().transport_mode != TransportMode::WebRtc {
            let rtcp_addr = {
                let remote_desc = self.inner.remote_description.lock().unwrap();
                if let Some(desc) = &*remote_desc {
                    // Check if rtcp-mux is enabled in the first media section
                    // If not, set rtcp_addr = remote_addr port + 1
                    // Note: This assumes all media sections follow the same mux policy or we only care about the first one for now.
                    // In a proper implementation, we might need per-transceiver transport or bundle handling.
                    if let Some(section) = desc.media_sections.first() {
                        let has_mux = section.attributes.iter().any(|a| a.key == "rtcp-mux");
                        if !has_mux {
                            let mut addr = pair.remote.address;
                            addr.set_port(addr.port() + 1);
                            Some(addr)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            if let Some(addr) = rtcp_addr {
                ice_conn.set_remote_rtcp_addr(Some(addr));
                debug!("RTCP-MUX not detected, setting RTCP address to {}", addr);
            }
        }

        let srtp_required = self.config().transport_mode != TransportMode::Rtp;
        let rtp_transport = Arc::new(RtpTransport::new(ice_conn.clone(), srtp_required));
        {
            let mut rx = ice_conn.rtp_receiver.write().unwrap();
            *rx = Some(Arc::downgrade(&rtp_transport)
                as std::sync::Weak<dyn crate::transports::PacketReceiver>);
        }
        *self.inner.rtp_transport.lock().unwrap() = Some(rtp_transport.clone());

        {
            let transceivers = self.inner.transceivers.lock().unwrap();
            for t in transceivers.iter() {
                // Store transport reference for late senders
                t.set_rtp_transport(Arc::downgrade(&rtp_transport));

                let receiver_arc = t.receiver.lock().unwrap().clone();
                if let Some(receiver) = &receiver_arc {
                    receiver.set_transport(rtp_transport.clone());
                }
            }
        }

        self.inner
            .ice_transport
            .set_data_receiver(ice_conn.clone())
            .await;

        if self.config().transport_mode == TransportMode::Srtp {
            self.setup_sdes(&rtp_transport)?;
            let rtcp_loop = Self::create_rtcp_loop(
                rtp_transport.clone(),
                Arc::downgrade(&self.inner),
                self.inner.stats_collector.clone(),
            );
            let pair_monitor = Self::create_pair_monitor(pair_rx.clone(), ice_conn_monitor.clone());
            let combined_loop = async move {
                tokio::select! {
                    _ = rtcp_loop => {},
                    _ = pair_monitor => {},
                }
            };
            return Ok(Box::pin(combined_loop) as Pin<Box<dyn Future<Output = ()> + Send>>);
        }

        if self.config().transport_mode == TransportMode::Rtp {
            let rtcp_loop = Self::create_rtcp_loop(
                rtp_transport.clone(),
                Arc::downgrade(&self.inner),
                self.inner.stats_collector.clone(),
            );

            let transceivers = self.inner.transceivers.lock().unwrap();
            for t in transceivers.iter() {
                let sender_arc = t.sender.lock().unwrap().clone();
                let receiver_arc = t.receiver.lock().unwrap().clone();

                // Set sender transport
                if let Some(sender) = &sender_arc {
                    let mid_opt = t.mid();
                    trace!(
                        "start_dtls: transceiver kind={:?} mid={:?}",
                        t.kind(),
                        mid_opt
                    );
                    sender.set_transport(rtp_transport.clone());
                }

                // Set feedback SSRC (receiver transport already set above)
                if let Some(receiver) = &receiver_arc {
                    if let Some(sender) = &sender_arc {
                        receiver.set_feedback_ssrc(sender.ssrc());
                    }
                }
            }
            let pair_monitor = Self::create_pair_monitor(pair_rx.clone(), ice_conn_monitor.clone());
            let combined_loop = async move {
                tokio::select! {
                    _ = rtcp_loop => {},
                    _ = pair_monitor => {},
                }
            };
            return Ok(Box::pin(combined_loop) as Pin<Box<dyn Future<Output = ()> + Send>>);
        }

        let (dtls, incoming_data_rx, dtls_runner) = DtlsTransport::new(
            ice_conn,
            self.inner.certificate.as_ref().clone(),
            is_client,
            self.config().dtls_buffer_size,
        )
        .await
        .map_err(|e| RtcError::Internal(format!("DTLS failed: {}", e)))?;

        let sctp_port = if let Some(caps) = &self.config().media_capabilities {
            if let Some(app) = &caps.application {
                app.sctp_port
            } else {
                5000
            }
        } else {
            5000
        };

        let (dc_tx, mut dc_rx) = mpsc::unbounded_channel();

        let (sctp, sctp_runner) = SctpTransport::new(
            dtls.clone(),
            incoming_data_rx,
            self.inner.data_channels.clone(),
            sctp_port,
            sctp_port,
            Some(dc_tx),
            is_client,
            self.config(),
        );
        *self.inner.sctp_transport.lock().unwrap() = Some(sctp);

        *self.inner.dtls_transport.lock().unwrap() = Some(dtls.clone());

        let dtls_clone = dtls.clone();
        let rtp_transport_clone = rtp_transport.clone();
        let inner_weak = Arc::downgrade(&self.inner);
        let stats_collector = self.inner.stats_collector.clone();

        let mut dtls_runner: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(dtls_runner);
        let mut sctp_runner: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(sctp_runner);

        let inner_weak_dc = inner_weak.clone();
        let dc_listener = async move {
            while let Some(dc) = dc_rx.recv().await {
                if let Some(inner) = inner_weak_dc.upgrade() {
                    let _ = inner.event_tx.send(PeerConnectionEvent::DataChannel(dc));
                } else {
                    break;
                }
            }
        };
        let mut dc_listener: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(dc_listener);

        let mut state_rx = dtls_clone.subscribe_state();
        loop {
            let state = state_rx.borrow().clone();
            match state {
                crate::transports::dtls::DtlsState::Connected(_, profile_opt) => {
                    self.setup_srtp(&dtls_clone, is_client, profile_opt, &rtp_transport_clone);

                    let rtcp_loop = Self::create_rtcp_loop(
                        rtp_transport_clone.clone(),
                        inner_weak.clone(),
                        stats_collector.clone(),
                    );

                    let pair_monitor =
                        Self::create_pair_monitor(pair_rx.clone(), ice_conn_monitor.clone());

                    let combined: Pin<Box<dyn Future<Output = ()> + Send>> = Box::pin(async move {
                        tokio::select! {
                            _ = rtcp_loop => {},
                            _ = dtls_runner => {},
                            _ = sctp_runner => {},
                            _ = dc_listener => {},
                            _ = pair_monitor => {},
                        }
                    });
                    return Ok(combined);
                }
                crate::transports::dtls::DtlsState::Failed => {
                    return Err(RtcError::Internal("DTLS handshake failed".into()));
                }
                _ => {}
            }

            tokio::select! {
                _ = &mut dtls_runner => {
                     return Err(RtcError::Internal("DTLS runner stopped unexpectedly".into()));
                }
                _ = &mut sctp_runner => {
                     return Err(RtcError::Internal("SCTP runner stopped unexpectedly".into()));
                }
                _ = &mut dc_listener => {
                     warn!("DataChannel listener stopped unexpectedly");
                     return Err(RtcError::Internal("DataChannel listener stopped unexpectedly".into()));
                }
                res = state_rx.changed() => {
                    if res.is_err() { break; }
                }
                res = pair_rx.changed() => {
                    if res.is_ok() {
                        if let Some(pair) = pair_rx.borrow().clone() {
                            if let Ok(mut addr) = ice_conn_monitor.remote_addr.write() {
                                *addr = pair.remote.address;
                            }
                        }
                    }
                }
            }
        }

        Ok(Box::pin(async {}) as Pin<Box<dyn Future<Output = ()> + Send>>)
    }

    fn setup_sdes(&self, rtp_transport: &Arc<RtpTransport>) -> RtcResult<()> {
        let (tx_keying, rx_keying, profile) = {
            let remote_desc = self.inner.remote_description.lock().unwrap();
            let local_desc = self.inner.local_description.lock().unwrap();

            let remote_crypto = remote_desc
                .as_ref()
                .and_then(|d| d.media_sections.first())
                .and_then(|m| m.get_crypto_attributes().into_iter().next());

            let local_crypto = local_desc
                .as_ref()
                .and_then(|d| d.media_sections.first())
                .and_then(|m| m.get_crypto_attributes().into_iter().next());

            if let (Some(remote), Some(local)) = (remote_crypto, local_crypto) {
                let profile = map_crypto_suite(&remote.crypto_suite)?;
                if profile != map_crypto_suite(&local.crypto_suite)? {
                    return Err(RtcError::Internal("Crypto suite mismatch".into()));
                }

                let rx_key_salt = parse_sdes_key_params(&remote.key_params)?;
                let tx_key_salt = parse_sdes_key_params(&local.key_params)?;

                let (key_len, salt_len) = match profile {
                    crate::srtp::SrtpProfile::Aes128Sha1_80
                    | crate::srtp::SrtpProfile::Aes128Sha1_32 => (16, 14),
                    crate::srtp::SrtpProfile::AeadAes128Gcm => (16, 12),
                    _ => (16, 14),
                };

                if rx_key_salt.len() < key_len + salt_len || tx_key_salt.len() < key_len + salt_len
                {
                    return Err(RtcError::Internal("Invalid key length".into()));
                }

                let rx_keying = crate::srtp::SrtpKeyingMaterial::new(
                    rx_key_salt[..key_len].to_vec(),
                    rx_key_salt[key_len..key_len + salt_len].to_vec(),
                );
                let tx_keying = crate::srtp::SrtpKeyingMaterial::new(
                    tx_key_salt[..key_len].to_vec(),
                    tx_key_salt[key_len..key_len + salt_len].to_vec(),
                );

                (tx_keying, rx_keying, profile)
            } else {
                return Err(RtcError::Internal(
                    "Missing crypto attributes for SDES".into(),
                ));
            }
        };

        let session = crate::srtp::SrtpSession::new(profile, tx_keying, rx_keying)
            .map_err(|e| RtcError::Internal(format!("SRTP error: {}", e)))?;

        rtp_transport.start_srtp(session);

        let transceivers = self.inner.transceivers.lock().unwrap();
        for t in transceivers.iter() {
            let sender_arc = t.sender.lock().unwrap().clone();
            let receiver_arc = t.receiver.lock().unwrap().clone();

            if let Some(sender) = &sender_arc {
                sender.set_transport(rtp_transport.clone());
            }

            if let Some(receiver) = &receiver_arc {
                receiver.set_transport(rtp_transport.clone());
                if let Some(sender) = &sender_arc {
                    receiver.set_feedback_ssrc(sender.ssrc());
                }
            }
        }

        *self.inner.rtp_transport.lock().unwrap() = Some(rtp_transport.clone());
        Ok(())
    }

    fn setup_srtp(
        &self,
        dtls: &DtlsTransport,
        is_client: bool,
        profile_opt: Option<u16>,
        rtp_transport: &Arc<RtpTransport>,
    ) {
        // Default to Aes128Sha1_80 if not specified or unknown
        let profile = match profile_opt {
            Some(0x0001) => crate::srtp::SrtpProfile::Aes128Sha1_80,
            Some(0x0002) => crate::srtp::SrtpProfile::Aes128Sha1_32,
            Some(0x0007) => crate::srtp::SrtpProfile::AeadAes128Gcm,
            _ => crate::srtp::SrtpProfile::Aes128Sha1_80,
        };

        let key_len = match profile {
            crate::srtp::SrtpProfile::AeadAes128Gcm => 16,
            _ => 16,
        };
        let salt_len = match profile {
            crate::srtp::SrtpProfile::AeadAes128Gcm => 12,
            _ => 14,
        };

        let total_len = 2 * (key_len + salt_len);

        if let Ok(mat) = dtls.export_keying_material("EXTRACTOR-dtls_srtp", total_len) {
            let client_key = &mat[0..key_len];
            let server_key = &mat[key_len..2 * key_len];
            let client_salt = &mat[2 * key_len..2 * key_len + salt_len];
            let server_salt = &mat[2 * key_len + salt_len..];

            let (tx_key, tx_salt, rx_key, rx_salt) = if is_client {
                (client_key, client_salt, server_key, server_salt)
            } else {
                (server_key, server_salt, client_key, client_salt)
            };

            let tx_keying = crate::srtp::SrtpKeyingMaterial::new(tx_key.to_vec(), tx_salt.to_vec());
            let rx_keying = crate::srtp::SrtpKeyingMaterial::new(rx_key.to_vec(), rx_salt.to_vec());

            match crate::srtp::SrtpSession::new(profile, tx_keying, rx_keying) {
                Ok(session) => {
                    rtp_transport.start_srtp(session);

                    let transceivers = self.inner.transceivers.lock().unwrap();
                    for t in transceivers.iter() {
                        let sender_arc = t.sender.lock().unwrap().clone();
                        let receiver_arc = t.receiver.lock().unwrap().clone();

                        if let Some(sender) = &sender_arc {
                            let mid_opt = t.mid();
                            trace!(
                                "start_dtls: transceiver kind={:?} mid={:?}",
                                t.kind(),
                                mid_opt
                            );
                            sender.set_transport(rtp_transport.clone());
                        }

                        if let Some(receiver) = &receiver_arc {
                            receiver.set_transport(rtp_transport.clone());
                            if let Some(sender) = &sender_arc {
                                receiver.set_feedback_ssrc(sender.ssrc());
                            }
                        }
                    }

                    // Update the inner transport to ensure future transceivers get the correct one
                    *self.inner.rtp_transport.lock().unwrap() = Some(rtp_transport.clone());
                }
                Err(e) => {
                    warn!("Failed to create SRTP session: {}", e);
                }
            }
        } else {
            warn!(
                "Failed to export keying material - DTLS state: {}",
                dtls.get_state()
            );
        }
    }

    fn create_rtcp_loop(
        rtp_transport: Arc<RtpTransport>,
        inner_weak: Weak<PeerConnectionInner>,
        stats_collector: Arc<StatsCollector>,
    ) -> impl Future<Output = ()> + Send {
        let (rtcp_tx, mut rtcp_rx) = mpsc::channel(2000);
        rtp_transport.register_rtcp_listener(rtcp_tx);

        async move {
            while let Some(packets) = rtcp_rx.recv().await {
                for packet in packets {
                    // Log every RTCP packet to debug
                    match &packet {
                        RtcpPacket::PictureLossIndication(_) => {}
                        RtcpPacket::GenericNack(n) => {
                            trace!("RTCP Loop: Got NACK for SSRC {}", n.media_ssrc)
                        }
                        RtcpPacket::ReceiverReport(rr) => trace!(
                            "RTCP Loop: Got RR for SSRC count {}",
                            rr.report_blocks.len()
                        ),
                        RtcpPacket::SenderReport(sr) => {
                            trace!("RTCP Loop: Got SR for SSRC {}", sr.sender_ssrc)
                        }
                        _ => trace!("RTCP Loop: Got packet {:?}", packet),
                    }

                    stats_collector.process_rtcp(&packet);
                    let Some(inner) = inner_weak.upgrade() else {
                        return;
                    };
                    {
                        let transceivers = inner.transceivers.lock().unwrap();
                        for t in transceivers.iter() {
                            if let Some(sender) = &*t.sender.lock().unwrap() {
                                let is_for_sender = match &packet {
                                    RtcpPacket::PictureLossIndication(p) => {
                                        if p.media_ssrc == sender.ssrc() {
                                            debug!("Received PLI for SSRC: {}", p.media_ssrc);
                                            true
                                        } else {
                                            false
                                        }
                                    }
                                    RtcpPacket::GenericNack(n) => n.media_ssrc == sender.ssrc(),
                                    _ => false,
                                };

                                if is_for_sender {
                                    sender.deliver_rtcp(packet.clone());
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    fn create_pair_monitor(
        mut pair_rx: watch::Receiver<Option<crate::transports::ice::IceCandidatePair>>,
        ice_conn_monitor: Arc<IceConn>,
    ) -> impl Future<Output = ()> + Send {
        async move {
            if let Some(pair) = pair_rx.borrow().clone() {
                if let Ok(mut addr) = ice_conn_monitor.remote_addr.write() {
                    trace!(
                        "PeerConnection: pair_monitor initial update: {} -> {}",
                        *addr, pair.remote.address
                    );
                    *addr = pair.remote.address;
                }
            }
            while pair_rx.changed().await.is_ok() {
                if let Some(pair) = pair_rx.borrow().clone() {
                    let old_addr = if let Ok(addr) = ice_conn_monitor.remote_addr.read() {
                        *addr
                    } else {
                        "0.0.0.0:0".parse().unwrap()
                    };
                    if let Ok(mut addr_guard) = ice_conn_monitor.remote_addr.write() {
                        trace!(
                            "PeerConnection: pair_monitor update: {} -> {}",
                            old_addr, pair.remote.address
                        );
                        *addr_guard = pair.remote.address;
                    }
                }
            }
        }
    }

    pub fn signaling_state(&self) -> SignalingState {
        *self.inner.signaling_state.borrow()
    }

    pub fn subscribe_signaling_state(&self) -> watch::Receiver<SignalingState> {
        self.inner.signaling_state.subscribe()
    }

    pub fn subscribe_peer_state(&self) -> watch::Receiver<PeerConnectionState> {
        self.inner.peer_state.subscribe()
    }

    pub async fn wait_for_connected(&self) -> RtcResult<()> {
        let mut peer_state_rx = self.subscribe_peer_state();
        loop {
            let state = *peer_state_rx.borrow_and_update();
            if state == PeerConnectionState::Connected {
                return Ok(());
            }
            if state == PeerConnectionState::Failed || state == PeerConnectionState::Closed {
                return Err(RtcError::Internal(format!(
                    "Peer connection failed or closed: {:?}",
                    state
                )));
            }
            if peer_state_rx.changed().await.is_err() {
                return Err(RtcError::Internal("Peer state channel closed".into()));
            }
        }
    }

    pub fn subscribe_ice_connection_state(&self) -> watch::Receiver<IceConnectionState> {
        self.inner.ice_connection_state.subscribe()
    }

    pub fn subscribe_ice_gathering_state(&self) -> watch::Receiver<IceGatheringState> {
        self.inner.ice_gathering_state.subscribe()
    }

    pub fn local_description(&self) -> Option<SessionDescription> {
        self.inner.local_description.lock().unwrap().clone()
    }

    pub fn remote_description(&self) -> Option<SessionDescription> {
        self.inner.remote_description.lock().unwrap().clone()
    }

    pub fn close(&self) {
        self.inner.close();
    }

    pub async fn recv(&self) -> Option<PeerConnectionEvent> {
        let mut rx = self.inner.event_rx.lock().await;
        rx.recv().await
    }

    pub fn create_data_channel(
        &self,
        label: &str,
        config: Option<crate::transports::sctp::DataChannelConfig>,
    ) -> RtcResult<Arc<crate::transports::sctp::DataChannel>> {
        // Ensure we have an application transceiver for negotiation
        let has_app_transceiver = {
            let transceivers = self.inner.transceivers.lock().unwrap();
            transceivers
                .iter()
                .any(|t| t.kind() == MediaKind::Application)
        };

        if !has_app_transceiver {
            self.add_transceiver(MediaKind::Application, TransceiverDirection::SendRecv);
        }

        let mut config = config.unwrap_or_default();
        config.label = label.to_string();

        let id = if let Some(negotiated_id) = config.negotiated {
            negotiated_id
        } else {
            let is_client = self.inner.dtls_role.borrow().unwrap_or(true);
            let offset = if is_client { 0 } else { 1 };

            let channels = self.inner.data_channels.lock().unwrap();
            let mut id = offset;
            loop {
                let mut used = false;
                for weak_dc in channels.iter() {
                    if let Some(dc) = weak_dc.upgrade() {
                        if dc.id == id {
                            used = true;
                            break;
                        }
                    }
                }
                if !used {
                    break;
                }
                id += 2;
            }
            id
        };

        let dc = Arc::new(crate::transports::sctp::DataChannel::new(
            id,
            config.clone(),
        ));

        self.inner
            .data_channels
            .lock()
            .unwrap()
            .push(Arc::downgrade(&dc));

        if !dc.negotiated {
            let transport = self.inner.sctp_transport.lock().unwrap().clone();
            if let Some(transport) = transport {
                let dc_clone = dc.clone();
                tokio::spawn(async move {
                    if let Err(e) = transport.send_dcep_open(&dc_clone).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                });
            }
        }

        Ok(dc)
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> RtcResult<()> {
        let transport = self.inner.sctp_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            transport
                .send_data(channel_id, data)
                .await
                .map_err(|e| RtcError::Internal(format!("SCTP send failed: {}", e)))
        } else {
            Err(RtcError::InvalidState("SCTP not connected".into()))
        }
    }

    pub async fn send_text(&self, channel_id: u16, data: impl AsRef<str>) -> RtcResult<()> {
        let transport = self.inner.sctp_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            transport
                .send_text(channel_id, data)
                .await
                .map_err(|e| RtcError::Internal(format!("SCTP send failed: {}", e)))
        } else {
            Err(RtcError::InvalidState("SCTP not connected".into()))
        }
    }

    pub async fn sctp_buffered_amount(&self) -> usize {
        let transport = self.inner.sctp_transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            transport.buffered_amount()
        } else {
            0
        }
    }

    pub async fn get_stats(&self) -> RtcResult<StatsReport> {
        gather_once(&[self.inner.stats_collector.clone()]).await
    }

    pub async fn wait_for_gathering_complete(&self) {
        let _ = self.inner.ice_transport.start_gathering();
        let mut rx = self.subscribe_ice_gathering_state();
        loop {
            if *rx.borrow_and_update() == IceGatheringState::Complete {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    pub fn subscribe_ice_candidates(&self) -> broadcast::Receiver<IceCandidate> {
        self.inner.ice_transport.subscribe_candidates()
    }

    pub fn add_ice_candidate(&self, candidate: IceCandidate) -> RtcResult<()> {
        self.inner.ice_transport.add_remote_candidate(candidate);
        Ok(())
    }

    /// Handle reinvite - update RTP parameters without recreating tracks
    async fn handle_reinvite(&self, new_desc: &SessionDescription) -> RtcResult<()> {
        debug!("Handling reinvite: updating RTP parameters");

        let transceivers = self.inner.transceivers.lock().unwrap().clone();

        // Extract RTP parameter changes for each media section
        for section in &new_desc.media_sections {
            // Find matching transceiver by mid
            let transceiver = transceivers
                .iter()
                .find(|t| t.mid().as_ref() == Some(&section.mid));

            if let Some(t) = transceiver {
                // Check SSRC change (indicates new track, not reinvite)
                if let Some(receiver) = t.receiver() {
                    let new_ssrc = Self::extract_ssrc_from_section(section);
                    if let Some(new_ssrc) = new_ssrc {
                        let old_ssrc = receiver.ssrc();
                        if old_ssrc != new_ssrc {
                            if old_ssrc != 0 {
                                warn!(
                                    "SSRC changed for mid={} ({} -> {}), updating listener",
                                    section.mid, old_ssrc, new_ssrc
                                );
                            } else {
                                debug!(
                                    "SSRC learned for mid={} (-> {}), updating listener",
                                    section.mid, new_ssrc
                                );
                            }
                            receiver.set_ssrc(new_ssrc);
                        }
                    } else {
                        // If no SSRC in SDP, re-enable provisional listener
                        // to handle potential SSRC changes during reinvite
                        receiver.ensure_provisional_listener();
                    }
                }

                // Extract and validate payload type mapping
                let payload_map = Self::extract_payload_map(section);
                if !payload_map.is_empty() {
                    // Basic validation: check if we support these codecs
                    for (pt, params) in &payload_map {
                        trace!("Validating PT {}: clock_rate={}", pt, params.clock_rate);
                        // TODO: Add full codec capability check against local capabilities
                    }
                    t.update_payload_map(payload_map)?;
                }

                // Extract and update extension mapping
                let extmap = Self::extract_extmap(section);
                t.update_extmap(extmap)?;

                // Handle direction changes
                let new_direction: TransceiverDirection = section.direction.into();
                let old_direction = t.direction();
                if new_direction != old_direction {
                    debug!(
                        "Direction changed for mid={}: {:?} -> {:?}",
                        section.mid, old_direction, new_direction
                    );
                    t.set_direction(new_direction);
                    Self::apply_direction_change(t, old_direction, new_direction).await?;
                }
            }
        }

        // Update remote description
        *self.inner.remote_description.lock().unwrap() = Some(new_desc.clone());

        debug!("Reinvite completed successfully");
        Ok(())
    }

    /// Extract payload type to codec parameters mapping from media section
    fn extract_payload_map(section: &crate::MediaSection) -> HashMap<u8, RtpCodecParameters> {
        let mut payload_map = HashMap::new();

        // Parse rtpmap attributes: "96 opus/48000/2"
        for attr in &section.attributes {
            if attr.key == "rtpmap" {
                if let Some(val) = &attr.value {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(pt) = parts[0].parse::<u8>() {
                            // Parse codec/rate/channels
                            let codec_parts: Vec<&str> = parts[1].split('/').collect();
                            if codec_parts.len() >= 2 {
                                let clock_rate = codec_parts[1].parse().unwrap_or(90000);
                                let channels = if codec_parts.len() >= 3 {
                                    codec_parts[2].parse().unwrap_or(0)
                                } else {
                                    0
                                };

                                payload_map.insert(
                                    pt,
                                    RtpCodecParameters {
                                        payload_type: pt,
                                        clock_rate,
                                        channels,
                                    },
                                );
                            }
                        }
                    }
                }
            }
        }

        payload_map
    }

    /// Extract extension header mapping from media section
    fn extract_extmap(section: &crate::MediaSection) -> HashMap<u8, String> {
        let mut extmap = HashMap::new();

        // Parse extmap attributes: "1 urn:ietf:params:rtp-hdrext:ssrc-audio-level"
        for attr in &section.attributes {
            if attr.key == "extmap" {
                if let Some(val) = &attr.value {
                    let parts: Vec<&str> = val.split_whitespace().collect();
                    if parts.len() >= 2 {
                        if let Ok(id) = parts[0].parse::<u8>() {
                            extmap.insert(id, parts[1].to_string());
                        }
                    }
                }
            }
        }

        extmap
    }

    /// Extract SSRC from media section
    fn extract_ssrc_from_section(section: &crate::MediaSection) -> Option<u32> {
        // Parse a=ssrc:<ssrc> <attribute>:<value>
        for attr in &section.attributes {
            if attr.key == "ssrc" {
                if let Some(val) = &attr.value {
                    if let Some(ssrc_str) = val.split_whitespace().next() {
                        if let Ok(ssrc) = ssrc_str.parse::<u32>() {
                            return Some(ssrc);
                        }
                    }
                }
            }
        }
        None
    }

    /// Apply direction change side effects
    async fn apply_direction_change(
        transceiver: &RtpTransceiver,
        old_direction: TransceiverDirection,
        new_direction: TransceiverDirection,
    ) -> RtcResult<()> {
        let old_sends = match old_direction {
            TransceiverDirection::SendRecv | TransceiverDirection::SendOnly => true,
            _ => false,
        };
        let new_sends = match new_direction {
            TransceiverDirection::SendRecv | TransceiverDirection::SendOnly => true,
            _ => false,
        };

        let old_receives = match old_direction {
            TransceiverDirection::SendRecv | TransceiverDirection::RecvOnly => true,
            _ => false,
        };
        let new_receives = match new_direction {
            TransceiverDirection::SendRecv | TransceiverDirection::RecvOnly => true,
            _ => false,
        };

        // Handle send direction changes
        if old_sends != new_sends {
            if new_sends {
                debug!("Transceiver {} starting to send", transceiver.id());
                // Resume sender if available
                if let Some(sender) = transceiver.sender() {
                    // In full implementation: sender.resume()
                    trace!("Sender {} would resume", sender.ssrc());
                }
            } else {
                debug!("Transceiver {} stopping send", transceiver.id());
                // Pause sender if available
                if let Some(sender) = transceiver.sender() {
                    // In full implementation: sender.pause()
                    trace!("Sender {} would pause", sender.ssrc());
                }
            }
        }

        // Handle receive direction changes
        if old_receives != new_receives {
            if new_receives {
                debug!("Transceiver {} starting to receive", transceiver.id());
                // In full implementation: activate receiver
            } else {
                debug!("Transceiver {} stopping receive", transceiver.id());
                // In full implementation: deactivate receiver or discard packets
            }
        }

        Ok(())
    }
}

async fn run_gathering_loop(
    ice_transport: IceTransport,
    ice_gathering_state_tx: watch::Sender<IceGatheringState>,
    inner_weak: std::sync::Weak<PeerConnectionInner>,
) {
    let mut rx = ice_transport.subscribe_gathering_state();
    let mut ice_state_rx = ice_transport.subscribe_state();
    loop {
        let state = *rx.borrow_and_update();
        if state == crate::transports::ice::IceGathererState::Complete {
            if let Some(inner) = inner_weak.upgrade() {
                let update_local_description = || {
                    if inner.config.transport_mode == TransportMode::WebRtc {
                        let candidates = ice_transport.local_candidates();
                        let candidate_strs: Vec<String> =
                            candidates.iter().map(|c| c.to_sdp()).collect();

                        let mut local_guard = inner.local_description.lock().unwrap();
                        if let Some(desc) = local_guard.as_mut() {
                            desc.add_candidates(&candidate_strs);
                        }
                        true
                    } else {
                        let candidates = ice_transport.local_candidates();
                        if let Some(candidate) = candidates.first() {
                            let mut local_guard = inner.local_description.lock().unwrap();
                            if let Some(desc) = local_guard.as_mut() {
                                for media in &mut desc.media_sections {
                                    media.port = candidate.address.port();
                                    let ip_str = candidate.address.ip().to_string();
                                    let ip_ver = if candidate.address.is_ipv4() {
                                        "IP4"
                                    } else {
                                        "IP6"
                                    };
                                    media.connection = Some(format!("IN {} {}", ip_ver, ip_str));
                                }
                            }
                        }
                        true
                    }
                };

                if !update_local_description() {
                    let mut sig_rx = inner.signaling_state.subscribe();
                    loop {
                        if update_local_description() {
                            break;
                        }
                        if sig_rx.changed().await.is_err() {
                            break;
                        }
                    }
                }
            }
        }

        let pc_state = match state {
            crate::transports::ice::IceGathererState::New => IceGatheringState::New,
            crate::transports::ice::IceGathererState::Gathering => IceGatheringState::Gathering,
            crate::transports::ice::IceGathererState::Complete => IceGatheringState::Complete,
        };

        if ice_gathering_state_tx.send(pc_state).is_err() {
            break;
        }
        if state == crate::transports::ice::IceGathererState::Complete {
            break;
        }
        tokio::select! {
            res = rx.changed() => {
                if res.is_err() { break; }
            }
            res = ice_state_rx.changed() => {
                if res.is_err() { break; }
                if *ice_state_rx.borrow() == crate::transports::ice::IceTransportState::Closed {
                    break;
                }
            }
        }
    }
}

async fn run_ice_dtls_loop(
    ice_transport: IceTransport,
    ice_connection_state_tx: watch::Sender<IceConnectionState>,
    mut dtls_role_rx: watch::Receiver<Option<bool>>,
    inner_weak: std::sync::Weak<PeerConnectionInner>,
) {
    let mut ice_state_rx = ice_transport.subscribe_state();
    loop {
        let ice_state = *ice_state_rx.borrow_and_update();

        let pc_ice_state = match ice_state {
            crate::transports::ice::IceTransportState::New => IceConnectionState::New,
            crate::transports::ice::IceTransportState::Checking => IceConnectionState::Checking,
            crate::transports::ice::IceTransportState::Connected => IceConnectionState::Connected,
            crate::transports::ice::IceTransportState::Completed => IceConnectionState::Completed,
            crate::transports::ice::IceTransportState::Failed => IceConnectionState::Failed,
            crate::transports::ice::IceTransportState::Disconnected => {
                IceConnectionState::Disconnected
            }
            crate::transports::ice::IceTransportState::Closed => IceConnectionState::Closed,
        };
        let _ = ice_connection_state_tx.send(pc_ice_state);
        match ice_state {
            crate::transports::ice::IceTransportState::Connected
            | crate::transports::ice::IceTransportState::Completed => {
                // For RTP/SRTP mode, we don't need DTLS role to start
                let transport_mode = if let Some(inner) = inner_weak.upgrade() {
                    inner.config.transport_mode.clone()
                } else {
                    return;
                };

                if transport_mode != TransportMode::WebRtc {
                    if !handle_connected_state_no_dtls(&inner_weak, &mut ice_state_rx).await {
                        return;
                    }
                    continue;
                }

                if !handle_connected_state(
                    &inner_weak,
                    &ice_connection_state_tx,
                    &mut dtls_role_rx,
                    &mut ice_state_rx,
                )
                .await
                {
                    return;
                }
                continue;
            }
            crate::transports::ice::IceTransportState::Failed => {
                if let Some(inner) = inner_weak.upgrade() {
                    let _ = inner.peer_state.send(PeerConnectionState::Failed);
                }
                return;
            }
            crate::transports::ice::IceTransportState::Closed => {
                if let Some(inner) = inner_weak.upgrade() {
                    let _ = inner.peer_state.send(PeerConnectionState::Closed);
                }
                return;
            }
            _ => {}
        }

        if ice_state_rx.changed().await.is_err() {
            return;
        }
    }
}

async fn handle_connected_state_no_dtls(
    inner_weak: &std::sync::Weak<PeerConnectionInner>,
    ice_state_rx: &mut watch::Receiver<crate::transports::ice::IceTransportState>,
) -> bool {
    if let Some(inner) = inner_weak.upgrade() {
        let pc_temp = PeerConnection {
            inner: inner.clone(),
        };
        // For RTP/SRTP, we pass false as is_client, but it doesn't matter as start_dtls handles it
        match pc_temp.start_dtls(false).await {
            Err(e) => {
                warn!("Transport start failed: {}", e);
                let _ = inner.peer_state.send(PeerConnectionState::Failed);
                return false;
            }
            Ok(mut rtcp_loop) => {
                let _ = inner.peer_state.send(PeerConnectionState::Connected);
                loop {
                    tokio::select! {
                        _ = &mut rtcp_loop => {
                            break;
                        }
                        res = ice_state_rx.changed() => {
                            if res.is_err() { return false; }
                            let new_state = *ice_state_rx.borrow();
                            if is_ice_disconnected(new_state) {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    }
    false
}

async fn handle_connected_state(
    inner_weak: &std::sync::Weak<PeerConnectionInner>,
    ice_connection_state_tx: &watch::Sender<IceConnectionState>,
    dtls_role_rx: &mut watch::Receiver<Option<bool>>,
    ice_state_rx: &mut watch::Receiver<crate::transports::ice::IceTransportState>,
) -> bool {
    loop {
        let role = *dtls_role_rx.borrow_and_update();
        if let Some(is_client) = role {
            if let Some(inner) = inner_weak.upgrade() {
                let pc_temp = PeerConnection {
                    inner: inner.clone(),
                };

                match pc_temp.start_dtls(is_client).await {
                    Err(e) => {
                        warn!("DTLS start failed: {}", e);
                        let _ = inner.peer_state.send(PeerConnectionState::Failed);
                        return false;
                    }
                    Ok(mut rtcp_loop) => {
                        let _ = inner.peer_state.send(PeerConnectionState::Connected);

                        let dtls_state_rx = {
                            let dtls_guard = inner.dtls_transport.lock().unwrap();
                            if let Some(dtls) = &*dtls_guard {
                                Some(dtls.subscribe_state())
                            } else {
                                None
                            }
                        };

                        if let Some(mut dtls_rx) = dtls_state_rx {
                            loop {
                                tokio::select! {
                                    _ = &mut rtcp_loop => {
                                        break;
                                    }
                                    res = ice_state_rx.changed() => {
                                        if res.is_err() { return false; }
                                        let new_state = *ice_state_rx.borrow();
                                        if is_ice_disconnected(new_state) {
                                            return true;
                                        }
                                    }
                                    res = dtls_rx.changed() => {
                                        if res.is_ok() {
                                            let state = dtls_rx.borrow().clone();
                                            if state == crate::transports::dtls::DtlsState::Closed || state == crate::transports::dtls::DtlsState::Failed {
                                                debug!("DTLS closed/failed, disconnecting PC");
                                                let _ = inner.peer_state.send(PeerConnectionState::Disconnected);
                                                let _ = ice_connection_state_tx.send(IceConnectionState::Disconnected);
                                                return false;
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        } else {
                            loop {
                                tokio::select! {
                                    _ = &mut rtcp_loop => {
                                        break;
                                    }
                                    res = ice_state_rx.changed() => {
                                        if res.is_err() { return false; }
                                        let new_state = *ice_state_rx.borrow();
                                        if is_ice_disconnected(new_state) {
                                            return true;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            let state = *ice_state_rx.borrow();
            if is_ice_disconnected(state) {
                return true;
            }
            return false;
        }

        tokio::select! {
            res = dtls_role_rx.changed() => {
                if res.is_err() { return false; }
            }
            res = ice_state_rx.changed() => {
                if res.is_err() { return false; }
                let new_state = *ice_state_rx.borrow();
                if is_ice_disconnected(new_state) {
                    return true;
                }
            }
        }
    }
}

fn is_ice_disconnected(state: crate::transports::ice::IceTransportState) -> bool {
    matches!(
        state,
        crate::transports::ice::IceTransportState::Failed
            | crate::transports::ice::IceTransportState::Closed
            | crate::transports::ice::IceTransportState::Disconnected
    )
}

impl PeerConnectionInner {
    async fn build_description<F>(
        &self,
        sdp_type: SdpType,
        map_direction: F,
    ) -> RtcResult<SessionDescription>
    where
        F: Fn(TransceiverDirection) -> TransceiverDirection,
    {
        let transceivers = {
            let list = self.transceivers.lock().unwrap();
            list.iter().cloned().collect::<Vec<_>>()
        };
        if transceivers.is_empty() {
            return Err(RtcError::InvalidState(
                "cannot build SDP with no transceivers".into(),
            ));
        }

        let mut remote_offered_bundle = false;

        let ordered_transceivers = if sdp_type == SdpType::Answer {
            let remote_guard = self.remote_description.lock().unwrap();
            let remote = remote_guard.as_ref().ok_or_else(|| {
                RtcError::InvalidState("create_answer called without remote description".into())
            })?;

            for attr in &remote.session.attributes {
                if attr.key == "group"
                    && let Some(val) = &attr.value
                    && val.starts_with("BUNDLE")
                {
                    remote_offered_bundle = true;
                }
            }

            let mut ordered = Vec::new();
            for section in &remote.media_sections {
                let mid = &section.mid;
                let mut found = None;
                for t in &transceivers {
                    if let Some(t_mid) = t.mid()
                        && t_mid == *mid
                    {
                        found = Some(t.clone());
                        break;
                    }
                }
                if let Some(t) = found {
                    ordered.push(t);
                } else {
                    return Err(RtcError::Internal(format!(
                        "No transceiver found for mid {} in answer generation",
                        mid
                    )));
                }
            }
            ordered
        } else {
            // For Offer, we must ensure MIDs and sort by them to maintain m-line stability
            // This handles cases where transceivers were added out-of-order relative to their
            // assigned MIDs (e.g. reused from previous negotiations)
            for t in &transceivers {
                self.ensure_mid(t);
            }

            let mut ordered = transceivers.clone();
            ordered.sort_by(|a, b| {
                let mid_a = a.mid().unwrap_or_default();
                let mid_b = b.mid().unwrap_or_default();

                // Try to sort numerically if possible ("0", "1", "10")
                // otherwise lexicographically ("0", "1", "a")
                match (mid_a.parse::<u64>(), mid_b.parse::<u64>()) {
                    (Ok(na), Ok(nb)) => na.cmp(&nb),
                    _ => mid_a.cmp(&mid_b),
                }
            });
            ordered
        };

        self.ice_transport
            .start_gathering()
            .map_err(|err| RtcError::InvalidState(format!("ICE gathering failed: {err}")))?;

        let mode = self.config.transport_mode.clone();

        // For non-WebRTC, wait for at least one candidate if none are available.
        // This ensures the SDP doesn't default to port 9 when no candidates are gathered yet.
        if mode != TransportMode::WebRtc {
            let mut candidates = self.ice_transport.local_candidates();
            if candidates.is_empty() {
                let mut rx = self.ice_transport.subscribe_candidates();
                let start = tokio::time::Instant::now();
                let timeout_dur = tokio::time::Duration::from_millis(500);

                while candidates.is_empty() && start.elapsed() < timeout_dur {
                    let _ = tokio::time::timeout(timeout_dur - start.elapsed(), rx.recv()).await;
                    candidates = self.ice_transport.local_candidates();
                }
            }
        }

        let ice_params = self.ice_transport.local_parameters();
        let ice_username = ice_params.username_fragment.clone();
        let ice_password = ice_params.password.clone();
        let candidate_lines: Vec<String> = self
            .ice_transport
            .local_candidates()
            .iter()
            .map(IceCandidate::to_sdp)
            .collect();
        let gather_complete = matches!(
            self.ice_transport.gather_state(),
            IceGathererState::Complete
        );
        let mut desc = SessionDescription::new(sdp_type);
        desc.session.origin = default_origin();
        if let Some(ext_ip) = &self.config.external_ip {
            desc.session.origin.unicast_address = ext_ip.clone();
        }
        desc.session.origin.session_version += 1;
        if !desc
            .session
            .attributes
            .iter()
            .any(|attr| attr.key == "msid-semantic")
            && self.config.transport_mode == TransportMode::WebRtc
        {
            desc.session
                .attributes
                .push(Attribute::new("msid-semantic", Some("WMS *".into())));
        }

        let mode = self.config.transport_mode.clone();

        if mode == TransportMode::Rtp || mode == TransportMode::Srtp {
            let local_ip = if let Some(ext_ip) = &self.config.external_ip {
                ext_ip
                    .parse()
                    .unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            } else {
                get_local_ip().unwrap_or(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            };
            if desc.session.connection.is_none() {
                desc.session.connection = Some(format!("IN IP4 {}", local_ip));
            }
        }

        for transceiver in ordered_transceivers.into_iter() {
            let mid = self.ensure_mid(&transceiver);
            let mut direction = map_direction(transceiver.direction());
            let sender_info = if direction.sends() {
                transceiver.sender.lock().unwrap().clone()
            } else {
                None
            };

            // Check if remote side expects us to send (for B2BUA scenarios)
            let remote_expects_media = if sdp_type == SdpType::Answer {
                let remote_guard = self.remote_description.lock().unwrap();
                if let Some(remote) = remote_guard.as_ref() {
                    // Find the matching remote section by mid
                    remote
                        .media_sections
                        .iter()
                        .find(|section| section.mid == mid)
                        .map(|section| {
                            // Remote expects media if their direction is sendrecv or sendonly
                            matches!(
                                section.direction,
                                crate::sdp::Direction::SendRecv | crate::sdp::Direction::SendOnly
                            )
                        })
                        .unwrap_or(false)
                } else {
                    false
                }
            } else {
                false
            };

            // If we are supposed to send, but have no sender (and it's not Application),
            // we must downgrade direction to avoid ghost tracks.
            let has_sender_ssrc = transceiver.sender_ssrc.lock().unwrap().is_some();
            if direction.sends()
                && sender_info.is_none()
                && !has_sender_ssrc
                && transceiver.kind() != MediaKind::Application
                && !remote_expects_media
            {
                direction = match direction {
                    TransceiverDirection::SendRecv => TransceiverDirection::RecvOnly,
                    TransceiverDirection::SendOnly => TransceiverDirection::Inactive,
                    _ => direction,
                };
            }

            let mut section = MediaSection::new(transceiver.kind(), mid);
            section.direction = direction.into();

            if mode == TransportMode::Rtp {
                section.protocol = "RTP/AVP".to_string();
            }

            if mode == TransportMode::WebRtc {
                section.connection = Some("IN IP4 0.0.0.0".to_string());
                section
                    .attributes
                    .push(Attribute::new("ice-ufrag", Some(ice_username.clone())));
                section
                    .attributes
                    .push(Attribute::new("ice-pwd", Some(ice_password.clone())));
                section
                    .attributes
                    .push(Attribute::new("ice-options", Some("trickle".into())));
                for candidate in &candidate_lines {
                    section
                        .attributes
                        .push(Attribute::new("candidate", Some(candidate.clone())));
                }
                if gather_complete {
                    section
                        .attributes
                        .push(Attribute::new("end-of-candidates", None));
                }
            } else {
                // For RTP/SRTP, use the first candidate's address for c= and m= port
                // Prefer non-loopback candidates
                let candidates = self.ice_transport.local_candidates();
                if let Some(cand) = candidates
                    .iter()
                    .find(|c| !c.address.ip().is_loopback())
                    .or(candidates.first())
                {
                    section.port = cand.address.port();
                    let conn = format!("IN IP4 {}", cand.address.ip());
                    if Some(&conn) != desc.session.connection.as_ref() {
                        section.connection = Some(conn);
                    }
                }
            }

            self.populate_media_capabilities(&mut section, transceiver.kind(), sdp_type);
            if let Some(sender) = sender_info {
                Self::attach_sender_attributes(
                    &mut section,
                    sender.ssrc(),
                    sender.cname(),
                    sender.stream_id(),
                    sender.track_id(),
                    &mode,
                );
            } else if direction.sends() {
                if let Some(ssrc) = *transceiver.sender_ssrc.lock().unwrap() {
                    let cname = format!("rustrtc-cname-{ssrc}");
                    let stream_id = transceiver
                        .sender_stream_id
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| "default".to_string());
                    let track_id = transceiver
                        .sender_track_id
                        .lock()
                        .unwrap()
                        .clone()
                        .unwrap_or_else(|| format!("track-{}", transceiver.id()));
                    Self::attach_sender_attributes(
                        &mut section,
                        ssrc,
                        &cname,
                        &stream_id,
                        &track_id,
                        &mode,
                    );
                }
            }

            if self.config.transport_mode == TransportMode::Srtp {
                let mut suite = "AES_CM_128_HMAC_SHA1_80".to_string();
                if sdp_type == SdpType::Answer {
                    let remote_desc = self.remote_description.lock().unwrap();
                    if let Some(remote) = &*remote_desc {
                        if let Some(c) = remote
                            .media_sections
                            .iter()
                            .flat_map(|m| m.get_crypto_attributes())
                            .find(|c| map_crypto_suite(&c.crypto_suite).is_ok())
                        {
                            suite = c.crypto_suite.clone();
                        }
                    }
                }

                let key_params = generate_sdes_key_params();
                let crypto_val = format!("1 {} {}|2^31|1:1", suite, key_params);
                section
                    .attributes
                    .push(Attribute::new("crypto", Some(crypto_val)));
            }

            desc.media_sections.push(section);
        }

        if !desc.media_sections.is_empty() {
            let should_bundle = match sdp_type {
                SdpType::Offer => true,
                SdpType::Answer => remote_offered_bundle,
                _ => false,
            };

            let should_bundle = should_bundle && desc.media_sections.len() > 1;

            if should_bundle {
                let mids: Vec<String> = desc.media_sections.iter().map(|m| m.mid.clone()).collect();
                let value = format!("BUNDLE {}", mids.join(" "));
                desc.session
                    .attributes
                    .push(Attribute::new("group", Some(value)));
            }
        }

        Ok(desc)
    }

    fn attach_sender_attributes(
        section: &mut MediaSection,
        ssrc: u32,
        cname: &str,
        stream_id: &str,
        track_id: &str,
        mode: &TransportMode,
    ) {
        if *mode == TransportMode::WebRtc {
            section.attributes.push(Attribute::new(
                "msid",
                Some(format!("{} {}", stream_id, track_id)),
            ));
        }

        section.attributes.push(Attribute::new(
            "ssrc",
            Some(format!("{} cname:{}", ssrc, cname)),
        ));

        if *mode == TransportMode::WebRtc {
            section.attributes.push(Attribute::new(
                "ssrc",
                Some(format!("{} msid:{} {}", ssrc, stream_id, track_id)),
            ));
        }
    }

    fn ensure_mid(&self, transceiver: &Arc<RtpTransceiver>) -> String {
        if let Some(mid) = transceiver.mid() {
            return mid;
        }
        let mid_value = self.allocate_mid();
        trace!(
            "Allocated MID: {} for transceiver kind={:?}",
            mid_value,
            transceiver.kind()
        );
        transceiver.set_mid(mid_value.clone());
        mid_value
    }

    fn allocate_mid(&self) -> String {
        let mid = self.next_mid.fetch_add(1, Ordering::SeqCst);
        mid.to_string()
    }

    fn validate_sdp_type(&self, sdp_type: &SdpType) -> RtcResult<()> {
        match sdp_type {
            SdpType::Offer | SdpType::Answer => Ok(()),
            _ => Err(RtcError::NotImplemented("pranswer/rollback")),
        }
    }

    fn populate_media_capabilities(
        &self,
        section: &mut MediaSection,
        kind: MediaKind,
        sdp_type: SdpType,
    ) {
        section.apply_config(&self.config);

        // Add extmap for Video
        if kind == MediaKind::Video {
            let (mut rid_id, mut repaired_rid_id) = self.get_remote_video_extmap_ids(&section.mid);

            if sdp_type == SdpType::Offer && self.config.transport_mode != TransportMode::Rtp {
                // If not found in remote (new transceiver), use defaults
                if rid_id.is_none() {
                    rid_id = Some("1".to_string());
                }
                if repaired_rid_id.is_none() {
                    repaired_rid_id = Some("2".to_string());
                }
            }

            section.add_video_extmaps(rid_id, repaired_rid_id);
        }

        // Add abs-send-time extmap
        let mut abs_send_time_id =
            self.get_remote_extmap_id(&section.mid, crate::sdp::ABS_SEND_TIME_URI);
        if sdp_type == SdpType::Offer
            && abs_send_time_id.is_none()
            && self.config.transport_mode != TransportMode::Rtp
        {
            abs_send_time_id = Some("3".to_string()); // Default ID for abs-send-time
        }
        if let Some(id) = abs_send_time_id {
            section.attributes.push(crate::sdp::Attribute::new(
                "extmap",
                Some(format!("{} {}", id, crate::sdp::ABS_SEND_TIME_URI)),
            ));
        }

        if self.config.transport_mode != TransportMode::Rtp {
            let setup_value = match sdp_type {
                SdpType::Offer => "actpass",
                SdpType::Answer => {
                    let role = *self.dtls_role.borrow();
                    match role {
                        Some(true) => "active",
                        Some(false) => "passive",
                        None => "active",
                    }
                }
                _ => "actpass",
            };
            section.add_dtls_attributes(&self.dtls_fingerprint, setup_value);
        }
    }

    fn get_remote_video_extmap_ids(&self, mid: &str) -> (Option<String>, Option<String>) {
        let rid_id =
            self.get_remote_extmap_id(mid, "urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id");
        let repaired_rid_id = self.get_remote_extmap_id(
            mid,
            "urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
        );
        (rid_id, repaired_rid_id)
    }

    fn get_remote_extmap_id(&self, mid: &str, uri: &str) -> Option<String> {
        let remote = self.remote_description.lock().unwrap();
        if let Some(desc) = &*remote {
            let remote_section = desc.media_sections.iter().find(|s| s.mid == mid)?;
            for attr in &remote_section.attributes {
                if attr.key != "extmap" {
                    continue;
                }
                let val = attr.value.as_ref()?;
                if val.contains(uri) {
                    if let Some(id_str) = val.split_whitespace().next() {
                        return Some(id_str.to_string());
                    }
                }
            }
        }
        None
    }

    fn close(&self) {
        if *self.peer_state.borrow() == PeerConnectionState::Closed {
            return;
        }
        let _ = self.signaling_state.send(SignalingState::Closed);
        let _ = self.peer_state.send(PeerConnectionState::Closed);
        let _ = self.ice_connection_state.send(IceConnectionState::Closed);
        let _ = self.ice_gathering_state.send(IceGatheringState::Complete);

        // Clean up all tracks to prevent audio bleeding into new connections
        {
            let transceivers = self.transceivers.lock().unwrap();
            for t in transceivers.iter() {
                // Stop receiver tracks by marking them as ended
                if let Some(receiver) = t.receiver() {
                    let track = receiver.track();
                    track.stop();
                    tracing::debug!(
                        "PeerConnection.close: marked receiver track {} as ended",
                        track.id()
                    );
                }
            }
        }

        // Clear RTP transport listeners to stop receiving packets
        let rtp_transport = self.rtp_transport.lock().unwrap().clone();
        if let Some(transport) = rtp_transport.as_ref() {
            let count = transport.clear_listeners();
            if count > 0 {
                tracing::debug!("PeerConnection.close: cleared {} listeners", count);
            }

            // Send RTCP BYE
            let transceivers = self.transceivers.lock().unwrap();
            let mut ssrcs = Vec::new();
            for t in transceivers.iter() {
                if let Some(sender) = t.sender() {
                    ssrcs.push(sender.ssrc());
                }
            }
            if !ssrcs.is_empty() {
                let bye = crate::rtp::RtcpPacket::Goodbye(crate::rtp::Goodbye {
                    sources: ssrcs,
                    reason: Some("PeerConnection closed".to_string()),
                });
                let transport_clone = transport.clone();
                tokio::spawn(async move {
                    let _ = transport_clone.send_rtcp(&[bye]).await;
                });
            }
        }

        if let Some(dtls) = self.dtls_transport.lock().unwrap().as_ref() {
            dtls.close();
        }

        self.ice_transport.stop();
    }
}

impl Drop for PeerConnectionInner {
    fn drop(&mut self) {
        debug!("PeerConnectionInner dropped, stopping ICE transport");
        self.close();
    }
}

fn default_origin() -> Origin {
    let mut origin = Origin::default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    origin.session_id = now;
    origin.session_version = now;
    if let Ok(ip) = get_local_ip() {
        origin.unicast_address = ip.to_string();
    }
    origin
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnectionState {
    New,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalingState {
    Stable,
    HaveLocalOffer,
    HaveRemoteOffer,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceConnectionState {
    New,
    Checking,
    Connected,
    Completed,
    Failed,
    Disconnected,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceGatheringState {
    New,
    Gathering,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum TransceiverDirection {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl TransceiverDirection {
    pub fn answer_direction(self) -> Self {
        match self {
            TransceiverDirection::SendRecv => TransceiverDirection::SendRecv,
            TransceiverDirection::SendOnly => TransceiverDirection::RecvOnly,
            TransceiverDirection::RecvOnly => TransceiverDirection::SendOnly,
            TransceiverDirection::Inactive => TransceiverDirection::Inactive,
        }
    }

    pub fn sends(self) -> bool {
        matches!(
            self,
            TransceiverDirection::SendRecv | TransceiverDirection::SendOnly
        )
    }
}

impl From<TransceiverDirection> for Direction {
    fn from(value: TransceiverDirection) -> Self {
        match value {
            TransceiverDirection::SendRecv => Direction::SendRecv,
            TransceiverDirection::SendOnly => Direction::SendOnly,
            TransceiverDirection::RecvOnly => Direction::RecvOnly,
            TransceiverDirection::Inactive => Direction::Inactive,
        }
    }
}

impl From<Direction> for TransceiverDirection {
    fn from(value: Direction) -> Self {
        match value {
            Direction::SendRecv => TransceiverDirection::SendRecv,
            Direction::SendOnly => TransceiverDirection::SendOnly,
            Direction::RecvOnly => TransceiverDirection::RecvOnly,
            Direction::Inactive => TransceiverDirection::Inactive,
        }
    }
}

static TRANSCEIVER_COUNTER: AtomicU64 = AtomicU64::new(1);

#[derive(Debug, Clone, PartialEq)]
pub struct RtpCodecParameters {
    pub payload_type: u8,
    pub clock_rate: u32,
    pub channels: u8,
}

impl Default for RtpCodecParameters {
    fn default() -> Self {
        Self {
            payload_type: 96,
            clock_rate: 90000,
            channels: 0,
        }
    }
}

pub struct RtpTransceiver {
    id: u64,
    kind: MediaKind,
    direction: Mutex<TransceiverDirection>,
    mid: Mutex<Option<String>>,
    sender: Mutex<Option<Arc<RtpSender>>>,
    receiver: Mutex<Option<Arc<RtpReceiver>>>,
    rtp_transport: Mutex<Option<Weak<RtpTransport>>>,
    sender_ssrc: Mutex<Option<u32>>,
    sender_stream_id: Mutex<Option<String>>,
    sender_track_id: Mutex<Option<String>>,
    payload_map: Arc<std::sync::RwLock<HashMap<u8, RtpCodecParameters>>>,
    extmap: Arc<std::sync::RwLock<HashMap<u8, String>>>,
}

impl RtpTransceiver {
    fn new(kind: MediaKind, direction: TransceiverDirection) -> Self {
        Self {
            id: TRANSCEIVER_COUNTER.fetch_add(1, Ordering::Relaxed),
            kind,
            direction: Mutex::new(direction),
            mid: Mutex::new(None),
            sender: Mutex::new(None),
            receiver: Mutex::new(None),
            rtp_transport: Mutex::new(None),
            sender_ssrc: Mutex::new(None),
            sender_stream_id: Mutex::new(None),
            sender_track_id: Mutex::new(None),
            payload_map: Arc::new(std::sync::RwLock::new(HashMap::new())),
            extmap: Arc::new(std::sync::RwLock::new(HashMap::new())),
        }
    }

    /// Create transceiver for testing purposes
    #[doc(hidden)]
    pub fn new_for_test(kind: MediaKind, direction: TransceiverDirection) -> Self {
        Self::new(kind, direction)
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn sender_ssrc(&self) -> Option<u32> {
        *self.sender_ssrc.lock().unwrap()
    }

    pub fn sender_stream_id(&self) -> Option<String> {
        self.sender_stream_id.lock().unwrap().clone()
    }

    pub fn sender_track_id(&self) -> Option<String> {
        self.sender_track_id.lock().unwrap().clone()
    }

    pub fn direction(&self) -> TransceiverDirection {
        *self.direction.lock().unwrap()
    }

    pub fn set_direction(&self, direction: TransceiverDirection) {
        *self.direction.lock().unwrap() = direction;
    }

    pub fn mid(&self) -> Option<String> {
        self.mid.lock().unwrap().clone()
    }

    fn set_mid(&self, mid: String) {
        *self.mid.lock().unwrap() = Some(mid);
    }

    pub fn sender(&self) -> Option<Arc<RtpSender>> {
        self.sender.lock().unwrap().clone()
    }

    pub fn set_sender(&self, sender: Option<Arc<RtpSender>>) {
        if let Some(ref s) = sender {
            // If transport is already established, connect the sender to it
            if let Some(weak_transport) = self.rtp_transport.lock().unwrap().as_ref() {
                if let Some(transport) = weak_transport.upgrade() {
                    debug!(
                        "set_sender: connecting late sender ssrc={} to existing transport",
                        s.ssrc()
                    );
                    s.set_transport(transport);
                }
            }
            // Sync pre-allocated fields
            *self.sender_ssrc.lock().unwrap() = Some(s.ssrc());
            *self.sender_stream_id.lock().unwrap() = Some(s.stream_id().to_string());
            *self.sender_track_id.lock().unwrap() = Some(s.track_id().to_string());
        }
        *self.sender.lock().unwrap() = sender;
    }

    /// Set the RTP transport reference. Called by start_dtls when transport is established.
    pub fn set_rtp_transport(&self, transport: Weak<RtpTransport>) {
        *self.rtp_transport.lock().unwrap() = Some(transport);
    }

    pub fn receiver(&self) -> Option<Arc<RtpReceiver>> {
        self.receiver.lock().unwrap().clone()
    }

    pub fn set_receiver(&self, receiver: Option<Arc<RtpReceiver>>) {
        *self.receiver.lock().unwrap() = receiver;
    }

    /// Update payload type mapping for reinvite scenarios
    pub fn update_payload_map(&self, new_map: HashMap<u8, RtpCodecParameters>) -> RtcResult<()> {
        let mut payload_map = self.payload_map.write().unwrap();

        // Log changes for debugging
        for (pt, codec) in &new_map {
            if !payload_map.contains_key(pt) || payload_map.get(pt) != Some(codec) {
                trace!(
                    "Payload type {} remapped: clock_rate={}, channels={}",
                    pt, codec.clock_rate, codec.channels
                );
            }
        }

        *payload_map = new_map.clone();

        // Update PT listeners in transport for fallback routing
        if let Some(receiver) = self.receiver() {
            if let Some(transport_weak) = self.rtp_transport.lock().unwrap().clone() {
                if let Some(transport) = transport_weak.upgrade() {
                    if let Some(tx) = receiver.packet_tx() {
                        for (&pt, _) in &new_map {
                            transport.register_pt_listener(pt, tx.clone());
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Update RTP header extension mapping for reinvite scenarios
    pub fn update_extmap(&self, new_extmap: HashMap<u8, String>) -> RtcResult<()> {
        let mut extmap = self.extmap.write().unwrap();

        // Log changes
        for (id, uri) in &new_extmap {
            if !extmap.contains_key(id) || extmap.get(id) != Some(uri) {
                trace!("Extmap ID {} remapped to {}", id, uri);
            }
        }

        *extmap = new_extmap;

        // Update transport extension IDs if available
        if let Some(weak_transport) = self.rtp_transport.lock().unwrap().as_ref() {
            if let Some(transport) = weak_transport.upgrade() {
                let id = extmap
                    .iter()
                    .find(|(_, uri)| uri.as_str() == crate::sdp::ABS_SEND_TIME_URI)
                    .map(|(id, _)| *id);
                transport.set_abs_send_time_extension_id(id);

                let id = extmap
                    .iter()
                    .find(|(_, uri)| uri.contains("rtp-stream-id"))
                    .map(|(id, _)| *id);
                transport.set_rid_extension_id(id);
            }
        }

        Ok(())
    }

    /// Get current payload type mapping (for testing/debugging)
    pub fn get_payload_map(&self) -> HashMap<u8, RtpCodecParameters> {
        self.payload_map.read().unwrap().clone()
    }

    /// Get current extmap (for testing/debugging)
    pub fn get_extmap(&self) -> HashMap<u8, String> {
        self.extmap.read().unwrap().clone()
    }
}

pub struct RtpSender {
    track: Arc<dyn MediaStreamTrack>,
    transport: Mutex<Option<Arc<RtpTransport>>>,
    ssrc: u32,
    params: Arc<Mutex<RtpCodecParameters>>,
    track_id: Arc<str>,
    stream_id: Arc<str>,
    cname: Arc<str>,
    rtcp_tx: broadcast::Sender<RtcpPacket>,
    stop_tx: Arc<tokio::sync::Notify>,
    next_sequence_number: Arc<AtomicU16>,
    interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
}

pub struct RtpSenderBuilder {
    track: Arc<dyn MediaStreamTrack>,
    ssrc: u32,
    stream_id: String,
    params: RtpCodecParameters,
    interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
}

impl RtpSenderBuilder {
    pub fn new(track: Arc<dyn MediaStreamTrack>, ssrc: u32) -> Self {
        Self {
            track,
            ssrc,
            stream_id: "stream".to_string(),
            params: RtpCodecParameters::default(),
            interceptors: Vec::new(),
        }
    }

    pub fn stream_id(mut self, id: String) -> Self {
        self.stream_id = id;
        self
    }

    pub fn params(mut self, params: RtpCodecParameters) -> Self {
        self.params = params;
        self
    }

    pub fn nack(mut self, buffer_size: usize) -> Self {
        self.interceptors
            .push(Arc::new(DefaultRtpSenderNackHandler::new(buffer_size)));
        self
    }

    pub fn bitrate_controller(mut self) -> Self {
        self.interceptors
            .push(Arc::new(DefaultRtpSenderBitrateHandler::new()));
        self
    }

    pub fn interceptor(mut self, interceptor: Arc<dyn RtpSenderInterceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    pub fn build(self) -> Arc<RtpSender> {
        Arc::new(RtpSender::new_internal(
            self.track,
            self.ssrc,
            self.stream_id,
            self.params,
            self.interceptors,
        ))
    }
}

impl RtpSender {
    pub fn builder(track: Arc<dyn MediaStreamTrack>, ssrc: u32) -> RtpSenderBuilder {
        RtpSenderBuilder::new(track, ssrc)
    }

    pub fn new(
        track: Arc<dyn MediaStreamTrack>,
        ssrc: u32,
        stream_id: String,
        params: RtpCodecParameters,
        interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
    ) -> Self {
        Self::new_internal(track, ssrc, stream_id, params, interceptors)
    }

    fn new_internal(
        track: Arc<dyn MediaStreamTrack>,
        ssrc: u32,
        stream_id: String,
        params: RtpCodecParameters,
        interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
    ) -> Self {
        let track_label = track.id().to_string();
        let track_id = Arc::<str>::from(track_label.clone());
        let stream_id = Arc::<str>::from(stream_id);
        let cname = Arc::<str>::from(format!("rustrtc-cname-{ssrc}"));
        let (rtcp_tx, _) = broadcast::channel(100);
        Self {
            track,
            transport: Mutex::new(None),
            ssrc,
            params: Arc::new(Mutex::new(params)),
            track_id,
            stream_id,
            cname,
            rtcp_tx,
            stop_tx: Arc::new(tokio::sync::Notify::new()),
            next_sequence_number: Arc::new(AtomicU16::new(random_u32() as u16)),
            interceptors,
        }
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn cname(&self) -> &str {
        &self.cname
    }

    pub fn track_id(&self) -> &str {
        &self.track_id
    }

    pub fn stream_id(&self) -> &str {
        &self.stream_id
    }

    pub fn subscribe_rtcp(&self) -> broadcast::Receiver<RtcpPacket> {
        self.rtcp_tx.subscribe()
    }

    pub(crate) fn deliver_rtcp(&self, packet: RtcpPacket) {
        let _ = self.rtcp_tx.send(packet);
    }

    pub fn params(&self) -> RtpCodecParameters {
        self.params.lock().unwrap().clone()
    }

    pub fn interceptors(&self) -> &[Arc<dyn RtpSenderInterceptor + Send + Sync>] {
        &self.interceptors
    }

    pub fn nack_handler(&self) -> Option<Arc<dyn NackStats>> {
        for i in &self.interceptors {
            if let Some(stats) = i.clone().as_nack_stats() {
                return Some(stats);
            }
        }
        None
    }

    pub fn set_transport(&self, transport: Arc<RtpTransport>) {
        *self.transport.lock().unwrap() = Some(transport.clone());
        let track = self.track.clone();
        let ssrc = self.ssrc;
        let params_lock = self.params.clone();
        let stop_rx = self.stop_tx.clone();
        let next_seq = self.next_sequence_number.clone();
        let interceptors = self.interceptors.clone();
        let mut rtcp_rx = self.rtcp_tx.subscribe();

        tokio::spawn(async move {
            let mut sequence_number = next_seq.load(Ordering::SeqCst);
            let mut last_source_ts: Option<u32> = None;
            let mut timestamp_offset = random_u32(); // Start with random offset
            let notified = stop_rx.notified();
            tokio::pin!(notified);

            loop {
                tokio::select! {
                    _ = &mut notified => break,
                    rtcp = rtcp_rx.recv() => {
                        match rtcp {
                            Ok(packet) => {
                                for interceptor in &interceptors {
                                    interceptor.on_rtcp_received(&packet, transport.clone()).await;
                                }
                            }
                            _ => {}
                        }
                    }
                    res = track.recv() => {
                        match res {
                            Ok(mut sample) => {
                                let payload_type = {
                                    let p = params_lock.lock().unwrap();
                                    p.payload_type
                                };

                                // Check if application provided sequence_number (indicates app wants control)
                                let app_controlled = match &sample {
                                    crate::media::MediaSample::Audio(f) => f.sequence_number.is_some(),
                                    crate::media::MediaSample::Video(f) => f.sequence_number.is_some(),
                                };

                                // Always rewrite sequence numbers to ensure continuity on the wire
                                match &mut sample {
                                    crate::media::MediaSample::Audio(f) => f.sequence_number = None,
                                    crate::media::MediaSample::Video(f) => f.sequence_number = None,
                                }

                                let mut packet = sample.into_rtp_packet(
                                    ssrc,
                                    payload_type,
                                    &mut sequence_number,
                                );

                                // Update the shared next_sequence_number
                                next_seq.store(sequence_number, Ordering::SeqCst);

                                if !app_controlled {
                                    // Application doesn't control seq/ts, use rustrtc's logic
                                    // Timestamp rewriting
                                    let src_ts = packet.header.timestamp;
                                    if let Some(last_src) = last_source_ts {
                                        let delta = src_ts.wrapping_sub(last_src);
                                        // Check if src_ts is newer (delta < 2^31)
                                        if delta < 0x80000000 {
                                            // If delta is very large (e.g. > 10 seconds), assume source switch/reset
                                            // 10 seconds * 90000 = 900,000.
                                            if delta > 900_000 {
                                                // Discontinuity detected.
                                                // We want the new timestamp to continue from where we left off.
                                                // But we don't track last_out_ts explicitly here, we rely on offset.
                                                // last_out_ts was (last_src + old_offset).
                                                // new_out_ts should be (last_out_ts + small_delta).
                                                // Let's assume small_delta = 3000 (1/30s at 90khz) or just 1 to be safe.
                                                // new_out_ts = last_src + old_offset + 3000.
                                                // new_out_ts = src_ts + new_offset.
                                                // => new_offset = last_src + old_offset + 3000 - src_ts.
                                                timestamp_offset = last_src.wrapping_add(timestamp_offset).wrapping_add(3000).wrapping_sub(src_ts);
                                            }
                                            last_source_ts = Some(src_ts);
                                        }
                                        // If src_ts is older (delta >= 2^31), it's an out-of-order packet.
                                        // We use the existing offset and do NOT update last_source_ts.
                                    } else {
                                        // First packet, establish offset
                                        // We want out_ts = src_ts + offset.
                                        // We initialized offset to random.
                                        // So out_ts will be random. Correct.
                                        last_source_ts = Some(src_ts);
                                    }

                                    packet.header.timestamp = src_ts.wrapping_add(timestamp_offset);

                                    // Rewrite sequence number
                                    packet.header.sequence_number = next_seq.fetch_add(1, Ordering::Relaxed);
                                }

                                for interceptor in &interceptors {
                                    interceptor.on_packet_sent(&packet).await;
                                }

                                if let Err(e) = transport.send_rtp(&packet).await {
                                    debug!("Failed to send RTP: {}", e);
                                }
                            }
                            Err(crate::media::error::MediaError::Lagged) => {
                                debug!("RtpSender: track lagged, skipping sample");
                                continue;
                            }
                            Err(_) => break,
                        }
                    }
                }
            }
        });
    }
}

impl Drop for RtpSender {
    fn drop(&mut self) {
        self.stop_tx.notify_waiters();
    }
}

pub struct RtpReceiver {
    track: Arc<SampleStreamTrack>,
    source: Arc<SampleStreamSource>,
    ssrc: Mutex<u32>,
    params: Mutex<RtpCodecParameters>,
    transport: Mutex<Option<Arc<RtpTransport>>>,
    packet_tx: Mutex<Option<mpsc::Sender<(crate::rtp::RtpPacket, std::net::SocketAddr)>>>,
    rtcp_feedback_ssrc: Mutex<Option<u32>>,
    rtx_ssrc: Mutex<Option<u32>>,
    fir_seq: AtomicU8,
    feedback_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<crate::media::track::FeedbackEvent>>>,
    simulcast_tracks: Mutex<
        HashMap<
            String,
            (
                Arc<SampleStreamSource>,
                Arc<SampleStreamTrack>,
                Arc<tokio::sync::Mutex<mpsc::Receiver<crate::media::track::FeedbackEvent>>>,
                Arc<Mutex<Option<u32>>>,
            ),
        >,
    >,
    runner_tx: Mutex<Option<mpsc::UnboundedSender<ReceiverCommand>>>,
    interceptors: Vec<Arc<dyn RtpReceiverInterceptor>>,
}

pub struct RtpReceiverBuilder {
    kind: MediaKind,
    ssrc: u32,
    interceptors: Vec<Arc<dyn RtpReceiverInterceptor>>,
}

impl RtpReceiverBuilder {
    pub fn new(kind: MediaKind, ssrc: u32) -> Self {
        Self {
            kind,
            ssrc,
            interceptors: Vec::new(),
        }
    }

    pub fn nack(mut self) -> Self {
        self.interceptors
            .push(Arc::new(DefaultRtpReceiverNackHandler::new()));
        self
    }

    pub fn interceptor(mut self, interceptor: Arc<dyn RtpReceiverInterceptor>) -> Self {
        self.interceptors.push(interceptor);
        self
    }

    pub fn build(self) -> Arc<RtpReceiver> {
        let media_kind = match self.kind {
            MediaKind::Audio => crate::media::frame::MediaKind::Audio,
            MediaKind::Video => crate::media::frame::MediaKind::Video,
            _ => crate::media::frame::MediaKind::Audio,
        };
        let (source, track, feedback_rx) = sample_track(media_kind, 100);

        let params = match self.kind {
            MediaKind::Audio => RtpCodecParameters {
                payload_type: 111,
                clock_rate: 48000,
                channels: 2,
            },
            MediaKind::Video => RtpCodecParameters {
                payload_type: 96,
                clock_rate: 90000,
                channels: 0,
            },
            _ => RtpCodecParameters::default(),
        };

        Arc::new(RtpReceiver {
            track,
            source: Arc::new(source),
            ssrc: Mutex::new(self.ssrc),
            params: Mutex::new(params),
            transport: Mutex::new(None),
            packet_tx: Mutex::new(None),
            rtcp_feedback_ssrc: Mutex::new(None),
            rtx_ssrc: Mutex::new(None),
            fir_seq: AtomicU8::new(0),
            feedback_rx: Arc::new(tokio::sync::Mutex::new(feedback_rx)),
            simulcast_tracks: Mutex::new(HashMap::new()),
            runner_tx: Mutex::new(None),
            interceptors: self.interceptors,
        })
    }
}

impl RtpReceiver {
    pub fn new(
        kind: MediaKind,
        ssrc: u32,
        interceptors: Vec<Arc<dyn RtpReceiverInterceptor>>,
    ) -> Self {
        let media_kind = match kind {
            MediaKind::Audio => crate::media::frame::MediaKind::Audio,
            MediaKind::Video => crate::media::frame::MediaKind::Video,
            _ => crate::media::frame::MediaKind::Audio, // Fallback or panic
        };
        let (source, track, feedback_rx) = sample_track(media_kind, 100);

        let params = match kind {
            MediaKind::Audio => RtpCodecParameters {
                payload_type: 111,
                clock_rate: 48000,
                channels: 2,
            },
            MediaKind::Video => RtpCodecParameters {
                payload_type: 96,
                clock_rate: 90000,
                channels: 0,
            },
            _ => RtpCodecParameters::default(),
        };

        Self {
            track,
            source: Arc::new(source),
            ssrc: Mutex::new(ssrc),
            params: Mutex::new(params),
            transport: Mutex::new(None),
            packet_tx: Mutex::new(None),
            rtcp_feedback_ssrc: Mutex::new(None),
            rtx_ssrc: Mutex::new(None),
            fir_seq: AtomicU8::new(0),
            feedback_rx: Arc::new(tokio::sync::Mutex::new(feedback_rx)),
            simulcast_tracks: Mutex::new(HashMap::new()),
            runner_tx: Mutex::new(None),
            interceptors,
        }
    }

    pub fn add_simulcast_track(self: &Arc<Self>, rid: String) -> Arc<SampleStreamTrack> {
        let (source, track, feedback_rx) = sample_track(self.track.kind(), 100);
        let source = Arc::new(source);
        let feedback_rx = Arc::new(tokio::sync::Mutex::new(feedback_rx));
        let simulcast_ssrc = Arc::new(Mutex::new(None));

        // If runner is active, send command
        let runner_tx = self.runner_tx.lock().unwrap().clone();
        if let Some(tx) = runner_tx {
            let transport = self.transport.lock().unwrap().clone();
            if let Some(transport) = transport {
                let (packet_tx, packet_rx) = mpsc::channel(100);
                transport.register_rid_listener(rid.clone(), packet_tx);

                let cmd = ReceiverCommand::AddTrack {
                    rid: Some(rid.clone()),
                    packet_rx,
                    feedback_rx: feedback_rx.clone(),
                    source: source.clone(),
                    simulcast_ssrc: simulcast_ssrc.clone(),
                };
                let _ = tx.send(cmd);
            }
        }

        self.simulcast_tracks
            .lock()
            .unwrap()
            .insert(rid, (source, track.clone(), feedback_rx, simulcast_ssrc));

        track
    }

    pub fn track(&self) -> Arc<SampleStreamTrack> {
        self.track.clone()
    }

    pub fn nack_handler(&self) -> Option<Arc<dyn NackStats>> {
        for i in &self.interceptors {
            if let Some(stats) = i.clone().as_nack_stats() {
                return Some(stats);
            }
        }
        None
    }

    pub fn simulcast_track(&self, rid: &str) -> Option<Arc<SampleStreamTrack>> {
        let tracks = self.simulcast_tracks.lock().unwrap();
        tracks.get(rid).map(|(_, track, _, _)| track.clone())
    }

    pub fn get_simulcast_rids(&self) -> Vec<String> {
        let tracks = self.simulcast_tracks.lock().unwrap();
        tracks.keys().cloned().collect()
    }

    pub fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock().unwrap() = params;
    }

    pub fn ssrc(&self) -> u32 {
        *self.ssrc.lock().unwrap()
    }

    pub fn packet_tx(&self) -> Option<mpsc::Sender<(crate::rtp::RtpPacket, std::net::SocketAddr)>> {
        self.packet_tx.lock().unwrap().clone()
    }

    pub fn rtx_ssrc(&self) -> Option<u32> {
        *self.rtx_ssrc.lock().unwrap()
    }

    pub fn set_ssrc(&self, ssrc: u32) {
        *self.ssrc.lock().unwrap() = ssrc;
        let transport = self.transport.lock().unwrap().clone();
        let packet_tx = self.packet_tx.lock().unwrap().clone();

        if let Some(transport) = transport
            && let Some(tx) = packet_tx
        {
            transport.register_listener_sync(ssrc, tx);
        }
    }

    pub fn ensure_provisional_listener(&self) {
        let transport = self.transport.lock().unwrap().clone();
        let packet_tx = self.packet_tx.lock().unwrap().clone();

        if let Some(transport) = transport
            && let Some(tx) = packet_tx
        {
            transport.register_provisional_listener(tx);
        }
    }

    pub fn set_rtx_ssrc(&self, ssrc: u32) {
        *self.rtx_ssrc.lock().unwrap() = Some(ssrc);
    }

    pub fn set_transport(self: &Arc<Self>, transport: Arc<RtpTransport>) {
        *self.transport.lock().unwrap() = Some(transport.clone());

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        *self.runner_tx.lock().unwrap() = Some(cmd_tx);

        let mut initial_tracks = Vec::new();

        // Main track
        let (tx, rx) = mpsc::channel(2000);
        let ssrc = *self.ssrc.lock().unwrap();
        transport.register_listener_sync(ssrc, tx.clone());
        transport.register_provisional_listener(tx.clone());

        // Also register current payload type as a fallback
        let pt = self.params.lock().unwrap().payload_type;
        transport.register_pt_listener(pt, tx.clone());

        *self.packet_tx.lock().unwrap() = Some(tx);

        initial_tracks.push(ReceiverCommand::AddTrack {
            rid: None,
            packet_rx: rx,
            feedback_rx: self.feedback_rx.clone(),
            source: self.source.clone(),
            simulcast_ssrc: Arc::new(Mutex::new(None)),
        });

        // Simulcast tracks
        let tracks_guard = self.simulcast_tracks.lock().unwrap();
        for (rid, (source, _, feedback_rx, simulcast_ssrc)) in tracks_guard.iter() {
            let (tx, rx) = mpsc::channel(2000);
            transport.register_rid_listener(rid.clone(), tx);
            initial_tracks.push(ReceiverCommand::AddTrack {
                rid: Some(rid.clone()),
                packet_rx: rx,
                feedback_rx: feedback_rx.clone(),
                source: source.clone(),
                simulcast_ssrc: simulcast_ssrc.clone(),
            });
        }
        drop(tracks_guard);

        let weak_self = Arc::downgrade(self);
        tokio::spawn(async move {
            Self::run_loop(weak_self, cmd_rx, initial_tracks).await;
        });
    }

    async fn run_loop(
        weak_self: Weak<Self>,
        mut cmd_rx: mpsc::UnboundedReceiver<ReceiverCommand>,
        initial_tracks: Vec<ReceiverCommand>,
    ) {
        let mut futures = FuturesUnordered::new();
        let mut tracks = HashMap::new();

        fn handle_add_track(
            cmd: ReceiverCommand,
            futures: &mut FuturesUnordered<Pin<Box<dyn Future<Output = LoopEvent> + Send>>>,
            tracks: &mut HashMap<
                Option<String>,
                (
                    Arc<crate::media::track::SampleStreamSource>,
                    Arc<Mutex<Option<u32>>>,
                    Arc<tokio::sync::Mutex<mpsc::Receiver<crate::media::track::FeedbackEvent>>>,
                ),
            >,
        ) {
            let ReceiverCommand::AddTrack {
                rid,
                packet_rx,
                feedback_rx,
                source,
                simulcast_ssrc,
            } = cmd;

            tracks.insert(rid.clone(), (source, simulcast_ssrc, feedback_rx.clone()));

            let rid_clone = rid.clone();
            futures.push(Box::pin(async move {
                let mut rx = packet_rx;
                let packet = rx.recv().await;
                LoopEvent::Packet(packet, rid_clone, rx)
            }));

            let rid_clone = rid.clone();
            futures.push(Box::pin(async move {
                let event = {
                    let mut lock = feedback_rx.lock().await;
                    lock.recv().await
                };
                LoopEvent::Feedback(event, rid_clone)
            }));
        }

        for cmd in initial_tracks {
            handle_add_track(cmd, &mut futures, &mut tracks);
        }

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => handle_add_track(cmd, &mut futures, &mut tracks),
                        None => break,
                    }
                }
                event = futures.next(), if !futures.is_empty() => {
                    if let Some(event) = event {
                        match event {
                            LoopEvent::Packet(packet_opt, rid, packet_rx) => {
                                if let Some((packet, addr)) = packet_opt {
                                    if let Some((source, simulcast_ssrc, _)) = tracks.get(&rid) {
                                        if rid.is_some() {
                                            let mut s = simulcast_ssrc.lock().unwrap();
                                            if s.is_none() {
                                                *s = Some(packet.header.ssrc);
                                            }
                                        } else {
                                            // Main track: Update SSRC if it matched via provisional listener
                                            if let Some(this) = weak_self.upgrade() {
                                                let mut s = this.ssrc.lock().unwrap();
                                                if *s != packet.header.ssrc {
                                                    debug!(
                                                        "RTP main track SSRC changed from {} to {}",
                                                        *s, packet.header.ssrc
                                                    );
                                                    *s = packet.header.ssrc;
                                                }
                                            }
                                        }

                                        if let Some(this) = weak_self.upgrade() {
                                            for interceptor in &this.interceptors {
                                                if let Some(mut rtcp_packet) = interceptor.on_packet_received(&packet).await {
                                                    if let RtcpPacket::GenericNack(ref mut nack) = rtcp_packet {
                                                        let sender_ssrc = this.rtcp_feedback_ssrc.lock().unwrap().unwrap_or(0);
                                                        if sender_ssrc != 0 {
                                                            nack.sender_ssrc = sender_ssrc;
                                                        } else {
                                                            debug!("NACK: skipping sender_ssrc update because it is 0");
                                                        }
                                                    }

                                                    let transport = this.transport.lock().unwrap().clone();
                                                    if let Some(transport) = transport {
                                                        let _ = transport.send_rtcp(&[rtcp_packet]).await;
                                                    }
                                                }
                                            }

                                            let params = this.params.lock().unwrap().clone();
                                            let sample = crate::media::frame::MediaSample::from_rtp_packet(
                                                packet,
                                                source.kind(),
                                                params.clock_rate,
                                                addr,
                                            );
                                            if let Ok(_) = source.send(sample).await {
                                                let rid_clone = rid.clone();
                                                futures.push(Box::pin(async move {
                                                    let mut rx = packet_rx;
                                                    let packet = rx.recv().await;
                                                    LoopEvent::Packet(packet, rid_clone, rx)
                                                }));
                                            }
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                            LoopEvent::Feedback(event_opt, rid) => {
                                if let Some(event) = event_opt {
                                    if let Some((_, simulcast_ssrc, feedback_rx)) = tracks.get(&rid) {
                                        if let Some(this) = weak_self.upgrade() {
                                            match event {
                                                crate::media::track::FeedbackEvent::RequestKeyFrame => {
                                                    let media_ssrc = if rid.is_some() {
                                                        *simulcast_ssrc.lock().unwrap()
                                                    } else {
                                                        Some(*this.ssrc.lock().unwrap())
                                                    };

                                                    if let Some(ssrc) = media_ssrc {
                                                        let sender_ssrc = *this.rtcp_feedback_ssrc.lock().unwrap();
                                                        let pli = crate::rtp::PictureLossIndication {
                                                            sender_ssrc: sender_ssrc.unwrap_or(0),
                                                            media_ssrc: ssrc,
                                                        };
                                                        let packet = crate::rtp::RtcpPacket::PictureLossIndication(pli);

                                                        let transport = this.transport.lock().unwrap().clone();
                                                        if let Some(transport) = transport {
                                                            if let Err(e) = transport.send_rtcp(&[packet]).await {
                                                                warn!("Failed to send PLI: {}", e);
                                                            }
                                                        }
                                                    }
                                                }
                                            }

                                            let rid_clone = rid.clone();
                                            let feedback_rx = feedback_rx.clone();
                                            futures.push(Box::pin(async move {
                                                let event = {
                                                    let mut lock = feedback_rx.lock().await;
                                                    lock.recv().await
                                                };
                                                LoopEvent::Feedback(event, rid_clone)
                                            }));
                                        } else {
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn set_feedback_ssrc(&self, ssrc: u32) {
        *self.rtcp_feedback_ssrc.lock().unwrap() = Some(ssrc);
    }

    pub async fn send_nack(&self, lost_packets: Vec<u16>) -> RtcResult<()> {
        let transport = self.transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            let media_ssrc = *self.ssrc.lock().unwrap();
            let sender_ssrc = (*self.rtcp_feedback_ssrc.lock().unwrap()).unwrap_or(media_ssrc);

            let nack = crate::rtp::GenericNack {
                sender_ssrc,
                media_ssrc,
                lost_packets,
            };
            let packet = RtcpPacket::GenericNack(nack);
            transport
                .send_rtcp(&[packet])
                .await
                .map_err(|e| RtcError::Internal(format!("Failed to send NACK: {}", e)))?;
            Ok(())
        } else {
            Err(RtcError::InvalidState("Transport not set".into()))
        }
    }

    pub async fn request_key_frame(&self) -> RtcResult<()> {
        let transport = self.transport.lock().unwrap().clone();
        if let Some(transport) = transport {
            let media_ssrc = *self.ssrc.lock().unwrap();
            let sender_ssrc = (*self.rtcp_feedback_ssrc.lock().unwrap()).unwrap_or(media_ssrc);

            // Try FIR
            let seq = self.fir_seq.fetch_add(1, Ordering::Relaxed);
            let fir = FullIntraRequest {
                sender_ssrc,
                requests: vec![FirRequest {
                    ssrc: media_ssrc,
                    sequence_number: seq,
                }],
            };
            let packet_fir = RtcpPacket::FullIntraRequest(fir);

            let pli = PictureLossIndication {
                sender_ssrc,
                media_ssrc,
            };
            let packet_pli = RtcpPacket::PictureLossIndication(pli);
            transport
                .send_rtcp(&[packet_fir, packet_pli])
                .await
                .map_err(|e| RtcError::Internal(format!("Failed to send PLI: {}", e)))?;
            Ok(())
        } else {
            Err(RtcError::InvalidState("Transport not set".into()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transports::ice::IceTransportState;
    use crate::{Direction, MediaKind, RtcConfiguration};

    const AUDIO_PAYLOAD_TYPE: u8 = 111;
    const VIDEO_PAYLOAD_TYPE: u8 = 96;
    const SCTP_FORMAT: &str = "webrtc-datachannel";
    const SCTP_PORT: u16 = 5000;

    #[tokio::test]
    async fn create_offer_contains_transceiver() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        // Add a sender so direction is not downgraded
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 111,
            clock_rate: 48000,
            channels: 2,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("stream".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        // First create_offer triggers gathering
        let _ = pc.create_offer().await.unwrap();

        // Wait for gathering to complete to ensure we have candidates and end-of-candidates
        pc.wait_for_gathering_complete().await;

        // Create offer again to get the candidates
        let offer = pc.create_offer().await.unwrap();

        assert_eq!(offer.media_sections.len(), 1);
        let section = &offer.media_sections[0];
        assert_eq!(section.kind, MediaKind::Audio);
        assert_eq!(section.direction, Direction::SendRecv);
        assert_eq!(section.formats, vec![AUDIO_PAYLOAD_TYPE.to_string()]);
        let attrs = &section.attributes;
        assert!(attrs.iter().any(|attr| attr.key == "ice-ufrag"));
        assert!(attrs.iter().any(|attr| attr.key == "ice-pwd"));

        // Should have msid-semantic
        assert!(
            offer
                .session
                .attributes
                .iter()
                .any(|a| a.key == "msid-semantic")
        );

        // Should have msid in media section
        assert!(attrs.iter().any(|a| a.key == "msid"));

        // Should have ssrc in media section
        assert!(attrs.iter().any(|a| a.key == "ssrc"));
        assert!(attrs.iter().any(|attr| attr.key == "ice-options"));
        assert!(attrs.iter().any(|attr| attr.key == "end-of-candidates"));
        assert!(attrs.iter().filter(|attr| attr.key == "candidate").count() >= 1);
        assert!(attrs.iter().any(|attr| {
            attr.key == "rtpmap"
                && attr
                    .value
                    .as_deref()
                    .map(|v| v.contains("opus"))
                    .unwrap_or(false)
        }));
        assert!(attrs.iter().any(|attr| attr.key == "fingerprint"));
        assert!(attrs.iter().any(|attr| {
            attr.key == "setup"
                && attr
                    .value
                    .as_deref()
                    .map(|v| v == "actpass")
                    .unwrap_or(false)
        }));
        assert_eq!(pc.signaling_state(), SignalingState::Stable);
    }

    #[tokio::test]
    async fn offer_includes_video_capabilities() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);
        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];
        assert_eq!(section.kind, MediaKind::Video);
        assert_eq!(section.formats, vec![VIDEO_PAYLOAD_TYPE.to_string()]);
        let attrs = &section.attributes;
        assert!(attrs.iter().any(|attr| attr.key == "rtcp-fb"));
        assert!(attrs.iter().any(|attr| {
            attr.key == "rtpmap"
                && attr
                    .value
                    .as_deref()
                    .map(|v| v.contains("VP8"))
                    .unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn offer_includes_application_capabilities() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Application, TransceiverDirection::SendRecv);
        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];
        assert_eq!(section.kind, MediaKind::Application);
        assert_eq!(section.protocol, "UDP/DTLS/SCTP");
        assert_eq!(section.formats, vec![SCTP_FORMAT.to_string()]);
        let attrs = &section.attributes;
        let expected_port = SCTP_PORT.to_string();
        assert!(attrs.iter().any(|attr| {
            attr.key == "sctp-port"
                && attr
                    .value
                    .as_deref()
                    .map(|v| v == expected_port)
                    .unwrap_or(false)
        }));
    }

    #[tokio::test]
    async fn test_simulcast_setup() {
        use crate::{SdpType, SessionDescription};
        let pc = PeerConnection::new(RtcConfiguration::default());

        // Create SDP with Simulcast
        // We need to include extmap for RID
        let sdp_str = "v=0\r\n\
                       o=- 123456 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       a=extmap:3 urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id\r\n\
                       c=IN IP4 127.0.0.1\r\n\
                       m=video 9 RTP/SAVPF 96\r\n\
                       a=rtpmap:96 VP8/90000\r\n\
                       a=rid:hi send\r\n\
                       a=rid:mid send\r\n\
                       a=rid:lo send\r\n\
                       a=simulcast:send hi;mid;lo\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let transceivers = pc.inner.transceivers.lock().unwrap();
        assert_eq!(transceivers.len(), 1);
        let t = &transceivers[0];
        let rx = t.receiver.lock().unwrap().as_ref().unwrap().clone();

        // Check simulcast tracks
        let simulcast_tracks = rx.simulcast_tracks.lock().unwrap();
        assert!(simulcast_tracks.contains_key("hi"));
        assert!(simulcast_tracks.contains_key("mid"));
        assert!(simulcast_tracks.contains_key("lo"));
        assert_eq!(simulcast_tracks.len(), 3);
    }

    #[tokio::test]
    async fn test_rtcp_mux_detection() {
        use crate::{SdpType, SessionDescription, TransportMode};
        // Setup PC in RTP mode
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Create SDP without rtcp-mux
        let sdp_str = "v=0\r\n\
                       o=- 123456 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       c=IN IP4 127.0.0.1\r\n\
                       m=audio 4000 RTP/AVP 111\r\n\
                       a=rtpmap:111 opus/48000/2\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();

        pc.set_remote_description(desc).await.unwrap();

        // Wait for connection
        let mut state_rx = pc.subscribe_peer_state();
        loop {
            if *state_rx.borrow() == PeerConnectionState::Connected {
                break;
            }
            state_rx.changed().await.unwrap();
        }

        // Now check IceConn
        let rtp_transport = pc.inner.rtp_transport.lock().unwrap().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read().unwrap();

        assert!(rtcp_addr.is_some());
        assert_eq!(rtcp_addr.unwrap().port(), 4001);
    }

    #[tokio::test]
    async fn test_rtcp_mux_enabled() {
        use crate::{SdpType, SessionDescription, TransportMode};
        // Setup PC in RTP mode
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Create SDP WITH rtcp-mux
        let sdp_str = "v=0\r\n\
                       o=- 123456 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       c=IN IP4 127.0.0.1\r\n\
                       m=audio 4000 RTP/AVP 111\r\n\
                       a=rtcp-mux\r\n\
                       a=rtpmap:111 opus/48000/2\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();

        pc.set_remote_description(desc).await.unwrap();

        let mut state_rx = pc.subscribe_peer_state();
        loop {
            if *state_rx.borrow() == PeerConnectionState::Connected {
                break;
            }
            state_rx.changed().await.unwrap();
        }

        let rtp_transport = pc.inner.rtp_transport.lock().unwrap().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read().unwrap();

        assert!(rtcp_addr.is_none());
    }

    #[tokio::test]
    async fn set_local_description_transitions_state() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer.clone()).unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);

        let mut answer = offer.clone();
        answer.sdp_type = SdpType::Answer;
        pc.set_remote_description(answer).await.unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::Stable);
    }

    #[tokio::test]
    async fn create_answer_requires_remote_offer() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendOnly);
        let err = pc.create_answer().await.unwrap_err();
        assert!(matches!(err, RtcError::InvalidState(_)));

        let offer = pc.create_offer().await.unwrap();
        pc.set_remote_description(offer.clone()).await.unwrap();
        let answer = pc.create_answer().await.unwrap();
        assert_eq!(answer.media_sections.len(), 1);
        assert_eq!(answer.media_sections[0].direction, Direction::RecvOnly);
        pc.set_local_description(answer).unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::Stable);
    }

    #[tokio::test]
    async fn remote_answer_without_local_offer_is_error() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
        let mut fake_answer = pc.create_offer().await.unwrap();
        fake_answer.sdp_type = SdpType::Answer;
        let err = pc.set_remote_description(fake_answer).await.unwrap_err();
        assert!(matches!(err, RtcError::InvalidState(_)));
    }

    #[tokio::test]
    async fn peer_connection_exposes_ice_transport() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        let ice = pc.ice_transport();
        assert_eq!(ice.state(), IceTransportState::New);
        assert_eq!(ice.config().ice_servers.len(), 0);
    }

    #[tokio::test]
    async fn create_offer_rtp_mode() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        // Add a sender so direction is not downgraded and RTP mode can advertise SSRC.
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 111,
            clock_rate: 48000,
            channels: 2,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("stream".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];

        // Should NOT have ICE attributes
        assert!(!section.attributes.iter().any(|a| a.key == "ice-ufrag"));
        assert!(!section.attributes.iter().any(|a| a.key == "candidate"));

        // Should NOT have DTLS fingerprint
        assert!(!section.attributes.iter().any(|a| a.key == "fingerprint"));

        // Should NOT have msid-semantic
        assert!(
            !offer
                .session
                .attributes
                .iter()
                .any(|a| a.key == "msid-semantic")
        );

        // Should NOT have msid in media section
        assert!(!section.attributes.iter().any(|a| a.key == "msid"));

        // Should have ssrc in media section
        assert!(section.attributes.iter().any(|a| a.key == "ssrc"));

        // Protocol should be RTP/AVP
        assert_eq!(section.protocol, "RTP/AVP");
    }

    #[tokio::test]
    async fn create_offer_srtp_mode() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Srtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];

        // Should NOT have ICE attributes
        assert!(!section.attributes.iter().any(|a| a.key == "ice-ufrag"));
        assert!(!section.attributes.iter().any(|a| a.key == "candidate"));

        // Should have DTLS fingerprint
        assert!(section.attributes.iter().any(|a| a.key == "fingerprint"));

        // Protocol should be UDP/TLS/RTP/SAVPF
        assert_eq!(section.protocol, "UDP/TLS/RTP/SAVPF");
    }

    #[tokio::test]
    async fn test_ssrc_parsing_with_fid_group() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pc = PeerConnection::new(RtcConfiguration::default());

        // Mock SDP
        let sdp_str = "v=0\r\n\
o=- 123456 123456 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 127.0.0.1\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:12345 cname:foo\r\n\
a=ssrc:67890 cname:foo\r\n\
a=ssrc-group:FID 12345 67890\r\n";

        let sdp =
            crate::sdp::SessionDescription::parse(crate::sdp::SdpType::Offer, sdp_str).unwrap();
        pc.set_remote_description(sdp).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);
        let t = &transceivers[0];
        let receiver = t.receiver().unwrap();

        assert_eq!(receiver.ssrc(), 12345);
        assert_eq!(receiver.rtx_ssrc(), Some(67890));
    }

    #[tokio::test]
    async fn test_ssrc_parsing_with_fid_group_before_ssrc() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pc = PeerConnection::new(RtcConfiguration::default());

        // Mock SDP
        let sdp_str = "v=0\r\n\
o=- 123456 123456 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 127.0.0.1\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc-group:FID 12345 67890\r\n\
a=ssrc:12345 cname:foo\r\n\
a=ssrc:67890 cname:foo\r\n";

        let sdp =
            crate::sdp::SessionDescription::parse(crate::sdp::SdpType::Offer, sdp_str).unwrap();
        pc.set_remote_description(sdp).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);
        let t = &transceivers[0];
        let receiver = t.receiver().unwrap();

        assert_eq!(receiver.ssrc(), 12345);
        assert_eq!(receiver.rtx_ssrc(), Some(67890));
    }

    #[tokio::test]
    async fn test_ssrc_parsing_rtx_first_group_last() {
        let _ = env_logger::builder().is_test(true).try_init();
        let pc = PeerConnection::new(RtcConfiguration::default());

        // Mock SDP: RTX (67890) comes before Primary (12345), and Group is last.
        let sdp_str = "v=0\r\n\
o=- 123456 123456 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
c=IN IP4 127.0.0.1\r\n\
a=mid:0\r\n\
a=sendrecv\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=ssrc:67890 cname:foo\r\n\
a=ssrc:12345 cname:foo\r\n\
a=ssrc-group:FID 12345 67890\r\n";

        let sdp =
            crate::sdp::SessionDescription::parse(crate::sdp::SdpType::Offer, sdp_str).unwrap();
        pc.set_remote_description(sdp).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);
        let t = &transceivers[0];
        let receiver = t.receiver().unwrap();

        println!("SSRC: {}", receiver.ssrc());
        println!("RTX SSRC: {:?}", receiver.rtx_ssrc());
        assert_eq!(receiver.ssrc(), 12345); // Should be Primary
        assert_eq!(receiver.rtx_ssrc(), Some(67890));
    }

    #[test]
    fn test_sdes_key_generation_and_parsing() {
        let params = generate_sdes_key_params();
        assert!(params.starts_with("inline:"));

        let key = parse_sdes_key_params(&params).expect("Failed to parse generated params");
        assert_eq!(key.len(), 30); // 30 bytes for AES_CM_128_HMAC_SHA1_80 (16 key + 14 salt)

        // Test invalid params
        assert!(parse_sdes_key_params("invalid").is_err());
        assert!(parse_sdes_key_params("inline:invalid_base64").is_err());
    }

    #[tokio::test]
    async fn create_offer_srtp_mode_includes_crypto() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Srtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];

        // Should have crypto attribute
        let crypto = section.attributes.iter().find(|a| a.key == "crypto");
        assert!(crypto.is_some(), "Missing crypto attribute in SRTP mode");

        let crypto_val = crypto.unwrap().value.as_ref().unwrap();
        assert!(crypto_val.starts_with("1 AES_CM_128_HMAC_SHA1_80 inline:"));
    }

    #[tokio::test]
    async fn test_receiver_nack_handler() {
        use crate::rtp::RtpHeader;
        let handler = DefaultRtpReceiverNackHandler::new();
        let mut header = RtpHeader::new(96, 100, 0, 1234);
        let packet1 = RtpPacket::new(header.clone(), vec![1, 2, 3]);

        // First packet initializes
        assert!(handler.on_packet_received(&packet1).await.is_none());

        // Consecutive packet
        header.sequence_number = 101;
        let packet2 = RtpPacket::new(header.clone(), vec![4, 5, 6]);
        assert!(handler.on_packet_received(&packet2).await.is_none());

        // Gap detected (102 missing)
        header.sequence_number = 103;
        let packet3 = RtpPacket::new(header.clone(), vec![7, 8, 9]);
        let res = handler
            .on_packet_received(&packet3)
            .await
            .expect("Should generate NACK");
        if let RtcpPacket::GenericNack(nack) = res {
            assert_eq!(nack.lost_packets, vec![102]);
            assert_eq!(nack.media_ssrc, 1234);
        } else {
            panic!("Expected GenericNack");
        }

        // Multiple gap detected (104, 105 missing)
        header.sequence_number = 106;
        let packet4 = RtpPacket::new(header.clone(), vec![10]);
        let res = handler
            .on_packet_received(&packet4)
            .await
            .expect("Should generate NACK");
        if let RtcpPacket::GenericNack(nack) = res {
            assert_eq!(nack.lost_packets, vec![104, 105]);
        } else {
            panic!("Expected GenericNack");
        }
    }

    #[tokio::test]
    async fn test_sender_nack_handler() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::conn::IceConn;
        use crate::transports::rtp::RtpTransport;
        use std::net::{Ipv4Addr, SocketAddr};

        let handler = DefaultRtpSenderNackHandler::new(10);
        let mut header = RtpHeader::new(96, 100, 0, 1234);
        let packet1 = RtpPacket::new(header.clone(), vec![1, 2, 3]);

        handler.on_packet_sent(&packet1).await;

        // Mock transport (we just need it to not crash, though it won't actually send)
        let (_, socket_rx) = tokio::sync::watch::channel(None);
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);
        let ice_conn = IceConn::new(socket_rx, addr);
        let transport = Arc::new(RtpTransport::new(ice_conn, false));

        let nack = GenericNack {
            sender_ssrc: 0,
            media_ssrc: 1234,
            lost_packets: vec![100],
        };

        // This will retransmit
        handler
            .on_rtcp_received(&RtcpPacket::GenericNack(nack), transport)
            .await;

        // Buffer overflow test
        for i in 101..115 {
            header.sequence_number = i;
            handler
                .on_packet_sent(&RtpPacket::new(header.clone(), vec![0]))
                .await;
        }

        // Packet 100 should be gone now (buffer size 10, we sent 14 more)
        let nack_old = GenericNack {
            sender_ssrc: 0,
            media_ssrc: 1234,
            lost_packets: vec![100],
        };

        // We can't easily check if it was sent without a mock transport that records sends,
        // but we can at least verify it doesn't panic and the logic runs.
        let (_, socket_rx2) = tokio::sync::watch::channel(None);
        let ice_conn2 = IceConn::new(socket_rx2, addr);
        let transport2 = Arc::new(RtpTransport::new(ice_conn2, false));
        handler
            .on_rtcp_received(&RtcpPacket::GenericNack(nack_old), transport2)
            .await;
    }

    #[tokio::test]
    async fn test_nack_configuration() {
        let mut config = RtcConfiguration::default();
        config.nack_buffer_size = 200;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        // Check receiver has handler
        let receiver = transceiver.receiver().unwrap();
        assert!(receiver.nack_handler().is_some());

        // Check sender has handler
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Video, 90000);
        let sender = pc
            .add_track_with_stream_id(track, "stream1".to_string(), RtpCodecParameters::default())
            .unwrap();
        assert!(sender.nack_handler().is_some());
    }
}
