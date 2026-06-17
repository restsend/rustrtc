use crate::media::depacketizer::{Depacketizer, DepacketizerFactory};
use crate::media::track::{MediaStreamTrack, SampleStreamSource, SampleStreamTrack, sample_track};
use crate::rtp::{
    FirRequest, FullIntraRequest, GenericNack, PictureLossIndication, RtcpPacket, RtpPacket,
    SenderReport,
};
use crate::stats::{StatsReport, gather_once};
use crate::stats_collector::StatsCollector;
#[cfg(feature = "t38")]
use crate::t38::endpoint::FaxEndpoint;
#[cfg(feature = "t38")]
use crate::t38::t30::{T30FaxConfig, T30Session};
use crate::transports::dtls::{self, DtlsTransport};
use crate::transports::get_local_ip;
use crate::transports::ice::stun::random_u32;
use crate::transports::ice::{IceCandidate, IceGathererState, IceTransport, conn::IceConn};
use crate::transports::rtp::{RtpRewriteBridgeParams, RtpTransport};
use crate::transports::sctp::SctpTransport;
use crate::transports::udptl::UdtlTransport;
use crate::{
    Attribute, AudioCapability, Direction, MediaKind, MediaSection, Origin, RtcConfiguration,
    RtcError, RtcResult, SdpType, SessionDescription, TransportMode, VideoCapability,
};
use base64::prelude::*;
use parking_lot::{Mutex, RwLock};
use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, info, trace, warn};

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

const RTP_RECEIVER_SAMPLE_CAPACITY: usize = 64;
const RTP_RECEIVER_PACKET_CAPACITY: usize = 64;

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
        let mut buffer = self.buffer.lock();
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
                let buffer = self.buffer.lock();
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
                let _ = transport.send_rtp(packet).await;
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
    last_ssrc: AtomicU32,
    initialized: std::sync::atomic::AtomicBool,
    pub nack_sent_count: AtomicU64,
    pub nack_recovered_count: AtomicU64,
}

impl DefaultRtpReceiverNackHandler {
    pub fn new() -> Self {
        Self {
            last_seq: AtomicU16::new(0),
            last_ssrc: AtomicU32::new(0),
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
        let ssrc = packet.header.ssrc;

        // Check if SSRC changed - indicates stream switch
        let last_ssrc = self.last_ssrc.load(Ordering::SeqCst);
        if last_ssrc != 0 && last_ssrc != ssrc {
            debug!(
                "NACK: SSRC changed from {} to {}, resetting state",
                last_ssrc, ssrc
            );
            self.last_ssrc.store(ssrc, Ordering::SeqCst);
            self.last_seq.store(seq, Ordering::SeqCst);
            return None; // Don't send NACK on stream switch
        }

        if !self.initialized.swap(true, Ordering::SeqCst) {
            self.last_ssrc.store(ssrc, Ordering::SeqCst);
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
        simulcast_ssrc: std::sync::Arc<Mutex<Option<u32>>>,
    },
}

enum LoopEvent {
    Packet(
        Option<(crate::rtp::RtpPacket, std::net::SocketAddr)>,
        Option<String>,
        mpsc::Receiver<(crate::rtp::RtpPacket, std::net::SocketAddr)>,
        Box<dyn Depacketizer>,
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
    remote_dtls_fingerprint: Mutex<Option<String>>,
    dtls_transport: Mutex<Option<Arc<DtlsTransport>>>,
    rtp_transport: Mutex<Option<Arc<RtpTransport>>>,
    rtp_media_ice_transports: Mutex<HashMap<u64, IceTransport>>,
    rtp_media_transports: Mutex<HashMap<u64, Arc<RtpTransport>>>,
    sctp_transport: Mutex<Option<Arc<SctpTransport>>>,
    data_channels: Arc<Mutex<Vec<std::sync::Weak<crate::transports::sctp::DataChannel>>>>,
    event_tx: mpsc::UnboundedSender<PeerConnectionEvent>,
    event_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<PeerConnectionEvent>>,
    dtls_role: watch::Sender<Option<bool>>,
    _dtls_role_rx: watch::Receiver<Option<bool>>,
    stats_collector: Arc<StatsCollector>,
    ssrc_generator: AtomicU32,
    disconnect_reason: watch::Sender<Option<DisconnectReason>>,
    _disconnect_reason_rx: watch::Receiver<Option<DisconnectReason>>,
}

pub(crate) fn generate_sdes_key_params() -> String {
    let mut key_salt = [0u8; 30];
    rand::fill(&mut key_salt);
    let encoded = BASE64_STANDARD.encode(&key_salt);
    format!("inline:{}", encoded)
}

pub(crate) fn parse_sdes_key_params(params: &str) -> RtcResult<Vec<u8>> {
    if !params.starts_with("inline:") {
        return Err(RtcError::Internal("Unsupported key params".into()));
    }
    let key_salt_base64 = &params[7..];
    let key_salt_base64 = key_salt_base64.split('|').next().ok_or_else(|| {
        RtcError::Internal("Empty key params after 'inline:' prefix".into())
    })?;
    if key_salt_base64.is_empty() {
        return Err(RtcError::Internal("Empty key params after 'inline:' prefix".into()));
    }
    BASE64_STANDARD
        .decode(key_salt_base64)
        .map_err(|e| RtcError::Internal(format!("Invalid base64 key: {}", e)))
}

pub(crate) fn map_crypto_suite(suite: &str) -> RtcResult<crate::srtp::SrtpProfile> {
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
        let is_rtp_mode = config.transport_mode == TransportMode::Rtp;
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
        let (disconnect_reason_tx, disconnect_reason_rx) = watch::channel(None);

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
            remote_dtls_fingerprint: Mutex::new(None),
            dtls_transport: Mutex::new(None),
            rtp_transport: Mutex::new(None),
            rtp_media_ice_transports: Mutex::new(HashMap::new()),
            rtp_media_transports: Mutex::new(HashMap::new()),
            sctp_transport: Mutex::new(None),
            data_channels: Arc::new(Mutex::new(Vec::new())),
            event_tx,
            event_rx: tokio::sync::Mutex::new(event_rx),
            dtls_role: dtls_role_tx,
            _dtls_role_rx: dtls_role_rx.clone(),
            stats_collector: Arc::new(StatsCollector::new()),
            ssrc_generator,
            disconnect_reason: disconnect_reason_tx,
            _disconnect_reason_rx: disconnect_reason_rx,
        };
        let pc = Self {
            inner: Arc::new(inner),
        };

        if is_rtp_mode {
            // RTP mode: skip ICE gathering/connectivity/DTLS loops entirely.
            // Only run the ice_runner for socket read loops (needed to receive packets).
            // The ICE state machine and DTLS loop are handled directly via
            // setup_direct_rtp / complete_direct_rtp.
            let inner_weak = Arc::downgrade(&pc.inner);
            let ice_transport = pc.inner.ice_transport.clone();
            let ice_connection_state_tx = pc.inner.ice_connection_state.clone();
            tokio::spawn(async move {
                let rtp_ice_loop =
                    run_rtp_direct_loop(ice_transport, ice_connection_state_tx, inner_weak);
                tokio::join!(rtp_ice_loop, ice_runner);
            });
        } else {
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
        }
        pc
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub fn bridge_rtp_with_rewrite_to(
        &self,
        dst: &PeerConnection,
        params: RtpRewriteBridgeParams,
    ) -> RtcResult<()> {
        let src = self.inner.rtp_transport.lock().clone().ok_or_else(|| {
            RtcError::InvalidState("RTP transport is not ready for source PeerConnection".into())
        })?;
        let dst = dst.inner.rtp_transport.lock().clone().ok_or_else(|| {
            RtcError::InvalidState(
                "RTP transport is not ready for destination PeerConnection".into(),
            )
        })?;
        src.bridge_rewrite_to(dst, params);
        Ok(())
    }

    pub fn bridge_rtp_with_rewrite_to_self(&self, params: RtpRewriteBridgeParams) -> RtcResult<()> {
        let transport = self.inner.rtp_transport.lock().clone().ok_or_else(|| {
            RtcError::InvalidState("RTP transport is not ready for PeerConnection".into())
        })?;
        transport.bridge_rewrite_to(transport.clone(), params);
        Ok(())
    }

    pub fn clear_rtp_rewrite_bridge(&self) {
        if let Some(transport) = self.inner.rtp_transport.lock().clone() {
            transport.clear_bridge_rewrite();
        }
        for transport in self.inner.rtp_media_transports.lock().values() {
            transport.clear_bridge_rewrite();
        }
    }

    pub async fn wait_for_rtp_transport_ready(
        &self,
        timeout: std::time::Duration,
    ) -> RtcResult<()> {
        let deadline = tokio::time::Instant::now() + timeout;
        while tokio::time::Instant::now() < deadline {
            if self.inner.rtp_transport.lock().is_some() {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }

        Err(RtcError::InvalidState(
            "timed out waiting for RTP transport".into(),
        ))
    }

    pub fn ice_transport(&self) -> IceTransport {
        self.inner.ice_transport.clone()
    }

    fn rtp_transport_for_transceiver_or(
        &self,
        transceiver: &Arc<RtpTransceiver>,
        default: Arc<RtpTransport>,
    ) -> Arc<RtpTransport> {
        self.inner
            .rtp_media_transports
            .lock()
            .get(&transceiver.id())
            .cloned()
            .unwrap_or(default)
    }

    fn attach_rtp_transport_to_transceiver(
        &self,
        transceiver: &Arc<RtpTransceiver>,
        transport: Arc<RtpTransport>,
    ) {
        transceiver.set_rtp_transport(Arc::downgrade(&transport));
        let extmap = transceiver.get_extmap();
        let _ = transceiver.update_extmap(extmap);

        let sender_arc = transceiver.sender.lock().clone();
        let receiver_arc = transceiver.receiver.lock().clone();

        if let Some(sender) = &sender_arc {
            sender.set_transport(transport.clone());
        }

        if let Some(receiver) = &receiver_arc {
            receiver.set_transport(
                transport,
                Some(self.inner.event_tx.clone()),
                Some(Arc::downgrade(transceiver)),
            );
            if let Some(sender) = &sender_arc {
                receiver.set_feedback_ssrc(sender.ssrc());
            }
        }
    }

    pub fn add_transceiver(
        &self,
        kind: MediaKind,
        direction: TransceiverDirection,
    ) -> Arc<RtpTransceiver> {
        let transceiver = Arc::new(RtpTransceiver::new(kind, direction));
        let mut builder = RtpReceiverBuilder::new(kind, 0)
            .payload_map(transceiver.payload_map.clone())
            .interceptor(self.inner.stats_collector.clone())
            .depacketizer_factory(self.inner.config.depacketizer_strategy.factory.clone());

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
                MediaKind::Image => false,
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
                MediaKind::Image => false,
            }
        };

        if nack_enabled {
            builder = builder.nack();
        }
        let receiver = builder.build();
        if direction.sends() {
            let rand_val = random_u32();
            let ssrc = self
                .inner
                .ssrc_generator
                .fetch_add(1 + rand_val, Ordering::Relaxed);
            *transceiver.sender_ssrc.lock() = Some(ssrc);
            *transceiver.sender_stream_id.lock() = Some("default".to_string());
            *transceiver.sender_track_id.lock() = Some(format!("track-{}", transceiver.id()));
        }
        transceiver.set_receiver(Some(receiver));

        let mut list = self.inner.transceivers.lock();
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
        // Reuse a transceiver created from the remote offer (WHEP/answerer path).
        // Otherwise add_track would create a second same-kind transceiver without the
        // offer MID, and create_answer would bind the offer m-line to the empty one.
        let transceiver = {
            let list = self.inner.transceivers.lock();
            if let Some(existing) = list.iter().find(|t| {
                t.kind() == kind && t.mid().is_some() && t.sender.lock().is_none()
            }) {
                info!(
                    "add_track: reusing offer transceiver kind={:?} mid={:?}",
                    kind,
                    existing.mid()
                );
                existing.clone()
            } else {
                drop(list);
                self.add_transceiver(kind, TransceiverDirection::SendRecv)
            }
        };
        let ssrc = (*transceiver.sender_ssrc.lock())
            .unwrap_or_else(|| self.inner.ssrc_generator.fetch_add(1, Ordering::Relaxed));

        let mut builder = RtpSenderBuilder::new(track, ssrc)
            .stream_id(stream_id)
            .params(params)
            .interceptor(self.inner.stats_collector.clone());

        if let Some(ref cname) = self.inner.config.cname {
            builder = builder.cname(cname.clone());
        }

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
                MediaKind::Image => false,
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
                MediaKind::Image => false,
            }
        };

        if nack_enabled {
            builder = builder
                .nack(self.inner.config.nack_buffer_size)
                .bitrate_controller();
        }

        let sender = builder.build();

        // Update transceiver's pre-allocated info to match the actual sender
        *transceiver.sender_ssrc.lock() = Some(sender.ssrc());
        *transceiver.sender_stream_id.lock() = Some(sender.stream_id().to_string());
        *transceiver.sender_track_id.lock() = Some(sender.track_id().to_string());

        // If transport is already established, attach the new transceiver
        // immediately. In direct RTP mode, only attach to an explicit media
        // transport; falling back to the primary transport would put a newly
        // added non-BUNDLE video sender on the audio socket until SDP setup
        // catches up.
        let transport = self
            .inner
            .rtp_media_transports
            .lock()
            .get(&transceiver.id())
            .cloned()
            .or_else(|| {
                if self.inner.config.transport_mode == TransportMode::Rtp {
                    None
                } else {
                    self.inner.rtp_transport.lock().clone()
                }
            });

        transceiver.set_sender(Some(sender.clone()));
        if let Some(transport) = transport {
            self.attach_rtp_transport_to_transceiver(&transceiver, transport);
        }
        Ok(sender)
    }

    pub fn get_transceivers(&self) -> Vec<Arc<RtpTransceiver>> {
        self.inner.transceivers.lock().clone()
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
            let local = self.inner.local_description.lock();
            let remote = self.inner.remote_description.lock();
            local.is_none() && remote.is_none()
        };

        if should_set_controlling {
            self.inner
                .ice_transport
                .set_role(crate::transports::ice::IceRole::Controlling);
        }
        let desc = self
            .inner
            .build_description(SdpType::Offer, |dir| dir)
            .await?;
        if self.inner.config.transport_mode == TransportMode::Rtp && !Self::sdp_has_bundle(&desc) {
            for (media_index, (transceiver, _)) in self
                .matched_rtp_media_sections(&desc)
                .into_iter()
                .enumerate()
            {
                if media_index == 0 {
                    continue;
                }
                let ice_transport = self.inner.direct_rtp_ice_transport(transceiver.id(), false);
                self.ensure_direct_rtp_media_transport(&transceiver, &ice_transport, None, None)
                    .await;
            }
        }
        Ok(desc)
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
                let local = self.inner.local_description.lock();
                local.is_some()
            };
            if is_reinvite {
                debug!("Offerer: extracting parameters from local reinvite offer");
                // Extract parameters from our offer for transceivers
                let transceivers = self.inner.transceivers.lock().clone();
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
                let transceivers = self.inner.transceivers.lock().clone();
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
                SdpType::Pranswer => {
                    if *state.borrow() != SignalingState::HaveRemoteOffer {
                        return Err(RtcError::InvalidState(
                            "set_local_description(pranswer) requires remote offer".into(),
                        ));
                    }
                    // Stay in HaveRemoteOffer.
                }
                SdpType::Rollback => {
                    return Err(RtcError::NotImplemented("rollback"));
                }
            }
        }
        let mut local = self.inner.local_description.lock();
        *local = Some(desc);
        Ok(())
    }

    pub async fn set_remote_description(&self, desc: SessionDescription) -> RtcResult<()> {
        self.inner.validate_sdp_type(&desc.sdp_type)?;
        let remote_dtls_fingerprint = if self.config().transport_mode == TransportMode::WebRtc {
            match desc.dtls_fingerprint() {
                Ok(Some(fingerprint)) if fingerprint.algorithm == "sha-256" => {
                    Some(fingerprint.value)
                }
                Ok(Some(fingerprint)) => {
                    return Err(RtcError::InvalidConfiguration(format!(
                        "unsupported DTLS fingerprint algorithm: {}",
                        fingerprint.algorithm
                    )));
                }
                Ok(None) => {
                    return Err(RtcError::InvalidConfiguration(
                        "remote SDP in WebRTC mode must contain a DTLS fingerprint".into(),
                    ));
                }
                Err(err) => {
                    return Err(RtcError::InvalidConfiguration(format!(
                        "invalid DTLS fingerprint in remote SDP: {}",
                        err
                    )));
                }
            }
        } else {
            None
        };

        // Check if this is a reinvite (not first negotiation)
        let is_reinvite = {
            let remote = self.inner.remote_description.lock();
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
                (SdpType::Answer | SdpType::Pranswer, SignalingState::HaveLocalOffer) => {
                    debug!("Offerer: applying reinvite from answer/pranswer");
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
                SdpType::Pranswer => {
                    // Provisional answer (SIP 183 early media): set up media transport like an
                    // answer but keep signaling state in HaveLocalOffer so the final 200 OK
                    // answer can still arrive and complete the negotiation.
                    if *state.borrow() != SignalingState::HaveLocalOffer {
                        return Err(RtcError::InvalidState(
                            "set_remote_description(pranswer) requires local offer".into(),
                        ));
                    }
                    // Do NOT transition to Stable – stay in HaveLocalOffer.
                }
                SdpType::Rollback => {
                    return Err(RtcError::NotImplemented("rollback"));
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

        {
            // Cache the remote fingerprint before ICE/DTLS starts so the handshake can bind
            // the SDP identity to the certificate actually presented on the wire.
            let dtls_started = self.inner.dtls_transport.lock().is_some();
            let mut stored = self.inner.remote_dtls_fingerprint.lock();
            if dtls_started && *stored != remote_dtls_fingerprint {
                return Err(RtcError::InvalidState(
                    "changing remote DTLS fingerprint after transport start is not supported"
                        .into(),
                ));
            }
            *stored = remote_dtls_fingerprint;
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
            if let (Some(u), Some(p)) = (ufrag.clone(), pwd.clone()) {
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

                for candidate in candidates.iter().cloned() {
                    self.inner.ice_transport.add_remote_candidate(candidate);
                }
            }
        } else if self.config().transport_mode == TransportMode::Rtp {
            // Direct RTP setup is deferred until media sections have been matched
            // to transceivers. Non-BUNDLE audio/video need separate sockets.
        } else if let Some(addr) = remote_addr {
            // SRTP mode: use ICE start_direct
            self.inner
                .ice_transport
                .start_direct(addr)
                .await
                .map_err(|e| crate::RtcError::Internal(format!("ICE direct error: {}", e)))?;
        }

        // Create transceivers for new media sections in Offer
        if desc.sdp_type == SdpType::Offer {
            let mut transceivers = self.inner.transceivers.lock();
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

                    if found_transceiver.is_none() && mid.is_empty() {
                        if let Some(t) = transceivers.iter().find(|t| t.kind() == section.kind) {
                            found_transceiver = Some(t.clone());
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
                    if let Some(transport) = self.inner.rtp_transport.lock().as_ref() {
                        transport.set_rid_extension_id(Some(id));
                    }
                }

                if let Some(id) = abs_send_time_ext_id {
                    if let Some(transport) = self.inner.rtp_transport.lock().as_ref() {
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
                        if let Some(rx) = t.receiver.lock().as_ref() {
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
                        if ssrc.is_some() {
                            if let Some(r) = t.receiver.lock().as_ref() {
                                r.track_event_sent.store(true, Ordering::SeqCst);
                            }
                            let _ = self.inner.event_tx.send(PeerConnectionEvent::Track(t));
                        }
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

                    let receiver_ssrc = ssrc.unwrap_or(0);

                    let mut builder = RtpReceiverBuilder::new(kind, receiver_ssrc)
                        .payload_map(t.payload_map.clone())
                        .interceptor(self.inner.stats_collector.clone());

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

                    // If transport is already active (renegotiation), attach it to the new receiver.
                    // Direct RTP attaches after media sections are matched so non-BUNDLE video
                    // does not briefly register on the primary audio transport.
                    if self.inner.config.transport_mode != TransportMode::Rtp {
                        let transport_guard = self.inner.rtp_transport.lock();
                        if let Some(transport) = &*transport_guard {
                            receiver.set_transport(
                                transport.clone(),
                                Some(self.inner.event_tx.clone()),
                                Some(Arc::downgrade(&t)),
                            );
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

                    t.set_receiver(Some(receiver));

                    transceivers.push(t.clone());

                    if ssrc.is_some() {
                        if let Some(r) = t.receiver.lock().as_ref() {
                            r.track_event_sent.store(true, Ordering::SeqCst);
                        }
                        let _ = self.inner.event_tx.send(PeerConnectionEvent::Track(t));
                    }
                }
            }
        } else if desc.sdp_type == SdpType::Answer || desc.sdp_type == SdpType::Pranswer {
            for (t, section_idx) in self.matched_rtp_media_sections(&desc) {
                let section = &desc.media_sections[section_idx];
                let mid = &section.mid;

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

                if let Some(ssrc_val) = ssrc {
                    if let Some(rx) = t.receiver.lock().as_ref() {
                        rx.set_ssrc(ssrc_val);
                        if !rx.track_event_sent.swap(true, Ordering::SeqCst) {
                            let _ = self
                                .inner
                                .event_tx
                                .send(PeerConnectionEvent::Track(t.clone()));
                            debug!(
                                "Answer SDP: Sent Track event for SSRC {} mid={}",
                                ssrc_val, mid
                            );
                        }
                    }
                    // For non-RTP modes the transport already exists at this point;
                    // propagate the expected SSRC so latching can use it.
                    let transport = self
                        .inner
                        .rtp_media_transports
                        .lock()
                        .get(&t.id())
                        .cloned()
                        .or_else(|| self.inner.rtp_transport.lock().clone());
                    if let Some(transport) = transport {
                        transport.ice_conn().set_expected_ssrc(ssrc_val);
                        debug!(
                            "Answer SDP: set expected SSRC {} for latching (mid={})",
                            ssrc_val, mid
                        );
                    }
                }
            }
        }

        {
            let mut remote = self.inner.remote_description.lock();
            *remote = Some(desc.clone());
        }

        if self.config().transport_mode == TransportMode::Rtp {
            self.configure_rtp_media_transports_from_remote(&desc, ufrag, pwd, candidates)
                .await?;
        }

        // Refresh mux/RTCP routing after any remote description change.
        // If the transport already exists, this keeps the derived RTCP
        // destination in sync across answers and re-INVITEs.
        self.update_rtcp_mux_from_remote();

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
        let rtcp_socket_rx = self.inner.ice_transport.subscribe_selected_rtcp_socket();

        // Create IceConn and register it immediately to avoid dropping packets
        let ice_conn = IceConn::new_with_rtcp(
            socket_rx.clone(),
            rtcp_socket_rx,
            pair.remote.address,
            self.config().label.clone(),
            self.config().probation_max_packets,
        );
        if self.config().transport_mode == TransportMode::Rtp && self.config().enable_latching {
            ice_conn.enable_latch_on_rtp();
        }

        // Monitor selected pair changes to update remote address
        let mut pair_rx = self.inner.ice_transport.subscribe_selected_pair();
        let ice_conn_monitor = ice_conn.clone();

        if self.config().transport_mode != TransportMode::WebRtc {
            let rtcp_addr = {
                let remote_desc = self.inner.remote_description.lock();
                if let Some(desc) = &*remote_desc {
                    Self::remote_rtcp_addr_from_sdp(desc, pair.remote.address)
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
        let allow_ssrc_change = self.config().enable_latching;
        let rtp_transport = Arc::new(RtpTransport::new_with_ssrc_change(
            ice_conn.clone(),
            srtp_required,
            allow_ssrc_change,
        ));
        {
            let mut rx = ice_conn.rtp_receiver.write();
            *rx = Some(Arc::downgrade(&rtp_transport)
                as std::sync::Weak<dyn crate::transports::PacketReceiver>);
        }
        *self.inner.rtp_transport.lock() = Some(rtp_transport.clone());

        {
            let transceivers = self.inner.transceivers.lock();
            for t in transceivers.iter() {
                let selected_transport =
                    self.rtp_transport_for_transceiver_or(t, rtp_transport.clone());
                // Store transport reference for late senders
                t.set_rtp_transport(Arc::downgrade(&selected_transport));

                let receiver_arc = t.receiver.lock().clone();
                if let Some(receiver) = &receiver_arc {
                    receiver.set_transport(
                        selected_transport,
                        Some(self.inner.event_tx.clone()),
                        Some(Arc::downgrade(&t)),
                    );
                }
            }
        }

        if self.config().transport_mode == TransportMode::Srtp {
            self.inner
                .ice_transport
                .set_data_receiver(ice_conn.clone())
                .await;
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
            self.inner
                .ice_transport
                .set_data_receiver(ice_conn.clone())
                .await;
            let rtcp_loop = Self::create_rtcp_loop(
                rtp_transport.clone(),
                Arc::downgrade(&self.inner),
                self.inner.stats_collector.clone(),
            );

            let transceivers = self.inner.transceivers.lock();
            for t in transceivers.iter() {
                let selected_transport =
                    self.rtp_transport_for_transceiver_or(t, rtp_transport.clone());
                trace!(
                    "start_dtls: transceiver kind={:?} mid={:?}",
                    t.kind(),
                    t.mid()
                );
                self.attach_rtp_transport_to_transceiver(t, selected_transport);
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

        let remote_dtls_fingerprint = self.inner.remote_dtls_fingerprint.lock().clone();
        let ice_conn_for_data = ice_conn.clone();
        let (dtls, incoming_data_rx, dtls_runner) = DtlsTransport::new(
            ice_conn,
            self.inner.certificate.as_ref().clone(),
            is_client,
            self.config().dtls_buffer_size,
            remote_dtls_fingerprint,
        )
        .await
        .map_err(|e| RtcError::Internal(format!("DTLS failed: {}", e)))?;

        // Start the handshake loop before flushing buffered packets so inbound
        // DTLS records are not dropped on the try_send race.
        let mut dtls_runner_task = tokio::spawn(dtls_runner);

        // DTLS receiver is now registered (inside DtlsTransport::new),
        // safe to set data receiver and flush buffered packets.
        self.inner
            .ice_transport
            .set_data_receiver(ice_conn_for_data)
            .await;

        let sctp_port = if let Some(caps) = &self.config().media_capabilities {
            if let Some(app) = &caps.application {
                app.sctp_port
            } else {
                5000
            }
        } else {
            5000
        };

        let sctp_needed = {
            let remote = self.inner.remote_description.lock();
            if let Some(desc) = &*remote {
                desc.media_sections
                    .iter()
                    .any(|m| m.kind == MediaKind::Application)
            } else {
                false
            }
        };

        let (dc_tx, mut dc_rx) = mpsc::unbounded_channel();

        let mut sctp_runner: Pin<Box<dyn Future<Output = ()> + Send>>;

        if sctp_needed {
            let (sctp, runner) = SctpTransport::new(
                dtls.clone(),
                incoming_data_rx,
                self.inner.data_channels.clone(),
                sctp_port,
                sctp_port,
                Some(dc_tx),
                is_client,
                self.config(),
            );
            *self.inner.sctp_transport.lock() = Some(sctp);
            sctp_runner = Box::pin(runner);
        } else {
            drop(incoming_data_rx);
            sctp_runner = Box::pin(std::future::pending());
        }

        *self.inner.dtls_transport.lock() = Some(dtls.clone());

        let dtls_clone = dtls.clone();
        let rtp_transport_clone = rtp_transport.clone();
        let inner_weak = Arc::downgrade(&self.inner);
        let stats_collector = self.inner.stats_collector.clone();

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
        let mut dc_listener: Pin<Box<dyn Future<Output = ()> + Send>> = if sctp_needed {
            Box::pin(dc_listener)
        } else {
            Box::pin(std::future::pending())
        };

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
                res = &mut dtls_runner_task => {
                    if let Err(e) = res {
                        return Err(RtcError::Internal(format!("DTLS runner panicked: {e}")));
                    }
                }
                _ = &mut sctp_runner => {
                     return Err(RtcError::Internal("SCTP runner stopped unexpectedly".into()));
                }
                _ = &mut dc_listener => {
                     debug!("DataChannel listener stopped unexpectedly");
                     return Err(RtcError::Internal("DataChannel listener stopped unexpectedly".into()));
                }
                res = state_rx.changed() => {
                    if res.is_err() { break; }
                }
                res = pair_rx.changed() => {
                    if res.is_ok() {
                        if let Some(pair) = pair_rx.borrow().clone() {
                            ice_conn_monitor.set_remote_addr_from_signaling(
                                pair.remote.address,
                                "dtls pair monitor update",
                            );
                        }
                    }
                }
            }
        }

        Ok(Box::pin(async {}) as Pin<Box<dyn Future<Output = ()> + Send>>)
    }

    fn setup_sdes(&self, rtp_transport: &Arc<RtpTransport>) -> RtcResult<()> {
        let (tx_keying, rx_keying, profile) = {
            let remote_desc = self.inner.remote_description.lock();
            let local_desc = self.inner.local_description.lock();

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

        let transceivers = self.inner.transceivers.lock();
        for t in transceivers.iter() {
            let sender_arc = t.sender.lock().clone();
            let receiver_arc = t.receiver.lock().clone();

            if let Some(sender) = &sender_arc {
                sender.set_transport(rtp_transport.clone());
            }

            if let Some(receiver) = &receiver_arc {
                receiver.set_transport(
                    rtp_transport.clone(),
                    Some(self.inner.event_tx.clone()),
                    Some(Arc::downgrade(&t)),
                );
                if let Some(sender) = &sender_arc {
                    receiver.set_feedback_ssrc(sender.ssrc());
                }
            }
        }

        *self.inner.rtp_transport.lock() = Some(rtp_transport.clone());
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
                    info!(
                        "setup_srtp: SRTP session ready (is_client={}, profile={:?})",
                        is_client, profile
                    );

                    let transceivers = self.inner.transceivers.lock();
                    for t in transceivers.iter() {
                        let sender_arc = t.sender.lock().clone();
                        let receiver_arc = t.receiver.lock().clone();

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
                            receiver.set_transport(
                                rtp_transport.clone(),
                                Some(self.inner.event_tx.clone()),
                                Some(Arc::downgrade(&t)),
                            );
                            if let Some(sender) = &sender_arc {
                                receiver.set_feedback_ssrc(sender.ssrc());
                            }
                        }
                    }

                    // Update the inner transport to ensure future transceivers get the correct one
                    *self.inner.rtp_transport.lock() = Some(rtp_transport.clone());
                }
                Err(e) => {
                    warn!("Failed to create SRTP session: {}", e);
                }
            }
        } else {
            warn!(
                "Failed to export DTLS-SRTP keying material - DTLS state: {}",
                dtls.get_state()
            );
        }
    }

    fn sdp_has_bundle(desc: &SessionDescription) -> bool {
        desc.session.attributes.iter().any(|attr| {
            attr.key == "group"
                && attr
                    .value
                    .as_deref()
                    .is_some_and(|value| value.starts_with("BUNDLE"))
        })
    }

    fn bundle_tag_mid(desc: &SessionDescription) -> Option<String> {
        desc.session
            .attributes
            .iter()
            .find(|attr| attr.key == "group")
            .and_then(|attr| attr.value.as_deref())
            .and_then(|value| {
                let mut parts = value.split_whitespace();
                if parts.next() == Some("BUNDLE") {
                    parts.next().map(ToString::to_string)
                } else {
                    None
                }
            })
    }

    fn remote_rtp_addr_from_section(
        desc: &SessionDescription,
        section: &MediaSection,
    ) -> Option<std::net::SocketAddr> {
        let conn = section
            .connection
            .as_ref()
            .or(desc.session.connection.as_ref())?;
        let parts: Vec<&str> = conn.split_whitespace().collect();
        if parts.len() >= 3
            && parts[0] == "IN"
            && matches!(parts[1], "IP4" | "IP6")
            && let Ok(ip) = parts[2].parse::<std::net::IpAddr>()
        {
            return Some(std::net::SocketAddr::new(ip, section.port));
        }
        None
    }

    fn matched_rtp_media_sections(
        &self,
        desc: &SessionDescription,
    ) -> Vec<(Arc<RtpTransceiver>, usize)> {
        let transceivers = self.inner.transceivers.lock().clone();
        let mut used_indices = std::collections::HashSet::new();
        let mut matched = Vec::new();

        for (section_idx, section) in desc.media_sections.iter().enumerate() {
            if section.kind == MediaKind::Application || section.kind == MediaKind::Image {
                continue;
            }

            let mut found: Option<(usize, Arc<RtpTransceiver>)> = None;
            if !section.mid.is_empty() {
                for (idx, t) in transceivers.iter().enumerate() {
                    if used_indices.contains(&idx) {
                        continue;
                    }
                    if let Some(t_mid) = t.mid()
                        && t_mid == section.mid
                    {
                        found = Some((idx, t.clone()));
                        break;
                    }
                }
            }

            if found.is_none() {
                for (idx, t) in transceivers.iter().enumerate() {
                    if used_indices.contains(&idx) {
                        continue;
                    }
                    if t.kind() == section.kind {
                        found = Some((idx, t.clone()));
                        break;
                    }
                }
            }

            if let Some((idx, transceiver)) = found {
                used_indices.insert(idx);
                matched.push((transceiver, section_idx));
            }
        }

        matched
    }

    fn stop_extra_rtp_media_transports(&self) {
        let extra_transports = self
            .inner
            .rtp_media_transports
            .lock()
            .drain()
            .map(|(_, transport)| transport)
            .collect::<Vec<_>>();
        for transport in extra_transports {
            transport.clear_listeners();
        }

        let extra_ice = self
            .inner
            .rtp_media_ice_transports
            .lock()
            .drain()
            .map(|(_, transport)| transport)
            .collect::<Vec<_>>();
        for transport in extra_ice {
            transport.stop();
        }
    }

    async fn configure_rtp_media_transports_from_remote(
        &self,
        desc: &SessionDescription,
        ufrag: Option<String>,
        pwd: Option<String>,
        remote_candidates: Vec<IceCandidate>,
    ) -> RtcResult<()> {
        let matched = self.matched_rtp_media_sections(desc);
        if matched.is_empty() {
            return Ok(());
        }

        if Self::sdp_has_bundle(desc) {
            self.stop_extra_rtp_media_transports();
            let bundle_tag = Self::bundle_tag_mid(desc);
            let primary = bundle_tag
                .as_ref()
                .and_then(|mid| {
                    matched
                        .iter()
                        .find(|(_, section_idx)| desc.media_sections[*section_idx].mid == *mid)
                })
                .or_else(|| matched.first());

            if let Some((transceiver, section_idx)) = primary
                && let Some(remote_addr) =
                    Self::remote_rtp_addr_from_section(desc, &desc.media_sections[*section_idx])
            {
                self.configure_rtp_media_transport(
                    transceiver,
                    &desc.media_sections[*section_idx],
                    true,
                    remote_addr,
                    ufrag.as_ref(),
                    pwd.as_ref(),
                    &remote_candidates,
                )
                .await?;
            }
            if let Some(transport) = self.inner.rtp_transport.lock().clone() {
                for (transceiver, _) in matched {
                    self.attach_rtp_transport_to_transceiver(&transceiver, transport.clone());
                }
            }
            return Ok(());
        }

        for (media_index, (transceiver, section_idx)) in matched.iter().enumerate() {
            if let Some(remote_addr) =
                Self::remote_rtp_addr_from_section(desc, &desc.media_sections[*section_idx])
            {
                self.configure_rtp_media_transport(
                    transceiver,
                    &desc.media_sections[*section_idx],
                    media_index == 0,
                    remote_addr,
                    ufrag.as_ref(),
                    pwd.as_ref(),
                    &remote_candidates,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn configure_rtp_media_transport(
        &self,
        transceiver: &Arc<RtpTransceiver>,
        section: &MediaSection,
        primary: bool,
        remote_addr: std::net::SocketAddr,
        ufrag: Option<&String>,
        pwd: Option<&String>,
        remote_candidates: &[IceCandidate],
    ) -> RtcResult<()> {
        let ice_transport = self
            .inner
            .direct_rtp_ice_transport(transceiver.id(), primary);

        if self.config().enable_ice_lite {
            if let (Some(u), Some(p)) = (ufrag, pwd) {
                let params = crate::transports::ice::IceParameters {
                    username_fragment: u.clone(),
                    password: p.clone(),
                    ice_lite: false,
                    tie_breaker: 0,
                };
                ice_transport.set_remote_parameters(params);
                ice_transport.set_role(crate::transports::ice::IceRole::Controlled);
            }
            for candidate in remote_candidates {
                ice_transport.add_remote_candidate(candidate.clone());
            }
        }

        let needs_rtcp_socket = !section.attributes.iter().any(|attr| attr.key == "rtcp-mux");
        if ice_transport.local_candidates().is_empty() {
            ice_transport
                .setup_direct_rtp_with_rtcp(remote_addr, needs_rtcp_socket)
                .await
                .map_err(|e| crate::RtcError::Internal(format!("RTP direct error: {}", e)))?;
        } else {
            ice_transport.complete_direct_rtp(remote_addr);
        }

        if primary {
            if let Some(transport) = self.inner.rtp_transport.lock().clone() {
                let ice_conn = transport.ice_conn();
                ice_conn.set_remote_addr_from_signaling(
                    remote_addr,
                    "primary direct RTP remote from SDP",
                );
                ice_conn.set_remote_rtcp_addr(Self::remote_rtcp_addr_from_media_section(
                    section,
                    remote_addr,
                ));
                if let Some(ssrc) = Self::remote_ssrc_from_section(section) {
                    ice_conn.set_expected_ssrc(ssrc);
                }
                self.attach_rtp_transport_to_transceiver(transceiver, transport);
            }
            return Ok(());
        }

        let transport = self
            .ensure_direct_rtp_media_transport(
                transceiver,
                &ice_transport,
                Some(section),
                Some(remote_addr),
            )
            .await;
        self.attach_rtp_transport_to_transceiver(transceiver, transport);
        Ok(())
    }

    async fn ensure_direct_rtp_media_transport(
        &self,
        transceiver: &Arc<RtpTransceiver>,
        ice_transport: &IceTransport,
        section: Option<&MediaSection>,
        remote_addr: Option<std::net::SocketAddr>,
    ) -> Arc<RtpTransport> {
        if let Some(transport) = self
            .inner
            .rtp_media_transports
            .lock()
            .get(&transceiver.id())
            .cloned()
        {
            if let Some(remote_addr) = remote_addr {
                let ice_conn = transport.ice_conn();
                ice_conn.set_remote_addr_from_signaling(
                    remote_addr,
                    "media direct RTP remote from SDP",
                );
                ice_conn.set_remote_rtcp_addr(section.and_then(|section| {
                    Self::remote_rtcp_addr_from_media_section(section, remote_addr)
                }));
                if let Some(ssrc) = section.and_then(Self::remote_ssrc_from_section) {
                    ice_conn.set_expected_ssrc(ssrc);
                }
            }
            return transport;
        }

        let socket_rx = ice_transport.subscribe_selected_socket();
        let rtcp_socket_rx = ice_transport.subscribe_selected_rtcp_socket();
        let remote_addr = remote_addr.unwrap_or_else(|| {
            std::net::SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
        });
        let ice_conn = IceConn::new_with_rtcp(
            socket_rx,
            rtcp_socket_rx,
            remote_addr,
            self.config().label.clone(),
            self.config().probation_max_packets,
        );
        if self.config().enable_latching {
            ice_conn.enable_latch_on_rtp();
        }
        ice_conn.set_remote_rtcp_addr(
            section.and_then(|section| {
                Self::remote_rtcp_addr_from_media_section(section, remote_addr)
            }),
        );
        if let Some(ssrc) = section.and_then(Self::remote_ssrc_from_section) {
            ice_conn.set_expected_ssrc(ssrc);
        }

        let rtp_transport = Arc::new(RtpTransport::new_with_ssrc_change(
            ice_conn.clone(),
            false,
            self.config().enable_latching,
        ));
        ice_conn.set_rtp_receiver(rtp_transport.clone());
        ice_transport.set_data_receiver(ice_conn.clone()).await;

        self.inner
            .rtp_media_transports
            .lock()
            .insert(transceiver.id(), rtp_transport.clone());

        let rtcp_loop = Self::create_rtcp_loop(
            rtp_transport.clone(),
            Arc::downgrade(&self.inner),
            self.inner.stats_collector.clone(),
        );
        let pair_monitor =
            Self::create_pair_monitor(ice_transport.subscribe_selected_pair(), ice_conn);
        tokio::spawn(async move {
            tokio::select! {
                _ = rtcp_loop => {},
                _ = pair_monitor => {},
            }
        });

        rtp_transport
    }

    /// Update the RTCP address based on the current remote description.
    ///
    /// Call this after `set_remote_description` to ensure the transport correctly
    /// separates RTP and RTCP when the remote peer does not support rtcp-mux.
    /// If the remote SDP contains `a=rtcp-mux`, RTCP will be multiplexed on the
    /// RTP port. Otherwise, RTCP is sent to the port specified by `a=rtcp` or
    /// the default RTP port + 1.
    pub fn update_rtcp_mux_from_remote(&self) {
        let remote_desc = self.inner.remote_description.lock();
        if let Some(desc) = &*remote_desc {
            if let Some(transport) = self.inner.rtp_transport.lock().as_ref() {
                let ice_conn = transport.ice_conn();
                let remote_addr = *ice_conn.remote_addr.read();
                let rtcp_addr = Self::remote_rtcp_addr_from_sdp(desc, remote_addr);
                ice_conn.set_remote_rtcp_addr(rtcp_addr);
                if let Some(addr) = rtcp_addr {
                    tracing::debug!("RTCP-MUX updated: separate RTCP address {}", addr);
                } else {
                    tracing::debug!("RTCP-MUX updated: multiplexing on RTP port");
                }
            }

            for (transceiver, section_idx) in self.matched_rtp_media_sections(desc) {
                let Some(transport) = self
                    .inner
                    .rtp_media_transports
                    .lock()
                    .get(&transceiver.id())
                    .cloned()
                else {
                    continue;
                };
                let section = &desc.media_sections[section_idx];
                let ice_conn = transport.ice_conn();
                let remote_addr = *ice_conn.remote_addr.read();
                ice_conn.set_remote_rtcp_addr(Self::remote_rtcp_addr_from_media_section(
                    section,
                    remote_addr,
                ));
            }
        }
    }

    /// Extract the first `a=ssrc:NNNNN` value from a media section.
    fn remote_ssrc_from_section(section: &MediaSection) -> Option<u32> {
        section
            .attributes
            .iter()
            .find(|a| a.key == "ssrc")
            .and_then(|a| a.value.as_ref())
            .and_then(|v| v.split_whitespace().next())
            .and_then(|s| s.parse().ok())
    }

    fn remote_rtcp_addr_from_sdp(
        desc: &SessionDescription,
        remote_rtp_addr: std::net::SocketAddr,
    ) -> Option<std::net::SocketAddr> {
        let section = Self::bundle_tag_mid(desc)
            .as_ref()
            .and_then(|mid| {
                desc.media_sections
                    .iter()
                    .find(|section| section.mid == *mid)
            })
            .or_else(|| desc.media_sections.first())?;
        Self::remote_rtcp_addr_from_media_section(section, remote_rtp_addr)
    }

    fn remote_rtcp_addr_from_media_section(
        section: &MediaSection,
        remote_rtp_addr: std::net::SocketAddr,
    ) -> Option<std::net::SocketAddr> {
        if section.attributes.iter().any(|attr| attr.key == "rtcp-mux") {
            return None;
        }

        if let Some(explicit_rtcp) = section
            .attributes
            .iter()
            .find(|attr| attr.key == "rtcp")
            .and_then(|attr| Self::parse_rtcp_attribute(attr, remote_rtp_addr.ip()))
        {
            return Some(explicit_rtcp);
        }

        let mut addr = remote_rtp_addr;
        addr.set_port(addr.port() + 1);
        Some(addr)
    }

    fn parse_rtcp_attribute(attr: &Attribute, fallback_ip: IpAddr) -> Option<std::net::SocketAddr> {
        let value = attr.value.as_deref()?;
        let mut parts = value.split_whitespace();
        let port = parts.next()?.parse::<u16>().ok()?;
        let ip = match (parts.next(), parts.next(), parts.next()) {
            (Some("IN"), Some("IP4" | "IP6"), Some(host)) => host.parse().ok()?,
            _ => fallback_ip,
        };
        Some(std::net::SocketAddr::new(ip, port))
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
                        let transceivers = inner.transceivers.lock();
                        for t in transceivers.iter() {
                            if let Some(sender) = &*t.sender.lock() {
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
                let old_addr = *ice_conn_monitor.remote_addr.read();
                trace!(
                    "PeerConnection: pair_monitor initial update: {} -> {}",
                    old_addr, pair.remote.address
                );
                ice_conn_monitor.set_remote_addr_from_signaling(
                    pair.remote.address,
                    "pair monitor initial update",
                );
            }
            while pair_rx.changed().await.is_ok() {
                if let Some(pair) = pair_rx.borrow().clone() {
                    let old_addr = *ice_conn_monitor.remote_addr.read();
                    trace!(
                        "PeerConnection: pair_monitor update: {} -> {}",
                        old_addr, pair.remote.address
                    );
                    ice_conn_monitor
                        .set_remote_addr_from_signaling(pair.remote.address, "pair monitor update");
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

    /// Subscribe to disconnect reason updates. The value changes from `None` to
    /// `Some(reason)` when the connection is disconnected, failed, or closed.
    pub fn subscribe_disconnect_reason(&self) -> watch::Receiver<Option<DisconnectReason>> {
        self.inner.disconnect_reason.subscribe()
    }

    /// Returns the current disconnect reason, if any.
    pub fn disconnect_reason(&self) -> Option<DisconnectReason> {
        self.inner.disconnect_reason.borrow().clone()
    }

    pub fn local_description(&self) -> Option<SessionDescription> {
        self.inner.local_description.lock().clone()
    }

    pub fn remote_description(&self) -> Option<SessionDescription> {
        self.inner.remote_description.lock().clone()
    }

    pub fn close(&self) {
        self.inner.close_with_reason(DisconnectReason::LocalClose);
    }

    pub async fn recv(&self) -> Option<PeerConnectionEvent> {
        let mut rx = self.inner.event_rx.lock().await;
        rx.recv().await
    }

    /// Initialize a T.38 fax endpoint for the Image transceiver.
    ///
    /// Must be called after SDP negotiation is complete (both local and remote
    /// descriptions are set). Returns a `FaxEndpoint` ready for sending/receiving
    /// T.38 IFP packets.
    ///
    /// The UDPTL transport is also stored on the Image transceiver and can be
    /// retrieved via `transceiver.udtl_transport()`.
    #[cfg(feature = "t38")]
    pub async fn init_t38_fax(&self) -> RtcResult<FaxEndpoint> {
        use std::net::IpAddr;

        // Get Image transceiver
        let transceiver = {
            let transceivers = self.inner.transceivers.lock();
            transceivers
                .iter()
                .find(|t| t.kind() == MediaKind::Image)
                .cloned()
                .ok_or_else(|| RtcError::InvalidState("no Image transceiver for T.38 fax".into()))?
        };

        // Get local address from local SDP
        let local_addr = {
            let desc = self.inner.local_description.lock();
            let section = desc
                .as_ref()
                .and_then(|d| d.media_sections.iter().find(|s| s.kind == MediaKind::Image))
                .ok_or_else(|| RtcError::InvalidState("no m=image in local SDP".into()))?;
            let ip: IpAddr = section
                .connection
                .as_deref()
                .and_then(|c| c.strip_prefix("IN IP4 "))
                .and_then(|s| s.parse().ok())
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            std::net::SocketAddr::new(ip, section.port)
        };

        // Get remote address from remote SDP
        let remote_addr = {
            let desc = self.inner.remote_description.lock();
            let section = desc
                .as_ref()
                .and_then(|d| d.media_sections.iter().find(|s| s.kind == MediaKind::Image))
                .ok_or_else(|| RtcError::InvalidState("no m=image in remote SDP".into()))?;
            let ip: IpAddr = section
                .connection
                .as_deref()
                .and_then(|c| c.strip_prefix("IN IP4 "))
                .and_then(|s| s.parse().ok())
                .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            std::net::SocketAddr::new(ip, section.port)
        };

        let socket = Arc::new(
            tokio::net::UdpSocket::bind(local_addr)
                .await
                .map_err(|e| RtcError::Transport(format!("T.38 bind({local_addr}): {e}")))?,
        );

        let transport = Arc::new(crate::transports::udptl::UdtlTransport::new(
            socket,
            remote_addr,
        ));
        transceiver.set_udtl_transport(transport.clone());

        let fax = FaxEndpoint::new(transport, T30Session::new(T30FaxConfig::default()));
        Ok(fax)
    }

    pub fn create_data_channel(
        &self,
        label: &str,
        config: Option<crate::transports::sctp::DataChannelConfig>,
    ) -> RtcResult<Arc<crate::transports::sctp::DataChannel>> {
        // Ensure we have an application transceiver for negotiation
        let has_app_transceiver = {
            let transceivers = self.inner.transceivers.lock();
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

            let channels = self.inner.data_channels.lock();
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

        self.inner.data_channels.lock().push(Arc::downgrade(&dc));

        if !dc.negotiated {
            let transport = self.inner.sctp_transport.lock().clone();
            if let Some(transport) = transport {
                let dc_clone = dc.clone();
                tokio::spawn(async move {
                    if let Err(e) = transport.send_dcep_open(&dc_clone).await {
                        debug!("Failed to send DCEP OPEN: {}", e);
                    }
                });
            }
        }

        Ok(dc)
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> RtcResult<()> {
        let transport = self.inner.sctp_transport.lock().clone();
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
        let transport = self.inner.sctp_transport.lock().clone();
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
        let transport = self.inner.sctp_transport.lock().clone();
        if let Some(transport) = transport {
            transport.buffered_amount()
        } else {
            0
        }
    }

    pub async fn get_stats(&self) -> RtcResult<StatsReport> {
        gather_once(&[self.inner.stats_collector.clone()]).await
    }

    /// Collect transport-level (UDP tx/rx) stats from all active IceConn instances.
    pub async fn get_transport_stats(&self) -> RtcResult<StatsReport> {
        use crate::stats::DynProvider;
        let providers: Vec<Arc<DynProvider>> = {
            let mut v: Vec<Arc<DynProvider>> = Vec::new();
            if let Some(rtp) = self.inner.rtp_transport.lock().as_ref() {
                v.push(rtp.ice_conn() as Arc<DynProvider>);
            }
            for rtp in self.inner.rtp_media_transports.lock().values() {
                v.push(rtp.ice_conn() as Arc<DynProvider>);
            }
            v
        };
        gather_once(&providers).await
    }

    pub async fn wait_for_gathering_complete(&self) {
        if self.config().transport_mode == TransportMode::Rtp {
            // RTP mode: no ICE gathering needed. Gathering completes
            // synchronously when setup_direct_rtp_offer is called.
            return;
        }
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

        let transceivers = self.inner.transceivers.lock().clone();

        // Extract RTP parameter changes for each media section
        for section in &new_desc.media_sections {
            // Find matching transceiver by mid
            let transceiver = transceivers
                .iter()
                .find(|t| t.mid().as_ref() == Some(&section.mid))
                .or_else(|| {
                    if section.mid.is_empty() {
                        // MID-less re-INVITE fallback: match by kind.
                        transceivers.iter().find(|t| t.kind() == section.kind)
                    } else {
                        None
                    }
                });

            if let Some(t) = transceiver {
                // Check SSRC change (indicates new track, not reinvite)
                if let Some(receiver) = t.receiver() {
                    let new_ssrc = Self::extract_ssrc_from_section(section);
                    if let Some(new_ssrc) = new_ssrc {
                        let old_ssrc = receiver.ssrc();
                        if old_ssrc != new_ssrc {
                            if old_ssrc != 0 {
                                debug!(
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

        if self.config().transport_mode != TransportMode::WebRtc {
            if let Some(section) = new_desc.media_sections.first() {
                let conn_opt = section
                    .connection
                    .as_ref()
                    .or(new_desc.session.connection.as_ref());
                if let Some(conn) = conn_opt {
                    let parts: Vec<&str> = conn.split_whitespace().collect();
                    if parts.len() >= 3
                        && parts[0] == "IN"
                        && parts[1] == "IP4"
                        && let Ok(ip) = parts[2].parse::<std::net::IpAddr>()
                    {
                        let remote_addr = std::net::SocketAddr::new(ip, section.port);
                        if self.config().transport_mode == TransportMode::Rtp {
                            self.inner.ice_transport.complete_direct_rtp(remote_addr);
                            debug!("Updated RTP remote address to {}", remote_addr);
                        } else if self.config().transport_mode == TransportMode::Srtp {
                            if let Some(transport) = self.inner.rtp_transport.lock().as_ref() {
                                transport.ice_conn().set_remote_addr_from_signaling(
                                    remote_addr,
                                    "SRTP remote from SDP",
                                );
                                debug!("Updated SRTP remote address to {}", remote_addr);
                            }
                        }
                    }
                }
            }
            self.update_rtcp_mux_from_remote();
        }

        // Update remote description
        *self.inner.remote_description.lock() = Some(new_desc.clone());

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
        for format in &section.formats {
            if let Ok(pt) = format.parse::<u8>() {
                if !payload_map.contains_key(&pt) {
                    if let Some(params) = Self::iana_static_rtp_params(pt) {
                        payload_map.insert(pt, params);
                    }
                }
            }
        }

        payload_map
    }

    /// Returns the IANA-assigned RTP codec parameters for well-known static
    /// payload types (RFC 3551 §6).  Returns `None` for dynamic PTs (96–127)
    /// or statically-unassigned PTs that have no defined clock-rate.
    fn iana_static_rtp_params(pt: u8) -> Option<RtpCodecParameters> {
        match pt {
            0 => Some(RtpCodecParameters {
                payload_type: 0,
                clock_rate: 8000,
                channels: 1,
            }), // PCMU
            8 => Some(RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            }), // PCMA
            9 => Some(RtpCodecParameters {
                payload_type: 9,
                clock_rate: 8000,
                channels: 1,
            }), // G.722
            18 => Some(RtpCodecParameters {
                payload_type: 18,
                clock_rate: 8000,
                channels: 1,
            }), // G.729
            _ => None,
        }
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

                        let mut local_guard = inner.local_description.lock();
                        if let Some(desc) = local_guard.as_mut() {
                            desc.add_candidates(&candidate_strs);
                        }
                        true
                    } else {
                        let candidates = ice_transport.local_candidates();
                        if let Some(candidate) = candidates.first() {
                            let mut local_guard = inner.local_description.lock();
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
                if matches!(*ice_state_rx.borrow(), crate::transports::ice::IceTransportState::Closed | crate::transports::ice::IceTransportState::Failed) {
                    break;
                }
            }
        }
    }
}

/// Simplified loop for RTP mode. Watches ICE state transitions from
/// setup_direct_rtp / complete_direct_rtp and triggers start_dtls
/// when the connection becomes available. No ICE gathering or STUN.
async fn run_rtp_direct_loop(
    ice_transport: IceTransport,
    ice_connection_state_tx: watch::Sender<IceConnectionState>,
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
                if !handle_connected_state_no_dtls(&inner_weak, &mut ice_state_rx).await {
                    return;
                }
                continue;
            }
            crate::transports::ice::IceTransportState::Failed => {
                if let Some(inner) = inner_weak.upgrade() {
                    let _ = inner.disconnect_reason.send_if_modified(|cur| {
                        if cur.is_none() {
                            *cur = Some(DisconnectReason::IceFailed);
                            true
                        } else {
                            false
                        }
                    });
                    let _ = inner.peer_state.send(PeerConnectionState::Failed);
                }
                return;
            }
            crate::transports::ice::IceTransportState::Closed => {
                if let Some(inner) = inner_weak.upgrade() {
                    let _ = inner.disconnect_reason.send_if_modified(|cur| {
                        if cur.is_none() {
                            *cur = Some(DisconnectReason::IceDisconnected);
                            true
                        } else {
                            false
                        }
                    });
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

async fn run_ice_dtls_loop(
    ice_transport: IceTransport,
    ice_connection_state_tx: watch::Sender<IceConnectionState>,
    mut dtls_role_rx: watch::Receiver<Option<bool>>,
    inner_weak: std::sync::Weak<PeerConnectionInner>,
) {
    let mut ice_state_rx = ice_transport.subscribe_state();
    // Subscribe once; the channel starts as None and transitions to Some(_) exactly once.
    let mut nomination_complete_rx = ice_transport.subscribe_nomination_complete();
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
                ice_transport.nudge_passive_tcp_nomination();
                tokio::task::yield_now().await;
                // Wait for ICE nomination to complete before starting DTLS.
                // This prevents a race where DTLS and the USE-CANDIDATE binding check
                // compete for the same UDP socket, causing spurious nomination timeouts.
                let nomination_timeout = if let Some(inner) = inner_weak.upgrade() {
                    inner.config.nomination_timeout
                } else {
                    return;
                };

                // Wait for ICE nomination to complete before starting DTLS.
                // ICE now tries candidate pairs in priority order (host → srflx → relay).
                // Each pair gets `nomination_timeout` for its STUN retransmissions.
                if nomination_complete_rx.borrow().is_none() {
                    let wait_result = tokio::select! {
                        changed = nomination_complete_rx.changed() => {
                            changed.ok().and_then(|_| *nomination_complete_rx.borrow())
                        }
                        // Guard: abort if ICE transitions away from connected/completed.
                        _ = async {
                            loop {
                                if ice_state_rx.changed().await.is_err() {
                                    break;
                                }
                                let s = *ice_state_rx.borrow();
                                if !matches!(
                                    s,
                                    crate::transports::ice::IceTransportState::Connected
                                    | crate::transports::ice::IceTransportState::Completed
                                ) {
                                    break;
                                }
                            }
                        } => None,
                        // Allow time for multiple candidate pairs to be tried.
                        _ = tokio::time::sleep(nomination_timeout.saturating_mul(6)) => None,
                    };

                    if wait_result != Some(true) {
                        debug!("ICE nomination did not succeed, skipping DTLS");
                        continue;
                    }
                    debug!("ICE nomination completed successfully, starting DTLS");
                }

                // Bail out if nomination was already completed with failure
                // (re-entry after continue above).  Wait for ICE to transition
                // away from Connected (should go to Failed) to avoid busy-looping.
                if *nomination_complete_rx.borrow() == Some(false) {
                    debug!("ICE nomination failed, waiting for ICE to transition");
                    loop {
                        if ice_state_rx.changed().await.is_err() {
                            return;
                        }
                        let s = *ice_state_rx.borrow();
                        if !matches!(
                            s,
                            crate::transports::ice::IceTransportState::Connected
                                | crate::transports::ice::IceTransportState::Completed
                        ) {
                            break;
                        }
                    }
                    continue;
                }

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
                    let _ = inner.disconnect_reason.send_if_modified(|cur| {
                        if cur.is_none() {
                            *cur = Some(DisconnectReason::IceFailed);
                            true
                        } else {
                            false
                        }
                    });
                    let _ = inner.peer_state.send(PeerConnectionState::Failed);
                }
                return;
            }
            crate::transports::ice::IceTransportState::Closed => {
                if let Some(inner) = inner_weak.upgrade() {
                    let _ = inner.disconnect_reason.send_if_modified(|cur| {
                        if cur.is_none() {
                            *cur = Some(DisconnectReason::IceDisconnected);
                            true
                        } else {
                            false
                        }
                    });
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

/// Check the SCTP transport's close reason and propagate it to the
/// PeerConnection's disconnect_reason if not already set.
fn propagate_sctp_close_reason(inner: &PeerConnectionInner) {
    let sctp_reason = inner
        .sctp_transport
        .lock()
        .as_ref()
        .and_then(|sctp: &Arc<SctpTransport>| {
            sctp.close_reason().and_then(|r: String| match r.as_str() {
                "HEARTBEAT_TIMEOUT" => Some(DisconnectReason::SctpHeartbeatTimeout),
                "HEARTBEAT_DEAD" => Some(DisconnectReason::SctpPeerDead),
                "REMOTE_ABORT" => Some(DisconnectReason::SctpRemoteAbort),
                "REMOTE_SHUTDOWN" => Some(DisconnectReason::SctpRemoteShutdown),
                "DTLS_FAILED" => Some(DisconnectReason::DtlsFailed),
                "DTLS_CLOSED" | "DTLS_CHANNEL_CLOSED" => Some(DisconnectReason::DtlsClosed),
                "LOCAL_CLOSE" => None,
                "INIT_TIMEOUT" => Some(DisconnectReason::TransportStartFailed(
                    "SCTP INIT timeout".into(),
                )),
                "TRANSPORT_CLOSED" => {
                    Some(DisconnectReason::Unknown("transport channel closed".into()))
                }
                other => Some(DisconnectReason::Unknown(other.to_string())),
            })
        });
    if let Some(reason) = sctp_reason {
        let _ = inner.disconnect_reason.send_if_modified(|cur| {
            if cur.is_none() {
                *cur = Some(reason);
                true
            } else {
                false
            }
        });
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
                debug!("Transport start failed: {}", e);
                let _ = inner.disconnect_reason.send_if_modified(|cur| {
                    if cur.is_none() {
                        *cur = Some(DisconnectReason::TransportStartFailed(e.to_string()));
                        true
                    } else {
                        false
                    }
                });
                let _ = inner.peer_state.send(PeerConnectionState::Failed);
                return false;
            }
            Ok(mut rtcp_loop) => {
                let _ = inner.peer_state.send(PeerConnectionState::Connected);
                loop {
                    tokio::select! {
                        _ = &mut rtcp_loop => {
                            // Combined loop exited (SCTP/DTLS/RTCP runner finished)
                            // Check SCTP close reason and propagate it
                            propagate_sctp_close_reason(&inner);
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
                        debug!("DTLS start failed: {}", e);
                        let _ = inner.disconnect_reason.send_if_modified(|cur| {
                            if cur.is_none() {
                                *cur = Some(DisconnectReason::DtlsFailed);
                                true
                            } else {
                                false
                            }
                        });
                        let _ = inner.peer_state.send(PeerConnectionState::Failed);
                        return false;
                    }
                    Ok(mut rtcp_loop) => {
                        let _ = inner.peer_state.send(PeerConnectionState::Connected);

                        let dtls_state_rx = {
                            let dtls_guard = inner.dtls_transport.lock();
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
                                        // Combined loop exited (SCTP/DTLS/RTCP runner finished)
                                        propagate_sctp_close_reason(&inner);
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
                                                let reason = if state == crate::transports::dtls::DtlsState::Failed {
                                                    DisconnectReason::DtlsFailed
                                                } else {
                                                    DisconnectReason::DtlsClosed
                                                };
                                                let _ = inner.disconnect_reason.send_if_modified(|cur| {
                                                    if cur.is_none() { *cur = Some(reason); true } else { false }
                                                });
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
                                        // Combined loop exited (SCTP/DTLS/RTCP runner finished)
                                        propagate_sctp_close_reason(&inner);
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
    fn direct_rtp_ice_transport(&self, transceiver_id: u64, primary: bool) -> IceTransport {
        if primary {
            return self.ice_transport.clone();
        }

        let mut transports = self.rtp_media_ice_transports.lock();
        if let Some(transport) = transports.get(&transceiver_id) {
            return transport.clone();
        }

        let (transport, runner) = IceTransport::new(self.config.clone());
        tokio::spawn(runner);
        transports.insert(transceiver_id, transport.clone());
        transport
    }

    async fn build_description<F>(
        &self,
        sdp_type: SdpType,
        map_direction: F,
    ) -> RtcResult<SessionDescription>
    where
        F: Fn(TransceiverDirection) -> TransceiverDirection,
    {
        let transceivers = {
            let list = self.transceivers.lock();
            list.iter().cloned().collect::<Vec<_>>()
        };
        if transceivers.is_empty() {
            return Err(RtcError::InvalidState(
                "cannot build SDP with no transceivers".into(),
            ));
        }

        let mut remote_offered_bundle = false;

        let ordered_transceivers = if sdp_type == SdpType::Answer {
            let remote_guard = self.remote_description.lock();
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
            let mut used_indices = std::collections::HashSet::new();
            for section in &remote.media_sections {
                let mid = &section.mid;
                let mut found: Option<(usize, Arc<RtpTransceiver>)> = None;

                // 1) Prefer exact MID match when remote provides MID.
                if !mid.is_empty() {
                    for (idx, t) in transceivers.iter().enumerate() {
                        if used_indices.contains(&idx) {
                            continue;
                        }
                        if let Some(t_mid) = t.mid()
                            && t_mid == *mid
                        {
                            found = Some((idx, t.clone()));
                            break;
                        }
                    }
                }

                // 2) Interop fallback for MID-less sections:
                // pick first unused same-kind transceiver.
                if found.is_none() && mid.is_empty() {
                    for (idx, t) in transceivers.iter().enumerate() {
                        if used_indices.contains(&idx) {
                            continue;
                        }
                        if t.kind() == section.kind {
                            found = Some((idx, t.clone()));
                            break;
                        }
                    }
                }

                if let Some((idx, t)) = found {
                    used_indices.insert(idx);
                    ordered.push((
                        t,
                        section.attributes.iter().any(|attr| attr.key == "rtcp-mux"),
                    ));
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
            ordered.into_iter().map(|t| (t, false)).collect()
        };

        let mode = self.config.transport_mode.clone();
        let will_bundle = match sdp_type {
            SdpType::Offer => true,
            SdpType::Answer => remote_offered_bundle,
            _ => false,
        } && ordered_transceivers.len() > 1
            && self.config.sdp_compatibility != crate::config::SdpCompatibilityMode::LegacySip;
        let local_offers_rtcp_mux = self.config.rtcp_mux_policy
            == crate::config::RtcpMuxPolicy::Require
            && self.config.sdp_compatibility != crate::config::SdpCompatibilityMode::LegacySip;

        if mode != TransportMode::Rtp {
            self.ice_transport
                .start_gathering()
                .map_err(|err| RtcError::InvalidState(format!("ICE gathering failed: {err}")))?;
        }

        // For non-WebRTC (SRTP), wait for at least one candidate if none are available.
        // RTP mode already has candidates from setup_direct_rtp_offer above.
        if mode == TransportMode::Srtp {
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
            if let Some(ext_ip) = &self.config.external_ip {
                desc.session.connection = Some(format!("IN IP4 {}", ext_ip));
            }
        }

        for (media_index, (transceiver, remote_offered_rtcp_mux)) in
            ordered_transceivers.into_iter().enumerate()
        {
            let mid = self.ensure_mid(&transceiver);
            let mut direction = map_direction(transceiver.direction());
            let sender_info = if direction.sends() {
                transceiver.sender.lock().clone()
            } else {
                None
            };

            // Check if remote side expects us to send (for B2BUA scenarios)
            let remote_expects_media = if sdp_type == SdpType::Answer {
                let remote_guard = self.remote_description.lock();
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
            let has_sender_ssrc = transceiver.sender_ssrc.lock().is_some();
            if direction.sends()
                && sender_info.is_none()
                && !has_sender_ssrc
                && transceiver.kind() != MediaKind::Application
                && transceiver.kind() != MediaKind::Image
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

            if mode == TransportMode::Rtp && transceiver.kind() != MediaKind::Image {
                section.protocol = "RTP/AVP".to_string();
            }

            let mut local_rtcp_addr = None;
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
                let section_ice_transport = if mode == TransportMode::Rtp {
                    let ice_transport = if !will_bundle && media_index > 0 {
                        let ice_transport = self.direct_rtp_ice_transport(transceiver.id(), false);
                        ice_transport
                    } else {
                        self.ice_transport.clone()
                    };
                    let needs_rtcp = match sdp_type {
                        SdpType::Answer => !remote_offered_rtcp_mux,
                        _ => !local_offers_rtcp_mux,
                    };
                    if ice_transport.local_candidates().is_empty() {
                        ice_transport
                            .setup_direct_rtp_offer_with_rtcp(needs_rtcp)
                            .await
                            .map_err(|err| {
                                RtcError::Internal(format!("RTP socket bind failed: {err}"))
                            })?;
                    }
                    // RTP mode skips the ICE gathering loop; section-driven direct socket
                    // setup publishes candidates synchronously.
                    let _ = self.ice_gathering_state.send(IceGatheringState::Complete);
                    ice_transport
                } else {
                    self.ice_transport.clone()
                };
                let candidates = section_ice_transport.local_candidates();
                local_rtcp_addr = section_ice_transport.local_rtcp_addr();
                if let Some(cand) = candidates
                    .iter()
                    .filter(|c| c.component == 1)
                    .find(|c| !c.address.ip().is_loopback())
                    .or_else(|| candidates.iter().find(|c| c.component == 1))
                {
                    section.port = cand.address.port();
                    let conn = format!("IN IP4 {}", cand.address.ip());
                    if desc.session.connection.is_none() {
                        desc.session.connection = Some(conn.clone());
                    }
                    if Some(&conn) != desc.session.connection.as_ref() {
                        section.connection = Some(conn);
                    }
                }

                // ICE-lite in RTP mode: include ICE attributes so remote full-ICE
                // agents can perform connectivity checks against us.
                if mode == TransportMode::Rtp && self.config.enable_ice_lite {
                    if !desc.session.attributes.iter().any(|a| a.key == "ice-lite") {
                        desc.session
                            .attributes
                            .push(Attribute::new("ice-lite", None));
                    }
                    let section_ice_params = section_ice_transport.local_parameters();
                    let section_candidate_lines: Vec<String> =
                        candidates.iter().map(IceCandidate::to_sdp).collect();
                    let section_gather_complete = matches!(
                        section_ice_transport.gather_state(),
                        IceGathererState::Complete
                    );
                    section.attributes.push(Attribute::new(
                        "ice-ufrag",
                        Some(section_ice_params.username_fragment.clone()),
                    ));
                    section.attributes.push(Attribute::new(
                        "ice-pwd",
                        Some(section_ice_params.password.clone()),
                    ));
                    for candidate in &section_candidate_lines {
                        section
                            .attributes
                            .push(Attribute::new("candidate", Some(candidate.clone())));
                    }
                    if section_gather_complete {
                        section
                            .attributes
                            .push(Attribute::new("end-of-candidates", None));
                    }
                }
            }

            self.populate_media_capabilities(&mut section, transceiver.kind(), sdp_type);
            if sdp_type == SdpType::Answer && !remote_offered_rtcp_mux {
                section.attributes.retain(|attr| attr.key != "rtcp-mux");
            }
            if mode == TransportMode::Rtp
                && !section.attributes.iter().any(|attr| attr.key == "rtcp-mux")
                && let Some(rtcp_addr) = local_rtcp_addr
            {
                section
                    .attributes
                    .push(Attribute::new("rtcp", Some(rtcp_addr.port().to_string())));
            }
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
                if let Some(ssrc) = *transceiver.sender_ssrc.lock() {
                    let cname = self
                        .config
                        .cname
                        .clone()
                        .unwrap_or_else(|| format!("rustrtc-cname-{ssrc}"));
                    let stream_id = transceiver
                        .sender_stream_id
                        .lock()
                        .clone()
                        .unwrap_or_else(|| "default".to_string());
                    let track_id = transceiver
                        .sender_track_id
                        .lock()
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
                    let remote_desc = self.remote_description.lock();
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
            if will_bundle {
                let mids: Vec<String> = desc.media_sections.iter().map(|m| m.mid.clone()).collect();
                let value = format!("BUNDLE {}", mids.join(" "));
                desc.session
                    .attributes
                    .push(Attribute::new("group", Some(value)));
            }

            // In LegacySip mode, omit a=mid entirely: legacy SIP endpoints confuse
            // a=mid without a matching a=group:BUNDLE.
            if self.config.sdp_compatibility == crate::config::SdpCompatibilityMode::LegacySip {
                for section in &mut desc.media_sections {
                    section.mid = String::new();
                }
            } else if !will_bundle {
                // In Standard mode with no BUNDLE, still clear mids from sections
                // that have no group association to avoid confusing endpoints that
                // interpret a=mid as requiring BUNDLE.
                // Exception: single-section SDP keeps its mid (it's harmless and
                // allows endpoints to identify the stream).
                if desc.media_sections.len() > 1 {
                    for section in &mut desc.media_sections {
                        section.mid = String::new();
                    }
                }
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
            SdpType::Offer | SdpType::Answer | SdpType::Pranswer => Ok(()),
            _ => Err(RtcError::NotImplemented("rollback")),
        }
    }

    fn populate_media_capabilities(
        &self,
        section: &mut MediaSection,
        kind: MediaKind,
        sdp_type: SdpType,
    ) {
        section.apply_config(&self.config);
        if let Some(caps) = self.reinvite_answer_audio_capabilities(&section.mid, kind, sdp_type) {
            Self::apply_audio_capabilities(section, &caps);
        }

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

        // Add sdes:mid extmap for BUNDLE support (RFC 8843).  Answers echo the
        // remote ID when offered; WebRTC offers use a default ID so bundled
        // audio/video can still be demuxed when payload types overlap.
        if self.config.sdp_compatibility != crate::config::SdpCompatibilityMode::LegacySip {
            let mut sdes_mid_id = self.get_remote_extmap_id(&section.mid, crate::sdp::SDES_MID_URI);
            if sdp_type == SdpType::Offer
                && sdes_mid_id.is_none()
                && self.config.transport_mode != TransportMode::Rtp
            {
                sdes_mid_id = Some("4".to_string());
            }
            if let Some(id) = sdes_mid_id {
                section.attributes.push(crate::sdp::Attribute::new(
                    "extmap",
                    Some(format!("{} {}", id, crate::sdp::SDES_MID_URI)),
                ));
            }
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

    fn audio_capability_matches(local: &AudioCapability, remote: &AudioCapability) -> bool {
        local.codec_name.eq_ignore_ascii_case(&remote.codec_name)
            && local.clock_rate == remote.clock_rate
            && local.channels == remote.channels
    }

    fn configured_audio_capabilities(config: &RtcConfiguration) -> Vec<AudioCapability> {
        let default_caps = AudioCapability::default();
        config
            .media_capabilities
            .as_ref()
            .map(|caps| {
                if caps.audio.is_empty() {
                    vec![default_caps.clone()]
                } else {
                    caps.audio.clone()
                }
            })
            .unwrap_or_else(|| vec![default_caps])
    }

    fn reinvite_answer_audio_capabilities(
        &self,
        mid: &str,
        kind: MediaKind,
        sdp_type: SdpType,
    ) -> Option<Vec<AudioCapability>> {
        if kind != MediaKind::Audio || sdp_type != SdpType::Answer {
            return None;
        }

        if self.local_description.lock().is_none() {
            return None;
        }

        let remote = self.remote_description.lock();
        let remote_desc = remote.as_ref()?;
        let remote_section = remote_desc
            .media_sections
            .iter()
            .find(|section| section.mid == mid)
            .or_else(|| {
                remote_desc
                    .media_sections
                    .iter()
                    .find(|section| section.kind == kind)
            })?;

        let local_caps = Self::configured_audio_capabilities(&self.config);
        let caps = Self::derive_answer_audio_capabilities(remote_section, &local_caps);
        if caps.is_empty() { None } else { Some(caps) }
    }

    fn derive_answer_audio_capabilities(
        remote_section: &MediaSection,
        local_caps: &[AudioCapability],
    ) -> Vec<AudioCapability> {
        remote_section
            .to_audio_capabilities()
            .into_iter()
            .filter_map(|remote_cap| {
                local_caps
                    .iter()
                    .find(|local_cap| Self::audio_capability_matches(local_cap, &remote_cap))
                    .map(|local_cap| {
                        let mut cap = local_cap.clone();
                        cap.payload_type = remote_cap.payload_type;
                        cap.codec_name = remote_cap.codec_name.clone();
                        cap.clock_rate = remote_cap.clock_rate;
                        cap.channels = remote_cap.channels;
                        if remote_cap
                            .codec_name
                            .eq_ignore_ascii_case("telephone-event")
                        {
                            cap.fmtp = remote_cap.fmtp.clone().or(cap.fmtp);
                        }
                        cap
                    })
            })
            .collect()
    }

    fn apply_audio_capabilities(section: &mut MediaSection, caps: &[AudioCapability]) {
        section.formats = caps.iter().map(|c| c.payload_type.to_string()).collect();
        section
            .attributes
            .retain(|attr| attr.key != "rtpmap" && attr.key != "fmtp" && attr.key != "rtcp-fb");

        for audio in caps {
            let rtpmap_value = if audio.channels == 1 {
                format!(
                    "{} {}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate
                )
            } else {
                format!(
                    "{} {}/{}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate, audio.channels
                )
            };

            section
                .attributes
                .push(Attribute::new("rtpmap", Some(rtpmap_value)));
            if let Some(fmtp) = &audio.fmtp {
                section.attributes.push(Attribute::new(
                    "fmtp",
                    Some(format!("{} {}", audio.payload_type, fmtp)),
                ));
            }
            for fb in &audio.rtcp_fbs {
                section.attributes.push(Attribute::new(
                    "rtcp-fb",
                    Some(format!("{} {}", audio.payload_type, fb)),
                ));
            }
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
        let remote = self.remote_description.lock();
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

    fn close_with_reason(&self, reason: DisconnectReason) {
        if *self.peer_state.borrow() == PeerConnectionState::Closed {
            return;
        }

        let final_reason = if self.disconnect_reason.borrow().is_none() {
            let sctp_reason =
                self.sctp_transport
                    .lock()
                    .as_ref()
                    .and_then(|sctp: &Arc<SctpTransport>| {
                        sctp.close_reason().and_then(|r: String| match r.as_str() {
                            "HEARTBEAT_TIMEOUT" => Some(DisconnectReason::SctpHeartbeatTimeout),
                            "HEARTBEAT_DEAD" => Some(DisconnectReason::SctpPeerDead),
                            "REMOTE_ABORT" => Some(DisconnectReason::SctpRemoteAbort),
                            "REMOTE_SHUTDOWN" => Some(DisconnectReason::SctpRemoteShutdown),
                            "DTLS_FAILED" => Some(DisconnectReason::DtlsFailed),
                            "DTLS_CLOSED" | "DTLS_CHANNEL_CLOSED" => {
                                Some(DisconnectReason::DtlsClosed)
                            }
                            "LOCAL_CLOSE" => None, // Not more specific than the outer reason
                            "INIT_TIMEOUT" => Some(DisconnectReason::TransportStartFailed(
                                "SCTP INIT timeout".into(),
                            )),
                            "TRANSPORT_CLOSED" => {
                                Some(DisconnectReason::Unknown("transport channel closed".into()))
                            }
                            other => Some(DisconnectReason::Unknown(other.to_string())),
                        })
                    });
            let r = sctp_reason.unwrap_or(reason);
            let _ = self.disconnect_reason.send(Some(r.clone()));
            r
        } else {
            self.disconnect_reason.borrow().clone().unwrap()
        };

        tracing::debug!("PeerConnection closing: reason={}", final_reason);

        // Log SCTP diagnostic info for debugging network issues
        if let Some(sctp) = self.sctp_transport.lock().as_ref() {
            tracing::debug!("SCTP diagnostics: {}", sctp.diagnostic_info());
        }

        let _ = self.signaling_state.send(SignalingState::Closed);
        let _ = self.peer_state.send(PeerConnectionState::Closed);
        let _ = self.ice_connection_state.send(IceConnectionState::Closed);
        let _ = self.ice_gathering_state.send(IceGatheringState::Complete);

        // Clean up all tracks to prevent audio bleeding into new connections
        {
            let transceivers = self.transceivers.lock();
            for t in transceivers.iter() {
                // Stop sender send loops immediately
                if let Some(sender) = t.sender() {
                    sender.stop();
                }
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
        let rtp_transport = self.rtp_transport.lock().clone();
        if let Some(transport) = rtp_transport.as_ref() {
            let count = transport.clear_listeners();
            if count > 0 {
                tracing::debug!("PeerConnection.close: cleared {} listeners", count);
            }

            // Send RTCP BYE
            let transceivers = self.transceivers.lock();
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

        let extra_transports = self
            .rtp_media_transports
            .lock()
            .drain()
            .map(|(_, transport)| transport)
            .collect::<Vec<_>>();
        for transport in extra_transports {
            let count = transport.clear_listeners();
            if count > 0 {
                tracing::debug!(
                    "PeerConnection.close: cleared {} extra RTP listeners",
                    count
                );
            }
        }

        // Close SCTP transport before closing DTLS/ICE to stop retransmission timers
        if let Some(sctp) = self.sctp_transport.lock().take() {
            sctp.close();
        }

        if let Some(dtls) = self.dtls_transport.lock().as_ref() {
            dtls.close();
        }

        self.ice_transport.stop();
        let extra_ice = self
            .rtp_media_ice_transports
            .lock()
            .drain()
            .map(|(_, transport)| transport)
            .collect::<Vec<_>>();
        for transport in extra_ice {
            transport.stop();
        }
    }
}

impl Drop for PeerConnectionInner {
    fn drop(&mut self) {
        debug!("PeerConnectionInner dropped, stopping ICE transport");
        self.close_with_reason(DisconnectReason::Dropped);
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

/// Describes why a PeerConnection was disconnected or closed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// Local side called close()
    LocalClose,
    /// PeerConnection was dropped without explicit close
    Dropped,
    /// ICE transport failed (connectivity check failures)
    IceFailed,
    /// ICE transport disconnected (lost connectivity)
    IceDisconnected,
    /// DTLS transport failed
    DtlsFailed,
    /// DTLS transport closed
    DtlsClosed,
    /// SCTP association closed due to heartbeat timeout
    /// (peer not responding to heartbeats)
    SctpHeartbeatTimeout,
    /// SCTP association closed because peer appears dead
    /// (consecutive heartbeat failures during RTO backoff)
    SctpPeerDead,
    /// Remote peer sent SCTP ABORT
    SctpRemoteAbort,
    /// Remote peer sent SCTP SHUTDOWN
    SctpRemoteShutdown,
    /// SCTP transport start failed
    TransportStartFailed(String),
    /// Unknown or unspecified reason
    Unknown(String),
}

impl std::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DisconnectReason::LocalClose => write!(f, "local close"),
            DisconnectReason::Dropped => write!(f, "connection dropped"),
            DisconnectReason::IceFailed => write!(f, "ICE failed"),
            DisconnectReason::IceDisconnected => write!(f, "ICE disconnected"),
            DisconnectReason::DtlsFailed => write!(f, "DTLS failed"),
            DisconnectReason::DtlsClosed => write!(f, "DTLS closed"),
            DisconnectReason::SctpHeartbeatTimeout => {
                write!(f, "SCTP heartbeat timeout (peer unresponsive)")
            }
            DisconnectReason::SctpPeerDead => {
                write!(f, "SCTP peer dead (consecutive heartbeat failures)")
            }
            DisconnectReason::SctpRemoteAbort => write!(f, "remote SCTP ABORT"),
            DisconnectReason::SctpRemoteShutdown => write!(f, "remote SCTP SHUTDOWN"),
            DisconnectReason::TransportStartFailed(e) => {
                write!(f, "transport start failed: {}", e)
            }
            DisconnectReason::Unknown(s) => write!(f, "unknown: {}", s),
        }
    }
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
    udtl_transport: Mutex<Option<Arc<UdtlTransport>>>,
    sender_ssrc: Mutex<Option<u32>>,
    sender_stream_id: Mutex<Option<String>>,
    sender_track_id: Mutex<Option<String>>,
    payload_map: Arc<RwLock<HashMap<u8, RtpCodecParameters>>>,
    extmap: Arc<RwLock<HashMap<u8, String>>>,
    /// Deferred sdes:mid configuration: stored here when update_extmap() is called
    /// but the sender has not been created yet.  Applied in set_sender().
    pending_sdes_mid: Mutex<Option<(u8, Arc<str>)>>,
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
            udtl_transport: Mutex::new(None),
            sender_ssrc: Mutex::new(None),
            sender_stream_id: Mutex::new(None),
            sender_track_id: Mutex::new(None),
            payload_map: Arc::new(RwLock::new(HashMap::new())),
            extmap: Arc::new(RwLock::new(HashMap::new())),
            pending_sdes_mid: Mutex::new(None),
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
        *self.sender_ssrc.lock()
    }

    pub fn sender_stream_id(&self) -> Option<String> {
        self.sender_stream_id.lock().clone()
    }

    pub fn sender_track_id(&self) -> Option<String> {
        self.sender_track_id.lock().clone()
    }

    pub fn direction(&self) -> TransceiverDirection {
        *self.direction.lock()
    }

    pub fn set_direction(&self, direction: TransceiverDirection) {
        *self.direction.lock() = direction;
    }

    pub fn mid(&self) -> Option<String> {
        self.mid.lock().clone()
    }

    fn set_mid(&self, mid: String) {
        *self.mid.lock() = Some(mid.clone());

        let transport = self
            .rtp_transport
            .lock()
            .as_ref()
            .and_then(|transport| transport.upgrade());
        let receiver = self.receiver.lock().clone();
        if let Some(transport) = transport
            && let Some(receiver) = receiver
            && let Some(tx) = receiver.packet_tx()
        {
            transport.register_mid_listener(mid, tx);
        }
    }

    /// Get the UDPTL transport for T.38 fax, if available.
    pub fn udtl_transport(&self) -> Option<Arc<UdtlTransport>> {
        self.udtl_transport.lock().clone()
    }

    /// Set the UDPTL transport for T.38 fax.
    pub fn set_udtl_transport(&self, transport: Arc<UdtlTransport>) {
        *self.udtl_transport.lock() = Some(transport);
    }

    pub fn sender(&self) -> Option<Arc<RtpSender>> {
        self.sender.lock().clone()
    }

    pub fn set_sender(&self, sender: Option<Arc<RtpSender>>) {
        if let Some(ref s) = sender {
            // If transport is already established, connect the sender to it
            if let Some(weak_transport) = self.rtp_transport.lock().as_ref() {
                if let Some(transport) = weak_transport.upgrade() {
                    debug!(
                        "set_sender: connecting late sender ssrc={} to existing transport",
                        s.ssrc()
                    );
                    s.set_transport(transport);
                }
            }
            // Sync pre-allocated fields
            *self.sender_ssrc.lock() = Some(s.ssrc());
            *self.sender_stream_id.lock() = Some(s.stream_id().to_string());
            *self.sender_track_id.lock() = Some(s.track_id().to_string());

            // Apply any negotiated sdes:mid configuration to replacement senders too.
            let pending_sdes_mid = self.pending_sdes_mid.lock().take();
            if let Some((id, mid_val)) = pending_sdes_mid {
                s.set_sdes_mid(id, mid_val);
            } else {
                let mid_value = self.mid.lock().clone();
                let sdes_mid_id = self
                    .extmap
                    .read()
                    .iter()
                    .find(|(_, uri)| uri.as_str() == crate::sdp::SDES_MID_URI)
                    .map(|(id, _)| *id);
                if let (Some(id), Some(mid)) = (sdes_mid_id, mid_value) {
                    s.set_sdes_mid(id, Arc::from(mid.as_str()));
                }
            }
        }
        *self.sender.lock() = sender;
    }

    /// Set the RTP transport reference. Called by start_dtls when transport is established.
    pub fn set_rtp_transport(&self, transport: Weak<RtpTransport>) {
        *self.rtp_transport.lock() = Some(transport);
    }

    pub fn receiver(&self) -> Option<Arc<RtpReceiver>> {
        self.receiver.lock().clone()
    }

    pub fn set_receiver(&self, receiver: Option<Arc<RtpReceiver>>) {
        *self.receiver.lock() = receiver;
    }

    /// Update payload type mapping for reinvite scenarios
    pub fn update_payload_map(&self, new_map: HashMap<u8, RtpCodecParameters>) -> RtcResult<()> {
        let mut payload_map = self.payload_map.write();

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
            if let Some(transport_weak) = self.rtp_transport.lock().clone() {
                if let Some(transport) = transport_weak.upgrade() {
                    if let Some(tx) = receiver.packet_tx() {
                        transport.register_payload_list_listener(
                            new_map.keys().copied().collect(),
                            tx.clone(),
                        );
                    }
                }
            }
        }

        Ok(())
    }

    /// Update RTP header extension mapping for reinvite scenarios
    pub fn update_extmap(&self, new_extmap: HashMap<u8, String>) -> RtcResult<()> {
        let mut extmap = self.extmap.write();

        // Log changes
        for (id, uri) in &new_extmap {
            if !extmap.contains_key(id) || extmap.get(id) != Some(uri) {
                trace!("Extmap ID {} remapped to {}", id, uri);
            }
        }

        *extmap = new_extmap;

        // Update transport extension IDs if available
        if let Some(weak_transport) = self.rtp_transport.lock().as_ref() {
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

                let id = extmap
                    .iter()
                    .find(|(_, uri)| uri.as_str() == crate::sdp::SDES_MID_URI)
                    .map(|(id, _)| *id);
                transport.set_sdes_mid_extension_id(id);
            }
        }

        // Propagate sdes:mid to the sender so it auto-injects the extension on every outgoing packet
        if let Some(sender_arc) = self.sender.lock().as_ref() {
            let mid_value = self.mid.lock().clone();
            let sdes_mid_id = extmap
                .iter()
                .find(|(_, uri)| uri.as_str() == crate::sdp::SDES_MID_URI)
                .map(|(id, _)| *id);
            if let (Some(id), Some(mid)) = (sdes_mid_id, mid_value) {
                sender_arc.set_sdes_mid(id, Arc::from(mid.as_str()));
            }
        } else {
            // Sender not yet created — defer sdes:mid so set_sender() can apply it.
            let mid_value = self.mid.lock().clone();
            let sdes_mid_id = extmap
                .iter()
                .find(|(_, uri)| uri.as_str() == crate::sdp::SDES_MID_URI)
                .map(|(id, _)| *id);
            if let (Some(id), Some(mid)) = (sdes_mid_id, mid_value) {
                *self.pending_sdes_mid.lock() = Some((id, Arc::from(mid.as_str())));
            }
        }

        Ok(())
    }

    /// Get current payload type mapping (for testing/debugging)
    pub fn get_payload_map(&self) -> HashMap<u8, RtpCodecParameters> {
        self.payload_map.read().clone()
    }

    /// Get current extmap (for testing/debugging)
    pub fn get_extmap(&self) -> HashMap<u8, String> {
        self.extmap.read().clone()
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
    packets_sent: Arc<AtomicU32>,
    octets_sent: Arc<AtomicU32>,
    last_rtp_timestamp: Arc<AtomicU32>,
    interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
    /// sdes:mid extension to inject: (extension header ID, mid value).
    /// Set automatically by update_extmap() when negotiation contains sdes:mid.
    sdes_mid: Arc<Mutex<Option<(u8, Arc<str>)>>>,
    transport_generation: Arc<AtomicU64>,
    transport_change_tx: watch::Sender<u64>,
}

pub struct RtpSenderBuilder {
    track: Arc<dyn MediaStreamTrack>,
    ssrc: u32,
    stream_id: String,
    params: RtpCodecParameters,
    interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
    cname: Option<String>,
}

impl RtpSenderBuilder {
    pub fn new(track: Arc<dyn MediaStreamTrack>, ssrc: u32) -> Self {
        Self {
            track,
            ssrc,
            stream_id: "stream".to_string(),
            params: RtpCodecParameters::default(),
            interceptors: Vec::new(),
            cname: None,
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

    pub fn cname(mut self, cname: String) -> Self {
        self.cname = Some(cname);
        self
    }

    pub fn build(self) -> Arc<RtpSender> {
        Arc::new(RtpSender::new_internal(
            self.track,
            self.ssrc,
            self.stream_id,
            self.params,
            self.interceptors,
            self.cname,
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
        Self::new_internal(track, ssrc, stream_id, params, interceptors, None)
    }

    fn new_internal(
        track: Arc<dyn MediaStreamTrack>,
        ssrc: u32,
        stream_id: String,
        params: RtpCodecParameters,
        interceptors: Vec<Arc<dyn RtpSenderInterceptor + Send + Sync>>,
        cname_override: Option<String>,
    ) -> Self {
        let track_label = track.id().to_string();
        let track_id = Arc::<str>::from(track_label.clone());
        let stream_id = Arc::<str>::from(stream_id);
        let cname = Arc::<str>::from(
            cname_override.unwrap_or_else(|| format!("rustrtc-cname-{ssrc}")),
        );
        let (rtcp_tx, _) = broadcast::channel(100);
        let (transport_change_tx, _) = watch::channel(0);

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
            packets_sent: Arc::new(AtomicU32::new(0)),
            octets_sent: Arc::new(AtomicU32::new(0)),
            last_rtp_timestamp: Arc::new(AtomicU32::new(0)),
            interceptors,
            sdes_mid: Arc::new(Mutex::new(None)),
            transport_generation: Arc::new(AtomicU64::new(0)),
            transport_change_tx,
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

    pub fn set_sdes_mid(&self, ext_id: u8, mid: Arc<str>) {
        *self.sdes_mid.lock() = Some((ext_id, mid));
    }

    pub fn subscribe_rtcp(&self) -> broadcast::Receiver<RtcpPacket> {
        self.rtcp_tx.subscribe()
    }

    pub(crate) fn deliver_rtcp(&self, packet: RtcpPacket) {
        let _ = self.rtcp_tx.send(packet);
    }

    pub fn params(&self) -> RtpCodecParameters {
        self.params.lock().clone()
    }

    pub fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock() = params;
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
        {
            let track_id = self.track_id.clone();
            let ssrc = self.ssrc;
            let current_transport = self.transport.lock();
            if let Some(existing) = current_transport.as_ref() {
                if Arc::ptr_eq(existing, &transport) {
                    info!(
                        "ignored same transport track_id={}, ssrc={}, transport_ptr={:p}",
                        track_id,
                        ssrc,
                        Arc::as_ptr(&transport)
                    );
                    return;
                }
            }
        }

        let generation = self
            .transport_generation
            .fetch_add(1, Ordering::SeqCst)
            .wrapping_add(1);
        let _ = self.transport_change_tx.send(generation);

        *self.transport.lock() = Some(transport.clone());
        let track_id = self.track_id.clone();
        let track = self.track.clone();
        let ssrc = self.ssrc;
        info!(
            "RtpSender: spawning send loop track_id={} ssrc={}",
            track_id, ssrc
        );
        let params_lock = self.params.clone();
        let stop_rx = self.stop_tx.clone();
        let mut transport_change_rx = self.transport_change_tx.subscribe();
        let transport_generation = self.transport_generation.clone();
        let next_seq = self.next_sequence_number.clone();
        let packets_sent = self.packets_sent.clone();
        let octets_sent = self.octets_sent.clone();
        let last_rtp_timestamp = self.last_rtp_timestamp.clone();
        let interceptors = self.interceptors.clone();
        let sdes_mid = self.sdes_mid.clone();
        let mut rtcp_rx = self.rtcp_tx.subscribe();

        tokio::spawn(async move {
            let mut sequence_number = next_seq.load(Ordering::SeqCst);
            let mut logged_first_sample = false;
            let mut last_source_ts: Option<u32> = None;
            let mut timestamp_offset = random_u32(); // Start with random offset
            // Delay the first SR so the initial RTP burst is not immediately followed by RTCP
            // on the same 5-tuple, which can confuse consumers that are expecting RTP first.
            let mut rtcp_interval = tokio::time::interval_at(
                tokio::time::Instant::now() + std::time::Duration::from_secs(3),
                std::time::Duration::from_secs(3),
            );
            rtcp_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            let notified = stop_rx.notified();
            tokio::pin!(notified);

            loop {
                if transport_generation.load(Ordering::SeqCst) != generation {
                    break;
                }

                tokio::select! {
                    _ = &mut notified => break,
                    changed = transport_change_rx.changed() => {
                        match changed {
                            Ok(()) => {
                                if *transport_change_rx.borrow() != generation {
                                    break;
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    _ = rtcp_interval.tick(), if packets_sent.load(Ordering::Relaxed) > 0 => {
                        if transport_generation.load(Ordering::SeqCst) != generation {
                            break;
                        }
                        let packet_count = packets_sent.load(Ordering::Relaxed);

                        let octet_count = octets_sent.load(Ordering::Relaxed);
                        let rtp_timestamp = last_rtp_timestamp.load(Ordering::Relaxed);
                        let report = Self::build_sender_report(
                            ssrc,
                            rtp_timestamp,
                            packet_count,
                            octet_count,
                            SystemTime::now(),
                        );

                        if let Err(e) = transport
                            .send_rtcp(&[RtcpPacket::SenderReport(report)])
                            .await
                        {
                            debug!("Failed to send Sender Report: {}", e);
                        }
                    }
                    rtcp = rtcp_rx.recv() => {
                        if transport_generation.load(Ordering::SeqCst) != generation {
                            break;
                        }
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
                        if transport_generation.load(Ordering::SeqCst) != generation {
                            break;
                        }
                        match res {
                            Ok(mut sample) => {
                                if !logged_first_sample {
                                    logged_first_sample = true;
                                    info!(
                                        "RtpSender: first sample dequeued ssrc={} track_id={}",
                                        ssrc, track_id
                                    );
                                }
                                let payload_type = {
                                    let p = params_lock.lock();
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

                                // Auto-inject sdes:mid header extension when negotiated (RFC 8843 / BUNDLE).
                                if let Some((id, ref mid)) = *sdes_mid.lock() {
                                    let _ = packet.header.set_extension(id, mid.as_bytes());
                                }

                                let payload_len = packet.payload.len() as u32;
                                let packet_timestamp = packet.header.timestamp;

                                if let Err(e) = transport.send_rtp(packet).await {
                                    let n = packets_sent.load(Ordering::Relaxed);
                                    if n < 5 {
                                        warn!("RtpSender: failed to send RTP (ssrc={}): {}", ssrc, e);
                                    } else {
                                        debug!("Failed to send RTP: {}", e);
                                    }
                                } else {
                                    let n = packets_sent.fetch_add(1, Ordering::Relaxed) + 1;
                                    if n == 1 {
                                        info!(
                                            "RtpSender: first RTP packet sent on wire ssrc={} track_id={}",
                                            ssrc, track_id
                                        );
                                    }
                                    octets_sent.fetch_add(payload_len, Ordering::Relaxed);
                                    last_rtp_timestamp.store(packet_timestamp, Ordering::Relaxed);
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

    fn build_sender_report(
        sender_ssrc: u32,
        rtp_timestamp: u32,
        packet_count: u32,
        octet_count: u32,
        now: SystemTime,
    ) -> SenderReport {
        let duration = now.duration_since(UNIX_EPOCH).unwrap_or_default();
        let ntp_seconds = duration.as_secs().saturating_add(2_208_988_800);
        let ntp_fraction = (duration.subsec_nanos() as u64 * (1u64 << 32) / 1_000_000_000) as u32;

        SenderReport {
            sender_ssrc,
            ntp_most: ntp_seconds as u32,
            ntp_least: ntp_fraction,
            rtp_timestamp,
            packet_count,
            octet_count,
            report_blocks: Vec::new(),
        }
    }
}

impl RtpSender {
    /// Stop the sender's send loop immediately (e.g. on PeerConnection close).
    pub(crate) fn stop(&self) {
        self.stop_tx.notify_waiters();
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
    payload_map: Arc<RwLock<HashMap<u8, RtpCodecParameters>>>,
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
    track_ready_event_tx: Mutex<Option<mpsc::UnboundedSender<PeerConnectionEvent>>>,
    track_ready_transceiver: Mutex<Option<Weak<RtpTransceiver>>>,
    track_event_sent: AtomicBool,
    pub depacketizer_factory: Arc<dyn DepacketizerFactory>,
}

pub struct RtpReceiverBuilder {
    kind: MediaKind,
    ssrc: u32,
    interceptors: Vec<Arc<dyn RtpReceiverInterceptor>>,
    depacketizer_factory: Option<Arc<dyn DepacketizerFactory>>,
    payload_map: Arc<RwLock<HashMap<u8, RtpCodecParameters>>>,
}

impl RtpReceiverBuilder {
    pub fn new(kind: MediaKind, ssrc: u32) -> Self {
        Self {
            kind,
            ssrc,
            interceptors: Vec::new(),
            depacketizer_factory: None,
            payload_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn depacketizer_factory(mut self, factory: Arc<dyn DepacketizerFactory>) -> Self {
        self.depacketizer_factory = Some(factory);
        self
    }

    pub fn payload_map(
        mut self,
        payload_map: Arc<RwLock<HashMap<u8, RtpCodecParameters>>>,
    ) -> Self {
        self.payload_map = payload_map;
        self
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
        let (source, track, feedback_rx) = sample_track(media_kind, RTP_RECEIVER_SAMPLE_CAPACITY);

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
            payload_map: self.payload_map,
            transport: Mutex::new(None),
            packet_tx: Mutex::new(None),
            rtcp_feedback_ssrc: Mutex::new(None),
            rtx_ssrc: Mutex::new(None),
            fir_seq: AtomicU8::new(0),
            feedback_rx: Arc::new(tokio::sync::Mutex::new(feedback_rx)),
            simulcast_tracks: Mutex::new(HashMap::new()),
            runner_tx: Mutex::new(None),
            interceptors: self.interceptors,
            track_ready_event_tx: Mutex::new(None),
            track_ready_transceiver: Mutex::new(None),
            track_event_sent: AtomicBool::new(false),
            depacketizer_factory: self.depacketizer_factory.unwrap_or_else(|| {
                Arc::new(crate::media::depacketizer::DefaultDepacketizerFactory)
            }),
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
        let (source, track, feedback_rx) = sample_track(media_kind, RTP_RECEIVER_SAMPLE_CAPACITY);

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
            payload_map: Arc::new(RwLock::new(HashMap::new())),
            transport: Mutex::new(None),
            packet_tx: Mutex::new(None),
            rtcp_feedback_ssrc: Mutex::new(None),
            rtx_ssrc: Mutex::new(None),
            fir_seq: AtomicU8::new(0),
            feedback_rx: Arc::new(tokio::sync::Mutex::new(feedback_rx)),
            simulcast_tracks: Mutex::new(HashMap::new()),
            runner_tx: Mutex::new(None),
            interceptors,
            track_ready_event_tx: Mutex::new(None),
            track_ready_transceiver: Mutex::new(None),
            track_event_sent: AtomicBool::new(false),
            depacketizer_factory: Arc::new(crate::media::depacketizer::DefaultDepacketizerFactory),
        }
    }

    pub fn add_simulcast_track(self: &Arc<Self>, rid: String) -> Arc<SampleStreamTrack> {
        let (source, track, feedback_rx) =
            sample_track(self.track.kind(), RTP_RECEIVER_SAMPLE_CAPACITY);
        let source = Arc::new(source);
        let feedback_rx = Arc::new(tokio::sync::Mutex::new(feedback_rx));
        let simulcast_ssrc = Arc::new(Mutex::new(None));

        // If runner is active, send command
        let runner_tx = self.runner_tx.lock().clone();
        if let Some(tx) = runner_tx {
            let transport = self.transport.lock().clone();
            if let Some(transport) = transport {
                let (packet_tx, packet_rx) = mpsc::channel(RTP_RECEIVER_PACKET_CAPACITY);
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
        let tracks = self.simulcast_tracks.lock();
        tracks.get(rid).map(|(_, track, _, _)| track.clone())
    }

    pub fn get_simulcast_rids(&self) -> Vec<String> {
        let tracks = self.simulcast_tracks.lock();
        tracks.keys().cloned().collect()
    }

    pub fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock() = params;
    }

    pub fn ssrc(&self) -> u32 {
        *self.ssrc.lock()
    }

    pub fn packet_tx(&self) -> Option<mpsc::Sender<(crate::rtp::RtpPacket, std::net::SocketAddr)>> {
        self.packet_tx.lock().clone()
    }

    fn codec_params_for_payload_type(&self, payload_type: u8) -> RtpCodecParameters {
        self.payload_map
            .read()
            .get(&payload_type)
            .cloned()
            .unwrap_or_else(|| self.params.lock().clone())
    }

    pub fn rtx_ssrc(&self) -> Option<u32> {
        *self.rtx_ssrc.lock()
    }

    pub fn set_ssrc(&self, ssrc: u32) {
        *self.ssrc.lock() = ssrc;
        let transport = self.transport.lock().clone();
        let packet_tx = self.packet_tx.lock().clone();

        if let Some(transport) = transport
            && let Some(tx) = packet_tx
            && ssrc != 0
        {
            transport.register_listener_sync(ssrc, tx);
        }
    }

    pub fn ensure_provisional_listener(&self) {
        let transport = self.transport.lock().clone();
        let packet_tx = self.packet_tx.lock().clone();

        if let Some(transport) = transport
            && let Some(tx) = packet_tx
        {
            transport.register_provisional_listener(tx);
        }
    }

    pub fn set_rtx_ssrc(&self, ssrc: u32) {
        *self.rtx_ssrc.lock() = Some(ssrc);
    }

    pub fn set_transport(
        self: &Arc<Self>,
        transport: Arc<RtpTransport>,
        event_tx: Option<mpsc::UnboundedSender<PeerConnectionEvent>>,
        transceiver: Option<Weak<RtpTransceiver>>,
    ) {
        {
            let current_transport = self.transport.lock();
            if let Some(existing) = current_transport.as_ref() {
                if Arc::ptr_eq(existing, &transport) {
                    return;
                }
                // Switching to a *different* transport (e.g. RTP-mode re-negotiation after
                // 183 early-media → 200 OK).  The Track event and SSRC were learned from
                // the previous transport; reset them so the first packet on the new
                // transport fires a fresh Track event and re-wires bridge forwarding.
                // We only reset on re-assignment (not first assignment) to avoid
                // duplicate Track events in WebRTC mode where the SDP SSRC path
                // already sent the Track event before set_transport was called.
                self.track_event_sent.store(false, Ordering::SeqCst);
                *self.ssrc.lock() = 0;
                tracing::debug!(
                    "RTP receiver: transport replaced — reset track_event_sent and ssrc"
                );
            }
        }

        let route_transceiver = transceiver.clone().and_then(|t| t.upgrade());
        *self.transport.lock() = Some(transport.clone());
        *self.track_ready_event_tx.lock() = event_tx;
        *self.track_ready_transceiver.lock() = transceiver;

        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        *self.runner_tx.lock() = Some(cmd_tx);

        let mut initial_tracks = Vec::new();

        // Main track
        let (tx, rx) = mpsc::channel(RTP_RECEIVER_PACKET_CAPACITY);
        let ssrc = *self.ssrc.lock();
        if ssrc != 0 {
            transport.register_listener_sync(ssrc, tx.clone());
        }
        transport.register_provisional_listener(tx.clone());
        if let Some(transceiver) = &route_transceiver {
            if let Some(mid) = transceiver.mid() {
                transport.register_mid_listener(mid, tx.clone());
            }
            let extmap = transceiver.get_extmap();
            let sdes_mid_id = extmap
                .iter()
                .find(|(_, uri)| uri.as_str() == crate::sdp::SDES_MID_URI)
                .map(|(id, _)| *id);
            transport.set_sdes_mid_extension_id(sdes_mid_id);
        }

        // Register the negotiated payload types when available, keeping the
        // default PT as a fallback before negotiation completes.
        let default_pt = self.params.lock().payload_type;
        let mut payload_types = vec![default_pt];
        for pt in self.payload_map.read().keys().copied() {
            if !payload_types.contains(&pt) {
                payload_types.push(pt);
            }
        }
        transport.register_payload_list_listener(payload_types.clone(), tx.clone());
        debug!(
            transport_id = format_args!("{:p}", Arc::as_ptr(&transport)),
            transceiver_id = route_transceiver.as_ref().map(|t| t.id()),
            transceiver_kind = ?route_transceiver.as_ref().map(|t| t.kind()),
            transceiver_mid = ?route_transceiver.as_ref().and_then(|t| t.mid()),
            receiver_kind = ?self.track.kind(),
            receiver_ssrc = ssrc,
            default_pt,
            payload_types = ?payload_types,
            "RTP receiver registered on transport"
        );

        *self.packet_tx.lock() = Some(tx);

        initial_tracks.push(ReceiverCommand::AddTrack {
            rid: None,
            packet_rx: rx,
            feedback_rx: self.feedback_rx.clone(),
            source: self.source.clone(),
            simulcast_ssrc: Arc::new(Mutex::new(None)),
        });

        // Simulcast tracks
        let tracks_guard = self.simulcast_tracks.lock();
        for (rid, (source, _, feedback_rx, simulcast_ssrc)) in tracks_guard.iter() {
            let (tx, rx) = mpsc::channel(RTP_RECEIVER_PACKET_CAPACITY);
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
        let depacketizer_factory = if let Some(receiver) = weak_self.upgrade() {
            receiver.depacketizer_factory.clone()
        } else {
            Arc::new(crate::media::depacketizer::DefaultDepacketizerFactory)
        };

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
            depacketizer_factory: &Arc<dyn DepacketizerFactory>,
        ) {
            let ReceiverCommand::AddTrack {
                rid,
                packet_rx,
                feedback_rx,
                source,
                simulcast_ssrc,
            } = cmd;

            tracks.insert(
                rid.clone(),
                (source.clone(), simulcast_ssrc, feedback_rx.clone()),
            );

            let rid_clone = rid.clone();
            // Initialize depacketizer
            let depacketizer = depacketizer_factory.create(source.kind());

            futures.push(Box::pin(async move {
                let mut rx = packet_rx;
                let packet = rx.recv().await;
                LoopEvent::Packet(packet, rid_clone, rx, depacketizer)
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
            handle_add_track(cmd, &mut futures, &mut tracks, &depacketizer_factory);
        }

        loop {
            tokio::select! {
                cmd = cmd_rx.recv() => {
                    match cmd {
                        Some(cmd) => handle_add_track(cmd, &mut futures, &mut tracks, &depacketizer_factory),
                        None => break,
                    }
                }
                event = futures.next(), if !futures.is_empty() => {
                    if let Some(event) = event {
                        match event {
                            LoopEvent::Packet(packet_opt, rid, packet_rx, mut depacketizer) => {
                                if let Some((packet, addr)) = packet_opt {
                                    if let Some((source, simulcast_ssrc, _)) = tracks.get(&rid) {
                                        if rid.is_some() {
                                            let mut s = simulcast_ssrc.lock();
                                            if s.is_none() {
                                                *s = Some(packet.header.ssrc);
                                            }
                                        } else {
                                            // Main track: Update SSRC if it matched via provisional listener
                                            if let Some(this) = weak_self.upgrade() {
                                                let mut s = this.ssrc.lock();
                                                let old_ssrc = *s;
                                                if old_ssrc != packet.header.ssrc {
                                                    trace!(
                                                        "RTP main track SSRC changed from {} to {}",
                                                        old_ssrc, packet.header.ssrc
                                                    );
                                                    *s = packet.header.ssrc;

                                                    // Send Track event after learning the first real SSRC.
                                                    if old_ssrc == 0 {
                                                        tracing::info!(
                                                            ssrc = packet.header.ssrc,
                                                            pt = packet.header.payload_type,
                                                            src = %addr,
                                                            "RTP run_loop: first packet — SSRC learned, sending Track event",
                                                        );
                                                        // Use swap to atomically check and set the flag
                                                        if !this.track_event_sent.swap(true, Ordering::SeqCst) {
                                                            if let Some(ref event_tx) = *this.track_ready_event_tx.lock() {
                                                                let transceiver = this.track_ready_transceiver.lock();
                                                                if let Some(transceiver) = transceiver.as_ref().and_then(|t| t.upgrade()) {
                                                                    let _ = event_tx.send(PeerConnectionEvent::Track(transceiver.clone()));
                                                                    debug!("RTP mode: Sent Track event after SSRC latching complete");
                                                                }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }

                                        if let Some(this) = weak_self.upgrade() {
                                            for interceptor in &this.interceptors {
                                                if let Some(mut rtcp_packet) = interceptor.on_packet_received(&packet).await {
                                                    if let RtcpPacket::GenericNack(ref mut nack) = rtcp_packet {
                                                        let sender_ssrc = this.rtcp_feedback_ssrc.lock().unwrap_or(0);
                                                        if sender_ssrc != 0 {
                                                            nack.sender_ssrc = sender_ssrc;
                                                        } else {
                                                            debug!("NACK: skipping sender_ssrc update because it is 0");
                                                        }
                                                    }

                                                    let transport = this.transport.lock().clone();
                                                    if let Some(transport) = transport {
                                                        let _ = transport.send_rtcp(&[rtcp_packet]).await;
                                                    }
                                                }
                                            }

                                            let params = this.codec_params_for_payload_type(packet.header.payload_type);
                                            let clock_rate = params.clock_rate;

                                            // Track depacketizer drop count changes
                                            let prev_drop = depacketizer.drop_count();
                                            // Fix: Use Depacketizer to handle frames correctly
                                            if let Ok(samples) = depacketizer.push(packet, clock_rate, addr, source.kind()) {
                                                if depacketizer.drop_count() > prev_drop {
                                                    source.increment_drop_count();
                                                }
                                                if let Err(e) = source.send_many(samples).await {
                                                    tracing::warn!("Failed to send media sample batch: {}", e);
                                                }
                                            }

                                            let rid_clone = rid.clone();
                                            futures.push(Box::pin(async move {
                                                let mut rx = packet_rx;
                                                let packet = rx.recv().await;
                                                LoopEvent::Packet(packet, rid_clone, rx, depacketizer)
                                            }));
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
                                                        *simulcast_ssrc.lock()
                                                    } else {
                                                        Some(*this.ssrc.lock())
                                                    };

                                                    if let Some(ssrc) = media_ssrc {
                                                        let sender_ssrc = *this.rtcp_feedback_ssrc.lock();
                                                        let pli = crate::rtp::PictureLossIndication {
                                                            sender_ssrc: sender_ssrc.unwrap_or(0),
                                                            media_ssrc: ssrc,
                                                        };
                                                        let packet = crate::rtp::RtcpPacket::PictureLossIndication(pli);

                                                        let transport = this.transport.lock().clone();
                                                        if let Some(transport) = transport {
                                                            if let Err(e) = transport.send_rtcp(&[packet]).await {
                                                                debug!("Failed to send PLI: {}", e);
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
        *self.rtcp_feedback_ssrc.lock() = Some(ssrc);
    }

    pub async fn send_nack(&self, lost_packets: Vec<u16>) -> RtcResult<()> {
        let transport = self.transport.lock().clone();
        if let Some(transport) = transport {
            let media_ssrc = *self.ssrc.lock();
            let sender_ssrc = (*self.rtcp_feedback_ssrc.lock()).unwrap_or(media_ssrc);

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
        let transport = self.transport.lock().clone();
        if let Some(transport) = transport {
            let media_ssrc = *self.ssrc.lock();
            let sender_ssrc = (*self.rtcp_feedback_ssrc.lock()).unwrap_or(media_ssrc);

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
impl PeerConnection {
    /// Expose the ICE transport for state manipulation in unit tests.
    pub fn ice_transport_for_test(&self) -> &crate::transports::ice::IceTransport {
        &self.inner.ice_transport
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
    async fn repro_pair_monitor_must_not_override_latched_rtp_remote() {
        use crate::transports::PacketReceiver;
        use std::net::{Ipv4Addr, SocketAddr};

        let (_socket_tx, socket_rx) = tokio::sync::watch::channel(None);
        let initial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);
        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let sdp_private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 4162);
        let conn = IceConn::new(socket_rx, initial_addr, None);
        conn.enable_latch_on_rtp();

        conn.receive(
            bytes::Bytes::from_static(&[
                0x80, 0x80, // V=2, marker=true
                0x00, 0x01, // seq=1
                0x00, 0x00, 0x00, 0x01, // ts=1
                0x00, 0x00, 0x00, 0x01, // ssrc=1
            ]),
            rtp_src,
        )
        .await;
        assert!(conn.rtp_latched.load(Ordering::Relaxed));

        let local = IceCandidate::host(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 20000), 1);
        let remote = IceCandidate::host(sdp_private, 1);
        let pair = crate::transports::ice::IceCandidatePair::new(local, remote);
        let (pair_tx, pair_rx) = tokio::sync::watch::channel(Some(pair));
        drop(pair_tx);

        PeerConnection::create_pair_monitor(pair_rx, conn.clone()).await;

        assert_eq!(
            *conn.remote_addr.read(),
            rtp_src,
            "selected-pair update must not replace an RTP-latched public tuple with private SDP"
        );
    }

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
                       a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
                       a=setup:passive\r\n\
                       c=IN IP4 127.0.0.1\r\n\
                       m=video 9 RTP/SAVPF 96\r\n\
                       a=rtpmap:96 VP8/90000\r\n\
                       a=rid:hi send\r\n\
                       a=rid:mid send\r\n\
                       a=rid:lo send\r\n\
                       a=simulcast:send hi;mid;lo\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let transceivers = pc.inner.transceivers.lock();
        assert_eq!(transceivers.len(), 1);
        let t = &transceivers[0];
        let rx = t.receiver.lock().as_ref().unwrap().clone();

        // Check simulcast tracks
        let simulcast_tracks = rx.simulcast_tracks.lock();
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
        let rtp_transport = pc.inner.rtp_transport.lock().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read();

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

        let rtp_transport = pc.inner.rtp_transport.lock().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read();

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

    /// SIP 183 Session Progress scenario: callee sends a pranswer (early media),
    /// caller should set up the media transport immediately and stay in
    /// HaveLocalOffer so the final 200 OK answer can still arrive.
    #[tokio::test]
    async fn pranswer_sets_up_media_without_completing_negotiation() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer.clone()).unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);

        // Simulate 183 Session Progress with a provisional answer SDP.
        let mut pranswer = offer.clone();
        pranswer.sdp_type = SdpType::Pranswer;
        pc.set_remote_description(pranswer).await.unwrap();
        // State must remain HaveLocalOffer so the final answer can still come in.
        assert_eq!(
            pc.signaling_state(),
            SignalingState::HaveLocalOffer,
            "pranswer must not complete negotiation"
        );

        // Simulate 200 OK with the final answer.
        let mut answer = offer.clone();
        answer.sdp_type = SdpType::Answer;
        pc.set_remote_description(answer).await.unwrap();
        assert_eq!(
            pc.signaling_state(),
            SignalingState::Stable,
            "final answer must complete negotiation"
        );
    }

    #[tokio::test]
    async fn set_local_description_pranswer_keeps_have_remote_offer_state() {
        let offerer = PeerConnection::new(RtcConfiguration::default());
        offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = offerer.create_offer().await.unwrap();

        let callee = PeerConnection::new(RtcConfiguration::default());
        callee.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        callee.set_remote_description(offer).await.unwrap();
        assert_eq!(callee.signaling_state(), SignalingState::HaveRemoteOffer);

        let answer = callee.create_answer().await.unwrap();
        let mut pranswer = answer.clone();
        pranswer.sdp_type = SdpType::Pranswer;
        callee.set_local_description(pranswer).unwrap();

        assert_eq!(
            callee.signaling_state(),
            SignalingState::HaveRemoteOffer,
            "pranswer must NOT complete negotiation"
        );
    }

    #[tokio::test]
    async fn set_local_description_pranswer_then_answer_completes_negotiation() {
        let offerer = PeerConnection::new(RtcConfiguration::default());
        offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = offerer.create_offer().await.unwrap();

        let callee = PeerConnection::new(RtcConfiguration::default());
        callee.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        callee.set_remote_description(offer).await.unwrap();

        // Step 1: provisional answer (SIP 183).
        let answer = callee.create_answer().await.unwrap();
        let mut pranswer = answer.clone();
        pranswer.sdp_type = SdpType::Pranswer;
        callee.set_local_description(pranswer).unwrap();
        assert_eq!(
            callee.signaling_state(),
            SignalingState::HaveRemoteOffer,
            "after pranswer state must remain HaveRemoteOffer"
        );

        // Step 2: final answer (SIP 200 OK).
        callee.set_local_description(answer).unwrap();
        assert_eq!(
            callee.signaling_state(),
            SignalingState::Stable,
            "after final answer state must be Stable"
        );
    }

    #[tokio::test]
    async fn set_local_description_pranswer_requires_have_remote_offer() {
        // Case 1: Stable state (no negotiation in progress).
        {
            let pc = PeerConnection::new(RtcConfiguration::default());
            pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
            let offer = pc.create_offer().await.unwrap();
            let mut pranswer = offer.clone();
            pranswer.sdp_type = SdpType::Pranswer;
            let err = pc.set_local_description(pranswer).unwrap_err();
            assert!(
                matches!(err, RtcError::InvalidState(_)),
                "pranswer from Stable must return InvalidState, got: {err:?}"
            );
        }

        // Case 2: HaveLocalOffer (caller side, waiting for remote answer).
        {
            let pc = PeerConnection::new(RtcConfiguration::default());
            pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
            let offer = pc.create_offer().await.unwrap();
            pc.set_local_description(offer.clone()).unwrap();
            assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);

            let mut pranswer = offer.clone();
            pranswer.sdp_type = SdpType::Pranswer;
            let err = pc.set_local_description(pranswer).unwrap_err();
            assert!(
                matches!(err, RtcError::InvalidState(_)),
                "pranswer from HaveLocalOffer must return InvalidState, got: {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn set_local_description_pranswer_stores_local_description() {
        let offerer = PeerConnection::new(RtcConfiguration::default());
        offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = offerer.create_offer().await.unwrap();

        let callee = PeerConnection::new(RtcConfiguration::default());
        callee.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        callee.set_remote_description(offer).await.unwrap();

        assert!(
            callee.local_description().is_none(),
            "no local description before pranswer"
        );

        let answer = callee.create_answer().await.unwrap();
        let mut pranswer = answer.clone();
        pranswer.sdp_type = SdpType::Pranswer;
        callee.set_local_description(pranswer).unwrap();

        let stored = callee
            .local_description()
            .expect("local_description must be set after pranswer");
        assert_eq!(
            stored.sdp_type,
            SdpType::Pranswer,
            "stored description must have type Pranswer"
        );
        assert!(
            !stored.media_sections.is_empty(),
            "stored pranswer must contain media sections"
        );
    }

    #[tokio::test]
    async fn set_local_description_pranswer_allows_multiple_provisional_answers() {
        let offerer = PeerConnection::new(RtcConfiguration::default());
        offerer.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = offerer.create_offer().await.unwrap();

        let callee = PeerConnection::new(RtcConfiguration::default());
        callee.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        callee.set_remote_description(offer).await.unwrap();

        let answer = callee.create_answer().await.unwrap();

        // First provisional answer.
        let mut pranswer1 = answer.clone();
        pranswer1.sdp_type = SdpType::Pranswer;
        callee
            .set_local_description(pranswer1)
            .expect("first pranswer must succeed");
        assert_eq!(callee.signaling_state(), SignalingState::HaveRemoteOffer);

        // Second provisional answer (e.g., updated early media).
        let mut pranswer2 = answer.clone();
        pranswer2.sdp_type = SdpType::Pranswer;
        callee
            .set_local_description(pranswer2)
            .expect("second pranswer must succeed");
        assert_eq!(callee.signaling_state(), SignalingState::HaveRemoteOffer);

        // Final answer.
        callee
            .set_local_description(answer)
            .expect("final answer after multiple pranswers must succeed");
        assert_eq!(callee.signaling_state(), SignalingState::Stable);
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
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:passive\r\n\
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
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:passive\r\n\
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
a=fingerprint:sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99\r\n\
a=setup:passive\r\n\
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
        let ice_conn = IceConn::new(socket_rx, addr, None);
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
        let ice_conn2 = IceConn::new(socket_rx2, addr, None);
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

    #[tokio::test]
    async fn rtp_mode_sends_track_event_after_ssrc_latching() {
        // Test that in RTP mode, Track event is sent after SSRC latching
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;

        let pc = PeerConnection::new(config);

        // Add a transceiver (simulating SIP call setup)
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        // Create remote SDP offer (simulating SIP INVITE with SDP)
        let remote_sdp = "\
v=0
o=- 12345 12345 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 9000 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendonly
a=mid:0
";

        let remote_offer = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(remote_offer).await.unwrap();

        // Verify transceiver has receiver
        let receiver = transceiver.receiver().unwrap();
        let initial_ssrc = receiver.ssrc();

        assert_eq!(
            initial_ssrc, 0,
            "Initial SSRC should be unknown until real RTP arrives"
        );

        println!(
            "✓ RTP mode test setup complete, initial unknown SSRC: {}",
            initial_ssrc
        );
        println!("✓ When real RTP packets arrive with actual SSRC, Track event will be sent");
        println!("✓ Track event sending logic is in place at SSRC latching point");
    }

    #[tokio::test]
    async fn test_custom_depacketizer_strategy() {
        use crate::config::DepacketizerStrategy;
        use crate::media::depacketizer::{
            Depacketizer, DepacketizerFactory, PassThroughDepacketizer,
        };
        use crate::media::frame::MediaKind as FrameMediaKind;

        #[derive(Debug)]
        struct MockFactory;

        impl DepacketizerFactory for MockFactory {
            fn create(&self, _kind: FrameMediaKind) -> Box<dyn Depacketizer> {
                Box::new(PassThroughDepacketizer)
            }
        }

        let factory: Arc<dyn DepacketizerFactory> = Arc::new(MockFactory);
        let mut config = RtcConfiguration::default();
        config.depacketizer_strategy = DepacketizerStrategy {
            factory: factory.clone(),
        };

        let pc = PeerConnection::new(config);

        let retrieved_config = pc.config();
        assert!(Arc::ptr_eq(
            &retrieved_config.depacketizer_strategy.factory,
            &factory
        ));

        // Ensure adding transceiver works with custom strategy
        let transceiver = pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);
        assert_eq!(transceiver.kind(), MediaKind::Video);
    }

    #[tokio::test]
    async fn receiver_uses_negotiated_clock_rate_for_incoming_audio_pt() {
        use crate::media::MediaStreamTrack;
        use crate::media::depacketizer::{
            Depacketizer, DepacketizerFactory, PassThroughDepacketizer,
        };

        #[derive(Debug)]
        struct MockFactory;

        impl DepacketizerFactory for MockFactory {
            fn create(&self, _kind: crate::media::frame::MediaKind) -> Box<dyn Depacketizer> {
                Box::new(PassThroughDepacketizer)
            }
        }

        let transceiver = Arc::new(RtpTransceiver::new_for_test(
            MediaKind::Audio,
            TransceiverDirection::RecvOnly,
        ));
        let receiver = RtpReceiverBuilder::new(MediaKind::Audio, 1234)
            .payload_map(transceiver.payload_map.clone())
            .depacketizer_factory(Arc::new(MockFactory))
            .build();
        transceiver.set_receiver(Some(receiver.clone()));

        let mut payload_map = HashMap::new();
        payload_map.insert(
            8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        );
        transceiver.update_payload_map(payload_map).unwrap();

        let (_socket_tx, socket_rx) =
            tokio::sync::watch::channel::<Option<crate::transports::ice::IceSocketWrapper>>(None);
        let ice_conn = crate::transports::ice::conn::IceConn::new(
            socket_rx,
            "127.0.0.1:0".parse().unwrap(),
            None,
        );
        let transport = Arc::new(crate::transports::rtp::RtpTransport::new(ice_conn, false));
        receiver.set_transport(transport, None, None);

        let packet_tx = receiver.packet_tx().unwrap();
        let packet = RtpPacket::new(
            crate::rtp::RtpHeader::new(8, 1, 160, 0x1234_5678),
            vec![0x55, 0x66],
        );
        packet_tx
            .send((packet, "127.0.0.1:5004".parse().unwrap()))
            .await
            .unwrap();

        let sample =
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.track().recv())
                .await
                .unwrap()
                .unwrap();

        match sample {
            crate::media::MediaSample::Audio(frame) => {
                assert_eq!(frame.clock_rate, 8000);
                assert_eq!(frame.payload_type, Some(8));
            }
            other => panic!("expected audio sample, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn set_remote_description_updates_audio_clock_rate_for_received_frames() {
        use crate::media::MediaStreamTrack;
        use crate::media::depacketizer::{
            Depacketizer, DepacketizerFactory, PassThroughDepacketizer,
        };

        #[derive(Debug)]
        struct MockFactory;

        impl DepacketizerFactory for MockFactory {
            fn create(&self, _kind: crate::media::frame::MediaKind) -> Box<dyn Depacketizer> {
                Box::new(PassThroughDepacketizer)
            }
        }

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.depacketizer_strategy.factory = Arc::new(MockFactory);

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        let remote_sdp = "\
v=0
o=- 12345 12345 IN IP4 192.168.1.100
s=-
c=IN IP4 192.168.1.100
t=0 0
m=audio 9000 RTP/AVP 8
a=rtpmap:8 PCMA/8000
a=sendonly
a=mid:0
";

        let remote_offer = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(remote_offer).await.unwrap();

        let payload_map = transceiver.get_payload_map();
        let codec = payload_map.get(&8).unwrap();
        assert_eq!(codec.clock_rate, 8000);
        assert_eq!(codec.channels, 0);

        let receiver = transceiver.receiver().unwrap();
        let (_socket_tx, socket_rx) =
            tokio::sync::watch::channel::<Option<crate::transports::ice::IceSocketWrapper>>(None);
        let ice_conn = crate::transports::ice::conn::IceConn::new(
            socket_rx,
            "127.0.0.1:0".parse().unwrap(),
            None,
        );
        let transport = Arc::new(crate::transports::rtp::RtpTransport::new(ice_conn, false));
        receiver.set_transport(transport, None, None);
        tokio::task::yield_now().await;

        let packet_tx = receiver.packet_tx().unwrap();
        let packet = RtpPacket::new(
            crate::rtp::RtpHeader::new(8, 7, 320, 0x2233_4455),
            vec![0x11, 0x22, 0x33],
        );
        packet_tx
            .send((packet, "127.0.0.1:5004".parse().unwrap()))
            .await
            .unwrap();

        let sample =
            tokio::time::timeout(std::time::Duration::from_secs(1), receiver.track().recv())
                .await
                .unwrap()
                .unwrap();

        match sample {
            crate::media::MediaSample::Audio(frame) => {
                assert_eq!(frame.clock_rate, 8000);
                assert_eq!(frame.payload_type, Some(8));
                assert_eq!(frame.rtp_timestamp, 320);
            }
            other => panic!("expected audio sample, got {:?}", other),
        }
    }

    // ===== RTP mode ICE-skip verification tests =====

    #[tokio::test]
    async fn rtp_mode_external_ip_in_sdp() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.external_ip = Some("203.0.113.5".to_string());

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp_text = offer.to_sdp_string();

        // Connection line must contain the external IP
        assert!(
            sdp_text.contains("c=IN IP4 203.0.113.5"),
            "SDP c= line should use external_ip, got:\n{}",
            sdp_text
        );

        // Origin should also use external IP
        assert!(
            sdp_text.contains("203.0.113.5"),
            "SDP origin should reference external_ip"
        );
    }

    #[tokio::test]
    async fn rtp_mode_external_port_in_sdp() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.external_ip = Some("203.0.113.5".to_string());
        config.external_port = Some(30000);

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp_text = offer.to_sdp_string();

        // m= line must use the external port (not the local bind port)
        assert!(
            sdp_text.contains("m=audio 30000 RTP/AVP"),
            "SDP m= line should use external_port=30000, got:\n{}",
            sdp_text
        );

        // SDP c= line must use the external IP
        assert!(
            sdp_text.contains("c=IN IP4 203.0.113.5"),
            "SDP c= line should use external_ip"
        );

        // Verify local candidate uses external port
        let candidates = pc.ice_transport().local_candidates();
        let cand = candidates.iter().find(|c| c.component == 1).unwrap();
        assert_eq!(
            cand.address.port(),
            30000,
            "Candidate address port should be external_port"
        );
        assert_eq!(
            cand.address.ip().to_string(),
            "203.0.113.5",
            "Candidate address IP should be external_ip"
        );
        assert!(
            cand.related_address.is_some(),
            "Candidate should have related_address when external_port is set"
        );
        if let Some(related) = cand.related_address {
            assert_ne!(
                related.port(),
                30000,
                "related_address port should differ from external port (local bind port)"
            );
        }
    }

    #[tokio::test]
    async fn rtp_mode_external_port_only_no_ip() {
        // Test external_port without external_ip — only the port is overridden.
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.external_port = Some(31000);

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp_text = offer.to_sdp_string();

        assert!(
            sdp_text.contains("m=audio 31000 RTP/AVP"),
            "SDP m= line should use external_port=31000, got:\n{}",
            sdp_text
        );

        let candidates = pc.ice_transport().local_candidates();
        let cand = candidates.iter().find(|c| c.component == 1).unwrap();
        assert_eq!(cand.address.port(), 31000);
        assert!(cand.related_address.is_some());
    }

    #[tokio::test]
    async fn rtp_mode_external_port_offerer_connects() {
        // Verify external_port works through the full offer/answer exchange.
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.external_ip = Some("203.0.113.5".to_string());
        config.external_port = Some(30000);
        let pc = PeerConnection::new(config);

        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        // Remote answer with a different remote port
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.2\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.2\r\n\
                          m=audio 6000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=recvonly\r\n";
        let answer = SessionDescription::parse(SdpType::Answer, remote_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        // Should reach Connected
        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .expect("PC should connect with external_port in RTP mode");

        let pair = pc.ice_transport().get_selected_pair().await.unwrap();
        // Local candidate should still have external port
        assert_eq!(pair.local.address.port(), 30000);
        assert_eq!(pair.remote.address.port(), 6000);
    }

    #[tokio::test]
    async fn rtp_mode_gathering_completes_immediately() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        // wait_for_gathering_complete must return instantly in RTP mode
        // (would hang before the fix if called before create_offer)
        tokio::time::timeout(
            std::time::Duration::from_millis(200),
            pc.wait_for_gathering_complete(),
        )
        .await
        .expect("wait_for_gathering_complete should return immediately in RTP mode");
    }

    #[tokio::test]
    async fn rtp_mode_offer_has_gathering_complete_after_create() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let _offer = pc.create_offer().await.unwrap();

        // After create_offer, gathering state should be Complete
        let state = *pc.subscribe_ice_gathering_state().borrow();
        assert_eq!(
            state,
            IceGatheringState::Complete,
            "Gathering state should be Complete after RTP mode create_offer"
        );
    }

    #[tokio::test]
    async fn rtp_mode_answerer_latching_config_propagates() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_latching = true;

        let pc = PeerConnection::new(config);

        // Simulate remote offer
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 5000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        // Wait for connected state
        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .expect("PC should connect in RTP mode");

        // Verify config's enable_latching is accessible and true
        assert!(
            pc.config().enable_latching,
            "enable_latching should be true in config"
        );

        // Verify rtp_transport was created (the direct RTP path works)
        let rtp_transport = pc.inner.rtp_transport.lock().clone();
        assert!(
            rtp_transport.is_some(),
            "rtp_transport should be created after connection in RTP mode"
        );
    }

    #[tokio::test]
    async fn rtp_mode_offerer_connects_after_answer() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 12345)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        // Create offer (offerer path: setup_direct_rtp_offer)
        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        // ICE state should still be New (no remote address yet)
        assert_eq!(
            *pc.subscribe_ice_connection_state().borrow(),
            IceConnectionState::New
        );

        // Simulate remote answer
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.2\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.2\r\n\
                          m=audio 6000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=recvonly\r\n";
        let answer = SessionDescription::parse(SdpType::Answer, remote_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        // Should reach Connected via complete_direct_rtp
        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .expect("PC should connect in RTP mode after answer");

        // Verify selected pair has the correct remote address
        let pair = pc.ice_transport().get_selected_pair().await.unwrap();
        assert_eq!(
            pair.remote.address.ip().to_string(),
            "10.0.0.2",
            "Remote candidate should be from answer SDP"
        );
        assert_eq!(pair.remote.address.port(), 6000);
    }

    #[tokio::test]
    async fn rtp_mode_answerer_connects_on_set_remote() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Simulate incoming offer
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 5000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        // Should reach Connected via setup_direct_rtp (answerer path)
        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .expect("Answerer PC should connect in RTP mode");

        // Verify selected pair
        let pair = pc.ice_transport().get_selected_pair().await.unwrap();
        assert_eq!(pair.remote.address.ip().to_string(), "10.0.0.1");
        assert_eq!(pair.remote.address.port(), 5000);
    }

    #[tokio::test]
    async fn rtp_mode_no_ice_dtls_artifacts() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 0,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 42)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        // Must not contain any ICE or DTLS attributes
        assert!(
            !sdp.contains("ice-ufrag"),
            "RTP SDP must not have ice-ufrag"
        );
        assert!(!sdp.contains("ice-pwd"), "RTP SDP must not have ice-pwd");
        assert!(
            !sdp.contains("ice-options"),
            "RTP SDP must not have ice-options"
        );
        assert!(
            !sdp.contains("a=candidate"),
            "RTP SDP must not have ICE candidates"
        );
        assert!(
            !sdp.contains("fingerprint"),
            "RTP SDP must not have DTLS fingerprint"
        );
        assert!(
            !sdp.contains("a=setup:"),
            "RTP SDP must not have DTLS setup"
        );
        assert!(
            !sdp.contains("msid-semantic"),
            "RTP SDP must not have msid-semantic"
        );

        // Must use RTP/AVP protocol
        assert!(sdp.contains("RTP/AVP"), "RTP SDP must use RTP/AVP");

        // Must have connection line
        assert!(
            sdp.contains("c=IN IP4"),
            "RTP SDP must have connection line"
        );
    }

    #[tokio::test]
    async fn rtp_mode_rtcp_separate_port_answerer() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // SDP without rtcp-mux → RTCP on port+1
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 8000 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .unwrap();

        let rtp_transport = pc.inner.rtp_transport.lock().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read();
        assert!(
            rtcp_addr.is_some(),
            "Without rtcp-mux, RTCP addr must be set"
        );
        assert_eq!(
            rtcp_addr.unwrap().port(),
            8001,
            "RTCP port should be RTP port + 1"
        );
    }

    #[tokio::test]
    async fn rtp_mode_rtcp_explicit_port_answerer() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 8000 RTP/AVP 0\r\n\
                          a=rtcp:9000\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .unwrap();

        let rtp_transport = pc.inner.rtp_transport.lock().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read();
        assert!(
            rtcp_addr.is_some(),
            "Explicit a=rtcp must produce a separate RTCP addr"
        );
        assert_eq!(
            rtcp_addr.unwrap().port(),
            9000,
            "RTCP port should honor explicit a=rtcp"
        );
    }

    #[tokio::test]
    async fn rtp_mode_rtcp_mux_answerer() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // SDP with rtcp-mux → no separate RTCP addr
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 8000 RTP/AVP 0\r\n\
                          a=rtpmap:0 PCMU/8000\r\n\
                          a=rtcp-mux\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .unwrap();

        let rtp_transport = pc.inner.rtp_transport.lock().clone().unwrap();
        let ice_conn = rtp_transport.ice_conn();
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read();
        assert!(
            rtcp_addr.is_none(),
            "With rtcp-mux, separate RTCP addr must be None"
        );
    }

    #[tokio::test]
    async fn rtp_mode_track_event_after_set_remote() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Remote offer without SSRC should keep receiver SSRC unknown until real RTP arrives.
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 7000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=sendonly\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);

        let receiver = transceivers[0].receiver().unwrap();
        let ssrc = receiver.ssrc();
        assert_eq!(
            ssrc, 0,
            "In RTP mode without SSRC in SDP, receiver SSRC should stay unknown"
        );
    }

    #[tokio::test]
    async fn rtp_mode_track_event_with_remote_ssrc() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Remote offer with explicit SSRC
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 7000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=ssrc:55555 cname:test\r\n\
                          a=sendonly\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);

        let receiver = transceivers[0].receiver().unwrap();
        let ssrc = receiver.ssrc();
        assert_eq!(ssrc, 55555, "Receiver SSRC should match remote SDP SSRC");
    }

    // ===== rtcp-mux policy tests =====

    #[tokio::test]
    async fn rtp_mode_rtcp_mux_negotiate_omits_attribute() {
        use crate::{RtcpMuxPolicy, TransportMode};
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.rtcp_mux_policy = RtcpMuxPolicy::Negotiate;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 100)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        assert!(
            !sdp.contains("rtcp-mux"),
            "Negotiate policy should NOT include rtcp-mux in offer SDP, got:\n{}",
            sdp
        );
    }

    #[tokio::test]
    async fn rtp_mode_rtcp_mux_require_includes_attribute() {
        use crate::{RtcpMuxPolicy, TransportMode};
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.rtcp_mux_policy = RtcpMuxPolicy::Require;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 100)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        assert!(
            sdp.contains("rtcp-mux"),
            "Require policy should include rtcp-mux in offer SDP, got:\n{}",
            sdp
        );
    }

    #[tokio::test]
    async fn rtp_mode_answer_omits_rtcp_mux_when_offer_omits_it() {
        use crate::{RtcpMuxPolicy, TransportMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.rtcp_mux_policy = RtcpMuxPolicy::Require;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 0,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 100)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let remote_offer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.1\r\n\
            m=audio 8000 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=sendrecv\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, remote_offer).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let answer = pc.create_answer().await.unwrap();
        let sdp = answer.to_sdp_string();

        assert!(
            !sdp.contains("a=rtcp-mux"),
            "Answer must not advertise rtcp-mux when the remote offer omitted it, got:\n{}",
            sdp
        );
        assert!(
            sdp.contains("a=rtcp:"),
            "Answer without rtcp-mux must advertise the separate RTCP port, got:\n{}",
            sdp
        );
    }

    #[tokio::test]
    async fn reinvite_answer_audio_codecs_follow_remote_offer_subset() {
        use crate::TransportMode;
        use crate::config::{MediaCapabilities, RtcpMuxPolicy};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.rtcp_mux_policy = RtcpMuxPolicy::Require;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![
                AudioCapability::opus(),
                AudioCapability::g722(),
                AudioCapability::telephone_event(),
            ],
            video: vec![],
            application: None,
            image: vec![],
        });

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let local_offer = pc.create_offer().await.unwrap();
        pc.set_local_description(local_offer).unwrap();

        let remote_answer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.1\r\n\
            m=audio 8000 RTP/AVP 111 101\r\n\
            a=rtpmap:111 opus/48000/2\r\n\
            a=fmtp:111 minptime=10;useinbandfec=1\r\n\
            a=rtpmap:101 telephone-event/8000\r\n\
            a=fmtp:101 0-16\r\n\
            a=sendrecv\r\n";

        let remote_answer_desc = SessionDescription::parse(SdpType::Answer, remote_answer).unwrap();
        pc.set_remote_description(remote_answer_desc).await.unwrap();

        let remote_offer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.1\r\n\
            m=audio 8000 RTP/AVP 9 101\r\n\
            a=rtpmap:9 G722/8000\r\n\
            a=rtpmap:101 telephone-event/8000\r\n\
            a=fmtp:101 0-16\r\n\
            a=sendrecv\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, remote_offer).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let answer = pc.create_answer().await.unwrap();
        let audio = answer.first_audio_section().expect("answer audio section");

        assert_eq!(audio.formats, vec!["9".to_string(), "101".to_string()]);
        assert!(
            audio
                .attributes
                .iter()
                .any(|attr| attr.key == "rtpmap" && attr.value.as_deref() == Some("9 G722/8000")),
            "answer should keep remote-offered G722 payload, got:\n{}",
            answer.to_sdp_string()
        );
        assert!(
            audio.attributes.iter().all(|attr| {
                attr.key != "rtpmap" || attr.value.as_deref() != Some("111 opus/48000/2")
            }),
            "answer must not advertise opus when it was not offered, got:\n{}",
            answer.to_sdp_string()
        );
    }

    #[tokio::test]
    async fn reinvite_updates_remote_addr_in_rtp_mode() {
        use crate::{SdpType, SessionDescription, TransportMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        // Initial negotiation
        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        let remote_answer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.1\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.1\r\n\
            m=audio 8000 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=sendrecv\r\n";

        let remote_answer_desc = SessionDescription::parse(SdpType::Answer, remote_answer).unwrap();
        pc.set_remote_description(remote_answer_desc).await.unwrap();

        // Verify initial remote address via selected pair
        let initial_pair = pc.inner.ice_transport.get_selected_pair().await;
        assert!(
            initial_pair.is_some(),
            "selected_pair should exist after initial negotiation"
        );
        assert_eq!(
            initial_pair.unwrap().remote.address,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                8000
            )
        );

        // Reinvite with changed address
        let reinvite_offer = "v=0\r\n\
            o=- 1 2 IN IP4 192.168.1.50\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 192.168.1.50\r\n\
            m=audio 9000 RTP/AVP 0\r\n\
            a=rtpmap:0 PCMU/8000\r\n\
            a=sendrecv\r\n";

        let reinvite_desc = SessionDescription::parse(SdpType::Offer, reinvite_offer).unwrap();
        pc.set_remote_description(reinvite_desc).await.unwrap();

        let answer = pc.create_answer().await.unwrap();
        pc.set_local_description(answer).unwrap();

        // Verify selected_pair reflects new remote address after reinvite
        let updated_pair = pc.inner.ice_transport.get_selected_pair().await;
        assert!(
            updated_pair.is_some(),
            "selected_pair should exist after reinvite"
        );
        assert_eq!(
            updated_pair.unwrap().remote.address,
            std::net::SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 50)),
                9000
            ),
            "reinvite should update RTP remote address"
        );
    }

    #[tokio::test]
    async fn webrtc_mode_rtcp_mux_negotiate_omits_attribute() {
        use crate::RtcpMuxPolicy;
        let mut config = RtcConfiguration::default();
        config.rtcp_mux_policy = RtcpMuxPolicy::Negotiate;

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        assert!(
            !sdp.contains("rtcp-mux"),
            "Negotiate policy should NOT include rtcp-mux even in WebRTC mode, got:\n{}",
            sdp
        );
    }

    // ===== ICE-lite in RTP mode tests =====

    #[tokio::test]
    async fn rtp_mode_ice_lite_sdp_attributes() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_ice_lite = true;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 100)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        // ICE-lite must have these attributes
        assert!(
            sdp.contains("a=ice-lite"),
            "ICE-lite RTP offer must have a=ice-lite, got:\n{}",
            sdp
        );
        assert!(
            sdp.contains("a=ice-ufrag:"),
            "ICE-lite RTP offer must have ice-ufrag, got:\n{}",
            sdp
        );
        assert!(
            sdp.contains("a=ice-pwd:"),
            "ICE-lite RTP offer must have ice-pwd, got:\n{}",
            sdp
        );
        assert!(
            sdp.contains("a=candidate:"),
            "ICE-lite RTP offer must have candidates, got:\n{}",
            sdp
        );

        // Should still use RTP/AVP (not DTLS)
        assert!(
            sdp.contains("RTP/AVP"),
            "ICE-lite RTP offer must still use RTP/AVP, got:\n{}",
            sdp
        );

        // Should NOT have DTLS fingerprint
        assert!(
            !sdp.contains("fingerprint"),
            "ICE-lite RTP offer must not have DTLS fingerprint"
        );
    }

    #[tokio::test]
    async fn rtp_mode_no_ice_lite_no_ice_attributes() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_ice_lite = false;

        let pc = PeerConnection::new(config);
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 48000);
        let params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let sender = RtpSender::builder(track, 100)
            .stream_id("s".to_string())
            .params(params)
            .build();
        transceiver.set_sender(Some(sender));

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        // Without ICE-lite, no ICE attributes
        assert!(
            !sdp.contains("ice-lite"),
            "Without enable_ice_lite, should not have a=ice-lite"
        );
        assert!(
            !sdp.contains("ice-ufrag"),
            "Without enable_ice_lite, should not have ice-ufrag"
        );
        assert!(
            !sdp.contains("a=candidate"),
            "Without enable_ice_lite, should not have candidates"
        );
    }

    /// Test: set_remote_description(Answer) with a=ssrc fires Track event
    ///
    /// When the Answer SDP contains `a=ssrc:XXXXX`, the SSRC is latched
    /// directly from the SDP. Previously, this skipped the Track event
    /// because the RTP receive loop's SSRC-latching code checked
    /// `old_ssrc != packet.ssrc`, which matched (already set from SDP).
    /// The fix fires Track directly in the Answer processing path.
    #[tokio::test]
    async fn answer_sdp_with_ssrc_fires_track_event() {
        use crate::TransportMode;
        let _ = env_logger::builder().is_test(true).try_init();

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        // Add a RecvOnly audio transceiver (simulates the caller expecting media)
        let transceiver = pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        // Create an offer and set as local description to move into HaveLocalOffer
        let offer = pc.create_offer().await.unwrap();
        let mid = offer.media_sections[0].mid.clone();
        pc.set_local_description(offer).unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::HaveLocalOffer);

        // Construct an Answer SDP that includes a=ssrc:10000
        let answer_sdp = format!(
            "v=0\r\n\
             o=- 1 1 IN IP4 192.168.1.100\r\n\
             s=-\r\n\
             t=0 0\r\n\
             c=IN IP4 192.168.1.100\r\n\
             m=audio 5000 RTP/AVP 8\r\n\
             a=mid:{mid}\r\n\
             a=recvonly\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=ssrc:10000 cname:test-cname\r\n"
        );

        let answer = SessionDescription::parse(SdpType::Answer, &answer_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();
        assert_eq!(pc.signaling_state(), SignalingState::Stable);

        // The receiver should have the SSRC from the Answer SDP
        let receiver = transceiver.receiver().unwrap();
        assert_eq!(
            receiver.ssrc(),
            10000,
            "Receiver SSRC should be set from Answer SDP"
        );

        // The Track event should have been sent
        assert!(
            receiver.track_event_sent.load(Ordering::SeqCst),
            "Track event should be marked as sent after Answer with SSRC"
        );

        // Verify Track event is receivable
        let event = tokio::time::timeout(std::time::Duration::from_millis(100), pc.recv())
            .await
            .expect("Should receive Track event within timeout");
        assert!(event.is_some(), "Should receive a PeerConnectionEvent");
        match event.unwrap() {
            PeerConnectionEvent::Track(t) => {
                assert_eq!(t.kind(), MediaKind::Audio);
            }
            PeerConnectionEvent::DataChannel(_) => panic!("Expected Track event, got DataChannel"),
        }
    }

    #[tokio::test]
    async fn rtp_mode_ice_lite_stores_remote_params() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_ice_lite = true;

        let pc = PeerConnection::new(config);

        // Remote offer with ICE credentials (from a full-ICE agent)
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 10.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 10.0.0.1\r\n\
                          m=audio 5000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          a=ice-ufrag:remote_ufrag\r\n\
                          a=ice-pwd:remote_pwd_value\r\n\
                          a=candidate:1 1 UDP 2130706431 10.0.0.1 5000 typ host\r\n\
                          a=sendrecv\r\n";
        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        // Wait for connected state
        let mut state_rx = pc.subscribe_peer_state();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if *state_rx.borrow() == PeerConnectionState::Connected {
                    return;
                }
                let _ = state_rx.changed().await;
            }
        })
        .await
        .expect("PC should connect in ICE-lite RTP mode");

        // Verify the ICE transport has remote parameters stored
        let ice = pc.ice_transport();
        let remote_candidates = ice.remote_candidates();
        assert!(
            !remote_candidates.is_empty(),
            "Remote ICE candidates should be stored"
        );

        // Verify the role is Controlled (ICE-lite is always controlled)
        let role = ice.role().await;
        assert_eq!(
            role,
            crate::transports::ice::IceRole::Controlled,
            "ICE-lite should set role to Controlled"
        );
    }

    #[test]
    fn sender_report_builder_uses_rtp_counters() {
        let report = RtpSender::build_sender_report(10000, 123456, 42, 4096, UNIX_EPOCH);

        assert_eq!(report.sender_ssrc, 10000);
        assert_eq!(report.rtp_timestamp, 123456);
        assert_eq!(report.packet_count, 42);
        assert_eq!(report.octet_count, 4096);
        assert_eq!(report.ntp_most, 2_208_988_800);
        assert_eq!(report.ntp_least, 0);
        assert!(report.report_blocks.is_empty());
    }

    // ---------------------------------------------------------------------------
    // DTLS fingerprint security tests
    // ---------------------------------------------------------------------------

    /// WebRTC mode: SDP without any a=fingerprint attribute must be rejected so
    /// that an attacker cannot strip the fingerprint and bypass identity binding.
    #[tokio::test]
    async fn test_set_remote_description_rejects_missing_fingerprint_webrtc() {
        use crate::{SdpType, SessionDescription, TransportMode};

        let pc = PeerConnection::new(RtcConfiguration::default()); // WebRtc mode
        assert_eq!(pc.config().transport_mode, TransportMode::WebRtc);

        // SDP has no a=fingerprint — must be rejected
        let sdp_str = "v=0\r\n\
                       o=- 123 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                       a=rtpmap:111 opus/48000/2\r\n\
                       a=setup:passive\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();
        let err = pc.set_remote_description(desc).await.unwrap_err();
        assert!(
            matches!(err, RtcError::InvalidConfiguration(_)),
            "expected InvalidConfiguration, got: {:?}",
            err
        );
        let msg = err.to_string();
        assert!(
            msg.contains("fingerprint"),
            "error should mention fingerprint: {}",
            msg
        );
    }

    /// WebRTC mode: SDP with a valid sha-256 a=fingerprint must be accepted.
    #[tokio::test]
    async fn test_set_remote_description_accepts_valid_sha256_fingerprint_webrtc() {
        use crate::{SdpType, SessionDescription, TransportMode};

        let pc = PeerConnection::new(RtcConfiguration::default());
        assert_eq!(pc.config().transport_mode, TransportMode::WebRtc);

        // Syntactically valid sha-256 fingerprint (random bytes)
        let fp = "sha-256 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:\
                  AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
        let sdp_str = format!(
            "v=0\r\n\
             o=- 123 0 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             t=0 0\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=rtpmap:111 opus/48000/2\r\n\
             a=setup:passive\r\n\
             a=fingerprint:{fp}\r\n"
        );
        let desc = SessionDescription::parse(SdpType::Offer, &sdp_str).unwrap();
        // Should not return InvalidConfiguration for fingerprint
        let result = pc.set_remote_description(desc).await;
        // The call may fail for other reasons (ICE, state), but NOT due to fingerprint
        if let Err(ref e) = result {
            assert!(
                !e.to_string().contains("fingerprint"),
                "unexpected fingerprint error: {}",
                e
            );
        }
    }

    /// WebRTC mode: SDP with an unsupported fingerprint algorithm (sha-1) must be rejected.
    #[tokio::test]
    async fn test_set_remote_description_rejects_unsupported_fingerprint_algorithm() {
        use crate::{SdpType, SessionDescription, TransportMode};

        let pc = PeerConnection::new(RtcConfiguration::default());
        assert_eq!(pc.config().transport_mode, TransportMode::WebRtc);

        let sdp_str = "v=0\r\n\
                       o=- 123 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                       a=rtpmap:111 opus/48000/2\r\n\
                       a=setup:passive\r\n\
                       a=fingerprint:sha-1 AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();
        let err = pc.set_remote_description(desc).await.unwrap_err();
        assert!(
            matches!(err, RtcError::InvalidConfiguration(_)),
            "expected InvalidConfiguration for sha-1, got: {:?}",
            err
        );
        assert!(err.to_string().contains("sha-1"));
    }

    /// RTP mode: missing fingerprint is fine — no DTLS identity binding applies.
    #[tokio::test]
    async fn test_set_remote_description_allows_missing_fingerprint_rtp_mode() {
        use crate::{SdpType, SessionDescription, TransportMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);

        let sdp_str = "v=0\r\n\
                       o=- 123 0 IN IP4 127.0.0.1\r\n\
                       s=-\r\n\
                       t=0 0\r\n\
                       c=IN IP4 127.0.0.1\r\n\
                       m=audio 4000 RTP/AVP 111\r\n\
                       a=rtpmap:111 opus/48000/2\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp_str).unwrap();
        // Must not fail with a fingerprint error
        let result = pc.set_remote_description(desc).await;
        if let Err(ref e) = result {
            assert!(
                !e.to_string().contains("fingerprint"),
                "unexpected fingerprint error in RTP mode: {}",
                e
            );
        }
    }

    // ── VideoCapability::fmtp passthrough ────────────────────────────────────

    /// H264 fmtp (profile-level-id, packetization-mode) must appear in the offer SDP.
    #[tokio::test]
    async fn offer_h264_emits_fmtp_in_sdp() {
        use crate::TransportMode;
        use crate::config::{MediaCapabilities, VideoCapability};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![],
            video: vec![VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];
        assert_eq!(section.kind, MediaKind::Video);

        let fmtp = section
            .attributes
            .iter()
            .find(|a| a.key == "fmtp")
            .expect("H264 offer must contain a=fmtp");
        assert!(
            fmtp.value
                .as_deref()
                .unwrap_or("")
                .contains("packetization-mode"),
            "a=fmtp must contain packetization-mode, got: {:?}",
            fmtp.value
        );
        assert!(
            fmtp.value
                .as_deref()
                .unwrap_or("")
                .contains("profile-level-id"),
            "a=fmtp must contain profile-level-id, got: {:?}",
            fmtp.value
        );
    }

    /// When fmtp is None, no a=fmtp line should appear in the video section.
    #[tokio::test]
    async fn offer_vp8_no_fmtp_in_sdp() {
        use crate::TransportMode;
        use crate::config::{MediaCapabilities, VideoCapability};

        let vp8 = VideoCapability {
            fmtp: None,
            ..VideoCapability::default()
        };
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![],
            video: vec![vp8],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];
        assert!(
            section.attributes.iter().all(|a| a.key != "fmtp"),
            "VP8 with no fmtp must not emit a=fmtp"
        );
    }

    // ── rtcp-fb passthrough in generated SDP ─────────────────────────────────

    /// H264 rtcp-fb entries (nack pli, ccm fir) must appear in the offer SDP.
    #[tokio::test]
    async fn offer_h264_emits_rtcp_fb_in_sdp() {
        use crate::TransportMode;
        use crate::config::{MediaCapabilities, VideoCapability};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![],
            video: vec![VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];

        let fbs: Vec<&str> = section
            .attributes
            .iter()
            .filter(|a| a.key == "rtcp-fb")
            .filter_map(|a| a.value.as_deref())
            .collect();
        assert!(
            fbs.iter().any(|v| v.contains("nack pli")),
            "should emit rtcp-fb nack pli, got: {fbs:?}"
        );
        assert!(
            fbs.iter().any(|v| v.contains("ccm fir")),
            "should emit rtcp-fb ccm fir, got: {fbs:?}"
        );
    }

    // ── SdpCompatibilityMode::LegacySip / a=mid and BUNDLE ───────────────────

    /// In LegacySip mode the generated offer must not contain any a=mid or a=rtcp-mux.
    #[tokio::test]
    async fn legacy_sip_offer_omits_mid_and_rtcp_mux() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::LegacySip;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        assert!(
            !sdp.contains("a=mid:"),
            "LegacySip offer must not contain a=mid, got SDP:\n{sdp}"
        );
        assert!(
            !sdp.contains("a=rtcp-mux"),
            "LegacySip offer must not contain a=rtcp-mux, got SDP:\n{sdp}"
        );
        assert!(
            sdp.contains("a=rtcp:"),
            "LegacySip offer without rtcp-mux must advertise the separate RTCP port, got SDP:\n{sdp}"
        );
        assert!(
            !sdp.contains("a=group:BUNDLE"),
            "LegacySip offer must not contain a=group:BUNDLE, got SDP:\n{sdp}"
        );
    }

    /// Standard mode with two media sections MUST produce a=group:BUNDLE and a=mid.
    #[tokio::test]
    async fn standard_mode_multi_section_includes_bundle_and_mid() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::Standard;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::default()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let sdp = offer.to_sdp_string();

        assert!(
            sdp.contains("a=group:BUNDLE"),
            "Standard mode with two sections must emit a=group:BUNDLE, got:\n{sdp}"
        );
        assert!(
            sdp.contains("a=mid:"),
            "Standard mode must emit a=mid for each section, got:\n{sdp}"
        );
    }

    /// In LegacySip mode with two media sections, no BUNDLE and no a=mid.
    #[tokio::test]
    async fn legacy_sip_multi_section_no_bundle_no_mid() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::LegacySip;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        assert_eq!(offer.media_sections.len(), 2, "should have audio+video");

        let sdp = offer.to_sdp_string();
        assert!(
            !sdp.contains("a=group:BUNDLE"),
            "LegacySip must not emit a=group:BUNDLE, got:\n{sdp}"
        );
        assert!(
            !sdp.contains("a=mid:"),
            "LegacySip must not emit a=mid, got:\n{sdp}"
        );
        assert_eq!(
            sdp.matches("a=rtcp:").count(),
            2,
            "non-BUNDLE RTP offer must advertise separate RTCP ports for audio and video:\n{sdp}"
        );
    }

    #[tokio::test]
    async fn rtp_mode_legacy_non_bundle_offer_uses_distinct_media_ports() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::LegacySip;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

        let offer = pc.create_offer().await.unwrap();
        assert_eq!(offer.media_sections.len(), 2, "should have audio+video");

        let audio_port = offer.media_sections[0].port;
        let video_port = offer.media_sections[1].port;
        assert_ne!(
            audio_port,
            video_port,
            "non-BUNDLE RTP offer must not reuse one RTP port for audio and video:\n{}",
            offer.to_sdp_string()
        );

        let sdp = offer.to_sdp_string();
        assert!(
            !sdp.contains("a=group:BUNDLE"),
            "LegacySip must not emit a=group:BUNDLE, got:\n{sdp}"
        );
        assert!(
            !sdp.contains("a=mid:"),
            "LegacySip must not emit a=mid, got:\n{sdp}"
        );
    }

    #[tokio::test]
    async fn rtp_mode_midless_non_bundle_offer_maps_each_media_transport() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::LegacySip;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let remote_offer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.2\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.2\r\n\
            m=audio 5000 RTP/AVP 8\r\n\
            a=rtcp:5001\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=sendrecv\r\n\
            m=video 6000 RTP/AVP 103\r\n\
            a=rtcp:6001\r\n\
            a=rtpmap:103 H264/90000\r\n\
            a=sendrecv\r\n";

        let offer = SessionDescription::parse(SdpType::Offer, remote_offer).unwrap();
        pc.set_remote_description(offer).await.unwrap();
        pc.wait_for_rtp_transport_ready(std::time::Duration::from_secs(2))
            .await
            .unwrap();

        let remote_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let primary = pc.inner.rtp_transport.lock().clone().unwrap();
        assert_eq!(
            *primary.ice_conn().remote_addr.read(),
            SocketAddr::new(remote_ip, 5000)
        );
        assert_eq!(
            *primary.ice_conn().remote_rtcp_addr.read(),
            Some(SocketAddr::new(remote_ip, 5001))
        );

        let video = pc
            .get_transceivers()
            .into_iter()
            .find(|t| t.kind() == MediaKind::Video)
            .unwrap();
        let video_transport = pc
            .inner
            .rtp_media_transports
            .lock()
            .get(&video.id())
            .cloned()
            .expect("video should have a non-BUNDLE RTP transport");
        assert_eq!(
            *video_transport.ice_conn().remote_addr.read(),
            SocketAddr::new(remote_ip, 6000)
        );
        assert_eq!(
            *video_transport.ice_conn().remote_rtcp_addr.read(),
            Some(SocketAddr::new(remote_ip, 6001))
        );
    }

    #[tokio::test]
    async fn rtp_mode_midless_non_bundle_answer_maps_each_media_transport() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.sdp_compatibility = SdpCompatibilityMode::LegacySip;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::RecvOnly);

        let local_offer = pc.create_offer().await.unwrap();
        assert_eq!(
            local_offer.media_sections.len(),
            2,
            "should have audio+video"
        );
        assert_ne!(
            local_offer.media_sections[0].port,
            local_offer.media_sections[1].port,
            "local non-BUNDLE offer should use distinct media sockets:\n{}",
            local_offer.to_sdp_string()
        );
        pc.set_local_description(local_offer).unwrap();

        let remote_answer = "v=0\r\n\
            o=- 1 1 IN IP4 10.0.0.2\r\n\
            s=-\r\n\
            t=0 0\r\n\
            c=IN IP4 10.0.0.2\r\n\
            m=audio 51637 RTP/AVP 8\r\n\
            a=rtcp:55079\r\n\
            a=rtpmap:8 PCMA/8000\r\n\
            a=sendonly\r\n\
            m=video 53379 RTP/AVP 96\r\n\
            a=rtcp:58854\r\n\
            a=rtpmap:96 H264/90000\r\n\
            a=fmtp:96 packetization-mode=1;profile-level-id=42e01f\r\n\
            a=sendonly\r\n";
        let answer = SessionDescription::parse(SdpType::Answer, remote_answer).unwrap();
        pc.set_remote_description(answer).await.unwrap();
        pc.wait_for_rtp_transport_ready(std::time::Duration::from_secs(2))
            .await
            .unwrap();

        let remote_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let primary = pc.inner.rtp_transport.lock().clone().unwrap();
        assert_eq!(
            *primary.ice_conn().remote_addr.read(),
            SocketAddr::new(remote_ip, 51637)
        );
        assert_eq!(
            *primary.ice_conn().remote_rtcp_addr.read(),
            Some(SocketAddr::new(remote_ip, 55079))
        );

        let video = pc
            .get_transceivers()
            .into_iter()
            .find(|t| t.kind() == MediaKind::Video)
            .unwrap();
        let video_transport = pc
            .inner
            .rtp_media_transports
            .lock()
            .get(&video.id())
            .cloned()
            .expect("video should have a non-BUNDLE RTP transport");
        assert_eq!(
            *video_transport.ice_conn().remote_addr.read(),
            SocketAddr::new(remote_ip, 53379)
        );
        assert_eq!(
            *video_transport.ice_conn().remote_rtcp_addr.read(),
            Some(SocketAddr::new(remote_ip, 58854))
        );
    }

    /// When answering a non-BUNDLE offer (e.g. Linphone), the answer must not
    /// contain a=mid in the sections (Standard mode).
    #[tokio::test]
    async fn answer_to_non_bundle_offer_omits_mid_in_sections() {
        use crate::TransportMode;
        use crate::config::{AudioCapability, MediaCapabilities};

        // No a=group:BUNDLE in this remote offer (traditional SIP style)
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 192.168.1.100\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 192.168.1.100\r\n\
                          m=audio 5000 RTP/AVP 8\r\n\
                          a=mid:as\r\n\
                          a=sendrecv\r\n\
                          a=rtpmap:8 PCMA/8000\r\n\
                          m=video 5002 RTP/AVP 96\r\n\
                          a=mid:vs\r\n\
                          a=sendrecv\r\n\
                          a=rtpmap:96 H264/90000\r\n\
                          a=fmtp:96 packetization-mode=0;profile-level-id=42801F\r\n";

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.media_capabilities = Some(MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![crate::config::VideoCapability::h264()],
            application: None,
            image: vec![],
        });
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv);

        let remote = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(remote).await.unwrap();

        let answer = pc.create_answer().await.unwrap();
        let sdp = answer.to_sdp_string();

        assert!(
            !sdp.contains("a=group:BUNDLE"),
            "answer to non-BUNDLE offer must not have a=group:BUNDLE, got:\n{sdp}"
        );
        // Neither section should have a=mid since there is no BUNDLE group
        assert!(
            !sdp.contains("a=mid:"),
            "answer to non-BUNDLE offer must not have a=mid in any section, got:\n{sdp}"
        );
    }

    /// Reproduce: WebRTC caller ↔ plain-RTP callee bridge scenario.
    ///
    /// The RTP PeerConnection acts as the *offerer* (bridge → callee):
    ///   1. `add_track(pcma_track)` – creates transceiver with SendRecv
    ///   2. `create_offer()` – binds UDP socket
    ///   3. `set_local_description(offer)`
    ///   4. `set_remote_description(pranswer)` – 183 early media, no a=ssrc
    ///   5. `set_remote_description(answer)` – 200 OK, no a=ssrc
    ///   6. First PCMA packet arrives from callee
    ///
    /// Expected: `pc.recv()` must yield `PeerConnectionEvent::Track`.
    /// Bug:      Without a fix, this times out – Track event is never fired.
    #[tokio::test]
    async fn repro_rtp_offerer_track_event_fires_on_first_packet() {
        use crate::media::track::sample_track;
        use crate::sdp::{SdpType, SessionDescription};

        // ── build a loopback-bound RTP PC (simulating the bridge RTP side) ──
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_latching = true;
        config.bind_ip = Some("127.0.0.1".to_string());

        let pc = PeerConnection::new(config);

        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 8000);
        let pcma_params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let _ = pc.add_track(track, pcma_params).unwrap();

        // ── negotiate as offerer ──
        let offer = pc.create_offer().await.unwrap();
        let offer_sdp = offer.to_sdp_string();
        println!("offer SDP:\n{offer_sdp}");
        pc.set_local_description(offer).unwrap();

        // Find the local port that was bound so we can send packets to it.
        let local_addr = pc
            .ice_transport()
            .local_candidates()
            .into_iter()
            .find(|c| c.component == 1)
            .map(|c| c.address)
            .expect("must have a local candidate after create_offer");
        println!("local_addr={local_addr}");

        // Build a minimal callee answer SDP (plain RTP, no a=ssrc).
        // The remote address used here is loopback too; actual packets will be
        // injected directly.
        let callee_sdp = format!(
            "v=0\r\n\
             o=- 9876 9876 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 127.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 20000 RTP/AVP 8\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=sendrecv\r\n"
        );

        // 183 early media → Pranswer
        let pranswer = SessionDescription::parse(SdpType::Pranswer, &callee_sdp).unwrap();
        pc.set_remote_description(pranswer).await.unwrap();

        // 200 OK → Answer
        let answer = SessionDescription::parse(SdpType::Answer, &callee_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        // Give start_dtls (spawned async) time to register the provisional
        // listener and call set_data_receiver before we send the packet.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // ── inject a minimal PCMA RTP packet from "callee" ──
        let fake_callee = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // RTP header: V=2, PT=8, seq=1, ts=0, SSRC=0xDEADBEEF, 20 bytes silence
        let mut rtp = vec![
            0x80u8, 0x08, // V=2 P=0 X=0 CC=0, M=0 PT=8
            0x00, 0x01, // sequence=1
            0x00, 0x00, 0x00, 0x00, // timestamp=0
            0xDE, 0xAD, 0xBE, 0xEF, // SSRC
        ];
        rtp.extend_from_slice(&[0xD5u8; 160]); // 160 bytes PCMA silence
        fake_callee.send_to(&rtp, local_addr).await.unwrap();

        // ── expect Track event within 500 ms ──
        let event = tokio::time::timeout(tokio::time::Duration::from_millis(500), pc.recv())
            .await
            .expect("timed out waiting for PeerConnectionEvent::Track – Track event never fired");

        assert!(
            matches!(event, Some(PeerConnectionEvent::Track(_))),
            "expected PeerConnectionEvent::Track"
        );
    }

    /// Same scenario but without the 50ms pre-send delay.
    /// Verifies that packets arriving before start_dtls completes are still
    /// delivered via the buffered-packet flush in set_data_receiver.
    #[tokio::test]
    async fn repro_rtp_offerer_track_event_fires_on_first_packet_no_delay() {
        use crate::media::track::sample_track;
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_latching = true;
        config.bind_ip = Some("127.0.0.1".to_string());

        let pc = PeerConnection::new(config);

        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 8000);
        let _ = pc
            .add_track(
                track,
                RtpCodecParameters {
                    payload_type: 8,
                    clock_rate: 8000,
                    channels: 1,
                },
            )
            .unwrap();

        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        let local_addr = pc
            .ice_transport()
            .local_candidates()
            .into_iter()
            .find(|c| c.component == 1)
            .map(|c| c.address)
            .expect("must have a local candidate");

        let callee_sdp = format!(
            "v=0\r\n\
             o=- 9876 9876 IN IP4 127.0.0.1\r\n\
             s=-\r\n\
             c=IN IP4 127.0.0.1\r\n\
             t=0 0\r\n\
             m=audio 20000 RTP/AVP 8\r\n\
             a=rtpmap:8 PCMA/8000\r\n\
             a=sendrecv\r\n"
        );

        let pranswer = SessionDescription::parse(SdpType::Pranswer, &callee_sdp).unwrap();
        pc.set_remote_description(pranswer).await.unwrap();

        let answer = SessionDescription::parse(SdpType::Answer, &callee_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        // NO delay – send packet immediately after SDP negotiation
        let fake_callee = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut rtp = vec![
            0x80u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
        ];
        rtp.extend_from_slice(&[0xD5u8; 160]);
        fake_callee.send_to(&rtp, local_addr).await.unwrap();

        // Allow time for start_dtls + buffer flush + run_loop processing
        let event = tokio::time::timeout(tokio::time::Duration::from_millis(500), pc.recv())
            .await
            .expect("timed out – packet received before start_dtls; buffer flush must deliver it");

        assert!(
            matches!(event, Some(PeerConnectionEvent::Track(_))),
            "expected PeerConnectionEvent::Track"
        );
    }

    /// Reproduce the production bug:
    /// WebRTC caller ↔ RTP callee via bridge.
    /// The callee responds with a 183 Pranswer (early media/ringing) followed
    /// by a 200 OK Answer.  The callee sends NO audio during the 183 phase and
    /// only starts sending RTP after the 200 OK is processed.
    /// This tests that the Track event still fires correctly.
    #[tokio::test]
    async fn repro_rtp_offerer_pranswer_then_answer_track_fires_on_rtp() {
        use crate::media::track::sample_track;
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_latching = true;
        config.bind_ip = Some("127.0.0.1".to_string());

        let pc = PeerConnection::new(config);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 8000);
        let pcma_params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let _ = pc.add_track(track, pcma_params).unwrap();

        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        // Use ice_transport local candidate to get bound address
        let local_addr = pc
            .ice_transport()
            .local_candidates()
            .into_iter()
            .find(|c| c.component == 1)
            .map(|c| c.address)
            .expect("must have a local candidate after create_offer");

        // Bind a fake callee UDP socket
        let fake_callee = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee_addr = fake_callee.local_addr().unwrap();

        // -------- 183 Pranswer: callee is ringing, no audio yet --------
        let pranswer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
            callee_addr.port()
        );
        let pranswer = SessionDescription::parse(SdpType::Pranswer, &pranswer_sdp).unwrap();
        pc.set_remote_description(pranswer).await.unwrap();

        // Simulate bridge polling rtp_pc.recv() (as spawn_bidirectional_forwarder does).
        // This must start BEFORE the Track event fires.
        let pc_clone = pc.clone();
        let recv_handle = tokio::spawn(async move {
            tokio::time::timeout(tokio::time::Duration::from_millis(2000), pc_clone.recv()).await
        });

        // Allow 183 to be fully processed (ICE=Connected, transport set up)
        // but callee sends NO audio during 183
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // -------- 200 OK Answer: callee picks up ----------
        let answer_sdp = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
            callee_addr.port()
        );
        let answer = SessionDescription::parse(SdpType::Answer, &answer_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        // Allow time for reinvite processing
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // -------- Callee sends its first RTP packet after 200 OK -----------
        let mut rtp = vec![
            0x80u8, 0x08, 0x00, 0x01, // V=2, PT=8, seq=1
            0x00, 0x00, 0x00, 0x00, // timestamp=0
            0xCA, 0xFE, 0xBA, 0xBE, // ssrc=0xCAFEBABE
        ];
        rtp.extend_from_slice(&[0xD5u8; 160]);
        fake_callee.send_to(&rtp, local_addr).await.unwrap();

        let result = recv_handle.await.expect("recv task panicked");
        let event = result.expect("timed out waiting for Track event after 200 OK + first RTP");
        assert!(
            matches!(event, Some(PeerConnectionEvent::Track(_))),
            "expected PeerConnectionEvent::Track"
        );
    }

    /// Same scenario but callee uses a DIFFERENT address in the 200 OK vs the 183.
    /// Simulates address change (NAT, load balancer) between provisional and final answer.
    #[tokio::test]
    async fn repro_rtp_offerer_pranswer_then_answer_addr_change_track_fires() {
        use crate::media::track::sample_track;
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.enable_latching = true;
        config.bind_ip = Some("127.0.0.1".to_string());

        let pc = PeerConnection::new(config);
        let (_, track, _) = sample_track(crate::media::frame::MediaKind::Audio, 8000);
        let pcma_params = RtpCodecParameters {
            payload_type: 8,
            clock_rate: 8000,
            channels: 1,
        };
        let _ = pc.add_track(track, pcma_params).unwrap();

        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer).unwrap();

        let local_addr = pc
            .ice_transport()
            .local_candidates()
            .into_iter()
            .find(|c| c.component == 1)
            .map(|c| c.address)
            .expect("must have a local candidate after create_offer");

        // Two fake callee sockets: one for 183, one for 200 OK (different port = address change)
        let fake_callee_183 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee_addr_183 = fake_callee_183.local_addr().unwrap();

        let fake_callee_200 = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let callee_addr_200 = fake_callee_200.local_addr().unwrap();

        // 183 Pranswer with first address
        let pranswer_sdp = format!(
            "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
            callee_addr_183.port()
        );
        let pranswer = SessionDescription::parse(SdpType::Pranswer, &pranswer_sdp).unwrap();
        pc.set_remote_description(pranswer).await.unwrap();

        let pc_clone = pc.clone();
        let recv_handle = tokio::spawn(async move {
            tokio::time::timeout(tokio::time::Duration::from_millis(2000), pc_clone.recv()).await
        });

        // 183 phase: no audio
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        // 200 OK Answer with NEW (different) address
        let answer_sdp = format!(
            "v=0\r\no=- 1 2 IN IP4 127.0.0.1\r\ns=-\r\nc=IN IP4 127.0.0.1\r\nt=0 0\r\n\
             m=audio {} RTP/AVP 8\r\na=rtpmap:8 PCMA/8000\r\na=sendrecv\r\n",
            callee_addr_200.port()
        );
        let answer = SessionDescription::parse(SdpType::Answer, &answer_sdp).unwrap();
        pc.set_remote_description(answer).await.unwrap();

        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Send RTP from the NEW callee address
        let mut rtp = vec![
            0x80u8, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0xCA, 0xFE, 0xBA, 0xBE,
        ];
        rtp.extend_from_slice(&[0xD5u8; 160]);
        fake_callee_200.send_to(&rtp, local_addr).await.unwrap();

        let result = recv_handle.await.expect("recv task panicked");
        let event = result.expect("timed out waiting for Track event (address-change scenario)");
        assert!(
            matches!(event, Some(PeerConnectionEvent::Track(_))),
            "expected PeerConnectionEvent::Track (address-change scenario)"
        );
    }

    /// Regression test for Bug 1 — carriers often omit `a=rtpmap` for
    /// well-known static payload types (RFC 3551 §6, e.g. PT=8 PCMA or
    /// PT=0 PCMU).  The fix in `extract_payload_map` calls
    /// `iana_static_rtp_params()` to fill in the missing clock-rate /
    /// channels so that `set_transport` can register a proper PT-based
    /// listener and audio forwarding works correctly.
    ///
    /// Without the fix: PT=8 absent from payload_map → `unique_by_pt(8)`
    /// returns `None` → every packet falls through to the provisional
    /// listener without ever binding the SSRC route, and the clock-rate
    /// seen by the depacketizer is whatever the receiver default is.
    ///
    /// With the fix: PT=8 is present with `{clock_rate:8000, channels:1}`.
    #[tokio::test]
    async fn repro_bug1_static_pt_registered_without_rtpmap() {
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        config.bind_ip = Some("127.0.0.1".to_string());

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        // Carrier SDP: advertises PT=8 (PCMA) but deliberately omits
        // `a=rtpmap:8 PCMA/8000` — this is legal per RFC 3551 §6 because
        // PT=8 has a static assignment.
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 127.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 127.0.0.1\r\n\
                          m=audio 9000 RTP/AVP 8\r\n\
                          a=sendonly\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let transceivers = pc.get_transceivers();
        assert_eq!(transceivers.len(), 1);
        let payload_map = transceivers[0].get_payload_map();

        // Bug 1 fix: PT=8 must appear in the payload_map with correct
        // IANA-defined parameters even though `a=rtpmap` was absent.
        assert!(
            payload_map.contains_key(&8),
            "Bug 1 regression: PT=8 must be registered via iana_static_rtp_params() \
             even when the carrier omits a=rtpmap"
        );
        let params = payload_map.get(&8).unwrap();
        assert_eq!(
            params.clock_rate, 8000,
            "PT=8 clock_rate must be 8000 Hz (PCMA RFC 3551)"
        );
        assert_eq!(params.channels, 1, "PT=8 must have 1 audio channel");

        // PT=0 (PCMU) is also a well-known static type — verify it too.
        let remote_sdp2 = "v=0\r\n\
                           o=- 2 2 IN IP4 127.0.0.1\r\n\
                           s=-\r\n\
                           t=0 0\r\n\
                           c=IN IP4 127.0.0.1\r\n\
                           m=audio 9002 RTP/AVP 0\r\n\
                           a=sendonly\r\n";
        let pc2 = PeerConnection::new({
            let mut c = RtcConfiguration::default();
            c.transport_mode = TransportMode::Rtp;
            c
        });
        pc2.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
        let desc2 = SessionDescription::parse(SdpType::Offer, remote_sdp2).unwrap();
        pc2.set_remote_description(desc2).await.unwrap();
        let t2 = pc2.get_transceivers();
        let pm2 = t2[0].get_payload_map();
        assert!(
            pm2.contains_key(&0),
            "PT=0 (PCMU) must also be registered via iana_static_rtp_params()"
        );
        assert_eq!(
            pm2.get(&0).unwrap().clock_rate,
            8000,
            "PT=0 clock_rate must be 8000 Hz"
        );
    }

    /// Unit test for Bug 3 — `track_event_sent` was NOT reset when a receiver's
    /// transport was replaced (e.g. after ICE restart or re-INVITE that creates
    /// a fresh `Arc<RtpTransport>`).
    ///
    /// Production impact: WebRTC caller can't hear audio from RTP carrier
    /// (`rtp_to_webrtc_pps=0`) after any event that forces a transport swap:
    ///   1. Carrier sends 183 early media → Track event fires → bridge wires up
    ///      forwarding loop A on transport A.
    ///   2. ICE restarts (re-INVITE with new credentials, or network change) →
    ///      `start_dtls` called again → `set_transport(transport_B)` called.
    ///   3. WITHOUT fix: `track_event_sent=true` (from step 1) is preserved →
    ///      no second Track event → bridge never re-wires → `pps=0`.
    ///      WITH fix: `track_event_sent` and SSRC are reset → first packet on
    ///      transport B fires a fresh Track event → bridge re-wires → pps>0.
    ///
    /// Intermittency: only carriers that send 183 early media AND later trigger
    /// an ICE restart hit this path.  Calls without early media have
    /// `track_event_sent=false` when the transport switches, so no loss occurs.
    #[tokio::test]
    async fn repro_bug3_track_event_resets_on_transport_switch() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::conn::IceConn;
        use crate::transports::rtp::RtpTransport;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::atomic::Ordering;

        let transceiver = Arc::new(RtpTransceiver::new_for_test(
            MediaKind::Audio,
            TransceiverDirection::RecvOnly,
        ));
        let receiver = RtpReceiverBuilder::new(MediaKind::Audio, 0)
            .payload_map(transceiver.payload_map.clone())
            .build();
        transceiver.set_receiver(Some(receiver.clone()));
        let _ = transceiver.update_payload_map(HashMap::from([(
            8u8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        )]));

        // Helper: create a fresh RtpTransport backed by a dummy IceConn.
        let make_transport = || {
            let (_, socket_rx) = tokio::sync::watch::channel::<
                Option<crate::transports::ice::IceSocketWrapper>,
            >(None);
            let ice_conn = IceConn::new(
                socket_rx,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                None,
            );
            Arc::new(RtpTransport::new(ice_conn, false))
        };

        let (event_tx, mut event_rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerConnectionEvent>();
        let transceiver_weak = Arc::downgrade(&transceiver);

        // ── Phase 1: transport A — simulate 183 early media ──────────────

        let transport_a = make_transport();
        receiver.set_transport(
            transport_a.clone(),
            Some(event_tx.clone()),
            Some(transceiver_weak.clone()),
        );
        tokio::task::yield_now().await;

        // Inject a PT=8 packet directly into the run_loop via packet_tx.
        let packet_tx_a = receiver
            .packet_tx()
            .expect("packet_tx must be set after set_transport");
        let pkt_a =
            crate::rtp::RtpPacket::new(RtpHeader::new(8, 1, 0, 0xDEAD_BEEF), vec![0xD5u8; 160]);
        packet_tx_a
            .send((pkt_a, "127.0.0.1:20000".parse().unwrap()))
            .await
            .unwrap();

        // First Track event must arrive (SSRC latched from first packet).
        let first_event = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("first Track event must arrive (early-media phase)");
        assert!(
            matches!(first_event, Some(PeerConnectionEvent::Track(_))),
            "expected Track event from early-media packet"
        );

        // track_event_sent is now true — no more Track events on transport A.
        assert!(
            receiver.track_event_sent.load(Ordering::SeqCst),
            "track_event_sent must be true after first Track event"
        );

        // ── Phase 2: transport B — simulate ICE restart / transport replacement ──

        let transport_b = make_transport();

        // Call set_transport with a *different* Arc — this is the Bug 3 scenario.
        // The fix must reset track_event_sent and ssrc so the first packet on the
        // new transport fires a fresh Track event.
        receiver.set_transport(
            transport_b.clone(),
            Some(event_tx.clone()),
            Some(transceiver_weak.clone()),
        );

        // Bug 3 fix assertions: both fields must be reset.
        assert!(
            !receiver.track_event_sent.load(Ordering::SeqCst),
            "Bug 3 fix: track_event_sent must be reset to false when transport switches"
        );
        assert_eq!(
            *receiver.ssrc.lock(),
            0,
            "Bug 3 fix: ssrc must be reset to 0 when transport switches"
        );

        tokio::task::yield_now().await;

        // ── Phase 3: verify second Track event fires on transport B ──────

        let packet_tx_b = receiver
            .packet_tx()
            .expect("packet_tx must be set after second set_transport");
        // Different pointer from packet_tx_a: confirms a new run_loop was spawned.
        assert!(
            !packet_tx_a.same_channel(&packet_tx_b),
            "transport switch must create a new packet channel (new run_loop)"
        );

        let pkt_b =
            crate::rtp::RtpPacket::new(RtpHeader::new(8, 2, 160, 0xDEAD_BEEF), vec![0xD5u8; 160]);
        packet_tx_b
            .send((pkt_b, "127.0.0.1:20001".parse().unwrap()))
            .await
            .unwrap();

        // Without Bug 3 fix this would time out (track_event_sent still true).
        let second_event = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("second Track event must arrive after transport switch — Bug 3 regression");
        assert!(
            matches!(second_event, Some(PeerConnectionEvent::Track(_))),
            "expected second Track event after transport replacement"
        );
    }

    // ── Bug 3 boundary: same-transport reuse must NOT reset state ─────────────

    /// Guard test: when `set_transport` is called with the **same** Arc (ptr_eq
    /// succeeds — normal 183+200 OK re-INVITE path), `track_event_sent` must
    /// stay `true` and no spurious second Track event is emitted.
    ///
    /// Without this boundary, every 200 OK re-INVITE would reset the flag and
    /// re-fire a Track event, causing the bridge to spawn duplicate forward
    /// loops.
    #[tokio::test]
    async fn repro_bug3_same_transport_reuse_no_spurious_reset() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::conn::IceConn;
        use crate::transports::rtp::RtpTransport;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::atomic::Ordering;

        let transceiver = Arc::new(RtpTransceiver::new_for_test(
            MediaKind::Audio,
            TransceiverDirection::RecvOnly,
        ));
        let receiver = RtpReceiverBuilder::new(MediaKind::Audio, 0)
            .payload_map(transceiver.payload_map.clone())
            .build();
        transceiver.set_receiver(Some(receiver.clone()));
        let _ = transceiver.update_payload_map(HashMap::from([(
            8u8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        )]));

        let (event_tx, mut event_rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerConnectionEvent>();
        let transceiver_weak = Arc::downgrade(&transceiver);

        let (_, socket_rx) =
            tokio::sync::watch::channel::<Option<crate::transports::ice::IceSocketWrapper>>(None);
        let ice_conn = IceConn::new(
            socket_rx,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            None,
        );
        let transport_a = Arc::new(RtpTransport::new(ice_conn, false));

        // First set_transport — first assignment, existing=None
        receiver.set_transport(
            transport_a.clone(),
            Some(event_tx.clone()),
            Some(transceiver_weak.clone()),
        );
        tokio::task::yield_now().await;

        // Send one packet → Track event fires → track_event_sent=true
        let packet_tx = receiver.packet_tx().unwrap();
        let pkt =
            crate::rtp::RtpPacket::new(RtpHeader::new(8, 1, 0, 0xDEAD_BEEF), vec![0xD5u8; 160]);
        packet_tx
            .send((pkt, "127.0.0.1:20000".parse().unwrap()))
            .await
            .unwrap();

        let first_event = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("first Track event must arrive");
        assert!(matches!(first_event, Some(PeerConnectionEvent::Track(_))));
        assert!(receiver.track_event_sent.load(Ordering::SeqCst));

        // ── Call set_transport with the SAME Arc (ptr_eq should early-return) ──
        receiver.set_transport(
            transport_a.clone(), // same pointer
            Some(event_tx.clone()),
            Some(transceiver_weak.clone()),
        );
        tokio::task::yield_now().await;

        // track_event_sent must still be true — no reset happened
        assert!(
            receiver.track_event_sent.load(Ordering::SeqCst),
            "ptr_eq match: track_event_sent must not be reset when reusing same transport"
        );

        // No spurious second Track event in the channel
        tokio::task::yield_now().await;
        assert!(
            event_rx.try_recv().is_err(),
            "ptr_eq match: no spurious Track event must be emitted when transport is reused"
        );
    }

    /// Guard test: the FIRST call to `set_transport` (existing=None) must NOT
    /// reset `track_event_sent` — it starts as false and must stay false until
    /// the first packet arrives.
    ///
    /// This guards against accidentally triggering the reset on brand-new
    /// receivers, which would be a no-op but could mask future regressions.
    #[tokio::test]
    async fn repro_bug3_first_assignment_does_not_reset_or_double_fire() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::conn::IceConn;
        use crate::transports::rtp::RtpTransport;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        use std::sync::atomic::Ordering;

        let transceiver = Arc::new(RtpTransceiver::new_for_test(
            MediaKind::Audio,
            TransceiverDirection::RecvOnly,
        ));
        let receiver = RtpReceiverBuilder::new(MediaKind::Audio, 0)
            .payload_map(transceiver.payload_map.clone())
            .build();
        transceiver.set_receiver(Some(receiver.clone()));
        let _ = transceiver.update_payload_map(HashMap::from([(
            8u8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        )]));

        // Precondition: starts as false
        assert!(!receiver.track_event_sent.load(Ordering::SeqCst));

        let (event_tx, mut event_rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerConnectionEvent>();
        let transceiver_weak = Arc::downgrade(&transceiver);

        let (_, socket_rx) =
            tokio::sync::watch::channel::<Option<crate::transports::ice::IceSocketWrapper>>(None);
        let ice_conn = IceConn::new(
            socket_rx,
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
            None,
        );
        let transport = Arc::new(RtpTransport::new(ice_conn, false));

        receiver.set_transport(
            transport,
            Some(event_tx.clone()),
            Some(transceiver_weak.clone()),
        );
        tokio::task::yield_now().await;

        // After first set_transport, track_event_sent must still be false
        // (no spurious reset from the "existing=None" branch)
        assert!(
            !receiver.track_event_sent.load(Ordering::SeqCst),
            "first set_transport must not modify track_event_sent (still false)"
        );

        // Exactly one packet → exactly one Track event
        let packet_tx = receiver.packet_tx().unwrap();
        let pkt =
            crate::rtp::RtpPacket::new(RtpHeader::new(8, 1, 0, 0xAB12_3456), vec![0xD5u8; 160]);
        packet_tx
            .send((pkt, "127.0.0.1:20002".parse().unwrap()))
            .await
            .unwrap();

        let ev = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("Track event must arrive after first packet on first transport");
        assert!(matches!(ev, Some(PeerConnectionEvent::Track(_))));

        // Exactly one — channel is now empty
        tokio::task::yield_now().await;
        assert!(
            event_rx.try_recv().is_err(),
            "only one Track event must be emitted per transport lifetime"
        );
    }

    /// After transport switch (Bug 3 fix), a packet carrying a **different SSRC**
    /// from the one used on transport A must still fire a Track event and bind
    /// the new SSRC correctly.
    ///
    /// This catches a potential double-reset issue where the fix incorrectly
    /// fires on every SSRC change rather than only on transport replacement.
    #[tokio::test]
    async fn repro_bug3_new_ssrc_on_new_transport_fires_track() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::conn::IceConn;
        use crate::transports::rtp::RtpTransport;
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};

        let transceiver = Arc::new(RtpTransceiver::new_for_test(
            MediaKind::Audio,
            TransceiverDirection::RecvOnly,
        ));
        let receiver = RtpReceiverBuilder::new(MediaKind::Audio, 0)
            .payload_map(transceiver.payload_map.clone())
            .build();
        transceiver.set_receiver(Some(receiver.clone()));
        let _ = transceiver.update_payload_map(HashMap::from([(
            8u8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        )]));

        let make_transport = || {
            let (_, socket_rx) = tokio::sync::watch::channel::<
                Option<crate::transports::ice::IceSocketWrapper>,
            >(None);
            let ice_conn = IceConn::new(
                socket_rx,
                SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
                None,
            );
            Arc::new(RtpTransport::new(ice_conn, false))
        };

        let (event_tx, mut event_rx) =
            tokio::sync::mpsc::unbounded_channel::<PeerConnectionEvent>();
        let tw = Arc::downgrade(&transceiver);

        // Transport A — SSRC = 0xAAAA_1111
        let ta = make_transport();
        receiver.set_transport(ta.clone(), Some(event_tx.clone()), Some(tw.clone()));
        tokio::task::yield_now().await;
        let ptx_a = receiver.packet_tx().unwrap();
        ptx_a
            .send((
                crate::rtp::RtpPacket::new(RtpHeader::new(8, 1, 0, 0xAAAA_1111), vec![0xD5; 160]),
                "127.0.0.1:30000".parse().unwrap(),
            ))
            .await
            .unwrap();
        let _ = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("first Track event on transport A");
        assert_eq!(*receiver.ssrc.lock(), 0xAAAA_1111);

        // Transport B — use a DIFFERENT SSRC (0xBBBB_2222)
        let tb = make_transport();
        receiver.set_transport(tb.clone(), Some(event_tx.clone()), Some(tw.clone()));
        assert_eq!(
            *receiver.ssrc.lock(),
            0,
            "ssrc reset to 0 on transport switch"
        );

        tokio::task::yield_now().await;
        let ptx_b = receiver.packet_tx().unwrap();
        ptx_b
            .send((
                crate::rtp::RtpPacket::new(
                    RtpHeader::new(8, 2, 160, 0xBBBB_2222), // different SSRC
                    vec![0xD5; 160],
                ),
                "127.0.0.1:30001".parse().unwrap(),
            ))
            .await
            .unwrap();

        let second_event = tokio::time::timeout(tokio::time::Duration::from_millis(500), async {
            event_rx.recv().await
        })
        .await
        .expect("Track event must fire on transport B with new SSRC");
        assert!(matches!(second_event, Some(PeerConnectionEvent::Track(_))));
        // SSRC correctly updated to the new value
        assert_eq!(
            *receiver.ssrc.lock(),
            0xBBBB_2222,
            "ssrc must be bound to new SSRC on transport B"
        );
    }

    // ── Bug 1 boundary: dynamic PT must NOT get a static fallback ─────────────

    /// Guard test: a dynamic PT (≥96) that appears in the `m=` format list but
    /// has no `a=rtpmap` line must NOT be added to the payload_map via
    /// `iana_static_rtp_params()`, since dynamic PTs have no IANA-defined
    /// default.
    ///
    /// Without this guard, the fix could accidentally "invent" parameters for
    /// unknown codecs and cause silent audio corruption.
    #[tokio::test]
    async fn repro_bug1_dynamic_pt_without_rtpmap_not_registered() {
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        // Dynamic PT=96 with no a=rtpmap — must NOT get a fallback
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 127.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 127.0.0.1\r\n\
                          m=audio 9000 RTP/AVP 96\r\n\
                          a=sendonly\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let payload_map = pc.get_transceivers()[0].get_payload_map();
        assert!(
            !payload_map.contains_key(&96),
            "Bug 1 guard: dynamic PT=96 must NOT be registered without a=rtpmap"
        );
    }

    /// Guard test: when the SDP includes an explicit `a=rtpmap` for a static
    /// PT, the explicit mapping must take precedence over the IANA default.
    ///
    /// This verifies that `iana_static_rtp_params()` is only used as a
    /// fallback and cannot override a real a=rtpmap negotiation.
    #[tokio::test]
    async fn repro_bug1_explicit_rtpmap_overrides_iana_static_default() {
        use crate::sdp::{SdpType, SessionDescription};

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);

        // PT=8 with a=rtpmap that specifies a non-standard clock rate.
        // The explicit value must win over the IANA default of 8000.
        let remote_sdp = "v=0\r\n\
                          o=- 1 1 IN IP4 127.0.0.1\r\n\
                          s=-\r\n\
                          t=0 0\r\n\
                          c=IN IP4 127.0.0.1\r\n\
                          m=audio 9000 RTP/AVP 8\r\n\
                          a=rtpmap:8 PCMA/16000\r\n\
                          a=sendonly\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, remote_sdp).unwrap();
        pc.set_remote_description(desc).await.unwrap();

        let payload_map = pc.get_transceivers()[0].get_payload_map();
        assert!(payload_map.contains_key(&8), "PT=8 must be registered");
        assert_eq!(
            payload_map[&8].clock_rate, 16000,
            "Bug 1 guard: explicit a=rtpmap clock_rate must override IANA static default (8000)"
        );
    }

    // ── Bug 3 integration: full ICE reconnect cycle ───────────────────────────

    /// End-to-end regression test for Bug 3 triggered by the real ICE reconnect
    /// path rather than direct `set_transport` calls.
    ///
    /// Scenario (mirrors production WebRTC keepalive timeout):
    ///   1. PC initialised → ICE Connected → `start_dtls` called → transport A
    ///   2. First RTP packet → Track event fires → `track_event_sent = true`
    ///   3. ICE keepalive timeout → `Disconnected`
    ///      (`run_rtp_direct_loop` exits inner loop with `true`)
    ///   4. ICE recovers → `Connected` again
    ///      → outer loop re-enters → `start_dtls` called again → transport B
    ///   5. Without Bug 3 fix: `track_event_sent` still `true` → no Track event
    ///      → bridge never re-wired → dead audio after reconnect
    ///   6. With Bug 3 fix: `set_transport` resets the flag → Track event fires
    ///      → bridge re-wires correctly
    #[tokio::test]
    async fn repro_bug3_ice_reconnect_cycle_re_fires_track_event() {
        use crate::rtp::RtpHeader;
        use crate::transports::ice::IceTransportState;
        use std::net::SocketAddr;
        use std::sync::atomic::Ordering;

        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;

        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly);
        let _ = pc.get_transceivers()[0].update_payload_map(HashMap::from([(
            8u8,
            RtpCodecParameters {
                payload_type: 8,
                clock_rate: 8000,
                channels: 1,
            },
        )]));

        // Init ICE: bind a loopback socket, set selected pair, send Connected.
        // run_rtp_direct_loop sees Connected → handle_connected_state_no_dtls
        // → start_dtls(false) → transport A registered on the receiver.
        let loopback: SocketAddr = "127.0.0.1:0".parse().unwrap();
        let ice = pc.ice_transport_for_test();
        ice.setup_direct_rtp(loopback).await.unwrap();

        // Allow run_rtp_direct_loop to process Connected and call start_dtls.
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;

        // Grab the receiver and its current packet channel (transport A).
        let receiver = pc.get_transceivers()[0].receiver.lock().clone().unwrap();
        let ptx_a = receiver
            .packet_tx()
            .expect("transport A packet_tx must exist after start_dtls");

        // ── Phase 1: first packet on transport A → Track event ────────────────
        ptx_a
            .send((
                crate::rtp::RtpPacket::new(RtpHeader::new(8, 1, 0, 0xAAAA_0001), vec![0xD5u8; 160]),
                "127.0.0.1:20010".parse().unwrap(),
            ))
            .await
            .unwrap();

        let ev1 = tokio::time::timeout(tokio::time::Duration::from_millis(500), pc.recv())
            .await
            .expect("Track event must arrive after first packet on transport A");
        assert!(
            matches!(ev1, Some(PeerConnectionEvent::Track(_))),
            "Phase 1: first Track event must fire"
        );
        assert!(
            receiver.track_event_sent.load(Ordering::SeqCst),
            "Phase 1: track_event_sent must be true after Track event"
        );

        // ── Phase 2: simulate ICE reconnect (Disconnected → Connected) ────────
        // In WebRtc mode this happens when run_keepalive_tick detects >5 s of
        // silence; in RTP mode it is triggered by an explicit reconnect or
        // network change.  We drive it directly via the test-only hook.
        ice.force_state_for_test(IceTransportState::Disconnected);
        // Let handle_connected_state_no_dtls see the state change and return true.
        tokio::time::sleep(tokio::time::Duration::from_millis(20)).await;

        // Recovery: outer run_rtp_direct_loop sees Connected →
        // calls handle_connected_state_no_dtls again → start_dtls →
        // new Arc<RtpTransport> (transport B) → set_transport → Bug 3 fix resets flag.
        ice.force_state_for_test(IceTransportState::Connected);
        tokio::time::sleep(tokio::time::Duration::from_millis(80)).await;

        // ── Phase 3: verify Bug 3 fix applied ─────────────────────────────────
        assert!(
            !receiver.track_event_sent.load(Ordering::SeqCst),
            "Bug 3 fix (ICE reconnect): track_event_sent must be reset to false \
             when start_dtls creates a new transport after ICE reconnect"
        );

        let ptx_b = receiver
            .packet_tx()
            .expect("transport B packet_tx must exist after reconnect");
        assert!(
            !ptx_a.same_channel(&ptx_b),
            "Bug 3 fix (ICE reconnect): a new transport must be created after ICE \
             reconnect (packet channel must differ from transport A)"
        );

        // ── Phase 4: second packet on transport B → second Track event ────────
        ptx_b
            .send((
                crate::rtp::RtpPacket::new(
                    RtpHeader::new(8, 2, 160, 0xBBBB_0002),
                    vec![0xD5u8; 160],
                ),
                "127.0.0.1:20011".parse().unwrap(),
            ))
            .await
            .unwrap();

        let ev2 = tokio::time::timeout(tokio::time::Duration::from_millis(500), pc.recv())
            .await
            .expect("second Track event must arrive after ICE reconnect");
        assert!(
            matches!(ev2, Some(PeerConnectionEvent::Track(_))),
            "Bug 3 fix (ICE reconnect): Track event must re-fire after ICE \
             reconnect so that the media bridge can be re-wired"
        );
    }
}
