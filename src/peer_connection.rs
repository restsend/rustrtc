use crate::media::track::{MediaStreamTrack, SampleStreamSource, SampleStreamTrack, sample_track};
use crate::rtp::{FirRequest, FullIntraRequest, PictureLossIndication, RtcpPacket};
use crate::stats::{StatsReport, gather_once};
use crate::stats_collector::StatsCollector;
use crate::transports::dtls::{self, DtlsTransport};
use crate::transports::ice::{IceCandidate, IceGathererState, IceTransport, conn::IceConn};
use crate::transports::rtp::RtpTransport;
use crate::transports::sctp::SctpTransport;
use crate::{
    Attribute, Direction, MediaKind, MediaSection, Origin, RtcConfiguration, RtcError, RtcResult,
    SdpType, SessionDescription, TransportMode,
};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{broadcast, mpsc, watch};
use tracing::{debug, trace, warn};

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
    dtls_role: watch::Sender<Option<bool>>,
    _dtls_role_rx: watch::Receiver<Option<bool>>,
    stats_collector: Arc<StatsCollector>,
}

impl PeerConnection {
    pub fn new(config: RtcConfiguration) -> Self {
        let ice_transport = IceTransport::new(config.clone());
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
            dtls_role: dtls_role_tx,
            _dtls_role_rx: dtls_role_rx.clone(),
            stats_collector: Arc::new(StatsCollector::new()),
        };
        let pc = Self {
            inner: Arc::new(inner),
        };

        let inner_weak = Arc::downgrade(&pc.inner);
        let ice_transport = pc.inner.ice_transport.clone();
        let dtls_role_rx = dtls_role_rx;
        let ice_connection_state_tx = pc.inner.ice_connection_state.clone();

        tokio::spawn(async move {
            run_ice_dtls_loop(
                ice_transport,
                ice_connection_state_tx,
                dtls_role_rx,
                inner_weak,
            )
            .await;
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
        let transceiver = Arc::new(RtpTransceiver::new(kind, direction));

        let receiver = Arc::new(RtpReceiver::new(kind, 67890)); // Random SSRC
        *transceiver.receiver.lock().unwrap() = Some(receiver);

        let mut list = self.inner.transceivers.lock().unwrap();
        list.push(transceiver.clone());
        transceiver
    }

    pub fn add_track(&self, track: Arc<dyn MediaStreamTrack>) -> RtcResult<Arc<RtpSender>> {
        let kind = match track.kind() {
            crate::media::frame::MediaKind::Audio => MediaKind::Audio,
            crate::media::frame::MediaKind::Video => MediaKind::Video,
        };
        let transceiver = self.add_transceiver(kind, TransceiverDirection::SendRecv);
        let ssrc = SSRC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let sender = Arc::new(RtpSender::new(track, ssrc));
        *transceiver.sender.lock().unwrap() = Some(sender.clone());
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
        self.inner
            .ice_transport
            .set_role(crate::transports::ice::IceRole::Controlling)
            .await;
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
            .set_role(crate::transports::ice::IceRole::Controlled)
            .await;
        self.inner
            .build_description(SdpType::Answer, |dir| dir.answer_direction())
            .await
    }

    pub fn set_local_description(&self, desc: SessionDescription) -> RtcResult<()> {
        self.inner.validate_sdp_type(&desc.sdp_type)?;
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
                if self.config().transport_mode == TransportMode::Rtp {
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
                                debug!(
                                    "DTLS Role determination: remote setup={}, is_client={}",
                                    val, is_client
                                );
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
                    .await
                    .map_err(|e| crate::RtcError::Internal(format!("ICE error: {}", e)))?;

                for candidate in candidates {
                    self.inner
                        .ice_transport
                        .add_remote_candidate(candidate)
                        .await;
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
                let mut found = false;
                for t in transceivers.iter() {
                    if let Some(t_mid) = t.mid()
                        && t_mid == *mid
                    {
                        found = true;
                        break;
                    }
                }

                if !found {
                    // Try to find a transceiver with no MID and same kind
                    for t in transceivers.iter() {
                        if t.mid().is_none() && t.kind() == section.kind {
                            t.set_mid(mid.clone());
                            found = true;
                            break;
                        }
                    }
                }

                let mut ssrc = None;
                for attr in &section.attributes {
                    if attr.key == "ssrc"
                        && let Some(val) = &attr.value
                        && let Some(ssrc_str) = val.split_whitespace().next()
                        && let Ok(parsed) = ssrc_str.parse::<u32>()
                    {
                        ssrc = Some(parsed);
                        break;
                    }
                }

                if found {
                    if let Some(ssrc_val) = ssrc {
                        // Find the transceiver again to update SSRC
                        for t in transceivers.iter() {
                            if let Some(t_mid) = t.mid()
                                && t_mid == *mid
                            {
                                if let Some(rx) = t.receiver.lock().unwrap().as_ref() {
                                    rx.set_ssrc(ssrc_val);
                                }
                                break;
                            }
                        }
                    }
                } else {
                    let kind = section.kind;
                    let t = Arc::new(RtpTransceiver::new(kind, TransceiverDirection::RecvOnly));
                    t.set_mid(mid.clone());

                    let receiver_ssrc = ssrc.unwrap_or_else(|| 2000 + transceivers.len() as u32);
                    let receiver = Arc::new(RtpReceiver::new(kind, receiver_ssrc));
                    *t.receiver.lock().unwrap() = Some(receiver);

                    transceivers.push(t);
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
                    let mut ssrc = None;
                    for attr in &section.attributes {
                        if attr.key == "ssrc"
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

    pub async fn start_dtls(
        &self,
        is_client: bool,
    ) -> RtcResult<std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>> {
        let pair = self
            .inner
            .ice_transport
            .get_selected_pair()
            .await
            .ok_or(RtcError::Internal("No selected pair".into()))?;

        let socket_rx = self.inner.ice_transport.subscribe_selected_socket();

        // Create IceConn and register it immediately to avoid dropping packets
        let ice_conn = IceConn::new(socket_rx.clone(), pair.remote.address);

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
                ice_conn.set_remote_rtcp_addr(Some(addr)).await;
                debug!("RTCP-MUX not detected, setting RTCP address to {}", addr);
            }
        }

        self.inner
            .ice_transport
            .set_data_receiver(ice_conn.clone())
            .await;

        let rtp_transport = Arc::new(RtpTransport::new(ice_conn.clone()));
        {
            let mut rx = ice_conn.rtp_receiver.write().await;
            *rx = Some(Arc::downgrade(&rtp_transport)
                as std::sync::Weak<dyn crate::transports::PacketReceiver>);
        }
        *self.inner.rtp_transport.lock().unwrap() = Some(rtp_transport.clone());

        if self.config().transport_mode == TransportMode::Rtp {
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
            return Ok(Box::pin(async {}));
        }

        let dtls = DtlsTransport::new(ice_conn, self.inner.certificate.as_ref().clone(), is_client)
            .await
            .map_err(|e| RtcError::Internal(format!("DTLS failed: {}", e)))?;

        let sctp = SctpTransport::new(dtls.clone(), self.inner.data_channels.clone());
        *self.inner.sctp_transport.lock().unwrap() = Some(sctp);

        *self.inner.dtls_transport.lock().unwrap() = Some(dtls.clone());

        let dtls_clone = dtls.clone();
        let rtp_transport_clone = rtp_transport.clone();
        let inner_weak = Arc::downgrade(&self.inner);

        let mut state_rx = dtls_clone.subscribe_state();
        loop {
            let state = state_rx.borrow_and_update().clone();
            match state {
                crate::transports::dtls::DtlsState::Connected(_, profile_opt) => {
                    // Setup SRTP
                    // RFC 5764:
                    // label = "EXTRACTOR-dtls_srtp"
                    // len = 2 * (key_len + salt_len)

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

                    if let Ok(mat) = dtls_clone
                        .export_keying_material("EXTRACTOR-dtls_srtp", total_len)
                        .await
                    {
                        let client_key = &mat[0..key_len];
                        let server_key = &mat[key_len..2 * key_len];
                        let client_salt = &mat[2 * key_len..2 * key_len + salt_len];
                        let server_salt = &mat[2 * key_len + salt_len..];

                        let (tx_key, tx_salt, rx_key, rx_salt) = if is_client {
                            (client_key, client_salt, server_key, server_salt)
                        } else {
                            (server_key, server_salt, client_key, client_salt)
                        };

                        let tx_keying =
                            crate::srtp::SrtpKeyingMaterial::new(tx_key.to_vec(), tx_salt.to_vec());
                        let rx_keying =
                            crate::srtp::SrtpKeyingMaterial::new(rx_key.to_vec(), rx_salt.to_vec());

                        match crate::srtp::SrtpSession::new(profile, tx_keying, rx_keying) {
                            Ok(session) => {
                                rtp_transport_clone.start_srtp(session);

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
                                        sender.set_transport(rtp_transport_clone.clone());
                                    }

                                    if let Some(receiver) = &receiver_arc {
                                        receiver.set_transport(rtp_transport_clone.clone());
                                        if let Some(sender) = &sender_arc {
                                            receiver.set_feedback_ssrc(sender.ssrc());
                                        }
                                    }
                                }
                            }
                            Err(e) => {
                                warn!("Failed to create SRTP session: {}", e);
                            }
                        }
                    } else {
                        warn!("Failed to export keying material");
                    }

                    let (rtcp_tx, mut rtcp_rx) = mpsc::channel(100);
                    rtp_transport_clone.register_rtcp_listener(rtcp_tx);
                    let inner_weak_rtcp = inner_weak.clone();
                    let stats_collector = self.inner.stats_collector.clone();

                    let rtcp_loop = Box::pin(async move {
                        while let Some(packets) = rtcp_rx.recv().await {
                            for packet in packets {
                                stats_collector.process_rtcp(&packet);
                                let Some(inner) = inner_weak_rtcp.upgrade() else {
                                    return;
                                };
                                let mut target_receiver_for_pli = None;
                                {
                                    let transceivers = inner.transceivers.lock().unwrap();

                                    // 1. Handle PLI for Receiver (Forward to upstream)
                                    if let RtcpPacket::PictureLossIndication(pli) = &packet {
                                        for t in transceivers.iter() {
                                            let sender_guard = t.sender.lock().unwrap();
                                            if let Some(sender) = &*sender_guard
                                                && sender.ssrc() == pli.media_ssrc
                                            {
                                                let receiver_guard = t.receiver.lock().unwrap();
                                                if let Some(receiver) = &*receiver_guard {
                                                    target_receiver_for_pli =
                                                        Some(receiver.clone());
                                                }
                                                break;
                                            }
                                        }
                                    }

                                    // 2. Forward RTCP to Sender (Application Feedback)
                                    for t in transceivers.iter() {
                                        if let Some(sender) = &*t.sender.lock().unwrap() {
                                            let is_for_sender = match &packet {
                                                RtcpPacket::PictureLossIndication(p) => {
                                                    p.media_ssrc == sender.ssrc()
                                                }
                                                RtcpPacket::GenericNack(n) => {
                                                    n.media_ssrc == sender.ssrc()
                                                }
                                                _ => false,
                                            };

                                            if is_for_sender {
                                                sender.deliver_rtcp(packet.clone());
                                            }
                                        }
                                    }
                                }

                                if let Some(receiver) = target_receiver_for_pli
                                    && let Err(err) = receiver.request_key_frame().await
                                {
                                    warn!("Failed to forward remote PLI: {}", err);
                                }
                            }
                        }
                    });
                    return Ok(rtcp_loop);
                }
                crate::transports::dtls::DtlsState::Failed => {
                    return Err(RtcError::Internal("DTLS handshake failed".into()));
                }
                _ => {}
            }

            if state_rx.changed().await.is_err() {
                break;
            }
        }

        Ok(Box::pin(async {}))
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

    pub async fn wait_for_connection(&self) -> RtcResult<()> {
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
        let _ = self.inner.signaling_state.send(SignalingState::Closed);
        let _ = self.inner.peer_state.send(PeerConnectionState::Closed);
        let _ = self
            .inner
            .ice_connection_state
            .send(IceConnectionState::Closed);
        let _ = self
            .inner
            .ice_gathering_state
            .send(IceGatheringState::Complete);
        self.inner.ice_transport.stop();
    }

    pub fn create_data_channel(
        &self,
        label: &str,
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

        let id = {
            let channels = self.inner.data_channels.lock().unwrap();
            channels.len() as u16
        };

        let dc = Arc::new(crate::transports::sctp::DataChannel::new(
            id,
            label.to_string(),
        ));

        self.inner
            .data_channels
            .lock()
            .unwrap()
            .push(Arc::downgrade(&dc));

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

    pub async fn get_stats(&self) -> RtcResult<StatsReport> {
        gather_once(&[self.inner.stats_collector.clone()]).await
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
            crate::transports::ice::IceTransportState::Connected => loop {
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
                            }
                            Ok(rtcp_loop) => {
                                let _ = inner.peer_state.send(PeerConnectionState::Connected);
                                rtcp_loop.await;
                            }
                        }
                    }
                    return;
                }

                tokio::select! {
                    res = dtls_role_rx.changed() => {
                        if res.is_err() { return; }
                    }
                    res = ice_state_rx.changed() => {
                        if res.is_err() { return; }
                        let new_state = *ice_state_rx.borrow();
                        if new_state != crate::transports::ice::IceTransportState::Connected {
                            break; // Go back to outer loop
                        }
                    }
                }
            },
            crate::transports::ice::IceTransportState::Failed
            | crate::transports::ice::IceTransportState::Closed => {
                return;
            }
            _ => {}
        }

        if ice_state_rx.changed().await.is_err() {
            return;
        }
    }
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
            transceivers
        };

        self.ice_transport
            .start_gathering()
            .await
            .map_err(|err| RtcError::InvalidState(format!("ICE gathering failed: {err}")))?;
        let ice_params = self.ice_transport.local_parameters().await;
        let ice_username = ice_params.username_fragment.clone();
        let ice_password = ice_params.password.clone();
        let candidate_lines: Vec<String> = self
            .ice_transport
            .local_candidates()
            .await
            .iter()
            .map(IceCandidate::to_sdp)
            .collect();
        let gather_complete = matches!(
            self.ice_transport.gather_state().await,
            IceGathererState::Complete
        );
        let mut desc = SessionDescription::new(sdp_type);
        desc.session.origin = default_origin();
        desc.session.origin.session_version += 1;
        if !desc
            .session
            .attributes
            .iter()
            .any(|attr| attr.key == "msid-semantic")
        {
            desc.session
                .attributes
                .push(Attribute::new("msid-semantic", Some("WMS *".into())));
        }

        let mode = self.config.transport_mode.clone();
        for transceiver in ordered_transceivers.into_iter() {
            let mid = self.ensure_mid(&transceiver);
            let direction = map_direction(transceiver.direction());
            let sender_info = if direction.sends() {
                transceiver.sender.lock().unwrap().clone()
            } else {
                None
            };
            let mut section = MediaSection::new(transceiver.kind(), mid);
            section.direction = direction.into();

            if mode == TransportMode::Rtp {
                section.protocol = "RTP/AVPF".to_string();
            }

            if mode == TransportMode::WebRtc {
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
                if let Some(first_cand) = self.ice_transport.local_candidates().await.first() {
                    section.port = first_cand.address.port();
                    section.connection = Some(format!("IN IP4 {}", first_cand.address.ip()));
                }
            }

            self.populate_media_capabilities(&mut section, transceiver.kind(), sdp_type);
            if let Some(sender) = sender_info {
                Self::attach_sender_attributes(&mut section, &sender);
            }
            desc.media_sections.push(section);
        }

        if !desc.media_sections.is_empty() {
            let should_bundle = match sdp_type {
                SdpType::Offer => true,
                SdpType::Answer => remote_offered_bundle,
                _ => false,
            };

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

    fn attach_sender_attributes(section: &mut MediaSection, sender: &Arc<RtpSender>) {
        let ssrc = sender.ssrc();
        let cname = sender.cname();
        let stream_id = sender.stream_id();
        let track_id = sender.track_id();
        section.attributes.push(Attribute::new(
            "msid",
            Some(format!("{} {}", stream_id, track_id)),
        ));
        section.attributes.push(Attribute::new(
            "ssrc",
            Some(format!("{} cname:{}", ssrc, cname)),
        ));
        section.attributes.push(Attribute::new(
            "ssrc",
            Some(format!("{} msid:{} {}", ssrc, stream_id, track_id)),
        ));
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
        match kind {
            MediaKind::Audio => apply_audio_capabilities(section, &self.config),
            MediaKind::Video => apply_video_capabilities(section, &self.config),
            MediaKind::Application => apply_application_capabilities(section, &self.config),
        }
        if self.config.transport_mode != TransportMode::Rtp {
            self.add_dtls_attributes(section, sdp_type);
        }
    }

    fn add_dtls_attributes(&self, section: &mut MediaSection, sdp_type: SdpType) {
        section.attributes.push(Attribute::new(
            "fingerprint",
            Some(format!("{} {}", DTLS_HASH_ALGO, self.dtls_fingerprint)),
        ));
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
        section
            .attributes
            .push(Attribute::new("setup", Some(setup_value.into())));
    }
}

impl Drop for PeerConnectionInner {
    fn drop(&mut self) {
        debug!("PeerConnectionInner dropped, stopping ICE transport");
        self.ice_transport.stop();
    }
}

const AUDIO_PAYLOAD_TYPE: &str = "111";
const VIDEO_PAYLOAD_TYPE: &str = "96";
const SCTP_FORMAT: &str = "webrtc-datachannel";
const SCTP_PORT: u16 = 5000;
const DTLS_HASH_ALGO: &str = "sha-256";

fn apply_audio_capabilities(section: &mut MediaSection, config: &RtcConfiguration) {
    if let Some(caps) = &config.media_capabilities
        && !caps.audio.is_empty()
    {
        section.formats = caps
            .audio
            .iter()
            .map(|c| c.payload_type.to_string())
            .collect();
        section.attributes.push(Attribute::new("rtcp-mux", None));
        for audio in &caps.audio {
            section.attributes.push(Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate, audio.channels
                )),
            ));
            if let Some(fmtp) = &audio.fmtp {
                section.attributes.push(Attribute::new(
                    "fmtp",
                    Some(format!("{} {}", audio.payload_type, fmtp)),
                ));
            }
        }
        return;
    }

    section.formats = vec![AUDIO_PAYLOAD_TYPE.into()];
    section.attributes.push(Attribute::new("rtcp-mux", None));
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some(format!("{} opus/48000/2", AUDIO_PAYLOAD_TYPE)),
    ));
    section.attributes.push(Attribute::new(
        "fmtp",
        Some(format!("{} minptime=10;useinbandfec=1", AUDIO_PAYLOAD_TYPE)),
    ));
}

fn apply_video_capabilities(section: &mut MediaSection, config: &RtcConfiguration) {
    if let Some(caps) = &config.media_capabilities
        && !caps.video.is_empty()
    {
        section.formats = caps
            .video
            .iter()
            .map(|c| c.payload_type.to_string())
            .collect();
        section.attributes.push(Attribute::new("rtcp-mux", None));
        for video in &caps.video {
            section.attributes.push(Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}",
                    video.payload_type, video.codec_name, video.clock_rate
                )),
            ));
            for fb in &video.rtcp_fbs {
                section.attributes.push(Attribute::new(
                    "rtcp-fb",
                    Some(format!("{} {}", video.payload_type, fb)),
                ));
            }
        }
        return;
    }

    section.formats = vec![VIDEO_PAYLOAD_TYPE.into()];
    section.attributes.push(Attribute::new("rtcp-mux", None));
    section.attributes.push(Attribute::new(
        "rtpmap",
        Some(format!("{} VP8/90000", VIDEO_PAYLOAD_TYPE)),
    ));
    section.attributes.push(Attribute::new(
        "rtcp-fb",
        Some(format!("{} nack pli", VIDEO_PAYLOAD_TYPE)),
    ));
    section.attributes.push(Attribute::new(
        "rtcp-fb",
        Some(format!("{} ccm fir", VIDEO_PAYLOAD_TYPE)),
    ));
    section.attributes.push(Attribute::new(
        "rtcp-fb",
        Some(format!("{} transport-cc", VIDEO_PAYLOAD_TYPE)),
    ));
}

fn apply_application_capabilities(section: &mut MediaSection, config: &RtcConfiguration) {
    let port = if let Some(caps) = &config.media_capabilities {
        if let Some(app) = &caps.application {
            app.sctp_port
        } else {
            SCTP_PORT
        }
    } else {
        SCTP_PORT
    };

    section.protocol = "UDP/DTLS/SCTP".into();
    section.formats = vec![SCTP_FORMAT.into()];
    section
        .attributes
        .push(Attribute::new("sctp-port", Some(port.to_string())));
}

fn default_origin() -> Origin {
    let mut origin = Origin::default();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    origin.session_id = now;
    origin.session_version = now;
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

static TRANSCEIVER_COUNTER: AtomicU64 = AtomicU64::new(1);
static SSRC_COUNTER: AtomicU32 = AtomicU32::new(10000);

#[derive(Debug, Clone)]
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
    pub sender: Mutex<Option<Arc<RtpSender>>>,
    pub receiver: Mutex<Option<Arc<RtpReceiver>>>,
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
        }
    }

    pub fn id(&self) -> u64 {
        self.id
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
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
}

pub struct RtpSender {
    track: Arc<dyn MediaStreamTrack>,
    transport: Mutex<Option<Arc<RtpTransport>>>,
    ssrc: u32,
    params: Mutex<RtpCodecParameters>,
    track_id: Arc<str>,
    stream_id: Arc<str>,
    cname: Arc<str>,
    rtcp_tx: broadcast::Sender<RtcpPacket>,
    stop_tx: Arc<tokio::sync::Notify>,
}

impl RtpSender {
    pub fn new(track: Arc<dyn MediaStreamTrack>, ssrc: u32) -> Self {
        let track_label = track.id().to_string();
        let track_id = Arc::<str>::from(track_label.clone());
        let stream_id = Arc::<str>::from(format!("rustrtc-stream-{track_label}"));
        let cname = Arc::<str>::from(format!("rustrtc-cname-{ssrc}"));
        let (rtcp_tx, _) = broadcast::channel(100);
        let params = match track.kind() {
            crate::media::frame::MediaKind::Audio => RtpCodecParameters {
                payload_type: 111,
                clock_rate: 48000,
                channels: 2,
            },
            crate::media::frame::MediaKind::Video => RtpCodecParameters {
                payload_type: 96,
                clock_rate: 90000,
                channels: 0,
            },
        };
        Self {
            track,
            transport: Mutex::new(None),
            ssrc,
            params: Mutex::new(params),
            track_id,
            stream_id,
            cname,
            rtcp_tx,
            stop_tx: Arc::new(tokio::sync::Notify::new()),
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

    pub fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock().unwrap() = params;
    }

    pub fn set_transport(&self, transport: Arc<RtpTransport>) {
        *self.transport.lock().unwrap() = Some(transport.clone());
        let track = self.track.clone();
        let ssrc = self.ssrc;
        let params = self.params.lock().unwrap().clone();
        let stop_rx = self.stop_tx.clone();
        tokio::spawn(async move {
            let mut sequence_number = 0u16;
            loop {
                tokio::select! {
                    _ = stop_rx.notified() => break,
                    res = track.recv() => {
                        match res {
                            Ok(mut sample) => {
                                match &mut sample {
                                    crate::media::frame::MediaSample::Audio(f) => {
                                        f.sequence_number = None;
                                        f.payload_type = None;
                                    }
                                    crate::media::frame::MediaSample::Video(f) => {
                                        f.sequence_number = None;
                                        f.payload_type = None;
                                        f.header_extension = None;
                                    }
                                }

                                let packet = sample.into_rtp_packet(
                                    ssrc,
                                    params.clock_rate,
                                    params.payload_type,
                                    &mut sequence_number,
                                );
                                if let Err(e) = transport.send_rtp(&packet).await {
                                    debug!("Failed to send RTP: {}", e);
                                }
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
    rtcp_feedback_ssrc: Mutex<Option<u32>>,
    fir_seq: AtomicU8,
}

impl RtpReceiver {
    pub fn new(kind: MediaKind, ssrc: u32) -> Self {
        let media_kind = match kind {
            MediaKind::Audio => crate::media::frame::MediaKind::Audio,
            MediaKind::Video => crate::media::frame::MediaKind::Video,
            _ => crate::media::frame::MediaKind::Audio, // Fallback or panic
        };
        let (source, track) = sample_track(media_kind, 100);

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
            rtcp_feedback_ssrc: Mutex::new(None),
            fir_seq: AtomicU8::new(0),
        }
    }

    pub fn track(&self) -> Arc<SampleStreamTrack> {
        self.track.clone()
    }

    pub fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock().unwrap() = params;
    }

    pub fn set_ssrc(&self, ssrc: u32) {
        *self.ssrc.lock().unwrap() = ssrc;
    }

    pub fn set_transport(&self, transport: Arc<RtpTransport>) {
        *self.transport.lock().unwrap() = Some(transport.clone());
        let (tx, mut rx) = mpsc::channel(100);
        let ssrc = *self.ssrc.lock().unwrap();
        transport.register_listener_sync(ssrc, tx);
        let source = self.source.clone();
        let params = self.params.lock().unwrap().clone();

        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                if packet.payload.is_empty() {
                    debug!(
                        "RtpReceiver: Dropping packet with empty payload ssrc={}",
                        packet.header.ssrc
                    );
                    continue;
                }
                let sample = crate::media::frame::MediaSample::from_rtp_packet(
                    packet,
                    source.kind(),
                    params.clock_rate,
                    params.channels,
                );

                match sample {
                    crate::media::frame::MediaSample::Audio(frame) => {
                        let _ = source.send_audio(frame).await;
                    }
                    crate::media::frame::MediaSample::Video(frame) => {
                        let _ = source.send_video(frame).await;
                    }
                }
            }
        });
    }

    pub fn set_feedback_ssrc(&self, ssrc: u32) {
        *self.rtcp_feedback_ssrc.lock().unwrap() = Some(ssrc);
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

    #[tokio::test]
    async fn create_offer_contains_transceiver() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
        let offer = pc.create_offer().await.unwrap();
        assert_eq!(offer.media_sections.len(), 1);
        let section = &offer.media_sections[0];
        assert_eq!(section.kind, MediaKind::Audio);
        assert_eq!(section.direction, Direction::SendRecv);
        assert_eq!(section.formats, vec![AUDIO_PAYLOAD_TYPE.to_string()]);
        let attrs = &section.attributes;
        assert!(attrs.iter().any(|attr| attr.key == "ice-ufrag"));
        assert!(attrs.iter().any(|attr| attr.key == "ice-pwd"));
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
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read().await;

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
        let rtcp_addr = *ice_conn.remote_rtcp_addr.read().await;

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
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);

        let offer = pc.create_offer().await.unwrap();
        let section = &offer.media_sections[0];

        // Should NOT have ICE attributes
        assert!(!section.attributes.iter().any(|a| a.key == "ice-ufrag"));
        assert!(!section.attributes.iter().any(|a| a.key == "candidate"));

        // Should NOT have DTLS fingerprint
        assert!(!section.attributes.iter().any(|a| a.key == "fingerprint"));

        // Protocol should be RTP/AVPF
        assert_eq!(section.protocol, "RTP/AVPF");
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
}
