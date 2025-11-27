use crate::media::track::{MediaStreamTrack, SampleStreamSource, SampleStreamTrack, sample_track};
use crate::rtp::{RtpHeader, RtpPacket};
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
        Arc,
        atomic::{AtomicU16, AtomicU32, AtomicU64, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::{Mutex, mpsc, watch};
use tracing::{debug, warn};

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
    data_channels: Arc<Mutex<Vec<Arc<crate::transports::sctp::DataChannel>>>>,
    dtls_role: watch::Sender<Option<bool>>,
    _dtls_role_rx: watch::Receiver<Option<bool>>,
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
        };
        let pc = Self {
            inner: Arc::new(inner),
        };

        let inner_weak = Arc::downgrade(&pc.inner);
        let ice_transport = pc.inner.ice_transport.clone();
        let mut dtls_role_rx = dtls_role_rx;

        tokio::spawn(async move {
            let mut ice_state_rx = ice_transport.subscribe_state();
            loop {
                let ice_state = *ice_state_rx.borrow_and_update();

                if ice_state == crate::transports::ice::IceTransportState::Connected {
                    loop {
                        let role = *dtls_role_rx.borrow_and_update();
                        if let Some(is_client) = role {
                            if let Some(inner) = inner_weak.upgrade() {
                                let pc_temp = PeerConnection {
                                    inner: inner.clone(),
                                };

                                if let Err(e) = pc_temp.start_dtls(is_client).await {
                                    warn!("DTLS start failed: {}", e);
                                    let _ = inner.peer_state.send(PeerConnectionState::Failed);
                                } else {
                                    let _ = inner.peer_state.send(PeerConnectionState::Connected);
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
                    }
                } else if ice_state == crate::transports::ice::IceTransportState::Failed
                    || ice_state == crate::transports::ice::IceTransportState::Closed
                {
                    return;
                }

                if ice_state_rx.changed().await.is_err() {
                    return;
                }
            }
        });

        pc
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub fn ice_transport(&self) -> IceTransport {
        self.inner.ice_transport.clone()
    }

    pub async fn add_transceiver(
        &self,
        kind: MediaKind,
        direction: TransceiverDirection,
    ) -> Arc<RtpTransceiver> {
        let transceiver = Arc::new(RtpTransceiver::new(kind, direction));

        let receiver = Arc::new(RtpReceiver::new(kind, 67890)); // Random SSRC
        *transceiver.receiver.lock().await = Some(receiver);

        let mut list = self.inner.transceivers.lock().await;
        list.push(transceiver.clone());
        transceiver
    }

    pub async fn add_track(&self, track: Arc<dyn MediaStreamTrack>) -> RtcResult<Arc<RtpSender>> {
        let kind = match track.kind() {
            crate::media::frame::MediaKind::Audio => MediaKind::Audio,
            crate::media::frame::MediaKind::Video => MediaKind::Video,
        };
        let transceiver = self
            .add_transceiver(kind, TransceiverDirection::SendRecv)
            .await;
        let ssrc = SSRC_COUNTER.fetch_add(1, Ordering::Relaxed);
        let sender = Arc::new(RtpSender::new(track, ssrc));
        *transceiver.sender.lock().await = Some(sender.clone());
        Ok(sender)
    }

    pub async fn get_transceivers(&self) -> Vec<Arc<RtpTransceiver>> {
        self.inner.transceivers.lock().await.clone()
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

    pub async fn set_local_description(&self, desc: SessionDescription) -> RtcResult<()> {
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
        let mut local = self.inner.local_description.lock().await;
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
                            if attr.key == "setup" {
                                if let Some(val) = &attr.value {
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

        for section in &desc.media_sections {
            if self.config().transport_mode != TransportMode::WebRtc {
                if let Some(conn) = &section.connection {
                    let parts: Vec<&str> = conn.split_whitespace().collect();
                    if parts.len() >= 3 && parts[0] == "IN" && parts[1] == "IP4" {
                        if let Ok(ip) = parts[2].parse::<std::net::IpAddr>() {
                            remote_addr = Some(std::net::SocketAddr::new(ip, section.port));
                        }
                    }
                }
            }

            for attr in &section.attributes {
                if attr.key == "ice-ufrag" {
                    ufrag = attr.value.clone();
                } else if attr.key == "ice-pwd" {
                    pwd = attr.value.clone();
                } else if attr.key == "candidate" {
                    if let Some(val) = &attr.value {
                        if let Ok(c) = crate::transports::ice::IceCandidate::from_sdp(val) {
                            candidates.push(c);
                        }
                    }
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
            let mut transceivers = self.inner.transceivers.lock().await;
            for section in &desc.media_sections {
                let mid = &section.mid;
                let mut found = false;
                for t in transceivers.iter() {
                    if let Some(t_mid) = t.mid().await {
                        if t_mid == *mid {
                            found = true;
                            break;
                        }
                    }
                }

                if !found {
                    // Try to find a transceiver with no MID and same kind
                    for t in transceivers.iter() {
                        if t.mid().await.is_none() && t.kind() == section.kind {
                            t.set_mid(mid.clone()).await;
                            found = true;
                            break;
                        }
                    }
                }

                let mut ssrc = None;
                for attr in &section.attributes {
                    if attr.key == "ssrc" {
                        if let Some(val) = &attr.value {
                            if let Some(ssrc_str) = val.split_whitespace().next() {
                                if let Ok(parsed) = ssrc_str.parse::<u32>() {
                                    ssrc = Some(parsed);
                                    break;
                                }
                            }
                        }
                    }
                }

                if found {
                    if let Some(ssrc_val) = ssrc {
                        // Find the transceiver again to update SSRC
                        for t in transceivers.iter() {
                            if let Some(t_mid) = t.mid().await {
                                if t_mid == *mid {
                                    if let Some(rx) = t.receiver.lock().await.as_ref() {
                                        rx.set_ssrc(ssrc_val).await;
                                    }
                                    break;
                                }
                            }
                        }
                    }
                } else {
                    let kind = section.kind;
                    let t = Arc::new(RtpTransceiver::new(kind, TransceiverDirection::RecvOnly));
                    t.set_mid(mid.clone()).await;

                    let receiver_ssrc = ssrc.unwrap_or_else(|| 2000 + transceivers.len() as u32);
                    let receiver = Arc::new(RtpReceiver::new(kind, receiver_ssrc));
                    *t.receiver.lock().await = Some(receiver);

                    transceivers.push(t);
                }
            }
        }

        let mut remote = self.inner.remote_description.lock().await;
        *remote = Some(desc);
        Ok(())
    }

    pub async fn start_dtls(&self, is_client: bool) -> RtcResult<()> {
        let pair = self
            .inner
            .ice_transport
            .get_selected_pair()
            .await
            .ok_or(RtcError::Internal("No selected pair".into()))?;
        let socket = self
            .inner
            .ice_transport
            .get_selected_socket()
            .await
            .ok_or(RtcError::Internal("No selected socket".into()))?;

        let ice_conn = IceConn::new(socket, pair.remote.address);
        self.inner
            .ice_transport
            .set_data_receiver(ice_conn.clone())
            .await;

        let rtp_transport = Arc::new(RtpTransport::new(ice_conn.clone()));
        {
            let mut rx = ice_conn.rtp_receiver.write().await;
            *rx = Some(rtp_transport.clone());
        }
        *self.inner.rtp_transport.lock().await = Some(rtp_transport.clone());

        {
            let transceivers = self.inner.transceivers.lock().await;
            for t in transceivers.iter() {
                if let Some(sender) = &*t.sender.lock().await {
                    sender.set_transport(rtp_transport.clone()).await;
                }
                if let Some(receiver) = &*t.receiver.lock().await {
                    receiver.set_transport(rtp_transport.clone()).await;
                }
            }
        }

        if self.config().transport_mode == TransportMode::Rtp {
            return Ok(());
        }

        let dtls = DtlsTransport::new(ice_conn, self.inner.certificate.as_ref().clone(), is_client)
            .await
            .map_err(|e| RtcError::Internal(format!("DTLS failed: {}", e)))?;

        let sctp = SctpTransport::new(dtls.clone(), self.inner.data_channels.clone());
        *self.inner.sctp_transport.lock().await = Some(sctp);

        *self.inner.dtls_transport.lock().await = Some(dtls.clone());

        let dtls_clone = dtls.clone();
        let rtp_transport_clone = rtp_transport.clone();
        tokio::spawn(async move {
            let mut state_rx = dtls_clone.subscribe_state();
            loop {
                if state_rx.changed().await.is_err() {
                    break;
                }
                let state = state_rx.borrow().clone();
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
                        
                        if let Ok(mat) = dtls_clone.export_keying_material("EXTRACTOR-dtls_srtp", total_len).await {
                            let client_key = &mat[0..key_len];
                            let server_key = &mat[key_len..2*key_len];
                            let client_salt = &mat[2*key_len..2*key_len+salt_len];
                            let server_salt = &mat[2*key_len+salt_len..];
                            
                            let (tx_key, tx_salt, rx_key, rx_salt) = if is_client {
                                (client_key, client_salt, server_key, server_salt)
                            } else {
                                (server_key, server_salt, client_key, client_salt)
                            };

                            let tx_keying = crate::srtp::SrtpKeyingMaterial::new(tx_key.to_vec(), tx_salt.to_vec());
                            let rx_keying = crate::srtp::SrtpKeyingMaterial::new(rx_key.to_vec(), rx_salt.to_vec());

                            if let Ok(session) = crate::srtp::SrtpSession::new(profile, tx_keying, rx_keying) {
                                rtp_transport_clone.start_srtp(session).await;
                            }
                        }
                        break;
                    }
                    crate::transports::dtls::DtlsState::Failed => {
                        break;
                    }
                    _ => {}
                }
            }
        });

        Ok(())
    }

    pub async fn signaling_state(&self) -> SignalingState {
        *self.inner.signaling_state.borrow()
    }

    pub async fn subscribe_signaling_state(&self) -> watch::Receiver<SignalingState> {
        self.inner.signaling_state.subscribe()
    }

    pub async fn subscribe_peer_state(&self) -> watch::Receiver<PeerConnectionState> {
        self.inner.peer_state.subscribe()
    }

    pub async fn subscribe_ice_connection_state(&self) -> watch::Receiver<IceConnectionState> {
        self.inner.ice_connection_state.subscribe()
    }

    pub async fn subscribe_ice_gathering_state(&self) -> watch::Receiver<IceGatheringState> {
        self.inner.ice_gathering_state.subscribe()
    }

    pub async fn local_description(&self) -> Option<SessionDescription> {
        self.inner.local_description.lock().await.clone()
    }

    pub async fn remote_description(&self) -> Option<SessionDescription> {
        self.inner.remote_description.lock().await.clone()
    }

    pub async fn close(&self) {
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
        self.inner.ice_transport.stop().await;
    }

    pub async fn create_data_channel(
        &self,
        label: &str,
    ) -> RtcResult<Arc<crate::transports::sctp::DataChannel>> {
        // Ensure we have an application transceiver for negotiation
        let has_app_transceiver = {
            let transceivers = self.inner.transceivers.lock().await;
            transceivers
                .iter()
                .any(|t| t.kind() == MediaKind::Application)
        };

        if !has_app_transceiver {
            self.add_transceiver(MediaKind::Application, TransceiverDirection::SendRecv)
                .await;
        }

        let id = {
            let channels = self.inner.data_channels.lock().await;
            channels.len() as u16
        };

        let dc = Arc::new(crate::transports::sctp::DataChannel::new(
            id,
            label.to_string(),
        ));

        self.inner.data_channels.lock().await.push(dc.clone());

        Ok(dc)
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> RtcResult<()> {
        let sctp = self.inner.sctp_transport.lock().await;
        if let Some(transport) = &*sctp {
            transport
                .send_data(channel_id, data)
                .await
                .map_err(|e| RtcError::Internal(format!("SCTP send failed: {}", e)))
        } else {
            Err(RtcError::InvalidState("SCTP not connected".into()))
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
            let list = self.transceivers.lock().await;
            list.iter().cloned().collect::<Vec<_>>()
        };
        if transceivers.is_empty() {
            return Err(RtcError::InvalidState(
                "cannot build SDP with no transceivers".into(),
            ));
        }

        let ordered_transceivers = if sdp_type == SdpType::Answer {
            let remote_guard = self.remote_description.lock().await;
            let remote = remote_guard.as_ref().ok_or_else(|| {
                RtcError::InvalidState("create_answer called without remote description".into())
            })?;
            let mut ordered = Vec::new();
            for section in &remote.media_sections {
                let mid = &section.mid;
                let mut found = None;
                for t in &transceivers {
                    if let Some(t_mid) = t.mid().await {
                        if t_mid == *mid {
                            found = Some(t.clone());
                            break;
                        }
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

        let mode = self.config.transport_mode.clone();

        for transceiver in ordered_transceivers {
            let mid = self.ensure_mid(&transceiver).await;
            let direction = map_direction(transceiver.direction().await);
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
            desc.media_sections.push(section);
        }
        Ok(desc)
    }

    async fn ensure_mid(&self, transceiver: &Arc<RtpTransceiver>) -> String {
        if let Some(mid) = transceiver.mid().await {
            return mid;
        }
        let mid_value = self.allocate_mid();
        transceiver.set_mid(mid_value.clone()).await;
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

const AUDIO_PAYLOAD_TYPE: &str = "111";
const VIDEO_PAYLOAD_TYPE: &str = "96";
const SCTP_FORMAT: &str = "webrtc-datachannel";
const SCTP_PORT: u16 = 5000;
const DTLS_HASH_ALGO: &str = "sha-256";

fn apply_audio_capabilities(section: &mut MediaSection, config: &RtcConfiguration) {
    if let Some(caps) = &config.media_capabilities {
        if !caps.audio.is_empty() {
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
    if let Some(caps) = &config.media_capabilities {
        if !caps.video.is_empty() {
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

    pub async fn direction(&self) -> TransceiverDirection {
        *self.direction.lock().await
    }

    pub async fn set_direction(&self, direction: TransceiverDirection) {
        *self.direction.lock().await = direction;
    }

    pub async fn mid(&self) -> Option<String> {
        self.mid.lock().await.clone()
    }

    async fn set_mid(&self, mid: String) {
        *self.mid.lock().await = Some(mid);
    }
}

pub struct RtpSender {
    track: Arc<dyn MediaStreamTrack>,
    transport: Mutex<Option<Arc<RtpTransport>>>,
    ssrc: u32,
    params: Mutex<RtpCodecParameters>,
}

impl RtpSender {
    pub fn new(track: Arc<dyn MediaStreamTrack>, ssrc: u32) -> Self {
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
        }
    }

    pub async fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock().await = params;
    }

    pub async fn set_transport(&self, transport: Arc<RtpTransport>) {
        *self.transport.lock().await = Some(transport.clone());
        let track = self.track.clone();
        let ssrc = self.ssrc;
        let params = self.params.lock().await.clone();
        tokio::spawn(async move {
            let mut sequence_number = 0u16;
            while let Ok(sample) = track.recv().await {
                let (payload, timestamp_duration, marker) = match sample {
                    crate::media::frame::MediaSample::Audio(f) => (f.data, f.timestamp, false),
                    crate::media::frame::MediaSample::Video(f) => {
                        (f.data, f.timestamp, f.is_last_packet)
                    }
                };

                let timestamp =
                    (timestamp_duration.as_secs_f64() * params.clock_rate as f64) as u32;

                let mut header =
                    RtpHeader::new(params.payload_type, sequence_number, timestamp, ssrc);
                header.marker = marker;
                sequence_number = sequence_number.wrapping_add(1);

                let packet = RtpPacket::new(header, payload.to_vec());
                debug!(
                    "Sending RTP packet: ssrc={} seq={} ts={} len={}",
                    ssrc,
                    sequence_number,
                    timestamp,
                    packet.payload.len()
                );
                if let Err(e) = transport.send_rtp(&packet).await {
                    debug!("Failed to send RTP: {}", e);
                }
            }
        });
    }
}

pub struct RtpReceiver {
    track: Arc<SampleStreamTrack>,
    source: Arc<SampleStreamSource>,
    ssrc: Mutex<u32>,
    params: Mutex<RtpCodecParameters>,
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
        }
    }

    pub fn track(&self) -> Arc<SampleStreamTrack> {
        self.track.clone()
    }

    pub async fn set_params(&self, params: RtpCodecParameters) {
        *self.params.lock().await = params;
    }

    pub async fn set_ssrc(&self, ssrc: u32) {
        *self.ssrc.lock().await = ssrc;
    }

    pub async fn set_transport(&self, transport: Arc<RtpTransport>) {
        let (tx, mut rx) = mpsc::channel(100);
        let ssrc = *self.ssrc.lock().await;
        transport.register_listener(ssrc, tx).await;
        let source = self.source.clone();
        let params = self.params.lock().await.clone();

        tokio::spawn(async move {
            while let Some(packet) = rx.recv().await {
                debug!(
                    "Received RTP packet: ssrc={} seq={} ts={} len={}",
                    packet.header.ssrc,
                    packet.header.sequence_number,
                    packet.header.timestamp,
                    packet.payload.len()
                );
                let data = bytes::Bytes::from(packet.payload);
                let timestamp = if params.clock_rate > 0 {
                    std::time::Duration::from_secs_f64(
                        packet.header.timestamp as f64 / params.clock_rate as f64,
                    )
                } else {
                    std::time::Duration::ZERO
                };

                if source.kind() == crate::media::frame::MediaKind::Audio {
                    let samples = if params.channels > 0 {
                        (data.len() as u32) / (params.channels as u32 * 2)
                    } else {
                        0
                    };
                    let frame = crate::media::frame::AudioFrame {
                        timestamp,
                        sample_rate: params.clock_rate,
                        channels: params.channels,
                        samples,
                        format: crate::media::frame::AudioSampleFormat::S16,
                        data,
                    };
                    let _ = source.send_audio(frame).await;
                } else if source.kind() == crate::media::frame::MediaKind::Video {
                    let frame = crate::media::frame::VideoFrame {
                        timestamp,
                        width: 0,
                        height: 0,
                        format: crate::media::frame::VideoPixelFormat::Unspecified,
                        rotation_deg: 0,
                        is_last_packet: packet.header.marker,
                        data,
                    };
                    let _ = source.send_video(frame).await;
                }
            }
        });
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
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv)
            .await;
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
        assert_eq!(pc.signaling_state().await, SignalingState::Stable);
    }

    #[tokio::test]
    async fn offer_includes_video_capabilities() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendRecv)
            .await;
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
        pc.add_transceiver(MediaKind::Application, TransceiverDirection::SendRecv)
            .await;
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
    async fn set_local_description_transitions_state() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv)
            .await;
        let offer = pc.create_offer().await.unwrap();
        pc.set_local_description(offer.clone()).await.unwrap();
        assert_eq!(pc.signaling_state().await, SignalingState::HaveLocalOffer);

        let mut answer = offer.clone();
        answer.sdp_type = SdpType::Answer;
        pc.set_remote_description(answer).await.unwrap();
        assert_eq!(pc.signaling_state().await, SignalingState::Stable);
    }

    #[tokio::test]
    async fn create_answer_requires_remote_offer() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Video, TransceiverDirection::SendOnly)
            .await;
        let err = pc.create_answer().await.unwrap_err();
        assert!(matches!(err, RtcError::InvalidState(_)));

        let offer = pc.create_offer().await.unwrap();
        pc.set_remote_description(offer.clone()).await.unwrap();
        let answer = pc.create_answer().await.unwrap();
        assert_eq!(answer.media_sections.len(), 1);
        assert_eq!(answer.media_sections[0].direction, Direction::RecvOnly);
        pc.set_local_description(answer).await.unwrap();
        assert_eq!(pc.signaling_state().await, SignalingState::Stable);
    }

    #[tokio::test]
    async fn remote_answer_without_local_offer_is_error() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::RecvOnly)
            .await;
        let mut fake_answer = pc.create_offer().await.unwrap();
        fake_answer.sdp_type = SdpType::Answer;
        let err = pc.set_remote_description(fake_answer).await.unwrap_err();
        assert!(matches!(err, RtcError::InvalidState(_)));
    }

    #[tokio::test]
    async fn peer_connection_exposes_ice_transport() {
        let pc = PeerConnection::new(RtcConfiguration::default());
        let ice = pc.ice_transport();
        assert_eq!(ice.state().await, IceTransportState::New);
        assert_eq!(ice.config().ice_servers.len(), 0);
    }

    #[tokio::test]
    async fn create_offer_rtp_mode() {
        use crate::TransportMode;
        let mut config = RtcConfiguration::default();
        config.transport_mode = TransportMode::Rtp;
        let pc = PeerConnection::new(config);
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv)
            .await;

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
        pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv)
            .await;

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
