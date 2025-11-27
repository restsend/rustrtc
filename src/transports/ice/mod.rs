pub mod conn;
pub mod stun;
#[cfg(test)]
mod tests;

use crate::transports::PacketReceiver;
use bytes::Bytes;
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use md5::{Digest as Md5Digest, Md5};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket, lookup_host};
use tokio::sync::{Mutex, oneshot, watch};
use tokio::time::timeout;
use tracing::{debug, instrument, trace, warn};

use self::stun::{
    StunAttribute, StunClass, StunDecoded, StunMessage, StunMethod, random_bytes, random_u64,
};
use crate::{IceCredentialType, IceServer, RtcConfiguration};

const STUN_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_STUN_MESSAGE: usize = 1500;
const DEFAULT_TURN_LIFETIME: u32 = 600;

#[derive(Debug, Clone)]
pub struct IceTransport {
    inner: Arc<IceTransportInner>,
}

struct IceTransportInner {
    state: watch::Sender<IceTransportState>,
    role: Mutex<IceRole>,
    selected_pair: Mutex<Option<IceCandidatePair>>,
    local_candidates: Mutex<Vec<IceCandidate>>,
    remote_candidates: Mutex<Vec<IceCandidate>>,
    gather_state: Mutex<IceGathererState>,
    config: RtcConfiguration,
    gatherer: IceGatherer,
    local_parameters: Mutex<IceParameters>,
    remote_parameters: Mutex<Option<IceParameters>>,
    pending_transactions: Mutex<HashMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    data_receiver: Mutex<Option<Arc<dyn PacketReceiver>>>,
}

impl std::fmt::Debug for IceTransportInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IceTransportInner")
            .field("state", &self.state)
            .field("role", &self.role)
            .field("selected_pair", &self.selected_pair)
            .field("local_candidates", &self.local_candidates)
            .field("remote_candidates", &self.remote_candidates)
            .field("gather_state", &self.gather_state)
            .field("config", &self.config)
            .field("gatherer", &self.gatherer)
            .field("local_parameters", &self.local_parameters)
            .field("remote_parameters", &self.remote_parameters)
            .field("pending_transactions", &self.pending_transactions)
            .field("data_receiver", &"PacketReceiver")
            .finish()
    }
}

impl IceTransport {
    pub fn new(config: RtcConfiguration) -> Self {
        let gatherer = IceGatherer::new(config.clone());
        let (state_tx, _) = watch::channel(IceTransportState::New);
        let inner = IceTransportInner {
            state: state_tx,
            role: Mutex::new(IceRole::Controlled),
            selected_pair: Mutex::new(None),
            local_candidates: Mutex::new(Vec::new()),
            remote_candidates: Mutex::new(Vec::new()),
            gather_state: Mutex::new(IceGathererState::New),
            config,
            gatherer,
            local_parameters: Mutex::new(IceParameters::generate()),
            remote_parameters: Mutex::new(None),
            pending_transactions: Mutex::new(HashMap::new()),
            data_receiver: Mutex::new(None),
        };
        Self {
            inner: Arc::new(inner),
        }
    }

    pub async fn state(&self) -> IceTransportState {
        *self.inner.state.borrow()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<IceTransportState> {
        self.inner.state.subscribe()
    }

    pub async fn gather_state(&self) -> IceGathererState {
        self.inner.gatherer.state().await
    }

    pub async fn role(&self) -> IceRole {
        *self.inner.role.lock().await
    }

    pub async fn local_candidates(&self) -> Vec<IceCandidate> {
        self.inner.gatherer.local_candidates().await
    }

    pub async fn remote_candidates(&self) -> Vec<IceCandidate> {
        self.inner.remote_candidates.lock().await.clone()
    }

    pub async fn local_parameters(&self) -> IceParameters {
        self.inner.local_parameters.lock().await.clone()
    }

    pub async fn start_gathering(&self) -> Result<()> {
        {
            let mut state = self.inner.gather_state.lock().await;
            if *state == IceGathererState::Complete {
                return Ok(());
            }
            if *state == IceGathererState::New {
                *state = IceGathererState::Gathering;
            }
        }
        self.inner.gatherer.gather().await?;
        let mut buffer = self.inner.local_candidates.lock().await;
        *buffer = self.inner.gatherer.local_candidates().await;
        *self.inner.gather_state.lock().await = IceGathererState::Complete;
        Ok(())
    }

    pub async fn start(&self, remote: IceParameters) -> Result<()> {
        self.start_gathering().await?;
        self.start_read_loops().await;
        {
            let mut params = self.inner.remote_parameters.lock().await;
            *params = Some(remote);
        }
        let _ = self.inner.state.send(IceTransportState::Checking);
        self.try_connectivity_checks();
        Ok(())
    }

    pub async fn start_direct(&self, remote_addr: SocketAddr) -> Result<()> {
        self.start_gathering().await?;
        self.start_read_loops().await;

        // Select the first local socket/candidate
        let local_candidates = self.inner.gatherer.local_candidates().await;
        let local = local_candidates
            .first()
            .ok_or_else(|| anyhow!("No local candidates gathered"))?
            .clone();

        let remote = IceCandidate::host(remote_addr, 1);
        let pair = IceCandidatePair::new(local, remote);

        *self.inner.selected_pair.lock().await = Some(pair);
        let _ = self.inner.state.send(IceTransportState::Connected);
        Ok(())
    }

    pub async fn stop(&self) {
        let _ = self.inner.state.send(IceTransportState::Closed);
    }

    pub async fn set_role(&self, role: IceRole) {
        *self.inner.role.lock().await = role;
    }

    pub async fn add_remote_candidate(&self, candidate: IceCandidate) {
        let mut list = self.inner.remote_candidates.lock().await;
        list.push(candidate);
        drop(list);
        self.try_connectivity_checks();
    }

    pub async fn select_pair(&self, pair: IceCandidatePair) {
        *self.inner.selected_pair.lock().await = Some(pair.clone());
        let _ = self.inner.state.send(IceTransportState::Connected);
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub async fn get_selected_socket(&self) -> Option<IceSocketWrapper> {
        let pair = self.inner.selected_pair.lock().await.clone()?;
        if pair.local.typ == IceCandidateType::Relay {
            let clients = self.inner.gatherer.turn_clients.lock().await;
            clients
                .get(&pair.local.address)
                .map(|c| IceSocketWrapper::Turn(c.clone()))
        } else {
            self.inner
                .gatherer
                .get_socket(pair.local.address)
                .await
                .map(IceSocketWrapper::Udp)
        }
    }

    pub async fn get_selected_pair(&self) -> Option<IceCandidatePair> {
        self.inner.selected_pair.lock().await.clone()
    }

    pub async fn set_data_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.inner.data_receiver.lock().await = Some(receiver);
    }

    fn try_connectivity_checks(&self) {
        try_connectivity_checks(self.inner.clone());
    }

    async fn start_read_loops(&self) {
        let sockets = self.inner.gatherer.sockets.lock().await;
        for socket in sockets.iter() {
            let socket = socket.clone();
            let inner = self.inner.clone();
            let mut state_rx = self.inner.state.subscribe();
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                trace!("Read loop started for {:?}", socket.local_addr());
                loop {
                    tokio::select! {
                        res = socket.recv_from(&mut buf) => {
                            let (len, addr) = match res {
                                Ok(v) => v,
                                Err(e) => {
                                    debug!("Socket recv error: {}", e);
                                    break;
                                }
                            };
                            let packet = &buf[..len];
                            if len > 0 {
                                handle_packet(packet, addr, inner.clone(), IceSocketWrapper::Udp(socket.clone()))
                                    .await;
                            }
                        }
                        _ = state_rx.changed() => {
                            if *state_rx.borrow() == IceTransportState::Closed {
                                debug!("Read loop stopping (IceTransport Closed)");
                                break;
                            }
                        }
                    }
                }
            });
        }

        let turn_clients = self.inner.gatherer.turn_clients.lock().await;
        for (relayed_addr, client) in turn_clients.iter() {
            let client = client.clone();
            let inner = self.inner.clone();
            let relayed_addr = *relayed_addr;
            let mut state_rx = self.inner.state.subscribe();
            tokio::spawn(async move {
                let mut buf = [0u8; 1500];
                trace!("Read loop started for TURN client {}", relayed_addr);
                loop {
                    let recv_future = async {
                        let client_lock = client.lock().await;
                        let result = client_lock.recv(&mut buf).await;
                        drop(client_lock); // Release lock
                        result
                    };

                    tokio::select! {
                        result = recv_future => {
                            match result {
                                Ok(len) => {
                                    if len > 0 {
                                        let packet = &buf[..len];
                                        if let Ok(msg) = StunMessage::decode(packet) {
                                            if msg.class == StunClass::Indication
                                                && msg.method == StunMethod::Data
                                            {
                                                if let Some(data) = &msg.data {
                                                    if let Some(peer_addr) = msg.xor_peer_address {
                                                        handle_packet(
                                                            data,
                                                            peer_addr,
                                                            inner.clone(),
                                                            IceSocketWrapper::Turn(client.clone()),
                                                        )
                                                        .await;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                                Err(e) => {
                                    warn!("TURN client recv error: {}", e);
                                    break;
                                }
                            }
                        }
                        _ = state_rx.changed() => {
                            if *state_rx.borrow() == IceTransportState::Closed {
                                debug!("TURN Read loop stopping (IceTransport Closed)");
                                break;
                            }
                        }
                    }
                }
            });
        }
    }
}

fn try_connectivity_checks(inner: Arc<IceTransportInner>) {
    tokio::spawn(async move {
        if *inner.state.borrow() != IceTransportState::Checking {
            return;
        }
        let locals = inner.local_candidates.lock().await.clone();
        let remotes = inner.remote_candidates.lock().await.clone();
        let role = *inner.role.lock().await;
        if locals.is_empty() || remotes.is_empty() {
            return;
        }

        let (tx, mut rx) = tokio::sync::mpsc::channel(1);
        let mut check_count = 0;

        for local in &locals {
            for remote in &remotes {
                if local.transport != remote.transport {
                    trace!(
                        "Skipping pair due to transport mismatch: {} != {}",
                        local.transport, remote.transport
                    );
                    continue;
                }
                check_count += 1;
                let inner = inner.clone();
                let local = local.clone();
                let remote = remote.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    match perform_binding_check(&local, &remote, &inner, role).await {
                        Ok(_) => {
                            trace!(
                                "ICE check succeeded: {} -> {}",
                                local.address, remote.address
                            );
                            let _ = tx.send(IceCandidatePair::new(local, remote)).await;
                        }
                        Err(e) => {
                            debug!(
                                "ICE check failed: {} -> {} : {}",
                                local.address, remote.address, e
                            );
                        }
                    }
                });
            }
        }

        if check_count == 0 {
            return;
        }

        // Wait for first success
        if let Some(pair) = rx.recv().await {
            debug!(
                "Selected pair: {} -> {}",
                pair.local.address, pair.remote.address
            );
            *inner.selected_pair.lock().await = Some(pair);
            let _ = inner.state.send(IceTransportState::Connected);
        } else {
            // If all failed (channel closed because all senders dropped? No, we hold one tx clone? No, we dropped it?)
            // We need to drop the initial tx to allow rx to close when all tasks finish.
            // But we cloned tx in the loop.
            // We should drop the initial tx.
            let _ = inner.state.send(IceTransportState::Failed);
        }
    });
}

async fn handle_packet(
    packet: &[u8],
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
    sender: IceSocketWrapper,
) {
    let b = packet[0];
    if b < 2 {
        // STUN
        match StunMessage::decode(packet) {
            Ok(msg) => {
                if msg.class == StunClass::Request {
                    trace!("Received STUN Request from {}", addr);
                    handle_stun_request(&sender, &msg, addr, inner).await;
                } else if msg.class == StunClass::SuccessResponse {
                    trace!(
                        "Received STUN Response from {} tx={:?}",
                        addr, msg.transaction_id
                    );
                    let mut map = inner.pending_transactions.lock().await;
                    if let Some(tx) = map.remove(&msg.transaction_id) {
                        trace!("Matched transaction {:?}", msg.transaction_id);
                        let _ = tx.send(msg);
                    } else {
                        trace!(
                            "Unmatched transaction {:?} Pending transactions: {:?}",
                            msg.transaction_id,
                            map.keys()
                        );
                    }
                } else if msg.class == StunClass::ErrorResponse {
                    trace!("Received STUN Error Response from {}", addr);
                    if let Some(code) = msg.error_code {
                        trace!("Error code: {}", code);
                    }
                }
            }
            Err(e) => {
                debug!("Failed to decode STUN packet from {}: {}", addr, e);
            }
        }
    } else {
        // DTLS or RTP
        debug!("Received non-STUN packet from {}, first byte: {}", addr, b);
        let receiver = inner.data_receiver.lock().await.clone();
        if let Some(rx) = receiver {
            rx.receive(Bytes::copy_from_slice(packet), addr).await;
        }
    }
}

async fn handle_stun_request(
    sender: &IceSocketWrapper,
    msg: &StunDecoded,
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
) {
    let response = StunMessage::binding_success_response(msg.transaction_id, addr);

    let local_params = inner.local_parameters.lock().await;
    let password = &local_params.password;

    trace!(
        "Handling STUN Request from {}, sending response with password {}",
        addr, password
    );
    if let Ok(bytes) = response.encode(Some(password.as_bytes()), true) {
        match sender.send_to(&bytes, addr).await {
            Ok(_) => trace!("Sent STUN Response to {}", addr),
            Err(e) => warn!("Failed to send STUN Response to {}: {}", addr, e),
        }
    } else {
        warn!("Failed to encode STUN Response");
    }

    // Check if we know this candidate
    let mut known = false;
    {
        let remotes = inner.remote_candidates.lock().await;
        for cand in remotes.iter() {
            if cand.address == addr {
                known = true;
                break;
            }
        }
    }

    if !known {
        debug!("Discovered peer reflexive candidate: {}", addr);
        let mut candidate = IceCandidate::host(addr, 1); // Use host for now, or prflx
        candidate.typ = IceCandidateType::PeerReflexive;
        candidate.foundation = "prflx".to_string();
        candidate.priority = IceCandidate::priority_for(IceCandidateType::PeerReflexive, 1);

        let mut list = inner.remote_candidates.lock().await;
        list.push(candidate);
        drop(list);

        try_connectivity_checks(inner.clone());
    }
}

async fn perform_binding_check(
    local: &IceCandidate,
    remote: &IceCandidate,
    inner: &Arc<IceTransportInner>,
    role: IceRole,
) -> Result<()> {
    if remote.transport != "udp" {
        bail!("only UDP connectivity checks are supported");
    }
    let local_params = inner.local_parameters.lock().await.clone();
    let remote_params = match inner.remote_parameters.lock().await.clone() {
        Some(p) => p,
        None => bail!("no remote params"),
    };

    let tx_id = random_bytes::<12>();
    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
    let username = format!(
        "{}:{}",
        remote_params.username_fragment, local_params.username_fragment
    );
    msg.attributes.push(StunAttribute::Username(username));
    msg.attributes.push(StunAttribute::Priority(local.priority));
    trace!("perform_binding_check: role={:?}", role);
    match role {
        IceRole::Controlling => {
            msg.attributes
                .push(StunAttribute::IceControlling(local_params.tie_breaker));
            msg.attributes.push(StunAttribute::UseCandidate);
        }
        IceRole::Controlled => msg
            .attributes
            .push(StunAttribute::IceControlled(local_params.tie_breaker)),
    }
    let bytes = msg.encode(Some(remote_params.password.as_bytes()), true)?;

    let (tx, rx) = oneshot::channel();
    {
        let mut map = inner.pending_transactions.lock().await;
        map.insert(tx_id, tx);
    }

    if local.typ == IceCandidateType::Relay {
        let gatherer = &inner.gatherer;
        let clients = gatherer.turn_clients.lock().await;
        if let Some(client_mutex) = clients.get(&local.address) {
            let client = client_mutex.clone();
            drop(clients);

            let client_lock = client.lock().await;
            let (perm_bytes, perm_tx_id) =
                client_lock.create_permission_packet(remote.address).await?;
            drop(client_lock);

            let (perm_tx, perm_rx) = oneshot::channel();
            {
                let mut map = inner.pending_transactions.lock().await;
                map.insert(perm_tx_id, perm_tx);
            }

            trace!("Sending CreatePermission to TURN server");
            client.lock().await.send(&perm_bytes).await?;

            match timeout(STUN_TIMEOUT, perm_rx).await {
                Ok(Ok(msg)) => {
                    if msg.class == StunClass::ErrorResponse {
                        bail!("CreatePermission failed: {:?}", msg.error_code);
                    }
                }
                _ => {
                    let mut map = inner.pending_transactions.lock().await;
                    map.remove(&perm_tx_id);
                    bail!("CreatePermission timeout");
                }
            }

            trace!(
                "Sending STUN Binding Request via TURN to {}",
                remote.address
            );
            client
                .lock()
                .await
                .send_indication(remote.address, &bytes)
                .await?;
        } else {
            bail!("TURN client not found for relay candidate");
        }
    } else {
        let socket = inner
            .gatherer
            .get_socket(local.address)
            .await
            .ok_or_else(|| anyhow!("no socket found for local candidate"))?;

        trace!("Sending STUN Request to {} tx={:?}", remote.address, tx_id);
        socket.send_to(&bytes, remote.address).await?;
    }

    let parsed = match timeout(STUN_TIMEOUT, rx).await {
        Ok(Ok(msg)) => msg,
        Ok(Err(_)) => bail!("channel closed"),
        Err(_) => {
            let mut map = inner.pending_transactions.lock().await;
            map.remove(&tx_id);
            bail!("timeout");
        }
    };

    if parsed.transaction_id != tx_id {
        bail!("binding response transaction mismatch");
    }
    if parsed.method != StunMethod::Binding {
        bail!("unexpected STUN method in binding response");
    }
    if parsed.class != StunClass::SuccessResponse {
        bail!("binding request failed");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceTransportState {
    New,
    Checking,
    Connected,
    Completed,
    Failed,
    Disconnected,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceGathererState {
    New,
    Gathering,
    Complete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceRole {
    Controlling,
    Controlled,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub foundation: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub typ: IceCandidateType,
    pub transport: String,
    pub related_address: Option<SocketAddr>,
    pub component: u16,
}

impl IceCandidate {
    pub fn host(address: SocketAddr, component: u16) -> Self {
        Self {
            foundation: format!("host:{}", address.ip()),
            priority: IceCandidate::priority_for(IceCandidateType::Host, component),
            address,
            typ: IceCandidateType::Host,
            transport: "udp".into(),
            related_address: None,
            component,
        }
    }

    fn server_reflexive(base: SocketAddr, mapped: SocketAddr, component: u16) -> Self {
        Self {
            foundation: format!("srflx:{}", mapped.ip()),
            priority: IceCandidate::priority_for(IceCandidateType::ServerReflexive, component),
            address: mapped,
            typ: IceCandidateType::ServerReflexive,
            transport: "udp".into(),
            related_address: Some(base),
            component,
        }
    }

    fn relay(mapped: SocketAddr, component: u16, transport: &str) -> Self {
        Self {
            foundation: format!("relay:{}", mapped.ip()),
            priority: IceCandidate::priority_for(IceCandidateType::Relay, component),
            address: mapped,
            typ: IceCandidateType::Relay,
            transport: transport.into(),
            related_address: None,
            component,
        }
    }

    fn priority_for(typ: IceCandidateType, component: u16) -> u32 {
        let type_pref = match typ {
            IceCandidateType::Host => 126u32,
            IceCandidateType::PeerReflexive => 110u32,
            IceCandidateType::ServerReflexive => 100u32,
            IceCandidateType::Relay => 0u32,
        };
        let local_pref = 65_535u32;
        let component = component.min(256) as u32;
        (type_pref << 24) | (local_pref << 8) | (256 - component)
    }

    pub fn to_sdp(&self) -> String {
        let mut parts = vec![
            self.foundation.clone(),
            self.component.to_string(),
            self.transport.to_ascii_lowercase(),
            self.priority.to_string(),
            self.address.ip().to_string(),
            self.address.port().to_string(),
            "typ".into(),
            self.typ.as_str().into(),
        ];
        if let Some(addr) = self.related_address {
            parts.push("raddr".into());
            parts.push(addr.ip().to_string());
            parts.push("rport".into());
            parts.push(addr.port().to_string());
        }
        parts.join(" ")
    }

    pub fn from_sdp(sdp: &str) -> Result<Self> {
        let parts: Vec<&str> = sdp.split_whitespace().collect();
        if parts.len() < 8 {
            bail!("invalid candidate");
        }
        // Handle "candidate:" prefix if present (though usually it's the attribute key)
        let start_idx = 0;

        let foundation = parts[start_idx]
            .trim_start_matches("candidate:")
            .to_string();
        let component = parts[start_idx + 1].parse::<u16>()?;
        let transport = parts[start_idx + 2].to_ascii_lowercase();
        let priority = parts[start_idx + 3].parse::<u32>()?;
        let ip_str = parts[start_idx + 4];
        let port = parts[start_idx + 5].parse::<u16>()?;
        let typ_str = parts[start_idx + 7];

        let address = format!("{}:{}", ip_str, port).parse()?;

        let typ = match typ_str {
            "host" => IceCandidateType::Host,
            "srflx" => IceCandidateType::ServerReflexive,
            "prflx" => IceCandidateType::PeerReflexive,
            "relay" => IceCandidateType::Relay,
            _ => bail!("unknown type"),
        };

        Ok(Self {
            foundation,
            priority,
            address,
            typ,
            transport,
            related_address: None,
            component,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IceCandidateType {
    Host,
    ServerReflexive,
    PeerReflexive,
    Relay,
}

impl IceCandidateType {
    fn as_str(&self) -> &'static str {
        match self {
            IceCandidateType::Host => "host",
            IceCandidateType::ServerReflexive => "srflx",
            IceCandidateType::PeerReflexive => "prflx",
            IceCandidateType::Relay => "relay",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidatePair {
    pub local: IceCandidate,
    pub remote: IceCandidate,
    pub nominated: bool,
}

impl IceCandidatePair {
    pub fn new(local: IceCandidate, remote: IceCandidate) -> Self {
        Self {
            local,
            remote,
            nominated: false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct IceParameters {
    pub username_fragment: String,
    pub password: String,
    pub ice_lite: bool,
    pub tie_breaker: u64,
}

impl IceParameters {
    pub fn new(username_fragment: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username_fragment: username_fragment.into(),
            password: password.into(),
            ice_lite: false,
            tie_breaker: random_u64(),
        }
    }

    fn generate() -> Self {
        let ufrag = hex_encode(&random_bytes::<8>());
        let pwd = hex_encode(&random_bytes::<16>());
        Self {
            username_fragment: ufrag,
            password: pwd,
            ice_lite: false,
            tie_breaker: random_u64(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct IceTransportBuilder {
    config: RtcConfiguration,
    role: IceRole,
    servers: Vec<IceServer>,
}

impl IceTransportBuilder {
    pub fn new(config: RtcConfiguration) -> Self {
        Self {
            config,
            role: IceRole::Controlled,
            servers: Vec::new(),
        }
    }

    pub fn role(mut self, role: IceRole) -> Self {
        self.role = role;
        self
    }

    pub fn server(mut self, server: IceServer) -> Self {
        self.servers.push(server);
        self
    }

    pub fn build(self) -> IceTransport {
        let mut config = self.config.clone();
        config.ice_servers.extend(self.servers);
        let transport = IceTransport::new(config);
        let task_transport = transport.clone();
        tokio::spawn(async move {
            task_transport.set_role(self.role).await;
            if let Err(err) = task_transport.start_gathering().await {
                warn!("ICE gather failed: {}", err);
            }
        });
        transport
    }
}

#[derive(Debug, Clone)]
struct IceGatherer {
    state: Arc<Mutex<IceGathererState>>,
    local_candidates: Arc<Mutex<Vec<IceCandidate>>>,
    sockets: Arc<Mutex<Vec<Arc<UdpSocket>>>>,
    turn_clients: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<TurnClient>>>>>,
    config: RtcConfiguration,
}

impl IceGatherer {
    fn new(config: RtcConfiguration) -> Self {
        Self {
            state: Arc::new(Mutex::new(IceGathererState::New)),
            local_candidates: Arc::new(Mutex::new(Vec::new())),
            sockets: Arc::new(Mutex::new(Vec::new())),
            turn_clients: Arc::new(Mutex::new(HashMap::new())),
            config,
        }
    }

    async fn state(&self) -> IceGathererState {
        *self.state.lock().await
    }

    async fn local_candidates(&self) -> Vec<IceCandidate> {
        self.local_candidates.lock().await.clone()
    }

    async fn get_socket(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        let sockets = self.sockets.lock().await;
        for socket in sockets.iter() {
            if let Ok(local) = socket.local_addr() {
                if local == addr {
                    return Some(socket.clone());
                }
                if local.ip().is_unspecified() && local.port() == addr.port() {
                    return Some(socket.clone());
                }
            }
        }
        None
    }

    #[instrument(skip(self))]
    async fn gather(&self) -> Result<()> {
        {
            let mut state = self.state.lock().await;
            if *state == IceGathererState::Complete {
                return Ok(());
            }
            *state = IceGathererState::Gathering;
        }
        let mut seen = HashSet::new();
        self.gather_host_candidates(&mut seen).await?;
        self.gather_servers(&mut seen).await?;
        *self.state.lock().await = IceGathererState::Complete;
        Ok(())
    }

    async fn gather_host_candidates(&self, seen: &mut HashSet<SocketAddr>) -> Result<()> {
        // 1. Loopback
        let loopback_ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        match UdpSocket::bind(SocketAddr::new(loopback_ip, 0)).await {
            Ok(socket) => {
                if let Ok(addr) = socket.local_addr() {
                    self.sockets.lock().await.push(Arc::new(socket));
                    self.push_candidate(IceCandidate::host(addr, 1), seen).await;
                }
            }
            Err(e) => warn!("Failed to bind loopback socket: {}", e),
        }

        // 2. LAN IP
        if let Ok(ip) = get_local_ip().await {
            if !ip.is_loopback() {
                match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
                    Ok(socket) => {
                        if let Ok(addr) = socket.local_addr() {
                            self.sockets.lock().await.push(Arc::new(socket));
                            self.push_candidate(IceCandidate::host(addr, 1), seen).await;
                        }
                    }
                    Err(e) => warn!("Failed to bind LAN socket on {}: {}", ip, e),
                }
            }
        }

        Ok(())
    }

    async fn gather_servers(&self, seen: &mut HashSet<SocketAddr>) -> Result<()> {
        for server in &self.config.ice_servers {
            for url in &server.urls {
                let uri = match IceServerUri::parse(url) {
                    Ok(uri) => uri,
                    Err(err) => {
                        warn!("invalid ICE server URI {}: {}", url, err);
                        continue;
                    }
                };
                match uri.kind {
                    IceUriKind::Stun => {
                        if let Some(candidate) = self.probe_stun(&uri).await? {
                            self.push_candidate(candidate, seen).await;
                        }
                    }
                    IceUriKind::Turn => {
                        if let Some(candidate) = self.probe_turn(&uri, server).await? {
                            self.push_candidate(candidate, seen).await;
                        }
                    }
                }
            }
        }
        Ok(())
    }

    async fn probe_stun(&self, uri: &IceServerUri) -> Result<Option<IceCandidate>> {
        let addr = uri.resolve(self.config.disable_ipv6).await?;
        let socket = match uri.transport {
            IceTransportProtocol::Udp => UdpSocket::bind("0.0.0.0:0").await?,
            IceTransportProtocol::Tcp => UdpSocket::bind("0.0.0.0:0").await?,
        };
        let local_addr = socket.local_addr()?;
        let tx_id = random_bytes::<12>();
        let message = StunMessage::binding_request(tx_id, Some("rustrtc"));
        let bytes = message.encode(None, true)?;
        socket.send_to(&bytes, addr).await?;
        let mut buf = [0u8; MAX_STUN_MESSAGE];
        let (len, from) = timeout(STUN_TIMEOUT, socket.recv_from(&mut buf)).await??;
        if from.ip() != addr.ip() {
            return Ok(None);
        }
        let parsed = StunMessage::decode(&buf[..len])?;
        if let Some(mapped) = parsed.xor_mapped_address {
            return Ok(Some(IceCandidate::server_reflexive(local_addr, mapped, 1)));
        }
        Ok(None)
    }

    async fn probe_turn(
        &self,
        uri: &IceServerUri,
        server: &IceServer,
    ) -> Result<Option<IceCandidate>> {
        let credentials = TurnCredentials::from_server(server)?;
        let client = TurnClient::connect(uri, self.config.disable_ipv6).await?;
        let allocation = client.allocate(credentials).await?;
        let relayed_addr = allocation.relayed_address;

        self.turn_clients
            .lock()
            .await
            .insert(relayed_addr, Arc::new(Mutex::new(client)));

        Ok(Some(IceCandidate::relay(
            relayed_addr,
            1,
            allocation.transport.as_str(),
        )))
    }

    async fn push_candidate(&self, candidate: IceCandidate, seen: &mut HashSet<SocketAddr>) {
        if self.config.disable_ipv6 && candidate.address.is_ipv6() {
            return;
        }
        if !seen.insert(candidate.address) {
            return;
        }
        self.local_candidates.lock().await.push(candidate);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IceServerUri {
    kind: IceUriKind,
    host: String,
    port: u16,
    transport: IceTransportProtocol,
}

impl IceServerUri {
    fn parse(input: &str) -> Result<Self> {
        let (scheme, rest) = input
            .split_once(':')
            .ok_or_else(|| anyhow!("missing scheme"))?;
        let (host_part, query) = match rest.split_once('?') {
            Some(parts) => parts,
            None => (rest, ""),
        };
        let (host, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
            let port = p.parse::<u16>().context("invalid port")?;
            (h.to_string(), port)
        } else {
            (host_part.to_string(), default_port_for_scheme(scheme)?)
        };
        let mut transport = default_transport_for_scheme(scheme)?;
        if !query.is_empty() {
            for pair in query.split('&') {
                if let Some((k, v)) = pair.split_once('=') {
                    if k == "transport" {
                        transport = match v.to_ascii_lowercase().as_str() {
                            "udp" => IceTransportProtocol::Udp,
                            "tcp" => IceTransportProtocol::Tcp,
                            other => bail!("unsupported transport {}", other),
                        };
                    }
                }
            }
        }
        if scheme.starts_with("stun") && query.contains("transport") {
            bail!("stun URI must not include transport parameter");
        }
        let kind = match scheme {
            "stun" | "stuns" => IceUriKind::Stun,
            "turn" | "turns" => IceUriKind::Turn,
            other => bail!("unsupported scheme {}", other),
        };
        Ok(Self {
            kind,
            host,
            port,
            transport,
        })
    }

    async fn resolve(&self, disable_ipv6: bool) -> Result<SocketAddr> {
        let target = format!("{}:{}", self.host, self.port);
        let addrs = lookup_host(target).await?;

        for addr in addrs {
            if disable_ipv6 && addr.is_ipv6() {
                continue;
            }
            return Ok(addr);
        }
        Err(anyhow!(
            "{} unresolved (disable_ipv6={})",
            self.host,
            disable_ipv6
        ))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceUriKind {
    Stun,
    Turn,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceTransportProtocol {
    Udp,
    Tcp,
}

impl IceTransportProtocol {
    fn as_str(&self) -> &'static str {
        match self {
            IceTransportProtocol::Udp => "udp",
            IceTransportProtocol::Tcp => "tcp",
        }
    }
}

fn default_port_for_scheme(scheme: &str) -> Result<u16> {
    Ok(match scheme {
        "stun" | "turn" => 3478,
        "stuns" | "turns" => 5349,
        other => bail!("unsupported scheme {}", other),
    })
}

fn default_transport_for_scheme(scheme: &str) -> Result<IceTransportProtocol> {
    Ok(match scheme {
        "stun" | "turn" => IceTransportProtocol::Udp,
        "stuns" | "turns" => IceTransportProtocol::Tcp,
        other => bail!("unsupported scheme {}", other),
    })
}

#[derive(Debug, Clone)]
struct TurnCredentials {
    username: String,
    password: String,
}

impl TurnCredentials {
    fn from_server(server: &IceServer) -> Result<Self> {
        if server.credential_type != IceCredentialType::Password {
            bail!("only password credentials supported for TURN");
        }
        let username = server
            .username
            .clone()
            .ok_or_else(|| anyhow!("TURN server missing username"))?;
        let password = server
            .credential
            .clone()
            .ok_or_else(|| anyhow!("TURN server missing credential"))?;
        Ok(Self { username, password })
    }
}

use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

#[derive(Debug)]
pub struct TurnClient {
    transport: TurnTransport,
    auth: Mutex<Option<TurnAuthState>>,
}

#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct TurnAuthState {
    username: String,
    password: String,
    realm: String,
    nonce: String,
    key: Vec<u8>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl TurnAuthState {
    fn with_key(
        username: String,
        password: String,
        realm: String,
        nonce: String,
        key: Vec<u8>,
    ) -> Self {
        Self {
            username,
            password,
            realm,
            nonce,
            key,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn update_nonce(&mut self, realm: String, nonce: String) {
        self.realm = realm;
        self.nonce = nonce;
        self.key = long_term_key(&self.username, &self.realm, &self.password);
    }
}

impl TurnClient {
    async fn connect(uri: &IceServerUri, disable_ipv6: bool) -> Result<Self> {
        let addr = uri.resolve(disable_ipv6).await?;
        let transport = match uri.transport {
            IceTransportProtocol::Udp => {
                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                TurnTransport::Udp {
                    socket,
                    server: addr,
                }
            }
            IceTransportProtocol::Tcp => {
                let stream = TcpStream::connect(addr).await?;
                let (read, write) = stream.into_split();
                TurnTransport::Tcp {
                    read: Arc::new(Mutex::new(read)),
                    write: Arc::new(Mutex::new(write)),
                }
            }
        };
        Ok(Self {
            transport,
            auth: Mutex::new(None),
        })
    }

    async fn allocate(&self, creds: TurnCredentials) -> Result<TurnAllocation> {
        *self.auth.lock().await = None;
        let mut nonce_info: Option<TurnNonce> = None;
        let mut attempt = 0;
        loop {
            attempt += 1;
            if attempt > 3 {
                bail!("TURN allocation failed after retries");
            }
            let tx_id = random_bytes::<12>();
            let attrs = vec![
                StunAttribute::RequestedTransport(17),
                StunAttribute::Lifetime(DEFAULT_TURN_LIFETIME),
            ];
            let (message, key_option) = if let Some(info) = &nonce_info {
                let key = long_term_key(&creds.username, &info.realm, &creds.password);
                let mut extended = attrs.clone();
                extended.push(StunAttribute::Username(creds.username.clone()));
                extended.push(StunAttribute::Realm(info.realm.clone()));
                extended.push(StunAttribute::Nonce(info.nonce.clone()));
                let msg = StunMessage::allocate_request(tx_id, extended);
                (msg, Some(key))
            } else {
                (StunMessage::allocate_request(tx_id, attrs.clone()), None)
            };
            let used_key = key_option.clone();
            let bytes = message.encode(key_option.as_deref(), true)?;
            self.send(&bytes).await?;
            let mut buf = [0u8; MAX_STUN_MESSAGE];
            let len = self.recv(&mut buf).await?;
            let parsed = StunMessage::decode(&buf[..len])?;
            if parsed.transaction_id != tx_id {
                continue;
            }
            if parsed.method != StunMethod::Allocate {
                bail!("unexpected STUN method in allocate response");
            }
            match parsed.class {
                StunClass::SuccessResponse => {
                    if let Some(relayed) = parsed.xor_relayed_address {
                        if let (Some(info), Some(key)) = (nonce_info.clone(), used_key) {
                            *self.auth.lock().await = Some(TurnAuthState::with_key(
                                creds.username.clone(),
                                creds.password.clone(),
                                info.realm,
                                info.nonce,
                                key,
                            ));
                        }
                        return Ok(TurnAllocation {
                            relayed_address: relayed,
                            transport: self.transport.protocol(),
                        });
                    }
                    bail!("TURN success without relayed address");
                }
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed
                            .realm
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing realm"))?;
                        let nonce = parsed
                            .nonce
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing nonce"))?;
                        nonce_info = Some(TurnNonce { realm, nonce });
                        continue;
                    }
                    bail!("TURN allocate error {}", parsed.error_code.unwrap_or(0));
                }
                _ => bail!("unexpected TURN response class"),
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    async fn create_permission(&self, peer: SocketAddr) -> Result<()> {
        const MAX_ATTEMPTS: usize = 3;
        for _ in 0..MAX_ATTEMPTS {
            let tx_id = random_bytes::<12>();
            let bytes = {
                let auth_guard = self.auth.lock().await;
                let auth = auth_guard
                    .as_ref()
                    .ok_or_else(|| anyhow!("TURN allocation missing auth context"))?;
                let mut attributes = vec![StunAttribute::Username(auth.username.clone())];
                attributes.push(StunAttribute::Realm(auth.realm.clone()));
                attributes.push(StunAttribute::Nonce(auth.nonce.clone()));
                attributes.push(StunAttribute::XorPeerAddress(peer));
                let msg = StunMessage {
                    class: StunClass::Request,
                    method: StunMethod::CreatePermission,
                    transaction_id: tx_id,
                    attributes,
                };
                msg.encode(Some(&auth.key), true)?
            };
            self.send(&bytes).await?;
            let mut buf = [0u8; MAX_STUN_MESSAGE];
            let len = self.recv(&mut buf).await?;
            let parsed = StunMessage::decode(&buf[..len])?;
            if parsed.transaction_id != tx_id {
                continue;
            }
            if parsed.method != StunMethod::CreatePermission {
                bail!("unexpected STUN method in create-permission response");
            }
            match parsed.class {
                StunClass::SuccessResponse => return Ok(()),
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed
                            .realm
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing realm"))?;
                        let nonce = parsed
                            .nonce
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing nonce"))?;
                        if let Some(state) = self.auth.lock().await.as_mut() {
                            state.update_nonce(realm, nonce);
                        }
                        continue;
                    }
                    bail!(
                        "TURN create-permission error {}",
                        parsed.error_code.unwrap_or(0)
                    );
                }
                _ => bail!("unexpected TURN response class"),
            }
        }
        bail!("TURN create-permission failed after retries");
    }

    pub(crate) async fn send(&self, data: &[u8]) -> Result<()> {
        match &self.transport {
            TurnTransport::Udp { socket, server } => {
                socket.send_to(data, *server).await?;
            }
            TurnTransport::Tcp { write, .. } => {
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(data);
                write.lock().await.write_all(&frame).await?;
            }
        }
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match &self.transport {
            TurnTransport::Udp { socket, .. } => {
                let (len, _) = timeout(STUN_TIMEOUT, socket.recv_from(buf)).await??;
                Ok(len)
            }
            TurnTransport::Tcp { read, .. } => {
                let mut header = [0u8; 2];
                let mut stream = read.lock().await;
                stream.read_exact(&mut header).await?;
                let len = u16::from_be_bytes(header) as usize;
                let mut offset = 0;
                while offset < len {
                    let read = stream.read(&mut buf[offset..len]).await?;
                    if read == 0 {
                        bail!("TURN TCP stream closed");
                    }
                    offset += read;
                }
                Ok(len)
            }
        }
    }

    async fn send_indication(&self, peer: SocketAddr, data: &[u8]) -> Result<()> {
        let tx_id = random_bytes::<12>();
        let mut attributes = vec![StunAttribute::XorPeerAddress(peer)];
        attributes.push(StunAttribute::Data(data.to_vec()));

        let msg = StunMessage {
            class: StunClass::Indication,
            method: StunMethod::Send,
            transaction_id: tx_id,
            attributes,
        };

        let bytes = {
            let auth_guard = self.auth.lock().await;
            if let Some(auth) = auth_guard.as_ref() {
                let mut authenticated_msg = msg.clone();
                authenticated_msg
                    .attributes
                    .insert(0, StunAttribute::Username(auth.username.clone()));
                authenticated_msg
                    .attributes
                    .insert(1, StunAttribute::Realm(auth.realm.clone()));
                authenticated_msg
                    .attributes
                    .insert(2, StunAttribute::Nonce(auth.nonce.clone()));
                authenticated_msg.encode(Some(&auth.key), true)?
            } else {
                msg.encode(None, false)?
            }
        };

        self.send(&bytes).await
    }

    async fn create_permission_packet(&self, peer: SocketAddr) -> Result<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock().await;
        let auth = auth_guard.as_ref().ok_or_else(|| anyhow!("no auth"))?;

        let mut attributes = vec![StunAttribute::Username(auth.username.clone())];
        attributes.push(StunAttribute::Realm(auth.realm.clone()));
        attributes.push(StunAttribute::Nonce(auth.nonce.clone()));
        attributes.push(StunAttribute::XorPeerAddress(peer));

        let msg = StunMessage {
            class: StunClass::Request,
            method: StunMethod::CreatePermission,
            transaction_id: tx_id,
            attributes,
        };
        let bytes = msg.encode(Some(&auth.key), true)?;
        Ok((bytes, tx_id))
    }
}

#[derive(Clone)]
struct TurnNonce {
    realm: String,
    nonce: String,
}

#[derive(Clone)]
struct TurnAllocation {
    relayed_address: SocketAddr,
    transport: IceTransportProtocol,
}

impl TurnTransport {
    fn protocol(&self) -> IceTransportProtocol {
        match self {
            TurnTransport::Udp { .. } => IceTransportProtocol::Udp,
            TurnTransport::Tcp { .. } => IceTransportProtocol::Tcp,
        }
    }
}

#[derive(Debug, Clone)]
enum TurnTransport {
    Udp {
        socket: Arc<UdpSocket>,
        server: SocketAddr,
    },
    Tcp {
        read: Arc<Mutex<OwnedReadHalf>>,
        write: Arc<Mutex<OwnedWriteHalf>>,
    },
}

fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{}:{}:{}", username, realm, password);
    md5_digest(input.as_bytes()).to_vec()
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input);
    let result = Md5Digest::finalize(hasher);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}

fn hex_encode(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

async fn get_local_ip() -> Result<IpAddr> {
    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    socket.connect("8.8.8.8:80").await?;
    Ok(socket.local_addr()?.ip())
}

#[derive(Debug, Clone)]
pub enum IceSocketWrapper {
    Udp(Arc<UdpSocket>),
    Turn(Arc<Mutex<TurnClient>>),
}

impl IceSocketWrapper {
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        match self {
            IceSocketWrapper::Udp(s) => s.send_to(data, addr).await.map_err(|e| e.into()),
            IceSocketWrapper::Turn(c) => {
                c.lock().await.send_indication(addr, data).await?;
                Ok(data.len())
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match self {
            IceSocketWrapper::Udp(s) => s.recv_from(buf).await.map_err(|e| e.into()),
            IceSocketWrapper::Turn(_) => Err(anyhow::anyhow!(
                "recv_from not supported on TURN wrapper directly"
            )),
        }
    }
}
