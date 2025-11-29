pub mod conn;
pub mod stun;
#[cfg(test)]
mod tests;
pub mod turn;

use crate::transports::PacketReceiver;
use crate::transports::ice::turn::{TurnClient, TurnCredentials};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use tokio::time::timeout;
use tracing::{debug, instrument, trace, warn};

use self::stun::{
    StunAttribute, StunClass, StunDecoded, StunMessage, StunMethod, random_bytes, random_u64,
};
use crate::{IceServer, IceTransportPolicy, RtcConfiguration};

pub(crate) const STUN_TIMEOUT: Duration = Duration::from_secs(3);
pub(crate) const MAX_STUN_MESSAGE: usize = 1500;

#[derive(Debug)]
enum IceCommand {
    StartGathering,
    RunChecks,
}

#[derive(Debug, Clone)]
pub struct IceTransport {
    inner: Arc<IceTransportInner>,
}

struct IceTransportInner {
    state: watch::Sender<IceTransportState>,
    gathering_state: watch::Sender<IceGathererState>,
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
    buffered_packets: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    selected_socket: watch::Sender<Option<IceSocketWrapper>>,
    _socket_rx_keeper: watch::Receiver<Option<IceSocketWrapper>>,
    last_received: Mutex<Instant>,
    candidate_tx: broadcast::Sender<IceCandidate>,
    cmd_tx: mpsc::UnboundedSender<IceCommand>,
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
            .field("buffered_packets", &self.buffered_packets)
            .field("selected_socket", &self.selected_socket)
            .field("candidate_tx", &self.candidate_tx)
            .field("cmd_tx", &self.cmd_tx)
            .finish()
    }
}

struct IceTransportRunner {
    inner: Arc<IceTransportInner>,
    socket_rx: mpsc::UnboundedReceiver<IceSocketWrapper>,
    candidate_rx: broadcast::Receiver<IceCandidate>,
    cmd_rx: mpsc::UnboundedReceiver<IceCommand>,
}

impl IceTransportRunner {
    async fn run(mut self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        let mut read_futures: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let mut check_futures: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();

        loop {
            tokio::select! {
                Some(socket) = self.socket_rx.recv() => {
                    match socket {
                        IceSocketWrapper::Udp(s) => {
                            read_futures.push(Box::pin(Self::run_udp_read_loop(s, self.inner.clone())));
                        }
                        IceSocketWrapper::Turn(c, addr) => {
                            read_futures.push(Box::pin(Self::run_turn_read_loop(c, addr, self.inner.clone())));
                        }
                    }
                }
                res = self.candidate_rx.recv() => {
                    match res {
                        Ok(_) => {
                             let inner = self.inner.clone();
                             check_futures.push(Box::pin(async move {
                                 perform_connectivity_checks_async(inner).await;
                             }));
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
                Some(cmd) = self.cmd_rx.recv() => {
                    match cmd {
                        IceCommand::StartGathering => {
                            let inner = self.inner.clone();
                            check_futures.push(Box::pin(async move {
                                if let Err(e) = inner.gatherer.gather().await {
                                    warn!("Gathering failed: {}", e);
                                }
                                {
                                    let mut buffer = inner.local_candidates.lock().await;
                                    *buffer = inner.gatherer.local_candidates().await;
                                }
                                *inner.gather_state.lock().await = IceGathererState::Complete;
                                let _ = inner.gathering_state.send(IceGathererState::Complete);
                            }));
                        }
                        IceCommand::RunChecks => {
                             let inner = self.inner.clone();
                             check_futures.push(Box::pin(async move {
                                 perform_connectivity_checks_async(inner).await;
                             }));
                        }
                    }
                }
                _ = interval.tick() => {
                    Self::run_keepalive_tick(&self.inner).await;
                }
                Some(_) = read_futures.next() => {
                    // Read loop finished
                }
                Some(_) = check_futures.next() => {
                    // Check finished
                }
            }
        }
    }

    async fn run_udp_read_loop(socket: Arc<UdpSocket>, inner: Arc<IceTransportInner>) {
        let mut buf = [0u8; 1500];
        let mut state_rx = inner.state.subscribe();
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
                        handle_packet(
                            packet,
                            addr,
                            inner.clone(),
                            IceSocketWrapper::Udp(socket.clone()),
                        )
                        .await;
                    }
                }
                res = state_rx.changed() => {
                    if res.is_err() || *state_rx.borrow() == IceTransportState::Closed {
                        debug!("Read loop stopping (IceTransport Closed)");
                        break;
                    }
                }
            }
        }
    }

    async fn run_turn_read_loop(
        client: Arc<Mutex<TurnClient>>,
        relayed_addr: SocketAddr,
        inner: Arc<IceTransportInner>,
    ) {
        let mut buf = [0u8; 1500];
        let mut state_rx = inner.state.subscribe();
        trace!("Read loop started for TURN client {}", relayed_addr);
        loop {
            let recv_future = async {
                let client_lock = client.lock().await;
                let result = client_lock.recv(&mut buf).await;
                drop(client_lock);
                result
            };

            tokio::select! {
                result = recv_future => {
                    match result {
                        Ok(len) => {
                            if len > 0 {
                                IceTransport::handle_turn_packet(&buf[..len], &inner, &client, relayed_addr).await;
                            }
                        }
                        Err(e) => {
                            warn!("TURN client recv error: {}", e);
                            break;
                        }
                    }
                }
                res = state_rx.changed() => {
                    if res.is_err() || *state_rx.borrow() == IceTransportState::Closed {
                        debug!("TURN Read loop stopping (IceTransport Closed)");
                        break;
                    }
                }
            }
        }
    }

    async fn run_keepalive_tick(inner: &Arc<IceTransportInner>) {
        let state = *inner.state.borrow();
        if state == IceTransportState::Connected || state == IceTransportState::Disconnected {
            let last = *inner.last_received.lock().await;
            let elapsed = last.elapsed();
            if elapsed > Duration::from_secs(30) {
                let _ = inner.state.send(IceTransportState::Failed);
            } else if elapsed > Duration::from_secs(5) {
                if state != IceTransportState::Disconnected {
                    let _ = inner.state.send(IceTransportState::Disconnected);
                }
            } else if state == IceTransportState::Disconnected {
                let _ = inner.state.send(IceTransportState::Connected);
            }

            // Send Keepalive
            if let Some(pair) = inner.selected_pair.lock().await.clone() {
                if let Some(socket) = resolve_socket(inner, &pair).await {
                    let tx_id = random_bytes::<12>();
                    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));

                    let remote_params = inner.remote_parameters.lock().await.clone();
                    if let Some(params) = remote_params {
                        let username = format!(
                            "{}:{}",
                            params.username_fragment,
                            inner.local_parameters.lock().await.username_fragment
                        );
                        msg.attributes.push(StunAttribute::Username(username));
                        msg.attributes
                            .push(StunAttribute::Priority(pair.local.priority));

                        if let Ok(bytes) = msg.encode(Some(params.password.as_bytes()), true) {
                            let _ = socket.send_to(&bytes, pair.remote.address).await;
                        }
                    } else if inner.config.transport_mode != crate::TransportMode::WebRtc {
                        if let Ok(bytes) = msg.encode(None, false) {
                            let _ = socket.send_to(&bytes, pair.remote.address).await;
                        }
                    }
                }
            }
        }
    }
}

impl IceTransport {
    pub fn new(config: RtcConfiguration) -> (Self, impl std::future::Future<Output = ()> + Send) {
        let (candidate_tx, _) = broadcast::channel(100);
        let (socket_tx, socket_rx) = tokio::sync::mpsc::unbounded_channel();
        let gatherer = IceGatherer::new(config.clone(), candidate_tx.clone(), socket_tx);
        let (state_tx, _) = watch::channel(IceTransportState::New);
        let (gathering_state_tx, _) = watch::channel(IceGathererState::New);
        let (selected_socket_tx, selected_socket_rx) = watch::channel(None);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let inner = IceTransportInner {
            state: state_tx,
            gathering_state: gathering_state_tx,
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
            buffered_packets: Mutex::new(Vec::new()),
            selected_socket: selected_socket_tx,
            _socket_rx_keeper: selected_socket_rx,
            last_received: Mutex::new(Instant::now()),
            candidate_tx: candidate_tx.clone(),
            cmd_tx,
        };
        let inner = Arc::new(inner);

        let runner = IceTransportRunner {
            inner: inner.clone(),
            socket_rx,
            candidate_rx: candidate_tx.subscribe(),
            cmd_rx,
        };

        (Self { inner }, runner.run())
    }

    pub fn state(&self) -> IceTransportState {
        *self.inner.state.borrow()
    }

    pub fn subscribe_state(&self) -> watch::Receiver<IceTransportState> {
        self.inner.state.subscribe()
    }

    pub fn subscribe_gathering_state(&self) -> watch::Receiver<IceGathererState> {
        self.inner.gathering_state.subscribe()
    }

    pub fn subscribe_candidates(&self) -> broadcast::Receiver<IceCandidate> {
        self.inner.candidate_tx.subscribe()
    }

    pub fn subscribe_selected_socket(&self) -> watch::Receiver<Option<IceSocketWrapper>> {
        self.inner.selected_socket.subscribe()
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

    fn start_keepalive(&self) {
        // Handled by runner
    }

    pub async fn start_gathering(&self) -> Result<()> {
        {
            let mut state = self.inner.gather_state.lock().await;
            if *state == IceGathererState::Complete || *state == IceGathererState::Gathering {
                return Ok(());
            }
            *state = IceGathererState::Gathering;
            let _ = self.inner.gathering_state.send(IceGathererState::Gathering);
        }

        let _ = self.inner.cmd_tx.send(IceCommand::StartGathering);
        Ok(())
    }

    pub async fn start(&self, remote: IceParameters) -> Result<()> {
        self.start_gathering().await?;
        self.start_keepalive();
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
        self.start_keepalive();

        // Wait for at least one local candidate
        let mut rx = self.subscribe_candidates();
        let local = if let Some(first) = self.inner.gatherer.local_candidates().await.first() {
            first.clone()
        } else {
            // Wait for one
            match timeout(Duration::from_secs(2), rx.recv()).await {
                Ok(Ok(c)) => c,
                _ => bail!("No local candidates gathered for direct connection"),
            }
        };

        let remote = IceCandidate::host(remote_addr, 1);
        let pair = IceCandidatePair::new(local, remote);

        *self.inner.selected_pair.lock().await = Some(pair.clone());
        if let Some(socket) = resolve_socket(&self.inner, &pair).await {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
        let _ = self.inner.state.send(IceTransportState::Connected);
        Ok(())
    }

    pub fn stop(&self) {
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
        if let Some(socket) = resolve_socket(&self.inner, &pair).await {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
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
                .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
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
        let mut rx_lock = self.inner.data_receiver.lock().await;
        *rx_lock = Some(receiver.clone());
        drop(rx_lock);

        let mut buffer = self.inner.buffered_packets.lock().await;
        if !buffer.is_empty() {
            debug!("Flushing {} buffered packets", buffer.len());
            for (packet, addr) in buffer.drain(..) {
                receiver.receive(Bytes::from(packet), addr).await;
            }
        }
    }

    fn try_connectivity_checks(&self) {
        let _ = self.inner.cmd_tx.send(IceCommand::RunChecks);
    }

    async fn handle_turn_packet(
        packet: &[u8],
        inner: &Arc<IceTransportInner>,
        client: &Arc<Mutex<TurnClient>>,
        relayed_addr: SocketAddr,
    ) {
        if let Ok(msg) = StunMessage::decode(packet)
            && msg.class == StunClass::Indication
            && msg.method == StunMethod::Data
            && let Some(data) = &msg.data
            && let Some(peer_addr) = msg.xor_peer_address
        {
            handle_packet(
                data,
                peer_addr,
                inner.clone(),
                IceSocketWrapper::Turn(client.clone(), relayed_addr),
            )
            .await;
        }
    }
}

async fn perform_connectivity_checks_async(inner: Arc<IceTransportInner>) {
    let state = *inner.state.borrow();
    if state != IceTransportState::Checking {
        trace!("try_connectivity_checks: state is {:?}, skipping", state);
        return;
    }
    let locals = inner.gatherer.local_candidates().await;
    let remotes = inner.remote_candidates.lock().await.clone();
    let role = *inner.role.lock().await;

    if locals.is_empty() || remotes.is_empty() {
        return;
    }

    let mut pairs = Vec::new();

    for local in &locals {
        for remote in &remotes {
            if local.transport != remote.transport {
                trace!(
                    "Skipping pair due to transport mismatch: {} != {}",
                    local.transport, remote.transport
                );
                continue;
            }
            pairs.push(IceCandidatePair::new(local.clone(), remote.clone()));
        }
    }

    // Sort by priority
    pairs.sort_by(|a, b| b.priority(role).cmp(&a.priority(role)));

    let mut checks = futures::stream::FuturesUnordered::new();

    for pair in pairs {
        let inner = inner.clone();
        let local = pair.local.clone();
        let remote = pair.remote.clone();

        checks.push(async move {
            match perform_binding_check(&local, &remote, &inner, role).await {
                Ok(_) => Some(IceCandidatePair::new(local, remote)),
                Err(_) => None,
            }
        });
    }

    if checks.is_empty() {
        return;
    }

    use futures::stream::StreamExt;
    let mut success = false;
    while let Some(res) = checks.next().await {
        if let Some(pair) = res {
            *inner.selected_pair.lock().await = Some(pair.clone());
            if let Some(socket) = resolve_socket(&inner, &pair).await {
                let _ = inner.selected_socket.send(Some(socket));
            }
            let _ = inner.state.send(IceTransportState::Connected);
            success = true;
            break;
        }
    }

    if !success {
        let _ = inner.state.send(IceTransportState::Failed);
    }
}

async fn resolve_socket(
    inner: &IceTransportInner,
    pair: &IceCandidatePair,
) -> Option<IceSocketWrapper> {
    if pair.local.typ == IceCandidateType::Relay {
        let clients = inner.gatherer.turn_clients.lock().await;
        clients
            .get(&pair.local.address)
            .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
    } else {
        let socket = inner.gatherer.get_socket(pair.local.address).await;
        if socket.is_none() {
            warn!(
                "resolve_socket: failed to find socket for {}",
                pair.local.address
            );
        }
        socket.map(IceSocketWrapper::Udp)
    }
}

async fn handle_packet(
    packet: &[u8],
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
    sender: IceSocketWrapper,
) {
    {
        let mut last = inner.last_received.lock().await;
        *last = Instant::now();
    }
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
                    warn!(
                        "Received STUN Error Response from {}: {:?}",
                        addr, msg.error_code
                    );
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
        let receiver = inner.data_receiver.lock().await.clone();
        if let Some(rx) = receiver {
            rx.receive(Bytes::copy_from_slice(packet), addr).await;
        } else {
            let mut buffer = inner.buffered_packets.lock().await;
            if buffer.len() < 100 {
                buffer.push((packet.to_vec(), addr));
            } else {
                warn!("Buffer full, dropping packet from {}", addr);
            }
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

        let _ = inner.cmd_tx.send(IceCommand::RunChecks);
    }

    if msg.use_candidate {
        let role = *inner.role.lock().await;
        if role == IceRole::Controlled {
            let local_addr = match sender {
                IceSocketWrapper::Udp(s) => s
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                IceSocketWrapper::Turn(_, addr) => *addr,
            };

            let locals = inner.gatherer.local_candidates().await;
            let local_cand = locals.iter().find(|c| c.address == local_addr);

            let remotes = inner.remote_candidates.lock().await;
            let remote_cand = remotes.iter().find(|c| c.address == addr);

            if let (Some(l), Some(r)) = (local_cand, remote_cand) {
                let pair = IceCandidatePair::new(l.clone(), r.clone());
                trace!(
                    "Controlled agent selected pair via UseCandidate: {} -> {}",
                    l.address, r.address
                );
                *inner.selected_pair.lock().await = Some(pair.clone());
                if let Some(socket) = resolve_socket(&inner, &pair).await {
                    let _ = inner.selected_socket.send(Some(socket));
                }
                let _ = inner.state.send(IceTransportState::Connected);
            } else {
                warn!(
                    "Received UseCandidate but could not find pair for {} -> {}",
                    local_addr, addr
                );
            }
        }
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

    pub fn priority(&self, role: IceRole) -> u64 {
        let g = self.local.priority as u64;
        let d = self.remote.priority as u64;
        let (g, d) = match role {
            IceRole::Controlling => (g, d),
            IceRole::Controlled => (d, g),
        };
        (1u64 << 32) * std::cmp::min(g, d) + 2 * std::cmp::max(g, d) + if g > d { 1 } else { 0 }
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

    pub fn build(self) -> (IceTransport, impl std::future::Future<Output = ()> + Send) {
        let mut config = self.config.clone();
        config.ice_servers.extend(self.servers);
        let (transport, runner) = IceTransport::new(config);
        let task_transport = transport.clone();
        tokio::spawn(async move {
            task_transport.set_role(self.role).await;
            if let Err(err) = task_transport.start_gathering().await {
                warn!("ICE gather failed: {}", err);
            }
        });
        (transport, runner)
    }
}

#[derive(Debug, Clone)]
struct IceGatherer {
    state: Arc<Mutex<IceGathererState>>,
    local_candidates: Arc<Mutex<Vec<IceCandidate>>>,
    sockets: Arc<Mutex<Vec<Arc<UdpSocket>>>>,
    turn_clients: Arc<Mutex<HashMap<SocketAddr, Arc<Mutex<TurnClient>>>>>,
    config: RtcConfiguration,
    candidate_tx: broadcast::Sender<IceCandidate>,
    socket_tx: tokio::sync::mpsc::UnboundedSender<IceSocketWrapper>,
}

impl IceGatherer {
    fn new(
        config: RtcConfiguration,
        candidate_tx: broadcast::Sender<IceCandidate>,
        socket_tx: tokio::sync::mpsc::UnboundedSender<IceSocketWrapper>,
    ) -> Self {
        Self {
            state: Arc::new(Mutex::new(IceGathererState::New)),
            local_candidates: Arc::new(Mutex::new(Vec::new())),
            sockets: Arc::new(Mutex::new(Vec::new())),
            turn_clients: Arc::new(Mutex::new(HashMap::new())),
            config,
            candidate_tx,
            socket_tx,
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
        // Avoid unwrap in logging to prevent panic hiding
        let available: Vec<String> = sockets
            .iter()
            .map(|s| {
                s.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "error".to_string())
            })
            .collect();
        warn!(
            "get_socket: no socket found for {}, available: {:?}",
            addr, available
        );
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
        if self.config.ice_transport_policy == IceTransportPolicy::All {
            self.gather_host_candidates(&mut seen).await?;
        }
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
                    let socket = Arc::new(socket);
                    self.sockets.lock().await.push(socket.clone());
                    let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));
                    self.push_candidate(IceCandidate::host(addr, 1), seen).await;
                }
            }
            Err(e) => warn!("Failed to bind loopback socket: {}", e),
        }

        // 2. LAN IP
        if let Ok(ip) = get_local_ip().await
            && !ip.is_loopback()
        {
            match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
                Ok(socket) => {
                    if let Ok(addr) = socket.local_addr() {
                        let socket = Arc::new(socket);
                        self.sockets.lock().await.push(socket.clone());
                        let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));
                        self.push_candidate(IceCandidate::host(addr, 1), seen).await;
                    }
                }
                Err(e) => warn!("Failed to bind LAN socket on {}: {}", ip, e),
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
                        if self.config.ice_transport_policy == IceTransportPolicy::All {
                            if let Some(candidate) = self.probe_stun(&uri).await? {
                                self.push_candidate(candidate, seen).await;
                            }
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

        let client = Arc::new(Mutex::new(client));
        self.turn_clients
            .lock()
            .await
            .insert(relayed_addr, client.clone());
        let _ = self
            .socket_tx
            .send(IceSocketWrapper::Turn(client, relayed_addr));

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
        self.local_candidates.lock().await.push(candidate.clone());
        let _ = self.candidate_tx.send(candidate);
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IceServerUri {
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
                if let Some((k, v)) = pair.split_once('=')
                    && k == "transport"
                {
                    transport = match v.to_ascii_lowercase().as_str() {
                        "udp" => IceTransportProtocol::Udp,
                        "tcp" => IceTransportProtocol::Tcp,
                        other => bail!("unsupported transport {}", other),
                    };
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
pub(crate) enum IceTransportProtocol {
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
    Turn(Arc<Mutex<TurnClient>>, SocketAddr),
}

impl IceSocketWrapper {
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        match self {
            IceSocketWrapper::Udp(s) => s.send_to(data, addr).await.map_err(|e| e.into()),
            IceSocketWrapper::Turn(c, _) => {
                c.lock().await.send_indication(addr, data).await?;
                Ok(data.len())
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        match self {
            IceSocketWrapper::Udp(s) => s.recv_from(buf).await.map_err(|e| e.into()),
            IceSocketWrapper::Turn(_, _) => Err(anyhow::anyhow!(
                "recv_from not supported on TURN wrapper directly"
            )),
        }
    }
}
