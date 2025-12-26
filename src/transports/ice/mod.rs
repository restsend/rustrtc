pub mod conn;
pub mod stun;
#[cfg(test)]
mod tests;
pub mod turn;

use crate::transports::ice::turn::{TurnClient, TurnCredentials};
use crate::transports::{PacketReceiver, get_local_ip};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
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
    _state_rx_keeper: watch::Receiver<IceTransportState>,
    gathering_state: watch::Sender<IceGathererState>,
    role: std::sync::Mutex<IceRole>,
    selected_pair: std::sync::Mutex<Option<IceCandidatePair>>,
    local_candidates: Mutex<Vec<IceCandidate>>,
    remote_candidates: std::sync::Mutex<Vec<IceCandidate>>,
    gather_state: std::sync::Mutex<IceGathererState>,
    config: RtcConfiguration,
    gatherer: IceGatherer,
    local_parameters: std::sync::Mutex<IceParameters>,
    remote_parameters: std::sync::Mutex<Option<IceParameters>>,
    pending_transactions: std::sync::Mutex<HashMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    data_receiver: std::sync::Mutex<Option<Arc<dyn PacketReceiver>>>,
    buffered_packets: std::sync::Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    selected_socket: watch::Sender<Option<IceSocketWrapper>>,
    _socket_rx_keeper: watch::Receiver<Option<IceSocketWrapper>>,
    selected_pair_notifier: watch::Sender<Option<IceCandidatePair>>,
    _selected_pair_rx_keeper: watch::Receiver<Option<IceCandidatePair>>,
    last_received: std::sync::Mutex<Instant>,
    candidate_tx: broadcast::Sender<IceCandidate>,
    cmd_tx: mpsc::UnboundedSender<IceCommand>,
    checking_pairs: Mutex<std::collections::HashSet<(SocketAddr, SocketAddr)>>,
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
            .field("selected_pair_notifier", &self.selected_pair_notifier)
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
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        let mut read_futures: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let mut gathering_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());

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
                             tokio::spawn(async move {
                                 perform_connectivity_checks_async(inner).await;
                             });
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                        Err(broadcast::error::RecvError::Lagged(_)) => continue,
                    }
                }
                Some(cmd) = self.cmd_rx.recv() => {
                    trace!("Runner received command: {:?}", cmd);
                    match cmd {
                        IceCommand::StartGathering => {
                            let inner = self.inner.clone();
                            gathering_future = Box::pin(async move {
                                if let Err(e) = inner.gatherer.gather().await {
                                    warn!("Gathering failed: {}", e);
                                }
                                {
                                    let mut buffer = inner.local_candidates.lock().await;
                                    *buffer = inner.gatherer.local_candidates();
                                }
                                *inner.gather_state.lock().unwrap() = IceGathererState::Complete;
                                let _ = inner.gathering_state.send(IceGathererState::Complete);
                            });
                        }
                        IceCommand::RunChecks => {
                             let inner = self.inner.clone();
                             tokio::spawn(async move {
                                 perform_connectivity_checks_async(inner).await;
                             });
                        }
                    }
                }
                _ = interval.tick() => {
                    Self::run_keepalive_tick(&self.inner).await;
                }
                Some(_) = read_futures.next() => {
                    // Read loop finished
                }
                _ = &mut gathering_future => {
                    gathering_future = Box::pin(futures::future::pending());
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
        client: Arc<TurnClient>,
        relayed_addr: SocketAddr,
        inner: Arc<IceTransportInner>,
    ) {
        let mut buf = [0u8; 1500];
        let mut state_rx = inner.state.subscribe();
        trace!("Read loop started for TURN client {}", relayed_addr);
        loop {
            let recv_future = async { client.recv(&mut buf).await };

            tokio::select! {
                result = recv_future => {
                    match result {
                        Ok(len) => {
                            if len > 0 {
                                IceTransport::handle_turn_packet(&buf[..len], &inner, &client, relayed_addr).await;
                            }
                        }
                        Err(e) => {
                            if e.to_string().contains("deadline has elapsed") {
                                continue;
                            }
                            debug!("TURN client recv error: {}", e);
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
            let elapsed = inner.last_received.lock().unwrap().elapsed();
            let ice_conn_timeout = inner.config.ice_connection_timeout;
            if elapsed > ice_conn_timeout {
                let _ = inner.state.send(IceTransportState::Failed);
            } else if elapsed > Duration::from_secs(5) {
                if state != IceTransportState::Disconnected {
                    let _ = inner.state.send(IceTransportState::Disconnected);
                }
            } else if state == IceTransportState::Disconnected {
                let _ = inner.state.send(IceTransportState::Connected);
            }

            // Send Keepalive
            let pair_opt = inner.selected_pair.lock().unwrap().clone();
            if let Some(pair) = pair_opt {
                if let Some(socket) = resolve_socket(inner, &pair) {
                    let tx_id = random_bytes::<12>();
                    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));

                    let remote_params = inner.remote_parameters.lock().unwrap().clone();
                    if let Some(params) = remote_params {
                        let username = format!(
                            "{}:{}",
                            params.username_fragment,
                            inner.local_parameters.lock().unwrap().username_fragment
                        );
                        msg.attributes.push(StunAttribute::Username(username));
                        msg.attributes
                            .push(StunAttribute::Priority(pair.local.priority));

                        if let Ok(bytes) = msg.encode(Some(params.password.as_bytes()), true) {
                            // Register transaction to avoid "Unmatched transaction" logs
                            let (tx, rx) = oneshot::channel();
                            {
                                let mut map = inner.pending_transactions.lock().unwrap();
                                map.insert(tx_id, tx);
                            }

                            let inner_weak = Arc::downgrade(inner);
                            tokio::spawn(async move {
                                let _ = timeout(Duration::from_secs(5), rx).await;
                                if let Some(inner) = inner_weak.upgrade() {
                                    let mut map = inner.pending_transactions.lock().unwrap();
                                    map.remove(&tx_id);
                                }
                            });

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
        let (state_tx, state_rx) = watch::channel(IceTransportState::New);
        let (gathering_state_tx, _) = watch::channel(IceGathererState::New);
        let (selected_socket_tx, selected_socket_rx) = watch::channel(None);
        let (selected_pair_tx, selected_pair_rx) = watch::channel(None);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();

        let inner = IceTransportInner {
            state: state_tx,
            _state_rx_keeper: state_rx,
            gathering_state: gathering_state_tx,
            role: std::sync::Mutex::new(IceRole::Controlled),
            selected_pair: std::sync::Mutex::new(None),
            local_candidates: Mutex::new(Vec::new()),
            remote_candidates: std::sync::Mutex::new(Vec::new()),
            gather_state: std::sync::Mutex::new(IceGathererState::New),
            config,
            gatherer,
            local_parameters: std::sync::Mutex::new(IceParameters::generate()),
            remote_parameters: std::sync::Mutex::new(None),
            pending_transactions: std::sync::Mutex::new(HashMap::new()),
            data_receiver: std::sync::Mutex::new(None),
            buffered_packets: std::sync::Mutex::new(Vec::new()),
            selected_socket: selected_socket_tx,
            _socket_rx_keeper: selected_socket_rx,
            selected_pair_notifier: selected_pair_tx,
            _selected_pair_rx_keeper: selected_pair_rx,
            last_received: std::sync::Mutex::new(Instant::now()),
            candidate_tx: candidate_tx.clone(),
            cmd_tx,
            checking_pairs: Mutex::new(std::collections::HashSet::new()),
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

    pub fn subscribe_selected_pair(&self) -> watch::Receiver<Option<IceCandidatePair>> {
        self.inner.selected_pair_notifier.subscribe()
    }

    pub fn gather_state(&self) -> IceGathererState {
        self.inner.gatherer.state()
    }

    pub async fn role(&self) -> IceRole {
        *self.inner.role.lock().unwrap()
    }

    pub fn local_candidates(&self) -> Vec<IceCandidate> {
        self.inner.gatherer.local_candidates()
    }

    pub fn remote_candidates(&self) -> Vec<IceCandidate> {
        self.inner.remote_candidates.lock().unwrap().clone()
    }

    pub fn local_parameters(&self) -> IceParameters {
        self.inner.local_parameters.lock().unwrap().clone()
    }

    fn start_keepalive(&self) {
        // Handled by runner
    }

    pub fn start_gathering(&self) -> Result<()> {
        {
            let mut state = self.inner.gather_state.lock().unwrap();
            if *state == IceGathererState::Complete || *state == IceGathererState::Gathering {
                return Ok(());
            }
            *state = IceGathererState::Gathering;
            let _ = self.inner.gathering_state.send(IceGathererState::Gathering);
        }

        let _ = self.inner.cmd_tx.send(IceCommand::StartGathering);
        Ok(())
    }

    pub fn start(&self, remote: IceParameters) -> Result<()> {
        self.start_gathering()?;
        self.start_keepalive();
        {
            let mut params = self.inner.remote_parameters.lock().unwrap();
            *params = Some(remote);
        }
        if let Err(e) = self.inner.state.send(IceTransportState::Checking) {
            warn!("start: failed to set state to Checking: {}", e);
        }
        self.try_connectivity_checks();
        Ok(())
    }

    pub async fn start_direct(&self, remote_addr: SocketAddr) -> Result<()> {
        self.start_gathering()?;
        self.start_keepalive();

        // Wait for a suitable local candidate
        // If remote is not loopback, we prefer a non-loopback local candidate to avoid os error 49 (EADDRNOTAVAIL)
        let mut rx = self.subscribe_candidates();
        let start = Instant::now();
        let timeout_dur = Duration::from_secs(2);

        let is_suitable = |c: &IceCandidate| -> bool {
            if !remote_addr.ip().is_loopback() && c.address.ip().is_loopback() {
                return false;
            }
            true
        };

        let mut best_local: Option<IceCandidate> = None;

        // 1. Check existing candidates
        {
            let candidates = self.inner.gatherer.local_candidates();
            for c in candidates {
                if is_suitable(&c) {
                    best_local = Some(c);
                    break;
                }
            }
        }

        // 2. If not found, wait for more
        if best_local.is_none() {
            loop {
                let remaining = timeout_dur
                    .checked_sub(start.elapsed())
                    .unwrap_or(Duration::ZERO);
                if remaining.is_zero() {
                    break;
                }

                match timeout(remaining, rx.recv()).await {
                    Ok(Ok(c)) => {
                        if is_suitable(&c) {
                            best_local = Some(c);
                            break;
                        }
                    }
                    _ => break,
                }
            }
        }

        // 3. Fallback to any candidate
        let local = if let Some(best) = best_local {
            best
        } else if let Some(first) = self.inner.gatherer.local_candidates().first() {
            first.clone()
        } else {
            bail!("No local candidates gathered for direct connection");
        };

        let remote = IceCandidate::host(remote_addr, 1);
        let pair = IceCandidatePair::new(local, remote);

        *self.inner.selected_pair.lock().unwrap() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
        let _ = self.inner.state.send(IceTransportState::Connected);
        Ok(())
    }

    pub fn stop(&self) {
        let _ = self.inner.state.send(IceTransportState::Closed);
    }

    pub fn set_role(&self, role: IceRole) {
        *self.inner.role.lock().unwrap() = role;
    }

    pub fn add_remote_candidate(&self, candidate: IceCandidate) {
        let mut list = self.inner.remote_candidates.lock().unwrap();
        list.push(candidate);
        drop(list);
        self.try_connectivity_checks();
    }

    pub fn select_pair(&self, pair: IceCandidatePair) {
        *self.inner.selected_pair.lock().unwrap() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
        let _ = self.inner.state.send(IceTransportState::Connected);
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub async fn get_selected_socket(&self) -> Option<IceSocketWrapper> {
        let pair = self.inner.selected_pair.lock().unwrap().clone()?;
        if pair.local.typ == IceCandidateType::Relay {
            let clients = self.inner.gatherer.turn_clients.lock().unwrap();
            clients
                .get(&pair.local.address)
                .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
        } else {
            self.inner
                .gatherer
                .get_socket(pair.local.base_address())
                .map(IceSocketWrapper::Udp)
        }
    }

    pub async fn get_selected_pair(&self) -> Option<IceCandidatePair> {
        self.inner.selected_pair.lock().unwrap().clone()
    }

    pub async fn set_data_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        {
            let mut rx_lock = self.inner.data_receiver.lock().unwrap();
            *rx_lock = Some(receiver.clone());
        }

        let packets: Vec<_> = {
            let mut buffer = self.inner.buffered_packets.lock().unwrap();
            if buffer.is_empty() {
                return;
            }
            debug!("Flushing {} buffered packets", buffer.len());
            buffer.drain(..).collect()
        };

        for (packet, addr) in packets {
            receiver.receive(Bytes::from(packet), addr).await;
        }
    }

    fn try_connectivity_checks(&self) {
        let _ = self.inner.cmd_tx.send(IceCommand::RunChecks);
    }

    async fn handle_turn_packet(
        packet: &[u8],
        inner: &Arc<IceTransportInner>,
        client: &Arc<TurnClient>,
        relayed_addr: SocketAddr,
    ) {
        // Check for ChannelData (0x4000 - 0x7FFF)
        if packet.len() >= 4 {
            let channel_num = u16::from_be_bytes([packet[0], packet[1]]);
            if channel_num >= 0x4000 && channel_num <= 0x7FFF {
                let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
                if packet.len() >= 4 + len {
                    let data = &packet[4..4 + len];
                    if let Some(peer_addr) = client.get_peer(channel_num).await {
                        handle_packet(
                            data,
                            peer_addr,
                            inner.clone(),
                            IceSocketWrapper::Turn(client.clone(), relayed_addr),
                        )
                        .await;
                    }
                }
                return;
            }
        }

        if let Ok(msg) = StunMessage::decode(packet) {
            if msg.class == StunClass::Indication && msg.method == StunMethod::Data {
                if let Some(data) = &msg.data
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
            } else {
                // Handle other TURN messages (e.g. CreatePermission response)
                handle_packet(
                    packet,
                    relayed_addr,
                    inner.clone(),
                    IceSocketWrapper::Turn(client.clone(), relayed_addr),
                )
                .await;
            }
        }
    }
}

async fn perform_connectivity_checks_async(inner: Arc<IceTransportInner>) {
    let state = *inner.state.borrow();
    if state != IceTransportState::Checking {
        return;
    }
    let locals = inner.gatherer.local_candidates();
    let remotes = inner.remote_candidates.lock().unwrap().clone();
    let role = *inner.role.lock().unwrap();

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
            // Filter out Loopback -> Non-Loopback to avoid EADDRNOTAVAIL (os error 49)
            if local.address.ip().is_loopback() && !remote.address.ip().is_loopback() {
                continue;
            }
            pairs.push(IceCandidatePair::new(local.clone(), remote.clone()));
        }
    }

    // Sort by priority
    pairs.sort_by(|a, b| b.priority(role).cmp(&a.priority(role)));

    let mut pairs_to_check = Vec::new();
    {
        let mut checking = inner.checking_pairs.lock().await;
        for pair in pairs {
            let key = (pair.local.address, pair.remote.address);
            if !checking.contains(&key) {
                checking.insert(key);
                pairs_to_check.push(pair);
            }
        }
    }

    if pairs_to_check.is_empty() {
        return;
    }

    let mut checks = futures::stream::FuturesUnordered::new();

    for pair in pairs_to_check {
        let inner = inner.clone();
        let local = pair.local.clone();
        let remote = pair.remote.clone();

        checks.push(async move {
            let key = (local.address, remote.address);
            let res = perform_binding_check(&local, &remote, &inner, role, false).await;

            {
                let mut checking = inner.checking_pairs.lock().await;
                checking.remove(&key);
            }

            match res {
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
            *inner.selected_pair.lock().unwrap() = Some(pair.clone());
            let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
            if let Some(socket) = resolve_socket(&inner, &pair) {
                let _ = inner.selected_socket.send(Some(socket));
            }
            let _ = inner.state.send(IceTransportState::Connected);
            success = true;
            debug!(
                "ICE checks complete. Selected pair: {} -> {}",
                pair.local.address, pair.remote.address
            );

            if role == IceRole::Controlling {
                debug!(
                    "Controlling agent nominating pair: {} -> {}",
                    pair.local.address, pair.remote.address
                );
                let inner_clone = inner.clone();
                let pair_clone = pair.clone();
                tokio::spawn(async move {
                    if let Err(e) = perform_binding_check(
                        &pair_clone.local,
                        &pair_clone.remote,
                        &inner_clone,
                        role,
                        true,
                    )
                    .await
                    {
                        warn!("Failed to send nomination: {}", e);
                    }
                });
            }

            break;
        }
    }

    if !success {
        let state = *inner.state.borrow();
        let has_selected_pair = inner.selected_pair.lock().unwrap().is_some();
        // Only set Failed if we're not already connected AND we don't have a working pair
        if state != IceTransportState::Connected && !has_selected_pair {
            let _ = inner.state.send(IceTransportState::Failed);
        }
    }
}

fn resolve_socket(inner: &IceTransportInner, pair: &IceCandidatePair) -> Option<IceSocketWrapper> {
    if pair.local.typ == IceCandidateType::Relay {
        let clients = inner.gatherer.turn_clients.lock().unwrap();
        clients
            .get(&pair.local.address)
            .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
    } else {
        let socket = inner.gatherer.get_socket(pair.local.base_address());
        if socket.is_none() {
            warn!(
                "resolve_socket: failed to find socket for {}",
                pair.local.base_address()
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
        *inner.last_received.lock().unwrap() = Instant::now();
    }
    let b = packet[0];
    if b < 2 {
        // STUN
        match StunMessage::decode(packet) {
            Ok(msg) => {
                if msg.class == StunClass::Request {
                    handle_stun_request(&sender, &msg, addr, inner).await;
                } else if msg.class == StunClass::SuccessResponse {
                    let mut map = inner.pending_transactions.lock().unwrap();
                    if let Some(tx) = map.remove(&msg.transaction_id) {
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
                        if code == 401 {
                            let remote_params = inner.remote_parameters.lock().unwrap().clone();
                            warn!(
                                "STUN 401 received. Current remote params: {:?}",
                                remote_params
                            );
                        }
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
        let receiver = inner.data_receiver.lock().unwrap().clone();
        if let Some(rx) = receiver {
            rx.receive(Bytes::copy_from_slice(packet), addr).await;
        } else {
            let mut buffer = inner.buffered_packets.lock().unwrap();
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

    let password = inner.local_parameters.lock().unwrap().password.clone();
    if let Ok(bytes) = response.encode(Some(password.as_bytes()), true) {
        match sender.send_to(&bytes, addr).await {
            Ok(_) => trace!("Sent STUN Response to {}", addr),
            Err(e) => {
                if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                    match io_err.kind() {
                        std::io::ErrorKind::HostUnreachable
                        | std::io::ErrorKind::NetworkUnreachable => {
                            debug!("Failed to send STUN Response to {}: {}", addr, e);
                        }
                        _ => {
                            if io_err.raw_os_error() == Some(65)
                                || io_err.raw_os_error() == Some(49)
                            {
                                debug!("Failed to send STUN Response to {}: {}", addr, e);
                            } else {
                                warn!("Failed to send STUN Response to {}: {}", addr, e);
                            }
                        }
                    }
                } else {
                    warn!("Failed to send STUN Response to {}: {}", addr, e);
                }
            }
        }
    } else {
        warn!("Failed to encode STUN Response");
    }

    // Check if we know this candidate
    let mut known = false;
    {
        let remotes = inner.remote_candidates.lock().unwrap();
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

        let mut list = inner.remote_candidates.lock().unwrap();
        list.push(candidate);
        drop(list);

        let _ = inner.cmd_tx.send(IceCommand::RunChecks);
    }

    if msg.use_candidate {
        let role = *inner.role.lock().unwrap();
        if role == IceRole::Controlled {
            let local_addr = match sender {
                IceSocketWrapper::Udp(s) => s
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                IceSocketWrapper::Turn(_, addr) => *addr,
            };

            let locals = inner.gatherer.local_candidates();
            let local_cand = locals.iter().find(|c| c.address == local_addr);

            let pair = {
                let remotes = inner.remote_candidates.lock().unwrap();
                let remote_cand = remotes.iter().find(|c| c.address == addr);
                if let (Some(l), Some(r)) = (local_cand, remote_cand) {
                    Some(IceCandidatePair::new(l.clone(), r.clone()))
                } else {
                    None
                }
            };

            if let Some(pair) = pair {
                trace!(
                    "Controlled agent selected pair via UseCandidate: {} -> {}",
                    pair.local.address, pair.remote.address
                );
                *inner.selected_pair.lock().unwrap() = Some(pair.clone());
                let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
                if let Some(socket) = resolve_socket(&inner, &pair) {
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

struct TransactionGuard<'a> {
    map: &'a std::sync::Mutex<HashMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    tx_id: [u8; 12],
}

impl<'a> Drop for TransactionGuard<'a> {
    fn drop(&mut self) {
        // debug!("TransactionGuard: dropping tx={:?}", self.tx_id);
        let mut map = self.map.lock().unwrap();
        map.remove(&self.tx_id);
    }
}

async fn perform_binding_check(
    local: &IceCandidate,
    remote: &IceCandidate,
    inner: &Arc<IceTransportInner>,
    role: IceRole,
    nominated: bool,
) -> Result<()> {
    if remote.transport != "udp" {
        bail!("only UDP connectivity checks are supported");
    }
    let local_params = inner.local_parameters.lock().unwrap().clone();
    let remote_params = match inner.remote_parameters.lock().unwrap().clone() {
        Some(p) => p,
        None => bail!("no remote params"),
    };

    let tx_id = random_bytes::<12>();
    // debug!("perform_binding_check: starting check for {} -> {} tx={:?}", local.address, remote.address, tx_id);

    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
    let username = format!(
        "{}:{}",
        remote_params.username_fragment, local_params.username_fragment
    );
    msg.attributes.push(StunAttribute::Username(username));
    msg.attributes.push(StunAttribute::Priority(local.priority));
    match role {
        IceRole::Controlling => {
            msg.attributes
                .push(StunAttribute::IceControlling(local_params.tie_breaker));
            if nominated {
                msg.attributes.push(StunAttribute::UseCandidate);
            }
        }
        IceRole::Controlled => msg
            .attributes
            .push(StunAttribute::IceControlled(local_params.tie_breaker)),
    }
    let bytes = msg.encode(Some(remote_params.password.as_bytes()), true)?;

    let (tx, mut rx) = oneshot::channel();
    {
        let mut map = inner.pending_transactions.lock().unwrap();
        map.insert(tx_id, tx);
    }

    // Ensure transaction is removed when this future is dropped
    let _guard = TransactionGuard {
        map: &inner.pending_transactions,
        tx_id,
    };

    let (socket, turn_client) = if local.typ == IceCandidateType::Relay {
        let gatherer = &inner.gatherer;
        let clients = gatherer.turn_clients.lock().unwrap();
        let client = clients.get(&local.address).cloned();
        (None, client)
    } else {
        let socket = inner.gatherer.get_socket(local.base_address());
        (socket, None)
    };

    if local.typ == IceCandidateType::Relay {
        let client = turn_client
            .as_ref()
            .ok_or_else(|| anyhow!("TURN client not found for relay candidate"))?;

        let (perm_bytes, perm_tx_id) = client.create_permission_packet(remote.address).await?;

        let (perm_tx, perm_rx) = oneshot::channel();
        {
            let mut map = inner.pending_transactions.lock().unwrap();
            map.insert(perm_tx_id, perm_tx);
        }

        trace!("Sending CreatePermission to TURN server");
        if let Err(e) = client.send(&perm_bytes).await {
            warn!("CreatePermission send failed: {}", e);
            return Err(e);
        }

        match timeout(inner.config.stun_timeout, perm_rx).await {
            Ok(Ok(msg)) => {
                if msg.class == StunClass::ErrorResponse {
                    bail!("CreatePermission failed: {:?}", msg.error_code);
                }

                // Try ChannelBind if not already bound
                if client.get_channel(remote.address).await.is_none() {
                    if let Ok((bind_bytes, bind_tx_id, channel_num)) =
                        client.create_channel_bind_packet(remote.address).await
                    {
                        let (bind_tx, bind_rx) = oneshot::channel();
                        {
                            let mut map = inner.pending_transactions.lock().unwrap();
                            map.insert(bind_tx_id, bind_tx);
                        }

                        if let Ok(_) = client.send(&bind_bytes).await {
                            let client_clone = client.clone();
                            let remote_addr = remote.address;
                            let inner_weak = Arc::downgrade(&inner);
                            let timeout_dur = inner.config.stun_timeout;

                            tokio::spawn(async move {
                                match timeout(timeout_dur, bind_rx).await {
                                    Ok(Ok(msg)) => {
                                        if msg.class == StunClass::SuccessResponse {
                                            client_clone
                                                .add_channel(remote_addr, channel_num)
                                                .await;
                                            debug!(
                                                "TURN ChannelBound: {} -> {}",
                                                remote_addr, channel_num
                                            );
                                        }
                                    }
                                    _ => {
                                        // Timeout or error
                                        if let Some(inner) = inner_weak.upgrade() {
                                            let mut map =
                                                inner.pending_transactions.lock().unwrap();
                                            map.remove(&bind_tx_id);
                                        }
                                    }
                                }
                            });
                        }
                    }
                }
            }
            _ => {
                let mut map = inner.pending_transactions.lock().unwrap();
                map.remove(&perm_tx_id);
                bail!("CreatePermission timeout");
            }
        }
    } else if socket.is_none() {
        bail!("no socket found for local candidate");
    }

    let start = Instant::now();
    let mut rto = Duration::from_millis(500);
    let max_timeout = inner.config.stun_timeout;

    loop {
        if let Some(client) = &turn_client {
            let sent = if let Some(channel) = client.get_channel(remote.address).await {
                client.send_channel_data(channel, &bytes).await
            } else {
                client.send_indication(remote.address, &bytes).await
            };

            if let Err(e) = sent {
                debug!("TURN send failed: {}", e);
                return Err(e);
            }
        } else if let Some(socket) = &socket {
            if let Err(e) = socket.send_to(&bytes, remote.address).await {
                match e.kind() {
                    std::io::ErrorKind::HostUnreachable
                    | std::io::ErrorKind::NetworkUnreachable => {
                        debug!("socket.send_to {} failed: {}", remote.address, e);
                    }
                    _ => {
                        // Also check raw OS error for cases not covered by ErrorKind
                        if e.raw_os_error() == Some(65) || e.raw_os_error() == Some(49) {
                            debug!("socket.send_to {} failed: {}", remote.address, e);
                        } else {
                            warn!("socket.send_to {} failed: {}", remote.address, e);
                        }
                    }
                }
                return Err(e.into());
            }
        }

        let timeout_fut = tokio::time::sleep(max_timeout.saturating_sub(start.elapsed()));
        let rto_fut = tokio::time::sleep(rto);

        tokio::select! {
            res = &mut rx => {
                let parsed = match res {
                    Ok(msg) => msg,
                    Err(_) => bail!("channel closed"),
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
                return Ok(());
            }
            _ = timeout_fut => {
                bail!("timeout");
            }
            _ = rto_fut => {
                if start.elapsed() >= max_timeout {
                    continue;
                }
                trace!("Retransmitting STUN Request to {} tx={:?}", remote.address, tx_id);
                rto = std::cmp::min(rto * 2, Duration::from_millis(1600));
            }
        }
    }
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

    pub fn base_address(&self) -> SocketAddr {
        if self.typ == IceCandidateType::ServerReflexive || self.typ == IceCandidateType::Host {
            self.related_address.unwrap_or(self.address)
        } else {
            self.address
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
            if self.typ != IceCandidateType::Host {
                parts.push("raddr".into());
                parts.push(addr.ip().to_string());
                parts.push("rport".into());
                parts.push(addr.port().to_string());
            }
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

        // IPv6 addresses need brackets when combined with port
        let address = if ip_str.contains(':') {
            format!("[{}]:{}", ip_str, port).parse()?
        } else {
            format!("{}:{}", ip_str, port).parse()?
        };

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
        transport.set_role(self.role);
        if let Err(err) = transport.start_gathering() {
            warn!("ICE gather failed: {}", err);
        }
        (transport, runner)
    }
}

#[derive(Debug, Clone)]
struct IceGatherer {
    state: Arc<std::sync::Mutex<IceGathererState>>,
    local_candidates: Arc<std::sync::Mutex<Vec<IceCandidate>>>,
    sockets: Arc<std::sync::Mutex<Vec<Arc<UdpSocket>>>>,
    turn_clients: Arc<std::sync::Mutex<HashMap<SocketAddr, Arc<TurnClient>>>>,
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
            state: Arc::new(std::sync::Mutex::new(IceGathererState::New)),
            local_candidates: Arc::new(std::sync::Mutex::new(Vec::new())),
            sockets: Arc::new(std::sync::Mutex::new(Vec::new())),
            turn_clients: Arc::new(std::sync::Mutex::new(HashMap::new())),
            config,
            candidate_tx,
            socket_tx,
        }
    }

    fn state(&self) -> IceGathererState {
        *self.state.lock().unwrap()
    }

    fn local_candidates(&self) -> Vec<IceCandidate> {
        self.local_candidates.lock().unwrap().clone()
    }

    fn get_socket(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        let sockets = self.sockets.lock().unwrap();
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
        trace!(
            "get_socket: no socket found for {}, available: {:?}",
            addr, available
        );
        None
    }

    #[instrument(skip(self))]
    async fn gather(&self) -> Result<()> {
        {
            let mut state = self.state.lock().unwrap();
            if *state == IceGathererState::Complete {
                return Ok(());
            }
            *state = IceGathererState::Gathering;
        }

        let host_fut = async {
            if self.config.ice_transport_policy == IceTransportPolicy::All {
                if let Err(e) = self.gather_host_candidates().await {
                    warn!("Host gathering failed: {}", e);
                }
            }
        };

        let server_fut = async {
            if let Err(e) = self.gather_servers().await {
                warn!("Server gathering failed: {}", e);
            }
        };

        tokio::join!(host_fut, server_fut);

        *self.state.lock().unwrap() = IceGathererState::Complete;
        Ok(())
    }

    async fn gather_host_candidates(&self) -> Result<()> {
        // 1. Loopback
        let loopback_ip = IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        match UdpSocket::bind(SocketAddr::new(loopback_ip, 0)).await {
            Ok(socket) => {
                if let Ok(addr) = socket.local_addr() {
                    let socket = Arc::new(socket);
                    self.sockets.lock().unwrap().push(socket.clone());
                    let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));
                    self.push_candidate(IceCandidate::host(addr, 1));
                }
            }
            Err(e) => warn!("Failed to bind loopback socket: {}", e),
        }

        // 2. LAN IP
        if let Ok(ip) = get_local_ip()
            && !ip.is_loopback()
        {
            match UdpSocket::bind(SocketAddr::new(ip, 0)).await {
                Ok(socket) => {
                    if let Ok(addr) = socket.local_addr() {
                        let socket = Arc::new(socket);
                        self.sockets.lock().unwrap().push(socket.clone());
                        let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));

                        if let Some(ext_ip) = &self.config.external_ip
                            && let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
                        {
                            let mut ext_addr = addr;
                            ext_addr.set_ip(parsed_ip);
                            let mut cand = IceCandidate::host(ext_addr, 1);
                            cand.related_address = Some(addr);
                            self.push_candidate(cand);
                        } else {
                            self.push_candidate(IceCandidate::host(addr, 1));
                        }
                    }
                }
                Err(e) => warn!("Failed to bind LAN socket on {}: {}", ip, e),
            }
        }

        Ok(())
    }

    async fn gather_servers(&self) -> Result<()> {
        let mut tasks = FuturesUnordered::new();

        for server in &self.config.ice_servers {
            for url in &server.urls {
                let server = server.clone();
                let url = url.clone();
                let this = self.clone();

                tasks.push(async move {
                    let uri = match IceServerUri::parse(&url) {
                        Ok(uri) => uri,
                        Err(err) => {
                            warn!("invalid ICE server URI {}: {}", url, err);
                            return;
                        }
                    };

                    match uri.kind {
                        IceUriKind::Stun => {
                            if this.config.ice_transport_policy == IceTransportPolicy::All {
                                match this.probe_stun(&uri).await {
                                    Ok(Some(candidate)) => this.push_candidate(candidate),
                                    Ok(None) => {}
                                    Err(e) => warn!("STUN probe failed for {}: {}", url, e),
                                }
                            }
                        }
                        IceUriKind::Turn => match this.probe_turn(&uri, &server).await {
                            Ok(Some(candidate)) => this.push_candidate(candidate),
                            Ok(None) => {}
                            Err(e) => warn!("TURN probe failed for {}: {}", url, e),
                        },
                    }
                });
            }
        }

        while let Some(_) = tasks.next().await {}
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
        let (len, from) = timeout(self.config.stun_timeout, socket.recv_from(&mut buf)).await??;
        if from.ip() != addr.ip() {
            return Ok(None);
        }
        let parsed = StunMessage::decode(&buf[..len])?;
        if let Some(mapped) = parsed.xor_mapped_address {
            let socket = Arc::new(socket);
            self.sockets.lock().unwrap().push(socket.clone());
            let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));
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

        let client = Arc::new(client);
        self.turn_clients
            .lock()
            .unwrap()
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

    fn push_candidate(&self, candidate: IceCandidate) {
        if self.config.disable_ipv6 && candidate.address.is_ipv6() {
            return;
        }
        let mut candidates = self.local_candidates.lock().unwrap();
        if candidates.iter().any(|c| c.address == candidate.address) {
            return;
        }
        tracing::debug!(
            "Gathered local candidate: {} type={:?}",
            candidate.address,
            candidate.typ
        );
        candidates.push(candidate.clone());
        drop(candidates);
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

#[derive(Debug, Clone)]
pub enum IceSocketWrapper {
    Udp(Arc<UdpSocket>),
    Turn(Arc<TurnClient>, SocketAddr),
}

impl IceSocketWrapper {
    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> Result<usize> {
        loop {
            match self {
                IceSocketWrapper::Udp(s) => match s.send_to(data, addr).await {
                    Ok(len) => return Ok(len),
                    Err(e) => {
                        if let Some(code) = e.raw_os_error() {
                            if code == 55 {
                                // ENOBUFS on macOS, wait a bit and retry
                                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
                                continue;
                            }
                        }
                        return Err(e.into());
                    }
                },
                IceSocketWrapper::Turn(c, _) => {
                    if let Some(channel) = c.get_channel(addr).await {
                        c.send_channel_data(channel, data).await?;
                    } else {
                        c.send_indication(addr, data).await?;
                    }
                    return Ok(data.len());
                }
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
