pub mod conn;
pub mod stun;
#[cfg(test)]
mod tests;
pub mod turn;
pub mod upnp;

// Re-export UPnP types
pub use upnp::{
    DEFAULT_LEASE_DURATION, DEFAULT_UPNP_DISCOVERY_TIMEOUT, MAX_LEASE_DURATION, MIN_LEASE_DURATION,
    UpnpPortMapper,
};

use crate::config::{BufferDropStrategy, IceServer, IceTransportPolicy, RtcConfiguration};
use crate::transports::ice::turn::{TurnClient, TurnCredentials};
use crate::transports::{PacketReceiver, get_local_ip};
use bytes::Bytes;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::{HashMap, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use tokio::net::{UdpSocket, lookup_host};
use tokio::sync::{Mutex, broadcast, mpsc, oneshot, watch};
use tokio::time::timeout;
use tracing::{debug, instrument, trace};

#[cfg(any(test, feature = "simulator"))]
use self::stun::random_u32;
use self::stun::{
    StunAttribute, StunClass, StunDecoded, StunMessage, StunMethod, random_bytes, random_u64,
};

pub(crate) const MAX_STUN_MESSAGE: usize = 1500;
#[cfg(any(test, feature = "simulator"))]
static PACKET_LOSS_RATE: AtomicU32 = AtomicU32::new(u32::MAX);

pub(crate) fn should_drop_packet() -> bool {
    #[cfg(not(any(test, feature = "simulator")))]
    return false;

    #[cfg(any(test, feature = "simulator"))]
    {
        let mut rate = PACKET_LOSS_RATE.load(Ordering::Relaxed);
        if rate == u32::MAX {
            rate = std::env::var("RUSTRTC_PACKET_LOSS")
                .ok()
                .and_then(|s| s.parse::<f64>().ok())
                .map(|f| (f * 100.0) as u32)
                .unwrap_or(0);
            PACKET_LOSS_RATE.store(rate, Ordering::Relaxed);
        }

        if rate == 0 {
            return false;
        }

        let rand_val = random_u32() % 10000;
        let drop = rand_val < rate;
        if drop {
            trace!("SIMULATOR: Dropping packet (rate={}%)", rate as f64 / 100.0);
        }
        drop
    }
}

/// Statistics for monitoring buffer behavior
#[derive(Debug)]
struct BufferStats {
    pub packets_received: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub current_size: AtomicU32,
    pub peak_size: AtomicU32,
    pub last_log_time: parking_lot::Mutex<Instant>,
}

impl Default for BufferStats {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            current_size: AtomicU32::new(0),
            peak_size: AtomicU32::new(0),
            last_log_time: parking_lot::Mutex::new(Instant::now()),
        }
    }
}

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
    role: parking_lot::Mutex<IceRole>,
    selected_pair: parking_lot::Mutex<Option<IceCandidatePair>>,
    local_candidates: Mutex<Vec<IceCandidate>>,
    remote_candidates: parking_lot::Mutex<Vec<IceCandidate>>,
    gather_state: parking_lot::Mutex<IceGathererState>,
    config: RtcConfiguration,
    gatherer: IceGatherer,
    local_parameters: parking_lot::Mutex<IceParameters>,
    remote_parameters: parking_lot::Mutex<Option<IceParameters>>,
    pending_transactions: parking_lot::Mutex<HashMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    data_receiver: parking_lot::Mutex<Option<Arc<dyn PacketReceiver>>>,
    /// Ring buffer for packets when no receiver is registered yet.
    /// Uses VecDeque for efficient pop_front removal.
    buffered_packets: parking_lot::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Statistics for monitoring buffer behavior
    buffer_stats: Arc<BufferStats>,
    selected_socket: watch::Sender<Option<IceSocketWrapper>>,
    _socket_rx_keeper: watch::Receiver<Option<IceSocketWrapper>>,
    selected_pair_notifier: watch::Sender<Option<IceCandidatePair>>,
    _selected_pair_rx_keeper: watch::Receiver<Option<IceCandidatePair>>,
    last_received: parking_lot::Mutex<Instant>,
    candidate_tx: broadcast::Sender<IceCandidate>,
    cmd_tx: mpsc::UnboundedSender<IceCommand>,
    checking_pairs: Mutex<std::collections::HashSet<(SocketAddr, SocketAddr)>>,
    /// Signals when the controlling-side nomination is complete.
    /// `true` = nomination succeeded, `false` = nomination failed (but ICE is still connected).
    /// Controlled side immediately sends `true` (no nomination to do).
    nomination_complete: watch::Sender<Option<bool>>,
    _nomination_complete_rx: watch::Receiver<Option<bool>>,
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
            .field("buffered_packets", &self.buffered_packets.lock().len())
            .field("buffer_stats", &self.buffer_stats)
            .field("selected_socket", &self.selected_socket)
            .field("selected_pair_notifier", &self.selected_pair_notifier)
            .field("candidate_tx", &self.candidate_tx)
            .field("cmd_tx", &self.cmd_tx)
            .field("nomination_complete", &self.nomination_complete)
            .finish()
    }
}

struct IceTransportRunner {
    inner: Arc<IceTransportInner>,
    socket_rx: mpsc::UnboundedReceiver<IceSocketWrapper>,
    candidate_rx: broadcast::Receiver<IceCandidate>,
    cmd_rx: mpsc::UnboundedReceiver<IceCommand>,
    state_rx: watch::Receiver<IceTransportState>,
}

impl IceTransportRunner {
    async fn run(mut self) {
        let mut interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(1),
            Duration::from_secs(1),
        );
        // TURN refresh interval: every 120s (well under 300s permission timeout)
        let mut turn_refresh_interval = tokio::time::interval_at(
            tokio::time::Instant::now() + Duration::from_secs(120),
            Duration::from_secs(120),
        );
        let mut read_futures: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let mut gathering_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());
        let mut turn_refresh_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());

        loop {
            tokio::select! {
                res = self.state_rx.changed() => {
                    if res.is_err() {
                        break;
                    }
                    if matches!(*self.state_rx.borrow(), IceTransportState::Closed | IceTransportState::Failed) {
                        break;
                    }
                }
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
                            read_futures.push(Box::pin(async move {
                                perform_connectivity_checks_async(inner).await;
                            }));
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
                                    debug!("Gathering failed: {}", e);
                                }
                                {
                                    let mut buffer = inner.local_candidates.lock().await;
                                    *buffer = inner.gatherer.local_candidates();
                                }
                                *inner.gather_state.lock() = IceGathererState::Complete;
                                let _ = inner.gathering_state.send(IceGathererState::Complete);
                            });
                        }
                        IceCommand::RunChecks => {
                            let inner = self.inner.clone();
                            read_futures.push(Box::pin(async move {
                                perform_connectivity_checks_async(inner).await;
                            }));
                        }
                    }
                }
                _ = interval.tick() => {
                    if let Some(f) = Self::run_keepalive_tick(&self.inner).await {
                        read_futures.push(f);
                    }
                }
                _ = turn_refresh_interval.tick() => {
                    // Only start a new refresh if the previous one has completed.
                    // If still running (e.g. server slow), skip this tick rather than
                    // stacking up concurrent refreshes.
                    let inner = self.inner.clone();
                    turn_refresh_future = Box::pin(async move {
                        Self::run_turn_refresh(&inner).await;
                    });
                }
                _ = &mut turn_refresh_future => {
                    turn_refresh_future = Box::pin(futures::future::pending());
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
        let sender = IceSocketWrapper::Udp(socket.clone());
        trace!("Read loop started for {:?}", socket.local_addr());
        loop {
            tokio::select! {
                res = socket.readable() => {
                    if let Err(e) = res {
                        debug!("Socket readable wait error: {}", e);
                        break;
                    }

                    loop {
                        let (len, addr) = match socket.try_recv_from(&mut buf) {
                            Ok(v) => v,
                            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                                break;
                            }
                            Err(e) => {
                                debug!("Socket recv error: {}", e);
                                return;
                            }
                        };

                        let packet = &buf[..len];
                        if len > 0 {
                            handle_packet(
                                packet,
                                addr,
                                inner.clone(),
                                sender.clone(),
                            )
                            .await;
                        }
                    }
                }
                res = state_rx.changed() => {
                    if res.is_err() || matches!(*state_rx.borrow(), IceTransportState::Closed | IceTransportState::Failed) {
                        debug!("Read loop stopping (IceTransport Closed or Failed)");
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
                    if res.is_err() || matches!(*state_rx.borrow(), IceTransportState::Closed | IceTransportState::Failed) {
                        debug!("TURN Read loop stopping (IceTransport Closed or Failed)");
                        break;
                    }
                }
            }
        }
    }

    /// Returns an optional cleanup future that should be pushed into `read_futures`
    /// by the caller. The future waits up to 5 s for the keepalive response then
    /// removes the transaction from `pending_transactions`.
    async fn run_keepalive_tick(inner: &Arc<IceTransportInner>) -> Option<BoxFuture<'static, ()>> {
        let state = *inner.state.borrow();
        if state == IceTransportState::Connected || state == IceTransportState::Disconnected {
            let elapsed = inner.last_received.lock().elapsed();
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
            let pair_opt = inner.selected_pair.lock().clone();
            if let Some(pair) = pair_opt {
                if let Some(socket) = resolve_socket(inner, &pair) {
                    let tx_id = random_bytes::<12>();
                    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));

                    let remote_params = inner.remote_parameters.lock().clone();
                    if let Some(params) = remote_params {
                        let username = format!(
                            "{}:{}",
                            params.username_fragment,
                            inner.local_parameters.lock().username_fragment
                        );
                        msg.attributes.push(StunAttribute::Username(username));
                        msg.attributes
                            .push(StunAttribute::Priority(pair.local.priority));

                        if let Ok(bytes) = msg.encode(Some(params.password.as_bytes()), true) {
                            // Register transaction to avoid "Unmatched transaction" logs
                            let (tx, rx) = oneshot::channel();
                            {
                                let mut map = inner.pending_transactions.lock();
                                map.insert(tx_id, tx);
                            }

                            let inner_weak = Arc::downgrade(inner);
                            let cleanup: BoxFuture<'static, ()> = Box::pin(async move {
                                let _ = timeout(Duration::from_secs(5), rx).await;
                                if let Some(inner) = inner_weak.upgrade() {
                                    let mut map = inner.pending_transactions.lock();
                                    map.remove(&tx_id);
                                }
                            });

                            let _ = socket.send_to(&bytes, pair.remote.address).await;
                            return Some(cleanup);
                        }
                    } else if inner.config.transport_mode != crate::TransportMode::WebRtc {
                        if let Ok(bytes) = msg.encode(None, false) {
                            let _ = socket.send_to(&bytes, pair.remote.address).await;
                        }
                    }
                }
            }
        }
        None
    }

    /// Periodically refresh TURN allocations, permissions, and channel bindings
    /// to prevent them from expiring. Per RFC 5766:
    ///   - Allocation lifetime: 600s (default), refresh before expiry
    ///   - Permission lifetime: 300s, must be refreshed
    ///   - ChannelBind lifetime: 600s, must be refreshed
    ///
    /// This runs every ~120s which is well under all three timeouts.
    ///
    /// Each request is awaited directly (no spawning) so that a 401/438
    /// stale-nonce response is detected immediately and the nonce is refreshed
    /// before retrying — preventing silent refresh failures that eventually let
    /// ChannelBindings expire and cause SCTP disconnects.
    async fn run_turn_refresh(inner: &Arc<IceTransportInner>) {
        let state = *inner.state.borrow();
        if state != IceTransportState::Connected && state != IceTransportState::Disconnected {
            return;
        }

        let all_clients: Vec<(SocketAddr, Arc<TurnClient>)> = {
            let clients = inner.gatherer.turn_clients.lock();
            clients.iter().map(|(k, v)| (*k, v.clone())).collect()
        };

        if all_clients.is_empty() {
            return;
        }

        let pair_opt = inner.selected_pair.lock().clone();

        let remote_addr_for_perm = pair_opt.as_ref().map(|p| p.remote.address);

        for (relay_local_addr, client) in all_clients {
            Self::refresh_one_turn_client(inner, relay_local_addr, &client, remote_addr_for_perm)
                .await;
        }
    }

    async fn refresh_one_turn_client(
        inner: &Arc<IceTransportInner>,
        _relay_local_addr: SocketAddr,
        client: &Arc<TurnClient>,
        remote_addr_opt: Option<SocketAddr>,
    ) {
        async fn send_and_await_inner(
            client: &Arc<TurnClient>,
            inner: &Arc<IceTransportInner>,
            bytes: Vec<u8>,
            tx_id: [u8; 12],
        ) -> Option<StunDecoded> {
            let (tx, rx) = oneshot::channel();
            inner.pending_transactions.lock().insert(tx_id, tx);
            if let Err(e) = client.send(&bytes).await {
                debug!("TURN refresh send failed: {}", e);
                inner.pending_transactions.lock().remove(&tx_id);
                return None;
            }
            match timeout(Duration::from_secs(5), rx).await {
                Ok(Ok(msg)) => Some(msg),
                _ => {
                    inner.pending_transactions.lock().remove(&tx_id);
                    None
                }
            }
        }

        let client = client;

        // 1. Refresh the allocation (extends lifetime).
        //    On 401/438 update the nonce and retry once.
        'alloc: for attempt in 0..2u8 {
            match client.create_refresh_packet().await {
                Ok((bytes, tx_id)) => {
                    match send_and_await_inner(client, inner, bytes, tx_id).await {
                        Some(msg) if msg.class == StunClass::SuccessResponse => {
                            trace!("TURN allocation refreshed successfully");
                            break 'alloc;
                        }
                        Some(msg)
                            if matches!(msg.error_code, Some(401) | Some(438)) && attempt == 0 =>
                        {
                            // Stale nonce: update and retry
                            if let (Some(realm), Some(nonce)) = (msg.realm, msg.nonce) {
                                debug!(
                                    "TURN Refresh got {}: updating nonce, retrying",
                                    msg.error_code.unwrap()
                                );
                                client.update_nonce(realm, nonce).await;
                            }
                            continue 'alloc;
                        }
                        Some(msg) => {
                            debug!("TURN Refresh failed: error={:?}", msg.error_code);
                        }
                        None => {
                            debug!("TURN Refresh timeout or send error");
                        }
                    }
                }
                Err(e) => debug!("TURN Refresh packet creation failed: {}", e),
            }
            break;
        }

        // 2. Refresh permission for the remote peer (if known).
        //    This keeps the relay→peer path warm even when the selected pair uses a
        //    host/srflx candidate, so that the relay path is available as a fallback.
        if let Some(remote_addr) = remote_addr_opt {
            'perm: for attempt in 0..2u8 {
                match client.create_permission_packet(remote_addr).await {
                    Ok((bytes, tx_id)) => {
                        match send_and_await_inner(client, inner, bytes, tx_id).await {
                            Some(msg) if msg.class == StunClass::SuccessResponse => {
                                trace!("TURN permission refreshed for {}", remote_addr);
                                break 'perm;
                            }
                            Some(msg)
                                if matches!(msg.error_code, Some(401) | Some(438))
                                    && attempt == 0 =>
                            {
                                if let (Some(realm), Some(nonce)) = (msg.realm, msg.nonce) {
                                    debug!(
                                        "TURN CreatePermission got {}: updating nonce, retrying",
                                        msg.error_code.unwrap()
                                    );
                                    client.update_nonce(realm, nonce).await;
                                }
                                continue 'perm;
                            }
                            Some(msg) => {
                                debug!(
                                    "TURN CreatePermission refresh failed: error={:?}",
                                    msg.error_code
                                );
                            }
                            None => {
                                debug!("TURN CreatePermission refresh timeout or send error");
                            }
                        }
                    }
                    Err(e) => debug!("TURN CreatePermission packet creation failed: {}", e),
                }
                break;
            }
        }

        // 3. Refresh channel bindings for all bound peers.
        //    On 401/438 update the nonce and retry once per channel.
        let bound_peers = client.bound_peers().await;
        let num_bindings = bound_peers.len();
        for peer in bound_peers {
            if let Some(channel) = client.get_channel(peer).await {
                'chan: for attempt in 0..2u8 {
                    match client.create_channel_rebind_packet(peer, channel).await {
                        Ok((bytes, tx_id)) => {
                            match send_and_await_inner(client, inner, bytes, tx_id).await {
                                Some(msg) if msg.class == StunClass::SuccessResponse => {
                                    trace!(
                                        "TURN ChannelBind refreshed: {} -> ch {}",
                                        peer, channel
                                    );
                                    break 'chan;
                                }
                                Some(msg)
                                    if matches!(msg.error_code, Some(401) | Some(438))
                                        && attempt == 0 =>
                                {
                                    if let (Some(realm), Some(nonce)) = (msg.realm, msg.nonce) {
                                        debug!(
                                            "TURN ChannelBind got {}: updating nonce, retrying ch {}",
                                            msg.error_code.unwrap(),
                                            channel
                                        );
                                        client.update_nonce(realm, nonce).await;
                                    }
                                    continue 'chan;
                                }
                                Some(msg) => {
                                    debug!(
                                        "TURN ChannelBind refresh failed: ch={} error={:?}",
                                        channel, msg.error_code
                                    );
                                }
                                None => {
                                    debug!(
                                        "TURN ChannelBind refresh timeout or send error: ch={}",
                                        channel
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            debug!("TURN ChannelBind refresh packet creation failed: {}", e);
                        }
                    }
                    break;
                }
            }
        }

        debug!(
            "TURN refresh done: allocation + {} permission + {} channel bindings",
            if remote_addr_opt.is_some() { 1 } else { 0 },
            num_bindings
        );
    }
}

impl IceTransport {
    pub fn new(config: RtcConfiguration) -> (Self, impl std::future::Future<Output = ()> + Send) {
        let (candidate_tx, _) = broadcast::channel(100);
        let (socket_tx, socket_rx) = tokio::sync::mpsc::unbounded_channel();
        let gatherer = IceGatherer::new(config.clone(), candidate_tx.clone(), socket_tx);
        let (state_tx, state_rx) = watch::channel(IceTransportState::New);
        let runner_state_rx = state_tx.subscribe();
        let (gathering_state_tx, _) = watch::channel(IceGathererState::New);
        let (selected_socket_tx, selected_socket_rx) = watch::channel(None);
        let (selected_pair_tx, selected_pair_rx) = watch::channel(None);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (nomination_complete_tx, nomination_complete_rx) = watch::channel(None);

        let inner = IceTransportInner {
            state: state_tx,
            _state_rx_keeper: state_rx,
            gathering_state: gathering_state_tx,
            role: parking_lot::Mutex::new(IceRole::Controlled),
            selected_pair: parking_lot::Mutex::new(None),
            local_candidates: Mutex::new(Vec::new()),
            remote_candidates: parking_lot::Mutex::new(Vec::new()),
            gather_state: parking_lot::Mutex::new(IceGathererState::New),
            config: config.clone(),
            gatherer,
            local_parameters: parking_lot::Mutex::new(IceParameters::generate()),
            remote_parameters: parking_lot::Mutex::new(None),
            pending_transactions: parking_lot::Mutex::new(HashMap::new()),
            data_receiver: parking_lot::Mutex::new(None),
            buffered_packets: parking_lot::Mutex::new(VecDeque::new()),
            selected_socket: selected_socket_tx,
            _socket_rx_keeper: selected_socket_rx,
            selected_pair_notifier: selected_pair_tx,
            _selected_pair_rx_keeper: selected_pair_rx,
            last_received: parking_lot::Mutex::new(Instant::now()),
            candidate_tx: candidate_tx.clone(),
            cmd_tx,
            checking_pairs: Mutex::new(std::collections::HashSet::new()),
            nomination_complete: nomination_complete_tx,
            _nomination_complete_rx: nomination_complete_rx,
            buffer_stats: Arc::new(BufferStats::default()),
        };
        let inner = Arc::new(inner);

        let runner = IceTransportRunner {
            inner: inner.clone(),
            socket_rx,
            candidate_rx: candidate_tx.subscribe(),
            cmd_rx,
            state_rx: runner_state_rx,
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

    /// Subscribe to the nomination-complete signal.
    /// Yields `Some(true)` when nomination succeeds, `Some(false)` when it fails.
    /// The controlled side yields `Some(true)` immediately (it has no nomination to perform).
    pub fn subscribe_nomination_complete(&self) -> watch::Receiver<Option<bool>> {
        self.inner.nomination_complete.subscribe()
    }
    pub fn gather_state(&self) -> IceGathererState {
        self.inner.gatherer.state()
    }

    pub async fn role(&self) -> IceRole {
        *self.inner.role.lock()
    }

    pub fn local_candidates(&self) -> Vec<IceCandidate> {
        self.inner.gatherer.local_candidates()
    }

    pub fn remote_candidates(&self) -> Vec<IceCandidate> {
        self.inner.remote_candidates.lock().clone()
    }

    pub fn local_parameters(&self) -> IceParameters {
        self.inner.local_parameters.lock().clone()
    }

    pub fn set_remote_parameters(&self, params: IceParameters) {
        *self.inner.remote_parameters.lock() = Some(params);
    }

    fn start_keepalive(&self) {
        // Handled by runner
    }

    pub fn start_gathering(&self) -> Result<()> {
        {
            let mut state = self.inner.gather_state.lock();
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
            let mut params = self.inner.remote_parameters.lock();
            *params = Some(remote);
        }
        if let Err(e) = self.inner.state.send(IceTransportState::Checking) {
            debug!("start: failed to set state to Checking: {}", e);
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

        *self.inner.selected_pair.lock() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
        let _ = self.inner.state.send(IceTransportState::Connected);
        Ok(())
    }

    /// Set up a direct UDP socket for RTP mode without any ICE gathering,
    /// STUN lookups, or connectivity checks.
    /// Binds a single socket, registers it, and marks the transport as connected.
    pub async fn setup_direct_rtp(&self, remote_addr: SocketAddr) -> Result<SocketAddr> {
        let bind_ip = if let Some(bind_ip_str) = &self.inner.config.bind_ip {
            bind_ip_str.parse::<IpAddr>().unwrap_or_else(|_| {
                get_local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            })
        } else if let Ok(ip) = get_local_ip() {
            ip
        } else {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };

        let socket = self.inner.gatherer.bind_socket(bind_ip).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        // Store the socket
        self.inner.gatherer.sockets.lock().push(socket.clone());

        // Register the socket wrapper for the read loop (handled by runner)
        let _ = self
            .inner
            .gatherer
            .socket_tx
            .send(IceSocketWrapper::Udp(socket.clone()));

        // Build a local candidate for SDP generation
        let mut cand_addr = local_addr;
        let mut upnp_external_addr = None;

        // Try UPnP if enabled (for RTP mode behind NAT)
        if self.inner.config.enable_upnp && !local_addr.ip().is_loopback() && !local_addr.is_ipv6()
        {
            let mut mapper = UpnpPortMapper::with_lease_duration(
                local_addr,
                self.inner.config.upnp_lease_duration,
            );
            if let Err(e) = mapper.discover().await {
                trace!("UPnP discovery failed for RTP mode: {}", e);
            } else if let Ok(ext_addr) = mapper.add_mapping(0).await {
                debug!(
                    "UPnP mapping created for RTP mode: {} -> {}",
                    local_addr, ext_addr
                );
                cand_addr.set_ip(ext_addr.ip());
                cand_addr.set_port(ext_addr.port());
                upnp_external_addr = Some(ext_addr);
                self.inner.gatherer.upnp_mappers.lock().push(mapper);
            } else {
                debug!("UPnP mapping failed for RTP mode, using local address");
            }
        }

        // Fall back to external_ip config if UPnP not available
        if upnp_external_addr.is_none() {
            if let Some(ext_ip) = &self.inner.config.external_ip {
                if let Ok(parsed_ip) = ext_ip.parse::<IpAddr>() {
                    if !bind_ip.is_loopback() {
                        cand_addr.set_ip(parsed_ip);
                    }
                }
            } else if bind_ip.is_unspecified() {
                if let Ok(local_ip) = get_local_ip() {
                    cand_addr.set_ip(local_ip);
                }
            }
        }
        let mut local_candidate = IceCandidate::host(cand_addr, 1);
        if cand_addr != local_addr {
            local_candidate.related_address = Some(local_addr);
        }
        self.inner.gatherer.push_candidate(local_candidate.clone());

        // Set gathering as complete
        *self.inner.gatherer.state.lock() = IceGathererState::Complete;
        let _ = self.inner.gathering_state.send(IceGathererState::Complete);

        // Set up the selected pair
        let remote_candidate = IceCandidate::host(remote_addr, 1);
        let pair = IceCandidatePair::new(local_candidate, remote_candidate);
        *self.inner.selected_pair.lock() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair));
        let _ = self
            .inner
            .selected_socket
            .send(Some(IceSocketWrapper::Udp(socket)));
        let _ = self.inner.state.send(IceTransportState::Connected);

        Ok(cand_addr)
    }

    /// Set up a direct UDP socket for RTP mode (offer side, no remote addr yet).
    /// Binds a socket and registers the local candidate, but does NOT set the
    /// selected pair or transition to Connected.
    pub async fn setup_direct_rtp_offer(&self) -> Result<SocketAddr> {
        let bind_ip = if let Some(bind_ip_str) = &self.inner.config.bind_ip {
            bind_ip_str.parse::<IpAddr>().unwrap_or_else(|_| {
                get_local_ip().unwrap_or(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED))
            })
        } else if let Ok(ip) = get_local_ip() {
            ip
        } else {
            IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
        };

        let socket = self.inner.gatherer.bind_socket(bind_ip).await?;
        let local_addr = socket.local_addr()?;
        let socket = Arc::new(socket);

        self.inner.gatherer.sockets.lock().push(socket.clone());
        let _ = self
            .inner
            .gatherer
            .socket_tx
            .send(IceSocketWrapper::Udp(socket));

        let mut cand_addr = local_addr;
        let mut upnp_external_addr = None;

        // Try UPnP if enabled (for RTP mode behind NAT)
        if self.inner.config.enable_upnp && !local_addr.ip().is_loopback() && !local_addr.is_ipv6()
        {
            let mut mapper = UpnpPortMapper::with_lease_duration(
                local_addr,
                self.inner.config.upnp_lease_duration,
            );
            if let Err(e) = mapper.discover().await {
                trace!("UPnP discovery failed for RTP offer mode: {}", e);
            } else if let Ok(ext_addr) = mapper.add_mapping(0).await {
                debug!(
                    "UPnP mapping created for RTP offer mode: {} -> {}",
                    local_addr, ext_addr
                );
                cand_addr.set_ip(ext_addr.ip());
                cand_addr.set_port(ext_addr.port());
                upnp_external_addr = Some(ext_addr);
                self.inner.gatherer.upnp_mappers.lock().push(mapper);
            } else {
                debug!("UPnP mapping failed for RTP offer mode, using local address");
            }
        }

        // Fall back to external_ip config if UPnP not available
        if upnp_external_addr.is_none() {
            if let Some(ext_ip) = &self.inner.config.external_ip {
                if let Ok(parsed_ip) = ext_ip.parse::<IpAddr>() {
                    if !bind_ip.is_loopback() {
                        cand_addr.set_ip(parsed_ip);
                    }
                }
            } else if bind_ip.is_unspecified() {
                if let Ok(local_ip) = get_local_ip() {
                    cand_addr.set_ip(local_ip);
                }
            }
        }
        let mut local_candidate = IceCandidate::host(cand_addr, 1);
        if cand_addr != local_addr {
            local_candidate.related_address = Some(local_addr);
        }
        self.inner.gatherer.push_candidate(local_candidate);

        *self.inner.gatherer.state.lock() = IceGathererState::Complete;
        let _ = self.inner.gathering_state.send(IceGathererState::Complete);

        Ok(cand_addr)
    }

    /// Complete the RTP direct connection by setting the remote address.
    /// Call after setup_direct_rtp_offer when the answer arrives with the remote address.
    pub fn complete_direct_rtp(&self, remote_addr: SocketAddr) {
        let remote_candidate = IceCandidate::host(remote_addr, 1);
        let local_candidate = self
            .inner
            .gatherer
            .local_candidates()
            .into_iter()
            .next()
            .unwrap_or_else(|| {
                IceCandidate::host(
                    SocketAddr::new(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 0),
                    1,
                )
            });
        let pair = IceCandidatePair::new(local_candidate, remote_candidate);
        *self.inner.selected_pair.lock() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket));
        }
        let _ = self.inner.state.send(IceTransportState::Connected);
    }

    pub fn stop(&self) {
        let _ = self.inner.state.send(IceTransportState::Closed);
        let _ = self.inner.selected_socket.send(None);
        let _ = self.inner.selected_pair_notifier.send(None);
        *self.inner.selected_pair.lock() = None;
        self.inner.gatherer.sockets.lock().clear();
        self.inner.gatherer.turn_clients.lock().clear();
    }

    pub fn set_role(&self, role: IceRole) {
        *self.inner.role.lock() = role;
    }

    pub fn add_remote_candidate(&self, candidate: IceCandidate) {
        let mut list = self.inner.remote_candidates.lock();
        list.push(candidate);
        drop(list);
        self.try_connectivity_checks();
    }

    pub fn select_pair(&self, pair: IceCandidatePair) {
        *self.inner.selected_pair.lock() = Some(pair.clone());
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
        let pair = self.inner.selected_pair.lock().clone()?;
        if pair.local.typ == IceCandidateType::Relay {
            let clients = self.inner.gatherer.turn_clients.lock();
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
        self.inner.selected_pair.lock().clone()
    }

    pub async fn set_data_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        {
            let mut rx_lock = self.inner.data_receiver.lock();
            *rx_lock = Some(receiver.clone());
        }

        let packets: Vec<_> = {
            let mut buffer = self.inner.buffered_packets.lock();
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

    // If we already have a selected pair, don't run more checks
    if inner.selected_pair.lock().is_some() {
        return;
    }

    let locals = inner.gatherer.local_candidates();
    let remotes = inner.remote_candidates.lock().clone();
    let role = *inner.role.lock();

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
            if local.address.is_ipv4() != remote.address.is_ipv4() {
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
            // Check if another concurrent check already selected a pair
            {
                let existing = inner.selected_pair.lock();
                if existing.is_some() {
                    debug!(
                        "ICE: Ignoring pair {} -> {} (already have selected pair)",
                        pair.local.address, pair.remote.address
                    );
                    success = true;
                    break;
                }
            }
            *inner.selected_pair.lock() = Some(pair.clone());
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
                    let result = perform_binding_check(
                        &pair_clone.local,
                        &pair_clone.remote,
                        &inner_clone,
                        role,
                        true,
                    )
                    .await;
                    match &result {
                        Ok(_) => {
                            debug!(
                                "Nomination succeeded: {} -> {}",
                                pair_clone.local.address, pair_clone.remote.address
                            );
                            let _ = inner_clone.nomination_complete.send(Some(true));
                        }
                        Err(e) => {
                            debug!("Failed to send nomination: {}", e);
                            let _ = inner_clone.nomination_complete.send(Some(false));
                        }
                    }
                });
            } else {
                // Controlled side: nomination_complete is signalled when we
                // receive USE-CANDIDATE from the controlling agent (see the
                // handle_stun_binding_request path below).  Do NOT signal here —
                // firing early causes DTLS to start before the controlling side
                // has finished its nomination binding check, creating a timing
                // gap that can exceed `nomination_timeout` (10 s in production).
            }

            break;
        }
    }

    if !success {
        let state = *inner.state.borrow();
        let has_selected_pair = inner.selected_pair.lock().is_some();
        // Only set Failed if we're not already connected AND we don't have a working pair
        if state != IceTransportState::Connected && !has_selected_pair {
            let _ = inner.state.send(IceTransportState::Failed);
        }
    }
}

fn resolve_socket(inner: &IceTransportInner, pair: &IceCandidatePair) -> Option<IceSocketWrapper> {
    if pair.local.typ == IceCandidateType::Relay {
        let clients = inner.gatherer.turn_clients.lock();
        clients
            .get(&pair.local.address)
            .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
    } else {
        let socket = inner.gatherer.get_socket(pair.local.base_address());
        if socket.is_none() {
            debug!(
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
    if should_drop_packet() {
        return;
    }
    {
        *inner.last_received.lock() = Instant::now();
    }
    let b = packet[0];
    if b < 2 {
        // STUN
        match StunMessage::decode(packet) {
            Ok(msg) => {
                if msg.class == StunClass::Request {
                    // Always respond to STUN Binding Requests on any transport mode
                    // (RFC 5389 compliance). Sending a Binding Response lets the remote
                    // peer (e.g. Linphone) confirm the media port is reachable even when
                    // it sends a STUN probe before its first real RTP packet.
                    //
                    // Address latching (updating the selected pair's remote IP based on
                    // the incoming source) is a separate concern gated by
                    // `enable_latching` inside handle_stun_request — it is NOT the same
                    // as "should we even reply to this STUN message".
                    handle_stun_request(&sender, &msg, addr, inner).await;
                } else if msg.class == StunClass::SuccessResponse {
                    let mut map = inner.pending_transactions.lock();
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
                    debug!(
                        "Received STUN Error Response from {}: {:?}",
                        addr, msg.error_code
                    );
                    if let Some(code) = msg.error_code {
                        if code == 401 {
                            let remote_params = inner.remote_parameters.lock().clone();
                            debug!(
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
        let receiver = inner.data_receiver.lock().clone();
        if let Some(rx) = receiver {
            rx.receive(Bytes::copy_from_slice(packet), addr).await;
        } else {
            let mut buffer = inner.buffered_packets.lock();
            let stats = inner.buffer_stats.clone();
            let capacity = inner.config.rtp_buffer_capacity;

            stats.packets_received.fetch_add(1, Ordering::Relaxed);

            if buffer.len() >= capacity {
                match inner.config.buffer_drop_strategy {
                    BufferDropStrategy::DropOldest => {
                        buffer.pop_front();
                        buffer.push_back((packet.to_vec(), addr));
                    }
                    BufferDropStrategy::DropNew => {
                        debug!("Buffer full, dropping packet from {}", addr);
                    }
                }
                stats.packets_dropped.fetch_add(1, Ordering::Relaxed);
            } else {
                buffer.push_back((packet.to_vec(), addr));
            }

            // Update statistics
            let current_size = buffer.len() as u32;
            stats.current_size.store(current_size, Ordering::Relaxed);

            // Track peak size
            let mut peak = stats.peak_size.load(Ordering::Relaxed);
            while current_size > peak {
                match stats.peak_size.compare_exchange_weak(
                    peak,
                    current_size,
                    Ordering::Relaxed,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(current) => peak = current,
                }
            }

            // Periodic logging
            let mut last_log = stats.last_log_time.lock();
            if last_log.elapsed() >= inner.config.buffer_stats_log_interval {
                let received = stats.packets_received.load(Ordering::Relaxed);
                let dropped = stats.packets_dropped.load(Ordering::Relaxed);
                let peak_size = stats.peak_size.load(Ordering::Relaxed);
                debug!(
                    "Buffer stats: received={}, dropped={}, current={}, peak={}, capacity={}",
                    received, dropped, current_size, peak_size, capacity
                );
                *last_log = Instant::now();
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

    let password = inner.local_parameters.lock().password.clone();
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
                                debug!("Failed to send STUN Response to {}: {}", addr, e);
                            }
                        }
                    }
                } else {
                    debug!("Failed to send STUN Response to {}: {}", addr, e);
                }
            }
        }
    } else {
        debug!("Failed to encode STUN Response");
    }

    // Check if we know this candidate
    let mut known = false;
    {
        let remotes = inner.remote_candidates.lock();
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
        candidate.foundation = IceCandidate::compute_foundation(
            IceCandidateType::PeerReflexive,
            candidate.base_address(),
            "udp",
        );
        candidate.priority = IceCandidate::priority_for(IceCandidateType::PeerReflexive, 1);

        let mut list = inner.remote_candidates.lock();
        list.push(candidate);
        drop(list);

        let _ = inner.cmd_tx.send(IceCommand::RunChecks);
    }
    if inner.config.enable_latching {
        let current_pair = inner.selected_pair.lock().clone();
        if let Some(pair) = current_pair {
            if pair.remote.address.port() == addr.port() && pair.remote.address.ip() != addr.ip() {
                debug!(
                    "RTP latching: updating remote address from {} to {}",
                    pair.remote.address, addr
                );
                let mut new_remote = pair.remote.clone();
                new_remote.address = addr;
                let new_pair = IceCandidatePair::new(pair.local.clone(), new_remote);
                *inner.selected_pair.lock() = Some(new_pair.clone());
                let _ = inner.selected_pair_notifier.send(Some(new_pair.clone()));
                if let Some(socket) = resolve_socket(&inner, &new_pair) {
                    let _ = inner.selected_socket.send(Some(socket));
                }
            }
        }
    }

    if msg.use_candidate {
        let role = *inner.role.lock();
        if role == IceRole::Controlled {
            // RFC 8445 §7.3.1.5: once a pair is already nominated, subsequent
            // USE-CANDIDATE (e.g. keepalives from other candidates) must not
            // trigger re-nomination.  Guard here to prevent pair_monitor churn.
            if inner.selected_pair.lock().is_some() {
                // Pair was selected via connectivity checks before USE-CANDIDATE arrived.
                // Still need to signal nomination_complete if not done yet — otherwise
                // peer_connection waits the full nomination_timeout (10 s) before DTLS.
                if inner.nomination_complete.borrow().is_none() {
                    trace!(
                        "Controlled agent: pair already selected, signalling nomination_complete via UseCandidate from {}",
                        addr
                    );
                    let _ = inner.nomination_complete.send(Some(true));
                } else {
                    trace!(
                        "Controlled agent ignoring UseCandidate from {} – pair already nominated",
                        addr
                    );
                }
            } else {
                let local_addr = match sender {
                    IceSocketWrapper::Udp(s) => s
                        .local_addr()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                    IceSocketWrapper::Turn(_, addr) => *addr,
                };

                let locals = inner.gatherer.local_candidates();
                let local_cand = locals.iter().find(|c| c.base_address() == local_addr);

                let pair = {
                    let remotes = inner.remote_candidates.lock();
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
                    *inner.selected_pair.lock() = Some(pair.clone());
                    let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
                    if let Some(socket) = resolve_socket(&inner, &pair) {
                        let _ = inner.selected_socket.send(Some(socket));
                    }
                    let _ = inner.state.send(IceTransportState::Connected);
                    // Controlled side: nomination is decided by the controlling agent;
                    // once we receive USE-CANDIDATE, our "nomination" is complete.
                    let _ = inner.nomination_complete.send(Some(true));
                } else {
                    debug!(
                        "Received UseCandidate but could not find pair for {} -> {}; \
                         signalling nomination_complete=Some(true) as fallback",
                        local_addr, addr
                    );
                    // Fallback: USE-CANDIDATE arrived before ICE checks completed
                    // (pair not yet in remote_candidates).  Signal nomination complete
                    // so peer_connection is not stuck waiting forever.
                    let _ = inner.nomination_complete.send(Some(true));
                }
            }
        }
    }
}

struct TransactionGuard<'a> {
    map: &'a parking_lot::Mutex<HashMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    tx_id: [u8; 12],
}

impl<'a> Drop for TransactionGuard<'a> {
    fn drop(&mut self) {
        // debug!("TransactionGuard: dropping tx={:?}", self.tx_id);
        let mut map = self.map.lock();
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

    let local_params = inner.local_parameters.lock().clone();
    let remote_params = match inner.remote_parameters.lock().clone() {
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
        let mut map = inner.pending_transactions.lock();
        map.insert(tx_id, tx);
    }

    // Ensure transaction is removed when this future is dropped
    let _guard = TransactionGuard {
        map: &inner.pending_transactions,
        tx_id,
    };

    let (socket, turn_client) = if local.typ == IceCandidateType::Relay {
        let gatherer = &inner.gatherer;
        let clients = gatherer.turn_clients.lock();
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
            let mut map = inner.pending_transactions.lock();
            map.insert(perm_tx_id, perm_tx);
        }

        trace!("Sending CreatePermission to TURN server");
        if let Err(e) = client.send(&perm_bytes).await {
            debug!("CreatePermission send failed: {}", e);
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
                            let mut map = inner.pending_transactions.lock();
                            map.insert(bind_tx_id, bind_tx);
                        }

                        if let Ok(_) = client.send(&bind_bytes).await {
                            let client_clone = client.clone();
                            let remote_addr = remote.address;
                            let inner_weak = Arc::downgrade(&inner);
                            let timeout_dur = inner.config.stun_timeout;

                            match timeout(timeout_dur, bind_rx).await {
                                Ok(Ok(msg)) => {
                                    if msg.class == StunClass::SuccessResponse {
                                        client_clone.add_channel(remote_addr, channel_num).await;
                                        debug!(
                                            "TURN ChannelBound: {} -> {}",
                                            remote_addr, channel_num
                                        );
                                    }
                                }
                                _ => {
                                    // Timeout or error: clean up pending transaction
                                    if let Some(inner) = inner_weak.upgrade() {
                                        let mut map = inner.pending_transactions.lock();
                                        map.remove(&bind_tx_id);
                                    }
                                }
                            }
                        }
                    }
                }
            }
            _ => {
                let mut map = inner.pending_transactions.lock();
                map.remove(&perm_tx_id);
                bail!("CreatePermission timeout");
            }
        }
    } else if socket.is_none() {
        bail!("no socket found for local candidate");
    }

    let start = Instant::now();
    let mut rto = Duration::from_millis(500);
    let max_timeout = if nominated {
        inner.config.nomination_timeout
    } else {
        inner.config.stun_timeout
    };

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
                let is_fatal = matches!(
                    e.kind(),
                    std::io::ErrorKind::BrokenPipe
                        | std::io::ErrorKind::ConnectionReset
                        | std::io::ErrorKind::NotConnected
                );
                if is_fatal {
                    debug!(
                        "socket.send_to {} fatal error, aborting nomination: {}",
                        remote.address, e
                    );
                    return Err(e.into());
                }
                // Transient error (e.g., EHOSTUNREACH / os error 65 during route setup).
                // Treat as a dropped send — wait for next RTO and retry.
                debug!(
                    "socket.send_to {} transient error, will retry: {}",
                    remote.address, e
                );
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
    fn compute_foundation(typ: IceCandidateType, base_addr: SocketAddr, transport: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        typ.hash(&mut hasher);
        base_addr.ip().hash(&mut hasher);
        transport.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }

    pub fn host(address: SocketAddr, component: u16) -> Self {
        Self {
            foundation: Self::compute_foundation(IceCandidateType::Host, address, "udp"),
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
            foundation: Self::compute_foundation(IceCandidateType::ServerReflexive, base, "udp"),
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
            foundation: Self::compute_foundation(IceCandidateType::Relay, mapped, transport),
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
            debug!("ICE gather failed: {}", err);
        }
        (transport, runner)
    }
}

#[derive(Debug, Clone)]
struct IceGatherer {
    state: Arc<parking_lot::Mutex<IceGathererState>>,
    local_candidates: Arc<parking_lot::Mutex<Vec<IceCandidate>>>,
    sockets: Arc<parking_lot::Mutex<Vec<Arc<UdpSocket>>>>,
    turn_clients: Arc<parking_lot::Mutex<HashMap<SocketAddr, Arc<TurnClient>>>>,
    upnp_mappers: Arc<parking_lot::Mutex<Vec<UpnpPortMapper>>>,
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
            state: Arc::new(parking_lot::Mutex::new(IceGathererState::New)),
            local_candidates: Arc::new(parking_lot::Mutex::new(Vec::new())),
            sockets: Arc::new(parking_lot::Mutex::new(Vec::new())),
            turn_clients: Arc::new(parking_lot::Mutex::new(HashMap::new())),
            upnp_mappers: Arc::new(parking_lot::Mutex::new(Vec::new())),
            config,
            candidate_tx,
            socket_tx,
        }
    }

    /// Get the UPnP mappers for manual cleanup
    #[allow(dead_code)]
    pub fn upnp_mappers(&self) -> Arc<parking_lot::Mutex<Vec<UpnpPortMapper>>> {
        self.upnp_mappers.clone()
    }

    /// Clean up all UPnP port mappings
    #[allow(dead_code)]
    pub async fn cleanup_upnp_mappings(&self) {
        let mappers = self.upnp_mappers.lock().clone();
        for mapper in mappers {
            if let Err(e) = mapper.cleanup().await {
                trace!("Failed to clean up UPnP mappings: {}", e);
            }
        }
        self.upnp_mappers.lock().clear();
    }

    fn state(&self) -> IceGathererState {
        *self.state.lock()
    }

    fn local_candidates(&self) -> Vec<IceCandidate> {
        self.local_candidates.lock().clone()
    }

    async fn bind_socket(&self, ip: IpAddr) -> Result<UdpSocket> {
        if let (Some(start), Some(end)) = (self.config.rtp_start_port, self.config.rtp_end_port) {
            let start = start.saturating_add(start % 2);
            let end = end - (end % 2);

            if start > end {
                bail!("No usable even RTP ports in range {}..={}", start, end);
            }

            let port_count = (((end - start) / 2) + 1) as u64;
            let start_index = (random_u64() % port_count) as u16;
            let mut port = start + (start_index * 2);

            for _ in 0..port_count {
                match UdpSocket::bind(SocketAddr::new(ip, port)).await {
                    Ok(socket) => return Ok(socket),
                    Err(_) => {
                        port = port.saturating_add(2);
                        if port > end {
                            port = start;
                        }
                    }
                }
            }
            bail!("No available even RTP ports in range {}..={}", start, end)
        } else {
            UdpSocket::bind(SocketAddr::new(ip, 0))
                .await
                .map_err(|e| anyhow!(e))
        }
    }

    fn get_socket(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        let sockets = self.sockets.lock();
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
            let mut state = self.state.lock();
            if *state == IceGathererState::Complete {
                return Ok(());
            }
            *state = IceGathererState::Gathering;
        }

        // Host gathering must complete first (creates sockets)
        let host_fut = async {
            if self.config.ice_transport_policy == IceTransportPolicy::All {
                if let Err(e) = self.gather_host_candidates().await {
                    debug!("Host gathering failed: {}", e);
                }
            }
        };

        host_fut.await;

        // STUN must complete before UPnP so we can detect double-NAT
        // and use STUN's public IP for UPnP candidates
        let stun_public_ip = if self.config.enable_upnp {
            self.gather_servers_and_get_public_ip().await
        } else {
            if let Err(e) = self.gather_servers().await {
                debug!("Server gathering failed: {}", e);
            }
            None
        };

        // UPnP depends on host sockets and optionally STUN's public IP
        if self.config.enable_upnp && self.config.ice_transport_policy == IceTransportPolicy::All {
            if let Err(e) = self.gather_upnp_candidates(stun_public_ip).await {
                debug!("UPnP gathering failed: {}", e);
            }
        }

        *self.state.lock() = IceGathererState::Complete;
        Ok(())
    }

    async fn gather_host_candidates(&self) -> Result<()> {
        let mut bind_ips = Vec::new();

        if let Some(bind_ip_str) = &self.config.bind_ip {
            if let Ok(ip) = bind_ip_str.parse::<IpAddr>() {
                bind_ips.push(ip);
            }
        } else if self.config.transport_mode != crate::TransportMode::WebRtc {
            // Non-WebRTC mode: prefer a LAN IP if available.
            // Binding to 0.0.0.0 on macOS can lead to "No route to host" (os error 65)
            // if the destination is on a LAN segment but the OS picks a wrong default interface.
            if let Ok(ip) = get_local_ip() {
                bind_ips.push(ip);
            } else {
                bind_ips.push(IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
            }
        } else {
            // Default: bind to loopback and all LAN IPs
            bind_ips.push(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));

            use local_ip_address::list_afinet_netifas;
            if let Ok(interfaces) = list_afinet_netifas() {
                for (name, addr) in interfaces {
                    if let IpAddr::V4(ip) = addr {
                        if !ip.is_loopback() && !bind_ips.contains(&IpAddr::V4(ip)) {
                            // Skip common virtual interface prefixes
                            if name.starts_with("utun")
                                || name.starts_with("gif")
                                || name.starts_with("stf")
                                || name.starts_with("awdl")
                                || name.starts_with("llw")
                            {
                                continue;
                            }
                            bind_ips.push(IpAddr::V4(ip));
                        }
                    }
                }
            }
        }

        for ip in bind_ips {
            match self.bind_socket(ip).await {
                Ok(socket) => {
                    if let Ok(addr) = socket.local_addr() {
                        let socket = Arc::new(socket);
                        self.sockets.lock().push(socket.clone());
                        let _ = self.socket_tx.send(IceSocketWrapper::Udp(socket));

                        if let Some(ext_ip) = &self.config.external_ip
                            && let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
                        {
                            if !ip.is_loopback() {
                                let mut ext_addr = addr;
                                ext_addr.set_ip(parsed_ip);
                                let mut cand = IceCandidate::host(ext_addr, 1);
                                cand.related_address = Some(addr);
                                self.push_candidate(cand);
                            } else {
                                self.push_candidate(IceCandidate::host(addr, 1));
                            }
                        } else if ip.is_unspecified() {
                            // If bound to 0.0.0.0 and no external_ip, try to find a reachable local IP for the candidate
                            let mut cand_addr = addr;
                            if let Ok(local_ip) = get_local_ip() {
                                cand_addr.set_ip(local_ip);
                            }
                            let mut cand = IceCandidate::host(cand_addr, 1);
                            cand.related_address = Some(addr);
                            self.push_candidate(cand);
                        } else {
                            self.push_candidate(IceCandidate::host(addr, 1));
                        }
                    }
                }
                Err(e) => {
                    if self.config.bind_ip.is_some() {
                        debug!("Failed to bind to requested bind_ip {}: {}", ip, e);
                    } else if !ip.is_loopback() && !ip.is_unspecified() {
                        debug!("Failed to bind socket on {}: {}", ip, e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn gather_upnp_candidates(&self, stun_public_ip: Option<IpAddr>) -> Result<()> {
        let sockets = self.sockets.lock().clone();

        for socket in sockets {
            let local_addr = match socket.local_addr() {
                Ok(addr) => addr,
                Err(_) => continue,
            };

            // Skip loopback addresses
            if local_addr.ip().is_loopback() {
                continue;
            }

            // Skip IPv6 (UPnP IGD doesn't support IPv6 well)
            if local_addr.is_ipv6() {
                continue;
            }

            // Create mapper with configured lease duration
            let mut mapper =
                UpnpPortMapper::with_lease_duration(local_addr, self.config.upnp_lease_duration);

            // Try to discover gateway
            if let Err(e) = mapper.discover().await {
                trace!("UPnP discovery failed for {}: {}", local_addr, e);
                continue;
            }

            // Try to add port mapping (0 = use same port as local)
            match mapper.add_mapping(0).await {
                Ok(external_addr) => {
                    // Check if UPnP returned a private IP (double-NAT scenario)
                    let is_private = is_private_ip(&external_addr.ip());

                    // Final address for the candidate
                    let candidate_addr = if is_private {
                        if let Some(public_ip) = stun_public_ip {
                            // Double-NAT: use STUN's public IP with UPnP's port
                            let mut addr = external_addr;
                            addr.set_ip(public_ip);
                            debug!(
                                "UPnP double-NAT detected: {} is private, using STUN public IP {} -> {}",
                                external_addr.ip(),
                                public_ip,
                                addr
                            );
                            addr
                        } else {
                            // No STUN public IP available, use as-is (may not work)
                            debug!(
                                "UPnP returned private IP {} but no STUN public IP available",
                                external_addr
                            );
                            external_addr
                        }
                    } else {
                        external_addr
                    };

                    // Create server reflexive candidate for the mapping
                    let candidate = IceCandidate::server_reflexive(local_addr, candidate_addr, 1);
                    self.push_candidate(candidate);

                    // Store mapper for later cleanup
                    self.upnp_mappers.lock().push(mapper);

                    debug!(
                        "UPnP candidate gathered: {} -> {}",
                        local_addr, candidate_addr
                    );
                }
                Err(e) => {
                    debug!("UPnP mapping failed for {}: {}", local_addr, e);
                }
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
                            debug!("invalid ICE server URI {}: {}", url, err);
                            return;
                        }
                    };

                    match uri.kind {
                        IceUriKind::Stun => {
                            if this.config.ice_transport_policy == IceTransportPolicy::All {
                                match this.probe_stun(&uri).await {
                                    Ok(Some(candidate)) => this.push_candidate(candidate),
                                    Ok(None) => {}
                                    Err(e) => debug!("STUN probe failed for {}: {}", url, e),
                                }
                            }
                        }
                        IceUriKind::Turn => match this.probe_turn(&uri, &server).await {
                            Ok(Some(candidate)) => this.push_candidate(candidate),
                            Ok(None) => {}
                            Err(e) => debug!("TURN probe failed for {}: {}", url, e),
                        },
                    }
                });
            }
        }

        while let Some(_) = tasks.next().await {}
        Ok(())
    }

    /// Gather server candidates and return the first public IP discovered via STUN.
    /// This is used to detect and fix double-NAT scenarios for UPnP.
    async fn gather_servers_and_get_public_ip(&self) -> Option<IpAddr> {
        let mut tasks = FuturesUnordered::new();
        let public_ip: Arc<parking_lot::Mutex<Option<IpAddr>>> =
            Arc::new(parking_lot::Mutex::new(None));

        for server in &self.config.ice_servers {
            for url in &server.urls {
                let server = server.clone();
                let url = url.clone();
                let this = self.clone();
                let public_ip_clone = public_ip.clone();

                tasks.push(async move {
                    let uri = match IceServerUri::parse(&url) {
                        Ok(uri) => uri,
                        Err(err) => {
                            debug!("invalid ICE server URI {}: {}", url, err);
                            return;
                        }
                    };

                    match uri.kind {
                        IceUriKind::Stun => {
                            if this.config.ice_transport_policy == IceTransportPolicy::All {
                                match this.probe_stun(&uri).await {
                                    Ok(Some(candidate)) => {
                                        // Capture public IP if it's not private
                                        if !is_private_ip(&candidate.address.ip()) {
                                            let mut ip = public_ip_clone.lock();
                                            if ip.is_none() {
                                                *ip = Some(candidate.address.ip());
                                            }
                                        }
                                        this.push_candidate(candidate);
                                    }
                                    Ok(None) => {}
                                    Err(e) => debug!("STUN probe failed for {}: {}", url, e),
                                }
                            }
                        }
                        IceUriKind::Turn => match this.probe_turn(&uri, &server).await {
                            Ok(Some(candidate)) => this.push_candidate(candidate),
                            Ok(None) => {}
                            Err(e) => debug!("TURN probe failed for {}: {}", url, e),
                        },
                    }
                });
            }
        }

        while let Some(_) = tasks.next().await {}
        let ip = public_ip.lock().clone();
        if let Some(ip) = &ip {
            debug!("STUN public IP for UPnP double-NAT detection: {}", ip);
        } else {
            debug!("No STUN public IP available for UPnP double-NAT detection");
        }
        ip
    }

    async fn probe_stun(&self, uri: &IceServerUri) -> Result<Option<IceCandidate>> {
        let addr = uri.resolve(self.config.disable_ipv6).await?;

        // Find a suitable host address to bind to (prefer non-loopback IPv4)
        let bind_ip = self
            .local_candidates
            .lock()
            .iter()
            .filter(|c| c.typ == IceCandidateType::Host)
            .filter_map(|c| match c.address.ip() {
                IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() => Some(IpAddr::V4(ip)),
                _ => None,
            })
            .next()
            .unwrap_or(IpAddr::V4(std::net::Ipv4Addr::new(0, 0, 0, 0)));

        let socket = match uri.transport {
            IceTransportProtocol::Udp => self.bind_socket(bind_ip).await?,
            IceTransportProtocol::Tcp => self.bind_socket(bind_ip).await?,
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
            self.sockets.lock().push(socket.clone());
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
        let mut candidates = self.local_candidates.lock();
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

/// Check if an IP address is a private/internal address (not publicly routable)
fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 10.0.0.0/8
            octets[0] == 10
                // 172.16.0.0/12
                || (octets[0] == 172 && (16..=31).contains(&octets[1]))
                // 192.168.0.0/16
                || (octets[0] == 192 && octets[1] == 168)
                // 169.254.0.0/16 (link-local)
                || (octets[0] == 169 && octets[1] == 254)
                // 127.0.0.0/8 (loopback)
                || octets[0] == 127
        }
        IpAddr::V6(ipv6) => {
            // IPv6 unique local fc00::/7
            ipv6.segments()[0] & 0xfe00 == 0xfc00
                // IPv6 link-local fe80::/10
                || ipv6.segments()[0] & 0xffc0 == 0xfe80
                // IPv6 loopback ::1
                || *ipv6 == std::net::Ipv6Addr::LOCALHOST
        }
    }
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
                IceSocketWrapper::Udp(s) => match s.try_send_to(data, addr) {
                    Ok(len) => return Ok(len),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        s.writable().await?;
                        continue;
                    }
                    Err(e) => {
                        if let Some(code) = e.raw_os_error()
                            && code == 55
                        {
                            // ENOBUFS on macOS, wait for writable and retry.
                            s.writable().await?;
                            continue;
                        }
                        let reason = anyhow!("UDP {} -> {} failed: {}", s.local_addr()?, addr, e);
                        return Err(reason);
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
