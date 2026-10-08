pub mod conn;
#[cfg(feature = "std")] // mDNS is excluded from the embedded target
pub mod mdns;
#[cfg(feature = "std")] // ICE-TCP is excluded from the embedded target
pub mod shared_tcp;

/// Placeholder registration (ICE-TCP excluded; never constructed).
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub struct SharedTcpRegistration;
pub mod shared_udp;
pub mod stun;
#[cfg(all(test, feature = "std"))]
mod tests;
pub mod turn;
#[cfg(feature = "std")] // UPnP is excluded from the embedded target
pub mod upnp;

// Re-export UPnP types
#[cfg(feature = "std")]
pub use upnp::{
    DEFAULT_LEASE_DURATION, DEFAULT_UPNP_DISCOVERY_TIMEOUT, MAX_LEASE_DURATION, MIN_LEASE_DURATION,
    UpnpPortMapper,
};

use crate::config::{BufferDropStrategy, IceServer, IceTransportPolicy, RtcConfiguration};
use crate::platform::atomic64::AtomicU64;
use crate::prelude::*;
use crate::transports::ice::turn::{TurnClient, TurnCredentials};
use crate::transports::{PacketReceiver, get_local_ip};
use alloc::collections::{BTreeMap, VecDeque};
use alloc::sync::Arc;
use bytes::Bytes;
use core::net::{IpAddr, SocketAddr};
use core::sync::atomic::AtomicU32;
use core::sync::atomic::Ordering;
use futures::future::BoxFuture;
use futures::stream::{FuturesUnordered, StreamExt};
#[cfg(feature = "std")]
use std::io::ErrorKind;

#[cfg(not(feature = "std"))]
use crate::platform::time::Instant;
use core::time::Duration;
#[cfg(feature = "std")]
use std::time::Instant;

use crate::errors::{RtcError, RtcResult};
#[cfg(feature = "std")]
use crate::platform::net::UdpSocket as NetUdpSocket;
#[cfg(feature = "std")]
use tokio::net::UdpSocket;
#[cfg(feature = "std")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(not(feature = "std"))]
/// Placeholder standing in for the tokio UDP socket on embedded targets:
/// direct-UDP gathering is a std-only path (the target uses Platform
/// sockets via the embedder's adapter). Never constructed.
#[derive(Debug, Clone)]
pub struct UdpSocket;

#[cfg(not(feature = "std"))]
impl UdpSocket {
    pub async fn bind(_addr: SocketAddr) -> RtcResult<Self> {
        unimplemented!("direct UDP sockets are std-only; use Platform sockets (WP3)")
    }
    pub fn local_addr(&self) -> RtcResult<SocketAddr> {
        unimplemented!("direct UDP sockets are std-only")
    }
    pub async fn send_to(&self, _: &[u8], _: SocketAddr) -> RtcResult<usize> {
        unimplemented!("direct UDP sockets are std-only")
    }
    pub async fn recv_from(&self, _: &mut [u8]) -> RtcResult<(usize, SocketAddr)> {
        unimplemented!("direct UDP sockets are std-only")
    }
    pub fn try_send_to(&self, _: &[u8], _: SocketAddr) -> RtcResult<usize> {
        unimplemented!("direct UDP sockets are std-only")
    }
    pub async fn writable(&self) -> RtcResult<()> {
        unimplemented!("direct UDP sockets are std-only")
    }
    pub fn diag(&self) -> SocketAddr {
        unimplemented!("direct UDP sockets are std-only")
    }
}

/// Placeholder for the tokio TcpStream on embedded targets: ICE-TCP is
/// excluded there. Never constructed.
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub struct TcpStream;

#[cfg(not(feature = "std"))]
impl TcpStream {
    pub async fn connect(_addr: SocketAddr) -> RtcResult<Self> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
    pub fn local_addr(&self) -> RtcResult<SocketAddr> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
    pub fn set_nodelay(&self, _: bool) -> RtcResult<()> {
        Ok(())
    }
    pub async fn write_all(&self, _: &[u8]) -> RtcResult<()> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
    pub async fn read_exact(&self, _: &mut [u8]) -> RtcResult<()> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
    pub fn into_split(self) -> (TcpReadHalf, TcpWriteHalf) {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
}

/// Placeholder for the tokio TcpListener on embedded targets.
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub struct TcpListener;

#[cfg(not(feature = "std"))]
impl TcpListener {
    pub async fn bind(_addr: SocketAddr) -> RtcResult<Self> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
    pub fn local_addr(&self) -> RtcResult<SocketAddr> {
        unimplemented!("ICE-TCP is excluded from the embedded target")
    }
}

/// Placeholder halves (ICE-TCP excluded).
#[cfg(not(feature = "std"))]
pub type TcpReadHalf = TcpStream;
#[cfg(not(feature = "std"))]
pub type TcpWriteHalf = TcpStream;

/// Placeholder for the UPnP port mapper (UPnP excluded from the embedded
/// target). Never constructed.
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone)]
pub struct UpnpPortMapper;

#[cfg(not(feature = "std"))]
impl UpnpPortMapper {
    pub fn with_lease_duration(_local_addr: SocketAddr, _lease: u32) -> Self {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn discover(&mut self) -> RtcResult<()> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn add_mapping(&mut self, _port: u16) -> RtcResult<SocketAddr> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn renew_all_stale(&self) -> RtcResult<()> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn discover_with_timeout(&mut self, _: core::time::Duration) -> RtcResult<()> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn add_mapping_random_port(&mut self, _: u16) -> RtcResult<u16> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
    pub async fn cleanup(&self) -> RtcResult<()> {
        Ok(())
    }
    pub async fn get_external_ip(&self) -> RtcResult<core::net::Ipv4Addr> {
        unimplemented!("UPnP is excluded from the embedded target")
    }
}
use crate::platform::sync::{AsyncMutex as Mutex, broadcast, mpsc, oneshot, watch};
use crate::platform::time::with_timeout;
use tracing::{debug, error, instrument, trace, warn};

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
            #[cfg(feature = "std")]
            {
                rate = std::env::var("RUSTRTC_PACKET_LOSS")
                    .ok()
                    .and_then(|s| s.parse::<f64>().ok())
                    .map(|f| (f * 100.0) as u32)
                    .unwrap_or(0);
            }
            #[cfg(not(feature = "std"))]
            {
                rate = 0;
            }
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

/// Simulator hook: delay STUN Binding responses so a nominally fast path can
/// be made slower than a lower-priority one, reproducing the ICE nomination
/// race seen across cascaded NAT (the controlling side picked a fast
/// srflx/relay pair while the controlled side selected the host path).
///
/// `RUSTRTC_STUN_RESPOND_DELAY_MS=<ms>` delays every response sent from a
/// direct (non-TURN) socket. Only used by tests.
#[cfg(any(test, feature = "simulator"))]
async fn simulate_stun_respond_delay(sender: &IceSocketWrapper) {
    #[cfg(not(feature = "std"))]
    {
        // No env vars on the embedded target: the simulator hook is a no-op.
        let _ = sender;
    }
    #[cfg(feature = "std")]
    {
        let spec = match std::env::var("RUSTRTC_STUN_RESPOND_DELAY_MS").ok() {
            Some(s) => s,
            None => return,
        };
        let Ok(ms) = spec.trim().parse::<u64>() else {
            return;
        };
        if ms == 0 {
            return;
        }
        let is_relayed_or_tcp = matches!(sender, IceSocketWrapper::Turn(_, _)) || matches!(
            sender,
            IceSocketWrapper::TcpListener(_) | IceSocketWrapper::TcpStream(_, _, _)
        );
        if is_relayed_or_tcp {
            return;
        }
        trace!("SIMULATOR: delaying STUN response by {}ms", ms);
        crate::platform::task::sleep(Duration::from_millis(ms)).await;
    }
}

/// Statistics for monitoring buffer behavior
#[derive(Debug)]
struct BufferStats {
    pub packets_received: AtomicU64,
    pub packets_dropped: AtomicU64,
    pub current_size: AtomicU32,
    pub peak_size: AtomicU32,
    pub last_log_time: crate::platform::sync::Mutex<Instant>,
}

impl Default for BufferStats {
    fn default() -> Self {
        Self {
            packets_received: AtomicU64::new(0),
            packets_dropped: AtomicU64::new(0),
            current_size: AtomicU32::new(0),
            peak_size: AtomicU32::new(0),
            last_log_time: crate::platform::sync::Mutex::new(Instant::now()),
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

pub(crate) struct IceTransportInner {
    state: watch::Sender<IceTransportState>,
    _state_rx_keeper: watch::Receiver<IceTransportState>,
    gathering_state: watch::Sender<IceGathererState>,
    /// Keeper receiver for the gathering_state watch channel. Without a live
    /// receiver, `watch::Sender::send()` with zero receivers returns Err and
    /// never stores the value — a late subscriber would miss the `Complete`
    /// update and `wait_for_gathering_complete()` would hang forever. Every
    /// other watch channel in this struct holds a keeper receiver for exactly
    /// this reason.
    _gathering_state_rx_keeper: watch::Receiver<IceGathererState>,
    role: crate::platform::sync::Mutex<IceRole>,
    selected_pair: crate::platform::sync::Mutex<Option<IceCandidatePair>>,
    local_candidates: Mutex<Vec<IceCandidate>>,
    remote_candidates: crate::platform::sync::Mutex<Vec<IceCandidate>>,
    gather_state: crate::platform::sync::Mutex<IceGathererState>,
    config: RtcConfiguration,
    gatherer: IceGatherer,
    local_parameters: crate::platform::sync::Mutex<IceParameters>,
    remote_parameters: crate::platform::sync::Mutex<Option<IceParameters>>,
    pending_transactions:
        crate::platform::sync::Mutex<BTreeMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
    data_receiver: crate::platform::sync::Mutex<Option<Arc<dyn PacketReceiver>>>,
    /// Ring buffer for packets when no receiver is registered yet.
    /// Uses VecDeque for efficient pop_front removal.
    buffered_packets: crate::platform::sync::Mutex<VecDeque<(Vec<u8>, SocketAddr)>>,
    /// Statistics for monitoring buffer behavior
    buffer_stats: Arc<BufferStats>,
    selected_socket: watch::Sender<Option<IceSocketWrapper>>,
    _socket_rx_keeper: watch::Receiver<Option<IceSocketWrapper>>,
    selected_rtcp_socket: watch::Sender<Option<IceSocketWrapper>>,
    _rtcp_socket_rx_keeper: watch::Receiver<Option<IceSocketWrapper>>,
    selected_pair_notifier: watch::Sender<Option<IceCandidatePair>>,
    _selected_pair_rx_keeper: watch::Receiver<Option<IceCandidatePair>>,
    /// Reference epoch used to interpret `last_received_nanos`.
    created_at: Instant,
    /// Nanoseconds since `created_at` when the most recent packet arrived.
    /// Stored atomically so the per-packet receive path records the timestamp
    /// without taking a mutex.
    last_received_nanos: AtomicU64,
    candidate_tx: broadcast::Sender<IceCandidate>,
    cmd_tx: mpsc::UnboundedSender<IceCommand>,
    checking_pairs: Mutex<alloc::collections::BTreeSet<(SocketAddr, SocketAddr)>>,
    /// Signals when the controlling-side nomination is complete.
    /// `true` = nomination succeeded, `false` = nomination failed (but ICE is still connected).
    /// Controlled side immediately sends `true` (no nomination to do).
    nomination_complete: watch::Sender<Option<bool>>,
    _nomination_complete_rx: watch::Receiver<Option<bool>>,
    /// Set while a locally-initiated ICE restart is in flight (between
    /// `restart()` and the next `start()` with the peer's answer). Prevents a
    /// changed remote ufrag/pwd in that answer from being misread as a
    /// remote-initiated restart (which would reset ICE a second time).
    restart_requested: core::sync::atomic::AtomicBool,
    /// Monotonic counter bumped for every new controlled-side nomination and on
    /// every ICE restart. A deferred path-verification task only commits its
    /// pair while its captured generation is still current, so a stale
    /// nomination whose verification finishes late cannot switch media back to
    /// a superseded path (RFC 8445 §8.1.1).
    /// no_std: backed by the 32-bit atomic64 shim.
    nomination_generation: crate::platform::atomic64::AtomicU64,
    /// mDNS hostname advertising our host candidates (`enable_mdns`).
    mdns_hostname: Option<String>,
    /// Guards against overlapping `run_turn_refresh` invocations: the refresh
    /// timer tick skips when a previous refresh is still in flight instead of
    /// cancelling it (which used to orphan pending transactions).
    turn_refresh_in_progress: core::sync::atomic::AtomicBool,
    /// Guards against overlapping UPnP mapping refreshes (same skip-on-in-flight
    /// pattern as `turn_refresh_in_progress`).
    upnp_refresh_in_progress: core::sync::atomic::AtomicBool,
}

impl core::fmt::Debug for IceTransportInner {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
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
            .field("selected_rtcp_socket", &self.selected_rtcp_socket)
            .field("selected_pair_notifier", &self.selected_pair_notifier)
            .field("candidate_tx", &self.candidate_tx)
            .field("cmd_tx", &self.cmd_tx)
            .field("nomination_complete", &self.nomination_complete)
            .finish()
    }
}

/// Collect the local addresses to advertise in mDNS answers and start a
/// responder for the transport's obfuscated hostname.
#[cfg(feature = "std")]
fn start_mdns_responder(
    inner: &Arc<IceTransportInner>,
) -> anyhow::Result<crate::transports::ice::mdns::MdnsResponder> {
    let mut addresses: Vec<core::net::IpAddr> = Vec::new();
    if let Some(bind) = &inner.config.bind_ip
        && let Ok(ip) = bind.parse::<core::net::IpAddr>()
    {
        addresses.push(ip);
    }
    #[cfg(feature = "std")]
    use local_ip_address::list_afinet_netifas;
    if let Ok(interfaces) = list_afinet_netifas() {
        for (_name, addr) in interfaces {
            if !addr.is_loopback() && !addresses.contains(&addr) {
                addresses.push(addr);
            }
        }
    }
    let hostname = inner
        .mdns_hostname
        .clone()
        .unwrap_or_else(crate::transports::ice::mdns::MdnsResponder::generate_hostname);
    crate::transports::ice::mdns::MdnsResponder::start(hostname, addresses)
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

        // mDNS responder lifetime: started when `enable_mdns` is set, stopped
        // when the runner loop exits (the guard's Drop signals the task).
        #[cfg(feature = "std")]
        let _mdns: Option<crate::transports::ice::mdns::MdnsResponder> =
            if self.inner.config.enable_mdns {
                match start_mdns_responder(&self.inner) {
                    Ok(responder) => {
                        debug!("mDNS responder started for {}", responder.hostname());
                        Some(responder)
                    }
                    Err(e) => {
                        debug!("mDNS responder failed to start: {}", e);
                        None
                    }
                }
            } else {
                None
            };
        let mut interval =
            crate::platform::task::interval_after(Duration::from_secs(1), Duration::from_secs(1));
        // TURN refresh interval. Kept well under both the 300 s permission
        // timeout AND typical UDP NAT mapping idle timeouts (~30 s on many
        // carrier/CGNAT deployments): each Refresh is bidirectional traffic
        // on the client<->TURN-server 5-tuple, so this also keeps that NAT
        // mapping warm for relays that are gathered but not selected (and
        // therefore carry no media ChannelData). 25 s is safely under all
        // those budgets while staying cheap (tiny authenticated packets).
        let mut turn_refresh_interval =
            crate::platform::task::interval_after(Duration::from_secs(25), Duration::from_secs(25));
        // UPnP mapping refresh interval. Long-lived sessions (> 1 hour) outlive
        // the default router lease (3600s); re-issuing AddPortMapping keeps the
        // mapping alive so inbound P2P traffic isn't lost mid-call.
        let mut upnp_refresh_interval = crate::platform::task::interval_after(
            self.inner.config.upnp_refresh_interval,
            self.inner.config.upnp_refresh_interval,
        );
        let mut read_futures: FuturesUnordered<BoxFuture<'static, ()>> = FuturesUnordered::new();
        let mut gathering_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());
        let mut turn_refresh_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());
        let mut upnp_refresh_future: BoxFuture<'static, ()> = Box::pin(futures::future::pending());

        loop {
            // Backend-agnostic 11-arm race (replaces `tokio::select!`):
            // every arm is polled once per wake in a fixed order; the first
            // `Ready` wins. `Some(x) = rx.recv()` arms keep tokio's
            // disabled-branch semantics through `*_open` flags — a closed
            // channel stops polling that arm instead of spinning.
            enum GatherArm {
                State(Result<(), watch::RecvError>),
                Socket(IceSocketWrapper),
                Candidate(Result<(), broadcast::RecvError>),
                Cmd(IceCommand),
                Keepalive,
                TurnRefreshTick,
                TurnRefreshDone,
                UpnpTick,
                UpnpDone,
                ReadLoopDone,
                GatheringDone,
            }
            let mut socket_rx_open = true;
            let mut cmd_rx_open = true;

            let arm = core::future::poll_fn(|cx| {
                use core::task::Poll;
                let mut state_fut = core::pin::pin!(self.state_rx.changed());
                let mut socket_fut = core::pin::pin!(self.socket_rx.recv());
                let mut cand_fut = core::pin::pin!(self.candidate_rx.recv());
                let mut cmd_fut = core::pin::pin!(self.cmd_rx.recv());
                let mut ka_fut = core::pin::pin!(interval.tick());
                let mut turn_tick_fut = core::pin::pin!(turn_refresh_interval.tick());
                let mut upnp_tick_fut = core::pin::pin!(upnp_refresh_interval.tick());
                let mut read_next_fut = core::pin::pin!(read_futures.next());
                loop {
                    if let Poll::Ready(res) = state_fut.as_mut().poll(cx) {
                        return Poll::Ready(GatherArm::State(res));
                    }
                    if socket_rx_open && let Poll::Ready(v) = socket_fut.as_mut().poll(cx) {
                        match v {
                            Some(socket) => return Poll::Ready(GatherArm::Socket(socket)),
                            None => socket_rx_open = false,
                        }
                    }
                    if let Poll::Ready(res) = cand_fut.as_mut().poll(cx) {
                        return Poll::Ready(GatherArm::Candidate(res.map(|_| ())));
                    }
                    if cmd_rx_open && let Poll::Ready(v) = cmd_fut.as_mut().poll(cx) {
                        match v {
                            Some(cmd) => return Poll::Ready(GatherArm::Cmd(cmd)),
                            None => cmd_rx_open = false,
                        }
                    }
                    if ka_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(GatherArm::Keepalive);
                    }
                    if turn_tick_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(GatherArm::TurnRefreshTick);
                    }
                    if core::pin::Pin::new(&mut turn_refresh_future)
                        .poll(cx)
                        .is_ready()
                    {
                        return Poll::Ready(GatherArm::TurnRefreshDone);
                    }
                    if upnp_tick_fut.as_mut().poll(cx).is_ready() {
                        return Poll::Ready(GatherArm::UpnpTick);
                    }
                    if core::pin::Pin::new(&mut upnp_refresh_future)
                        .poll(cx)
                        .is_ready()
                    {
                        return Poll::Ready(GatherArm::UpnpDone);
                    }
                    if let Poll::Ready(Some(_)) = read_next_fut.as_mut().poll(cx) {
                        return Poll::Ready(GatherArm::ReadLoopDone);
                    }
                    if core::pin::Pin::new(&mut gathering_future)
                        .poll(cx)
                        .is_ready()
                    {
                        return Poll::Ready(GatherArm::GatheringDone);
                    }
                    return Poll::Pending;
                }
            })
            .await;
            match arm {
                GatherArm::State(res) => {
                    if res.is_err() {
                        break;
                    }
                    if matches!(
                        *self.state_rx.borrow(),
                        IceTransportState::Closed | IceTransportState::Failed
                    ) {
                        break;
                    }
                }
                GatherArm::Socket(socket) => {
                    match socket {
                        IceSocketWrapper::Udp(s) => {
                            // std: the tokio socket's dedicated read loop;
                            // no_std: Udp is a placeholder, never constructed.
                            #[cfg(feature = "std")]
                            {
                                read_futures
                                    .push(Box::pin(Self::run_udp_read_loop(s, self.inner.clone())));
                            }
                            #[cfg(not(feature = "std"))]
                            {
                                let _ = s;
                            }
                        }
                        IceSocketWrapper::SharedUdp(handle) => {
                            read_futures.push(Box::pin(Self::run_shared_udp_read_loop(
                                handle,
                                self.inner.clone(),
                            )));
                        }
                        #[cfg(feature = "std")]
                        IceSocketWrapper::TcpListener(l) => {
                            read_futures
                                .push(Box::pin(Self::run_tcp_listen_loop(l, self.inner.clone())));
                        }
                        #[cfg(feature = "std")]
                        IceSocketWrapper::TcpStream(read, write, peer) => {
                            read_futures.push(Box::pin(Self::run_tcp_read_loop(
                                read,
                                write,
                                peer,
                                self.inner.clone(),
                            )));
                        }
                        IceSocketWrapper::Platform(s) => {
                            read_futures.push(Box::pin(Self::run_platform_read_loop(
                                s,
                                self.inner.clone(),
                            )));
                        }
                        IceSocketWrapper::Turn(c, addr) => {
                            read_futures.push(Box::pin(Self::run_turn_read_loop(
                                c,
                                addr,
                                self.inner.clone(),
                            )));
                        }
                    }
                }
                GatherArm::Candidate(res) => match res {                    Ok(_) => {
                        let inner = self.inner.clone();
                        read_futures.push(Box::pin(async move {
                            perform_connectivity_checks_async(inner).await;
                        }));
                    }
                    Err(broadcast::RecvError::Closed) => break,
                    Err(broadcast::RecvError::Lagged(_)) => continue,
                }
                GatherArm::Cmd(cmd) => {


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
                            // Spawn connectivity checks in a separate task so they don't
                            // block the runner's event loop. This is critical for TCP
                            // candidates: the check may block on TcpStream::connect while
                            // the runner still needs to process pending socket_rx messages
                            // (e.g. TcpListener accept loops) to complete the connection.
                            let rt_handle = inner.config.runtime_handle.clone();
                            crate::spawn_rtc(
                                rt_handle.as_ref(),
                                tracing::Span::current(),
                                async move {
                                    perform_connectivity_checks_async(inner).await;
                                },
                            );
                        }
                    }
                }
                GatherArm::Keepalive => {
                    if let Some(f) = Self::run_keepalive_tick(&self.inner).await {
                        read_futures.push(f);
                    }
                }
                GatherArm::TurnRefreshTick => {
                    // Only start a new refresh if the previous one has
                    // completed. If still running (e.g. server slow), skip
                    // this tick rather than reassigning the future, which
                    // would cancel the in-flight refresh and orphan its
                    // pending transactions. The in-progress flag is cleared
                    // by `run_turn_refresh` on every exit path.
                    if !self
                        .inner
                        .turn_refresh_in_progress
                        .load(core::sync::atomic::Ordering::SeqCst)
                    {
                        let inner = self.inner.clone();
                        turn_refresh_future = Box::pin(async move {
                            Self::run_turn_refresh(&inner).await;
                        });
                    }
                }
                GatherArm::TurnRefreshDone => {
                    turn_refresh_future = Box::pin(futures::future::pending());
                }
                GatherArm::UpnpTick => {
                    // UPnP SOAP calls can be slow (hundreds of ms). Run them in
                    // a detached future so the runner's 1s keepalive tick is
                    // never blocked. Guard with an in-progress flag so slow
                    // routers don't pile up overlapping refreshes.
                    if !self
                        .inner
                        .upnp_refresh_in_progress
                        .swap(true, core::sync::atomic::Ordering::SeqCst)
                    {
                        let inner = self.inner.clone();
                        upnp_refresh_future = Box::pin(async move {
                            #[cfg(feature = "std")]
                            inner.gatherer.renew_upnp_mappings().await;
                            #[cfg(not(feature = "std"))]
                            {
                                let _ = &inner;
                            }
                            inner
                                .upnp_refresh_in_progress
                                .store(false, core::sync::atomic::Ordering::SeqCst);
                        });
                    }
                }
                GatherArm::UpnpDone => {
                    upnp_refresh_future = Box::pin(futures::future::pending());
                }
                GatherArm::ReadLoopDone => {
                    // Read loop finished
                }
                GatherArm::GatheringDone => {
                    gathering_future = Box::pin(futures::future::pending());
                }
            }
        }
    }

    #[cfg(feature = "std")]
    async fn run_udp_read_loop(socket: Arc<UdpSocket>, inner: Arc<IceTransportInner>) {
        let mut buf = [0u8; 1500];
        let mut marshal_buf = Vec::with_capacity(1500);
        let mut state_rx = inner.state.subscribe();
        let sender = IceSocketWrapper::Udp(socket.clone());
        trace!("Read loop started for {:?}", socket.local_addr());
        loop {
            let which = {
                let mut readable_fut = core::pin::pin!(socket.readable());
                let mut state_fut = core::pin::pin!(state_rx.changed());
                crate::platform::select::select2(&mut readable_fut, &mut state_fut).await
            };
            match which {
                crate::platform::select::Either::A(res) => {
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
                            Err(e) if e.kind() == ErrorKind::ConnectionReset => {
                                // Windows surfaces the ICMP "Port Unreachable" reply to an
                                // earlier send as WSAECONNRESET (os error 10054) on the next
                                // recv. UDP is connectionless, so this is not a fatal socket
                                // error — return to the outer select and keep serving this
                                // socket (same class of fix as tokio-rs/tokio#2017 and
                                // aws/s2n-quic#1448; matches the tolerant handling already
                                // used by the shared-UDP recv loop).
                                debug!("Socket recv error (connection reset, continuing): {}", e);
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
                                &mut marshal_buf,
                            )
                            .await;
                        }
                    }
                }
                crate::platform::select::Either::B(res) => {
                    if res.is_err()
                        || matches!(
                            *state_rx.borrow(),
                            IceTransportState::Closed | IceTransportState::Failed
                        )
                    {
                        // routine teardown; one line per read loop is noisy at debug
                        trace!("Read loop stopping (IceTransport Closed or Failed)");
                        break;
                    }
                }
            }
        }
    }

    async fn run_platform_read_loop(
        socket: Arc<dyn crate::platform::net::UdpSocket>,
        inner: Arc<IceTransportInner>,
    ) {
        let mut buf = vec![0u8; 1500];
        let mut marshal_buf = Vec::with_capacity(1500);
        let sender = IceSocketWrapper::Platform(socket.clone());
        loop {
            let result = crate::platform::time::with_timeout(
                core::time::Duration::from_secs(1),
                socket.recv_from(&mut buf),
            )
            .await;
            let (len, addr) = match result {
                Err(_) => continue,
                Ok(Err(_)) => break,
                Ok(Ok(v)) => v,
            };
            let packet = &buf[..len];
            if len > 0 {
                handle_packet(
                    packet,
                    addr,
                    inner.clone(),
                    sender.clone(),
                    &mut marshal_buf,
                )
                .await;
            }
        }
    }

    /// Read loop for a shared (muxed) UDP socket. Packets arrive via the
    /// handle's receiver (fed by the shared demux loop); outbound replies go out
    /// through the same handle.
    async fn run_shared_udp_read_loop(
        handle: Arc<shared_udp::SharedUdpHandle>,
        inner: Arc<IceTransportInner>,
    ) {
        let mut state_rx = inner.state.subscribe();
        let mut marshal_buf = Vec::with_capacity(1500);
        let sender = IceSocketWrapper::SharedUdp(handle.clone());
        trace!("Shared UDP read loop started");
        loop {
            // state arm polled first each wake (matches the old `biased;`).
            // The block scopes the pinned futures so `state_rx` is released
            // before the arm bodies run.
            let which = {
                let mut state_fut = core::pin::pin!(state_rx.changed());
                let mut recv_fut = core::pin::pin!(handle.recv());
                crate::platform::select::select2(&mut state_fut, &mut recv_fut).await
            };
            let packet_opt = match which {
                crate::platform::select::Either::A(res) => {
                    if res.is_err()
                        || matches!(
                            *state_rx.borrow(),
                            IceTransportState::Closed | IceTransportState::Failed
                        )
                    {
                        debug!("Shared UDP read loop stopping (IceTransport Closed or Failed)");
                        break;
                    }
                    continue;
                }
                crate::platform::select::Either::B(pkt) => pkt,
            };
            match packet_opt {
                Some((packet, addr)) => {
                    handle_packet(
                        &packet,
                        addr,
                        inner.clone(),
                        sender.clone(),
                        &mut marshal_buf,
                    )
                    .await;
                }
                None => break,
            }
        }
    }

    async fn run_turn_read_loop(
        client: Arc<TurnClient>,
        relayed_addr: SocketAddr,
        inner: Arc<IceTransportInner>,
    ) {
        let mut buf = [0u8; 1500];
        let mut marshal_buf = Vec::with_capacity(1500);
        let mut state_rx = inner.state.subscribe();
        trace!("Read loop started for TURN client {}", relayed_addr);
        loop {
            let which = {
                let mut recv_fut = core::pin::pin!(async { client.recv(&mut buf).await });
                let mut state_fut = core::pin::pin!(state_rx.changed());
                crate::platform::select::select2(&mut recv_fut, &mut state_fut).await
            };
            match which {
                crate::platform::select::Either::A(result) => match result {
                    Ok(len) => {
                        if len > 0 {
                            IceTransport::handle_turn_packet(
                                &buf[..len],
                                &inner,
                                &client,
                                relayed_addr,
                                &mut marshal_buf,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        if e.to_string().contains("deadline has elapsed") {
                            continue;
                        }
                        debug!("TURN client recv error: {}", e);
                        break;
                    }
                },
                crate::platform::select::Either::B(res) => {
                    if res.is_err()
                        || matches!(
                            *state_rx.borrow(),
                            IceTransportState::Closed | IceTransportState::Failed
                        )
                    {
                        trace!("TURN Read loop stopping (IceTransport Closed or Failed)");
                        break;
                    }
                }
            }
        }
    }

    #[cfg(feature = "std")]
    async fn run_tcp_listen_loop(listener: Arc<TcpListener>, inner: Arc<IceTransportInner>) {
        let mut state_rx = inner.state.subscribe();
        let local_addr = match listener.local_addr() {
            Ok(a) => a,
            Err(e) => {
                debug!("TCP listener local_addr error: {}", e);
                return;
            }
        };
        trace!("TCP listen loop started for {:?}", local_addr);
        loop {
            let which = {
                let mut accept_fut = core::pin::pin!(listener.accept());
                let mut state_fut = core::pin::pin!(state_rx.changed());
                crate::platform::select::select2(&mut accept_fut, &mut state_fut).await
            };
            match which {
                crate::platform::select::Either::A(accept_res) => match accept_res {
                    Ok((stream, peer_addr)) => {
                        trace!("TCP accepted connection from {}", peer_addr);
                        let wrapper = split_tcp_stream(stream, peer_addr);
                        inner.gatherer.store_tcp_stream(local_addr, wrapper.clone());
                        let _ = inner.gatherer.socket_tx.send(wrapper);
                    }
                    Err(e) => {
                        debug!("TCP accept error: {}", e);
                        break;
                    }
                },
                crate::platform::select::Either::B(res) => {
                    if res.is_err()
                        || matches!(
                            *state_rx.borrow(),
                            IceTransportState::Closed | IceTransportState::Failed
                        )
                    {
                        debug!("TCP listen loop stopping (IceTransport Closed or Failed)");
                        break;
                    }
                }
            }
        }
    }

    #[cfg(feature = "std")]
    async fn run_tcp_read_loop(
        read: Arc<Mutex<TcpReadHalf>>,
        write: Arc<Mutex<TcpWriteHalf>>,
        peer_addr: SocketAddr,
        inner: Arc<IceTransportInner>,
    ) {
        let mut buf = [0u8; 65_535];
        let mut marshal_buf = Vec::with_capacity(1500);
        let mut state_rx = inner.state.subscribe();
        #[cfg(feature = "std")]
        let sender = IceSocketWrapper::TcpStream(read, write, peer_addr);
        trace!("TCP read loop started for peer {}", peer_addr);
        loop {
            let which = {
                let mut recv_fut = core::pin::pin!(sender.recv_from(&mut buf));
                let mut state_fut = core::pin::pin!(state_rx.changed());
                crate::platform::select::select2(&mut recv_fut, &mut state_fut).await
            };
            match which {
                crate::platform::select::Either::A(result) => match result {
                    Ok((len, addr)) => {
                        if len > 0 {
                            handle_packet(
                                &buf[..len],
                                addr,
                                inner.clone(),
                                sender.clone(),
                                &mut marshal_buf,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        debug!("TCP recv error from {}: {}", peer_addr, e);
                        break;
                    }
                },
                crate::platform::select::Either::B(res) => {
                    if res.is_err()
                        || matches!(
                            *state_rx.borrow(),
                            IceTransportState::Closed | IceTransportState::Failed
                        )
                    {
                        debug!("TCP read loop stopping (IceTransport Closed or Failed)");
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
            if inner.config.transport_mode == crate::TransportMode::WebRtc {
                let last_nanos = inner.last_received_nanos.load(Ordering::Relaxed);
                let now_nanos = inner.created_at.elapsed().as_nanos() as u64;
                let elapsed = Duration::from_nanos(now_nanos.saturating_sub(last_nanos));
                let ice_conn_timeout = inner.config.ice_connection_timeout;
                let tcp_selected = inner
                    .selected_pair
                    .lock()
                    .as_ref()
                    .map(|pair| pair.local.transport == "tcp")
                    .unwrap_or(false);
                // ICE-TCP recv-only peers (e.g. WHEP) may not send STUN for several seconds
                // while DTLS/SRTP comes up; do not flap to Disconnected on the UDP 5s heuristic.
                let disconnect_threshold = if tcp_selected {
                    ice_conn_timeout.saturating_sub(Duration::from_secs(1))
                } else {
                    inner.config.ice_disconnect_threshold
                };
                if elapsed > ice_conn_timeout {
                    let _ = inner.set_state(IceTransportState::Failed);
                } else if elapsed > disconnect_threshold {
                    if state != IceTransportState::Disconnected {
                        let _ = inner.set_state(IceTransportState::Disconnected);
                    }
                } else if state == IceTransportState::Disconnected {
                    let _ = inner.set_state(IceTransportState::Connected);
                }
            }

            // Send Keepalive
            let pair_opt = inner.selected_pair.lock().clone();
            if let Some(pair) = pair_opt {
                let socket = inner
                    ._socket_rx_keeper
                    .borrow()
                    .clone()
                    .or_else(|| resolve_socket(inner, &pair));
                if let Some(socket) = socket {
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
                                let _ = with_timeout(Duration::from_secs(5), rx).await;
                                if let Some(inner) = inner_weak.upgrade() {
                                    let mut map = inner.pending_transactions.lock();
                                    map.remove(&tx_id);
                                }
                            });

                            let _ = socket.send_to(&bytes, pair.remote.address).await;
                            return Some(cleanup);
                        }
                    } else if inner.config.transport_mode != crate::TransportMode::WebRtc
                        && let Ok(bytes) = msg.encode(None, false)
                    {
                        let _ = socket.send_to(&bytes, pair.remote.address).await;
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
    /// This runs every ~25s — well under all three timeouts AND under typical
    /// UDP NAT mapping idle timeouts, so the client<->TURN-server 5-tuple stays
    /// mapped even for relays that carry no media (the bidirectional Refresh
    /// traffic refreshes the NAT). See the interval setup in `run`.
    ///
    /// Each request is awaited directly (no spawning) so that a 401/438
    /// stale-nonce response is detected immediately and the nonce is refreshed
    /// before retrying — preventing silent refresh failures that eventually let
    /// ChannelBindings expire and cause SCTP disconnects.
    async fn run_turn_refresh(inner: &Arc<IceTransportInner>) {
        // Acquire the in-progress guard. If a previous refresh is somehow still
        // running (e.g. the runner raced two ticks), bail out instead of running
        // two concurrent refreshes that could interleave nonce updates.
        if inner
            .turn_refresh_in_progress
            .swap(true, core::sync::atomic::Ordering::SeqCst)
        {
            return;
        }
        // RAII: guarantees the flag is cleared on every exit path, including
        // early returns and panics, so the timer never deadlocks on refresh.
        struct RefreshGuard<'a>(&'a core::sync::atomic::AtomicBool);
        impl Drop for RefreshGuard<'_> {
            fn drop(&mut self) {
                self.0.store(false, core::sync::atomic::Ordering::SeqCst);
            }
        }
        let _guard = RefreshGuard(&inner.turn_refresh_in_progress);

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
            match with_timeout(Duration::from_secs(5), rx).await {
                Ok(Ok(msg)) => Some(msg),
                _ => {
                    inner.pending_transactions.lock().remove(&tx_id);
                    None
                }
            }
        }

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
                                    msg.error_code.unwrap_or(0)
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
                                        msg.error_code.unwrap_or(0)
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
                                            msg.error_code.unwrap_or(0),
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
    pub fn new(config: RtcConfiguration) -> (Self, impl core::future::Future<Output = ()> + Send) {
        let (candidate_tx, _) = broadcast::channel(100);
        let (socket_tx, socket_rx) = crate::platform::sync::mpsc::unbounded_channel();
        let gatherer = IceGatherer::new(config.clone(), candidate_tx.clone(), socket_tx);
        let (state_tx, state_rx) = watch::channel(IceTransportState::New);
        let runner_state_rx = state_tx.subscribe();
        let (gathering_state_tx, gathering_state_rx) = watch::channel(IceGathererState::New);
        let (selected_socket_tx, selected_socket_rx) = watch::channel(None);
        let (selected_rtcp_socket_tx, selected_rtcp_socket_rx) = watch::channel(None);
        let (selected_pair_tx, selected_pair_rx) = watch::channel(None);
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (nomination_complete_tx, nomination_complete_rx) = watch::channel(None);

        let inner = IceTransportInner {
            state: state_tx,
            _state_rx_keeper: state_rx,
            gathering_state: gathering_state_tx,
            _gathering_state_rx_keeper: gathering_state_rx,
            role: crate::platform::sync::Mutex::new(IceRole::Controlled),
            selected_pair: crate::platform::sync::Mutex::new(None),
            local_candidates: Mutex::new(Vec::new()),
            remote_candidates: crate::platform::sync::Mutex::new(Vec::new()),
            gather_state: crate::platform::sync::Mutex::new(IceGathererState::New),
            config: config.clone(),
            gatherer,
            local_parameters: crate::platform::sync::Mutex::new(IceParameters::generate()),
            remote_parameters: crate::platform::sync::Mutex::new(None),
            pending_transactions: crate::platform::sync::Mutex::new(BTreeMap::new()),
            data_receiver: crate::platform::sync::Mutex::new(None),
            buffered_packets: crate::platform::sync::Mutex::new(VecDeque::new()),
            selected_socket: selected_socket_tx,
            _socket_rx_keeper: selected_socket_rx,
            selected_rtcp_socket: selected_rtcp_socket_tx,
            _rtcp_socket_rx_keeper: selected_rtcp_socket_rx,
            selected_pair_notifier: selected_pair_tx,
            _selected_pair_rx_keeper: selected_pair_rx,
            created_at: Instant::now(),
            last_received_nanos: AtomicU64::new(0),
            candidate_tx: candidate_tx.clone(),
            cmd_tx,
            checking_pairs: Mutex::new(alloc::collections::BTreeSet::new()),
            nomination_complete: nomination_complete_tx,
            _nomination_complete_rx: nomination_complete_rx,
            restart_requested: core::sync::atomic::AtomicBool::new(false),
            nomination_generation: crate::platform::atomic64::AtomicU64::new(0),
            mdns_hostname: {
                #[cfg(feature = "std")]
                {
                    config
                        .enable_mdns
                        .then(crate::transports::ice::mdns::MdnsResponder::generate_hostname)
                }
                #[cfg(not(feature = "std"))]
                {
                    None
                }
            },
            turn_refresh_in_progress: core::sync::atomic::AtomicBool::new(false),
            upnp_refresh_in_progress: core::sync::atomic::AtomicBool::new(false),
            buffer_stats: Arc::new(BufferStats::default()),
        };
        let inner = Arc::new(inner);
        inner.gatherer.set_transport(Arc::downgrade(&inner));

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

    pub(crate) fn subscribe_selected_rtcp_socket(
        &self,
    ) -> watch::Receiver<Option<IceSocketWrapper>> {
        self.inner.selected_rtcp_socket.subscribe()
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

    /// When the controlling peer has no local TCP candidates it may connect inbound
    /// without sending USE-CANDIDATE. Complete nomination once a passive TCP stream exists.
    pub fn nudge_passive_tcp_nomination(&self) {
        if *self.inner.role.lock() != IceRole::Controlled {
            return;
        }
        if self.inner.nomination_complete.borrow().is_some() {
            return;
        }
        let inner = self.inner.clone();
        debug!("ICE: nudging passive TCP nomination (controlled, awaiting inbound TCP)");
        let rt_handle = inner.config.runtime_handle.clone();
        crate::spawn_rtc(rt_handle.as_ref(), tracing::Span::current(), async move {
            let streams: Vec<_> = inner
                .gatherer
                .tcp_streams
                .lock()
                .values()
                .cloned()
                .collect();
            for wrapper in streams {
                #[cfg(feature = "std")]
                if let IceSocketWrapper::TcpStream(_, _, peer) = wrapper {
                    #[cfg(feature = "std")]
                    complete_controlled_inbound_tcp_nomination(&wrapper, peer, inner).await;
                    #[cfg(not(feature = "std"))]
                    {
                        let _ = (&wrapper, &peer, &inner);
                    }
                    return;
                }
            }
        });
    }

    pub fn gather_state(&self) -> IceGathererState {
        self.inner.gatherer.state()
    }

    pub fn role(&self) -> IceRole {
        *self.inner.role.lock()
    }

    pub fn local_candidates(&self) -> Vec<IceCandidate> {
        self.inner.gatherer.local_candidates()
    }

    pub(crate) fn local_rtcp_addr(&self) -> Option<SocketAddr> {
        self.inner
            .gatherer
            .local_candidates()
            .into_iter()
            .find(|candidate| candidate.component == 2)
            .map(|candidate| candidate.address)
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

    /// Restart ICE (RFC 8445 §9): roll fresh local credentials and reset all
    /// connectivity-check / nomination state so checks re-run end-to-end.
    ///
    /// This is a credential-only restart: gathered candidates and their
    /// sockets stay in place, because the dominant trigger is a re-INVITE /
    /// `restartIce()` where the local network interfaces did not change. The
    /// next local description automatically carries the new ufrag/pwd (both
    /// `build_description` paths read `local_parameters` live). DTLS and SRTP
    /// state are untouched — media resumes over the (possibly different)
    /// selected pair once checks and nomination complete again.
    ///
    /// A remote-initiated restart (peer offers new ice-ufrag/ice-pwd) is
    /// detected in [`Self::start`], which runs the same reset via
    /// `restart_internal` *without* marking it as locally initiated.
    pub async fn restart(&self) -> RtcResult<()> {
        // Mark this as locally initiated *before* rolling credentials, so the
        // peer's answer (which carries our new ufrag/pwd) is recognised as the
        // completion of our own restart rather than a fresh remote one. This
        // flag must NOT be set by a remote-triggered restart: leaving it set
        // after `restart_internal` would make the *next* remote restart look
        // like the completion of a local restart and skip it (issue #54).
        self.inner
            .restart_requested
            .store(true, core::sync::atomic::Ordering::SeqCst);
        self.restart_internal().await
    }

    /// Shared restart body used by both locally- and remotely-initiated
    /// restarts. Deliberately does not touch `restart_requested`; see
    /// [`Self::restart`] for why only the local path may set that flag.
    async fn restart_internal(&self) -> RtcResult<()> {
        // 1. Fresh credentials. A new tie_breaker also makes us win/lose role
        //    conflicts per RFC 8445 §5.1.1.1 semantics for the new session.
        *self.inner.local_parameters.lock() = IceParameters::generate();

        // 2. Reset check/nomination state. The selected socket stays published
        //    so DTLS/SRTP keep running on the old path until a new pair is
        //    nominated — media pauses, but the session does not tear down.
        self.inner.checking_pairs.lock().await.clear();
        self.inner.pending_transactions.lock().clear();
        *self.inner.selected_pair.lock() = None;
        let _ = self.inner.selected_pair_notifier.send(None);
        // Invalidate any in-flight path-verification task from before the
        // restart so it cannot re-select the old pair afterwards.
        self.inner
            .nomination_generation
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        let _ = self.inner.nomination_complete.send(None);
        let _ = self.inner.set_state(IceTransportState::Checking);

        // 3. Shared UDP mux sessions are keyed by server ufrag, so the mux
        //    socket must be re-registered under the new ufrag or every inbound
        //    STUN binding request would be demuxed to a dead session.
        self.rebind_shared_udp_mux().await?;

        debug!(
            label = self.inner.config.label.as_deref().unwrap_or("-"),
            "ICE restart: new ufrag={}, pwd=<redacted>",
            self.inner.local_parameters.lock().username_fragment
        );
        Ok(())
    }

    /// Re-register this transport on the shared UDP mux socket under the
    /// current (fresh) ufrag. No-op when mux is not in use.
    async fn rebind_shared_udp_mux(&self) -> RtcResult<()> {
        let gatherer = &self.inner.gatherer;
        let listen_key = {
            let regs = gatherer.shared_udp_regs.lock();
            let Some(reg) = regs.first() else {
                return Ok(()); // mux not in use
            };
            reg.listen_key()
        };

        // Dropping the old registrations removes the old ufrag session; the
        // old read loop exits once its channel's senders are gone.
        gatherer.shared_udp_regs.lock().clear();

        let ufrag = self.inner.local_parameters.lock().username_fragment.clone();
        let (_local_addr, handle, registration) =
            shared_udp::acquire(listen_key, ufrag).await.map_err(|e| {
                // Fall back to dropping the session entirely rather than
                // leaving the mux registered under the stale ufrag.
                RtcError::Internal(format!("shared UDP mux rebind failed: {e:#}"))
            })?;
        gatherer.shared_udp_regs.lock().push(registration);

        let wrapper = IceSocketWrapper::SharedUdp(Arc::new(handle));
        *gatherer.shared_udp_socket.lock() = Some(wrapper.clone());
        // Publish the new handle so the runner starts a read loop on it.
        gatherer.socket_tx.send(wrapper).ok();
        Ok(())
    }

    fn start_keepalive(&self) {
        // Handled by runner
    }

    pub fn start_gathering(&self) -> RtcResult<()> {
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

    pub async fn start(&self, remote: IceParameters) -> RtcResult<()> {
        // Remote-initiated ICE restart detection (RFC 8445 §9): the peer
        // signals a restart by changing its ice-ufrag/ice-pwd after the
        // session was established. When we did NOT ask for a restart
        // ourselves, mirror it: roll fresh local credentials so our answer
        // carries new credentials too, and reset check state. (When we DID
        // request a restart, `restart()` already reset everything — the
        // changed peer credentials are just the remote half of our restart.)
        let previous_remote = self.inner.remote_parameters.lock().clone();
        if let Some(prev) = previous_remote
            && (prev.username_fragment != remote.username_fragment
                || prev.password != remote.password)
        {
            if self
                .inner
                .restart_requested
                .swap(false, core::sync::atomic::Ordering::SeqCst)
            {
                debug!(
                    label = self.inner.config.label.as_deref().unwrap_or("-"),
                    "ICE restart completing: peer re-signalled credentials"
                );
            } else {
                debug!(
                    label = self.inner.config.label.as_deref().unwrap_or("-"),
                    "remote ICE restart detected (ufrag/pwd changed): restarting locally"
                );
                self.restart_internal().await?;
            }
        } else {
            self.inner
                .restart_requested
                .store(false, core::sync::atomic::Ordering::SeqCst);
        }

        self.start_gathering()?;
        self.start_keepalive();
        {
            let mut params = self.inner.remote_parameters.lock();
            *params = Some(remote);
        }
        self.inner.set_state(IceTransportState::Checking);
        self.try_connectivity_checks();
        Ok(())
    }

    pub async fn start_direct(&self, remote_addr: SocketAddr) -> RtcResult<()> {
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

                match with_timeout(remaining, rx.recv()).await {
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
            return Err(RtcError::Internal(format!(
                "No local candidates gathered for direct connection"
            )));
        };

        let remote = IceCandidate::host(remote_addr, 1);
        let pair = IceCandidatePair::new(local, remote);

        *self.inner.selected_pair.lock() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket.clone()));
            publish_selected_rtcp_socket(&self.inner, Some(socket));
        }
        let _ = self.inner.set_state(IceTransportState::Connected);
        Ok(())
    }

    /// Set up a direct UDP socket for RTP mode without any ICE gathering,
    /// STUN lookups, or connectivity checks.
    /// Binds a single socket, registers it, and marks the transport as connected.
    pub async fn setup_direct_rtp(&self, remote_addr: SocketAddr) -> RtcResult<SocketAddr> {
        self.setup_direct_rtp_with_rtcp(remote_addr, false).await
    }

    pub(crate) async fn setup_direct_rtp_with_rtcp(
        &self,
        remote_addr: SocketAddr,
        bind_rtcp: bool,
    ) -> RtcResult<SocketAddr> {
        let bind_ip = if let Some(bind_ip_str) = &self.inner.config.bind_ip {
            bind_ip_str.parse::<IpAddr>().unwrap_or_else(|_| {
                get_local_ip().unwrap_or(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED))
            })
        } else if let Ok(ip) = get_local_ip() {
            ip
        } else {
            IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED)
        };

        let socket = self.inner.gatherer.bind_socket(bind_ip).await?;
        let local_addr = socket.local_addr()?;

        // Register the socket wrapper for the read loop (handled by runner);
        // backend bookkeeping already happened in bind_one.
        self.inner.gatherer.register_bound(&socket);

        // Build a local candidate for SDP generation
        let mut cand_addr = local_addr;
        let mut upnp_external_addr: Option<SocketAddr> = None;

        // Try UPnP if enabled (for RTP mode behind NAT) — std-only
        // (UPnP is excluded from the embedded target)
        #[cfg(feature = "std")]
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
                if let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
                    && !bind_ip.is_loopback()
                {
                    cand_addr.set_ip(parsed_ip);
                }
            } else if bind_ip.is_unspecified()
                && let Ok(local_ip) = get_local_ip()
            {
                cand_addr.set_ip(local_ip);
            }
        }

        // Apply external_port override (for NAT port forwarding)
        if upnp_external_addr.is_none()
            && let Some(ext_port) = self.inner.config.external_port
            && !bind_ip.is_loopback()
        {
            cand_addr.set_port(ext_port);
        }

        let mut local_candidate = IceCandidate::host(cand_addr, 1);
        if cand_addr != local_addr {
            local_candidate.related_address = Some(local_addr);
        }
        let mut rtcp_socket = None;
        let mut rtcp_candidate = None;
        if bind_rtcp {
            let (rtcp, candidate) =
                bind_direct_rtcp_socket(&self.inner, local_addr, cand_addr.ip()).await?;
            rtcp_socket = Some(rtcp);
            rtcp_candidate = Some(candidate);
        }
        self.inner.gatherer.push_candidate(local_candidate.clone());
        if let Some(candidate) = rtcp_candidate {
            self.inner.gatherer.push_candidate(candidate);
        }

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
            .send(Some(socket.clone()));
        let rtcp_socket = rtcp_socket.unwrap_or_else(|| socket.clone());
        let _ = self
            .inner
            .selected_rtcp_socket
            .send(Some(rtcp_socket));
        let _ = self.inner.set_state(IceTransportState::Connected);

        Ok(cand_addr)
    }

    /// Set up a direct UDP socket for RTP mode (offer side, no remote addr yet).
    /// Binds a socket and registers the local candidate, but does NOT set the
    /// selected pair or transition to Connected.
    pub async fn setup_direct_rtp_offer(&self) -> RtcResult<SocketAddr> {
        self.setup_direct_rtp_offer_with_rtcp(false).await
    }

    pub(crate) async fn setup_direct_rtp_offer_with_rtcp(
        &self,
        bind_rtcp: bool,
    ) -> RtcResult<SocketAddr> {
        let bind_ip = if let Some(bind_ip_str) = &self.inner.config.bind_ip {
            bind_ip_str.parse::<IpAddr>().unwrap_or_else(|_| {
                get_local_ip().unwrap_or(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED))
            })
        } else if let Ok(ip) = get_local_ip() {
            ip
        } else {
            IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED)
        };

        let socket = self.inner.gatherer.bind_socket(bind_ip).await?;
        let local_addr = socket.local_addr()?;
        self.inner.gatherer.register_bound(&socket);

        let mut cand_addr = local_addr;
        let mut upnp_external_addr: Option<SocketAddr> = None;

        // Try UPnP if enabled (for RTP mode behind NAT) — std-only
        // (UPnP is excluded from the embedded target)
        #[cfg(feature = "std")]
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
                if let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
                    && !bind_ip.is_loopback()
                {
                    cand_addr.set_ip(parsed_ip);
                }
            } else if bind_ip.is_unspecified()
                && let Ok(local_ip) = get_local_ip()
            {
                cand_addr.set_ip(local_ip);
            }
        }

        // Apply external_port override (for NAT port forwarding)
        if upnp_external_addr.is_none()
            && let Some(ext_port) = self.inner.config.external_port
            && !bind_ip.is_loopback()
        {
            cand_addr.set_port(ext_port);
        }

        let mut local_candidate = IceCandidate::host(cand_addr, 1);
        if cand_addr != local_addr {
            local_candidate.related_address = Some(local_addr);
        }
        let mut rtcp_socket = None;
        let mut rtcp_candidate = None;
        if bind_rtcp {
            let (rtcp, candidate) =
                bind_direct_rtcp_socket(&self.inner, local_addr, cand_addr.ip()).await?;
            rtcp_socket = Some(rtcp);
            rtcp_candidate = Some(candidate);
        }
        self.inner.gatherer.push_candidate(local_candidate);
        if let Some(candidate) = rtcp_candidate {
            self.inner.gatherer.push_candidate(candidate);
        }
        if let Some(rtcp_socket) = rtcp_socket {
            let _ = self
                .inner
                .selected_rtcp_socket
                .send(Some(rtcp_socket));
        }

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
            .find(|candidate| candidate.component == 1)
            .unwrap_or_else(|| {
                IceCandidate::host(
                    SocketAddr::new(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST), 0),
                    1,
                )
            });
        let pair = IceCandidatePair::new(local_candidate, remote_candidate);
        *self.inner.selected_pair.lock() = Some(pair.clone());
        let _ = self.inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&self.inner, &pair) {
            let _ = self.inner.selected_socket.send(Some(socket.clone()));
            publish_selected_rtcp_socket(&self.inner, Some(socket));
        }
        let _ = self.inner.set_state(IceTransportState::Connected);
    }

    /// Best-effort explicit destruction of all TURN allocations (RFC 5766 §7.4).
    ///
    /// Sends a Refresh request with LIFETIME=0 to each TURN server. The server
    /// releases the allocation on receipt of the request; the success response
    /// is informational. Runs on a detached task so it never blocks `stop()` /
    /// `PeerConnection::close()`.
    fn destroy_turn_allocations_best_effort(&self) {
        // Synchronous, no spawn/await: build a Refresh(LIFETIME=0) packet and
        // fire it off via non-blocking UDP. We do NOT wait for a response or
        // retry on stale-nonce — the server destroys the allocation on receipt
        // (RFC 5766 §7.4) and eventually times it out if the packet is lost.
        let clients: Vec<Arc<TurnClient>> = {
            let map = self.inner.gatherer.turn_clients.lock();
            map.values().cloned().collect()
        };
        for client in &clients {
            if let Ok((bytes, _tx_id)) = client.create_destroy_packet_sync()
                && client.try_send_sync(&bytes)
            {
                trace!("TURN allocation destroy Refresh(LIFETIME=0) sent (best-effort)");
            }
        }
    }

    pub fn stop(&self) {
        // Best-effort explicit TURN allocation destruction (RFC 5766 §7.4).
        // Spawned BEFORE flipping state to Closed so the TURN read loops that
        // dispatch the success/stale-nonce responses are still alive. The server
        // releases the allocation on receipt of Refresh(LIFETIME=0) regardless
        // of whether we observe the response, so this is robust even if the
        // detached task races the read-loop shutdown.
        self.destroy_turn_allocations_best_effort();

        // Best-effort UPnP port mapping cleanup. Guarded: only spawn when a
        // tokio runtime is alive (normal close). During runtime teardown
        // (Drop) this is skipped — port mapping leases expire on the router.
        // Detached best-effort UPnP cleanup: only possible on a live tokio
        // runtime (normal close). During runtime teardown the handle is
        // unavailable and the mappings are abandoned (process is exiting).
        #[cfg(feature = "std")]
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let upnp_clone = self.inner.gatherer.clone();
            handle.spawn(async move {
                upnp_clone.cleanup_upnp_mappings().await;
            });
        }

        let _ = self.inner.set_state(IceTransportState::Closed);
        let _ = self.inner.selected_socket.send(None);
        let _ = self.inner.selected_rtcp_socket.send(None);
        let _ = self.inner.selected_pair_notifier.send(None);
        *self.inner.selected_pair.lock() = None;
        self.inner.gatherer.sockets.lock().clear();
        self.inner.gatherer.tcp_listeners.lock().clear();
        self.inner.gatherer.tcp_streams.lock().clear();
        self.inner.gatherer.shared_tcp_regs.lock().clear();
        self.inner.gatherer.shared_udp_regs.lock().clear();
        self.inner.gatherer.turn_clients.lock().clear();
        // Drop the shared-UDP handle so the demux port's per-session state is
        // released immediately instead of waiting for Arc<IceTransportInner>.
        *self.inner.gatherer.shared_udp_socket.lock() = None;
    }

    /// Force the ICE transport into a specific state (test-only).
    ///
    /// Used to simulate ICE reconnect cycles in unit tests without running a
    /// full ICE stack.  Production code must never call this.
    #[cfg(test)]
    pub fn force_state_for_test(&self, state: IceTransportState) {
        let _ = self.inner.set_state(state);
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
            let _ = self.inner.selected_socket.send(Some(socket.clone()));
            publish_selected_rtcp_socket(&self.inner, Some(socket));
        }
        let _ = self.inner.set_state(IceTransportState::Connected);
    }

    pub fn config(&self) -> &RtcConfiguration {
        &self.inner.config
    }

    pub fn get_selected_socket(&self) -> Option<IceSocketWrapper> {
        if let Some(socket) = self.inner._socket_rx_keeper.borrow().clone() {
            return Some(socket);
        }
        let pair = self.inner.selected_pair.lock().clone()?;
        resolve_socket(&self.inner, &pair)
    }

    pub fn get_selected_pair(&self) -> Option<IceCandidatePair> {
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
            debug!(
                count = buffer.len(),
                "Flushing buffered RTP packets to newly registered data_receiver"
            );
            buffer.drain(..).collect()
        };

        let mut marshal_buf = Vec::new();
        for (packet, addr) in packets {
            receiver
                .receive(Bytes::from(packet), addr, &mut marshal_buf)
                .await;
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
        marshal_buf: &mut Vec<u8>,
    ) {
        // Check for ChannelData (0x4000 - 0x7FFF)
        if packet.len() >= 4 {
            let channel_num = u16::from_be_bytes([packet[0], packet[1]]);
            if (0x4000..=0x7FFF).contains(&channel_num) {
                let len = u16::from_be_bytes([packet[2], packet[3]]) as usize;
                if packet.len() >= 4 + len {
                    let data = &packet[4..4 + len];
                    if let Some(peer_addr) = client.get_peer(channel_num).await {
                        handle_packet(
                            data,
                            peer_addr,
                            inner.clone(),
                            IceSocketWrapper::Turn(client.clone(), relayed_addr),
                            marshal_buf,
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
                        marshal_buf,
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
                    marshal_buf,
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

    let remotes = inner.remote_candidates.lock().clone();
    let role = *inner.role.lock();

    if remotes.is_empty() {
        return;
    }

    let mut locals = inner.gatherer.local_candidates();

    // Controlling agents may have no gathered locals when UDP is disabled and no TCP
    // passive port range is configured. Synthesize active TCP locals so we open
    // outbound connections to remote passive TCP candidates (RFC 6544).
    if locals.is_empty() && role == IceRole::Controlling {
        use core::net::{IpAddr, Ipv4Addr};
        for remote in &remotes {
            if remote.transport == "tcp" && remote.tcp_type == Some(TcpType::Passive) {
                locals.push(IceCandidate::tcp(
                    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
                    remote.component,
                    "active",
                ));
            }
        }
    }

    if locals.is_empty() {
        return;
    }

    let mut pairs = Vec::new();

    for local in &locals {
        for remote in &remotes {
            if local.transport != remote.transport {
                continue;
            }
            if local.component != remote.component {
                continue;
            }
            // Filter out Loopback -> Non-Loopback to avoid EADDRNOTAVAIL (os error 49)
            if local.address.ip().is_loopback() && !remote.address.ip().is_loopback() {
                continue;
            }
            if local.address.is_ipv4() != remote.address.is_ipv4() {
                continue;
            }
            // For Controlled role with TCP passive candidates, skip connectivity checks.
            // The pair will be selected when the Controlling side connects via TCP
            // and sends USE-CANDIDATE.
            if role == IceRole::Controlled
                && local.transport == "tcp"
                && local.tcp_type == Some(TcpType::Passive)
            {
                continue;
            }
            pairs.push(IceCandidatePair::new(local.clone(), remote.clone()));
        }
    }

    // Sort by priority
    pairs.sort_by_key(|p| core::cmp::Reverse(p.priority(role)));

    // If configured, demote host candidate pairs behind NAT so that srflx
    // pairs are checked first.  A host behind NAT may pass a single STUN
    // binding check but then fail the DTLS handshake, whereas the srflx
    // candidate (mapped public IP) works reliably.
    // Only demote when the remote is NOT also a private host — same-LAN pairs
    // (e.g. 192.168.1.x ↔ 192.168.1.y) keep their high priority.
    if inner.config.prefer_srflx_over_natted_host {
        let is_private_ip = |ip: core::net::IpAddr| -> bool {
            match ip {
                core::net::IpAddr::V4(v4) => v4.is_private(),
                core::net::IpAddr::V6(v6) => v6.is_unique_local(),
            }
        };
        let is_behind_nat = |pair: &IceCandidatePair| -> bool {
            pair.local.typ == IceCandidateType::Host
                && is_private_ip(pair.local.address.ip())
                && !(pair.remote.typ == IceCandidateType::Host
                    && is_private_ip(pair.remote.address.ip()))
        };
        pairs.sort_by(|a, b| {
            let a_natted = is_behind_nat(a);
            let b_natted = is_behind_nat(b);
            if a_natted != b_natted {
                return a_natted.cmp(&b_natted);
            }
            b.priority(role).cmp(&a.priority(role))
        });
    }

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
                Err(e) => {
                    // Per-pair failures are expected in mixed networks (unreachable
                    // LAN candidates, stale addresses, ...) — ICE keeps working via
                    // the other pairs. Keep them at trace to avoid log spam and tag
                    // with the configured label (call id) for correlation.
                    trace!(
                        label = inner.config.label.as_deref().unwrap_or("-"),
                        "ICE connectivity check failed: {} -> {}: {}",
                        local.address,
                        remote.address,
                        e
                    );
                    None
                }
            }
        });
    }

    if checks.is_empty() {
        return;
    }

    #[cfg(feature = "std")]
    use futures::stream::StreamExt;
    let mut successful_pairs: Vec<IceCandidatePair> = Vec::new();

    // Collect successful pairs. Once the first usable pair arrives, only wait a
    // short grace window for additional (possibly higher-priority) pairs before
    // proceeding to nomination. This keeps a single unreachable candidate (e.g.
    // a stale LAN host candidate returning EHOSTDOWN/EHOSTUNREACH) from stalling
    // connection setup for the full STUN timeout — all checks still run
    // concurrently, but nomination is no longer gated on the slowest failing pair.
    const NOMINATION_GRACE: Duration = Duration::from_millis(200);
    loop {
        let next = if successful_pairs.is_empty() {
            checks.next().await
        } else {
            // checks arm polled first each wake (matches the old `biased;`).
            let mut checks_fut = core::pin::pin!(checks.next());
            let mut grace_fut = core::pin::pin!(crate::platform::task::sleep(NOMINATION_GRACE));
            match crate::platform::select::select2(&mut checks_fut, &mut grace_fut).await {
                crate::platform::select::Either::A(res) => res,
                crate::platform::select::Either::B(_) => break,
            }
        };

        match next {
            Some(pair) => {
                if let Some(pair) = pair {
                    // Skip duplicates (same local+remote already collected)
                    let key = (pair.local.address, pair.remote.address);
                    if !successful_pairs
                        .iter()
                        .any(|p| (p.local.address, p.remote.address) == key)
                    {
                        successful_pairs.push(pair);
                    }
                }
            }
            None => break,
        }
    }

    if successful_pairs.is_empty() {
        // Don't transition to Failed — trickle ICE candidates may arrive
        // later via add_remote_candidate and trigger new connectivity checks.
        // The disconnect monitor (ice_connection_timeout) handles long-term
        // connectivity failure.
        return;
    }

    // Sort by priority: host > srflx > relay.  P2P first, relay last.
    successful_pairs.sort_by_key(|p| core::cmp::Reverse(p.priority(role)));

    for p in &successful_pairs {
        debug!(
            label = inner.config.label.as_deref().unwrap_or("-"),
            "ICE successful pair ({}): local {} {:?} -> remote {} {:?}",
            if role == IceRole::Controlling {
                "controlling"
            } else {
                "controlled"
            },
            p.local.address,
            p.local.typ,
            p.remote.address,
            p.remote.typ
        );
    }

    if role == IceRole::Controlling {
        // Signal Connected so the PeerConnection starts waiting for nomination_complete.
        let _ = inner.set_state(IceTransportState::Connected);

        // Nominate once. Late trickle candidates re-trigger connectivity checks;
        // re-nominating on every round would make the controlled peer flap
        // between pairs (RFC 8445 nominates a single pair for the session —
        // re-nomination is only expected after an ICE restart, which resets
        // nomination state).
        if inner.nomination_complete.borrow().is_some() {
            debug!(
                label = inner.config.label.as_deref().unwrap_or("-"),
                "ICE checks complete (controlling): already nominated, keeping selected pair"
            );
            return;
        }

        // RFC 8445 regular nomination: send USE-CANDIDATE on exactly ONE pair
        // — the highest-priority pair that passed connectivity checks
        // (`successful_pairs` is already sorted best-first). Nominating every
        // successful pair in parallel (the previous behaviour) sends
        // USE-CANDIDATE on multiple pairs, leaving the controlled peer unable
        // to tell which is authoritative; it had to freeze/guess, and when a
        // real controlling peer later re-nominated (e.g. a browser abandoning
        // a dead srflx path for its relay) the frozen side kept DTLS pointed
        // at the stale address and the handshake never completed. A single
        // authoritative nomination makes re-nomination unambiguous.
        //
        // Try pairs in priority order; a nomination binding check can still be
        // lost, so fall through to the next successful pair. Bound the whole
        // phase to a single nomination_timeout so a lossy link cannot multiply
        // the latency by the candidate count (which previously stalled setup
        // for N × nomination_timeout under high packet loss).
        let nomination_start = crate::platform::time::Instant::now();
        let mut nominated_pair: Option<IceCandidatePair> = None;
        for (idx, pair) in successful_pairs.iter().enumerate() {
            // Always attempt the best pair; only bound the fallbacks.
            if idx > 0
                && crate::platform::time::Instant::now().duration_since(nomination_start)
                    >= inner.config.nomination_timeout
            {
                debug!("Nomination deadline reached before trying all candidate pairs");
                break;
            }
            debug!(
                label = inner.config.label.as_deref().unwrap_or("-"),
                "Controlling agent nominating pair: {} -> {}",
                pair.local.address,
                pair.remote.address
            );
            match perform_binding_check(&pair.local, &pair.remote, &inner, role, true).await {
                Ok(_) => {
                    debug!(
                        label = inner.config.label.as_deref().unwrap_or("-"),
                        "Nomination succeeded: {} -> {}", pair.local.address, pair.remote.address
                    );
                    nominated_pair = Some(pair.clone());
                    break;
                }
                Err(e) => {
                    debug!(
                        label = inner.config.label.as_deref().unwrap_or("-"),
                        "Nomination failed for {} -> {}: {}",
                        pair.local.address,
                        pair.remote.address,
                        e
                    );
                }
            }
        }

        // Fall back to the highest-priority pair on all-fail so best-effort
        // data still has a path.
        let final_pair = nominated_pair
            .clone()
            .unwrap_or_else(|| successful_pairs[0].clone());
        let nominated = nominated_pair.is_some();
        *inner.selected_pair.lock() = Some(final_pair.clone());
        let _ = inner.selected_pair_notifier.send(Some(final_pair.clone()));
        if let Some(socket) = resolve_socket(&inner, &final_pair) {
            let _ = inner.selected_socket.send(Some(socket.clone()));
            publish_selected_rtcp_socket(&inner, Some(socket));
        }
        debug!(
            label = inner.config.label.as_deref().unwrap_or("-"),
            "ICE checks complete. Selected pair: {} -> {}",
            final_pair.local.address,
            final_pair.remote.address
        );

        if nominated {
            let _ = inner.nomination_complete.send(Some(true));
        } else {
            let _ = inner.nomination_complete.send(Some(false));
            let _ = inner.set_state(IceTransportState::Failed);
        }
    } else {
        // Controlled side: select best pair but don't nominate.
        // nomination_complete is signalled when we receive USE-CANDIDATE
        // from the controlling agent.
        //
        // Once the peer has nominated a pair, that choice is authoritative
        // and this selection must not run again: check rounds re-triggered
        // by late (e.g. peer-reflexive) candidates would otherwise stomp the
        // nominated pair with a locally-preferred one the peer never chose.
        if inner.nomination_complete.borrow().is_some() {
            debug!(
                label = inner.config.label.as_deref().unwrap_or("-"),
                "ICE checks complete (controlled): keeping peer-nominated pair"
            );
            return;
        }
        let pair = &successful_pairs[0];
        *inner.selected_pair.lock() = Some(pair.clone());
        let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
        if let Some(socket) = resolve_socket(&inner, pair) {
            let _ = inner.selected_socket.send(Some(socket.clone()));
            publish_selected_rtcp_socket(&inner, Some(socket));
        }
        let _ = inner.set_state(IceTransportState::Connected);
        if pair.local.transport == "tcp" {
            let _ = inner.nomination_complete.send(Some(true));
        }
        debug!(
            label = inner.config.label.as_deref().unwrap_or("-"),
            "ICE checks complete. Selected pair: {} -> {}", pair.local.address, pair.remote.address
        );

        // Controlled side with a working path but no USE-CANDIDATE yet:
        // the controlling agent's nomination is still in flight (our checks
        // complete before its do under asymmetric timing). Keep the selected
        // pair and wait, bounded by nomination_timeout — a dead controlling
        // agent still fails the transport via the PC-level timeout.
        if pair.local.transport != "tcp"
            && inner.nomination_complete.borrow().is_none()
        {
            debug!(
                label = inner.config.label.as_deref().unwrap_or("-"),
                "Controlled checks complete without nomination — waiting for USE-CANDIDATE"
            );
            let deadline = Instant::now() + inner.config.nomination_timeout;
            while Instant::now() < deadline
                && inner.nomination_complete.borrow().is_none()
                && inner.state.borrow().clone() == IceTransportState::Connected
            {
                crate::platform::task::sleep(core::time::Duration::from_millis(20)).await;
            }
            if inner.nomination_complete.borrow().is_none() {
                debug!(
                    label = inner.config.label.as_deref().unwrap_or("-"),
                    "Nomination did not arrive in time; keeping best-effort selected pair"
                );
                let _ = inner.nomination_complete.send(Some(true));
            }
        }
    }
}

fn resolve_socket(inner: &IceTransportInner, pair: &IceCandidatePair) -> Option<IceSocketWrapper> {
    if pair.local.typ == IceCandidateType::Relay {
        let clients = inner.gatherer.turn_clients.lock();
        clients
            .get(&pair.local.address)
            .map(|c| IceSocketWrapper::Turn(c.clone(), pair.local.address))
    } else if pair.local.transport == "tcp" {
        // Prefer the accepted inbound stream that matches the nominated remote peer.
        // get_tcp_socket() keys by listener local_addr and may return a stale socket
        // when multiple sessions share a passive port range.
        let streams = inner.gatherer.tcp_streams.lock();
        for wrapper in streams.values() {
            #[cfg(feature = "std")]
            if let IceSocketWrapper::TcpStream(_, _, peer) = wrapper
                && *peer == pair.remote.address
            {
                return Some(wrapper.clone());
            }
        }
        drop(streams);
        inner.gatherer.get_tcp_socket(pair.local.base_address())
    } else {
        // Shared UDP mux socket backs the single host candidate when active.
        if pair.local.typ == IceCandidateType::Host
            && let Some(shared) = inner.gatherer.shared_udp_socket.lock().clone()
        {
            return Some(shared);
        }
        // Factory-bound platform sockets (rtcembed / loopback backends).
        if let Some(platform) = inner.gatherer.get_platform_socket(pair.local.base_address()) {
            return Some(IceSocketWrapper::Platform(platform));
        }
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

fn publish_selected_socket(
    inner: &IceTransportInner,
    pair: &IceCandidatePair,
    inbound: Option<&IceSocketWrapper>,
) {
    // Inbound TCP is authoritative for passive ICE-TCP: the controlling peer
    // connected to us on this stream and nominated it via USE-CANDIDATE.
    let socket = match inbound {
        #[cfg(feature = "std")]
        Some(s @ IceSocketWrapper::TcpStream(_, _, _)) => Some(s.clone()),
        _ => resolve_socket(inner, pair),
    };
    if let Some(socket) = socket {
        #[cfg(feature = "std")]
        let inbound_tcp = matches!(inbound, Some(IceSocketWrapper::TcpStream(_, _, _)));
        #[cfg(not(feature = "std"))]
        let inbound_tcp = false;
        debug!(
            pair_local = %pair.local.address,
            pair_remote = %pair.remote.address,
            socket = %socket.diag(),
            inbound_tcp,
            "ICE: published selected socket"
        );
        let _ = inner.selected_socket.send(Some(socket.clone()));
        publish_selected_rtcp_socket(inner, Some(socket));
    }
}

/// Apply a verified controlled-side nomination only if it is still the most
/// recent one. `generation` is the value captured when the USE-CANDIDATE that
/// spawned the verification was handled; any newer nomination (or an ICE
/// restart) bumps `nomination_generation`, in which case this returns `false`
/// and leaves the currently selected pair untouched.
fn commit_verified_nomination(
    inner: &IceTransportInner,
    generation: u64,
    pair: &IceCandidatePair,
    sender: &IceSocketWrapper,
) -> bool {
    if inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst)
        != generation
    {
        return false;
    }
    *inner.selected_pair.lock() = Some(pair.clone());
    let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
    publish_selected_socket(inner, pair, Some(sender));
    true
}

#[cfg(feature = "std")]
async fn complete_controlled_inbound_tcp_nomination(
    sender: &IceSocketWrapper,
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
) {
    if *inner.role.lock() != IceRole::Controlled {
        return;
    }
    #[cfg(feature = "std")]
    let IceSocketWrapper::TcpStream(read, _, _) = sender else {
        return;
    };
    if inner.nomination_complete.borrow().is_some() {
        if let Some(pair) = inner.selected_pair.lock().clone() {
            publish_selected_socket(&inner, &pair, Some(sender));
        }
        return;
    }

    let local_addr: SocketAddr = {
        let s = read.lock().await;
        s.local_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
    };

    let locals = inner.gatherer.local_candidates();
    let local_cand = locals.iter().find(|c| {
        c.base_address() == local_addr
            || (c.transport == "tcp"
                && c.base_address().port() == local_addr.port()
                && (c.base_address().ip().is_unspecified() || local_addr.ip().is_unspecified()))
    });

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
            "Controlled agent selected pair via inbound TCP nomination: {} -> {}",
            pair.local.address, pair.remote.address
        );
        // A TCP nomination supersedes any pending UDP path verification.
        inner
            .nomination_generation
            .fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        *inner.selected_pair.lock() = Some(pair.clone());
        let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
        publish_selected_socket(&inner, &pair, Some(sender));
        let _ = inner.set_state(IceTransportState::Connected);
    } else {
        debug!(
            "Inbound TCP nomination: synthesizing pair for {} -> {}",
            local_addr, addr
        );
        let local_cand = locals.iter().find(|c| {
            c.transport == "tcp"
                && c.tcp_type == Some(TcpType::Passive)
                && (c.base_address().port() == local_addr.port()
                    || c.address.port() == local_addr.port())
        });
        let remote_cand = {
            let remotes = inner.remote_candidates.lock();
            remotes.iter().find(|c| c.address == addr).cloned()
        };
        if let (Some(l), Some(r)) = (local_cand, remote_cand) {
            let pair = IceCandidatePair::new(l.clone(), r.clone());
            *inner.selected_pair.lock() = Some(pair.clone());
            let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
            publish_selected_socket(&inner, &pair, Some(sender));
            let _ = inner.set_state(IceTransportState::Connected);
        } else {
            let _ = inner.selected_socket.send(Some(sender.clone()));
            publish_selected_rtcp_socket(&inner, Some(sender.clone()));
        }
    }
    let _ = inner.nomination_complete.send(Some(true));
    let pair_summary = inner
        .selected_pair
        .lock()
        .as_ref()
        .map(|p| format!("{} -> {}", p.local.address, p.remote.address))
        .unwrap_or_else(|| format!("(no pair) peer={addr}"));
    debug!(
        peer = %addr,
        local_bind = %local_addr,
        pair = %pair_summary,
        socket = %sender.diag(),
        "ICE: passive TCP nomination complete"
    );
}

fn resolve_rtcp_socket(inner: &IceTransportInner) -> Option<IceSocketWrapper> {
    let candidate = inner
        .gatherer
        .local_candidates()
        .into_iter()
        .find(|candidate| candidate.component == 2)?;

    if candidate.typ == IceCandidateType::Relay {
        let clients = inner.gatherer.turn_clients.lock();
        clients
            .get(&candidate.address)
            .map(|client| IceSocketWrapper::Turn(client.clone(), candidate.address))
    } else if candidate.transport == "tcp" {
        inner.gatherer.get_tcp_socket(candidate.base_address())
    } else {
        // Factory-bound platform sockets (rtcembed / loopback backends).
        if let Some(platform) = inner.gatherer.get_platform_socket(candidate.base_address()) {
            return Some(IceSocketWrapper::Platform(platform));
        }
        let socket = inner.gatherer.get_socket(candidate.base_address());
        if socket.is_none() {
            debug!(
                "resolve_rtcp_socket: failed to find socket for {}",
                candidate.base_address()
            );
        }
        socket.map(IceSocketWrapper::Udp)
    }
}

fn publish_selected_rtcp_socket(inner: &IceTransportInner, fallback: Option<IceSocketWrapper>) {
    if let Some(socket) = resolve_rtcp_socket(inner).or(fallback) {
        let _ = inner.selected_rtcp_socket.send(Some(socket));
    }
}

async fn bind_direct_rtcp_socket(
    inner: &IceTransportInner,
    rtp_base: SocketAddr,
    advertised_ip: IpAddr,
) -> RtcResult<(IceSocketWrapper, IceCandidate)> {
    let rtcp_bind_addr = rtp_base
        .port()
        .checked_add(1)
        .map(|port| SocketAddr::new(rtp_base.ip(), port));
    let rtcp = if let Some(addr) = rtcp_bind_addr {
        match inner.gatherer.bind_one(addr).await {
            Ok(socket) => socket,
            Err(err) => {
                debug!(
                    "Failed to bind RTCP socket on {}, falling back to ephemeral port: {}",
                    addr, err
                );
                inner
                    .gatherer
                    .bind_one(SocketAddr::new(rtp_base.ip(), 0))
                    .await?
            }
        }
    } else {
        inner
            .gatherer
            .bind_one(SocketAddr::new(rtp_base.ip(), 0))
            .await?
    };
    let local_rtcp_addr = rtcp.local_addr()?;
    inner.gatherer.register_bound(&rtcp);

    let mut rtcp_cand_addr = local_rtcp_addr;
    rtcp_cand_addr.set_ip(advertised_ip);
    let mut candidate = IceCandidate::host(rtcp_cand_addr, 2);
    if rtcp_cand_addr != local_rtcp_addr {
        candidate.related_address = Some(local_rtcp_addr);
    }
    Ok((rtcp, candidate))
}


async fn handle_packet(
    packet: &[u8],
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
    sender: IceSocketWrapper,
    marshal_buf: &mut Vec<u8>,
) {    if should_drop_packet() {
        return;
    }
    inner.last_received_nanos.store(
        inner.created_at.elapsed().as_nanos() as u64,
        Ordering::Relaxed,
    );
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
                    // Dispatch error responses to pending transactions so that callers
                    // waiting on send_and_await_inner (e.g. TURN Refresh, ChannelBind)
                    // can receive 401/438 and retry with a fresh nonce instead of timing out.
                    let mut map = inner.pending_transactions.lock();
                    if let Some(tx) = map.remove(&msg.transaction_id) {
                        let _ = tx.send(msg);
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
            rx.receive(Bytes::copy_from_slice(packet), addr, marshal_buf)
                .await;
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
                        // Rate-limit: warn on the first drop and every 1000th
                        // thereafter, so a persistently-full buffer does not
                        // spam per packet (drops are also counted in buffer_stats).
                        let dropped = stats.packets_dropped.load(Ordering::Relaxed);
                        if dropped == 0 || dropped.is_multiple_of(1000) {
                            tracing::warn!(src = %addr, capacity, "RTP buffer full — dropping inbound packet (DropNew strategy)");
                        }
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
                trace!(
                    "Buffer stats: received={}, dropped={}, current={}, peak={}, capacity={}",
                    received, dropped, current_size, peak_size, capacity
                );
                *last_log = Instant::now();
            }
        }
    }
}

/// Round-trip a binding request on a newly nominated path. Returns true when
/// the peer answers on that path, proving media can actually flow there.
///
/// Used by the Controlled UseCandidate handler: once a session is already
/// running on a nominated pair, a second nomination must prove the new path
/// is live (the controlling peer answers checks on a path it truly switched
/// to) before the SRTP downlink is diverted onto it.
async fn verify_nominated_path(
    sender: &IceSocketWrapper,
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
) -> bool {
    let remote_params = inner.remote_parameters.lock().clone();
    let Some(rp) = remote_params else {
        return false;
    };
    let local_params = inner.local_parameters.lock().clone();

    let tx_id = random_bytes::<12>();
    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
    msg.attributes.push(StunAttribute::Username(format!(
        "{}:{}",
        rp.username_fragment, local_params.username_fragment
    )));
    let bytes = match msg.encode(Some(rp.password.as_bytes()), true) {
        Ok(b) => b,
        Err(_) => return false,
    };

    let (tx, rx) = oneshot::channel();
    {
        let mut map = inner.pending_transactions.lock();
        map.insert(tx_id, tx);
    }

    if let Err(e) = sender.send_to(&bytes, addr).await {
        inner.pending_transactions.lock().remove(&tx_id);
        debug!("Path verification send to {} failed: {}", addr, e);
        return false;
    }

    let verified = with_timeout(inner.config.stun_timeout, rx)
        .await
        .map(|res| res.is_ok())
        .unwrap_or(false);
    if !verified {
        let mut map = inner.pending_transactions.lock();
        map.remove(&tx_id);
    }
    verified
}

async fn handle_stun_request(
    sender: &IceSocketWrapper,
    msg: &StunDecoded,
    addr: SocketAddr,
    inner: Arc<IceTransportInner>,
) {
    let response = StunMessage::binding_success_response(msg.transaction_id, addr);

    #[cfg(any(test, feature = "simulator"))]
    simulate_stun_respond_delay(sender).await;

    let password = inner.local_parameters.lock().password.clone();
    if let Ok(bytes) = response.encode(Some(password.as_bytes()), true) {
        match sender.send_to(&bytes, addr).await {
            Ok(_) => trace!("Sent STUN Response to {}", addr),
            Err(e) => {
                // send failures (incl. unreachable/err65/49) are logged and
                // tolerated — STUN retransmits recover
                debug!("Failed to send STUN Response to {}: {}", addr, e);
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
        let transport = match sender {
            IceSocketWrapper::Platform(_)
            | IceSocketWrapper::Udp(_)
            | IceSocketWrapper::SharedUdp(_) => "udp",
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpListener(_) | IceSocketWrapper::TcpStream(_, _, _) => "tcp",
            IceSocketWrapper::Turn(_, _) => "udp",
        };
        let mut candidate = IceCandidate::host(addr, 1); // Use host for now, or prflx
        candidate.typ = IceCandidateType::PeerReflexive;
        candidate.transport = transport.to_string();
        candidate.foundation = IceCandidate::compute_foundation(
            IceCandidateType::PeerReflexive,
            candidate.base_address(),
            transport,
        );
        candidate.priority = if transport == "tcp" {
            IceCandidate::priority_for_tcp(IceCandidateType::PeerReflexive, 1, TcpType::Passive)
        } else {
            IceCandidate::priority_for(IceCandidateType::PeerReflexive, 1)
        };

        let mut list = inner.remote_candidates.lock();
        list.push(candidate);
        drop(list);

        let _ = inner.cmd_tx.send(IceCommand::RunChecks);
    }
    // ICE-layer latching retargets the selected pair when an inbound STUN
    // arrives from the same port on a different IP. That is an RTP/SRTP-mode
    // concept (plain RTP peers may legitimately change source addresses
    // mid-stream). For WebRTC the SRTP media path must stay pinned to the
    // nominated pair: retargeting it onto an address the peer never nominated
    // blackholes media while consent keepalives still flow on the original
    // socket.
    if inner.config.enable_latching && inner.config.transport_mode != crate::TransportMode::WebRtc {
        let current_pair = inner.selected_pair.lock().clone();
        if let Some(pair) = current_pair
            && pair.remote.address.port() == addr.port()
            && pair.remote.address.ip() != addr.ip()
        {
            debug!(
                "RTP latching: updating remote address from {} to {}",
                pair.remote.address, addr
            );
            let mut new_remote = pair.remote.clone();
            new_remote.address = addr;
            let new_pair = IceCandidatePair::new(pair.local.clone(), new_remote);
            *inner.selected_pair.lock() = Some(new_pair.clone());
            let _ = inner.selected_pair_notifier.send(Some(new_pair.clone()));
            publish_selected_socket(&inner, &new_pair, Some(sender));
        }
    }

    #[cfg(feature = "std")]
    complete_controlled_inbound_tcp_nomination(sender, addr, inner.clone()).await;
    #[cfg(not(feature = "std"))]
    {
        let _ = (sender, &addr, &inner);
    }

    if msg.use_candidate {
        let role = *inner.role.lock();
        if role == IceRole::Controlled {
            // TCP passive nomination is handled above; UDP still uses USE-CANDIDATE below.
            #[cfg(feature = "std")]
            if matches!(sender, IceSocketWrapper::TcpStream(_, _, _)) {
                #[allow(unused_mut, unused_variables)]
                let sender = &sender;
                return;
            }
            // A newer USE-CANDIDATE supersedes any pending path verification:
            // the most recent nomination wins (RFC 8445 §8.1.1). Capture this
            // nomination's generation so a deferred verifier can detect that it
            // has since been superseded and must not move media (issue #55).
            let use_candidate_generation = inner
                .nomination_generation
                .fetch_add(1, core::sync::atomic::Ordering::SeqCst)
                + 1;
            // The controlling agent is authoritative, but "authoritative"
            // does not mean media should be diverted onto an unproven path.
            // Two failure modes motivated the current design:
            //
            //   * Freezing on the first nomination (very old behaviour) broke
            //     legitimate browser path-failover: a browser whose srflx path
            //     died re-sends USE-CANDIDATE on its relay path, and a frozen
            //     controlled agent kept sending DTLS to the abandoned address.
            //   * Following every USE-CANDIDATE unconditionally let duplicate
            //     or oscillating nominations (e.g. a browser nominating both
            //     multi-homed host candidates of the server) divert the SRTP
            //     downlink onto a path the peer never sends media on, so the
            //     call keeps "flowing" on PBX counters while the user hears
            //     nothing.
            //
            // The current behaviour follows the RFC 8445 intent while staying
            // safe: the FIRST nomination is followed immediately; a later
            // nomination on a different pair must pass a same-path round trip
            // (see `verify_nominated_path`) before media is switched. Genuine
            // failovers answer checks on the new path and converge within one
            // RTT; dead paths never respond and are ignored.
            let local_addr: SocketAddr = match sender {
                IceSocketWrapper::Platform(s) => s
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                IceSocketWrapper::Udp(s) => s
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                IceSocketWrapper::SharedUdp(h) => h
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                #[cfg(feature = "std")]
                IceSocketWrapper::TcpListener(l) => l
                    .local_addr()
                    .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap()),
                #[cfg(feature = "std")]
                IceSocketWrapper::TcpStream(read, _, _) => {
                    let s = read.lock().await;
                    s.local_addr()
                        .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap())
                }
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
                let same_pair = {
                    let selected = inner.selected_pair.lock();
                    selected
                        .as_ref()
                        .map(|cur| {
                            cur.local.address == pair.local.address
                                && cur.remote.address == pair.remote.address
                        })
                        .unwrap_or(false)
                };
                let has_selected = inner.selected_pair.lock().is_some();

                if same_pair {
                    trace!(
                        "Controlled agent keeping current pair (UseCandidate {} -> {})",
                        pair.local.address, pair.remote.address
                    );
                } else if !has_selected {
                    // First nomination: follow immediately so call setup is
                    // never delayed.
                    debug!(
                        label = inner.config.label.as_deref().unwrap_or("-"),
                        "Controlled agent following UseCandidate (first nomination): {} -> {}",
                        pair.local.address,
                        pair.remote.address
                    );
                    *inner.selected_pair.lock() = Some(pair.clone());
                    let _ = inner.selected_pair_notifier.send(Some(pair.clone()));
                    publish_selected_socket(&inner, &pair, Some(sender));
                } else {
                    // A second nomination on a DIFFERENT pair while already
                    // connected: verify the new path with a same-path round
                    // trip before diverting media to it. A controlling peer
                    // that genuinely switched (dead path → relay failover)
                    // answers checks on the new path; duplicate or oscillating
                    // nominations on dead paths never respond and are ignored,
                    // keeping the working path (and its established DTLS/SRTP
                    // session) intact.
                    debug!(
                        label = inner.config.label.as_deref().unwrap_or("-"),
                        "Controlled agent deferring switch to newly nominated path {} -> {} until verified",
                        pair.local.address,
                        pair.remote.address
                    );
                    let inner2 = inner.clone();
                    let sender2 = sender.clone();
                    let pair2 = pair.clone();
                    crate::platform::task::spawn(async move {
                        let verified = verify_nominated_path(&sender2, addr, inner2.clone()).await;
                        if !verified {
                            debug!(
                                label = inner2.config.label.as_deref().unwrap_or("-"),
                                "New nominated path {} -> {} failed verification; keeping current pair",
                                pair2.local.address,
                                pair2.remote.address
                            );
                        } else if commit_verified_nomination(
                            &inner2,
                            use_candidate_generation,
                            &pair2,
                            &sender2,
                        ) {
                            debug!(
                                label = inner2.config.label.as_deref().unwrap_or("-"),
                                "New nominated path verified, switching: {} -> {}",
                                pair2.local.address,
                                pair2.remote.address
                            );
                        } else {
                            debug!(
                                label = inner2.config.label.as_deref().unwrap_or("-"),
                                "New nominated path {} -> {} verified but superseded by a newer nomination; keeping current pair",
                                pair2.local.address,
                                pair2.remote.address
                            );
                        }
                    });
                }
                let _ = inner.set_state(IceTransportState::Connected);
                let _ = inner.nomination_complete.send(Some(true));
            } else {
                debug!(
                    "Received UseCandidate but could not find UDP pair for {} -> {}",
                    local_addr, addr
                );
                let _ = inner.nomination_complete.send(Some(true));
            }
        }
    }
}

struct TransactionGuard<'a> {
    map: &'a crate::platform::sync::Mutex<BTreeMap<[u8; 12], oneshot::Sender<StunDecoded>>>,
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
) -> RtcResult<()> {
    // Handle TCP candidates separately — establish connection and perform STUN over TCP
    #[cfg(feature = "std")]
    if local.transport == "tcp" && remote.transport == "tcp" {
        return perform_tcp_binding_check(local, remote, inner, role, nominated).await;
    }
    #[cfg(not(feature = "std"))]
    if local.transport == "tcp" && remote.transport == "tcp" {
        return Err(RtcError::Internal(
            "ICE-TCP is excluded from the embedded target".into(),
        ));
    }

    // For Controlled role with TCP passive candidates, don't initiate outbound checks
    if role == IceRole::Controlled && local.transport == "tcp" {
        return Ok(());
    }

    // For non-TCP candidates, transport must be UDP
    if remote.transport != "udp" {
        return Err(RtcError::Internal(format!(
            "only UDP connectivity checks are supported"
        )));
    }

    let local_params = inner.local_parameters.lock().clone();
    let remote_params = match inner.remote_parameters.lock().clone() {
        Some(p) => p,
        None => return Err(RtcError::Internal(format!("no remote params"))),
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

    let (socket, platform_socket, turn_client) = if local.typ == IceCandidateType::Relay {
        let gatherer = &inner.gatherer;
        let clients = gatherer.turn_clients.lock();
        let client = clients.get(&local.address).cloned();
        (None, None, client)
    } else {
        let socket = inner.gatherer.get_socket(local.base_address());
        let platform_socket = inner.gatherer.get_platform_socket(local.base_address());
        (socket, platform_socket, None)
    };

    if local.typ == IceCandidateType::Relay {
        let client = turn_client.as_ref().ok_or_else(|| {
            RtcError::Internal(format!("TURN client not found for relay candidate"))
        })?;

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

        match with_timeout(inner.config.stun_timeout, perm_rx).await {
            Ok(Ok(msg)) => {
                if msg.class == StunClass::ErrorResponse {
                    return Err(RtcError::Internal(format!(
                        "CreatePermission failed: {:?}",
                        msg.error_code
                    )));
                }

                // Try ChannelBind if not already bound
                if client.get_channel(remote.address).await.is_none()
                    && let Ok((bind_bytes, bind_tx_id, channel_num)) =
                        client.create_channel_bind_packet(remote.address).await
                {
                    let (bind_tx, bind_rx) = oneshot::channel();
                    {
                        let mut map = inner.pending_transactions.lock();
                        map.insert(bind_tx_id, bind_tx);
                    }

                    if client.send(&bind_bytes).await.is_ok() {
                        let client_clone = client.clone();
                        let remote_addr = remote.address;
                        let inner_weak = Arc::downgrade(inner);
                        let timeout_dur = inner.config.stun_timeout;

                        match with_timeout(timeout_dur, bind_rx).await {
                            Ok(Ok(msg)) => {
                                if msg.class == StunClass::SuccessResponse {
                                    client_clone.add_channel(remote_addr, channel_num).await;
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
            _ => {
                let mut map = inner.pending_transactions.lock();
                map.remove(&perm_tx_id);
                return Err(RtcError::Internal(format!("CreatePermission timeout")));
            }
        }
    } else if socket.is_none() && platform_socket.is_none() {
        return Err(RtcError::Internal(format!(
            "no socket found for local candidate"
        )));
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
        } else if local.transport == "tcp" {
            // For TCP transport (active side): connect to remote and send STUN
            let tcp_stream = match TcpStream::connect(remote.address).await {
                Ok(stream) => {
                    stream.set_nodelay(true).ok();
                    stream
                }
                Err(e) => {
                    debug!("TCP connect to {} failed: {}", remote.address, e);
                    return Err(e.into());
                }
            };
            #[cfg(feature = "std")]
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut tcp_stream = tcp_stream;
            let mut framed = Vec::with_capacity(2 + bytes.len());
            let flen = bytes.len() as u16;
            framed.extend_from_slice(&flen.to_be_bytes());
            framed.extend_from_slice(&bytes);
            tcp_stream.write_all(&framed).await?;
            // Read STUN response with TCP framing
            match with_timeout(inner.config.stun_timeout, async {
                let mut len_buf = [0u8; 2];
                tcp_stream.read_exact(&mut len_buf).await?;
                let resp_len = u16::from_be_bytes(len_buf) as usize;
                let mut resp_buf = vec![0u8; resp_len];
                tcp_stream.read_exact(&mut resp_buf).await?;
                StunMessage::decode(&resp_buf)
                    .map_err(|e| RtcError::Internal(format!("stun decode: {e}")))
            })
            .await
            {
                Ok(Ok(parsed)) => {
                    if parsed.class == StunClass::SuccessResponse {
                        return Ok(());
                    }
                    return Err(RtcError::Internal(format!(
                        "TCP binding check failed: unexpected response"
                    )));
                }
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(RtcError::Internal(format!("TCP binding check timeout"))),
            }
        } else if let Some(platform_socket) = &platform_socket {
            // Platform sockets report NetError without an errno carrier:
            // treat every send failure as transient and wait for the next
            // RTO (matches the tolerant path below).
            if let Err(e) = platform_socket.send_to(&bytes, remote.address).await {
                debug!(
                    "platform socket send_to {} failed (transient): {}",
                    remote.address, e
                );
            }
        } else if let Some(socket) = &socket
            && let Err(e) = socket.send_to(&bytes, remote.address).await
        {
            // std inspects io::ErrorKind; no_std treats everything as
            // transient (the Platform socket reports errors as text).
            let is_fatal = {
                #[cfg(feature = "std")]
                {
                    matches!(
                        e.kind(),
                        std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::NotConnected
                    )
                }
                #[cfg(not(feature = "std"))]
                {
                    false
                }
            };
            if is_fatal {
                debug!(
                    "socket.send_to {} fatal error, aborting nomination: {}",
                    remote.address, e
                );
                return Err(e.into());
            }
            // Transient error (e.g., EHOSTUNREACH / os error 65 during route setup).
            // Treat as a dropped send — wait for next RTO and retry.
        }

        let timeout_fut = crate::platform::task::sleep(max_timeout.saturating_sub(start.elapsed()));
        let rto_fut = crate::platform::task::sleep(rto);

        let mut timeout_fut = core::pin::pin!(timeout_fut);
        let mut rto_fut = core::pin::pin!(rto_fut);
        match crate::platform::select::select3(&mut rx, &mut timeout_fut, &mut rto_fut).await {
            crate::platform::select::Which3::A(res) => {
                let parsed = match res {
                    Ok(msg) => msg,
                    Err(_) => return Err(RtcError::Internal(format!("channel closed"))),
                };

                if parsed.transaction_id != tx_id {
                    return Err(RtcError::Internal(format!(
                        "binding response transaction mismatch"
                    )));
                }
                if parsed.method != StunMethod::Binding {
                    return Err(RtcError::Internal(format!(
                        "unexpected STUN method in binding response"
                    )));
                }
                if parsed.class != StunClass::SuccessResponse {
                    return Err(RtcError::Internal(format!("binding request failed")));
                }
                return Ok(());
            }
            crate::platform::select::Which3::B(_) => {
                return Err(RtcError::Internal(format!("timeout")));
            }
            crate::platform::select::Which3::C(_) => {
                if start.elapsed() >= max_timeout {
                    continue;
                }
                trace!(
                    "Retransmitting STUN Request to {} tx={:?}",
                    remote.address, tx_id
                );
                rto = core::cmp::min(rto * 2, Duration::from_millis(1600));
            }
        }
    }
}

/// Perform a STUN binding check over a TCP connection.
///
/// For TCP candidates (RFC 6544):
/// 1. Connect to the remote peer's TCP address
/// 2. Send the STUN binding request over the TCP stream
/// 3. Read the response, decode it, and deliver it to the pending transaction
/// 4. Store the stream for later media use
///
/// RFC 4571 STUN/TCP framing used by WebRTC (length prefix + message).
#[cfg(feature = "std")]
fn frame_stun_for_tcp(data: &[u8]) -> Vec<u8> {
    let len = data.len() as u16;
    let mut framed = Vec::with_capacity(2 + data.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(data);
    framed
}

#[cfg(feature = "std")]
type TcpReadHalf = tokio::net::tcp::OwnedReadHalf;
#[cfg(feature = "std")]
type TcpWriteHalf = tokio::net::tcp::OwnedWriteHalf;

#[cfg(feature = "std")]
fn split_tcp_stream(stream: TcpStream, peer: SocketAddr) -> IceSocketWrapper {
    if let Err(e) = stream.set_nodelay(true) {
        debug!("TCP set_nodelay failed: {}", e);
    }
    let (read, write) = stream.into_split();
    #[cfg(feature = "std")]
    IceSocketWrapper::TcpStream(
        Arc::new(Mutex::new(read)),
        Arc::new(Mutex::new(write)),
        peer,
    )
}

#[cfg(feature = "std")]
pub(crate) async fn attach_demuxed_tcp_stream(
    inner: Arc<IceTransportInner>,
    stream: TcpStream,
    peer_addr: SocketAddr,
    listen_addr: SocketAddr,
    first_packet: Vec<u8>,
) {
    let wrapper = split_tcp_stream(stream, peer_addr);
    inner
        .gatherer
        .store_tcp_stream(listen_addr, wrapper.clone());
    let _ = inner.gatherer.socket_tx.send(wrapper.clone());
    let mut marshal_buf = Vec::new();
    handle_packet(&first_packet, peer_addr, inner, wrapper, &mut marshal_buf).await;
}

#[cfg(feature = "std")]
pub(crate) async fn tcp_write_all(write: &Arc<Mutex<TcpWriteHalf>>, data: &[u8]) -> RtcResult<()> {
    let mut offset = 0;
    while offset < data.len() {
        let guard = write.lock().await;
        loop {
            match guard.try_write(&data[offset..]) {
                Ok(0) => guard.writable().await?,
                Ok(n) => {
                    offset += n;
                    break;
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => guard.writable().await?,
                Err(e) => return Err(RtcError::Internal(format!("TCP write failed: {}", e))),
            }
        }
    }
    Ok(())
}

#[cfg(feature = "std")]
async fn perform_tcp_binding_check(
    local: &IceCandidate,
    remote: &IceCandidate,
    inner: &Arc<IceTransportInner>,
    role: IceRole,
    nominated: bool,
) -> RtcResult<()> {
    debug!(
        "perform_tcp_binding_check: {} -> {}",
        local.address, remote.address
    );
    let local_params = inner.local_parameters.lock().clone();
    let remote_params = match inner.remote_parameters.lock().clone() {
        Some(p) => p,
        None => return Err(RtcError::Internal(format!("no remote params"))),
    };

    let tx_id = random_bytes::<12>();
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

    // Establish TCP connection to the remote peer
    let connect_timeout = inner.config.stun_timeout;
    let stream = with_timeout(connect_timeout, TcpStream::connect(remote.address))
        .await
        .map_err(|_| RtcError::Internal(format!("TCP connect timeout to {}", remote.address)))?
        .map_err(|e| {
            RtcError::Internal(format!("TCP connect to {} failed: {}", remote.address, e))
        })?;

    let local_addr = stream.local_addr()?;
    let wrapper = split_tcp_stream(stream, remote.address);
    let write = match &wrapper {
        #[cfg(feature = "std")]
        IceSocketWrapper::TcpStream(_, write, _) => write.clone(),
        _ => return Err(RtcError::Internal(format!("split_tcp_stream invariant"))),
    };

    // Register the TCP stream with the runner so its read loop handles incoming STUN responses
    inner.gatherer.store_tcp_stream(local_addr, wrapper.clone());
    let _ = inner.gatherer.socket_tx.send(wrapper);

    // Register pending transaction
    let (tx, mut rx) = oneshot::channel();
    {
        let mut map = inner.pending_transactions.lock();
        map.insert(tx_id, tx);
    }
    let _guard = TransactionGuard {
        map: &inner.pending_transactions,
        tx_id,
    };

    // Send STUN binding request over TCP (RFC 4571 framed)
    {
        let framed = frame_stun_for_tcp(&bytes);
        #[cfg(feature = "std")]
        tcp_write_all(&write, &framed).await?;
    }

    // Wait for response (with retransmissions) via read loop → pending_transactions
    let start = Instant::now();
    let mut rto = Duration::from_millis(500);
    let max_timeout = if nominated {
        inner.config.nomination_timeout
    } else {
        inner.config.stun_timeout
    };

    loop {
        let timeout_fut = crate::platform::task::sleep(max_timeout.saturating_sub(start.elapsed()));
        let rto_fut = crate::platform::task::sleep(rto);

        let mut timeout_fut = core::pin::pin!(timeout_fut);
        let mut rto_fut = core::pin::pin!(rto_fut);
        match crate::platform::select::select3(&mut rx, &mut timeout_fut, &mut rto_fut).await {
            crate::platform::select::Which3::A(res) => {
                let parsed = match res {
                    Ok(msg) => msg,
                    Err(_) => return Err(RtcError::Internal(format!("channel closed"))),
                };
                if parsed.transaction_id != tx_id {
                    return Err(RtcError::Internal(format!(
                        "binding response transaction mismatch"
                    )));
                }
                if parsed.method != StunMethod::Binding {
                    return Err(RtcError::Internal(format!(
                        "unexpected STUN method in binding response"
                    )));
                }
                if parsed.class != StunClass::SuccessResponse {
                    return Err(RtcError::Internal(format!("binding request failed")));
                }
                return Ok(());
            }
            crate::platform::select::Which3::B(_) => {
                return Err(RtcError::Internal(format!("timeout")));
            }
            crate::platform::select::Which3::C(_) => {
                if start.elapsed() >= max_timeout {
                    continue;
                }
                trace!(
                    "TCP Retransmitting STUN Request to {} tx={:?}",
                    remote.address, tx_id
                );
                rto = core::cmp::min(rto * 2, Duration::from_millis(1600));
                let framed = frame_stun_for_tcp(&bytes);
                #[cfg(feature = "std")]
                let _ = tcp_write_all(&write, &framed).await;
            }
        }
    }
}

/// Store `new` into the ICE state watch, notifying subscribers only when the
/// value actually changes.
///
/// `watch::Sender::send` marks the channel changed even for an identical value,
/// so re-sending `Connected` on hot paths (USE-CANDIDATE consent keepalives,
/// per-check-round completion) made the peer-connection state loop log
/// "ICE recovered" and re-broadcast on every keepalive.
fn store_ice_state(state: &watch::Sender<IceTransportState>, new: IceTransportState) {
    if *state.borrow() != new {
        let _ = state.send(new);
    }
}

impl IceTransportInner {
    fn set_state(&self, new: IceTransportState) {
        store_ice_state(&self.state, new);
    }
}

#[cfg(all(test, feature = "std"))]
mod state_tests {
    use super::{IceTransportState, store_ice_state};
    use tokio::sync::watch;

    /// Regression guard: an unchanged value must not wake subscribers.
    #[test]
    fn store_ice_state_dedupes_equal_values() {
        let (tx, mut rx) = watch::channel(IceTransportState::Checking);
        store_ice_state(&tx, IceTransportState::Connected);
        assert!(rx.has_changed().unwrap());
        let _ = rx.borrow_and_update();
        store_ice_state(&tx, IceTransportState::Connected);
        assert!(
            !rx.has_changed().unwrap(),
            "re-sending an equal state must not notify (ICE recovered spam)"
        );
        store_ice_state(&tx, IceTransportState::Disconnected);
        assert!(rx.has_changed().unwrap());
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

/// TCP candidate type per RFC 6544 § 4.5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TcpType {
    Active,
    Passive,
    So,
}

impl TcpType {
    fn as_str(&self) -> &'static str {
        match self {
            TcpType::Active => "active",
            TcpType::Passive => "passive",
            TcpType::So => "so",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "active" => Some(TcpType::Active),
            "passive" => Some(TcpType::Passive),
            "so" => Some(TcpType::So),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IceCandidate {
    pub foundation: String,
    pub priority: u32,
    pub address: SocketAddr,
    pub typ: IceCandidateType,
    pub transport: String,
    pub tcp_type: Option<TcpType>,
    pub related_address: Option<SocketAddr>,
    pub component: u16,
    /// mDNS hostname advertised in SDP instead of `address.ip()` (RFC 6762 /
    /// draft-ietf-rtcweb-mdns). The real address is kept internally so
    /// connectivity checks and pairing work unchanged; only the SDP wire form
    /// is obfuscated.
    pub hostname: Option<String>,
}

impl IceCandidate {
    fn compute_foundation(typ: IceCandidateType, base_addr: SocketAddr, transport: &str) -> String {
        // FNV-1a 64-bit: deterministic across platforms (std's DefaultHasher
        // is randomly seeded per process — wrong for a session-persistent
        // candidate foundation anyway) and available under no_std.
        fn fnv1a(parts: &[&[u8]]) -> u64 {
            let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
            for part in parts {
                for b in *part {
                    hash ^= u64::from(*b);
                    hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
                }
                hash ^= 0xff; // part separator
                hash = hash.wrapping_mul(0x0000_0100_0000_01B3);
            }
            hash
        }
        let typ_label = alloc::format!("{typ:?}");
        let ip_label = base_addr.ip().to_string();
        format!(
            "{:x}",
            fnv1a(&[
                typ_label.as_bytes(),
                ip_label.as_bytes(),
                transport.as_bytes(),
            ])
        )
    }

    /// Set the TCP type on this candidate (for peer-reflexive discovery over TCP).
    pub fn with_tcp_type(mut self, tcp_type: TcpType) -> Self {
        self.tcp_type = Some(tcp_type);
        self.transport = "tcp".into();
        self
    }

    pub fn host(address: SocketAddr, component: u16) -> Self {
        Self {
            foundation: Self::compute_foundation(IceCandidateType::Host, address, "udp"),
            priority: IceCandidate::priority_for(IceCandidateType::Host, component),
            address,
            typ: IceCandidateType::Host,
            transport: "udp".into(),
            tcp_type: None,
            related_address: None,
            component,
            hostname: None,
        }
    }

    pub fn host_tcp(address: SocketAddr, component: u16, tcp_type: TcpType) -> Self {
        Self {
            foundation: Self::compute_foundation(IceCandidateType::Host, address, "tcp"),
            priority: IceCandidate::priority_for_tcp(IceCandidateType::Host, component, tcp_type),
            address,
            typ: IceCandidateType::Host,
            transport: "tcp".into(),
            tcp_type: Some(tcp_type),
            related_address: None,
            component,
            hostname: None,
        }
    }

    pub fn tcp(address: SocketAddr, component: u16, tcptype_str: &str) -> Self {
        let transport = "tcp";
        let tcp_type = TcpType::from_str(tcptype_str).unwrap_or(TcpType::Passive);
        Self {
            foundation: Self::compute_foundation(IceCandidateType::Host, address, transport),
            priority: IceCandidate::priority_for_tcp(IceCandidateType::Host, component, tcp_type),
            address,
            typ: IceCandidateType::Host,
            transport: transport.into(),
            tcp_type: Some(tcp_type),
            related_address: None,
            component,
            hostname: None,
        }
    }

    /// Advertise this candidate's address in SDP as an mDNS hostname
    /// (draft-ietf-rtcweb-mdns). The internal address is unchanged.
    pub fn with_hostname(mut self, hostname: impl Into<String>) -> Self {
        self.hostname = Some(hostname.into());
        self
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
            tcp_type: None,
            related_address: Some(base),
            component,
            hostname: None,
        }
    }

    fn relay(mapped: SocketAddr, component: u16, transport: &str) -> Self {
        Self {
            foundation: Self::compute_foundation(IceCandidateType::Relay, mapped, transport),
            priority: IceCandidate::priority_for(IceCandidateType::Relay, component),
            address: mapped,
            typ: IceCandidateType::Relay,
            transport: transport.into(),
            tcp_type: None,
            related_address: None,
            component,
            hostname: None,
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

    /// Priority for TCP candidates per RFC 6544 § 4.1.
    /// TCP candidates use a different local preference to distinguish
    /// between active, passive, and SO types, while UDP candidates always
    /// use the full 65535 local preference.
    fn priority_for_tcp(typ: IceCandidateType, component: u16, tcp_type: TcpType) -> u32 {
        let type_pref = match typ {
            IceCandidateType::Host => 126u32,
            IceCandidateType::PeerReflexive => 110u32,
            IceCandidateType::ServerReflexive => 100u32,
            IceCandidateType::Relay => 0u32,
        };
        // RFC 6544 § 4.1: local preference for TCP candidates
        let local_pref = match tcp_type {
            TcpType::Passive => 65535u32,
            TcpType::Active => 65534u32,
            TcpType::So => 65533u32,
        };
        let component = component.min(256) as u32;
        (type_pref << 24) | (local_pref << 8) | (256 - component)
    }

    pub fn to_sdp(&self) -> String {
        let advertised_ip = match &self.hostname {
            Some(h) => h.clone(),
            None => self.address.ip().to_string(),
        };
        let mut parts = vec![
            self.foundation.clone(),
            self.component.to_string(),
            self.transport.to_ascii_lowercase(),
            self.priority.to_string(),
            advertised_ip,
            self.address.port().to_string(),
            "typ".into(),
            self.typ.as_str().into(),
        ];
        if let Some(tcp_type) = self.tcp_type {
            parts.push("tcptype".into());
            parts.push(tcp_type.as_str().into());
        }
        if let Some(addr) = self.related_address
            && self.typ != IceCandidateType::Host
        {
            parts.push("raddr".into());
            parts.push(addr.ip().to_string());
            parts.push("rport".into());
            parts.push(addr.port().to_string());
        }
        parts.join(" ")
    }

    pub fn from_sdp(sdp: &str) -> RtcResult<Self> {
        let parts: Vec<&str> = sdp.split_whitespace().collect();
        if parts.len() < 8 {
            return Err(RtcError::Internal(format!("invalid candidate")));
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
            _ => return Err(RtcError::Internal(format!("unknown type"))),
        };

        // Parse optional tcptype attribute (RFC 6544)
        let tcp_type = if transport == "tcp" {
            // Search for "tcptype" keyword at even indices after position 8
            let mut i = 8;
            loop {
                if i + 1 >= parts.len() {
                    break None;
                }
                match parts[i] {
                    "tcptype" => {
                        break TcpType::from_str(parts[i + 1]);
                    }
                    _ => {
                        i += 2;
                    }
                }
            }
        } else {
            None
        };

        Ok(Self {
            foundation,
            priority,
            address,
            typ,
            transport,
            tcp_type,
            related_address: None,
            component,
            hostname: None,
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
        (1u64 << 32) * core::cmp::min(g, d) + 2 * core::cmp::max(g, d) + if g > d { 1 } else { 0 }
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

    pub fn build(self) -> (IceTransport, impl core::future::Future<Output = ()> + Send) {
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
    state: Arc<crate::platform::sync::Mutex<IceGathererState>>,
    local_candidates: Arc<crate::platform::sync::Mutex<Vec<IceCandidate>>>,
    sockets: Arc<crate::platform::sync::Mutex<Vec<Arc<UdpSocket>>>>,
    /// Sockets created through the platform bind factory
    /// ([`crate::platform::net::set_udp_bind_fn`] — rtcembed's embassy-net
    /// backend, or a host-test loopback). Kept so socket resolution can
    /// send from the same base socket the candidate advertises.
    platform_sockets: Arc<
        crate::platform::sync::Mutex<Vec<Arc<dyn crate::platform::net::UdpSocket>>>,
    >,
    #[cfg_attr(not(feature = "std"), allow(dead_code))]
    tcp_listeners: Arc<crate::platform::sync::Mutex<Vec<Arc<TcpListener>>>>,
    tcp_streams: Arc<crate::platform::sync::Mutex<BTreeMap<SocketAddr, IceSocketWrapper>>>,
    #[cfg(feature = "std")]
    shared_tcp_regs: Arc<crate::platform::sync::Mutex<Vec<shared_tcp::SharedTcpRegistration>>>,
    #[cfg(not(feature = "std"))]
    shared_tcp_regs: Arc<crate::platform::sync::Mutex<Vec<SharedTcpRegistration>>>,
    shared_udp_regs: Arc<crate::platform::sync::Mutex<Vec<shared_udp::SharedUdpRegistration>>>,
    /// The shared UDP mux socket wrapper (when `ice_udp_mux` is enabled).
    /// Stored so `resolve_socket` can return it for sending.
    shared_udp_socket: Arc<crate::platform::sync::Mutex<Option<IceSocketWrapper>>>,
    transport_inner:
        Arc<crate::platform::sync::Mutex<Option<alloc::sync::Weak<IceTransportInner>>>>,
    turn_clients: Arc<crate::platform::sync::Mutex<BTreeMap<SocketAddr, Arc<TurnClient>>>>,
    upnp_mappers: Arc<crate::platform::sync::Mutex<Vec<UpnpPortMapper>>>,
    config: RtcConfiguration,
    candidate_tx: broadcast::Sender<IceCandidate>,
    socket_tx: crate::platform::sync::mpsc::UnboundedSender<IceSocketWrapper>,
}

impl IceGatherer {
    fn new(
        config: RtcConfiguration,
        candidate_tx: broadcast::Sender<IceCandidate>,
        socket_tx: crate::platform::sync::mpsc::UnboundedSender<IceSocketWrapper>,
    ) -> Self {
        Self {
            state: Arc::new(crate::platform::sync::Mutex::new(IceGathererState::New)),
            local_candidates: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            sockets: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            platform_sockets: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            tcp_listeners: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            tcp_streams: Arc::new(crate::platform::sync::Mutex::new(BTreeMap::new())),
            shared_tcp_regs: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            shared_udp_regs: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            shared_udp_socket: Arc::new(crate::platform::sync::Mutex::new(None)),
            transport_inner: Arc::new(crate::platform::sync::Mutex::new(None)),
            turn_clients: Arc::new(crate::platform::sync::Mutex::new(BTreeMap::new())),
            upnp_mappers: Arc::new(crate::platform::sync::Mutex::new(Vec::new())),
            config,
            candidate_tx,
            socket_tx,
        }
    }

    fn set_transport(&self, inner: alloc::sync::Weak<IceTransportInner>) {
        *self.transport_inner.lock() = Some(inner);
    }

    /// The external IP to advertise as a srflx candidate (ServerReflexive
    /// mode, WebRTC, non-loopback bind, non-relay policy).
    fn external_srflx_ip(&self, bind_ip: IpAddr) -> Option<IpAddr> {
        if self.config.external_ip_candidate_type
            != crate::config::ExternalIpCandidateType::ServerReflexive
            || self.config.transport_mode != crate::config::TransportMode::WebRtc
            || self.config.ice_transport_policy != IceTransportPolicy::All
            || bind_ip.is_loopback()
        {
            return None;
        }
        self.config.external_ip.as_ref()?.parse().ok()
    }

    /// Push the host candidate for a socket bound at `local_addr`, plus the
    /// external IP as a server-reflexive candidate on the same socket.
    /// Returns false when the mode does not apply.
    fn push_host_with_external_srflx(
        &self,
        local_addr: SocketAddr,
        bind_ip: IpAddr,
        tcp_type: Option<TcpType>,
    ) -> bool {
        let Some(external) = self.external_srflx_ip(bind_ip) else {
            return false;
        };
        let mut host_addr = local_addr;
        if bind_ip.is_unspecified()
            && let Ok(local_ip) = get_local_ip()
        {
            host_addr.set_ip(local_ip);
        }
        let mut host = match tcp_type {
            Some(tcp_type) => IceCandidate::host_tcp(host_addr, 1, tcp_type),
            None => IceCandidate::host(host_addr, 1),
        };
        if host_addr != local_addr {
            host.related_address = Some(local_addr);
        }
        // Base = the socket's own address, as for STUN-learned candidates.
        let mut srflx = IceCandidate::server_reflexive(
            local_addr,
            SocketAddr::new(external, local_addr.port()),
            1,
        );
        if let Some(tcp_type) = tcp_type {
            srflx = srflx.with_tcp_type(tcp_type);
            srflx.foundation = IceCandidate::compute_foundation(
                IceCandidateType::ServerReflexive,
                local_addr,
                "tcp",
            );
            srflx.priority =
                IceCandidate::priority_for_tcp(IceCandidateType::ServerReflexive, 1, tcp_type);
        }
        self.push_candidate(host);
        if external.is_ipv4() == local_addr.is_ipv4() {
            self.push_candidate(srflx);
        }
        true
    }

    fn push_tcp_passive_candidate(&self, local_addr: SocketAddr, bind_ip: IpAddr) {
        if self.push_host_with_external_srflx(local_addr, bind_ip, Some(TcpType::Passive)) {
            return;
        }
        if let Some(ext_ip) = &self.config.external_ip
            && let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
        {
            if !bind_ip.is_loopback() {
                let mut ext_addr = local_addr;
                ext_addr.set_ip(parsed_ip);
                let mut cand = IceCandidate::tcp(ext_addr, 1, "passive");
                cand.related_address = Some(local_addr);
                self.push_candidate(cand);
            } else {
                self.push_candidate(IceCandidate::tcp(local_addr, 1, "passive"));
            }
        } else if bind_ip.is_unspecified() {
            let mut cand_addr = local_addr;
            if let Ok(local_ip) = get_local_ip() {
                cand_addr.set_ip(local_ip);
            }
            let mut cand = IceCandidate::tcp(cand_addr, 1, "passive");
            cand.related_address = Some(local_addr);
            self.push_candidate(cand);
        } else {
            self.push_candidate(IceCandidate::tcp(local_addr, 1, "passive"));
        }
    }

    /// Get the UPnP mappers for manual cleanup
    #[allow(dead_code)]
    #[cfg(feature = "std")]
    pub fn upnp_mappers(&self) -> Arc<crate::platform::sync::Mutex<Vec<UpnpPortMapper>>> {
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

    /// Refresh all stale UPnP port mappings (best-effort).
    ///
    /// Called periodically by the ICE runner so long-lived sessions keep their
    /// router leases alive. Each mapper renews its own stale mappings and a
    /// single failure does not abort the rest.
    #[cfg(feature = "std")]
    pub async fn renew_upnp_mappings(&self) {
        let mappers = self.upnp_mappers.lock().clone();
        for mapper in mappers {
            if let Err(e) = mapper.renew_all_stale().await {
                warn!("Failed to refresh UPnP mappings: {}", e);
            }
        }
    }

    fn state(&self) -> IceGathererState {
        *self.state.lock()
    }

    fn local_candidates(&self) -> Vec<IceCandidate> {
        self.local_candidates.lock().clone()
    }

    async fn bind_socket(&self, ip: IpAddr) -> RtcResult<IceSocketWrapper> {
        if let (Some(start), Some(end)) = (self.config.rtp_start_port, self.config.rtp_end_port) {
            let start = start.saturating_add(start % 2);
            let end = end - (end % 2);

            if start > end {
                return Err(RtcError::Internal(format!(
                    "No usable even RTP ports in range {}..={}",
                    start, end
                )));
            }

            let port_count = (((end - start) / 2) + 1) as u64;
            let start_index = (random_u64() % port_count) as u16;
            let mut port = start + (start_index * 2);

            for _ in 0..port_count {
                match self.bind_one(SocketAddr::new(ip, port)).await {
                    Ok(socket) => return Ok(socket),
                    Err(e) => {
                        // Only a genuinely busy port is worth retrying with
                        // the next port in the range (std io::Error and the
                        // platform factory both surface it as
                        // RtcError::AddrInUse). Any other error kind (bind IP
                        // not assigned to a local interface, permissions,
                        // ...) fails for every port in the range and must not
                        // be misreported as port exhaustion below.
                        if !e.is_addr_in_use() {
                            error!(
                                label = self.config.label.as_deref().unwrap_or("-"),
                                "binding RTP port {} on {} failed: {}", port, ip, e
                            );
                            return Err(e);
                        }
                        port = port.saturating_add(2);
                        if port > end {
                            port = start;
                        }
                    }
                }
            }
            return Err(RtcError::Internal(format!(
                "No available even RTP ports in range {}..={} (label={label})",
                start,
                end,
                label = self.config.label.as_deref().unwrap_or("-")
            )));
        } else {
            self.bind_one(SocketAddr::new(ip, 0)).await
        }
    }

    /// One bind attempt through the active backend: the platform factory
    /// when installed ([`crate::platform::net::set_udp_bind_fn`] — rtcembed's
    /// embassy-net backend, or a host-test loopback), else the tokio socket
    /// (std). Backend bookkeeping (sockets list) is done here so callers
    /// only deal with the wrapper.
    async fn bind_one(&self, addr: SocketAddr) -> RtcResult<IceSocketWrapper> {
        if let Some(result) = crate::platform::net::udp_bind_via_factory(addr) {
            let socket = result?;
            let wrapper = IceSocketWrapper::Platform(socket.clone());
            self.platform_sockets.lock().push(socket);
            return Ok(wrapper);
        }

        #[cfg(feature = "std")]
        {
            let socket = UdpSocket::bind(addr).await?;
            let socket = Arc::new(socket);
            self.sockets.lock().push(socket.clone());
            Ok(IceSocketWrapper::Udp(socket))
        }
        #[cfg(not(feature = "std"))]
        {
            let _ = addr;
            Err(RtcError::Internal(alloc::string::String::from(
                "no UDP bind backend: install one via platform::net::set_udp_bind_fn (rtcembed)",
            )))
        }
    }

    /// Looks up a factory-bound platform socket by local address (exact
    /// match, or unspecified-IP with matching port).
    pub(crate) fn get_platform_socket(
        &self,
        addr: SocketAddr,
    ) -> Option<Arc<dyn crate::platform::net::UdpSocket>> {
        let sockets = self.platform_sockets.lock();
        sockets.iter().find_map(|socket| {
            let local = socket.local_addr().ok()?;
            let matches =
                local == addr || (local.ip().is_unspecified() && local.port() == addr.port());
            matches.then(|| socket.clone())
        })
    }

    /// Registers a bound socket: backend bookkeeping (tokio sockets list;
    /// platform sockets are registered in `bind_one`) plus handing the
    /// wrapper to the runner so it starts a read loop.
    pub(crate) fn register_bound(&self, wrapper: &IceSocketWrapper) {
        if let IceSocketWrapper::Udp(s) = wrapper {
            self.sockets.lock().push(s.clone());
        }
        let _ = self.socket_tx.send(wrapper.clone());
    }

    fn get_socket(&self, addr: SocketAddr) -> Option<Arc<UdpSocket>> {
        let found = {
            let sockets = self.sockets.lock();
            sockets.iter().find_map(|socket| {
                let local = socket.local_addr().ok()?;
                let matches =
                    local == addr || (local.ip().is_unspecified() && local.port() == addr.port());
                matches.then(|| socket.clone())
            })
        };
        if let Some(s) = found {
            return Some(s);
        }
        // Fallback: the shared UDP mux socket (sending side). It backs the single
        // host candidate when `ice_udp_mux` is enabled and is not stored in
        // `sockets` (to keep a single demux read loop).
        if let Some(IceSocketWrapper::SharedUdp(handle)) = self.shared_udp_socket.lock().clone()
            && let Ok(local) = handle.local_addr()
            && (local == addr || (local.ip().is_unspecified() && local.port() == addr.port()))
        {
            return None; // mux socket is not a tokio-UdpSocket (Platform path owns it)
        }
        // Avoid unwrap in logging to prevent panic hiding
        let available: Vec<String> = self
            .sockets
            .lock()
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

    fn get_tcp_socket(&self, addr: SocketAddr) -> Option<IceSocketWrapper> {
        let streams = self.tcp_streams.lock();
        for (local_addr, wrapper) in streams.iter() {
            if *local_addr == addr {
                return Some(wrapper.clone());
            }
            // Match on port only if IP is unspecified (0.0.0.0)
            if local_addr.ip().is_unspecified() && local_addr.port() == addr.port() {
                return Some(wrapper.clone());
            }
        }
        trace!(
            "get_tcp_socket: no TCP stream found for {}, available: {:?}",
            addr,
            streams.keys().collect::<Vec<_>>()
        );
        None
    }

    fn store_tcp_stream(&self, local_addr: SocketAddr, wrapper: IceSocketWrapper) {
        self.tcp_streams.lock().insert(local_addr, wrapper);
    }

    #[instrument(skip(self))]
    async fn gather(&self) -> RtcResult<()> {
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
                if self.config.ice_gather_udp_hosts {
                    if let Err(e) = self.gather_host_candidates().await {
                        debug!("Host gathering failed: {}", e);
                    }
                } else if self.config.ice_tcp_policy == crate::config::IceTcpPolicy::Enabled {
                    // Outbound controlling peers with no TCP listen range advertise active locals.
                    // WHEP/answerer setups configure tcp_port_range_* for passive listeners;
                    // skip active placeholders so SDP does not contain invalid port 0 candidates.
                    let has_tcp_listen_range = match (
                        self.config.tcp_port_range_start,
                        self.config.tcp_port_range_end,
                    ) {
                        (Some(s), Some(e)) => s > 0 && e > 0 && s <= e,
                        _ => false,
                    };
                    if !has_tcp_listen_range
                        && let Err(e) = self.gather_tcp_active_candidates().await
                    {
                        debug!("TCP active gathering failed: {}", e);
                    }
                }
            }
        };

        host_fut.await;

        // TCP host candidate gathering
        if (self.config.tcp_port_range_start.is_some() || self.config.tcp_port_range_end.is_some())
            && let Err(e) = {
                #[cfg(feature = "std")]
                {
                    self.gather_tcp_host_candidates().await
                }
                #[cfg(not(feature = "std"))]
                {
                    Ok::<(), RtcError>(())
                }
            }
        {
            debug!("TCP host gathering failed: {}", e);
        }

        // STUN must complete before UPnP so we can detect double-NAT
        // and use STUN's public IP for UPnP candidates. Bounded so a
        // hung STUN/TURN server (no DNS timeout, no TCP connect timeout)
        // can never stall the whole gather — UPnP still runs and the
        // gather completes with whatever candidates arrived in time.
        let stun_public_ip = if self.config.enable_upnp {
            with_timeout(
                Duration::from_secs(5),
                self.gather_servers_and_get_public_ip(),
            )
            .await
            .unwrap_or_else(|_| {
                debug!(
                    "STUN/TURN gathering timed out after 5s, skipping UPnP double-NAT detection"
                );
                None
            })
        } else {
            if let Err(e) = self.gather_servers().await {
                debug!("Server gathering failed: {}", e);
            }
            None
        };

        // UPnP depends on host sockets and optionally STUN's public IP
        if self.config.enable_upnp
            && self.config.ice_transport_policy == IceTransportPolicy::All
            && let Err(e) = self.gather_upnp_candidates(stun_public_ip).await
        {
            debug!("UPnP gathering failed: {}", e);
        }

        *self.state.lock() = IceGathererState::Complete;
        Ok(())
    }

    /// Gather a host candidate backed by the process-wide shared UDP socket
    /// (single-port multiplexing). All PeerConnections sharing the same
    /// `ice_udp_mux_port` register their ufrag on the same socket; incoming
    /// packets are demuxed by ufrag / source address in `shared_udp`.
    async fn gather_shared_udp_host_candidate(&self) -> RtcResult<()> {
        let port = self.config.ice_udp_mux_port.ok_or_else(|| {
            RtcError::Internal(format!(
                "ice_udp_mux is enabled but ice_udp_mux_port is not set"
            ))
        })?;

        let bind_ip = if let Some(bind_ip_str) = &self.config.bind_ip {
            bind_ip_str
                .parse::<IpAddr>()
                .map_err(|e| RtcError::Internal(format!("invalid bind_ip {bind_ip_str}: {e}")))?
        } else {
            // Bind on the wildcard so the shared socket accepts on every
            // interface; the advertised candidate IP is rewritten below.
            IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED)
        };

        if self.config.disable_ipv6 && bind_ip.is_ipv6() {
            return Err(RtcError::Internal(format!(
                "disable_ipv6 is set but bind_ip is IPv6"
            )));
        }

        let bind_addr = SocketAddr::new(bind_ip, port);

        let inner = self
            .transport_inner
            .lock()
            .as_ref()
            .and_then(|weak| weak.upgrade())
            .ok_or_else(|| {
                RtcError::Internal("ICE transport unavailable during shared UDP gather".into())
            })?;
        let ufrag = inner.local_parameters.lock().username_fragment.clone();

        let (local_addr, handle, registration) = shared_udp::acquire(bind_addr, ufrag)
            .await
            .map_err(|e| RtcError::Internal(format!("shared udp acquire: {e}")))?;

        self.shared_udp_regs.lock().push(registration);

        let wrapper = IceSocketWrapper::SharedUdp(Arc::new(handle));
        *self.shared_udp_socket.lock() = Some(wrapper.clone());
        let _ = self.socket_tx.send(wrapper);

        if self.push_host_with_external_srflx(local_addr, bind_ip, None) {
            return Ok(());
        }
        // Derive the advertised candidate address (mirror the per-IP path).
        let mut cand_addr = local_addr;
        if let Some(ext_ip) = &self.config.external_ip
            && let Ok(parsed_ip) = ext_ip.parse::<IpAddr>()
        {
            if !bind_ip.is_loopback() {
                cand_addr.set_ip(parsed_ip);
            }
        } else if bind_ip.is_unspecified()
            && let Ok(local_ip) = get_local_ip()
        {
            cand_addr.set_ip(local_ip);
        }

        let mut cand = IceCandidate::host(cand_addr, 1);
        if cand_addr != local_addr {
            cand.related_address = Some(local_addr);
        }
        self.push_candidate(cand);
        Ok(())
    }

    async fn gather_host_candidates(&self) -> RtcResult<()> {
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
                bind_ips.push(IpAddr::V4(core::net::Ipv4Addr::UNSPECIFIED));
            }
        } else {
            // Default: bind to all LAN IPs. Loopback is only added on explicit
            // opt-in (`ice_include_loopback_candidates`) — advertising 127.0.0.1
            // to remote peers is useless and wastes their permissions/checks.
            if self.config.ice_include_loopback_candidates {
                bind_ips.push(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST));
            }

            #[cfg(feature = "std")]
            use local_ip_address::list_afinet_netifas;
            #[cfg(feature = "std")]
            if let Ok(interfaces) = list_afinet_netifas() {
                for (name, addr) in interfaces {
                    if let IpAddr::V4(ip) = addr
                        && !ip.is_loopback()
                        && !bind_ips.contains(&IpAddr::V4(ip))
                    {
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

            // no_std (embedded) has no interface enumeration, so use the
            // embedder's local-IP seam (`platform::net`/`set_local_ip_fn`) to
            // produce a host candidate — otherwise the WebRTC offer carries no
            // candidates at all.
            #[cfg(not(feature = "std"))]
            if let Ok(ip) = get_local_ip() {
                bind_ips.push(ip);
            }
        }

        if self.config.ice_udp_mux
            && let Err(e) = self.gather_shared_udp_host_candidate().await
        {
            debug!("Shared UDP mux host candidate failed: {}", e);
        }

        for ip in &bind_ips {
            let ip = *ip;
            // When UDP mux is enabled, the shared socket already provides the
            // host candidate; skip per-IP UDP socket binding.
            if self.config.ice_udp_mux {
                continue;
            }
            match self.bind_socket(ip).await {
                Ok(socket) => {
                    if let Ok(addr) = socket.local_addr() {
                        self.register_bound(&socket);

                        if self.push_host_with_external_srflx(addr, ip, None) {
                            // host + external server-reflexive pushed
                        } else if let Some(ext_ip) = &self.config.external_ip
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
                        debug!(
                            label = self.config.label.as_deref().unwrap_or("-"),
                            "Failed to bind to requested bind_ip {}: {}", ip, e
                        );
                    } else if !ip.is_loopback() && !ip.is_unspecified() {
                        debug!(
                            label = self.config.label.as_deref().unwrap_or("-"),
                            "Failed to bind socket on {}: {}", ip, e
                        );
                    }
                }
            }
        }

        // Gather TCP host candidates if TCP is enabled (std-only:
        // ICE-TCP is excluded from the embedded target)
        #[cfg(feature = "std")]
        if self.config.ice_tcp_policy != crate::config::IceTcpPolicy::Disabled {
            for ip in &bind_ips {
                let ip = *ip;
                match TcpListener::bind(SocketAddr::new(ip, 0)).await {
                    Ok(listener) => {
                        if let Ok(addr) = listener.local_addr() {
                            let listener = Arc::new(listener);
                            self.tcp_listeners.lock().push(listener.clone());
                            #[cfg(feature = "std")]
                            let _ = self.socket_tx.send(IceSocketWrapper::TcpListener(listener));

                            let tcp_type = TcpType::Passive;
                            if self.push_host_with_external_srflx(addr, ip, Some(tcp_type)) {
                                continue;
                            }
                            let mut cand = IceCandidate::host_tcp(addr, 1, tcp_type);
                            if ip.is_unspecified()
                                && let Ok(local_ip) = get_local_ip()
                            {
                                let mut cand_addr = addr;
                                cand_addr.set_ip(local_ip);
                                let mut ext_cand = IceCandidate::host_tcp(cand_addr, 1, tcp_type);
                                ext_cand.related_address = Some(addr);
                                cand = ext_cand;
                            }
                            self.push_candidate(cand);
                        }
                    }
                    Err(e) => {
                        debug!("Failed to bind TCP listener on {}: {}", ip, e);
                    }
                }
            }
        }

        Ok(())
    }

    /// Advertise ICE-TCP active host candidates for controlling clients (no UDP gather).
    ///
    /// RFC 6544 uses port 9 in SDP for active candidates (not 0 — browsers reject port 0).
    async fn gather_tcp_active_candidates(&self) -> RtcResult<()> {
        use core::net::{IpAddr, Ipv4Addr};

        const ACTIVE_PLACEHOLDER_PORT: u16 = 9;

        let mut bind_ips = Vec::new();
        if self.config.ice_include_loopback_candidates {
            bind_ips.push(IpAddr::V4(Ipv4Addr::LOCALHOST));
        }
        if let Ok(local_ip) = get_local_ip()
            && !bind_ips.contains(&local_ip)
        {
            bind_ips.push(local_ip);
        }

        for ip in bind_ips {
            self.push_candidate(IceCandidate::tcp(
                SocketAddr::new(ip, ACTIVE_PLACEHOLDER_PORT),
                1,
                "active",
            ));
        }
        self.push_candidate(IceCandidate::tcp(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), ACTIVE_PLACEHOLDER_PORT),
            1,
            "active",
        ));
        Ok(())
    }

    #[cfg(feature = "std")]
    async fn gather_tcp_host_candidates(&self) -> RtcResult<()> {
        let start = self.config.tcp_port_range_start.unwrap_or(0);
        let end = self.config.tcp_port_range_end.unwrap_or(0);

        if start == 0 || end == 0 || start > end {
            return Ok(());
        }

        let bind_ips = if let Some(bind_ip_str) = &self.config.bind_ip {
            if let Ok(ip) = bind_ip_str.parse::<IpAddr>() {
                vec![ip]
            } else {
                return Ok(());
            }
        } else {
            let mut ips = Vec::new();
            if self.config.ice_include_loopback_candidates {
                ips.push(IpAddr::V4(core::net::Ipv4Addr::LOCALHOST));
            }
            #[cfg(feature = "std")]
            use local_ip_address::list_afinet_netifas;
            #[cfg(feature = "std")]
            if let Ok(interfaces) = list_afinet_netifas() {
                for (name, addr) in interfaces {
                    if let IpAddr::V4(ip) = addr
                        && !ip.is_loopback()
                        && !ips.contains(&IpAddr::V4(ip))
                    {
                        if name.starts_with("utun")
                            || name.starts_with("gif")
                            || name.starts_with("stf")
                            || name.starts_with("awdl")
                            || name.starts_with("llw")
                        {
                            continue;
                        }
                        ips.push(IpAddr::V4(ip));
                    }
                }
            }
            ips
        };

        // One passive TCP listener per local IP (first free port in range). Binding the
        // entire range per PeerConnection exhausts the pool after a single session.
        // When start == end, share one listener process-wide and demux by ICE ufrag.
        let use_shared_listener = start == end;

        for ip in bind_ips {
            if use_shared_listener {
                let addr = SocketAddr::new(ip, start);
                let inner = self
                    .transport_inner
                    .lock()
                    .as_ref()
                    .and_then(|weak| weak.upgrade())
                    .ok_or_else(|| {
                        RtcError::Internal("ICE transport unavailable during TCP gather".into())
                    })?;
                let ufrag = inner.local_parameters.lock().username_fragment.clone();
                match shared_tcp::acquire(addr, ufrag, Arc::downgrade(&inner)).await {
                    Ok((local_addr, registration)) => {
                        self.shared_tcp_regs.lock().push(registration);
                        self.push_tcp_passive_candidate(local_addr, ip);
                        break;
                    }
                    Err(e) => {
                        debug!("shared TCP listener acquire on {} failed: {}", addr, e);
                    }
                }
                continue;
            }

            for port in start..=end {
                let addr = SocketAddr::new(ip, port);
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        let local_addr = match listener.local_addr() {
                            Ok(a) => a,
                            Err(_) => continue,
                        };
                        let listener = Arc::new(listener);
                        self.tcp_listeners.lock().push(listener.clone());
                        #[cfg(feature = "std")]
                        let _ = self.socket_tx.send(IceSocketWrapper::TcpListener(listener));

                        self.push_tcp_passive_candidate(local_addr, ip);
                        break;
                    }
                    Err(_) => continue,
                }
            }
        }

        Ok(())
    }

    async fn gather_upnp_candidates(&self, stun_public_ip: Option<IpAddr>) -> RtcResult<()> {
        let sockets = self.sockets.lock().clone();
        let timeout = self.config.upnp_discovery_timeout;
        let mut tasks = FuturesUnordered::new();

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

            let this = self.clone();
            let stun_ip = stun_public_ip;
            tasks.push(async move {
                // Create mapper with configured lease duration
                let mut mapper = UpnpPortMapper::with_lease_duration(
                    local_addr,
                    this.config.upnp_lease_duration,
                );

                // Try to discover gateway
                if let Err(e) = mapper.discover_with_timeout(timeout).await {
                    trace!("UPnP discovery failed for {}: {}", local_addr, e);
                    return;
                }

                // Try to add port mapping (0 = use same port as local)
                match mapper.add_mapping(0).await {
                    Ok(external_addr) => {
                        // Check if UPnP returned a private IP (double-NAT scenario)
                        let is_private = is_private_ip(&external_addr.ip());

                        // Final address for the candidate
                        let candidate_addr = if is_private {
                            if let Some(public_ip) = stun_ip {
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
                                debug!(
                                    "UPnP returned private IP {} but no STUN public IP available",
                                    external_addr.ip()
                                );
                                external_addr
                            }
                        } else {
                            external_addr
                        };

                        // Create server reflexive candidate for the mapping
                        let candidate =
                            IceCandidate::server_reflexive(local_addr, candidate_addr, 1);
                        this.push_candidate(candidate);

                        // Store mapper for later cleanup
                        this.upnp_mappers.lock().push(mapper);

                        debug!(
                            "UPnP candidate gathered: {} -> {}",
                            local_addr, candidate_addr
                        );
                    }
                    Err(e) => {
                        debug!("UPnP mapping failed for {}: {}", local_addr, e);
                    }
                }
            });
        }

        while tasks.next().await.is_some() {}

        Ok(())
    }

    async fn gather_servers(&self) -> RtcResult<()> {
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
                                    Err(e) => debug!(
                                        label = this.config.label.as_deref().unwrap_or("-"),
                                        "STUN probe failed for {}: {}", url, e
                                    ),
                                }
                            }
                        }
                        IceUriKind::Turn => match this.probe_turn(&uri, &server).await {
                            Ok(Some(candidate)) => this.push_candidate(candidate),
                            Ok(None) => {}
                            Err(e) => debug!(
                                label = this.config.label.as_deref().unwrap_or("-"),
                                "TURN probe failed for {}: {}", url, e
                            ),
                        },
                    }
                });
            }
        }

        while tasks.next().await.is_some() {}
        Ok(())
    }

    /// Gather server candidates and return the first public IP discovered via STUN.
    /// This is used to detect and fix double-NAT scenarios for UPnP.
    async fn gather_servers_and_get_public_ip(&self) -> Option<IpAddr> {
        let mut tasks = FuturesUnordered::new();
        let public_ip: Arc<crate::platform::sync::Mutex<Option<IpAddr>>> =
            Arc::new(crate::platform::sync::Mutex::new(None));

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
                                    Err(e) => debug!(
                                        label = this.config.label.as_deref().unwrap_or("-"),
                                        "STUN probe failed for {}: {}", url, e
                                    ),
                                }
                            }
                        }
                        IceUriKind::Turn => match this.probe_turn(&uri, &server).await {
                            Ok(Some(candidate)) => this.push_candidate(candidate),
                            Ok(None) => {}
                            Err(e) => debug!(
                                label = this.config.label.as_deref().unwrap_or("-"),
                                "TURN probe failed for {}: {}", url, e
                            ),
                        },
                    }
                });
            }
        }

        while tasks.next().await.is_some() {}
        let ip = *public_ip.lock();
        if let Some(ip) = &ip {
            debug!("STUN public IP for UPnP double-NAT detection: {}", ip);
        } else {
            debug!("No STUN public IP available for UPnP double-NAT detection");
        }
        ip
    }

    async fn probe_stun(&self, uri: &IceServerUri) -> RtcResult<Option<IceCandidate>> {
        let addr = uri.resolve(self.config.disable_ipv6).await?;

        // Find a suitable host address to bind to (prefer non-loopback IPv4).
        // Prefer the candidate's `related_address` (the address the socket was
        // actually bound on): with `external_ip` configured, the candidate
        // `address` carries the advertised NAT/EIP IP which is NOT assigned to
        // any local interface — binding on it fails with EADDRNOTAVAIL for
        // every port in the RTP range.
        let pick_bind_ip = |c: &IceCandidate| -> Option<IpAddr> {
            let base = c.related_address.unwrap_or(c.address);
            match base.ip() {
                IpAddr::V4(ip) if !addr.is_ipv6() && !ip.is_loopback() && !ip.is_unspecified() => {
                    Some(IpAddr::V4(ip))
                }
                IpAddr::V6(ip) if addr.is_ipv6() && !ip.is_loopback() && !ip.is_unspecified() => {
                    Some(IpAddr::V6(ip))
                }
                _ => None,
            }
        };
        let fallback = if addr.is_ipv6() {
            IpAddr::V6(core::net::Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(core::net::Ipv4Addr::new(0, 0, 0, 0))
        };
        let bind_ip = self
            .local_candidates
            .lock()
            .iter()
            .filter(|c| c.typ == IceCandidateType::Host)
            .filter_map(pick_bind_ip)
            .next()
            .unwrap_or(fallback);

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
        let (len, from) = with_timeout(self.config.stun_timeout, socket.recv_from(&mut buf))
            .await
            .map_err(|_| RtcError::Internal("stun recv timeout".into()))??;
        if from.ip() != addr.ip() {
            return Ok(None);
        }
        let parsed = StunMessage::decode(&buf[..len])?;
        if let Some(mapped) = parsed.xor_mapped_address {
            self.register_bound(&socket);
            return Ok(Some(IceCandidate::server_reflexive(local_addr, mapped, 1)));
        }
        Ok(None)
    }

    async fn probe_turn(
        &self,
        uri: &IceServerUri,
        server: &IceServer,
    ) -> RtcResult<Option<IceCandidate>> {
        let credentials = TurnCredentials::from_server(server)?;
        let client = TurnClient::connect(uri, self.config.disable_ipv6).await?;
        let allocation = client.allocate(credentials).await?;
        let relayed_addr = allocation.relayed_address;
        debug!(
            "TURN allocation granted: relayed={}, lifetime={}s",
            relayed_addr, allocation.lifetime_secs
        );

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

    fn push_candidate(&self, mut candidate: IceCandidate) {
        if self.config.disable_ipv6 && candidate.address.is_ipv6() {
            return;
        }
        // mDNS obfuscation (draft-ietf-rtcweb-mdns): host candidates advertise
        // our `<random>.local` hostname in SDP; the real address stays
        // internal so pairing and connectivity checks are unaffected.
        if candidate.typ == IceCandidateType::Host
            && let Some(hostname) = self
                .transport_inner
                .lock()
                .as_ref()
                .and_then(|weak| weak.upgrade())
                .and_then(|inner| inner.mdns_hostname.clone())
        {
            candidate = candidate.with_hostname(hostname);
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
    fn parse(input: &str) -> RtcResult<Self> {
        let (scheme, rest) = input
            .split_once(':')
            .ok_or_else(|| RtcError::Internal(format!("missing scheme")))?;
        let (host_part, query) = match rest.split_once('?') {
            Some(parts) => parts,
            None => (rest, ""),
        };
        let (host, port) = if let Some((h, p)) = host_part.rsplit_once(':') {
            let port = p
                .parse::<u16>()
                .map_err(|e| RtcError::Internal(format!("invalid port: {e}")))?;
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
                        other => {
                            return Err(RtcError::Internal(format!(
                                "unsupported transport {}",
                                other
                            )));
                        }
                    };
                }
            }
        }
        if scheme.starts_with("stun") && query.contains("transport") {
            return Err(RtcError::Internal(format!(
                "stun URI must not include transport parameter"
            )));
        }
        let kind = match scheme {
            "stun" | "stuns" => IceUriKind::Stun,
            "turn" | "turns" => IceUriKind::Turn,
            other => return Err(RtcError::Internal(format!("unsupported scheme {}", other))),
        };
        Ok(Self {
            kind,
            host,
            port,
            transport,
        })
    }

    async fn resolve(&self, disable_ipv6: bool) -> RtcResult<SocketAddr> {
        let target = format!("{}:{}", self.host, self.port);
        let addrs = with_timeout(
            Duration::from_secs(5),
            crate::platform::dns::lookup_host(&target),
        )
        .await
        .map_err(|_| RtcError::Internal(format!("DNS lookup timed out for {}", target)))??;

        for addr in addrs {
            if disable_ipv6 && addr.is_ipv6() {
                continue;
            }
            return Ok(addr);
        }
        Err(RtcError::Internal(format!(
            "{} unresolved (disable_ipv6={})",
            self.host, disable_ipv6
        )))
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

fn default_port_for_scheme(scheme: &str) -> RtcResult<u16> {
    Ok(match scheme {
        "stun" | "turn" => 3478,
        "stuns" | "turns" => 5349,
        other => return Err(RtcError::Internal(format!("unsupported scheme {}", other))),
    })
}

fn default_transport_for_scheme(scheme: &str) -> RtcResult<IceTransportProtocol> {
    Ok(match scheme {
        "stun" | "turn" => IceTransportProtocol::Udp,
        "stuns" | "turns" => IceTransportProtocol::Tcp,
        other => return Err(RtcError::Internal(format!("unsupported scheme {}", other))),
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
                || *ipv6 == core::net::Ipv6Addr::LOCALHOST
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

#[derive(Clone)]
pub enum IceSocketWrapper {
    Platform(Arc<dyn crate::platform::net::UdpSocket>),
    /// std: the tokio UDP socket; no_std: never constructed (the placeholder
    /// type keeps the enum shape).
    Udp(Arc<UdpSocket>),
    /// Shared (muxed) UDP socket. Incoming packets arrive via the handle's
    /// receiver (fed by the shared demux loop); outbound packets go out through
    /// the handle, which also records the destination for reverse routing.
    SharedUdp(Arc<shared_udp::SharedUdpHandle>),
    #[cfg(feature = "std")]
    TcpListener(Arc<TcpListener>),
    #[cfg(feature = "std")]
    TcpStream(
        Arc<Mutex<TcpReadHalf>>,
        Arc<Mutex<TcpWriteHalf>>,
        SocketAddr,
    ),
    Turn(Arc<TurnClient>, SocketAddr),
}

impl core::fmt::Debug for IceSocketWrapper {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.diag())
    }
}

impl IceSocketWrapper {
    /// Local address of the underlying socket (best effort: TURN/TCP
    /// variants report the relay/listen endpoint where meaningful).
    pub fn local_addr(&self) -> RtcResult<SocketAddr> {
        match self {
            IceSocketWrapper::Platform(s) => s.local_addr().map_err(RtcError::from),
            IceSocketWrapper::Udp(s) => s.local_addr().map_err(RtcError::from),
            IceSocketWrapper::SharedUdp(h) => h.local_addr(),
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpListener(l) => l.local_addr().map_err(RtcError::from),
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpStream(_, _, peer) => Ok(*peer),
            IceSocketWrapper::Turn(_, addr) => Ok(*addr),
        }
    }

    /// Short description for diagnostic logs (no async I/O).
    pub fn diag(&self) -> String {
        match self {
            IceSocketWrapper::Platform(s) => format!(
                "platform-udp:{}",
                s.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            ),
            IceSocketWrapper::Udp(s) => format!(
                "udp:{}",
                s.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            ),
            IceSocketWrapper::SharedUdp(h) => format!(
                "udp-mux:{}",
                h.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            ),
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpListener(l) => format!(
                "tcp-listen:{}",
                l.local_addr()
                    .map(|a| a.to_string())
                    .unwrap_or_else(|_| "?".into())
            ),
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpStream(_, _, peer) => format!("tcp-stream:peer={peer}"),
            IceSocketWrapper::Turn(_, addr) => format!("turn:{addr}"),
        }
    }

    /// Non-blocking variant of `send_to`: calls `try_send_to` once and returns
    /// immediately on `WouldBlock` / `ENOBUFS` instead of parking on
    /// `writable()`. Used by the RTP bridge fast-path.
    pub fn try_send_to(&self, data: &[u8], addr: SocketAddr) -> RtcResult<usize> {
        match self {
            IceSocketWrapper::Platform(s) => {
                match <dyn crate::platform::net::UdpSocket>::try_send_to(
                    s.as_ref(),
                    data,
                    addr,
                ) {
                    Ok(len) => Ok(len),
                    Err(e) => Err(RtcError::Internal(alloc::format!(
                        "platform try_send_to: {e}"
                    ))),
                }
            }
            IceSocketWrapper::Udp(s) => match s.try_send_to(data, addr) {
                Ok(len) => Ok(len),
                Err(e) => {
                    let reason = match s.local_addr() {
                        Ok(local) => format!("UDP {} -> {} failed: {}", local, addr, e),
                        Err(_) => format!("UDP -> {} failed: {}", addr, e),
                    };
                    Err(RtcError::Internal(reason))
                }
            },
            #[cfg(not(feature = "std"))]
            IceSocketWrapper::Udp(_) => {
                unimplemented!("direct UDP sockets are std-only")
            }
            IceSocketWrapper::SharedUdp(h) => {
                // Shared (muxed) UDP is still a synchronous datagram socket:
                // record the peer for reverse routing, then write without
                // parking (same contract as the `Udp` arm above).
                h.register_peer(addr);
                match <dyn crate::platform::net::UdpSocket>::try_send_to(
                    h.socket().as_ref(),
                    data,
                    addr,
                ) {
                    Ok(len) => Ok(len),
                    Err(e) => {
                        let reason = match h.local_addr() {
                            Ok(local) => format!("shared UDP {} -> {} failed: {}", local, addr, e),
                            Err(_) => format!("shared UDP -> {} failed: {}", addr, e),
                        };
                        Err(RtcError::Internal(reason))
                    }
                }
            }
            // TURN / TCP / TLS have no synchronous send: callers must use the
            // async `send_to` (the bridge fast-path queues via `IceConn`).
            _ => Err(RtcError::Internal(format!(
                "IceSocketWrapper::try_send_to not supported for this transport variant"
            ))),
        }
    }

    pub async fn send_to(&self, data: &[u8], addr: SocketAddr) -> RtcResult<usize> {
        match self {
            IceSocketWrapper::Platform(s) => s
                .send_to(data, addr)
                .await
                .map_err(|e| RtcError::Internal(format!("platform send_to: {e}"))),
            #[cfg(feature = "std")]
            IceSocketWrapper::Udp(s) => loop {
                match s.try_send_to(data, addr) {
                    Ok(len) => return Ok(len),
                    Err(e) if e.kind() == ErrorKind::WouldBlock => {
                        s.writable().await?;
                        continue;
                    }
                    Err(e) => {
                        if let Some(code) = e.raw_os_error()
                            && code == 55
                        {
                            s.writable().await?;
                            continue;
                        }
                        let reason = RtcError::Internal(format!(
                            "UDP {} -> {} failed: {}",
                            s.local_addr()?,
                            addr,
                            e
                        ));
                        return Err(reason);
                    }
                }
            },
            #[cfg(not(feature = "std"))]
            IceSocketWrapper::Udp(_) => {
                unimplemented!("direct UDP sockets are std-only")
            }
            IceSocketWrapper::SharedUdp(h) => {
                let dest = addr;
                h.send_to(data, dest).await.map_err(RtcError::from)
            }
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpListener(_) => {
                return Err(RtcError::Internal(format!(
                    "send_to not supported on TcpListener"
                )));
            }
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpStream(_, write, _) => {
                let len = data.len();
                if len > 0xFFFF {
                    return Err(RtcError::Internal(format!(
                        "STUN message too large for TCP framing"
                    )));
                }
                let header = (len as u16).to_be_bytes();
                let mut framed = Vec::with_capacity(2 + len);
                framed.extend_from_slice(&header);
                framed.extend_from_slice(data);
                tcp_write_all(write, &framed).await?;
                Ok(data.len())
            }
            IceSocketWrapper::Turn(c, _) => {
                if let Some(channel) = c.get_channel(addr).await {
                    c.send_channel_data(channel, data).await?;
                } else {
                    c.send_indication(addr, data).await?;
                }
                Ok(data.len())
            }
        }
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> RtcResult<(usize, SocketAddr)> {
        match self {
            IceSocketWrapper::Platform(s) => s.recv_from(buf).await.map_err(|e| e.into()),
            IceSocketWrapper::Udp(s) => s.recv_from(buf).await.map_err(|e| e.into()),
            IceSocketWrapper::SharedUdp(h) => match h.recv().await {
                Some((data, addr)) => {
                    if data.len() > buf.len() {
                        return Err(RtcError::Internal(format!(
                            "shared UDP packet too large: {} > {}",
                            data.len(),
                            buf.len()
                        )));
                    }
                    let len = data.len();
                    buf[..len].copy_from_slice(&data);
                    Ok((len, addr))
                }
                None => Err(RtcError::Internal(format!("shared UDP channel closed"))),
            },
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpStream(read, _, peer) => {
                #[cfg(feature = "std")]
                use tokio::io::AsyncReadExt;
                let mut stream = read.lock().await;
                let mut len_buf = [0u8; 2];
                stream.read_exact(&mut len_buf).await?;
                let len = u16::from_be_bytes(len_buf) as usize;
                if len > buf.len() {
                    return Err(RtcError::Internal(format!(
                        "TCP STUN message too large: {} > {}",
                        len,
                        buf.len()
                    )));
                }
                stream.read_exact(&mut buf[..len]).await?;
                Ok((len, *peer))
            }
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpListener(_) => Err(RtcError::Internal(format!(
                "recv_from not supported on TcpListener wrapper directly"
            ))),
            IceSocketWrapper::Turn(_, _) => Err(RtcError::Internal(format!(
                "recv_from not supported on TURN wrapper directly"
            ))),
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod bind_socket_retry_tests {
    //! An EADDRINUSE port must be skipped in favor of the next one in the
    //! configured range (the old string check never matched the platform
    //! errno text "Address already in use" and failed the bind outright).

    use super::*;

    fn gatherer(start: u16, end: u16) -> IceGatherer {
        let (candidate_tx, _) = broadcast::channel(1);
        let (socket_tx, _socket_rx) = crate::platform::sync::mpsc::unbounded_channel();
        let mut config = RtcConfiguration::default();
        config.rtp_start_port = Some(start);
        config.rtp_end_port = Some(end);
        IceGatherer::new(config, candidate_tx, socket_tx)
    }

    /// A socket actually occupying an even port (bind_socket scans even
    /// ports only).
    async fn occupy_even_port() -> (tokio::net::UdpSocket, u16) {
        loop {
            let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let p = s.local_addr().unwrap().port();
            if p % 2 == 0 {
                return (s, p);
            }
        }
    }

    #[tokio::test]
    async fn skips_a_busy_port_and_binds_the_next_one() {
        // One busy even port; a two-port range must still yield the other.
        let (_blocker, busy) = occupy_even_port().await;
        let other = busy + 2;

        let g = gatherer(busy, other);
        let socket = g
            .bind_socket(IpAddr::from([127, 0, 0, 1]))
            .await
            .expect("bind_socket must skip the busy port");
        assert_eq!(socket.local_addr().unwrap().port(), other);
    }

    #[tokio::test]
    async fn exhausts_the_range_with_the_port_exhaustion_error() {
        // A single-port range whose port is busy reports exhaustion, not a
        // raw bind failure.
        let (_blocker, busy) = occupy_even_port().await;

        let g = gatherer(busy, busy);
        let err = g
            .bind_socket(IpAddr::from([127, 0, 0, 1]))
            .await
            .expect_err("a fully busy range must fail");
        assert!(
            err.to_string().contains("No available even RTP ports"),
            "expected port exhaustion, got: {err}"
        );
    }
}
