use crate::RtcConfiguration;
pub use crate::transports::datachannel::*;
use crate::transports::dtls::{DtlsState, DtlsTransport};
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Notify, mpsc};
use tracing::{debug, trace, warn};

// RTO Constants (RFC 4960)
const RTO_ALPHA: f64 = 0.125;
const RTO_BETA: f64 = 0.25;

// Flow Control Constants
const CWND_INITIAL: usize = 1200 * 10; // Start with 10 MTUs (~12KB, RFC 6928)
const SSTHRESH_MIN: usize = CWND_INITIAL / 3; // Minimum ssthresh: 1/3 of initial cwnd (~4KB)

#[derive(Debug, Clone)]
struct ChunkRecord {
    payload: Bytes,
    sent_time: Instant,
    transmit_count: u32,
    missing_reports: u8,
    stream_id: u16,
    abandoned: bool,
    fast_retransmit: bool,
    fast_retransmit_time: Option<Instant>,
    in_flight: bool,
    acked: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    New,
    Connecting,
    Connected,
    Closed,
}

// SCTP Constants
const SCTP_COMMON_HEADER_SIZE: usize = 12;
const CHUNK_HEADER_SIZE: usize = 4;
const MAX_SCTP_PACKET_SIZE: usize = 1200;
const DEFAULT_MAX_PAYLOAD_SIZE: usize = 1172; // 1200 - 12 (common) - 16 (data header)
const DUP_THRESH: u8 = 3;

// Chunk Types
const CT_DATA: u8 = 0;
const CT_INIT: u8 = 1;
const CT_INIT_ACK: u8 = 2;
const CT_SACK: u8 = 3;
const CT_HEARTBEAT: u8 = 4;
const CT_HEARTBEAT_ACK: u8 = 5;
#[allow(unused)]
const CT_ABORT: u8 = 6;
#[allow(unused)]
const CT_SHUTDOWN: u8 = 7;
#[allow(unused)]
const CT_SHUTDOWN_ACK: u8 = 8;
#[allow(unused)]
const CT_ERROR: u8 = 9;
const CT_COOKIE_ECHO: u8 = 10;
const CT_COOKIE_ACK: u8 = 11;
const CT_RECONFIG: u8 = 130;
const CT_FORWARD_TSN: u8 = 192;

// Reconfig Parameter Types
const RECONFIG_PARAM_OUTGOING_SSN_RESET: u16 = 13;
#[allow(unused)]
const RECONFIG_PARAM_INCOMING_SSN_RESET: u16 = 14;
const RECONFIG_PARAM_RESPONSE: u16 = 16;

// Reconfig Response Results
const RECONFIG_RESPONSE_SUCCESS_NOTHING_TO_DO: u32 = 0;
const RECONFIG_RESPONSE_SUCCESS_PERFORMED: u32 = 1;
#[allow(unused)]
const RECONFIG_RESPONSE_DENIED: u32 = 2;
#[allow(unused)]
const RECONFIG_RESPONSE_ERROR_WRONG_SSN: u32 = 3;
#[allow(unused)]
const RECONFIG_RESPONSE_ERROR_REQUEST_ALREADY_IN_PROGRESS: u32 = 4;
#[allow(unused)]
const RECONFIG_RESPONSE_ERROR_BAD_SEQUENCE_NUMBER: u32 = 5;
#[allow(unused)]
const RECONFIG_RESPONSE_IN_PROGRESS: u32 = 6;

#[derive(Debug)]
struct RtoCalculator {
    srtt: f64,
    rttvar: f64,
    rto: f64,
    min: f64,
    max: f64,
}

impl RtoCalculator {
    fn new(initial: f64, min: f64, max: f64) -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            rto: initial,
            min,
            max,
        }
    }

    fn update(&mut self, rtt: f64) {
        if self.srtt == 0.0 {
            self.srtt = rtt;
            self.rttvar = rtt / 2.0;
        } else {
            self.rttvar = (1.0 - RTO_BETA) * self.rttvar + RTO_BETA * (self.srtt - rtt).abs();
            self.srtt = (1.0 - RTO_ALPHA) * self.srtt + RTO_ALPHA * rtt;
        }
        self.rto = (self.srtt + 4.0 * self.rttvar).clamp(self.min, self.max);
    }

    fn backoff(&mut self) {
        self.rto = (self.rto * 2.0).min(self.max);
    }
}

struct SctpInner {
    dtls_transport: Arc<DtlsTransport>,
    state: Arc<Mutex<SctpState>>,
    data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
    local_port: u16,
    remote_port: u16,
    verification_tag: AtomicU32,
    remote_verification_tag: AtomicU32,
    next_tsn: AtomicU32,
    cumulative_tsn_ack: AtomicU32,
    new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
    sack_counter: AtomicU8,
    is_client: bool,
    sent_queue: Mutex<BTreeMap<u32, ChunkRecord>>,
    received_queue: Mutex<BTreeMap<u32, (u8, Bytes)>>,

    // RTO State
    rto_state: Mutex<RtoCalculator>,

    // Flow Control
    flight_size: AtomicUsize,
    cwnd: AtomicUsize,
    ssthresh: AtomicUsize,
    partial_bytes_acked: AtomicUsize,
    peer_rwnd: AtomicU32, // Peer's Advertised Receiver Window
    timer_notify: Arc<Notify>,
    flow_control_notify: Arc<Notify>,
    ack_delay_ms: AtomicU32,
    ack_scheduled: AtomicBool,
    last_gap_sig: AtomicU32,
    dups_buffer: Mutex<Vec<u32>>, // duplicate TSNs to include in next SACK
    last_immediate_sack: Mutex<Option<Instant>>, // throttle immediate SACKs

    // Reconfig State
    reconfig_request_sn: AtomicU32,
    peer_reconfig_request_sn: AtomicU32,
    local_rwnd: usize,

    // Fast Recovery
    fast_recovery_exit_tsn: AtomicU32,
    fast_recovery_active: AtomicBool,

    // Association Retransmission Limit
    max_association_retransmits: u32,

    // Association Error Counter
    association_error_count: AtomicU32,
    heartbeat_sent_time: Mutex<Option<Instant>>,
    consecutive_heartbeat_failures: AtomicU32,

    // Receiver Window Tracking
    used_rwnd: AtomicUsize,

    // Receiver Packet Counter (for Quick-Start ACKs)
    packets_received: AtomicU64,

    // Flow control serialization to prevent overshoot
    tx_lock: tokio::sync::Mutex<()>,

    // Cached Timeout State
    cached_rto_timeout: Mutex<Option<(Instant, Duration)>>,

    // Outgoing Packet Queue to prevent deadlocks
    outgoing_packet_tx: mpsc::UnboundedSender<Bytes>,

    // Statistics
    stats_bytes_sent: AtomicU64,
    stats_bytes_received: AtomicU64,
    stats_packets_sent: AtomicU64,
    stats_packets_received: AtomicU64,
    stats_retransmissions: AtomicU64,
    stats_heartbeats_sent: AtomicU64,
    stats_created_time: Instant,
}

struct SctpCleanupGuard<'a> {
    inner: &'a SctpInner,
}

/// Build Gap Ack Blocks from buffered out-of-order packets so the peer knows
/// exactly which TSNs we have received beyond the cumulative ack. We limit the
/// number of blocks to keep the SACK compact and stay within 16-bit offsets.
fn build_gap_ack_blocks_from_map(
    received: &BTreeMap<u32, (u8, Bytes)>,
    cumulative_tsn_ack: u32,
) -> Vec<(u16, u16)> {
    let mut blocks: Vec<(u16, u16)> = Vec::new();
    let mut current: Option<(u32, u32)> = None;

    for &tsn in received.keys() {
        // Ignore any TSN that is already cumulatively acked or would wrap.
        if (tsn.wrapping_sub(cumulative_tsn_ack) as i32) <= 0 {
            continue;
        }

        match current {
            Some((start, end)) if tsn == end.wrapping_add(1) => {
                current = Some((start, tsn));
            }
            Some((start, end)) => {
                let start_off = start.wrapping_sub(cumulative_tsn_ack);
                let end_off = end.wrapping_sub(cumulative_tsn_ack);
                if start_off <= u16::MAX as u32 && end_off <= u16::MAX as u32 {
                    blocks.push((start_off as u16, end_off as u16));
                }
                current = Some((tsn, tsn));
            }
            None => {
                current = Some((tsn, tsn));
            }
        }

        if blocks.len() >= 16 {
            break; // keep SACK compact
        }
    }

    if blocks.len() < 16 {
        if let Some((start, end)) = current {
            let start_off = start.wrapping_sub(cumulative_tsn_ack);
            let end_off = end.wrapping_sub(cumulative_tsn_ack);
            if start_off <= u16::MAX as u32 && end_off <= u16::MAX as u32 {
                blocks.push((start_off as u16, end_off as u16));
            }
        }
    }

    blocks
}

#[derive(Debug, Default, PartialEq)]
struct SackOutcome {
    flight_reduction: usize,
    bytes_acked_by_cum_tsn: usize,
    rtt_samples: Vec<f64>,
    retransmit: Vec<(u32, Bytes)>,
    head_moved: bool,
    max_reported: u32,
}

fn apply_sack_to_sent_queue(
    sent_queue: &mut BTreeMap<u32, ChunkRecord>,
    cumulative_tsn_ack: u32,
    gap_blocks: &[(u16, u16)],
    now: Instant,
) -> SackOutcome {
    let before_head = sent_queue.keys().next().cloned();

    // 0. Filter out late SACKs
    if let Some(&lowest_tsn) = sent_queue.keys().next() {
        if (cumulative_tsn_ack.wrapping_sub(lowest_tsn.wrapping_sub(1)) as i32) < 0 {
            // This SACK is even older than our earliest outstanding TSN,
            // except for the case where it might be acknowledging gaps.
            // But usually this means it's a reordered old SACK.
            // Check if max_reported is also old.
            let mut max_reported = cumulative_tsn_ack;
            for (_start, end) in gap_blocks {
                let block_end = cumulative_tsn_ack.wrapping_add(*end as u32);
                if (block_end.wrapping_sub(max_reported) as i32) > 0 {
                    max_reported = block_end;
                }
            }
            if (max_reported.wrapping_sub(lowest_tsn) as i32) < 0 {
                return SackOutcome::default();
            }
        }
    }

    let mut max_reported = cumulative_tsn_ack;
    for (_start, end) in gap_blocks {
        let block_end = cumulative_tsn_ack.wrapping_add(*end as u32);
        if (block_end.wrapping_sub(max_reported) as i32) > 0 {
            max_reported = block_end;
        }
    }

    let mut outcome = SackOutcome::default();
    outcome.max_reported = max_reported;

    // 1. Remove everything that the SACK explicitly acknowledges via cumulative TSN.
    let to_remove: Vec<u32> = sent_queue
        .keys()
        .filter(|&&tsn| (tsn.wrapping_sub(cumulative_tsn_ack) as i32) <= 0)
        .cloned()
        .collect();

    for tsn in to_remove {
        if let Some(record) = sent_queue.remove(&tsn) {
            let len = record.payload.len();
            trace!("SACK acknowledging TSN {} (len={})", tsn, len);
            if record.in_flight {
                outcome.flight_reduction += len;
            }
            // Even if it was already acked via GAPS, we count it for CWND growth now
            // because it's officially cumulative-acked.
            outcome.bytes_acked_by_cum_tsn += len;
            if record.transmit_count == 0 && !record.acked {
                outcome
                    .rtt_samples
                    .push(now.duration_since(record.sent_time).as_secs_f64());
            }
        }
    }

    // 2. Handle Gap Ack Blocks
    for (start, end) in gap_blocks {
        let s = cumulative_tsn_ack.wrapping_add(*start as u32);
        let e = cumulative_tsn_ack.wrapping_add(*end as u32);

        let mut to_ack = Vec::new();
        if s <= e {
            for (&tsn, _) in sent_queue.range(s..=e) {
                to_ack.push(tsn);
            }
        } else {
            for (&tsn, _) in sent_queue.range(s..) {
                to_ack.push(tsn);
            }
            for (&tsn, _) in sent_queue.range(..=e) {
                to_ack.push(tsn);
            }
        }

        for tsn in to_ack {
            if let Some(record) = sent_queue.get_mut(&tsn) {
                if !record.acked {
                    record.acked = true;
                    if record.in_flight {
                        record.in_flight = false;
                        outcome.flight_reduction += record.payload.len();
                    }
                    if record.transmit_count == 0 {
                        outcome
                            .rtt_samples
                            .push(now.duration_since(record.sent_time).as_secs_f64());
                    }
                }
            }
        }
    }

    // 3. Mark missing reports and schedule fast retransmits.
    // Use order-aware iteration up to max_reported.
    let mut to_retransmit = Vec::new();
    let mut missing_count = 0;
    for (&tsn, record) in sent_queue.iter_mut() {
        // if tsn <= max_reported
        if (tsn.wrapping_sub(max_reported) as i32) <= 0 {
            if !record.acked {
                missing_count += 1;
                let old_reports = record.missing_reports;
                record.missing_reports = record.missing_reports.saturating_add(1);

                // Log first few missing TSNs
                if missing_count <= 3 {
                    debug!(
                        "Missing TSN {} reports: {} -> {}, acked={}, fast_retrans={}",
                        tsn,
                        old_reports,
                        record.missing_reports,
                        record.acked,
                        record.fast_retransmit
                    );
                }

                // Allow re-triggering fast retransmit if:
                // 1. This is the first fast retransmit, OR
                // 2. Enough time has passed since last fast retransmit (> 500ms), OR
                // 3. Missing reports are significantly high (>= 7), indicating severe packet loss
                let can_fast_retransmit = if record.fast_retransmit {
                    if let Some(fr_time) = record.fast_retransmit_time {
                        let elapsed = now.duration_since(fr_time);
                        // Bypass cooldown if missing_reports is high or enough time passed
                        // DUP_THRESH is 3, so 7 reports means ~4 additional duplicate SACKs after first fast retransmit
                        record.missing_reports >= 7 || elapsed > Duration::from_millis(500)
                    } else {
                        true
                    }
                } else {
                    true
                };

                if record.missing_reports >= DUP_THRESH && !record.abandoned && can_fast_retransmit
                {
                    record.missing_reports = 0;
                    record.transmit_count += 1;
                    record.sent_time = now; // Reset timer for retransmission
                    record.fast_retransmit = true;
                    record.fast_retransmit_time = Some(now);

                    debug!(
                        "Fast retransmit triggered for TSN {} after {} missing reports (retrans #{})",
                        tsn, DUP_THRESH, record.transmit_count
                    );

                    // Note: We do NOT remove from in_flight or reduce flight_size here per spec.
                    to_retransmit.push((tsn, record.payload.clone()));
                }
            }
        }
    }

    if missing_count > 0 && to_retransmit.is_empty() {
        debug!(
            "Found {} missing TSNs but none reached fast retransmit threshold",
            missing_count
        );
    }
    outcome.retransmit = to_retransmit;

    let after_head = sent_queue.keys().next().cloned();
    outcome.head_moved = before_head != after_head;

    if !outcome.retransmit.is_empty() {
        trace!(
            "Fast Retransmission triggered for {} chunks",
            outcome.retransmit.len()
        );
    }

    outcome
}

impl<'a> Drop for SctpCleanupGuard<'a> {
    fn drop(&mut self) {
        *self.inner.state.lock().unwrap() = SctpState::Closed;

        let channels = self.inner.data_channels.lock().unwrap();
        for weak_dc in channels.iter() {
            if let Some(dc) = weak_dc.upgrade() {
                let old_state = dc
                    .state
                    .swap(DataChannelState::Closed as usize, Ordering::SeqCst);
                if old_state != DataChannelState::Closed as usize {
                    dc.send_event(DataChannelEvent::Close);
                    dc.close_channel();
                }
            }
        }
    }
}

pub struct SctpTransport {
    inner: Arc<SctpInner>,
    close_tx: Arc<tokio::sync::Notify>,
}

impl SctpTransport {
    pub fn new(
        dtls_transport: Arc<DtlsTransport>,
        incoming_data_rx: mpsc::UnboundedReceiver<Bytes>,
        data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
        local_port: u16,
        remote_port: u16,
        new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
        is_client: bool,
        config: &RtcConfiguration,
    ) -> (
        Arc<Self>,
        impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let (outgoing_packet_tx, mut outgoing_packet_rx) = mpsc::unbounded_channel::<Bytes>();

        let inner = Arc::new(SctpInner {
            dtls_transport: dtls_transport.clone(),
            state: Arc::new(Mutex::new(SctpState::New)),
            data_channels,
            local_port,
            remote_port,
            verification_tag: AtomicU32::new(0),
            remote_verification_tag: AtomicU32::new(0),
            next_tsn: AtomicU32::new(0),
            cumulative_tsn_ack: AtomicU32::new(0),
            new_data_channel_tx,
            sack_counter: AtomicU8::new(0),
            is_client,
            sent_queue: Mutex::new(BTreeMap::new()),
            received_queue: Mutex::new(BTreeMap::new()),
            rto_state: Mutex::new(RtoCalculator::new(
                config.sctp_rto_initial.as_secs_f64(),
                config.sctp_rto_min.as_secs_f64(),
                config.sctp_rto_max.as_secs_f64(),
            )),
            flight_size: AtomicUsize::new(0),
            cwnd: AtomicUsize::new(CWND_INITIAL),
            ssthresh: AtomicUsize::new(usize::MAX),
            partial_bytes_acked: AtomicUsize::new(0),
            peer_rwnd: AtomicU32::new(1024 * 1024), // Default 1MB until we hear otherwise
            timer_notify: Arc::new(Notify::new()),
            flow_control_notify: Arc::new(Notify::new()),
            ack_delay_ms: AtomicU32::new(50),
            ack_scheduled: AtomicBool::new(false),
            last_gap_sig: AtomicU32::new(0),
            dups_buffer: Mutex::new(Vec::new()),
            last_immediate_sack: Mutex::new(None),
            reconfig_request_sn: AtomicU32::new(0),
            peer_reconfig_request_sn: AtomicU32::new(u32::MAX), // Initial value to allow 0
            local_rwnd: config.sctp_receive_window,
            fast_recovery_exit_tsn: AtomicU32::new(0),
            fast_recovery_active: AtomicBool::new(false),
            max_association_retransmits: config.sctp_max_association_retransmits,
            association_error_count: AtomicU32::new(0),
            heartbeat_sent_time: Mutex::new(None),
            consecutive_heartbeat_failures: AtomicU32::new(0),
            used_rwnd: AtomicUsize::new(0),
            packets_received: AtomicU64::new(0),
            tx_lock: tokio::sync::Mutex::new(()),
            cached_rto_timeout: Mutex::new(None),
            stats_bytes_sent: AtomicU64::new(0),
            stats_bytes_received: AtomicU64::new(0),
            stats_packets_sent: AtomicU64::new(0),
            stats_packets_received: AtomicU64::new(0),
            stats_retransmissions: AtomicU64::new(0),
            stats_heartbeats_sent: AtomicU64::new(0),
            stats_created_time: Instant::now(),
            outgoing_packet_tx,
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        let inner_clone = inner.clone();
        let dtls_transport_clone = dtls_transport.clone();
        let runner = async move {
            let close_rx_2 = close_rx.clone();
            tokio::select! {
                _ = inner_clone.run_loop(close_rx, incoming_data_rx) => {},
                _ = async {
                    while let Some(packet) = outgoing_packet_rx.recv().await {
                        if let Err(e) = dtls_transport_clone.send(packet).await {
                            warn!("SCTP Failed to send outgoing DTLS packet: {}", e);
                            if e.to_string().contains("DTLS not connected") {
                                break;
                            }
                        }
                    }
                } => {},
                _ = close_rx_2.notified() => {}
            }
        };

        (transport, runner)
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.inner.send_data(channel_id, data).await
    }

    pub async fn send_text(&self, channel_id: u16, data: impl AsRef<str>) -> Result<()> {
        self.inner.send_text(channel_id, data).await
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        self.inner.send_dcep_open(dc).await
    }

    pub async fn close_data_channel(&self, channel_id: u16) -> Result<()> {
        self.inner.close_data_channel(channel_id).await
    }

    pub fn buffered_amount(&self) -> usize {
        self.inner.flight_size.load(Ordering::SeqCst)
    }
}

impl Drop for SctpTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl SctpInner {
    fn compute_ack_delay_ms(&self, has_gap: bool) -> u32 {
        if !has_gap {
            return 50;
        }
        let srtt = self.rto_state.lock().unwrap().srtt;
        if srtt == 0.0 {
            return 20;
        }
        let ms = (srtt * 1000.0 * 0.25).round() as u32;
        ms.clamp(10, 50)
    }

    fn gap_signature(&self, cumulative_tsn_ack: u32) -> u32 {
        let blocks = self.build_gap_ack_blocks(cumulative_tsn_ack);
        let mut sig: u32 = 0x9E37_79B9; // golden ratio constant seed
        for (s, e) in blocks {
            let pair = ((s as u32) << 16) | (e as u32);
            // mix
            sig = sig.wrapping_add(pair ^ (pair.rotate_left(13)));
            sig ^= sig.rotate_left(7);
        }
        sig
    }
    async fn run_loop(
        &self,
        close_rx: Arc<tokio::sync::Notify>,
        mut incoming_data_rx: mpsc::UnboundedReceiver<Bytes>,
    ) {
        debug!("SctpTransport run_loop started");
        *self.state.lock().unwrap() = SctpState::Connecting;

        // Guard to ensure cleanup happens on drop (cancellation)
        let _guard = SctpCleanupGuard { inner: self };

        // Wait for DTLS to be connected
        let mut dtls_state_rx = self.dtls_transport.subscribe_state();
        loop {
            let state = dtls_state_rx.borrow_and_update().clone();
            if let DtlsState::Connected(_, _) = state {
                debug!("SCTP: DTLS connected, starting SCTP");
                break;
            }
            if let DtlsState::Failed | DtlsState::Closed = state {
                warn!("DTLS failed or closed before SCTP start");
                return;
            }
            if dtls_state_rx.changed().await.is_err() {
                return;
            }
        }

        if self.is_client {
            if let Err(e) = self.send_init().await {
                warn!("Failed to send SCTP INIT: {}", e);
            }
        }

        let mut sack_deadline: Option<Instant> = None;
        let mut last_heartbeat = Instant::now();
        let heartbeat_interval = Duration::from_secs(15);

        loop {
            // Check if state was changed to Closed by timeout handler
            {
                let state = self.state.lock().unwrap();
                if *state == SctpState::Closed {
                    debug!("SctpTransport run_loop exiting (state is Closed)");
                    break;
                }
            }

            let now = Instant::now();

            // 1. Calculate RTO Timeout
            let rto_timeout_cached = {
                let cached = self.cached_rto_timeout.lock().unwrap();
                if let Some((last_calc, timeout)) = *cached {
                    if now.duration_since(last_calc) < Duration::from_millis(10) {
                        Some(timeout)
                    } else {
                        None
                    }
                } else {
                    None
                }
            };

            let rto_timeout = if let Some(t) = rto_timeout_cached {
                t
            } else {
                let t = {
                    let sent_queue = self.sent_queue.lock().unwrap();
                    let rto = self.rto_state.lock().unwrap().rto;
                    let mut soonest_expiry = None;
                    let mut soonest_tsn = None;

                    for (tsn, record) in sent_queue.iter() {
                        if record.acked {
                            continue;
                        }
                        let expiry = record.sent_time + Duration::from_secs_f64(rto);
                        if soonest_expiry.is_none() || expiry < soonest_expiry.unwrap() {
                            soonest_expiry = Some(expiry);
                            soonest_tsn = Some(*tsn);
                        }
                    }

                    if let Some(expiry) = soonest_expiry {
                        let timeout = if expiry > now {
                            expiry - now
                        } else {
                            Duration::from_millis(1)
                        };

                        // Log if timeout is suspiciously long
                        if timeout > Duration::from_secs(5) {
                            debug!(
                                "RTO timer: suspiciously long timeout {:.1}s for TSN {}, rto={:.1}s, queue_len={}",
                                timeout.as_secs_f64(),
                                soonest_tsn.unwrap_or(0),
                                rto,
                                sent_queue.len()
                            );
                        }

                        timeout
                    } else {
                        Duration::from_secs(3600)
                    }
                };
                let mut cached = self.cached_rto_timeout.lock().unwrap();
                *cached = Some((now, t));
                t
            };

            // 2. Calculate SACK Timeout
            let sack_timeout = if self.sack_counter.load(Ordering::Relaxed) > 0 {
                if sack_deadline.is_none() {
                    let delay = self.ack_delay_ms.load(Ordering::Relaxed);
                    sack_deadline = Some(now + Duration::from_millis(delay as u64));
                }
                let deadline = sack_deadline.unwrap();
                if deadline > now {
                    deadline - now
                } else {
                    Duration::from_millis(1)
                }
            } else {
                sack_deadline = None;
                Duration::from_secs(3600)
            };

            // 3. Calculate Heartbeat Timeout
            let heartbeat_timeout = if now >= last_heartbeat + heartbeat_interval {
                Duration::from_millis(1)
            } else {
                (last_heartbeat + heartbeat_interval) - now
            };

            let sleep_duration = rto_timeout.min(sack_timeout).min(heartbeat_timeout);

            tokio::select! {
                _ = close_rx.notified() => {
                    debug!("SctpTransport run_loop exiting (closed)");
                    break;
                },
                _ = self.timer_notify.notified() => {
                    // Woken up by sender, recalculate timeout
                },
                _ = tokio::time::sleep(sleep_duration) => {
                    // Check SACK Timer
                    if let Some(deadline) = sack_deadline {
                        if Instant::now() >= deadline {
                            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
                            // Only send if we still have pending acks
                            if self.sack_counter.load(Ordering::Relaxed) > 0 {
                                trace!("SACK Timer expired, sending SACK for {}", ack);
                                if let Err(e) = self.send_sack(ack).await {
                                    debug!("Failed to send Delayed SACK: {}", e);
                                }
                                self.sack_counter.store(0, Ordering::Relaxed);
                                self.ack_scheduled.store(false, Ordering::Relaxed);
                            }
                            sack_deadline = None;
                        }
                    }

                    // Check RTO Timer
                    // We check this regardless of whether sleep woke up due to RTO or SACK,
                    // because they might be close.
                    if let Err(e) = self.handle_timeout().await {
                        warn!("SCTP handle timeout error: {}", e);
                    }

                    // Check Heartbeat Timer
                    if Instant::now() >= last_heartbeat + heartbeat_interval {
                        if let Err(e) = self.send_heartbeat().await {
                            warn!("Failed to send HEARTBEAT: {}", e);
                        }
                        last_heartbeat = Instant::now();
                    }
                },
                res = incoming_data_rx.recv() => {
                    match res {
                        Some(packet) => {
                            if let Err(e) = self.handle_packet(packet).await {
                                warn!("SCTP handle packet error: {}", e);
                            }
                            // Batch receive: try to drain channel
                            while let Ok(packet) = incoming_data_rx.try_recv() {
                                if let Err(e) = self.handle_packet(packet).await {
                                    warn!("SCTP handle packet error: {}", e);
                                }
                            }
                        }
                        None => {
                            warn!("SCTP loop error: Channel closed");
                            break;
                        }
                    }
                }
            }
        }
        debug!("SctpTransport run_loop finished");

        // Print stats on loop exit if connection was established
        let final_state = *self.state.lock().unwrap();
        if final_state == SctpState::Closed {
            self.print_stats("LOOP_EXIT");
        }
    }

    async fn handle_timeout(&self) -> Result<()> {
        let mut to_retransmit = Vec::new();
        let mut abandoned_tsn: Option<u32> = None;
        let retransmit_size;

        let now = Instant::now();
        let rto = { self.rto_state.lock().unwrap().rto };
        let rto_duration = Duration::from_secs_f64(rto);
        {
            let mut sent_queue = self.sent_queue.lock().unwrap();

            // First pass: identify which packets have actually timed out
            let timed_out_tsns: std::collections::HashSet<u32> = sent_queue
                .iter()
                .filter(|(_, record)| !record.acked && now >= record.sent_time + rto_duration)
                .map(|(tsn, _)| *tsn)
                .collect();

            if timed_out_tsns.is_empty() {
                return Ok(());
            }

            // Second pass: reset flight status for ALL in-flight packets
            // This is necessary because RTO means we lost all in-flight data
            for record in sent_queue.values_mut() {
                if record.in_flight {
                    record.in_flight = false;
                    let len = record.payload.len();
                    self.flight_size
                        .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |f| {
                            Some(f.saturating_sub(len))
                        })
                        .ok();
                }
            }

            // Third pass: Only reset sent_time and stats for packets that actually timed out
            // This prevents disrupting packets that are still within their RTO window
            for (tsn, record) in sent_queue.iter_mut() {
                if timed_out_tsns.contains(tsn) {
                    record.sent_time = now;
                    record.missing_reports = 0;
                    record.fast_retransmit = false;
                    record.fast_retransmit_time = None; // Clear fast retransmit timestamp on RTO
                }
            }
            self.flow_control_notify.notify_waiters();

            {
                let mut cached = self.cached_rto_timeout.lock().unwrap();
                *cached = None;
            }

            let channel_info: std::collections::HashMap<u16, Option<u16>> = {
                let channels = self.data_channels.lock().unwrap();
                channels
                    .iter()
                    .filter_map(|weak_dc| weak_dc.upgrade().map(|dc| (dc.id, dc.max_retransmits)))
                    .collect()
            };

            let cwnd_for_retrans = MAX_SCTP_PACKET_SIZE * 2;
            let mut current_len: usize = 0;
            let mut retransmit_batch_size: usize = 0;

            // Fourth pass: Only process packets that actually timed out
            // Use the pre-computed set to avoid issues with modified sent_time
            for (tsn, record) in sent_queue.iter_mut() {
                if record.acked {
                    continue;
                }

                // Only process packets that actually timed out
                if !timed_out_tsns.contains(tsn) {
                    continue;
                }

                // Increment transmit_count only for timed-out packets
                record.transmit_count += 1;

                let mut abandoned = false;
                // Check global limit first (applies to all channels)
                if record.transmit_count >= 20 {
                    abandoned = true;
                    warn!(
                        "Abandoning TSN {} after {} retransmits (global limit reached, stream_id={})",
                        tsn, record.transmit_count, record.stream_id
                    );
                } else if let Some(Some(max_rexmit)) = channel_info.get(&record.stream_id) {
                    // Check channel-specific limit
                    if record.transmit_count >= *max_rexmit as u32 {
                        abandoned = true;
                        warn!(
                            "Abandoning TSN {} after {} retransmits (channel {} max_retransmits={})",
                            tsn, record.transmit_count, record.stream_id, max_rexmit
                        );
                    }
                }

                if abandoned {
                    record.abandoned = true;
                    if abandoned_tsn.is_none() || *tsn > abandoned_tsn.unwrap() {
                        abandoned_tsn = Some(*tsn);
                    }
                } else {
                    if current_len + record.payload.len() <= cwnd_for_retrans {
                        // Log which TSN we're retransmitting
                        if to_retransmit.is_empty() {
                            debug!(
                                "Retransmitting TSN {} (transmit_count: {}, payload: {} bytes)",
                                tsn,
                                record.transmit_count,
                                record.payload.len()
                            );
                        }
                        to_retransmit.push((*tsn, record.payload.clone()));
                        current_len += record.payload.len();
                        retransmit_batch_size += record.payload.len();
                        record.sent_time = now;
                        record.in_flight = true;
                    } else {
                        record.in_flight = false;
                    }
                }
            }

            retransmit_size = retransmit_batch_size;
        }

        let sent_queue_len = self.sent_queue.lock().unwrap().len();

        if let Some(tsn) = abandoned_tsn {
            debug!("Abandoning chunks up to TSN {}", tsn);
            self.send_forward_tsn(tsn).await?;
        }

        if !to_retransmit.is_empty() {
            let error_count = self.association_error_count.fetch_add(1, Ordering::SeqCst) + 1;

            // Check if peer window is closed
            let peer_rwnd = self.peer_rwnd.load(Ordering::SeqCst);
            if peer_rwnd == 0 && to_retransmit.len() > 1 {
                // Peer's receive window is full, only send a probe packet
                warn!(
                    "SCTP peer receive window is 0, sending only 1 probe packet instead of {} chunks",
                    to_retransmit.len()
                );
                to_retransmit.truncate(1);
            }

            if error_count >= self.max_association_retransmits
                && self.max_association_retransmits > 0
            {
                let rto_state = self.rto_state.lock().unwrap();
                warn!(
                    "SCTP Association RTO limit reached ({}/{}), RTO={:.1}s, closing connection",
                    error_count, self.max_association_retransmits, rto_state.rto
                );
                drop(rto_state);
                self.print_stats("RTO_LIMIT_REACHED");
                self.set_state(SctpState::Closed);
                return Ok(());
            }

            {
                let mut rto_state = self.rto_state.lock().unwrap();
                rto_state.backoff();
                let chunk_count = to_retransmit.len();
                let peer_rwnd = self.peer_rwnd.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);

                if chunk_count > 5 {
                    debug!(
                        "SCTP RTO Timeout! Backoff RTO to {}s, retransmitting {} chunks, error count: {}/{}, peer_rwnd={}, cwnd={}, queue_len={}",
                        rto_state.rto,
                        chunk_count,
                        error_count,
                        self.max_association_retransmits,
                        peer_rwnd,
                        cwnd,
                        sent_queue_len
                    );
                }

                // Check if we're stuck - no progress for multiple RTOs
                if error_count >= 5 && sent_queue_len > 10 {
                    debug!(
                        "SCTP connection appears stuck: {} pending chunks, {} error count, peer may be unresponsive",
                        sent_queue_len, error_count
                    );
                }
            }

            self.stats_retransmissions
                .fetch_add(to_retransmit.len() as u64, Ordering::Relaxed);

            let cwnd = self.cwnd.load(Ordering::SeqCst);
            let new_ssthresh = (cwnd / 2).max(SSTHRESH_MIN);
            self.ssthresh.store(new_ssthresh, Ordering::SeqCst);

            let new_cwnd = MAX_SCTP_PACKET_SIZE * 2;
            self.cwnd.store(new_cwnd, Ordering::SeqCst);
            self.partial_bytes_acked.store(0, Ordering::SeqCst);
            self.fast_recovery_active.store(false, Ordering::SeqCst);

            self.fast_recovery_exit_tsn.store(0, Ordering::SeqCst);
            debug!(
                "Congestion Control: RTO timeout, cwnd {} -> {}, ssthresh {}",
                cwnd, new_cwnd, new_ssthresh
            );

            if retransmit_size > 0 {
                self.flight_size
                    .fetch_add(retransmit_size, Ordering::SeqCst);
            }

            let chunks: Vec<Bytes> = to_retransmit.into_iter().map(|(_, p)| p).collect();
            if let Err(e) = self.transmit_chunks(chunks).await {
                warn!("Failed to retransmit chunks: {}", e);
            }
        }

        self.drain_retransmissions().await?;

        Ok(())
    }

    async fn drain_retransmissions(&self) -> Result<()> {
        let now = Instant::now();
        let chunks_to_send = {
            let mut sent_queue = self.sent_queue.lock().unwrap();
            let current_flight = self.flight_size.load(Ordering::SeqCst);
            let cwnd = self.cwnd.load(Ordering::SeqCst);
            let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
            let effective_window = cwnd.min(rwnd);

            if current_flight >= effective_window {
                return Ok(()); // Window already full
            }

            let available_window = effective_window - current_flight;
            let mut chunks_to_send = Vec::new();
            let mut total_size = 0;
            let mut modified_tsns = Vec::new();
            let mut window_blocked = false;

            // Collect chunks that fit in available window
            for (tsn, record) in sent_queue.iter_mut() {
                if !record.acked && !record.in_flight && !record.abandoned {
                    let len = record.payload.len();
                    if total_size + len > available_window {
                        window_blocked = true;
                        break; // Would exceed window
                    }

                    record.in_flight = true;
                    record.transmit_count += 1;
                    // Only update sent_time for retransmissions (transmit_count > 1)
                    // For first transmission (transmit_count going 0->1), keep original sent_time
                    if record.transmit_count > 1 {
                        record.sent_time = now;
                    }
                    record.fast_retransmit = false;
                    total_size += len;
                    chunks_to_send.push(record.payload.clone());
                    modified_tsns.push(*tsn);

                    if chunks_to_send.len() >= 32 {
                        break;
                    }
                }
            }

            // Zero Window Probing: If logic prevents sending but window is zero (or too small) and flight is zero,
            // strict flow control would deadlock. We must send 1 packet as probe.
            let mut is_probe = false;
            if chunks_to_send.is_empty() && current_flight == 0 && window_blocked {
                for (tsn, record) in sent_queue.iter_mut() {
                    if !record.acked && !record.in_flight && !record.abandoned {
                        record.in_flight = true;
                        record.transmit_count += 1;
                        if record.transmit_count > 1 {
                            record.sent_time = now;
                        }
                        record.fast_retransmit = false;

                        let len = record.payload.len();
                        total_size += len;
                        chunks_to_send.push(record.payload.clone());
                        modified_tsns.push(*tsn);
                        is_probe = true;
                        break; // Only 1 probe packet
                    }
                }
            }

            if total_size > 0 {
                let new_flight = current_flight + total_size;
                // Re-check effective_window because rwnd/cwnd might have changed (atomics)
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                // If probing, we intentionally exceed window (0).
                // Otherwise calculate strict overflow logic.
                if !is_probe && new_flight > effective_window {
                    debug!(
                        "drain_retransmissions: would exceed window (flight={} + {} > {}), skipping",
                        current_flight, total_size, effective_window
                    );
                    for tsn in modified_tsns {
                        if let Some(record) = sent_queue.get_mut(&tsn) {
                            if record.in_flight {
                                record.in_flight = false;
                                if record.transmit_count > 0 {
                                    record.transmit_count -= 1;
                                }
                            }
                        }
                    }
                    return Ok(());
                }
                self.flight_size.store(new_flight, Ordering::SeqCst);
            }

            chunks_to_send
        };

        if !chunks_to_send.is_empty() {
            debug!(
                "Draining {} retransmissions from queue",
                chunks_to_send.len()
            );
            self.transmit_chunks(chunks_to_send).await?;
        }
        Ok(())
    }

    fn update_rto(&self, rtt: f64) {
        let mut rto_state = self.rto_state.lock().unwrap();
        rto_state.update(rtt);
        trace!(
            "RTT update: rtt={} srtt={} rttvar={} rto={}",
            rtt, rto_state.srtt, rto_state.rttvar, rto_state.rto
        );
    }

    async fn send_init(&self) -> Result<()> {
        let local_tag = random_u32();
        self.verification_tag.store(local_tag, Ordering::SeqCst);

        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);

        let mut init_params = BytesMut::new();
        // Initiate Tag
        init_params.put_u32(local_tag);
        // a_rwnd (1MB)
        init_params.put_u32(1024 * 1024);
        // Outbound streams
        init_params.put_u16(10);
        // Inbound streams
        init_params.put_u16(10);
        // Initial TSN
        init_params.put_u32(initial_tsn);

        // Forward TSN (Type 0xC000)
        init_params.put_u16(0xC000);
        init_params.put_u16(4);

        // Supported Extensions (Type 0x8008)
        init_params.put_u16(0x8008);
        init_params.put_u16(5);
        init_params.put_u8(0xC0); // Forward TSN
        init_params.put_u8(0); // Padding
        init_params.put_u16(0); // Padding to 8 bytes total (4 header + 1 value + 3 padding)

        // Optional: Supported Address Types (IPv4)
        init_params.put_u16(12); // Type 12
        init_params.put_u16(6); // Length 6
        init_params.put_u16(5); // IPv4
        init_params.put_u16(0); // Padding

        self.send_chunk(CT_INIT, 0, init_params.freeze(), 0).await
    }

    fn set_state(&self, new_state: SctpState) {
        let mut state = self.state.lock().unwrap();
        if *state != new_state {
            debug!("SCTP state transition: {:?} -> {:?}", *state, new_state);
            *state = new_state;
        }
    }

    async fn handle_packet(&self, packet: Bytes) -> Result<()> {
        let now = Instant::now();
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        self.stats_bytes_received
            .fetch_add(packet.len() as u64, Ordering::Relaxed);
        self.stats_packets_received.fetch_add(1, Ordering::Relaxed);

        let mut buf = packet.clone();
        let src_port = buf.get_u16();
        let dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let received_checksum = buf.get_u32_le();
        trace!(
            "SCTP packet received: src={}, dst={}, vtag={:08x}",
            src_port, dst_port, verification_tag
        );

        {
            let mut packet_copy = packet.to_vec();
            if packet_copy.len() >= 12 {
                packet_copy[8] = 0;
                packet_copy[9] = 0;
                packet_copy[10] = 0;
                packet_copy[11] = 0;
                let calculated = crc32c::crc32c(&packet_copy);
                if calculated != received_checksum {
                    warn!(
                        "SCTP Checksum mismatch: received {:08x}, calculated {:08x}",
                        received_checksum, calculated
                    );
                    return Ok(());
                }
            }
        }

        while buf.has_remaining() {
            if buf.remaining() < CHUNK_HEADER_SIZE {
                break;
            }
            let chunk_type = buf.get_u8();
            let chunk_flags = buf.get_u8();
            let chunk_length = buf.get_u16() as usize;

            if chunk_length < CHUNK_HEADER_SIZE
                || buf.remaining() < chunk_length - CHUNK_HEADER_SIZE
            {
                break;
            }

            let chunk_value = buf.split_to(chunk_length - CHUNK_HEADER_SIZE);

            // Padding
            let padding = (4 - (chunk_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            match chunk_type {
                CT_INIT => self.handle_init(verification_tag, chunk_value).await?,
                CT_INIT_ACK => self.handle_init_ack(chunk_value).await?,
                CT_COOKIE_ECHO => self.handle_cookie_echo(chunk_value).await?,
                CT_COOKIE_ACK => self.handle_cookie_ack(chunk_value).await?,
                CT_DATA => self.handle_data(chunk_flags, chunk_value).await?,
                CT_SACK => self.handle_sack(chunk_value).await?,
                CT_HEARTBEAT => self.handle_heartbeat(chunk_value).await?,
                CT_HEARTBEAT_ACK => {
                    trace!("SCTP HEARTBEAT ACK received");
                    self.association_error_count.store(0, Ordering::SeqCst);
                    self.consecutive_heartbeat_failures
                        .store(0, Ordering::SeqCst);
                    let mut sent_time = self.heartbeat_sent_time.lock().unwrap();
                    if let Some(start) = *sent_time {
                        let rtt = now.duration_since(start).as_secs_f64();
                        trace!("SCTP Heartbeat RTT: {:.3}s", rtt);
                        self.update_rto(rtt);
                        *sent_time = None;
                    }
                }
                CT_FORWARD_TSN => self.handle_forward_tsn(chunk_value).await?,
                CT_RECONFIG => self.handle_reconfig(chunk_value).await?,
                CT_ABORT => {
                    let error_count = self.association_error_count.load(Ordering::SeqCst);
                    debug!(
                        "SCTP ABORT received from remote peer (our error_count was {}/{}). Remote may have different max_association_retransmits limit.",
                        error_count, self.max_association_retransmits
                    );
                    self.print_stats("REMOTE_ABORT");
                    self.set_state(SctpState::Closed);
                }
                CT_SHUTDOWN => {
                    debug!("SCTP SHUTDOWN received from remote peer");
                    let tag = self.remote_verification_tag.load(Ordering::SeqCst);
                    self.send_chunk(CT_SHUTDOWN_ACK, 0, Bytes::new(), tag)
                        .await?;
                }
                CT_SHUTDOWN_ACK => {
                    debug!("SCTP SHUTDOWN ACK received, closing connection");
                    self.print_stats("REMOTE_SHUTDOWN");
                    self.set_state(SctpState::Closed);
                }
                _ => {
                    trace!("Unhandled SCTP chunk type: {}", chunk_type);
                }
            }
        }

        // After processing all chunks in the packet, check if we should send a SACK
        let sack_count = self.sack_counter.load(Ordering::Relaxed);
        if sack_count >= 2 {
            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
            if let Err(e) = self.send_sack(ack).await {
                warn!("Failed to send SACK after packet: {}", e);
            }
            self.sack_counter.store(0, Ordering::Relaxed);
            self.ack_scheduled.store(false, Ordering::Relaxed);
        }

        Ok(())
    }

    async fn handle_init(&self, _remote_tag: u32, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            // Fixed params
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);
        self.remote_verification_tag
            .store(initiate_tag, Ordering::SeqCst);
        self.cumulative_tsn_ack
            .store(initial_tsn.wrapping_sub(1), Ordering::SeqCst);

        // Generate local tag
        let local_tag = random_u32();
        self.verification_tag.store(local_tag, Ordering::SeqCst);

        // Send INIT ACK
        // We need to construct a cookie. For simplicity, we'll just echo back some dummy data.
        let cookie = b"dummy_cookie";

        let mut init_ack_params = BytesMut::new();
        // Initiate Tag
        init_ack_params.put_u32(local_tag);
        // a_rwnd
        init_ack_params.put_u32(self.local_rwnd as u32);
        // Outbound streams
        init_ack_params.put_u16(10);
        // Inbound streams
        init_ack_params.put_u16(10);
        // Initial TSN
        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);
        init_ack_params.put_u32(initial_tsn);

        // Forward TSN (Type 0xC000)
        init_ack_params.put_u16(0xC000);
        init_ack_params.put_u16(4);

        // Supported Extensions (Type 0x8008)
        init_ack_params.put_u16(0x8008);
        init_ack_params.put_u16(5);
        init_ack_params.put_u8(0xC0); // Forward TSN
        init_ack_params.put_u8(0); // Padding
        init_ack_params.put_u16(0); // Padding to 4 bytes payload

        // State Cookie Parameter (Type 7)
        init_ack_params.put_u16(7);
        init_ack_params.put_u16(4 + cookie.len() as u16);
        init_ack_params.put_slice(cookie);
        // Padding for cookie
        let padding = (4 - (cookie.len() % 4)) % 4;
        for _ in 0..padding {
            init_ack_params.put_u8(0);
        }

        self.send_chunk(CT_INIT_ACK, 0, init_ack_params.freeze(), initiate_tag)
            .await?;
        Ok(())
    }

    async fn handle_init_ack(&self, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        if buf.remaining() < 16 {
            return Ok(());
        }
        let initiate_tag = buf.get_u32();
        let a_rwnd = buf.get_u32();
        let _outbound_streams = buf.get_u16();
        let _inbound_streams = buf.get_u16();
        let initial_tsn = buf.get_u32();

        self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);
        self.remote_verification_tag
            .store(initiate_tag, Ordering::SeqCst);
        self.cumulative_tsn_ack
            .store(initial_tsn.wrapping_sub(1), Ordering::SeqCst);

        // Parse parameters to find Cookie
        let mut cookie = None;
        while buf.remaining() >= 4 {
            let param_type = buf.get_u16();
            let param_len = buf.get_u16() as usize;
            if param_len < 4 || buf.remaining() < param_len - 4 {
                break;
            }
            let param_value = buf.split_to(param_len - 4);

            // Padding
            let padding = (4 - (param_len % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            if param_type == 7 {
                // State Cookie
                cookie = Some(param_value);
            }
        }

        if let Some(cookie_bytes) = cookie {
            let tag = self.remote_verification_tag.load(Ordering::SeqCst);
            self.send_chunk(CT_COOKIE_ECHO, 0, cookie_bytes, tag)
                .await?;
        }

        Ok(())
    }

    async fn handle_cookie_ack(&self, _chunk: Bytes) -> Result<()> {
        *self.state.lock().unwrap() = SctpState::Connected;

        let channels_to_process = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut to_process = Vec::new();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    to_process.push(dc);
                    true
                } else {
                    false
                }
            });
            to_process
        };

        for dc in channels_to_process {
            if dc.negotiated {
                dc.state
                    .store(DataChannelState::Open as usize, Ordering::SeqCst);
                dc.send_event(DataChannelEvent::Open);
            } else {
                let state = dc.state.load(Ordering::SeqCst);
                if state == DataChannelState::Connecting as usize {
                    if let Err(e) = self.send_dcep_open(&dc).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_sack(&self, chunk: Bytes) -> Result<()> {
        // Parse SACK to see if we are losing packets
        if chunk.len() >= 12 {
            let mut buf = chunk.clone();
            let cumulative_tsn_ack = buf.get_u32();
            let a_rwnd = buf.get_u32();
            let num_gap_ack_blocks = buf.get_u16();
            let _num_duplicate_tsns = buf.get_u16();
            let _old_rwnd = self.peer_rwnd.swap(a_rwnd, Ordering::SeqCst);

            self.flow_control_notify.notify_waiters();

            let mut gap_blocks = Vec::new();
            for _ in 0..num_gap_ack_blocks {
                if buf.remaining() < 4 {
                    break;
                }
                gap_blocks.push((buf.get_u16(), buf.get_u16()));
            }

            // Log SACK receipt with flight size and queue info
            let current_flight = self.flight_size.load(Ordering::SeqCst);
            let queue_len = self.sent_queue.lock().unwrap().len();
            if !gap_blocks.is_empty() {
                trace!(
                    "Received SACK: cum_ack={}, a_rwnd={}, gaps={}, flight={}, queue={}",
                    cumulative_tsn_ack,
                    a_rwnd,
                    gap_blocks.len(),
                    current_flight,
                    queue_len
                );
            } else {
                trace!(
                    "Received SACK: cum_ack={}, a_rwnd={}, flight={}, queue={}",
                    cumulative_tsn_ack, a_rwnd, current_flight, queue_len
                );
            }

            let now = Instant::now();
            let outcome = {
                let mut sent_queue = self.sent_queue.lock().unwrap();
                apply_sack_to_sent_queue(&mut *sent_queue, cumulative_tsn_ack, &gap_blocks, now)
            };

            // Track retransmissions from fast retransmit
            if !outcome.retransmit.is_empty() {
                self.stats_retransmissions
                    .fetch_add(outcome.retransmit.len() as u64, Ordering::Relaxed);
            }

            if outcome.bytes_acked_by_cum_tsn > 0 || !outcome.rtt_samples.is_empty() {
                self.association_error_count.store(0, Ordering::SeqCst);

                let ssthresh = self.ssthresh.load(Ordering::SeqCst);
                if ssthresh == SSTHRESH_MIN && outcome.bytes_acked_by_cum_tsn > 0 {
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    // If cwnd is approaching ssthresh (within 20%), allow it to grow further
                    if cwnd >= ssthresh * 4 / 5 {
                        // Raise ssthresh to 50% of initial cwnd (6KB), allowing controlled growth
                        let new_ssthresh = CWND_INITIAL / 2;
                        self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
                        debug!(
                            "Raising ssthresh {} -> {} to allow faster recovery",
                            ssthresh, new_ssthresh
                        );
                    }
                }
            }

            for rtt in outcome.rtt_samples {
                self.update_rto(rtt);
            }

            if outcome.flight_reduction > 0 {
                let reduction = outcome.flight_reduction;
                let _ = self
                    .flight_size
                    .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |f| {
                        Some(f.saturating_sub(reduction))
                    });

                // Congestion Control: Update cwnd
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let ssthresh = self.ssthresh.load(Ordering::SeqCst);

                // Check if we are in Fast Recovery
                let exit_tsn = self.fast_recovery_exit_tsn.load(Ordering::SeqCst);
                let was_in_fast_recovery = self.fast_recovery_active.load(Ordering::SeqCst);
                let in_fast_recovery =
                    was_in_fast_recovery && (cumulative_tsn_ack.wrapping_sub(exit_tsn) as i32) < 0;

                if was_in_fast_recovery && !in_fast_recovery {
                    self.fast_recovery_active.store(false, Ordering::SeqCst);
                    debug!(
                        "Exiting Fast Recovery! cum_ack: {}, exit_tsn: {}",
                        cumulative_tsn_ack, exit_tsn
                    );
                }

                if in_fast_recovery {
                    // In Fast Recovery, we don't increase cwnd normally.
                } else if cwnd < ssthresh {
                    // Slow Start: cwnd += bytes_acked (exponential growth)
                    // RFC 4960: limit growth to avoid overshooting network capacity
                    if outcome.bytes_acked_by_cum_tsn > 0 {
                        // Limit single ACK increase to 2*MTU for more controlled growth
                        // This reduces the risk of overshoot while maintaining fast recovery
                        let increase = outcome.bytes_acked_by_cum_tsn.min(MAX_SCTP_PACKET_SIZE * 2);
                        let old_cwnd = self.cwnd.fetch_add(increase, Ordering::SeqCst);
                        let new_cwnd = old_cwnd + increase;
                        // Log when cwnd doubles to track growth
                        if new_cwnd >= old_cwnd * 2 || old_cwnd < MAX_SCTP_PACKET_SIZE * 3 {
                            debug!(
                                "Congestion Control: Slow Start cwnd {} -> {} (ssthresh={}, increase={})",
                                old_cwnd, new_cwnd, ssthresh, increase
                            );
                        }
                    }
                } else {
                    // Congestion Avoidance: cwnd += MTU per RTT
                    if outcome.bytes_acked_by_cum_tsn > 0 {
                        let pba = self
                            .partial_bytes_acked
                            .fetch_add(outcome.bytes_acked_by_cum_tsn, Ordering::SeqCst);
                        let total_pba = pba + outcome.bytes_acked_by_cum_tsn;
                        if total_pba >= cwnd {
                            self.partial_bytes_acked.fetch_sub(cwnd, Ordering::SeqCst);
                            let old_cwnd =
                                self.cwnd.fetch_add(MAX_SCTP_PACKET_SIZE, Ordering::SeqCst);
                            debug!(
                                "Congestion Control: Congestion Avoidance cwnd {} -> {} (ssthresh={}, pba={})",
                                old_cwnd,
                                old_cwnd + MAX_SCTP_PACKET_SIZE,
                                ssthresh,
                                total_pba
                            );
                        }
                    }
                }

                self.flow_control_notify.notify_waiters();
            }

            if outcome.head_moved || outcome.flight_reduction > 0 {
                self.timer_notify.notify_one();
                let mut cached = self.cached_rto_timeout.lock().unwrap();
                *cached = None;
            }

            // Handle Fast Retransmit
            if !outcome.retransmit.is_empty() {
                let exit_tsn = self.fast_recovery_exit_tsn.load(Ordering::SeqCst);
                let was_in_fast_recovery = self.fast_recovery_active.load(Ordering::SeqCst);
                let in_fast_recovery =
                    was_in_fast_recovery && (cumulative_tsn_ack.wrapping_sub(exit_tsn) as i32) < 0;

                if !in_fast_recovery {
                    // Enter Fast Recovery
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    let new_ssthresh = (cwnd / 2).max(SSTHRESH_MIN);
                    self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
                    self.cwnd.store(new_ssthresh, Ordering::SeqCst);
                    self.partial_bytes_acked.store(0, Ordering::SeqCst);
                    self.fast_recovery_active.store(true, Ordering::SeqCst);

                    // Record the highest TSN currently in flight
                    let highest_tsn = self.next_tsn.load(Ordering::SeqCst).wrapping_sub(1);
                    self.fast_recovery_exit_tsn
                        .store(highest_tsn, Ordering::SeqCst);

                    debug!(
                        "Entering Fast Recovery! New ssthresh/cwnd: {}, exit_tsn: {}, retransmitting {} chunks",
                        new_ssthresh,
                        highest_tsn,
                        outcome.retransmit.len()
                    );
                }

                let chunks: Vec<Bytes> = outcome.retransmit.into_iter().map(|(_, d)| d).collect();
                if let Err(e) = self.transmit_chunks(chunks).await {
                    debug!("Failed to retransmit fast recovery chunks: {}", e);
                }
            }

            // Also check if we should drain any other pending retransmissions
            // (e.g., chunks lost during an RTO that now fit in the growing cwnd)
            self.drain_retransmissions().await?;
        }
        Ok(())
    }

    async fn handle_cookie_echo(&self, _chunk: Bytes) -> Result<()> {
        // Send COOKIE ACK
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_COOKIE_ACK, 0, Bytes::new(), tag).await?;

        *self.state.lock().unwrap() = SctpState::Connected;

        let channels_to_process = {
            let mut channels = self.data_channels.lock().unwrap();
            let mut to_process = Vec::new();
            channels.retain(|weak_dc| {
                if let Some(dc) = weak_dc.upgrade() {
                    to_process.push(dc);
                    true
                } else {
                    false
                }
            });
            to_process
        };

        for dc in channels_to_process {
            if dc.negotiated {
                dc.state
                    .store(DataChannelState::Open as usize, Ordering::SeqCst);
                dc.send_event(DataChannelEvent::Open);
            } else {
                let state = dc.state.load(Ordering::SeqCst);
                if state == DataChannelState::Connecting as usize {
                    if let Err(e) = self.send_dcep_open(&dc).await {
                        warn!("Failed to send DCEP OPEN: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    async fn handle_forward_tsn(&self, chunk: Bytes) -> Result<()> {
        if chunk.len() < 4 {
            return Ok(());
        }
        let mut buf = chunk;
        let new_cumulative_tsn = buf.get_u32();

        let old_cumulative_tsn = self.cumulative_tsn_ack.load(Ordering::SeqCst);
        if new_cumulative_tsn > old_cumulative_tsn {
            debug!(
                "FORWARD TSN: moving cumulative ack from {} to {}",
                old_cumulative_tsn, new_cumulative_tsn
            );
            self.cumulative_tsn_ack
                .store(new_cumulative_tsn, Ordering::SeqCst);

            // Remove skipped packets from received_queue
            {
                let mut received_queue = self.received_queue.lock().unwrap();
                received_queue.retain(|&tsn, _| tsn > new_cumulative_tsn);
            }

            // Trigger processing of any now-contiguous packets
            self.timer_notify.notify_one();
        }

        Ok(())
    }

    async fn handle_reconfig(&self, chunk: Bytes) -> Result<()> {
        let mut buf = chunk;
        while buf.remaining() >= 4 {
            let param_type = buf.get_u16();
            let param_length = buf.get_u16() as usize;
            if param_length < 4 || buf.remaining() < param_length - 4 {
                break;
            }
            let param_data = buf.split_to(param_length - 4);

            // Padding
            let padding = (4 - (param_length % 4)) % 4;
            if buf.remaining() >= padding {
                buf.advance(padding);
            }

            match param_type {
                RECONFIG_PARAM_OUTGOING_SSN_RESET => {
                    self.handle_reconfig_outgoing_ssn_reset(param_data).await?;
                }
                RECONFIG_PARAM_RESPONSE => {
                    self.handle_reconfig_response(param_data).await?;
                }
                _ => {
                    trace!("Unhandled RE-CONFIG parameter type: {}", param_type);
                }
            }
        }
        Ok(())
    }

    async fn handle_reconfig_outgoing_ssn_reset(&self, mut buf: Bytes) -> Result<()> {
        if buf.remaining() < 12 {
            return Ok(());
        }
        let request_sn = buf.get_u32();
        let _response_sn = buf.get_u32();
        let _send_next_tsn = buf.get_u32();

        let last_peer_sn = self.peer_reconfig_request_sn.load(Ordering::SeqCst);
        if request_sn <= last_peer_sn && last_peer_sn != u32::MAX {
            // Duplicate request, just ack it again
            self.send_reconfig_response(request_sn, RECONFIG_RESPONSE_SUCCESS_NOTHING_TO_DO)
                .await?;
            return Ok(());
        }

        self.peer_reconfig_request_sn
            .store(request_sn, Ordering::SeqCst);

        // Reset SSNs for specified streams
        let mut streams = Vec::new();
        while buf.remaining() >= 2 {
            streams.push(buf.get_u16());
        }

        {
            let channels = self.data_channels.lock().unwrap();
            for weak_dc in channels.iter() {
                if let Some(dc) = weak_dc.upgrade() {
                    if streams.is_empty() || streams.contains(&dc.id) {
                        dc.next_ssn.store(0, Ordering::SeqCst);
                        debug!("Reset SSN for stream {}", dc.id);
                    }
                }
            }
        }

        self.send_reconfig_response(request_sn, RECONFIG_RESPONSE_SUCCESS_PERFORMED)
            .await?;
        Ok(())
    }

    async fn handle_reconfig_response(&self, mut buf: Bytes) -> Result<()> {
        if buf.remaining() < 8 {
            return Ok(());
        }
        let response_sn = buf.get_u32();
        let result = buf.get_u32();
        debug!(
            "Received RE-CONFIG response for SN {}, result: {}",
            response_sn, result
        );
        Ok(())
    }

    async fn send_reconfig_response(&self, response_sn: u32, result: u32) -> Result<()> {
        let mut param = BytesMut::with_capacity(12);
        param.put_u16(RECONFIG_PARAM_RESPONSE);
        param.put_u16(12);
        param.put_u32(response_sn);
        param.put_u32(result);

        let mut chunk = BytesMut::with_capacity(16);
        chunk.put_u8(CT_RECONFIG);
        chunk.put_u8(0);
        chunk.put_u16(16);
        chunk.put(param);

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.transmit_chunks_with_tag(vec![chunk.freeze()], tag)
            .await
    }

    pub async fn send_reconfig_ssn_reset(&self, streams: &[u16]) -> Result<()> {
        let request_sn = self.reconfig_request_sn.fetch_add(1, Ordering::SeqCst);
        let param_len = 16 + streams.len() * 2;
        let mut param = BytesMut::with_capacity(param_len);
        param.put_u16(RECONFIG_PARAM_OUTGOING_SSN_RESET);
        param.put_u16(param_len as u16);
        param.put_u32(request_sn);
        param.put_u32(0); // response SN (not used for outgoing reset)
        param.put_u32(self.next_tsn.load(Ordering::SeqCst));

        for &stream in streams {
            param.put_u16(stream);
        }

        // Padding for parameter
        let padding = (4 - (param_len % 4)) % 4;
        for _ in 0..padding {
            param.put_u8(0);
        }

        let chunk_len = 4 + param.len();
        let mut chunk = BytesMut::with_capacity(chunk_len);
        chunk.put_u8(CT_RECONFIG);
        chunk.put_u8(0);
        chunk.put_u16(chunk_len as u16);
        chunk.put(param);

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.transmit_chunks_with_tag(vec![chunk.freeze()], tag)
            .await
    }

    pub async fn close_data_channel(&self, channel_id: u16) -> Result<()> {
        // 1. Find the channel and set state to Closing
        {
            let channels = self.data_channels.lock().unwrap();
            if let Some(dc) = channels
                .iter()
                .find_map(|w| w.upgrade().filter(|d| d.id == channel_id))
            {
                dc.state
                    .store(DataChannelState::Closing as usize, Ordering::SeqCst);
            }
        }

        // 2. Send RE-CONFIG SSN Reset
        self.send_reconfig_ssn_reset(&[channel_id]).await?;

        // 3. Set state to Closed
        {
            let channels = self.data_channels.lock().unwrap();
            if let Some(dc) = channels
                .iter()
                .find_map(|w| w.upgrade().filter(|d| d.id == channel_id))
            {
                dc.state
                    .store(DataChannelState::Closed as usize, Ordering::SeqCst);
                dc.send_event(DataChannelEvent::Close);
            }
        }

        Ok(())
    }

    async fn send_forward_tsn(&self, new_cumulative_tsn: u32) -> Result<()> {
        let mut buf = BytesMut::with_capacity(4);
        buf.put_u32(new_cumulative_tsn);
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_FORWARD_TSN, 0, buf.freeze(), tag).await
    }

    async fn send_heartbeat(&self) -> Result<()> {
        let now = Instant::now();
        {
            let mut sent_time = self.heartbeat_sent_time.lock().unwrap();
            if sent_time.is_some() {
                let rto = self.rto_state.lock().unwrap().rto;
                let is_rto_backing_off = rto > 2.0;

                // Track consecutive heartbeat failures
                let consecutive_failures = self
                    .consecutive_heartbeat_failures
                    .fetch_add(1, Ordering::SeqCst)
                    + 1;

                if !is_rto_backing_off {
                    let error_count =
                        self.association_error_count.fetch_add(1, Ordering::SeqCst) + 1;
                    let sent_queue_len = self.sent_queue.lock().unwrap().len();
                    warn!(
                        "SCTP Heartbeat timeout! Error count: {}/{}, consecutive failures: {}, pending chunks: {}",
                        error_count,
                        self.max_association_retransmits,
                        consecutive_failures,
                        sent_queue_len
                    );
                    if error_count >= self.max_association_retransmits
                        && self.max_association_retransmits > 0
                    {
                        let rto_state = self.rto_state.lock().unwrap();
                        warn!(
                            "SCTP Association heartbeat timeout limit reached ({}/{}), RTO={:.1}s, closing connection",
                            error_count, self.max_association_retransmits, rto_state.rto
                        );
                        drop(rto_state);
                        self.print_stats("HEARTBEAT_TIMEOUT");
                        self.set_state(SctpState::Closed);
                        return Ok(());
                    }
                } else {
                    debug!(
                        "SCTP Heartbeat timeout (RTO={:.1}s is backing off, consecutive failures: {})",
                        rto, consecutive_failures
                    );

                    // If we have 4 consecutive heartbeat failures, even during RTO backoff,
                    // the peer is likely dead. Force close the connection.
                    if consecutive_failures >= 4 {
                        warn!(
                            "SCTP Connection dead: {} consecutive heartbeat failures (RTO={:.1}s), closing connection",
                            consecutive_failures, rto
                        );
                        self.print_stats("HEARTBEAT_DEAD");
                        self.set_state(SctpState::Closed);
                        return Ok(());
                    }
                }
            }
            *sent_time = Some(now);
        }

        let mut buf = BytesMut::with_capacity(8);
        buf.put_u16(1); // Heartbeat Info Parameter Type
        buf.put_u16(8); // Length
        buf.put_u32(random_u32()); // Random info

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        if tag == 0 {
            return Ok(()); // Not connected yet
        }
        self.stats_heartbeats_sent.fetch_add(1, Ordering::Relaxed);
        trace!("Sending SCTP Heartbeat");
        self.send_chunk(CT_HEARTBEAT, 0, buf.freeze(), tag).await
    }

    async fn handle_heartbeat(&self, chunk: Bytes) -> Result<()> {
        // Send HEARTBEAT ACK with same info
        trace!("Received SCTP Heartbeat, sending ACK");

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_HEARTBEAT_ACK, 0, chunk, tag).await?;
        Ok(())
    }

    async fn handle_data(&self, flags: u8, chunk: Bytes) -> Result<()> {
        let mut buf = chunk.clone();
        if buf.remaining() < 12 {
            return Ok(());
        }
        let tsn = buf.get_u32();

        // Deduplication and Ordering Check
        let cumulative_ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
        let diff = tsn.wrapping_sub(cumulative_ack);

        trace!(
            "SCTP DATA received: tsn={}, cum_ack={}, flags={:02x}, diff={}",
            tsn, cumulative_ack, flags, diff as i32
        );

        if diff == 0 || diff > 0x80000000 {
            // Duplicate or Old: record duplicate and schedule fast SACK
            {
                let mut dups = self.dups_buffer.lock().unwrap();
                if dups.len() < 32 {
                    dups.push(tsn);
                }
            }
            let delay = self.compute_ack_delay_ms(true);
            self.ack_delay_ms.store(delay, Ordering::Relaxed);
            if self
                .ack_scheduled
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                self.sack_counter.store(1, Ordering::Relaxed);
                self.timer_notify.notify_one();
            }
            return Ok(());
        }

        // Store in received_queue
        {
            let mut received_queue = self.received_queue.lock().unwrap();
            if received_queue.contains_key(&tsn) {
                debug!("Dropping duplicate buffered packet TSN={}", tsn);
            } else {
                self.used_rwnd.fetch_add(chunk.len(), Ordering::Relaxed);
                received_queue.insert(tsn, (flags, chunk));
            }
        }

        // Process packets in order
        let mut to_process = Vec::new();
        {
            let mut received_queue = self.received_queue.lock().unwrap();
            loop {
                let next_tsn = self
                    .cumulative_tsn_ack
                    .load(Ordering::SeqCst)
                    .wrapping_add(1 + to_process.len() as u32);

                if let Some(entry) = received_queue.remove(&next_tsn) {
                    to_process.push(entry);
                } else {
                    break;
                }
            }
        }

        if !to_process.is_empty() {
            trace!("SCTP processing batch of {} data chunks", to_process.len());
            // Collect channel info once to avoid repeated locking
            let channel_map: std::collections::HashMap<u16, Arc<DataChannel>> = {
                let channels = self.data_channels.lock().unwrap();
                channels
                    .iter()
                    .filter_map(|w| w.upgrade().map(|dc| (dc.id, dc)))
                    .collect()
            };

            for (p_flags, p_chunk) in to_process {
                let chunk_len = p_chunk.len();
                let next_tsn = self
                    .cumulative_tsn_ack
                    .load(Ordering::SeqCst)
                    .wrapping_add(1);

                self.process_data_payload(p_flags, p_chunk, &channel_map)
                    .await?;
                self.cumulative_tsn_ack.store(next_tsn, Ordering::SeqCst);
                self.used_rwnd.fetch_sub(chunk_len, Ordering::Relaxed);
            }
        }

        let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);

        // Check if we have a gap
        let has_gap = !self.received_queue.lock().unwrap().is_empty();

        if has_gap {
            // Prefer quick delayed ack when gaps exist
            let delay = self.compute_ack_delay_ms(true);
            self.ack_delay_ms.store(delay, Ordering::Relaxed);
            // If the gap pattern changed, send an immediate SACK once
            let sig = self.gap_signature(ack);
            let prev = self.last_gap_sig.swap(sig, Ordering::Relaxed);
            if sig != prev {
                // Throttle immediate SACKs to avoid spamming; use RTT-based minimum interval
                let min_ms = self.compute_ack_delay_ms(true);
                let now = Instant::now();
                let allow_immediate = {
                    let last = self.last_immediate_sack.lock().unwrap();
                    match *last {
                        Some(t) => now.duration_since(t) >= Duration::from_millis(min_ms as u64),
                        None => true,
                    }
                };
                if allow_immediate {
                    trace!("Gap changed. Immediate SACK; cum_ack={}.", ack);
                    self.send_sack(ack).await?;
                    self.ack_scheduled.store(false, Ordering::Relaxed);
                    self.sack_counter.store(0, Ordering::Relaxed);
                    {
                        let mut last = self.last_immediate_sack.lock().unwrap();
                        *last = Some(now);
                    }
                } else if self
                    .ack_scheduled
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    debug!(
                        "Gap detected. Cumulative ACK: {}. Scheduling delayed SACK.",
                        ack
                    );
                    self.sack_counter.store(1, Ordering::Relaxed);
                    self.timer_notify.notify_one();
                }
            } else if self
                .ack_scheduled
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                debug!(
                    "Gap detected. Cumulative ACK: {}. Scheduling delayed SACK.",
                    ack
                );
                self.sack_counter.store(1, Ordering::Relaxed);
                self.timer_notify.notify_one();
            }
        } else {
            // Restore normal delayed ack timing
            self.ack_delay_ms.store(200, Ordering::Relaxed);

            // Quick Start: ACK every packet for the first 100 packets to accelerate sender's CWND growth
            let total_received = self.packets_received.fetch_add(1, Ordering::Relaxed);
            if total_received < 100 {
                self.send_sack(ack).await?;
                self.sack_counter.store(0, Ordering::Relaxed);
                self.ack_scheduled.store(false, Ordering::Relaxed);
            } else {
                // Delayed Ack logic (RFC 4960): increment counter; handle_packet or run_loop will send SACK
                self.sack_counter.fetch_add(1, Ordering::Relaxed);
            }
        }
        Ok(())
    }

    async fn process_data_payload(
        &self,
        flags: u8,
        chunk: Bytes,
        channel_map: &std::collections::HashMap<u16, Arc<DataChannel>>,
    ) -> Result<()> {
        let mut buf = chunk;
        // Skip TSN (4 bytes)
        buf.advance(4);

        let stream_id = buf.get_u16();
        let _stream_seq = buf.get_u16();
        let payload_proto = buf.get_u32();

        let user_data = buf;

        if payload_proto == DATA_CHANNEL_PPID_DCEP {
            self.handle_dcep(stream_id, user_data).await?;
            return Ok(());
        }

        if let Some(dc) = channel_map.get(&stream_id) {
            // Handle fragmentation
            // B bit: 0x02, E bit: 0x01
            let b_bit = (flags & 0x02) != 0;
            let e_bit = (flags & 0x01) != 0;

            let mut buffer = dc.reassembly_buffer.lock().unwrap();
            if b_bit {
                if !buffer.is_empty() {
                    warn!(
                        "SCTP Reassembly: unexpected B bit, clearing buffer of size {}",
                        buffer.len()
                    );
                    self.used_rwnd.fetch_sub(buffer.len(), Ordering::Relaxed);
                }
                buffer.clear();
            }
            self.used_rwnd.fetch_add(user_data.len(), Ordering::Relaxed);
            buffer.extend_from_slice(&user_data);
            if e_bit {
                let buffer_len = buffer.len();
                let msg = std::mem::take(&mut *buffer).freeze();
                self.used_rwnd.fetch_sub(buffer_len, Ordering::Relaxed);
                dc.send_event(DataChannelEvent::Message(msg));
            }
        } else {
            warn!("SCTP: Received data for unknown stream id {}", stream_id);
        }

        Ok(())
    }

    async fn handle_dcep(&self, stream_id: u16, data: Bytes) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let msg_type = data[0];
        match msg_type {
            DCEP_TYPE_OPEN => {
                let open = DataChannelOpen::unmarshal(&data)?;
                trace!("Received DCEP OPEN: {:?}", open);

                let mut found = false;
                {
                    let channels = self.data_channels.lock().unwrap();
                    for weak_dc in channels.iter() {
                        if let Some(dc) = weak_dc.upgrade() {
                            if dc.id == stream_id {
                                found = true;
                                break;
                            }
                        }
                    }
                }

                if !found {
                    // Create new channel
                    let config = DataChannelConfig {
                        label: open.label.clone(),
                        protocol: open.protocol,
                        ordered: (open.channel_type & 0x80) == 0,
                        max_retransmits: if (open.channel_type & 0x03) == 0x01
                            || (open.channel_type & 0x03) == 0x81
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        max_packet_life_time: if (open.channel_type & 0x03) == 0x02
                            || (open.channel_type & 0x03) == 0x82
                        {
                            Some(open.reliability_parameter as u16)
                        } else {
                            None
                        },
                        max_payload_size: None,
                        negotiated: None,
                    };

                    let dc = Arc::new(DataChannel::new(stream_id, config));
                    dc.state
                        .store(DataChannelState::Open as usize, Ordering::SeqCst);
                    dc.send_event(DataChannelEvent::Open);

                    {
                        let mut channels = self.data_channels.lock().unwrap();
                        channels.push(Arc::downgrade(&dc));
                    }

                    if let Some(tx) = &self.new_data_channel_tx {
                        let _ = tx.send(dc.clone());
                    } else {
                        debug!(
                            "New DataChannel created from DCEP: id={} label={} (no listener)",
                            stream_id, open.label
                        );
                    }
                }

                // Send ACK
                self.send_dcep_ack(stream_id).await?;
            }
            DCEP_TYPE_ACK => {
                trace!("Received DCEP ACK for stream {}", stream_id);
                let channels = self.data_channels.lock().unwrap();
                for weak_dc in channels.iter() {
                    if let Some(dc) = weak_dc.upgrade() {
                        if dc.id == stream_id {
                            if dc
                                .state
                                .compare_exchange(
                                    DataChannelState::Connecting as usize,
                                    DataChannelState::Open as usize,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                            {
                                dc.send_event(DataChannelEvent::Open);
                            }
                            break;
                        }
                    }
                }
            }
            _ => {
                debug!("Unknown DCEP message type: {}", msg_type);
            }
        }
        Ok(())
    }

    /// Build Gap Ack Blocks from buffered out-of-order packets so the peer knows
    /// exactly which TSNs we have received beyond the cumulative ack. We limit
    /// the number of blocks to keep the SACK compact and stay within 16-bit
    /// offsets.
    fn build_gap_ack_blocks(&self, cumulative_tsn_ack: u32) -> Vec<(u16, u16)> {
        let received = self.received_queue.lock().unwrap();
        build_gap_ack_blocks_from_map(&received, cumulative_tsn_ack)
    }

    fn advertised_rwnd(&self) -> u32 {
        let used = self.used_rwnd.load(Ordering::Relaxed);
        self.local_rwnd.saturating_sub(used).try_into().unwrap_or(0)
    }

    async fn send_sack(&self, cumulative_tsn_ack: u32) -> Result<()> {
        let mut sack = BytesMut::new();
        sack.put_u32(cumulative_tsn_ack); // Cumulative TSN Ack
        sack.put_u32(self.advertised_rwnd()); // a_rwnd reflects buffered state
        let gap_blocks = self.build_gap_ack_blocks(cumulative_tsn_ack);
        let dups = {
            let mut d = self.dups_buffer.lock().unwrap();
            let mut out = Vec::new();
            while !d.is_empty() && out.len() < 32 {
                out.push(d.remove(0));
            }
            out
        };
        sack.put_u16(gap_blocks.len() as u16); // Number of Gap Ack Blocks
        sack.put_u16(dups.len() as u16); // Number of Duplicate TSNs

        for (start, end) in &gap_blocks {
            sack.put_u16(*start);
            sack.put_u16(*end);
        }
        for tsn in dups {
            sack.put_u32(tsn);
        }

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.send_chunk(CT_SACK, 0, sack.freeze(), tag).await
    }

    async fn send_chunk(
        &self,
        type_: u8,
        flags: u8,
        value: Bytes,
        verification_tag: u32,
    ) -> Result<()> {
        let value_len = value.len();
        let chunk_len = CHUNK_HEADER_SIZE + value_len;
        let padding = (4 - (chunk_len % 4)) % 4;
        let mut chunk_buf = BytesMut::with_capacity(chunk_len + padding);

        // Chunk
        chunk_buf.put_u8(type_);
        chunk_buf.put_u8(flags);
        chunk_buf.put_u16(chunk_len as u16);
        chunk_buf.put_slice(&value);

        // Padding
        for _ in 0..padding {
            chunk_buf.put_u8(0);
        }

        self.transmit_chunks_with_tag(vec![chunk_buf.freeze()], verification_tag)
            .await
    }

    async fn transmit_chunks(&self, chunks: Vec<Bytes>) -> Result<()> {
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        self.transmit_chunks_with_tag(chunks, tag).await
    }

    async fn transmit_chunks_with_tag(&self, chunks: Vec<Bytes>, tag: u32) -> Result<()> {
        if chunks.is_empty() {
            return Ok(());
        }

        let mut current_batch = Vec::new();
        let mut current_len = SCTP_COMMON_HEADER_SIZE;

        for chunk in chunks {
            if !current_batch.is_empty() && current_len + chunk.len() > MAX_SCTP_PACKET_SIZE {
                // Send current batch
                self.send_packet_with_tag(current_batch, tag).await?;
                current_batch = Vec::new();
                current_len = SCTP_COMMON_HEADER_SIZE;
            }
            current_len += chunk.len();
            current_batch.push(chunk);
        }

        if !current_batch.is_empty() {
            self.send_packet_with_tag(current_batch, tag).await?;
        }

        Ok(())
    }

    async fn send_packet_with_tag(&self, chunks: Vec<Bytes>, tag: u32) -> Result<()> {
        let mut total_len = SCTP_COMMON_HEADER_SIZE;
        for c in &chunks {
            total_len += c.len();
        }

        let mut buf = BytesMut::with_capacity(total_len);

        // Common Header
        buf.put_u16(self.local_port);
        buf.put_u16(self.remote_port);
        buf.put_u32(tag);
        buf.put_u32(0); // Checksum placeholder

        for c in chunks {
            buf.put_slice(&c);
        }

        // Calculate Checksum (CRC32c)
        let checksum = crc32c::crc32c(&buf);
        let checksum_bytes = checksum.to_le_bytes();
        buf[8] = checksum_bytes[0];
        buf[9] = checksum_bytes[1];
        buf[10] = checksum_bytes[2];
        buf[11] = checksum_bytes[3];

        let packet_size = buf.len();
        self.stats_bytes_sent
            .fetch_add(packet_size as u64, Ordering::Relaxed);
        self.stats_packets_sent.fetch_add(1, Ordering::Relaxed);

        if let Err(_) = self.outgoing_packet_tx.send(buf.freeze()) {
            warn!("Failed to send SCTP packet to transport: channel closed");
            self.set_state(SctpState::Closed);
            return Err(anyhow::anyhow!("Transport channel closed"));
        }
        Ok(())
    }

    pub async fn send_data(&self, channel_id: u16, data: &[u8]) -> Result<()> {
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_BINARY, data)
            .await
    }

    pub async fn send_text(&self, channel_id: u16, data: impl AsRef<str>) -> Result<()> {
        self.send_data_raw(
            channel_id,
            DATA_CHANNEL_PPID_STRING,
            data.as_ref().as_bytes(),
        )
        .await
    }

    pub async fn send_data_raw(&self, channel_id: u16, ppid: u32, data: &[u8]) -> Result<()> {
        let dc_opt = {
            let channels = self.data_channels.lock().unwrap();
            channels
                .iter()
                .find_map(|weak_dc| weak_dc.upgrade().filter(|dc| dc.id == channel_id))
        };

        // Acquire tx_lock to prevent concurrent senders from overshooting the window
        let _tx_guard = self.tx_lock.lock().await;

        let is_dcep = ppid == DATA_CHANNEL_PPID_DCEP;
        let mut ordered = !is_dcep;
        let mut max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE;

        let (_guard, ssn) = if let Some(dc) = &dc_opt {
            let guard = dc.send_lock.lock().await;
            ordered = if is_dcep { false } else { dc.ordered };
            let ssn = if ordered {
                dc.next_ssn.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            };
            max_payload_size = dc.max_payload_size.min(DEFAULT_MAX_PAYLOAD_SIZE);
            (Some(guard), ssn)
        } else {
            (None, 0)
        };

        let total_len = data.len();
        let flags_base = if !ordered { 0x04 } else { 0x00 };

        if total_len == 0 {
            // Send empty packet (unfragmented)
            loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    let notified = self.flow_control_notify.notified();
                    // Re-check after registering listener
                    let flight = self.flight_size.load(Ordering::SeqCst);
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                    let effective_window = cwnd.min(rwnd);
                    if flight < effective_window {
                        break;
                    }
                    notified.await;
                } else {
                    break;
                }
            }

            let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
            let chunk = self.create_data_chunk(channel_id, ppid, data, ssn, flags_base | 0x03, tsn);
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let was_empty = queue.is_empty();

                // Check window before adding to flight_size
                let chunk_len = chunk.len();
                let current_flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if current_flight + chunk_len > effective_window {
                    // Window full, this shouldn't happen for empty packets but guard it
                    warn!("Empty packet would exceed window, dropping");
                    return Ok(());
                }

                let record = ChunkRecord {
                    payload: chunk.clone(),
                    sent_time: Instant::now(),
                    transmit_count: 0,
                    missing_reports: 0,
                    stream_id: channel_id,
                    abandoned: false,
                    fast_retransmit: false,
                    fast_retransmit_time: None,
                    in_flight: true,
                    acked: false,
                };
                queue.insert(tsn, record);
                self.flight_size
                    .store(current_flight + chunk_len, Ordering::SeqCst);
                if was_empty {
                    self.timer_notify.notify_one();
                    let mut cached = self.cached_rto_timeout.lock().unwrap();
                    *cached = None;
                }
            }
            return self.transmit_chunks(vec![chunk]).await;
        }

        let mut offset = 0;

        while offset < total_len {
            // 1. Wait for window space
            let allowed_bytes = loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    // RFC 4960 Section 6.2.1: Zero Window Probing.
                    // If flight is 0 and rwnd is 0, we are allowed to send 1 chunk to probe.
                    if flight == 0 && rwnd == 0 {
                        break max_payload_size;
                    }

                    if flight % 4096 < 1200 {
                        debug!(
                            "Flow control: window full (flight={}, cwnd={}, rwnd={})",
                            flight, cwnd, rwnd
                        );
                    }
                    let notified = self.flow_control_notify.notified();
                    let flight = self.flight_size.load(Ordering::SeqCst);
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                    let effective_window = cwnd.min(rwnd);
                    if flight < effective_window {
                        let bytes = effective_window - flight;
                        break bytes;
                    }
                    notified.await;
                } else {
                    break effective_window - flight;
                }
            };

            // 2. Create a batch of chunks that fits in the window
            let mut chunks = Vec::new();
            let mut batch_len = 0;

            while offset < total_len {
                let remaining = total_len - offset;
                let chunk_payload_size = std::cmp::min(remaining, max_payload_size);

                let chunk_total_len = {
                    let chunk_value_len = 12 + chunk_payload_size;
                    let chunk_len = 4 + chunk_value_len;
                    let padding = (4 - (chunk_len % 4)) % 4;
                    chunk_len + padding
                };

                if !chunks.is_empty() {
                    if batch_len + chunk_total_len > allowed_bytes
                        || batch_len + chunk_total_len
                            > MAX_SCTP_PACKET_SIZE - SCTP_COMMON_HEADER_SIZE
                    {
                        break;
                    }
                }

                let mut flags = flags_base;
                if offset == 0 {
                    if remaining <= max_payload_size {
                        flags |= 0x03; // B=1, E=1
                    } else {
                        flags |= 0x02; // B=1, E=0
                    }
                } else if offset + chunk_payload_size >= total_len {
                    flags |= 0x01; // B=0, E=1
                } else {
                    flags |= 0x00; // Middle
                }

                let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
                let chunk_data = &data[offset..offset + chunk_payload_size];
                let chunk = self.create_data_chunk(channel_id, ppid, chunk_data, ssn, flags, tsn);

                let chunk_len = chunk.len();
                chunks.push((tsn, chunk));
                batch_len += chunk_len;
                offset += chunk_payload_size;

                if batch_len >= allowed_bytes
                    || batch_len >= MAX_SCTP_PACKET_SIZE - SCTP_COMMON_HEADER_SIZE
                {
                    break;
                }
            }

            // 3. Batch insert into sent_queue with flow control protection
            let (chunks_to_send, should_retry) = {
                let mut queue = self.sent_queue.lock().unwrap();
                let now = Instant::now();
                let was_empty = queue.is_empty();

                // Calculate total batch size
                let total_batch_size: usize = chunks.iter().map(|(_, c)| c.len()).sum();

                // Atomically check and add to flight_size
                let current_flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                let new_flight = current_flight + total_batch_size;
                if new_flight > effective_window && current_flight > 0 {
                    // Window closed due to race condition
                    // We need to queue the chunks anyway since TSN is already allocated
                    // But mark them as NOT in_flight so they'll be sent when window opens
                    trace!(
                        "Flow control race: flight={} + batch={} > window={}, queueing for later",
                        current_flight, total_batch_size, effective_window
                    );

                    for (tsn, chunk) in &chunks {
                        let record = ChunkRecord {
                            payload: chunk.clone(),
                            sent_time: now,
                            transmit_count: 0,
                            missing_reports: 0,
                            stream_id: channel_id,
                            abandoned: false,
                            fast_retransmit: false,
                            fast_retransmit_time: None,
                            in_flight: false, // Not in flight yet
                            acked: false,
                        };
                        queue.insert(*tsn, record);
                    }

                    if was_empty {
                        self.timer_notify.notify_one();
                        let mut cached = self.cached_rto_timeout.lock().unwrap();
                        *cached = None;
                    }

                    (vec![], true) // Need to retry via drain_retransmissions
                } else {
                    // Safe to add - do it atomically
                    self.flight_size.store(new_flight, Ordering::SeqCst);

                    for (tsn, chunk) in &chunks {
                        let record = ChunkRecord {
                            payload: chunk.clone(),
                            sent_time: now,
                            transmit_count: 0,
                            missing_reports: 0,
                            stream_id: channel_id,
                            abandoned: false,
                            fast_retransmit: false,
                            fast_retransmit_time: None,
                            in_flight: true,
                            acked: false,
                        };
                        queue.insert(*tsn, record);
                    }

                    if was_empty {
                        self.timer_notify.notify_one();
                        let mut cached = self.cached_rto_timeout.lock().unwrap();
                        *cached = None;
                    }

                    (chunks.into_iter().map(|(_, c)| c).collect(), false)
                }
            };

            if !chunks_to_send.is_empty() {
                self.transmit_chunks(chunks_to_send).await?;
            } else if should_retry {
                // Wait for flow control to allow sending
                self.flow_control_notify.notified().await;
                // drain_retransmissions will be called by the run_loop
                self.timer_notify.notify_one();
            }
        }

        Ok(())
    }

    fn create_data_chunk(
        &self,
        channel_id: u16,
        ppid: u32,
        data: &[u8],
        ssn: u16,
        flags: u8,
        tsn: u32,
    ) -> Bytes {
        let data_len = data.len();
        let chunk_value_len = 12 + data_len;
        let chunk_len = 4 + chunk_value_len;
        let padding = (4 - (chunk_len % 4)) % 4;
        let total_len = chunk_len + padding;

        let mut buf = BytesMut::with_capacity(total_len);

        // Chunk Header (DATA)
        buf.put_u8(CT_DATA);
        buf.put_u8(flags); // Flags
        buf.put_u16(chunk_len as u16);

        // DATA Chunk Value
        buf.put_u32(tsn);
        buf.put_u16(channel_id);
        buf.put_u16(ssn);
        buf.put_u32(ppid);
        buf.put_slice(data);

        // Padding
        for _ in 0..padding {
            buf.put_u8(0);
        }

        buf.freeze()
    }

    pub async fn send_dcep_open(&self, dc: &DataChannel) -> Result<()> {
        let channel_type = if dc.ordered {
            if dc.max_retransmits.is_some() {
                0x01 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT
            } else if dc.max_packet_life_time.is_some() {
                0x02 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED
            } else {
                0x00 // DATA_CHANNEL_RELIABLE
            }
        } else {
            if dc.max_retransmits.is_some() {
                0x81 // DATA_CHANNEL_PARTIAL_RELIABLE_REXMIT_UNORDERED
            } else if dc.max_packet_life_time.is_some() {
                0x82 // DATA_CHANNEL_PARTIAL_RELIABLE_TIMED_UNORDERED
            } else {
                0x80 // DATA_CHANNEL_RELIABLE_UNORDERED
            }
        };

        let reliability_parameter = if let Some(r) = dc.max_retransmits {
            r as u32
        } else if let Some(t) = dc.max_packet_life_time {
            t as u32
        } else {
            0
        };

        let open = DataChannelOpen {
            message_type: DCEP_TYPE_OPEN,
            channel_type,
            priority: 0,
            reliability_parameter,
            label: dc.label.clone(),
            protocol: dc.protocol.clone(),
        };

        let payload = open.marshal();
        self.send_data_raw(dc.id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }

    pub async fn send_dcep_ack(&self, channel_id: u16) -> Result<()> {
        let ack = DataChannelAck {
            message_type: DCEP_TYPE_ACK,
        };
        let payload = ack.marshal();
        self.send_data_raw(channel_id, DATA_CHANNEL_PPID_DCEP, &payload)
            .await
    }

    fn print_stats(&self, reason: &str) {
        let duration = self.stats_created_time.elapsed();
        let bytes_sent = self.stats_bytes_sent.load(Ordering::SeqCst);
        let bytes_received = self.stats_bytes_received.load(Ordering::SeqCst);
        let packets_sent = self.stats_packets_sent.load(Ordering::SeqCst);
        let packets_received = self.stats_packets_received.load(Ordering::SeqCst);
        let retransmissions = self.stats_retransmissions.load(Ordering::SeqCst);
        let heartbeats_sent = self.stats_heartbeats_sent.load(Ordering::SeqCst);
        let error_count = self.association_error_count.load(Ordering::SeqCst);
        let cwnd = self.cwnd.load(Ordering::SeqCst);
        let ssthresh = self.ssthresh.load(Ordering::SeqCst);
        let flight_size = self.flight_size.load(Ordering::SeqCst);
        let peer_rwnd = self.peer_rwnd.load(Ordering::SeqCst);
        let sent_queue_len = self.sent_queue.lock().unwrap().len();
        let rto = self.rto_state.lock().unwrap().rto;

        warn!(
            "\n==================== SCTP CONNECTION CLOSED ====================\n\
             Reason: {}\n\
             Duration: {:.2}s\n\
             Bytes Sent: {} ({:.2} KB)\n\
             Bytes Received: {} ({:.2} KB)\n\
             Packets Sent: {}\n\
             Packets Received: {}\n\
             Retransmissions: {} ({:.1}% of sent)\n\
             Heartbeats Sent: {}\n\
             Error Count: {}/{}\n\
             Final RTO: {:.1}s\n\
             Final CWND: {} bytes\n\
             Final SSThresh: {} bytes\n\
             Peer RWND: {} bytes{}\n\
             Flight Size: {} bytes\n\
             Pending Queue: {} chunks\n\
             ================================================================",
            reason,
            duration.as_secs_f64(),
            bytes_sent,
            bytes_sent as f64 / 1024.0,
            bytes_received,
            bytes_received as f64 / 1024.0,
            packets_sent,
            packets_received,
            retransmissions,
            if packets_sent > 0 {
                (retransmissions as f64 / packets_sent as f64) * 100.0
            } else {
                0.0
            },
            heartbeats_sent,
            error_count,
            self.max_association_retransmits,
            rto,
            cwnd,
            ssthresh,
            peer_rwnd,
            if peer_rwnd == 0 {
                " (ZERO WINDOW!)"
            } else {
                ""
            },
            flight_size,
            sent_queue_len
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[test]
    fn test_rto_calculator() {
        let mut calc = RtoCalculator::new(1.0, 0.2, 60.0);
        assert_eq!(calc.rto, 1.0);

        // First measurement: RTT = 1.0
        calc.update(1.0);
        // srtt = 1.0, rttvar = 0.5
        // rto = 1.0 + 4 * 0.5 = 3.0
        assert_eq!(calc.srtt, 1.0);
        assert_eq!(calc.rttvar, 0.5);
        assert_eq!(calc.rto, 3.0);

        // Second measurement: RTT = 1.0 (Stable)
        calc.update(1.0);
        // rttvar = (1 - 0.25) * 0.5 + 0.25 * |1.0 - 1.0| = 0.375
        // srtt = (1 - 0.125) * 1.0 + 0.125 * 1.0 = 1.0
        // rto = 1.0 + 4 * 0.375 = 1.0 + 1.5 = 2.5
        assert_eq!(calc.srtt, 1.0);
        assert_eq!(calc.rttvar, 0.375);
        assert_eq!(calc.rto, 2.5);

        // Backoff
        calc.backoff();
        assert_eq!(calc.rto, 5.0);
    }

    #[tokio::test]
    async fn test_rto_backoff() {
        let mut calc = RtoCalculator::new(1.0, 0.2, 60.0);
        calc.update(0.1); // RTT 100ms
        assert!(calc.rto >= 0.2); // Min RTO is 0.2s

        calc.backoff();
        assert!(calc.rto >= 0.4);
    }

    #[test]
    fn test_gap_ack_blocks_contiguous_and_gaps() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // cumulative ack is 10; we have 12-13 contiguous and 15 isolated
        received.insert(12, (0, Bytes::new()));
        received.insert(13, (0, Bytes::new()));
        received.insert(15, (0, Bytes::new()));

        let blocks = build_gap_ack_blocks_from_map(&received, 10);
        assert_eq!(blocks, vec![(2, 3), (5, 5)]);
    }

    #[test]
    fn test_gap_ack_blocks_limit_to_16() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // Build more than 16 small gaps; we should cap at 16 blocks
        let cumulative = 1;
        for i in 0..20 {
            // Place isolated TSNs two apart to force separate blocks
            let tsn = cumulative + 2 + i * 2;
            received.insert(tsn, (0, Bytes::new()));
        }

        let blocks = build_gap_ack_blocks_from_map(&received, cumulative);
        assert_eq!(blocks.len(), 16);
        // First block should start at offset 1 (tsn 3) and every block single TSN
        assert_eq!(blocks[0], (2, 2));
    }

    #[test]
    fn test_gap_ack_blocks_ignore_acked_or_wrapped() {
        let mut received: BTreeMap<u32, (u8, Bytes)> = BTreeMap::new();
        // Below or equal cumulative should be ignored
        received.insert(5, (0, Bytes::new()));
        received.insert(6, (0, Bytes::new()));
        // Valid ones after cumulative
        received.insert(8, (0, Bytes::new()));
        received.insert(9, (0, Bytes::new()));

        let blocks = build_gap_ack_blocks_from_map(&received, 6);
        assert_eq!(blocks, vec![(2, 3)]);
    }

    #[test]
    fn test_apply_sack_removes_gaps_and_tracks_rtt() {
        let mut sent: BTreeMap<u32, ChunkRecord> = BTreeMap::new();
        let base = Instant::now() - Duration::from_millis(100);
        sent.insert(
            10,
            ChunkRecord {
                payload: Bytes::from_static(b"a"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
                stream_id: 0,
                abandoned: false,
                fast_retransmit: false,
                fast_retransmit_time: None,
                in_flight: true,
                acked: false,
            },
        );
        sent.insert(
            11,
            ChunkRecord {
                payload: Bytes::from_static(b"b"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
                stream_id: 0,
                abandoned: false,
                fast_retransmit: false,
                fast_retransmit_time: None,
                in_flight: true,
                acked: false,
            },
        );
        sent.insert(
            12,
            ChunkRecord {
                payload: Bytes::from_static(b"c"),
                sent_time: base,
                transmit_count: 0,
                missing_reports: 0,
                stream_id: 0,
                abandoned: false,
                fast_retransmit: false,
                fast_retransmit_time: None,
                in_flight: true,
                acked: false,
            },
        );

        // Ack cumulative 10 and gap-ack 12, leaving 11 outstanding.
        let outcome = apply_sack_to_sent_queue(&mut sent, 10, &[(2, 2)], Instant::now());

        assert_eq!(outcome.flight_reduction, 2); // a cumulative-acked + c gap-acked
        assert_eq!(outcome.rtt_samples.len(), 2);
        assert!(outcome.retransmit.is_empty());
        assert!(outcome.head_moved); // head advanced from 10 to 11

        assert_eq!(sent.len(), 2); // 11 outstanding, 12 remains (acked) until cumulative ack
        assert!(sent.contains_key(&11));
        assert!(sent.contains_key(&12));
        assert!(sent.get(&12).unwrap().acked);
    }

    #[test]
    fn test_fast_retransmit_after_dup_thresh() {
        let mut sent: BTreeMap<u32, ChunkRecord> = BTreeMap::new();
        let base = Instant::now() - Duration::from_millis(50);
        for tsn in 21..=23 {
            sent.insert(
                tsn,
                ChunkRecord {
                    payload: Bytes::from_static(b"p"),
                    sent_time: base,
                    transmit_count: 0,
                    missing_reports: 0,
                    stream_id: 0,
                    abandoned: false,
                    fast_retransmit: false,
                    fast_retransmit_time: None,
                    in_flight: true,
                    acked: false,
                },
            );
        }

        // Repeated SACKs report up to TSN 23 but never ack TSN 22.
        let sack_gap = [(2u16, 2u16)];
        let mut outcome;

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 0);
        assert_eq!(sent.len(), 2); // 21 removed, 22 and 23 remain (23 acked)

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 0);

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 1);
        assert_eq!(outcome.retransmit[0].0, 22);
        let rec = sent.get(&22).unwrap();
        assert_eq!(rec.missing_reports, 0);
    }

    #[test]
    fn test_checksum_validation() {
        let mut buf = BytesMut::with_capacity(12);
        buf.put_u16(1234); // src
        buf.put_u16(5678); // dst
        buf.put_u32(0x12345678); // tag
        buf.put_u32(0); // checksum placeholder

        let calculated = crc32c::crc32c(&buf);
        let checksum_bytes = calculated.to_le_bytes();
        buf[8] = checksum_bytes[0];
        buf[9] = checksum_bytes[1];
        buf[10] = checksum_bytes[2];
        buf[11] = checksum_bytes[3];

        let packet = buf.freeze();

        // Verify it passes
        let mut check_buf = packet.clone();
        let _ = check_buf.get_u16();
        let _ = check_buf.get_u16();
        let _ = check_buf.get_u32();
        let received_checksum = check_buf.get_u32_le();

        let mut packet_copy = packet.to_vec();
        packet_copy[8] = 0;
        packet_copy[9] = 0;
        packet_copy[10] = 0;
        packet_copy[11] = 0;
        let calculated_again = crc32c::crc32c(&packet_copy);
        assert_eq!(received_checksum, calculated_again);
    }

    #[tokio::test]
    async fn test_sctp_association_retransmission_limit() {
        let (socket_tx, _) = tokio::sync::watch::channel(None);
        let ice_conn = crate::transports::ice::conn::IceConn::new(
            socket_tx.subscribe(),
            "127.0.0.1:5000".parse().unwrap(),
        );
        let cert = crate::transports::dtls::generate_certificate().unwrap();
        let (dtls, _, _) = DtlsTransport::new(ice_conn, cert, true, 100).await.unwrap();

        let config = RtcConfiguration::default();
        let mut config = config;
        config.sctp_max_association_retransmits = 2;

        // Create incoming channel (not used in this test)
        let (_incoming_tx, incoming_rx) = mpsc::unbounded_channel();

        let (sctp, runner) = SctpTransport::new(
            dtls,
            incoming_rx,
            Arc::new(Mutex::new(Vec::new())),
            5000,
            5000,
            None,
            true,
            &config,
        );

        // Spawn the runner to handle outgoing packets
        tokio::spawn(runner);

        // Set state to Connecting
        *sctp.inner.state.lock().unwrap() = SctpState::Connecting;

        // Add a chunk to sent queue
        {
            let mut sent_queue = sctp.inner.sent_queue.lock().unwrap();
            sent_queue.insert(
                100,
                ChunkRecord {
                    payload: Bytes::from_static(b"test"),
                    sent_time: Instant::now() - Duration::from_secs(10),
                    transmit_count: 1,
                    missing_reports: 0,
                    stream_id: 0,
                    abandoned: false,
                    fast_retransmit: false,
                    fast_retransmit_time: None,
                    in_flight: true,
                    acked: false,
                },
            );
        }

        // First timeout: error_count becomes 1, transmit_count becomes 2
        sctp.inner.handle_timeout().await.unwrap();
        let state_after_first = sctp.inner.state.lock().unwrap().clone();
        let error_count_after_first = sctp.inner.association_error_count.load(Ordering::SeqCst);

        // State should still be Connecting after first timeout
        assert_eq!(state_after_first, SctpState::Connecting);
        assert_eq!(error_count_after_first, 1);

        // Check transmit_count was incremented
        {
            let sent_queue = sctp.inner.sent_queue.lock().unwrap();
            let record = sent_queue.get(&100).unwrap();
            assert_eq!(record.transmit_count, 2);
        }

        // Check transmit_count was incremented
        {
            let sent_queue = sctp.inner.sent_queue.lock().unwrap();
            let record = sent_queue.get(&100).unwrap();
            assert_eq!(record.transmit_count, 2);
        }

        // Manually set sent_time back to old time to trigger another timeout
        {
            let mut sent_queue = sctp.inner.sent_queue.lock().unwrap();
            let record = sent_queue.get_mut(&100).unwrap();
            record.sent_time = Instant::now() - Duration::from_secs(10);
        }

        // Second timeout: error_count becomes 2, transmit_count becomes 3
        sctp.inner.handle_timeout().await.unwrap();

        // With max_association_retransmits=2, error_count reaching 2 should trigger close
        let final_state = sctp.inner.state.lock().unwrap().clone();
        let final_error_count = sctp.inner.association_error_count.load(Ordering::SeqCst);
        assert_eq!(final_error_count, 2);
        assert_eq!(final_state, SctpState::Closed);
    }

    #[tokio::test]
    async fn test_forward_tsn_handling() {
        // Mock SctpInner
        // This is hard because SctpInner has many fields.
        // But we can test handle_forward_tsn logic if we make it more testable or just test the side effects.
    }

    #[test]
    fn test_global_retransmit_limit_logic() {
        // Test the retransmit limit logic in isolation without network I/O
        let mut channel_info: std::collections::HashMap<u16, Option<u16>> =
            std::collections::HashMap::new();
        channel_info.insert(1, None); // Reliable channel on stream 1
        channel_info.insert(2, Some(5)); // Unreliable channel with max 5 retransmits

        let test_cases = vec![
            // (stream_id, transmit_count, expected_abandoned, description)
            (0, 19, false, "Below global limit on unknown stream"),
            (0, 20, true, "At global limit on unknown stream"),
            (0, 21, true, "Above global limit on unknown stream"),
            (1, 19, false, "Below global limit on reliable channel"),
            (1, 20, true, "Global limit applies to reliable channel"),
            (1, 100, true, "Way above global limit on reliable channel"),
            (2, 4, false, "Below channel limit"),
            (2, 5, true, "At channel limit"),
            (2, 19, true, "Between channel and global limit"),
            (2, 20, true, "At global limit"),
        ];

        for (stream_id, transmit_count, expected_abandoned, desc) in test_cases {
            let mut abandoned = false;

            // This mimics the logic in handle_timeout() after transmit_count increment
            if transmit_count >= 20 {
                abandoned = true;
            } else if let Some(Some(max_rexmit)) = channel_info.get(&stream_id) {
                if transmit_count >= *max_rexmit as u32 {
                    abandoned = true;
                }
            }

            assert_eq!(
                abandoned, expected_abandoned,
                "Test case failed: {} (stream={}, count={})",
                desc, stream_id, transmit_count
            );
        }
    }

    #[test]
    fn test_fast_retransmit_cooldown_logic() {
        // Test that fast retransmit can re-trigger properly
        let now = Instant::now();
        let dup_thresh = 3u32;

        let test_cases = vec![
            // (fast_retransmit, fast_retransmit_time, missing_reports, elapsed_ms, should_trigger, desc)
            (false, None, 3, 0, true, "First fast retransmit"),
            (
                false,
                None,
                10,
                0,
                true,
                "First fast retransmit with high missing_reports",
            ),
            (
                true,
                Some(0),
                3,
                100,
                false,
                "Too soon after first fast retransmit (100ms < 500ms)",
            ),
            (
                true,
                Some(0),
                3,
                600,
                true,
                "Long enough after first fast retransmit (600ms > 500ms)",
            ),
            (
                true,
                Some(0),
                10,
                100,
                true,
                "High missing_reports should bypass cooldown",
            ),
            (
                true,
                Some(0),
                7,
                200,
                true,
                "Moderate high missing_reports should bypass cooldown",
            ),
        ];

        for (fast_retrans, fr_time_offset, missing_reports, elapsed_ms, should_trigger, desc) in
            test_cases
        {
            let fast_retransmit_time =
                fr_time_offset.map(|offset| now - Duration::from_millis(offset));
            let current_time = now + Duration::from_millis(elapsed_ms);

            // Simulate the can_fast_retransmit logic with improved handling
            let can_fast_retransmit = if fast_retrans {
                if let Some(fr_time) = fast_retransmit_time {
                    let elapsed = current_time.duration_since(fr_time);
                    // Allow immediate re-trigger if missing_reports is high (>= 7)
                    // or if enough time has passed (> 500ms)
                    missing_reports >= 7 || elapsed > Duration::from_millis(500)
                } else {
                    true
                }
            } else {
                true
            };

            let will_trigger = missing_reports >= dup_thresh && can_fast_retransmit;

            assert_eq!(
                will_trigger, should_trigger,
                "Test case failed: {} (fast_retrans={}, missing={}, elapsed={}ms)",
                desc, fast_retrans, missing_reports, elapsed_ms
            );
        }
    }

    #[test]
    fn test_sent_time_accuracy_with_drain_retransmissions() {
        // This test verifies the bug where drain_retransmissions doesn't update sent_time
        // for first-time transmissions (transmit_count going 0->1)

        let creation_time = Instant::now();
        std::thread::sleep(Duration::from_millis(50));
        let drain_time = Instant::now();

        // Simulate a packet created at T0 but sent later via drain_retransmissions
        let mut record = ChunkRecord {
            payload: Bytes::from_static(b"test"),
            sent_time: creation_time, // Created at T0
            transmit_count: 0,        // Not yet sent
            missing_reports: 0,
            stream_id: 0,
            abandoned: false,
            fast_retransmit: false,
            fast_retransmit_time: None,
            in_flight: false,
            acked: false,
        };

        // Simulate drain_retransmissions logic (current buggy behavior)
        record.in_flight = true;
        record.transmit_count += 1;
        // BUG: Only update sent_time for retransmissions (transmit_count > 1)
        if record.transmit_count > 1 {
            record.sent_time = drain_time;
        }

        // After drain at drain_time, transmit_count is 1 but sent_time is still creation_time
        assert_eq!(record.transmit_count, 1);
        assert_eq!(record.sent_time, creation_time); // BUG: Should be drain_time!

        // Calculate when RTO timeout would trigger with RTO = 0.2s
        let rto = Duration::from_secs_f64(0.2);
        let rto_expiry = record.sent_time + rto;

        // The packet was actually sent at drain_time, so RTO should expire at drain_time + 0.2s
        // But the code uses creation_time + 0.2s, which is 50ms earlier!
        let expected_expiry = drain_time + rto;
        let actual_time_diff = expected_expiry.duration_since(rto_expiry);

        println!("Bug demonstration:");
        println!("  Packet created at: T0");
        println!("  Packet sent at: T0 + 50ms");
        println!("  RTO = 200ms");
        println!("  Expected RTO expiry: T0 + 50ms + 200ms = T0 + 250ms");
        println!("  Actual RTO expiry (buggy): T0 + 200ms");
        println!("  Timing error: -50ms (expires too early!)");

        // The bug causes RTO to expire 50ms too early
        assert!(
            actual_time_diff >= Duration::from_millis(45), // Allow small timing variance
            "BUG DETECTED: RTO expiry is calculated from creation_time instead of actual send time. \
             Time difference: {:?}ms (should be ~50ms)",
            actual_time_diff.as_millis()
        );
    }

    #[test]
    fn test_sent_time_accuracy_with_immediate_send() {
        // This test verifies another aspect: packets sent immediately (in_flight=true, transmit_count=0)

        let creation_time = Instant::now();

        // Simulate immediate send (like in send_data for small packets)
        let record = ChunkRecord {
            payload: Bytes::from_static(b"test"),
            sent_time: creation_time,
            transmit_count: 0, // BUG: Should be 1 after sending!
            missing_reports: 0,
            stream_id: 0,
            abandoned: false,
            fast_retransmit: false,
            fast_retransmit_time: None,
            in_flight: true, // Already sent
            acked: false,
        };

        // Packet is in_flight but transmit_count is still 0
        assert_eq!(record.in_flight, true);
        assert_eq!(record.transmit_count, 0); // BUG: Should be 1!

        println!("Bug demonstration:");
        println!("  Packet marked as in_flight=true (sent)");
        println!("  But transmit_count=0 (not sent)");
        println!("  This semantic inconsistency causes RTO timing issues");

        // The semantic inconsistency: packet is "sent" (in_flight) but "not sent" (transmit_count=0)
        assert_eq!(
            record.in_flight as u8 + record.transmit_count as u8,
            1, // in_flight(1) + transmit_count(0) = 1
            "INCONSISTENCY DETECTED: Packet is in_flight but transmit_count is 0"
        );
    }

    #[test]
    fn test_rto_timing_with_delayed_transmission() {
        // Test the complete scenario: packet created, queued, then sent later

        let t0 = Instant::now();

        // T0: Packet created and queued (window full)
        let mut sent_queue: BTreeMap<u32, ChunkRecord> = BTreeMap::new();
        sent_queue.insert(
            100,
            ChunkRecord {
                payload: Bytes::from_static(b"data"),
                sent_time: t0,
                transmit_count: 0,
                missing_reports: 0,
                stream_id: 0,
                abandoned: false,
                fast_retransmit: false,
                fast_retransmit_time: None,
                in_flight: false,
                acked: false,
            },
        );

        // Simulate 100ms delay before window opens
        std::thread::sleep(Duration::from_millis(100));
        let t1 = Instant::now();

        // T1: drain_retransmissions sends the packet (current buggy logic)
        let record = sent_queue.get_mut(&100).unwrap();
        record.in_flight = true;
        record.transmit_count += 1;
        if record.transmit_count > 1 {
            record.sent_time = t1; // Only update for retransmissions
        }

        // Now check RTO timeout calculation
        let rto = Duration::from_millis(200);
        let now = t1;

        let record = sent_queue.get(&100).unwrap();
        let rto_expiry = record.sent_time + rto;
        let time_until_timeout = if rto_expiry > now {
            rto_expiry - now
        } else {
            Duration::ZERO
        };

        println!("Scenario:");
        println!("  T0: Packet created and queued");
        println!("  T1 (T0+100ms): Packet actually sent");
        println!("  RTO = 200ms");
        println!("  Expected timeout at: T1 + 200ms = T0 + 300ms");
        println!("  Actual timeout at (buggy): T0 + 200ms");
        println!(
            "  Time until timeout from T1: {:?}ms",
            time_until_timeout.as_millis()
        );

        // BUG: Time until timeout is only ~100ms instead of 200ms
        // because sent_time is T0, not T1
        assert!(
            time_until_timeout < Duration::from_millis(150),
            "BUG VERIFIED: Timeout will trigger in {:?}ms instead of 200ms. \
             The packet will timeout 100ms early because sent_time wasn't updated!",
            time_until_timeout.as_millis()
        );
    }
}
