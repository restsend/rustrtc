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
use tracing::{debug, info, trace, warn};

// RTO Constants (RFC 4960)
const RTO_INITIAL: f64 = 1.0;
const RTO_MIN: f64 = 0.1; // Lower RTO_MIN for faster recovery in high-speed networks
const RTO_MAX: f64 = 60.0;
const RTO_ALPHA: f64 = 0.125;
const RTO_BETA: f64 = 0.25;

// Flow Control Constants
const CWND_INITIAL: usize = 1200 * 200; // Start with 200 MTUs for better performance
const MAX_BURST: usize = 20; // RFC 4960 Section 7.2.4

#[derive(Debug, Clone)]
struct ChunkRecord {
    payload: Bytes,
    sent_time: Instant,
    transmit_count: u32,
    missing_reports: u8,
    stream_id: u16,
    abandoned: bool,
    fast_retransmit: bool,
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
const MAX_SCTP_PACKET_SIZE: usize = 1400; // Increased for better throughput
const DEFAULT_MAX_PAYLOAD_SIZE: usize = 1372; // 1400 - 12 (common) - 16 (data header)
const LOCAL_RWND_BYTES: usize = 16 * 1024 * 1024;
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
}

impl RtoCalculator {
    fn new() -> Self {
        Self {
            srtt: 0.0,
            rttvar: 0.0,
            rto: RTO_INITIAL,
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
        self.rto = (self.srtt + 4.0 * self.rttvar).clamp(RTO_MIN, RTO_MAX);
    }

    fn backoff(&mut self) {
        self.rto = (self.rto * 2.0).min(RTO_MAX);
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

    // Fast Recovery
    fast_recovery_exit_tsn: AtomicU32,

    // Receiver Window Tracking
    used_rwnd: AtomicUsize,

    // Receiver Packet Counter (for Quick-Start ACKs)
    packets_received: AtomicU64,

    // Cached Timeout State
    cached_rto_timeout: Mutex<Option<(Instant, Duration)>>,
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
        if tsn <= cumulative_tsn_ack {
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

    let mut max_reported = cumulative_tsn_ack;
    for (_start, end) in gap_blocks {
        let block_end = cumulative_tsn_ack.wrapping_add(*end as u32);
        if block_end > max_reported {
            max_reported = block_end;
        }
    }

    let mut outcome = SackOutcome::default();
    outcome.max_reported = max_reported;

    // 1. Remove everything that the SACK explicitly acknowledges.
    // Since BTreeMap is ordered, we can efficiently remove all TSNs <= cumulative_tsn_ack.
    while let Some(&tsn) = sent_queue.keys().next() {
        if tsn.wrapping_sub(cumulative_tsn_ack) as i32 <= 0 {
            if let Some(record) = sent_queue.remove(&tsn) {
                let len = record.payload.len();
                outcome.flight_reduction += len;
                outcome.bytes_acked_by_cum_tsn += len;
                if record.transmit_count == 0 {
                    outcome
                        .rtt_samples
                        .push(now.duration_since(record.sent_time).as_secs_f64());
                }
            }
        } else {
            break;
        }
    }

    // 2. Handle Gap Ack Blocks
    for (start, end) in gap_blocks {
        let s = cumulative_tsn_ack.wrapping_add(*start as u32);
        let e = cumulative_tsn_ack.wrapping_add(*end as u32);

        // We only need to check TSNs in the range [s, e]
        let to_remove: Vec<u32> = sent_queue.range(s..=e).map(|(&tsn, _)| tsn).collect();

        for tsn in to_remove {
            if let Some(record) = sent_queue.remove(&tsn) {
                outcome.flight_reduction += record.payload.len();
                if record.transmit_count == 0 {
                    outcome
                        .rtt_samples
                        .push(now.duration_since(record.sent_time).as_secs_f64());
                }
            }
        }
    }

    // 3. Mark missing reports and schedule fast retransmits.
    // We only need to check TSNs up to max_reported.
    for (&tsn, record) in sent_queue.range_mut(..=max_reported) {
        // If it's in the queue and <= max_reported, it's missing (since we already removed gap-acked ones)
        record.missing_reports = record.missing_reports.saturating_add(1);

        if record.missing_reports >= DUP_THRESH && !record.abandoned && !record.fast_retransmit {
            record.missing_reports = 0;
            record.transmit_count += 1;
            record.sent_time = now;
            record.fast_retransmit = true;
            outcome.retransmit.push((tsn, record.payload.clone()));
        }
    }

    // Reset missing reports for anything beyond max_reported (optional but safer)
    // Actually, we don't need to iterate beyond max_reported.

    let after_head = sent_queue.keys().next().cloned();
    outcome.head_moved = before_head != after_head;

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
        incoming_data_rx: mpsc::Receiver<Bytes>,
        data_channels: Arc<Mutex<Vec<Weak<DataChannel>>>>,
        local_port: u16,
        remote_port: u16,
        new_data_channel_tx: Option<mpsc::UnboundedSender<Arc<DataChannel>>>,
        is_client: bool,
    ) -> (
        Arc<Self>,
        impl std::future::Future<Output = ()> + Send + 'static,
    ) {
        let inner = Arc::new(SctpInner {
            dtls_transport,
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
            rto_state: Mutex::new(RtoCalculator::new()),
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
            fast_recovery_exit_tsn: AtomicU32::new(0),
            used_rwnd: AtomicUsize::new(0),
            packets_received: AtomicU64::new(0),
            cached_rto_timeout: Mutex::new(None),
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        let inner_clone = inner.clone();
        let runner = async move {
            inner_clone.run_loop(close_rx, incoming_data_rx).await;
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
        mut incoming_data_rx: mpsc::Receiver<Bytes>,
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
        let heartbeat_interval = Duration::from_secs(30);

        loop {
            let now = Instant::now();

            // Check for timeouts at the start of each loop iteration
            if let Err(e) = self.handle_timeout().await {
                warn!("SCTP handle timeout error: {}", e);
            }

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
                    if let Some((_, record)) = sent_queue.iter().next() {
                        let rto = self.rto_state.lock().unwrap().rto;
                        let expiry = record.sent_time + Duration::from_secs_f64(rto);
                        if expiry > now {
                            expiry - now
                        } else {
                            Duration::from_millis(1)
                        }
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
                                    warn!("Failed to send Delayed SACK: {}", e);
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
                            // Check for timeouts after processing a batch of packets
                            if let Err(e) = self.handle_timeout().await {
                                warn!("SCTP handle timeout error: {}", e);
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
        info!("SctpTransport run_loop finished");
    }

    async fn handle_timeout(&self) -> Result<()> {
        let mut to_retransmit = Vec::new();
        let mut abandoned_tsn: Option<u32> = None;

        // 1. Collect all expired chunks and backoff RTO once
        let now = Instant::now();
        let rto = { self.rto_state.lock().unwrap().rto };
        {
            let mut sent_queue = self.sent_queue.lock().unwrap();
            if let Some((_, record)) = sent_queue.iter().next() {
                if now < record.sent_time + Duration::from_secs_f64(rto) {
                    return Ok(());
                }
            } else {
                return Ok(());
            }

            // Collect channel info once to avoid locking in the loop
            let channel_info: std::collections::HashMap<u16, Option<u16>> = {
                let channels = self.data_channels.lock().unwrap();
                channels
                    .iter()
                    .filter_map(|weak_dc| weak_dc.upgrade().map(|dc| (dc.id, dc.max_retransmits)))
                    .collect()
            };

            for (tsn, record) in sent_queue.iter_mut() {
                let expiry = record.sent_time + Duration::from_secs_f64(rto);
                if now >= expiry {
                    // Check for abandonment
                    let mut abandoned = false;
                    if let Some(Some(max_rexmit)) = channel_info.get(&record.stream_id) {
                        if record.transmit_count >= *max_rexmit as u32 {
                            abandoned = true;
                        }
                    }

                    if abandoned {
                        record.abandoned = true;
                        if abandoned_tsn.is_none() || *tsn > abandoned_tsn.unwrap() {
                            abandoned_tsn = Some(*tsn);
                        }
                    } else {
                        to_retransmit.push((*tsn, record.payload.clone()));
                        record.transmit_count += 1;
                        record.sent_time = now; // restart timer; don't sample RTT on retransmit
                        record.fast_retransmit = false; // Reset flag on timeout to allow future fast retransmit if needed
                    }
                }
            }
        }

        if let Some(tsn) = abandoned_tsn {
            debug!("Abandoning chunks up to TSN {}", tsn);
            self.send_forward_tsn(tsn).await?;
        }

        if !to_retransmit.is_empty() {
            // Backoff RTO once per timer tick
            let mut rto_state = self.rto_state.lock().unwrap();
            rto_state.backoff();
            debug!(
                "T3-RTX Timeout! Retransmitting {} chunks, New RTO: {}",
                to_retransmit.len(),
                rto_state.rto
            );

            // Reduce ssthresh and cwnd (RFC 4960 / Modern TCP)
            let cwnd = self.cwnd.load(Ordering::SeqCst);
            let new_ssthresh = (cwnd / 2).max(MAX_SCTP_PACKET_SIZE * 32); // Higher minimum ssthresh
            self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
            self.cwnd.store(CWND_INITIAL, Ordering::SeqCst); // Reset to Initial Window for faster recovery
            self.partial_bytes_acked.store(0, Ordering::SeqCst);
            // Exit Fast Recovery on timeout
            self.fast_recovery_exit_tsn.store(0, Ordering::SeqCst);
        }

        // 2. Retransmit expired chunks
        if !to_retransmit.is_empty() {
            let mut chunks = Vec::new();
            for (_, data) in to_retransmit {
                chunks.push(data);
            }
            if let Err(e) = self.transmit_chunks(chunks).await {
                warn!("Failed to retransmit chunks: {}", e);
            }
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
            info!("SCTP state transition: {:?} -> {:?}", *state, new_state);
            *state = new_state;
        }
    }

    async fn handle_packet(&self, packet: Bytes) -> Result<()> {
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        let mut buf = packet.clone();
        let _src_port = buf.get_u16();
        let _dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let received_checksum = buf.get_u32_le();

        // Verify checksum
        {
            // We need the original packet bytes but with checksum field zeroed.
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
                CT_FORWARD_TSN => self.handle_forward_tsn(chunk_value).await?,
                CT_RECONFIG => self.handle_reconfig(chunk_value).await?,
                CT_ABORT => {
                    warn!("SCTP ABORT received");
                    self.set_state(SctpState::Closed);
                }
                CT_SHUTDOWN => {
                    info!("SCTP SHUTDOWN received");
                    let tag = self.remote_verification_tag.load(Ordering::SeqCst);
                    self.send_chunk(CT_SHUTDOWN_ACK, 0, Bytes::new(), tag)
                        .await?;
                }
                CT_SHUTDOWN_ACK => {
                    info!("SCTP SHUTDOWN ACK received");
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
        init_ack_params.put_u32(LOCAL_RWND_BYTES as u32);
        // Outbound streams
        init_ack_params.put_u16(10);
        // Inbound streams
        init_ack_params.put_u16(10);
        // Initial TSN
        let initial_tsn = random_u32();
        self.next_tsn.store(initial_tsn, Ordering::SeqCst);
        init_ack_params.put_u32(initial_tsn);

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

            let old_rwnd = self.peer_rwnd.swap(a_rwnd, Ordering::SeqCst);
            if a_rwnd > old_rwnd as u32 {
                self.flow_control_notify.notify_waiters();
            }

            let mut gap_blocks = Vec::new();
            for _ in 0..num_gap_ack_blocks {
                if buf.remaining() < 4 {
                    break;
                }
                gap_blocks.push((buf.get_u16(), buf.get_u16()));
            }

            let now = Instant::now();
            let outcome = {
                let mut sent_queue = self.sent_queue.lock().unwrap();
                apply_sack_to_sent_queue(&mut *sent_queue, cumulative_tsn_ack, &gap_blocks, now)
            };

            for rtt in outcome.rtt_samples {
                self.update_rto(rtt);
            }

            if outcome.flight_reduction > 0 {
                self.flight_size
                    .fetch_sub(outcome.flight_reduction, Ordering::SeqCst);

                // Congestion Control: Update cwnd
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let ssthresh = self.ssthresh.load(Ordering::SeqCst);

                // Check if we are in Fast Recovery
                let exit_tsn = self.fast_recovery_exit_tsn.load(Ordering::SeqCst);
                let in_fast_recovery = (cumulative_tsn_ack.wrapping_sub(exit_tsn) as i32) < 0;

                if in_fast_recovery {
                    // In Fast Recovery, we don't increase cwnd normally.
                } else if cwnd < ssthresh {
                    // Slow Start: cwnd += bytes_acked (only for cumulative ack advancement)
                    if outcome.bytes_acked_by_cum_tsn > 0 {
                        let increase = outcome
                            .bytes_acked_by_cum_tsn
                            .min(MAX_BURST * MAX_SCTP_PACKET_SIZE);
                        self.cwnd.fetch_add(increase, Ordering::SeqCst);
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
                            self.cwnd.fetch_add(MAX_SCTP_PACKET_SIZE, Ordering::SeqCst);
                        }
                    }
                }

                self.flow_control_notify.notify_waiters();
            }

            if outcome.head_moved {
                self.timer_notify.notify_one();
                let mut cached = self.cached_rto_timeout.lock().unwrap();
                *cached = None;
            }

            // Handle Fast Retransmit
            if !outcome.retransmit.is_empty() {
                let exit_tsn = self.fast_recovery_exit_tsn.load(Ordering::SeqCst);
                let in_fast_recovery = (cumulative_tsn_ack.wrapping_sub(exit_tsn) as i32) < 0;

                if !in_fast_recovery {
                    // Enter Fast Recovery
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    let new_ssthresh = (cwnd / 2).max(MAX_SCTP_PACKET_SIZE * 32);
                    self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
                    self.cwnd.store(new_ssthresh, Ordering::SeqCst);
                    self.partial_bytes_acked.store(0, Ordering::SeqCst);

                    // Record the highest TSN currently in flight
                    let highest_tsn = self.next_tsn.load(Ordering::SeqCst).wrapping_sub(1);
                    self.fast_recovery_exit_tsn
                        .store(highest_tsn, Ordering::SeqCst);

                    debug!(
                        "Entering Fast Recovery! New ssthresh/cwnd: {}, exit_tsn: {}",
                        new_ssthresh, highest_tsn
                    );
                }

                for (tsn, data) in outcome.retransmit {
                    if let Err(e) = self.transmit_chunks(vec![data]).await {
                        warn!("Failed to retransmit TSN {}: {}", tsn, e);
                    }
                }
            }
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
                        info!("Reset SSN for stream {}", dc.id);
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
        info!(
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
        let mut buf = BytesMut::with_capacity(8);
        buf.put_u16(1); // Heartbeat Info Parameter Type
        buf.put_u16(8); // Length
        buf.put_u32(random_u32()); // Random info

        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        if tag == 0 {
            return Ok(()); // Not connected yet
        }
        self.send_chunk(CT_HEARTBEAT, 0, buf.freeze(), tag).await
    }

    async fn handle_heartbeat(&self, chunk: Bytes) -> Result<()> {
        // Send HEARTBEAT ACK with same info
        // ...

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
                    debug!("Gap changed. Immediate SACK; cum_ack={}.", ack);
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
        LOCAL_RWND_BYTES
            .saturating_sub(used)
            .try_into()
            .unwrap_or(0)
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

        self.dtls_transport.send(buf.freeze()).await
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

        let mut max_payload_size = DEFAULT_MAX_PAYLOAD_SIZE;
        let mut ordered = true;
        let (_guard, ssn) = if let Some(dc) = &dc_opt {
            let guard = dc.send_lock.lock().await;
            ordered = dc.ordered;
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

        // Flow Control Check
        // We loop to send data in chunks that fit within the congestion window.
        // This prevents bursting large messages and flooding the network.
        let total_len = data.len();

        if total_len == 0 {
            // Send empty packet (unfragmented)
            // Wait for window space for at least 1 byte/packet
            loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    self.flow_control_notify.notified().await;
                } else {
                    break;
                }
            }

            let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
            let mut flags = 0x03;
            if !ordered {
                flags |= 0x04;
            }
            let chunk = self.create_data_chunk(channel_id, ppid, data, ssn, flags, tsn);
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let was_empty = queue.is_empty();
                let record = ChunkRecord {
                    payload: chunk.clone(),
                    sent_time: Instant::now(),
                    transmit_count: 0,
                    missing_reports: 0,
                    stream_id: channel_id,
                    abandoned: false,
                    fast_retransmit: false,
                };
                queue.insert(tsn, record);
                self.flight_size.fetch_add(chunk.len(), Ordering::SeqCst);
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
            let allowed_bytes;
            loop {
                let flight = self.flight_size.load(Ordering::SeqCst);
                let cwnd = self.cwnd.load(Ordering::SeqCst);
                let rwnd = self.peer_rwnd.load(Ordering::SeqCst) as usize;
                let effective_window = cwnd.min(rwnd);

                if flight >= effective_window {
                    self.flow_control_notify.notified().await;
                } else {
                    let mut bytes = effective_window - flight;
                    if bytes == 0 {
                        // Should not happen if flight < effective_window, but safety check
                        bytes = max_payload_size;
                    }
                    allowed_bytes = bytes;
                    break;
                }
            }

            // 2. Create a batch of chunks that fits in the window
            let mut chunks = Vec::new();
            let mut batch_len = 0;

            while offset < total_len {
                let remaining = total_len - offset;
                let chunk_size = std::cmp::min(remaining, max_payload_size);

                // Check if we have room in the congestion window
                let next_chunk_len = 16 + chunk_size; // 16 bytes DATA header

                if !chunks.is_empty() {
                    // CWND check
                    if batch_len + next_chunk_len > allowed_bytes {
                        break;
                    }
                }

                let mut flags = if offset == 0 {
                    if remaining <= max_payload_size {
                        0x03 // B=1, E=1 (Unfragmented)
                    } else {
                        0x02 // B=1, E=0 (First)
                    }
                } else if offset + chunk_size >= total_len {
                    0x01 // B=0, E=1 (Last)
                } else {
                    0x00 // B=0, E=0 (Middle)
                };

                if !ordered {
                    flags |= 0x04; // Set U bit
                }

                let tsn = self.next_tsn.fetch_add(1, Ordering::SeqCst);
                let chunk_data = &data[offset..offset + chunk_size];
                let chunk = self.create_data_chunk(channel_id, ppid, chunk_data, ssn, flags, tsn);

                let chunk_len = chunk.len();
                chunks.push((tsn, chunk));
                batch_len += chunk_len;
                offset += chunk_size;

                if batch_len >= allowed_bytes || batch_len >= 64 * 1024 {
                    break;
                }
            }

            // 3. Batch insert into sent_queue
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let now = Instant::now();
                let was_empty = queue.is_empty();

                for (tsn, chunk) in &chunks {
                    let record = ChunkRecord {
                        payload: chunk.clone(),
                        sent_time: now,
                        transmit_count: 0,
                        missing_reports: 0,
                        stream_id: channel_id,
                        abandoned: false,
                        fast_retransmit: false,
                    };
                    queue.insert(*tsn, record);
                }

                self.flight_size.fetch_add(batch_len, Ordering::SeqCst);

                // Only notify timer if the queue was empty (head changed)
                if was_empty {
                    self.timer_notify.notify_one();
                    let mut cached = self.cached_rto_timeout.lock().unwrap();
                    *cached = None;
                }
            }

            // 4. Bundle and send
            let mut to_send = Vec::new();
            for (_, chunk) in chunks {
                to_send.push(chunk);
            }
            self.transmit_chunks(to_send).await?;
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::time::Duration;

    #[test]
    fn test_rto_calculator() {
        let mut calc = RtoCalculator::new();
        assert_eq!(calc.rto, RTO_INITIAL);

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
        let mut calc = RtoCalculator::new();
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
            },
        );

        // Ack cumulative 10 and gap-ack 12, leaving 11 outstanding.
        let outcome = apply_sack_to_sent_queue(&mut sent, 10, &[(2, 2)], Instant::now());

        assert_eq!(outcome.flight_reduction, 2); // a + c removed
        assert_eq!(outcome.rtt_samples.len(), 2);
        assert!(outcome.retransmit.is_empty());
        assert!(outcome.head_moved); // head advanced from 10 to 11

        assert_eq!(sent.len(), 1);
        assert!(sent.contains_key(&11));
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
                },
            );
        }

        // Repeated SACKs report up to TSN 23 but never ack TSN 22.
        let sack_gap = [(2u16, 2u16)];
        let mut outcome;

        outcome = apply_sack_to_sent_queue(&mut sent, 21, &sack_gap, Instant::now());
        assert_eq!(outcome.retransmit.len(), 0);
        assert_eq!(sent.len(), 1); // 21 and 23 acked

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
    async fn test_forward_tsn_handling() {
        // Mock SctpInner
        // This is hard because SctpInner has many fields.
        // But we can test handle_forward_tsn logic if we make it more testable or just test the side effects.
    }
}
