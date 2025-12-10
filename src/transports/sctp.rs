use crate::transports::dtls::{DtlsState, DtlsTransport};
use crate::transports::ice::stun::random_u32;
use anyhow::Result;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use std::collections::{BTreeMap, HashSet};
use std::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex as TokioMutex, Notify, mpsc};
use tracing::{debug, info, trace, warn};

// DCEP Constants
const DATA_CHANNEL_PPID_DCEP: u32 = 50;
const DATA_CHANNEL_PPID_STRING: u32 = 51;
const DATA_CHANNEL_PPID_BINARY: u32 = 53;

const DCEP_TYPE_OPEN: u8 = 0x03;
const DCEP_TYPE_ACK: u8 = 0x02;

// RTO Constants (RFC 4960)
const RTO_INITIAL: f64 = 3.0;
const RTO_MIN: f64 = 1.0;
const RTO_MAX: f64 = 60.0;
const RTO_ALPHA: f64 = 0.125;
const RTO_BETA: f64 = 0.25;

// Flow Control Constants
const CWND_INITIAL: usize = 1200 * 10; // Start with ~10 packets

#[derive(Debug, Clone)]
struct ChunkRecord {
    payload: Bytes,
    sent_time: Instant,
    transmit_count: u32,
}

#[derive(Debug, Clone)]
pub struct DataChannelOpen {
    pub message_type: u8,
    pub channel_type: u8,
    pub priority: u16,
    pub reliability_parameter: u32,
    pub label: String,
    pub protocol: String,
}

impl DataChannelOpen {
    pub fn marshal(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        buf.put_u8(self.message_type);
        buf.put_u8(self.channel_type);
        buf.put_u16(self.priority);
        buf.put_u32(self.reliability_parameter);

        let label_bytes = self.label.as_bytes();
        buf.put_u16(label_bytes.len() as u16);

        let protocol_bytes = self.protocol.as_bytes();
        buf.put_u16(protocol_bytes.len() as u16);

        buf.put_slice(label_bytes);
        buf.put_slice(protocol_bytes);

        buf.to_vec()
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        let mut buf = Bytes::copy_from_slice(data);
        if buf.remaining() < 12 {
            return Err(anyhow::anyhow!("DCEP Open message too short"));
        }

        let message_type = buf.get_u8();
        if message_type != DCEP_TYPE_OPEN {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }

        let channel_type = buf.get_u8();
        let priority = buf.get_u16();
        let reliability_parameter = buf.get_u32();
        let label_len = buf.get_u16() as usize;
        let protocol_len = buf.get_u16() as usize;

        if buf.remaining() < label_len + protocol_len {
            return Err(anyhow::anyhow!("DCEP Open message too short for payload"));
        }

        let label_bytes = buf.split_to(label_len);
        let protocol_bytes = buf.split_to(protocol_len);

        let label = String::from_utf8(label_bytes.to_vec())?;
        let protocol = String::from_utf8(protocol_bytes.to_vec())?;

        Ok(Self {
            message_type,
            channel_type,
            priority,
            reliability_parameter,
            label,
            protocol,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DataChannelAck {
    pub message_type: u8,
}

impl DataChannelAck {
    pub fn marshal(&self) -> Vec<u8> {
        vec![self.message_type]
    }

    pub fn unmarshal(data: &[u8]) -> Result<Self> {
        if data.is_empty() {
            return Err(anyhow::anyhow!("DCEP Ack message too short"));
        }
        let message_type = data[0];
        if message_type != DCEP_TYPE_ACK {
            return Err(anyhow::anyhow!("Invalid DCEP message type"));
        }
        Ok(Self { message_type })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SctpState {
    New,
    Connecting,
    Connected,
    Closed,
}

#[derive(Debug, Clone)]
pub enum DataChannelEvent {
    Open,
    Message(Bytes),
    Close,
}

pub struct DataChannel {
    pub id: u16,
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub max_payload_size: usize,
    pub negotiated: bool,
    pub state: AtomicUsize,
    pub next_ssn: AtomicU16,
    tx: Mutex<Option<mpsc::UnboundedSender<DataChannelEvent>>>,
    rx: TokioMutex<mpsc::UnboundedReceiver<DataChannelEvent>>,
    reassembly_buffer: Mutex<Vec<u8>>,
    pub(crate) send_lock: TokioMutex<()>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum DataChannelState {
    Connecting = 0,
    Open = 1,
    Closing = 2,
    Closed = 3,
}

impl From<usize> for DataChannelState {
    fn from(v: usize) -> Self {
        match v {
            0 => DataChannelState::Connecting,
            1 => DataChannelState::Open,
            2 => DataChannelState::Closing,
            3 => DataChannelState::Closed,
            _ => DataChannelState::Closed,
        }
    }
}

// SCTP Constants
const SCTP_COMMON_HEADER_SIZE: usize = 12;
const CHUNK_HEADER_SIZE: usize = 4;

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
    peer_rwnd: AtomicU32, // Peer's Advertised Receiver Window
    timer_notify: Arc<Notify>,
    flow_control_notify: Arc<Notify>,
}

struct SctpCleanupGuard<'a> {
    inner: &'a SctpInner,
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
            peer_rwnd: AtomicU32::new(1024 * 1024), // Default 1MB until we hear otherwise
            timer_notify: Arc::new(Notify::new()),
            flow_control_notify: Arc::new(Notify::new()),
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

        loop {
            let now = Instant::now();

            // 1. Calculate RTO Timeout
            let rto_timeout = {
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

            // 2. Calculate SACK Timeout
            let sack_timeout = if self.sack_counter.load(Ordering::Relaxed) > 0 {
                if sack_deadline.is_none() {
                    sack_deadline = Some(now + Duration::from_millis(200));
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

            let sleep_duration = rto_timeout.min(sack_timeout);

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
        info!("SctpTransport run_loop finished");
    }

    async fn handle_timeout(&self) -> Result<()> {
        let mut to_retransmit = Vec::new();

        // 1. Check what needs retransmission
        {
            let mut sent_queue = self.sent_queue.lock().unwrap();
            if let Some((tsn, record)) = sent_queue.iter_mut().next() {
                // Double RTO (Backoff)
                let mut rto_state = self.rto_state.lock().unwrap();
                rto_state.backoff();
                debug!(
                    "T3-RTX Timeout! Retransmitting TSN {}, New RTO: {}",
                    tsn, rto_state.rto
                );

                record.transmit_count += 1;
                // Don't update sent_time for retransmissions to avoid RTT pollution?
                // Actually, we restart the timer, so we treat it as "sent now" for timer purposes,
                // but we MUST NOT use it for RTT calculation (Karn's Algorithm).
                record.sent_time = Instant::now();

                to_retransmit.push((*tsn, record.payload.clone()));

                // Reduce ssthresh and cwnd (Congestion Control - Simplified)
                let flight_size = self.flight_size.load(Ordering::SeqCst);
                let new_ssthresh = (flight_size / 2).max(1200 * 4);
                self.ssthresh.store(new_ssthresh, Ordering::SeqCst);
                self.cwnd.store(1200, Ordering::SeqCst); // Reset to 1 MTU on timeout (RFC 4960)
            }
        }

        // 2. Retransmit
        for (tsn, data) in to_retransmit {
            if let Err(e) = self.dtls_transport.send(data).await {
                warn!("Failed to retransmit TSN {}: {}", tsn, e);
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

    async fn handle_packet(&self, packet: Bytes) -> Result<()> {
        if packet.len() < SCTP_COMMON_HEADER_SIZE {
            return Ok(());
        }

        let mut buf = packet;
        let _src_port = buf.get_u16();
        let _dst_port = buf.get_u16();
        let verification_tag = buf.get_u32();
        let _checksum = buf.get_u32();

        // Verify checksum (TODO)

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
                _ => {
                    trace!("Unhandled SCTP chunk type: {}", chunk_type);
                }
            }
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
        init_ack_params.put_u32(128 * 1024);
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

            self.peer_rwnd.store(a_rwnd, Ordering::SeqCst);

            // 1. Remove acknowledged packets
            {
                let mut sent_queue = self.sent_queue.lock().unwrap();
                // split_off returns keys >= cumulative_tsn_ack + 1.
                // So we keep the remaining (unacked) part in `remaining`.
                // The original `sent_queue` retains the acked part.
                let remaining = sent_queue.split_off(&(cumulative_tsn_ack + 1));
                let acked = std::mem::replace(&mut *sent_queue, remaining);

                let mut flight_size_reduction = 0;
                let now = Instant::now();

                for (_, record) in acked {
                    flight_size_reduction += record.payload.len();

                    // Karn's Algorithm: Only measure RTT for packets sent once
                    if record.transmit_count == 0 {
                        let rtt = now.duration_since(record.sent_time).as_secs_f64();
                        self.update_rto(rtt);
                    }
                }

                if flight_size_reduction > 0 {
                    self.flight_size
                        .fetch_sub(flight_size_reduction, Ordering::SeqCst);

                    // Congestion Control: Update cwnd
                    let cwnd = self.cwnd.load(Ordering::SeqCst);
                    let ssthresh = self.ssthresh.load(Ordering::SeqCst);

                    if cwnd <= ssthresh {
                        // Slow Start: cwnd += min(bytes_acked, MTU)
                        // We approximate bytes_acked as flight_size_reduction
                        let increase = flight_size_reduction.min(1200); // Cap at MTU
                        self.cwnd.fetch_add(increase, Ordering::SeqCst);
                    } else {
                        // Congestion Avoidance: cwnd += MTU * MTU / cwnd
                        // We add (MTU * bytes_acked) / cwnd
                        let increase = (1200 * flight_size_reduction) / cwnd;
                        // Ensure at least 1 byte growth if possible, but usually this is small
                        if increase > 0 {
                            self.cwnd.fetch_add(increase, Ordering::SeqCst);
                        }
                    }

                    self.flow_control_notify.notify_waiters();
                }
            }

            if num_gap_ack_blocks > 0 {
                let mut max_sack_tsn = cumulative_tsn_ack;
                let mut received_tsns = HashSet::new();

                for _ in 0..num_gap_ack_blocks {
                    if buf.remaining() < 4 {
                        break;
                    }
                    let start = buf.get_u16();
                    let end = buf.get_u16();
                    let block_start = cumulative_tsn_ack.wrapping_add(start as u32);
                    let block_end = cumulative_tsn_ack.wrapping_add(end as u32);

                    if block_end > max_sack_tsn {
                        max_sack_tsn = block_end;
                    }

                    for tsn in block_start..=block_end {
                        received_tsns.insert(tsn);
                    }
                }

                let mut to_retransmit = Vec::new();
                {
                    let mut sent_queue = self.sent_queue.lock().unwrap();
                    for (&tsn, record) in sent_queue.iter_mut() {
                        if tsn <= max_sack_tsn && !received_tsns.contains(&tsn) {
                            // Fast Retransmit
                            record.transmit_count += 1;
                            to_retransmit.push((tsn, record.payload.clone()));
                        }
                    }
                }

                for (tsn, data) in to_retransmit {
                    if let Err(e) = self.dtls_transport.send(data).await {
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
            // Duplicate or Old
            let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);
            self.send_sack(ack).await?;
            return Ok(());
        }

        // Store in received_queue
        {
            let mut received_queue = self.received_queue.lock().unwrap();
            if received_queue.contains_key(&tsn) {
                debug!("Dropping duplicate buffered packet TSN={}", tsn);
            } else {
                received_queue.insert(tsn, (flags, chunk));
            }
        }

        // Process packets in order
        loop {
            let next_tsn = self
                .cumulative_tsn_ack
                .load(Ordering::SeqCst)
                .wrapping_add(1);

            let packet_entry = {
                let mut received_queue = self.received_queue.lock().unwrap();
                received_queue.remove(&next_tsn)
            };

            if let Some((p_flags, p_chunk)) = packet_entry {
                // Process this packet
                self.process_data_payload(p_flags, p_chunk).await?;
                self.cumulative_tsn_ack.store(next_tsn, Ordering::SeqCst);
            } else {
                break;
            }
        }

        let ack = self.cumulative_tsn_ack.load(Ordering::SeqCst);

        // Check if we have a gap
        let has_gap = !self.received_queue.lock().unwrap().is_empty();

        if has_gap {
            warn!("Gap detected! Cumulative ACK: {}. Sending SACK.", ack);
            self.send_sack(ack).await?;
        } else {
            // Delayed Ack logic (RFC 4960)
            // Send SACK every 2 packets
            let count = self.sack_counter.fetch_add(1, Ordering::Relaxed);
            if count >= 1 {
                self.sack_counter.store(0, Ordering::Relaxed);
                self.send_sack(ack).await?;
            }
            // If count was 0, it is now 1. The run_loop will pick this up and set the 200ms timer.
        }
        Ok(())
    }

    async fn process_data_payload(&self, flags: u8, chunk: Bytes) -> Result<()> {
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

        let found_dc = {
            let channels = self.data_channels.lock().unwrap();
            channels
                .iter()
                .find_map(|weak_dc| weak_dc.upgrade().filter(|dc| dc.id == stream_id))
        };

        if let Some(dc) = found_dc {
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
                }
                buffer.clear();
            }
            buffer.extend_from_slice(&user_data);
            if e_bit {
                let msg = Bytes::from(buffer.clone());
                buffer.clear();
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

    async fn send_sack(&self, cumulative_tsn_ack: u32) -> Result<()> {
        let mut sack = BytesMut::new();
        sack.put_u32(cumulative_tsn_ack); // Cumulative TSN Ack
        sack.put_u32(1024 * 1024); // a_rwnd
        sack.put_u16(0); // Number of Gap Ack Blocks
        sack.put_u16(0); // Number of Duplicate TSNs

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
        let padding = (4 - (value_len % 4)) % 4;
        let total_len = SCTP_COMMON_HEADER_SIZE + CHUNK_HEADER_SIZE + value_len + padding;

        let mut packet = BytesMut::with_capacity(total_len);

        // Common Header
        packet.put_u16(self.local_port);
        packet.put_u16(self.remote_port);
        packet.put_u32(verification_tag);
        packet.put_u32(0); // Checksum placeholder

        // Chunk
        packet.put_u8(type_);
        packet.put_u8(flags);
        packet.put_u16((CHUNK_HEADER_SIZE + value_len) as u16);
        packet.put_slice(&value);

        // Padding
        for _ in 0..padding {
            packet.put_u8(0);
        }

        // Calculate Checksum (CRC32c)
        let checksum = crc32c::crc32c(&packet);

        let checksum_bytes = checksum.to_le_bytes();

        packet[8] = checksum_bytes[0];
        packet[9] = checksum_bytes[1];
        packet[10] = checksum_bytes[2];
        packet[11] = checksum_bytes[3];

        self.dtls_transport.send(packet.freeze()).await
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

        let mut max_payload_size = 1200;
        let mut ordered = true;
        let (_guard, ssn) = if let Some(dc) = &dc_opt {
            let guard = dc.send_lock.lock().await;
            ordered = dc.ordered;
            let ssn = if ordered {
                dc.next_ssn.fetch_add(1, Ordering::SeqCst)
            } else {
                0
            };
            max_payload_size = dc.max_payload_size;
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
            let packet = self.create_packet(channel_id, ppid, data, ssn, flags, tsn);
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let was_empty = queue.is_empty();
                let record = ChunkRecord {
                    payload: packet.clone(),
                    sent_time: Instant::now(),
                    transmit_count: 0,
                };
                queue.insert(tsn, record);
                self.flight_size.fetch_add(packet.len(), Ordering::SeqCst);
                if was_empty {
                    self.timer_notify.notify_one();
                }
            }
            return self.dtls_transport.send(packet).await;
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

                // Check if we have room (approximate check before expensive create_packet)
                // Header overhead is ~28 bytes.
                if !chunks.is_empty() && batch_len + chunk_size + 28 > allowed_bytes {
                    break;
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
                let packet = self.create_packet(channel_id, ppid, chunk_data, ssn, flags, tsn);

                let pkt_len = packet.len();
                chunks.push((tsn, packet));
                batch_len += pkt_len;
                offset += chunk_size;

                if batch_len >= allowed_bytes {
                    break;
                }
            }

            // 3. Batch insert into sent_queue
            {
                let mut queue = self.sent_queue.lock().unwrap();
                let now = Instant::now();
                let was_empty = queue.is_empty();

                for (tsn, packet) in &chunks {
                    let record = ChunkRecord {
                        payload: packet.clone(),
                        sent_time: now,
                        transmit_count: 0,
                    };
                    queue.insert(*tsn, record);
                }

                self.flight_size.fetch_add(batch_len, Ordering::SeqCst);

                // Only notify timer if the queue was empty (head changed)
                if was_empty {
                    self.timer_notify.notify_one();
                }
            }

            // 4. Batch send
            for (_, packet) in chunks {
                self.dtls_transport.send(packet).await?;
            }
        }

        Ok(())
    }
    fn create_packet(
        &self,
        channel_id: u16,
        ppid: u32,
        data: &[u8],
        ssn: u16,
        flags: u8,
        tsn: u32,
    ) -> Bytes {
        // Calculate total size
        // Common Header: 12
        // Chunk Header: 4
        // TSN: 4, StreamID: 2, StreamSeq: 2, PPID: 4 = 12
        // Data: N
        // Padding: 0-3

        let data_len = data.len();
        trace!(
            "Sending fragment: len={}, flags={:#x}, ssn={}",
            data_len, flags, ssn
        );
        let chunk_value_len = 12 + data_len;
        let chunk_len = 4 + chunk_value_len;
        let padding = (4 - (chunk_len % 4)) % 4;
        let total_len = 12 + chunk_len + padding;

        let mut buf = BytesMut::with_capacity(total_len);

        // Common Header
        buf.put_u16(self.local_port);
        buf.put_u16(self.remote_port);
        let tag = self.remote_verification_tag.load(Ordering::SeqCst);
        buf.put_u32(tag);
        buf.put_u32(0); // Checksum placeholder (offset 8)

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

        // CRC32c
        let checksum = crc32c::crc32c(&buf);
        let checksum_bytes = checksum.to_le_bytes();
        buf[8] = checksum_bytes[0];
        buf[9] = checksum_bytes[1];
        buf[10] = checksum_bytes[2];
        buf[11] = checksum_bytes[3];

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

#[derive(Debug, Clone, Default)]
pub struct DataChannelConfig {
    pub label: String,
    pub protocol: String,
    pub ordered: bool,
    pub max_retransmits: Option<u16>,
    pub max_packet_life_time: Option<u16>,
    pub max_payload_size: Option<usize>,
    pub negotiated: Option<u16>,
}

impl DataChannel {
    pub fn new(id: u16, config: DataChannelConfig) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            id,
            label: config.label,
            protocol: config.protocol,
            ordered: config.ordered,
            max_retransmits: config.max_retransmits,
            max_packet_life_time: config.max_packet_life_time,
            max_payload_size: config.max_payload_size.unwrap_or(1200),
            negotiated: config.negotiated.is_some(),
            state: AtomicUsize::new(DataChannelState::Connecting as usize),
            next_ssn: AtomicU16::new(0),
            tx: Mutex::new(Some(tx)),
            rx: TokioMutex::new(rx),
            reassembly_buffer: Mutex::new(Vec::new()),
            send_lock: TokioMutex::new(()),
        }
    }

    pub async fn recv(&self) -> Option<DataChannelEvent> {
        let mut rx = self.rx.lock().await;
        rx.recv().await
    }

    pub(crate) fn send_event(&self, event: DataChannelEvent) {
        if let Some(tx) = &*self.tx.lock().unwrap() {
            let _ = tx.send(event);
        }
    }

    pub(crate) fn close_channel(&self) {
        *self.tx.lock().unwrap() = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
        assert!(calc.rto >= 1.0); // Min RTO is 1.0s

        calc.backoff();
        assert!(calc.rto >= 2.0);
    }
}
