//! Read-only packet-path observations. Counters are cumulative, not an atomic
//! transaction across stages. No packet payloads, keys or ICE credentials are exposed.
//! In serialized snapshots an omitted error/drop stage means zero observations;
//! primary traffic stages always retain explicit None first/last ages for never.
use crate::prelude::*;
use serde::Serialize;

#[derive(Debug, Clone, Default, Serialize)]
pub struct PacketCounter {
    pub packets: u64,
    pub bytes: u64,
    /// Monotonic elapsed milliseconds since the first observation; None means never.
    pub first_age_ms: Option<u64>,
    /// Monotonic elapsed milliseconds since the last observation; None means never.
    pub last_age_ms: Option<u64>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct SelectedPairDiagnostics {
    pub local_addr: String,
    pub remote_addr: String,
    pub local_type: String,
    pub remote_type: String,
    pub transport: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IcePacketDiagnostics {
    pub state: String,
    pub gathering_state: String,
    pub role: String,
    pub local_candidates: usize,
    pub remote_candidates: usize,
    pub buffered_pending: usize,
    pub buffered_received: u64,
    pub buffered_dropped: u64,
    pub last_turn_control: Option<TurnControlDiagnostics>,
    pub turn_control_history: Vec<TurnControlAttempt>,
    pub selected_pair: Option<SelectedPairDiagnostics>,
    pub udp_read: PacketCounter,
    /// Direct socket reads, excluding the allocated TURN reader.
    pub direct_udp_read: PacketCounter,
    /// Reads from an allocated TURN transport, before unwrapping control or media.
    pub turn_wire_read: PacketCounter,
    /// Packets delivered by a shared-socket demultiplexer, not raw socket reads.
    pub shared_udp_read: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub udp_read_errors: PacketCounter,
    pub udp_read_exits: PacketCounter,
    pub turn_channel_data: PacketCounter,
    pub turn_data_indication: PacketCounter,
    pub turn_control: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub turn_unknown_channel: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub turn_malformed: PacketCounter,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct IceConnDiagnostics {
    /// Process-local diagnostic identity of this owner; never a routing generation.
    pub connection_id: u64,
    pub selected_socket: Option<String>,
    pub rtp_latched: bool,
    pub rtcp_latched: bool,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub send_simulated_drop: PacketCounter,
    pub received: PacketCounter,
    pub dtls: PacketCounter,
    pub rtp: PacketCounter,
    pub rtcp: PacketCounter,
    pub unknown: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub dtls_no_receiver: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtp_no_receiver: PacketCounter,
    pub send_attempts: PacketCounter,
    pub send_sync_success: PacketCounter,
    pub send_deferred_queued: PacketCounter,
    /// Includes the currently executing deferred write; zero is only a point-in-time observation.
    pub send_deferred_pending: u64,
    pub deferred_send_observer_installed: bool,
    pub send_deferred_completed: u64,
    pub send_deferred_errors: u64,
    pub send_async_completed: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub send_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub send_queue_closed: PacketCounter,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RtpPacketDiagnostics {
    pub local_addr: String,
    pub remote_addr: String,
    pub srtp_required: bool,
    pub srtp_session_ready: bool,
    pub conn: IceConnDiagnostics,
    pub rtp_accepted: PacketCounter,
    /// Completed normal RTP writes, excluding bridge relay writes.
    pub rtp_sent: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtp_send_errors: PacketCounter,
    pub pending_srtp_packets: usize,
    pub rtcp_accepted: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtp_parse_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtp_unprotect_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtp_no_session: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtcp_unprotect_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtcp_no_session: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtcp_parse_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtp_parse_errors: PacketCounter,
    pub listener_delivered: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub listener_full: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub listener_closed: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub no_listener: PacketCounter,
    pub rtcp_listener_delivered: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtcp_listener_closed: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub rtcp_no_listener: PacketCounter,
    pub bridge_relayed: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub bridge_send_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub bridge_dropped: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub bridge_direction_dropped: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub send_direction_dropped: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtp_protect_errors: PacketCounter,
    #[serde(skip_serializing_if = "PacketCounter::is_never")]
    pub srtp_send_no_session: PacketCounter,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct PacketDiagnostics {
    /// Packet-stage recording is part of the always-on stats pipeline.
    pub enabled: bool,
    /// Display form only: Debug for DtlsState::Connected contains key material.
    pub dtls_state: Option<String>,
    pub dtls_error_observation_supported: bool,
    pub ice: IcePacketDiagnostics,
    pub media_ice: Vec<IcePacketDiagnostics>,
    pub transports: Vec<RtpPacketDiagnostics>,
}

use crate::platform::atomic64::AtomicU64;
#[cfg(not(feature = "std"))]
use crate::platform::time::Instant;
use core::sync::atomic::{AtomicBool, Ordering};
#[cfg(feature = "std")]
use std::time::Instant;

/// One stage's observations. std uses a monotonic clock; no_std uses the
/// embedder's logical platform clock. A zero timestamp always means never.
pub(crate) struct Counter {
    epoch: Instant,
    packets: AtomicU64,
    bytes: AtomicU64,
    last_ms: AtomicU64,
    first_ms: AtomicU64,
    first_seen: AtomicBool,
}
impl Default for Counter {
    fn default() -> Self {
        Self {
            epoch: Instant::now(),
            packets: AtomicU64::new(0),
            bytes: AtomicU64::new(0),
            last_ms: AtomicU64::new(0),
            first_ms: AtomicU64::new(0),
            first_seen: AtomicBool::new(false),
        }
    }
}
impl Counter {
    #[inline]
    pub(crate) fn record(&self, bytes: usize) {
        self.record_many(1, bytes);
    }
    #[inline]
    pub(crate) fn record_many(&self, packets: u64, bytes: usize) {
        {
            self.packets.fetch_add(packets, Ordering::Relaxed);
            self.mark(bytes);
        }
    }
    /// Attach byte/time observations to a counter already owned by the transport.
    #[inline]
    pub(crate) fn mark(&self, bytes: usize) {
        {
            self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
            let now = self.epoch.elapsed().as_millis() as u64 + 1;
            if !self.first_seen.load(Ordering::Relaxed)
                && self
                    .first_seen
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
            {
                self.first_ms.store(now, Ordering::Relaxed);
            }
            #[cfg(target_has_atomic = "64")]
            self.last_ms.fetch_max(now, Ordering::Relaxed);
            #[cfg(not(target_has_atomic = "64"))]
            self.last_ms.store(now, Ordering::Relaxed);
        }
    }
    pub(crate) fn snapshot(&self) -> PacketCounter {
        {
            let last = self.last_ms.load(Ordering::Relaxed);
            let first = self.first_ms.load(Ordering::Relaxed);
            let now = self.epoch.elapsed().as_millis() as u64 + 1;
            PacketCounter {
                packets: self.packets.load(Ordering::Relaxed),
                bytes: self.bytes.load(Ordering::Relaxed),
                first_age_ms: (first != 0).then(|| now.saturating_sub(first)),
                last_age_ms: (last != 0).then(|| now.saturating_sub(last)),
            }
        }
    }
    pub(crate) fn snapshot_count(&self, packets: u64) -> PacketCounter {
        PacketCounter {
            packets,
            ..self.snapshot()
        }
    }
}

macro_rules! observations {
    ($state:ident, $snapshot:ident, $($field:ident),+ $(,)?) => {
        #[derive(Default)]
        pub(crate) struct $state { $(pub(crate) $field: Counter,)+ }
        impl $state {
            pub(crate) fn snapshot(&self) -> $snapshot {
                $snapshot { $($field: self.$field.snapshot(),)+ ..Default::default() }
            }
        }
    };
}
observations!(
    IceObservations,
    IcePacketDiagnostics,
    udp_read,
    turn_wire_read,
    shared_udp_read,
    udp_read_errors,
    udp_read_exits,
    turn_channel_data,
    turn_data_indication,
    turn_control,
    turn_unknown_channel,
    turn_malformed
);
static NEXT_CONNECTION_DIAGNOSTIC_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) struct ConnObservations {
    connection_id: u64,
    pub(crate) received: Counter,
    pub(crate) dtls: Counter,
    pub(crate) rtp: Counter,
    pub(crate) rtcp: Counter,
    pub(crate) unknown: Counter,
    pub(crate) dtls_no_receiver: Counter,
    pub(crate) rtp_no_receiver: Counter,
    pub(crate) send_attempts: Counter,
    pub(crate) send_sync_success: Counter,
    pub(crate) send_deferred_queued: Counter,
    pub(crate) send_async_completed: Counter,
    pub(crate) send_errors: Counter,
    pub(crate) send_queue_closed: Counter,
    pub(crate) send_simulated_drop: Counter,
    pub(crate) deferred_pending: AtomicU64,
    pub(crate) deferred_completed: AtomicU64,
    pub(crate) deferred_errors: AtomicU64,
    pub(crate) deferred_observer: crate::platform::sync::OnceLock<Arc<DeferredSendObserver>>,
}
impl Default for ConnObservations {
    fn default() -> Self {
        Self {
            connection_id: NEXT_CONNECTION_DIAGNOSTIC_ID.fetch_add(1, Ordering::Relaxed),
            received: Default::default(),
            dtls: Default::default(),
            rtp: Default::default(),
            rtcp: Default::default(),
            unknown: Default::default(),
            dtls_no_receiver: Default::default(),
            rtp_no_receiver: Default::default(),
            send_attempts: Default::default(),
            send_sync_success: Default::default(),
            send_deferred_queued: Default::default(),
            send_async_completed: Default::default(),
            send_errors: Default::default(),
            send_queue_closed: Default::default(),
            send_simulated_drop: Default::default(),
            deferred_pending: Default::default(),
            deferred_completed: Default::default(),
            deferred_errors: Default::default(),
            deferred_observer: Default::default(),
        }
    }
}

impl ConnObservations {
    pub(crate) fn snapshot(&self) -> IceConnDiagnostics {
        IceConnDiagnostics {
            connection_id: self.connection_id,
            received: self.received.snapshot(),
            dtls: self.dtls.snapshot(),
            rtp: self.rtp.snapshot(),
            rtcp: self.rtcp.snapshot(),
            unknown: self.unknown.snapshot(),
            dtls_no_receiver: self.dtls_no_receiver.snapshot(),
            rtp_no_receiver: self.rtp_no_receiver.snapshot(),
            send_attempts: self.send_attempts.snapshot(),
            send_sync_success: self.send_sync_success.snapshot(),
            send_deferred_queued: self.send_deferred_queued.snapshot(),
            send_async_completed: self.send_async_completed.snapshot(),
            send_errors: self.send_errors.snapshot(),
            send_queue_closed: self.send_queue_closed.snapshot(),
            send_simulated_drop: self.send_simulated_drop.snapshot(),
            send_deferred_pending: self.deferred_pending.load(Ordering::Acquire),
            deferred_send_observer_installed: self.deferred_observer.get().is_some(),
            send_deferred_completed: self.deferred_completed.load(Ordering::Relaxed),
            send_deferred_errors: self.deferred_errors.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    pub(crate) fn deferred_result(&self, remote_addr: core::net::SocketAddr, failed: bool) {
        let Some(observer) = self.deferred_observer.get() else {
            return;
        };
        // Normal traffic does no callback, snapshot, formatting, lock or Arc clone.
        if observer.stopping.load(Ordering::Acquire) {
            (observer.on_result)(DeferredSendSnapshot {
                connection_id: self.connection_id,
                remote_addr,
                failed,
                queued: self.send_deferred_queued.snapshot(),
                pending: self.deferred_pending.load(Ordering::Acquire),
                completed: self.deferred_completed.load(Ordering::Relaxed),
                errors: self.deferred_errors.load(Ordering::Relaxed),
                send_async_completed: self.send_async_completed.snapshot(),
                send_errors: self.send_errors.snapshot(),
            });
        }
    }
}

/// An actual deferred-write outcome. Counters are cumulative for this IceConn,
/// not an atomic transaction across fields. No payload or error text is retained.
/// The two send-stage counters also include non-deferred async writes.
#[derive(Debug, Clone, Serialize)]
pub struct DeferredSendSnapshot {
    pub connection_id: u64,
    pub remote_addr: core::net::SocketAddr,
    pub failed: bool,
    pub queued: PacketCounter,
    pub pending: u64,
    pub completed: u64,
    pub errors: u64,
    pub send_async_completed: PacketCounter,
    pub send_errors: PacketCounter,
}

/// Observation ownership is independent of PeerConnection/transport lifetime.
/// The caller must not capture those owners in its callback. Notifications are
/// enabled only at stopping; this never drains, delays, or cancels a write.
pub struct DeferredSendObserver {
    stopping: AtomicBool,
    on_result: Box<dyn Fn(DeferredSendSnapshot) + Send + Sync>,
}
impl DeferredSendObserver {
    pub fn new(on_result: impl Fn(DeferredSendSnapshot) + Send + Sync + 'static) -> Self {
        {
            Self {
                stopping: AtomicBool::new(false),
                on_result: Box::new(on_result),
            }
        }
    }

    pub fn mark_stopping(&self) {
        self.stopping.store(true, Ordering::Release);
    }
}

observations!(
    RtpObservations,
    RtpPacketDiagnostics,
    rtp_accepted,
    rtp_sent,
    rtp_send_errors,
    rtcp_accepted,
    srtp_parse_errors,
    srtp_unprotect_errors,
    srtp_no_session,
    srtcp_unprotect_errors,
    srtcp_no_session,
    rtcp_parse_errors,
    rtp_parse_errors,
    listener_delivered,
    listener_full,
    listener_closed,
    no_listener,
    rtcp_listener_delivered,
    rtcp_listener_closed,
    rtcp_no_listener,
    bridge_relayed,
    bridge_send_errors,
    bridge_dropped,
    bridge_direction_dropped,
    send_direction_dropped,
    srtp_protect_errors,
    srtp_send_no_session
);

/// Counts exits including task cancellation, without retaining its owning transport.
pub(crate) struct ReadExitGuard<'a>(pub(crate) &'a Counter);
impl Drop for ReadExitGuard<'_> {
    fn drop(&mut self) {
        self.0.record(0);
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct TurnControlDiagnostics {
    pub method: String,
    pub class: String,
    pub error_code: Option<u16>,
}

impl PacketCounter {
    pub(crate) fn combined(&self, other: &Self) -> Self {
        Self {
            packets: self.packets.saturating_add(other.packets),
            bytes: self.bytes.saturating_add(other.bytes),
            first_age_ms: self
                .first_age_ms
                .into_iter()
                .chain(other.first_age_ms)
                .max(),
            last_age_ms: self.last_age_ms.into_iter().chain(other.last_age_ms).min(),
        }
    }

    fn is_never(&self) -> bool {
        self.packets == 0
            && self.bytes == 0
            && self.first_age_ms.is_none()
            && self.last_age_ms.is_none()
    }
}

/// At most eight real TURN request attempts, oldest first. Duration is only
/// present after an observed outcome; pending attempts expose start age.
#[derive(Debug, Clone, Serialize)]
pub struct TurnControlAttempt {
    pub method: String,
    pub started_age_ms: u64,
    pub duration_ms: Option<u64>,
    pub outcome: String,
    pub response_class: Option<String>,
    pub error_code: Option<u16>,
}

use crate::platform::sync::Mutex;
use alloc::collections::VecDeque;

struct TurnControlRecord {
    transaction_id: [u8; 12], // Internal association only; never serialized.
    started: Instant,
    duration_ms: Option<u64>,
    method: &'static str,
    outcome: &'static str,
    response_class: Option<String>,
    error_code: Option<u16>,
}

/// Observation-only history, bounded independently of the transaction lifecycle.
#[derive(Default)]
pub(crate) struct TurnControlHistory(Mutex<VecDeque<TurnControlRecord>>);
impl core::fmt::Debug for TurnControlHistory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TurnControlHistory").finish_non_exhaustive()
    }
}
impl TurnControlHistory {
    pub(crate) fn begin(
        self: &Arc<Self>,
        transaction_id: [u8; 12],
        method: &'static str,
    ) -> TurnControlGuard {
        {
            let mut entries = self.0.lock();
            if entries.len() == 8 {
                entries.pop_front();
            }
            entries.push_back(TurnControlRecord {
                transaction_id,
                started: Instant::now(),
                duration_ms: None,
                method,
                outcome: "pending",
                response_class: None,
                error_code: None,
            });
            TurnControlGuard {
                history: self.clone(),
                transaction_id,
                finished: false,
            }
        }
    }
    pub(crate) fn snapshot(&self) -> Vec<TurnControlAttempt> {
        {
            self.0
                .lock()
                .iter()
                .map(|entry| TurnControlAttempt {
                    method: entry.method.to_string(),
                    started_age_ms: entry.started.elapsed().as_millis() as u64,
                    duration_ms: entry.duration_ms,
                    outcome: entry.outcome.to_string(),
                    response_class: entry.response_class.clone(),
                    error_code: entry.error_code,
                })
                .collect()
        }
    }
}
pub(crate) struct TurnControlGuard {
    history: Arc<TurnControlHistory>,
    transaction_id: [u8; 12],
    finished: bool,
}
impl TurnControlGuard {
    pub(crate) fn failure(&mut self, outcome: &'static str) {
        {
            if let Some(entry) = self
                .history
                .0
                .lock()
                .iter_mut()
                .rev()
                .find(|entry| entry.transaction_id == self.transaction_id)
            {
                entry.outcome = outcome;
                entry.duration_ms = Some(entry.started.elapsed().as_millis() as u64);
            }
            self.finished = true;
        }
    }
    pub(crate) fn error(&mut self, error: &crate::errors::RtcError, phase: &'static str) {
        self.failure(if error.is_timeout() { "timeout" } else { phase });
    }
    pub(crate) fn response(&mut self, msg: &crate::transports::ice::stun::StunDecoded) {
        {
            use crate::transports::ice::stun::StunClass;
            if let Some(entry) = self
                .history
                .0
                .lock()
                .iter_mut()
                .rev()
                .find(|entry| entry.transaction_id == self.transaction_id)
            {
                entry.outcome = if format!("{:?}", msg.method) != entry.method {
                    "unexpected_method"
                } else if msg.class == StunClass::SuccessResponse {
                    "success"
                } else if msg.class == StunClass::ErrorResponse {
                    "error_response"
                } else {
                    "unexpected_class"
                };
                entry.response_class = Some(format!("{:?}", msg.class));
                entry.error_code = msg.error_code;
                entry.duration_ms = Some(entry.started.elapsed().as_millis() as u64);
            }
            self.finished = true;
        }
    }
}
impl Drop for TurnControlGuard {
    fn drop(&mut self) {
        if !self.finished {
            self.failure("cancelled");
        }
    }
}
