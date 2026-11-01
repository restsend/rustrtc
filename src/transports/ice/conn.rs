use super::{IceSocketWrapper, should_drop_packet};
use crate::errors::{RtcError, RtcResult};
use crate::platform::atomic64::AtomicU64;
use crate::platform::sync::OnceLock;
use crate::platform::sync::{Mutex, RwLock};
use crate::platform::sync::{mpsc, watch};
use crate::platform::task;
use crate::platform::time::Instant;
use crate::prelude::*;
use crate::stats::{StatsEntry, StatsId, StatsKind, StatsProvider};
use crate::transports::PacketReceiver;
use alloc::sync::{Arc, Weak};
use async_trait::async_trait;
use bytes::Bytes;
use core::net::SocketAddr;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, Ordering};
use serde_json::json;
use tracing::{debug, trace, warn};

/// Per-source state observed during the initial-latch probation: a stale
/// NAT binding or port glitch may deliver a few packets from the wrong
/// source before the real stream settles.  Identity is `ip:port + SSRC`;
/// a candidate earns credit only for packets carrying its own SSRC.
///
/// Winner rules: consecutive dominance (`consecutive_count >= 2`, i.e. 3
/// packets in a row, once `>= 3` total observed) or, after `max_packets`
/// observations, the timeout fallback (most packets; ties by marker, then
/// earliest `first_seq` in wrapping order).  No single packet — marker or
/// not — can move the egress address.
#[derive(Debug)]
struct RtpCandidateState {
    addr: SocketAddr,
    /// SSRC this candidate was first seen with; the candidate identity.
    ssrc: u32,
    first_seq: u16,
    last_seq: u16,
    packet_count: u8,
    /// Number of RTP packets received with `seq == last_seq + 1`.
    consecutive_count: u8,
    has_marker: bool,
}

/// State held while we are in the probation / candidate-selection phase.
#[derive(Debug)]
struct RtpProbationState {
    candidates: Vec<RtpCandidateState>,
    total_packets: u8,
    /// Maximum total observed packets before forcing a decision
    /// (≈ 80 ms at 20 ms ptime when set to 6).
    max_packets: u8,
}

// ── Competitive re-latch (steady-state source migration) ─────────────
//
// After the initial latch, a different source takes over the egress path
// only after `RELATCH_PACKETS` consecutive-sequence packets carrying one
// SSRC inside `RELATCH_WINDOW_MS` — the sanctioned path for legitimate
// NAT rebinding.  Persistence is accident-robustness, not a security
// boundary: sustained on-path injection is left to deployment and future
// crypto fast-paths (STUN MIC / SRTP auth).

/// Consecutive-sequence packets (same SSRC) a new source must show before a
/// competitive re-latch commits (≈ 80 ms at 20 ms ptime).
const RELATCH_PACKETS: u8 = 4;
/// A probe that has not reached `RELATCH_PACKETS` within this window is
/// discarded (a straggler, not a live flow).
const RELATCH_WINDOW_MS: u64 = 2_000;
/// After a re-latch commits, further probes are suppressed for this long
/// (anti flapping / ping-pong between paths).
const RELATCH_COOLDOWN_MS: u64 = 10_000;
/// Maximum competitive re-latches per session; beyond this the address is
/// frozen until signaling retargets it.
const RELATCH_MAX_SWITCHES: u8 = 4;
/// Non-mux RTCP latching also requires repetition — one packet must not
/// move the RTCP destination.
const RTCP_LATCH_PACKETS: u8 = 2;

/// Probe state for a source address competing to take over the latched
/// egress path; identity is `addr + ssrc`.
#[derive(Debug)]
struct RelatchProbe {
    addr: SocketAddr,
    ssrc: u32,
    last_seq: u16,
    consecutive: u8,
    first_seen_ms: u64,
    last_seen_ms: u64,
}

impl RelatchProbe {
    fn new(addr: SocketAddr, ssrc: u32, seq: u16, now_ms: u64) -> Self {
        Self {
            addr,
            ssrc,
            last_seq: seq,
            consecutive: 1,
            first_seen_ms: now_ms,
            last_seen_ms: now_ms,
        }
    }
}

/// True when RTP sequence `seq` immediately follows `prev` (wrapping-aware).
fn seq_is_next(prev: u16, seq: u16) -> bool {
    seq == prev.wrapping_add(1)
}

/// True when RTP sequence number `a` precedes `b` in 16-bit wrapping order
/// (`a` is the older/newer-towards-wrap side).  Plain `<` breaks at the
/// 0xFFFF → 0x0000 wrap.
fn seq_before(a: u16, b: u16) -> bool {
    let d = a.wrapping_sub(b);
    d != 0 && d >= 0x8000
}

/// Emitted when the RTP remote source (egress destination) changes: the
/// initial latch commit (`switch == 0`) or a competitive re-latch
/// (`switch >= 1`).  Delivered to the upper layer through the channel
/// installed with [`IceConn::set_source_change_sender`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceChange {
    /// Remote address media was being sent to before the change.
    pub from: SocketAddr,
    /// Newly committed remote address.
    pub to: SocketAddr,
    /// RTP SSRC that drove the decision.
    pub ssrc: u32,
    /// 0 = initial latch, 1.. = nth competitive re-latch this session.
    pub switch: u8,
}

pub struct IceConn {
    diagnostics: Arc<crate::stats::packet::ConnObservations>,
    pub socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
    pub remote_addr: RwLock<SocketAddr>,
    pub remote_rtcp_addr: RwLock<Option<SocketAddr>>,
    pub dtls_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub rtp_receiver: RwLock<Option<Weak<dyn PacketReceiver>>>,
    pub latch_on_rtp: AtomicBool,
    pub rtp_latched: AtomicBool,
    pub rtcp_latched: AtomicBool,
    pub expected_ssrc: AtomicU32,
    pub rtp_rx_count: AtomicU64,
    pub label: Option<String>,
    /// First inbound RTP logged (INFO, once) — proves the remote is sending
    /// media to us.
    first_rtp_rx_logged: AtomicBool,
    /// First inbound RTCP logged (INFO, once) — proves the remote's stack is
    /// alive / acking.
    first_rtcp_rx_logged: AtomicBool,
    /// Set once the first outbound RTP has been written to the wire.
    first_out_seen: AtomicBool,
    /// Set once the "media flowing both directions" INFO has been emitted.
    both_ways_logged: AtomicBool,
    pub rx_packets: AtomicU64,
    pub rx_bytes: AtomicU64,
    /// DTLS datagrams dropped because no DTLS receiver was registered yet
    /// (or it was torn down). Surfaced for handshake-stall diagnostics.
    dtls_no_receiver_drops: AtomicU64,
    pub tx_packets: AtomicU64,
    pub tx_bytes: AtomicU64,
    /// Candidate state during the brief probation window before latch commits.
    /// Set to `Some` when `latch_on_rtp` is enabled, `None` once latched
    /// (or when not using probation-mode latching).
    probation: Mutex<Option<RtpProbationState>>,
    /// Maximum packets to observe during probation.  `0` means "no probation"
    /// — first SSRC-matching RTP latches immediately (legacy behaviour).
    probation_max_packets: AtomicU8,
    /// Steady-state competitive re-latch probe for a new source address.
    /// `Some` while a candidate is accumulating the consecutive packets
    /// required to take over the latched egress path, `None` otherwise.
    relatch_probe: Mutex<Option<RelatchProbe>>,
    /// Cheap gate so the steady-state inbound path never locks the probe
    /// mutex: `true` iff `relatch_probe` is `Some`.
    probe_active: AtomicBool,
    /// Monotonic ms of the last committed re-latch (cooldown basis), 0 = never.
    last_relatch_ms: AtomicU64,
    /// Committed competitive re-latches this session.
    relatch_count: AtomicU8,
    /// Upper-layer sink for [`SourceChange`] notifications (latch commits).
    source_change_tx: Mutex<Option<mpsc::UnboundedSender<SourceChange>>>,
    /// Two-packet hysteresis for non-mux RTCP latching (addr, packets seen).
    rtcp_probe: Mutex<Option<(SocketAddr, u8)>>,
    /// Warn-once flag for the exhausted re-latch budget.
    relatch_budget_warned: AtomicBool,
    /// Construction time — origin of the monotonic ms clock used by the
    /// re-latch windows (no_std-safe: logical clock via `platform::time`).
    created: Instant,
    /// Added to `created.elapsed()` by tests to jump past cooldowns and
    /// windows without sleeping in real time.
    clock_offset_ms: AtomicU64,
    /// Lazily-initialised queue for transports without a synchronous send
    /// (TURN / TCP / TLS): the RTP bridge fast-path hands packets here and a
    /// spawned task drains them through the async `send_to`. Without this the
    /// fast-path dropped every packet on Relay paths ("call connected but no
    /// audio").
    deferred_send_tx: OnceLock<mpsc::UnboundedSender<(IceSocketWrapper, Vec<u8>, SocketAddr)>>,
}

impl IceConn {
    pub fn new(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
        label: Option<String>,
    ) -> Arc<Self> {
        Self::new_with_rtcp(socket_rx.clone(), socket_rx, remote_addr, label, None)
    }

    pub(crate) fn new_with_rtcp(
        socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        rtcp_socket_rx: watch::Receiver<Option<IceSocketWrapper>>,
        remote_addr: SocketAddr,
        label: Option<String>,
        probation_max_packets: Option<u8>,
    ) -> Arc<Self> {
        Arc::new(Self {
            diagnostics: Arc::new(Default::default()),
            socket_rx,
            rtcp_socket_rx,
            remote_addr: RwLock::new(remote_addr),
            remote_rtcp_addr: RwLock::new(None),
            dtls_receiver: RwLock::new(None),
            rtp_receiver: RwLock::new(None),
            latch_on_rtp: AtomicBool::new(false),
            rtp_latched: AtomicBool::new(false),
            rtcp_latched: AtomicBool::new(false),
            expected_ssrc: AtomicU32::new(0),
            rtp_rx_count: AtomicU64::new(0),
            label,
            first_rtp_rx_logged: AtomicBool::new(false),
            first_rtcp_rx_logged: AtomicBool::new(false),
            first_out_seen: AtomicBool::new(false),
            both_ways_logged: AtomicBool::new(false),
            rx_packets: AtomicU64::new(0),
            rx_bytes: AtomicU64::new(0),
            dtls_no_receiver_drops: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            tx_bytes: AtomicU64::new(0),
            probation: Mutex::new(None),
            probation_max_packets: AtomicU8::new(probation_max_packets.unwrap_or(0)),
            relatch_probe: Mutex::new(None),
            probe_active: AtomicBool::new(false),
            last_relatch_ms: AtomicU64::new(0),
            relatch_count: AtomicU8::new(0),
            source_change_tx: Mutex::new(None),
            rtcp_probe: Mutex::new(None),
            relatch_budget_warned: AtomicBool::new(false),
            created: Instant::now(),
            clock_offset_ms: AtomicU64::new(0),
            deferred_send_tx: OnceLock::new(),
        })
    }

    pub fn set_deferred_send_observer(
        &self,
        observer: Arc<crate::stats::packet::DeferredSendObserver>,
    ) {
        self.diagnostics.deferred_observer.get_or_init(|| observer);
    }

    pub(crate) fn packet_diagnostics(&self) -> crate::stats::packet::IceConnDiagnostics {
        let mut snapshot = self.diagnostics.snapshot();
        snapshot.received = self
            .diagnostics
            .received
            .snapshot_count(self.rx_packets.load(Ordering::Relaxed));
        snapshot.received.bytes = self.rx_bytes.load(Ordering::Relaxed);
        snapshot.dtls_no_receiver = self
            .diagnostics
            .dtls_no_receiver
            .snapshot_count(self.dtls_no_receiver_drops.load(Ordering::Relaxed));
        snapshot.selected_socket = self.socket_rx.borrow().as_ref().map(|socket| {
            match socket {
                IceSocketWrapper::Udp(_) => "udp",
                IceSocketWrapper::SharedUdp(_) => "shared_udp",
                IceSocketWrapper::Turn(_, _) => "turn",
                IceSocketWrapper::Platform(_) => "platform",
                #[cfg(feature = "std")]
                IceSocketWrapper::TcpStream(_, _, _) => "tcp",
                #[cfg(feature = "std")]
                IceSocketWrapper::TcpListener(_) => "tcp_listener",
            }
            .to_string()
        });
        snapshot.rtp_latched = self.rtp_latched.load(Ordering::Relaxed);
        snapshot.rtcp_latched = self.rtcp_latched.load(Ordering::Relaxed);
        snapshot
    }

    pub fn set_probation_max_packets(&self, max: Option<u8>) {
        self.probation_max_packets
            .store(max.unwrap_or(0), Ordering::Relaxed);
    }

    /// Install the upper-layer sink for [`SourceChange`] notifications.
    /// Called by the `PeerConnection` when it wires up this connection; the
    /// events are delivered to the registered `RtpObserver`s via
    /// `RtpObserver::on_source_change`.
    pub fn set_source_change_sender(&self, tx: mpsc::UnboundedSender<SourceChange>) {
        *self.source_change_tx.lock() = Some(tx);
    }

    /// Number of competitive re-latches committed so far this session.
    pub fn relatch_count(&self) -> u8 {
        self.relatch_count.load(Ordering::Relaxed)
    }

    /// Monotonic milliseconds relative to construction (no_std-safe: the
    /// logical clock from `platform::time`), plus the test clock offset.
    /// Deliberately never 0 — 0 is the "never" sentinel for
    /// `last_relatch_ms` (a fresh test connection observes at t≈0).
    fn now_ms(&self) -> u64 {
        self.created.elapsed().as_millis() as u64 + self.clock_offset_ms.load(Ordering::Relaxed) + 1
    }

    /// Test-only: advance the re-latch clock past cooldowns / windows
    /// without sleeping in real time.
    #[cfg(test)]
    pub(crate) fn test_advance_clock_ms(&self, ms: u64) {
        self.clock_offset_ms.fetch_add(ms, Ordering::Relaxed);
    }

    /// Emit a source-change notification to the upper layer (best effort —
    /// a missing/unreachable sink never affects the media path).
    fn notify_source_change(&self, from: SocketAddr, to: SocketAddr, ssrc: u32, switch: u8) {
        if let Some(tx) = self.source_change_tx.lock().as_ref() {
            let _ = tx.send(SourceChange {
                from,
                to,
                ssrc,
                switch,
            });
        }
    }

    /// Commit an egress destination: set the remote, mark latched, notify
    /// observers.  `switch` is 0 for the initial latch, 1.. for re-latches.
    fn commit_latch(&self, from: SocketAddr, to: SocketAddr, ssrc: u32, switch: u8, reason: &str) {
        if to != from {
            *self.remote_addr.write() = to;
        }
        self.rtp_latched.store(true, Ordering::Relaxed);
        tracing::info!("IceConn: RTP latched to {} ({})", to, reason);
        self.notify_source_change(from, to, ssrc, switch);
    }

    /// Pre-latch probation: attribute the packet to a candidate source and
    /// pick a winner once persistence or the observation budget says so.
    /// Thresholds favour availability pre-latch (3 packets in a row) over
    /// post-latch defence (4, see `RELATCH_PACKETS`).
    fn latch_probation(
        &self,
        addr: SocketAddr,
        pkt_ssrc: u32,
        seq: u16,
        marker: bool,
        expected: u32,
    ) {
        let current_remote = *self.remote_addr.read();
        let mut probation_guard = self.probation.lock();
        if let Some(ref mut prob) = *probation_guard {
            let pos = prob.candidates.iter().position(|c| c.addr == addr);
            let mut credited = true;
            match pos {
                Some(i) => {
                    let c = &mut prob.candidates[i];
                    // Identity is ip:port + SSRC: a drifted SSRC earns no
                    // credit and does not advance the probation budget.
                    if pkt_ssrc != c.ssrc {
                        credited = false;
                    } else {
                        if seq_is_next(c.last_seq, seq) {
                            c.consecutive_count = c.consecutive_count.saturating_add(1);
                        } else {
                            // Non-sequential — reset run
                            c.consecutive_count = 0;
                        }
                        c.last_seq = seq;
                        c.packet_count = c.packet_count.saturating_add(1);
                        if marker {
                            c.has_marker = true;
                        }
                        if seq_before(seq, c.first_seq) {
                            c.first_seq = seq;
                        }
                    }
                }
                None => {
                    prob.candidates.push(RtpCandidateState {
                        addr,
                        ssrc: pkt_ssrc,
                        first_seq: seq,
                        last_seq: seq,
                        packet_count: 1,
                        consecutive_count: 0,
                        has_marker: marker,
                    });
                }
            }

            if !credited {
                return;
            }

            prob.total_packets = prob.total_packets.saturating_add(1);
            let total = prob.total_packets;
            let winner: Option<SocketAddr> = if total >= prob.max_packets {
                // Timeout fallback: the candidate with the most packets
                // wins; ties broken by marker, then by earliest first_seq
                // in wrapping order.
                prob.candidates
                    .iter()
                    .max_by(|a, b| {
                        a.packet_count
                            .cmp(&b.packet_count)
                            .then(a.has_marker.cmp(&b.has_marker))
                            .then_with(|| {
                                if seq_before(b.first_seq, a.first_seq) {
                                    // a starts earlier → a ranks higher
                                    core::cmp::Ordering::Greater
                                } else if seq_before(a.first_seq, b.first_seq) {
                                    core::cmp::Ordering::Less
                                } else {
                                    core::cmp::Ordering::Equal
                                }
                            })
                    })
                    .map(|c| c.addr)
            } else if total >= 3 {
                // Consecutive dominance: at least 2 consecutive packets
                // from one source and at least 3 total observed.  A marker
                // packet alone is deliberately not enough — persistence
                // is required before the egress address moves.
                prob.candidates
                    .iter()
                    .find(|c| c.consecutive_count >= 2)
                    .map(|c| c.addr)
            } else {
                None
            };

            if let Some(win_addr) = winner {
                // Drop the probation state so the steady-state path never
                // locks this Mutex again.
                *probation_guard = None;
                drop(probation_guard);
                self.commit_latch(
                    current_remote,
                    win_addr,
                    pkt_ssrc,
                    0,
                    &format!("probation, expected_ssrc={expected}, observed={total}"),
                );
            }
        } else {
            // No probation state — immediate latch (legacy path).
            self.commit_latch(
                current_remote,
                addr,
                pkt_ssrc,
                0,
                &format!("immediately, expected_ssrc={expected}"),
            );
        }
    }

    /// Steady-state observation for the competitive re-latch, called for
    /// every SSRC-matching RTP packet once the initial latch has committed.
    /// A new source takes over only after `RELATCH_PACKETS` consecutive
    /// packets carrying one SSRC inside the probe window; the incumbent's
    /// packets reset the probe.
    fn observe_relatch(&self, addr: SocketAddr, ssrc: u32, seq: u16) {
        let current = *self.remote_addr.read();

        if addr == current {
            // Hot path: gate on the flag so incumbents never lock the probe.
            if self.probe_active.swap(false, Ordering::Relaxed)
                && self.relatch_probe.lock().take().is_some()
            {
                tracing::debug!("IceConn: re-latch probe cleared — incumbent source alive");
            }
            return;
        }

        let now = self.now_ms();

        // Budget: past the switch cap the egress address is frozen until
        // signaling retargets it (reset_latch).
        let switches = self.relatch_count.load(Ordering::Relaxed);
        if switches >= RELATCH_MAX_SWITCHES {
            if !self.relatch_budget_warned.swap(true, Ordering::Relaxed) {
                tracing::warn!(
                    "IceConn: RTP from {} ignored — re-latch budget exhausted \
                     ({}/{} switches); signaling required to retarget",
                    addr, switches, RELATCH_MAX_SWITCHES
                );
            }
            return;
        }

        // Cooldown: suppress flapping right after a committed switch.
        let last = self.last_relatch_ms.load(Ordering::Relaxed);
        if last != 0 {
            let since = now.saturating_sub(last);
            if since < RELATCH_COOLDOWN_MS {
                tracing::debug!(
                    "IceConn: re-latch probe from {} suppressed by cooldown \
                     ({} ms left)",
                    addr,
                    RELATCH_COOLDOWN_MS - since
                );
                return;
            }
        }

        let mut guard = self.relatch_probe.lock();
        let run_advanced = match guard.as_mut() {
            Some(p) if p.addr == addr && p.ssrc == ssrc => {
                if now.saturating_sub(p.first_seen_ms) > RELATCH_WINDOW_MS {
                    // Stale probe (a trickle, not a live flow) — restart.
                    *p = RelatchProbe::new(addr, ssrc, seq, now);
                    false
                } else if seq_is_next(p.last_seq, seq) {
                    p.last_seq = seq;
                    p.last_seen_ms = now;
                    p.consecutive = p.consecutive.saturating_add(1);
                    true
                } else {
                    // Out-of-order / retransmission — the run restarts.
                    p.last_seq = seq;
                    p.last_seen_ms = now;
                    p.consecutive = 1;
                    false
                }
            }
            _ => {
                // New contender.  Identity is addr+SSRC, so a source whose
                // SSRC drifts keeps restarting its probe.
                *guard = Some(RelatchProbe::new(addr, ssrc, seq, now));
                self.probe_active.store(true, Ordering::Relaxed);
                tracing::debug!(
                    "IceConn: re-latch probe started from {} (ssrc={}, need {} consecutive)",
                    addr, ssrc, RELATCH_PACKETS
                );
                false
            }
        };

        if !run_advanced {
            return;
        }
        let commit = {
            let p = guard.as_ref().expect("probe just updated");
            p.consecutive >= RELATCH_PACKETS
        };
        if commit {
            let (probe_addr, probe_ssrc) = {
                let p = guard.as_ref().expect("probe just updated");
                (p.addr, p.ssrc)
            };
            *guard = None;
            drop(guard);
            self.probe_active.store(false, Ordering::Relaxed);
            self.last_relatch_ms.store(now, Ordering::Relaxed);
            let switch = self.relatch_count.fetch_add(1, Ordering::Relaxed) + 1;
            self.commit_latch(
                current,
                probe_addr,
                probe_ssrc,
                switch,
                &format!(
                    "re-latch, {RELATCH_PACKETS} consecutive, switch {switch}/{RELATCH_MAX_SWITCHES}"
                ),
            );
        }
    }

    /// Record that the first outbound RTP was written to the wire. Called by
    /// `RtpTransport` after its first successful send.
    pub fn mark_first_outbound(&self) {
        if self.first_out_seen.swap(true, Ordering::Relaxed) {
            return;
        }
        let label_str = self.label.as_deref().unwrap_or("unknown");
        tracing::trace!("IceConn: first outbound RTP sent label={}", label_str);
        self.maybe_log_both_ways(label_str);
    }

    /// Single TRACE "media confirmed both directions" emitted once outbound and
    /// inbound (RTP or RTCP) traffic have both been observed on this connection.
    fn maybe_log_both_ways(&self, label_str: &str) {
        if self.both_ways_logged.load(Ordering::Relaxed) {
            return;
        }
        let inbound_seen = self.first_rtp_rx_logged.load(Ordering::Relaxed)
            || self.first_rtcp_rx_logged.load(Ordering::Relaxed);
        if self.first_out_seen.load(Ordering::Relaxed)
            && inbound_seen
            && self
                .both_ways_logged
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
        {
            tracing::trace!(
                "IceConn: media confirmed both directions (outbound + inbound) label={}",
                label_str
            );
        }
    }

    pub fn enable_latch_on_rtp(&self) {
        self.latch_on_rtp.store(true, Ordering::Relaxed);
        let max = self.probation_max_packets.load(Ordering::Relaxed);
        if max > 0 {
            // Initialise the probation state so candidate observation begins.
            let mut p = self.probation.lock();
            if p.is_none() {
                *p = Some(RtpProbationState {
                    candidates: Vec::new(),
                    total_packets: 0,
                    max_packets: max,
                });
            }
        } else {
            // max == 0 → immediate latch, no probation state
            self.probation.lock().take();
        }
    }

    /// Set the expected SSRC from the remote answer SDP.
    /// When set, RTP latching uses SSRC match instead of source-address
    /// mismatch, allowing latch to succeed even when NAT changes the port.
    pub fn set_expected_ssrc(&self, ssrc: u32) {
        self.expected_ssrc.store(ssrc, Ordering::Relaxed);
    }

    pub fn set_remote_rtcp_addr(&self, addr: Option<SocketAddr>) {
        *self.remote_rtcp_addr.write() = addr;
        self.rtcp_latched.store(false, Ordering::Relaxed);
        self.rtcp_probe.lock().take();
    }

    /// Returns the local socket address (the bind address of the current
    /// ICE socket). Returns `0.0.0.0:0` when the socket is not yet available
    /// (e.g., during ICE candidate gathering).
    pub fn local_addr(&self) -> SocketAddr {
        let socket = self.socket_rx.borrow();
        match socket.as_ref() {
            Some(IceSocketWrapper::Udp(s)) => s
                .local_addr()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
            Some(IceSocketWrapper::SharedUdp(h)) => h
                .local_addr()
                .unwrap_or(SocketAddr::from(([0, 0, 0, 0], 0))),
            _ => SocketAddr::from(([0, 0, 0, 0], 0)),
        }
    }

    pub(crate) fn set_remote_addr_from_selected_pair(
        &self,
        addr: SocketAddr,
        reason: &'static str,
    ) {
        let current = *self.remote_addr.read();
        if self.latch_on_rtp.load(Ordering::Relaxed)
            && self.rtp_latched.load(Ordering::Relaxed)
            && current != addr
        {
            warn!(
                "IceConn: preserving latched RTP remote {} instead of selected-pair remote {} ({})",
                current, addr, reason
            );
            return;
        }

        if current != addr {
            debug!(
                "IceConn: selected-pair remote changed {} -> {} ({})",
                current, addr, reason
            );
        }
        *self.remote_addr.write() = addr;
    }

    pub(crate) fn set_remote_addr_from_signaling(&self, addr: SocketAddr, reason: &'static str) {
        self.reset_latch();
        *self.remote_addr.write() = addr;
        trace!(
            "IceConn: signaling RTP remote set to {} ({}), latch reset",
            addr, reason
        );
    }

    /// Reset latching state before applying a remote SDP so a new source can
    /// be selected. Clears both the latch flag and any in-progress probation,
    /// plus the re-latch probe, RTCP probe and cooldown (a fresh negotiation
    /// starts a fresh media path; the switch budget stays session-scoped).
    pub fn reset_latch(&self) {
        self.rtp_latched.store(false, Ordering::Relaxed);
        self.rtcp_latched.store(false, Ordering::Relaxed);
        self.relatch_probe.lock().take();
        self.probe_active.store(false, Ordering::Relaxed);
        self.rtcp_probe.lock().take();
        self.last_relatch_ms.store(0, Ordering::Relaxed);
        self.relatch_budget_warned.store(false, Ordering::Relaxed);
        let max = self.probation_max_packets.load(Ordering::Relaxed);
        *self.probation.lock() = if self.latch_on_rtp.load(Ordering::Relaxed) && max > 0 {
            Some(RtpProbationState {
                candidates: Vec::new(),
                total_packets: 0,
                max_packets: max,
            })
        } else {
            None
        };
    }

    pub fn set_dtls_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.dtls_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    pub fn set_rtp_receiver(&self, receiver: Arc<dyn PacketReceiver>) {
        *self.rtp_receiver.write() = Some(Arc::downgrade(&receiver));
    }

    /// Non-blocking variant of `send`. Skips the `writable().await` parking
    /// and simply returns `Err` when the kernel socket buffer is full. Used by
    /// the RTP bridge fast-path so the receive loop never suspends on send.
    pub fn try_send(&self, buf: &[u8]) -> RtcResult<usize> {
        self.diagnostics.send_attempts.record(buf.len());
        if should_drop_packet() {
            self.diagnostics.send_simulated_drop.record(buf.len());
            return Ok(buf.len());
        }
        let socket = self.socket_rx.borrow().clone();
        let Some(socket) = socket else {
            // Fallback: try the latest value
            let mut socket_rx = self.socket_rx.clone();
            let socket = socket_rx.borrow_and_update().clone();
            let Some(socket) = socket else {
                self.diagnostics.send_errors.record(buf.len());
                tracing::trace!("IceConn: try_send failed - no selected socket");
                return Err(RtcError::Internal(format!("No selected socket")));
            };
            return self.do_try_send(socket, buf);
        };
        self.do_try_send(socket, buf)
    }

    fn do_try_send(&self, socket: IceSocketWrapper, buf: &[u8]) -> RtcResult<usize> {
        let remote = *self.remote_addr.read();
        if remote.port() == 0 {
            self.diagnostics.send_errors.record(buf.len());
            return Err(RtcError::Internal(format!("Remote address not set")));
        }
        match &socket {
            IceSocketWrapper::Udp(_) | IceSocketWrapper::SharedUdp(_) => {
                let n = socket
                    .try_send_to(buf, remote)
                    .inspect_err(|_| self.diagnostics.send_errors.record(buf.len()))?;
                self.diagnostics.send_sync_success.record(n);
                // Keep legacy transport totals intact; diagnostics includes this fast path.
                Ok(n)
            }
            // TURN relay / TCP / TLS only expose async sends: queue the packet
            // for a background task instead of failing (and dropping) forever.
            _ => {
                self.defer_async_send(socket, buf, remote);
                Ok(buf.len())
            }
        }
    }

    /// Queue `buf` for asynchronous transmission on `socket`. The drain task is
    /// spawned on first use and exits when `self` (and therefore the channel
    /// sender) is dropped. Unbounded on purpose: this is the audio path, and
    /// dropping on a full queue is exactly the failure mode being fixed.
    fn defer_async_send(&self, socket: IceSocketWrapper, buf: &[u8], addr: SocketAddr) {
        let tx = self.deferred_send_tx.get_or_init(|| {
            let (tx, mut rx) = mpsc::unbounded_channel::<(IceSocketWrapper, Vec<u8>, SocketAddr)>();
            let diagnostics = self.diagnostics.clone();
            task::spawn(async move {
                while let Some((socket, buf, addr)) = rx.recv().await {
                    let result = socket.send_to(&buf, addr).await;
                    if let Ok(n) = &result {
                        diagnostics.send_async_completed.record(*n);
                        diagnostics
                            .deferred_completed
                            .fetch_add(1, Ordering::Relaxed);
                    }
                    let failed = result.is_err();
                    if let Err(e) = result {
                        {
                            diagnostics.deferred_errors.fetch_add(1, Ordering::Relaxed);
                            diagnostics.send_errors.record(buf.len());
                        }
                        debug!(
                            error = %e,
                            "IceConn: deferred async send failed (relay fast-path fallback)"
                        );
                    }
                    {
                        diagnostics.deferred_pending.fetch_sub(1, Ordering::Release);
                        diagnostics.deferred_result(addr, failed);
                    }
                }
            });
            tx
        });
        // Increment before publishing: the worker may complete on another thread.
        self.diagnostics
            .deferred_pending
            .fetch_add(1, Ordering::Relaxed);
        if tx.send((socket, buf.to_vec(), addr)).is_err() {
            self.diagnostics
                .deferred_pending
                .fetch_sub(1, Ordering::Release);
            self.diagnostics.send_queue_closed.record(buf.len());
            trace!("IceConn: deferred send queue closed, dropping packet");
        } else {
            self.diagnostics.send_deferred_queued.record(buf.len());
        }
    }

    pub async fn send(&self, buf: &[u8]) -> RtcResult<usize> {
        self.diagnostics.send_attempts.record(buf.len());
        if should_drop_packet() {
            self.diagnostics.send_simulated_drop.record(buf.len());
            return Ok(buf.len());
        }
        let socket_rx = self.socket_rx.clone();
        let socket_opt = socket_rx.borrow().clone();

        if let Some(socket) = socket_opt {
            let remote = *self.remote_addr.read();
            if remote.port() == 0 {
                self.diagnostics.send_errors.record(buf.len());
                return Err(RtcError::Internal(format!("Remote address not set")));
            }
            let n = socket
                .send_to(buf, remote)
                .await
                .inspect_err(|_| self.diagnostics.send_errors.record(buf.len()))?;
            self.diagnostics.send_async_completed.record(n);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        } else {
            // Fallback: try to update if None
            let mut socket_rx = self.socket_rx.clone();
            let socket_opt = socket_rx.borrow_and_update().clone();
            if let Some(socket) = socket_opt {
                let remote = *self.remote_addr.read();
                if remote.port() == 0 {
                    self.diagnostics.send_errors.record(buf.len());
                    return Err(RtcError::Internal(format!("Remote address not set")));
                }
                let n = socket
                    .send_to(buf, remote)
                    .await
                    .inspect_err(|_| self.diagnostics.send_errors.record(buf.len()))?;
                self.diagnostics.send_async_completed.record(n);
                self.tx_packets.fetch_add(1, Ordering::Relaxed);
                self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
                Ok(n)
            } else {
                self.diagnostics.send_errors.record(buf.len());
                tracing::trace!("IceConn: send failed - no selected socket");
                Err(RtcError::Internal(format!("No selected socket")))
            }
        }
    }

    /// Send multiple DTLS records. On TCP, each record is RFC 4571-framed and all
    /// frames are written in one syscall (avoids Chrome seeing a partial flight).
    pub async fn send_dtls_record_batch(&self, records: &[Vec<u8>]) -> RtcResult<usize> {
        if records.is_empty() {
            return Ok(0);
        }
        let total_payload: usize = records.iter().map(|r| r.len()).sum();
        if should_drop_packet() {
            self.diagnostics
                .send_attempts
                .record_many(records.len() as u64, total_payload);
            self.diagnostics
                .send_simulated_drop
                .record_many(records.len() as u64, total_payload);
            return Ok(total_payload);
        }

        let remote = *self.remote_addr.read();
        if remote.port() == 0 {
            self.diagnostics
                .send_attempts
                .record_many(records.len() as u64, total_payload);
            self.diagnostics
                .send_errors
                .record_many(records.len() as u64, total_payload);
            return Err(RtcError::Internal(format!("Remote address not set")));
        }

        let socket_rx = self.socket_rx.clone();
        let mut socket_opt = socket_rx.borrow().clone();
        if socket_opt.is_none() {
            let mut rx = self.socket_rx.clone();
            socket_opt = rx.borrow_and_update().clone();
        }

        let Some(socket) = socket_opt else {
            self.diagnostics
                .send_attempts
                .record_many(records.len() as u64, total_payload);
            self.diagnostics
                .send_errors
                .record_many(records.len() as u64, total_payload);
            tracing::trace!("IceConn: send_dtls_record_batch failed - no selected socket");
            return Err(RtcError::Internal(format!("No selected socket")));
        };

        self.tx_packets
            .fetch_add(records.len() as u64, Ordering::Relaxed);

        match &socket {
            #[cfg(feature = "std")]
            IceSocketWrapper::TcpStream(_, write, _) => {
                self.diagnostics
                    .send_attempts
                    .record_many(records.len() as u64, total_payload);
                let mut framed = Vec::new();
                for record in records {
                    if record.len() > 0xFFFF {
                        self.diagnostics
                            .send_errors
                            .record_many(records.len() as u64, total_payload);
                        return Err(RtcError::Internal(format!(
                            "DTLS record too large for TCP framing"
                        )));
                    }
                    framed.extend_from_slice(&(record.len() as u16).to_be_bytes());
                    framed.extend_from_slice(record);
                }
                super::tcp_write_all(write, &framed)
                    .await
                    .inspect_err(|_| {
                        self.diagnostics
                            .send_errors
                            .record_many(records.len() as u64, total_payload);
                    })?;
                self.diagnostics
                    .send_async_completed
                    .record_many(records.len() as u64, framed.len());
                self.tx_bytes
                    .fetch_add(framed.len() as u64, Ordering::Relaxed);
                Ok(total_payload)
            }
            _ => {
                let mut total = 0usize;
                for record in records {
                    total += self.send(record).await?;
                }
                Ok(total)
            }
        }
    }

    pub async fn send_rtcp(&self, buf: &[u8]) -> RtcResult<usize> {
        self.diagnostics.send_attempts.record(buf.len());
        let rtcp_addr = *self.remote_rtcp_addr.read();
        let remote = if let Some(rtcp_addr) = rtcp_addr {
            rtcp_addr
        } else {
            *self.remote_addr.read()
        };

        if remote.port() == 0 {
            self.diagnostics.send_errors.record(buf.len());
            return Err(RtcError::Internal(format!("Remote address not set")));
        }

        let mut socket_rx = if rtcp_addr.is_some() {
            self.rtcp_socket_rx.clone()
        } else {
            self.socket_rx.clone()
        };
        let mut socket_opt = socket_rx.borrow().clone();
        if socket_opt.is_none() {
            socket_opt = socket_rx.borrow_and_update().clone();
        }

        if socket_opt.is_none() && rtcp_addr.is_some() {
            #[allow(unused_mut)]
            let mut fallback_rx = self.socket_rx.clone();
            socket_opt = fallback_rx.borrow().clone();
            if socket_opt.is_none() {
                socket_opt = fallback_rx.borrow_and_update().clone();
            }
        }

        if let Some(socket) = socket_opt {
            let n = socket
                .send_to(buf, remote)
                .await
                .inspect_err(|_| self.diagnostics.send_errors.record(buf.len()))?;
            self.diagnostics.send_async_completed.record(n);
            self.tx_packets.fetch_add(1, Ordering::Relaxed);
            self.tx_bytes.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        } else {
            self.diagnostics.send_errors.record(buf.len());
            tracing::trace!("IceConn: send_rtcp failed - no selected socket");
            Err(RtcError::Internal(format!("No selected socket")))
        }
    }
}

#[async_trait]
impl PacketReceiver for IceConn {
    async fn receive(&self, packet: Bytes, addr: SocketAddr, marshal_buf: &mut Vec<u8>) {
        if packet.is_empty() {
            return;
        }

        self.diagnostics.received.mark(packet.len());
        self.rx_packets.fetch_add(1, Ordering::Relaxed);
        self.rx_bytes
            .fetch_add(packet.len() as u64, Ordering::Relaxed);

        let first_byte = packet[0];
        // Scope for read lock
        let current_remote = *self.remote_addr.read();

        // Passive ICE-TCP: the browser often omits TCP candidates in SDP and
        // connects inbound. Latch the real peer from the first packet on the
        // accepted stream so DTLS/RTP replies use the correct destination.
        let socket_is_inbound_tcp = {
            #[cfg_attr(not(feature = "std"), allow(unused_variables))]
            let socket_rx = self.socket_rx.clone();
            #[cfg(feature = "std")]
            {
                matches!(
                    socket_rx.borrow().as_ref(),
                    Some(IceSocketWrapper::TcpStream(_, _, _))
                )
            }
            #[cfg(not(feature = "std"))]
            {
                false
            }
        };
        if current_remote.port() == 0 || (socket_is_inbound_tcp && current_remote != addr) {
            *self.remote_addr.write() = addr;
        } else if addr != current_remote {
            // Note: We no longer automatically switch the remote address just by receiving
            // a packet from a new source (e.g. DTLS). This prevents "path flapping"
            // that can confuse the transport Layer. The remote address should only
            // be updated via the ICE nomination process.
            tracing::trace!(
                "IceConn: Received packet from new address {:?} (byte={}) - ignoring address change",
                addr,
                first_byte
            );
        }

        if (20..64).contains(&first_byte) {
            // DTLS
            self.diagnostics.dtls.record(packet.len());
            let receiver = {
                let rx_lock = self.dtls_receiver.read();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                // tracing::trace!("IceConn: Forwarding DTLS packet to receiver");
                strong_rx.receive(packet, addr, marshal_buf).await;
            } else {
                self.diagnostics.dtls_no_receiver.mark(packet.len());
                let drops = self.dtls_no_receiver_drops.fetch_add(1, Ordering::Relaxed) + 1;
                debug!(
                    drops,
                    len = packet.len(),
                    from = %addr,
                    "IceConn: Received DTLS packet but no receiver registered — dropped"
                );
            }
        } else if (128..192).contains(&first_byte) {
            // RTP / RTCP
            let is_rtcp = packet.len() >= 2 && (200..=211).contains(&packet[1]);
            if is_rtcp {
                self.diagnostics.rtcp.record(packet.len());
            } else {
                self.diagnostics.rtp.record(packet.len());
            }

            if self.latch_on_rtp.load(Ordering::Relaxed) {
                if is_rtcp {
                    // RTCP may teach the RTCP destination in non-mux mode, but it must
                    // never override the RTP remote address.  A *new* RTCP source must
                    // repeat itself before taking over — one packet must not move
                    // the destination.
                    let mut remote_rtcp_addr = self.remote_rtcp_addr.write();
                    if let Some(current_rtcp_remote) = *remote_rtcp_addr
                        && addr != current_rtcp_remote
                        && !self.rtcp_latched.load(Ordering::Relaxed)
                    {
                        let mut probe = self.rtcp_probe.lock();
                        let seen = match *probe {
                            Some((seen_addr, n)) if seen_addr == addr => n + 1,
                            _ => 1,
                        };
                        if seen >= RTCP_LATCH_PACKETS {
                            *remote_rtcp_addr = Some(addr);
                            self.rtcp_latched.store(true, Ordering::Relaxed);
                            *probe = None;
                            tracing::debug!(
                                "IceConn: RTCP latched to {} after {} packets",
                                addr, seen
                            );
                        } else {
                            *probe = Some((addr, seen));
                        }
                    }
                } else if packet.len() >= 12 {
                    let expected = self.expected_ssrc.load(Ordering::Relaxed);
                    let pkt_ssrc =
                        u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]);

                    let ssrc_ok = expected == 0 || pkt_ssrc == expected;

                    if ssrc_ok {
                        let seq = u16::from_be_bytes([packet[2], packet[3]]);
                        let marker = (packet[1] & 0x80) != 0;

                        if self.rtp_latched.load(Ordering::Relaxed) {
                            // Steady state: a different source may take over
                            // the egress path only by proving persistence
                            // (competitive re-latch).  Packets from the
                            // incumbent keep the latch healthy instead.
                            self.observe_relatch(addr, pkt_ssrc, seq);
                        } else {
                            self.latch_probation(addr, pkt_ssrc, seq, marker, expected);
                        }
                    }
                }
            }
            let receiver = {
                let rx_lock = self.rtp_receiver.read();
                if let Some(rx) = &*rx_lock {
                    rx.upgrade()
                } else {
                    None
                }
            };

            if let Some(strong_rx) = receiver {
                self.rtp_rx_count.fetch_add(1, Ordering::Relaxed);
                let label_str = self.label.as_deref().unwrap_or("unknown");
                if is_rtcp {
                    if self
                        .first_rtcp_rx_logged
                        .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        tracing::debug!(
                            "IceConn: first inbound RTCP ({} bytes) from {} label={} — remote alive",
                            packet.len(),
                            addr,
                            label_str
                        );
                    }
                } else if self
                    .first_rtp_rx_logged
                    .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                    .is_ok()
                {
                    tracing::debug!(
                        "IceConn: first inbound RTP ({} bytes) from {} label={}",
                        packet.len(),
                        addr,
                        label_str
                    );
                }
                self.maybe_log_both_ways(label_str);
                strong_rx.receive(packet, addr, marshal_buf).await;
            } else {
                self.diagnostics.rtp_no_receiver.record(packet.len());
                trace!(
                    "IceConn: No RTP receiver registered for packet from {}",
                    addr
                );
            }
        } else {
            self.diagnostics.unknown.record(packet.len());
        }
    }
}

impl StatsProvider for IceConn {
    fn collect(&self) -> RtcResult<Vec<StatsEntry>> {
        let rx_packets = self.rx_packets.load(Ordering::Relaxed);
        let rx_bytes = self.rx_bytes.load(Ordering::Relaxed);
        let tx_packets = self.tx_packets.load(Ordering::Relaxed);
        let tx_bytes = self.tx_bytes.load(Ordering::Relaxed);
        let label = self.label.as_deref().unwrap_or("unknown");
        let remote = *self.remote_addr.read();
        let id = StatsId::new(format!("ice-conn-{}", label));
        let entry = StatsEntry::new(id, StatsKind::Transport)
            .with_value("label", json!(label))
            .with_value("rxPackets", json!(rx_packets))
            .with_value(
                "dtlsNoReceiverDrops",
                json!(self.dtls_no_receiver_drops.load(Ordering::Relaxed)),
            )
            .with_value("rxBytes", json!(rx_bytes))
            .with_value("txPackets", json!(tx_packets))
            .with_value("txBytes", json!(tx_bytes))
            .with_value("srcAddr", json!(remote.to_string()))
            .with_value(
                "relatchCount",
                json!(self.relatch_count.load(Ordering::Relaxed)),
            );
        Ok(vec![entry])
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use bytes::Bytes;
    use core::net::{IpAddr, Ipv4Addr};
    use tokio::io::AsyncReadExt;
    use tokio::io::AsyncWriteExt;
    use tokio::net::UdpSocket;
    use tokio::sync::watch;

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_mux() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(Arc::new(socket));
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let conn = IceConn::new(rx, receiver_addr, None);

        // Send RTCP (via send_rtcp) -> should go to receiver_addr (default)
        conn.send_rtcp(b"hello").await.unwrap();

        let mut buf = [0u8; 1024];
        let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"hello");
    }

    /// Regression: the RTP bridge fast-path used to drop every packet on a
    /// non-`Udp` transport because `IceSocketWrapper::try_send_to` returned
    /// "not supported" (the "call connected but no audio" Relay-path bug).
    /// Shared (muxed) UDP is such a transport — `try_send` must still deliver.
    #[tokio::test]
    async fn test_try_send_delivers_on_shared_udp_transport() {
        // `acquire` keys the shared-port registry by the requested address, so
        // reserve a concrete loopback port first instead of using port 0.
        let probe = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let bind_addr = probe.local_addr().unwrap();
        drop(probe);

        let (_local, handle, _guard) =
            crate::transports::ice::shared_udp::acquire(bind_addr, "fastpath-test".to_string())
                .await
                .unwrap();
        // tokio's `try_send_to` reports WouldBlock until the reactor has marked
        // the socket writable; in production the socket is already actively
        // receiving, so this only matters for the test's fresh socket.
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::SharedUdp(Arc::new(handle))));

        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();
        let conn = IceConn::new(rx, receiver_addr, None);

        // (trait sockets have no `writable()`; the tokio socket behind the
        // test mux is immediately writable after bind)
        tokio::time::sleep(core::time::Duration::from_millis(50)).await;
        conn.try_send(b"relayed")
            .expect("fast-path send must not fail on shared UDP");

        let mut buf = [0u8; 32];
        let (len, _) = tokio::time::timeout(
            core::time::Duration::from_millis(500),
            receiver.recv_from(&mut buf),
        )
        .await
        .expect("shared-UDP fast-path send must deliver")
        .unwrap();
        assert_eq!(&buf[..len], b"relayed");
    }

    /// Same regression for the transports that have **no** synchronous send
    /// (TURN / TCP / TLS) — the production Relay-path case. `try_send` must
    /// queue through the deferred async sender instead of returning Err.
    #[tokio::test]
    async fn test_try_send_defers_on_non_udp_transport() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let mut client = tokio::net::TcpStream::connect(listen_addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let (read, write) = server.into_split();

        let wrapper = IceSocketWrapper::TcpStream(
            Arc::new(tokio::sync::Mutex::new(read)),
            Arc::new(tokio::sync::Mutex::new(write)),
            peer,
        );
        let (_tx, rx) = watch::channel(Some(wrapper));
        let conn = IceConn::new(rx, peer, None);

        // Non-UDP: must be accepted (queued for async send), not rejected.
        conn.try_send(b"relayed")
            .expect("fast-path send must not fail on non-UDP transport");

        // The async drain task writes a 2-byte big-endian length prefix + data.
        let mut header = [0u8; 2];
        tokio::time::timeout(
            core::time::Duration::from_millis(500),
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut header),
        )
        .await
        .expect("deferred fast-path send must deliver")
        .unwrap();
        let n = u16::from_be_bytes(header) as usize;
        let mut body = vec![0u8; n];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut body)
            .await
            .unwrap();
        assert_eq!(&body[..], b"relayed");
        {
            tokio::time::timeout(core::time::Duration::from_secs(1), async {
                while conn.packet_diagnostics().send_async_completed.packets != 1 {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .unwrap();
            let diag = conn.packet_diagnostics();
            assert_eq!(diag.send_attempts.packets, 1);
            assert_eq!(diag.send_deferred_queued.packets, 1);
            assert_eq!(diag.send_async_completed.packets, 1);
            assert_eq!(diag.send_sync_success.packets, 0);
            assert_eq!(diag.send_errors.packets, 0);
        }
    }

    #[tokio::test]
    async fn test_ice_conn_send_rtcp_no_mux() {
        let rtp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtp_socket_addr = rtp_socket.local_addr().unwrap();
        let socket_wrapper = IceSocketWrapper::Udp(rtp_socket);
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let rtcp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let rtcp_socket_addr = rtcp_socket.local_addr().unwrap();
        let rtcp_socket_wrapper = IceSocketWrapper::Udp(rtcp_socket);
        let (_rtcp_tx, rtcp_rx) = watch::channel(Some(rtcp_socket_wrapper));

        let rtp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtp_addr = rtp_receiver.local_addr().unwrap();

        let rtcp_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let rtcp_addr = rtcp_receiver.local_addr().unwrap();

        let conn = IceConn::new_with_rtcp(rx, rtcp_rx, rtp_addr, None, None);
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        // Send RTP (via send) -> should go to rtp_addr
        conn.send(b"rtp").await.unwrap();
        let mut buf = [0u8; 1024];
        let (len, rtp_src) = rtp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtp");
        assert_eq!(rtp_src, rtp_socket_addr);

        // Send RTCP (via send_rtcp) -> should go to rtcp_addr from the RTCP socket.
        conn.send_rtcp(b"rtcp").await.unwrap();
        let (len, rtcp_src) = rtcp_receiver.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..len], b"rtcp");
        assert_eq!(rtcp_src, rtcp_socket_addr);
    }

    #[tokio::test]
    async fn test_changed_signaling_remote_resets_latch_and_retargets_send() {
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let socket_wrapper = IceSocketWrapper::Udp(socket);
        let (_tx, rx) = watch::channel(Some(socket_wrapper));

        let old_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let old_addr = old_receiver.local_addr().unwrap();
        let new_receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let new_addr = new_receiver.local_addr().unwrap();

        let conn = IceConn::new(rx, old_addr, None);
        conn.enable_latch_on_rtp();
        conn.rtp_latched.store(true, Ordering::Relaxed);

        conn.set_remote_addr_from_signaling(new_addr, "test SDP endpoint change");

        assert_eq!(*conn.remote_addr.read(), new_addr);
        assert!(!conn.rtp_latched.load(Ordering::Relaxed));

        conn.send(b"retargeted").await.unwrap();
        let mut buf = [0u8; 32];
        let (len, _) = tokio::time::timeout(
            core::time::Duration::from_millis(100),
            new_receiver.recv_from(&mut buf),
        )
        .await
        .expect("new signaling endpoint should receive RTP")
        .unwrap();
        assert_eq!(&buf[..len], b"retargeted");
        assert!(
            tokio::time::timeout(
                core::time::Duration::from_millis(20),
                old_receiver.recv_from(&mut buf),
            )
            .await
            .is_err(),
            "old signaling endpoint must stop receiving after retarget"
        );
    }

    struct NoopReceiver;

    #[async_trait]
    impl PacketReceiver for NoopReceiver {
        async fn receive(&self, _packet: Bytes, _addr: SocketAddr, _buf: &mut Vec<u8>) {}
    }

    #[tokio::test]
    async fn test_ice_conn_latches_remote_addr_on_rtp() {
        let (_tx, rx) = watch::channel(None);
        let initial_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let latched_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let conn = IceConn::new(rx, initial_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Use a valid 12-byte RTP packet with marker=true (bit 7 of byte 1).
        let pkt = Bytes::from_static(&[
            0x80, 0x80, // V=2, M=1 (marker set)
            0x00, 0x01, // seq=1
            0x00, 0x00, 0x00, 0x01, // ts=1
            0x00, 0x00, 0x00, 0x01, // ssrc=1
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(pkt, latched_addr, &mut marshal_buf).await;

        assert_eq!(*conn.remote_addr.read(), latched_addr);
    }

    #[tokio::test]
    async fn test_rtcp_does_not_override_rtp_remote_addr() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        // Use a valid 12-byte RTP packet with marker=true so probation resolves.
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(rtp_pkt, rtp_src, &mut marshal_buf).await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));

        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(
            Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]),
            rtcp_src,
            &mut marshal_buf,
        )
        .await;

        assert_eq!(
            *conn.remote_addr.read(),
            rtp_src,
            "RTCP should not override RTP remote address"
        );
    }

    #[tokio::test]
    async fn test_rtcp_latches_rtcp_addr_in_non_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let initial_rtcp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(initial_rtcp_addr));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(rtp_pkt, rtp_src, &mut marshal_buf).await;

        let rtcp_pkt = Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]);
        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        // One RTCP packet is not enough to move the RTCP destination…
        conn.receive(rtcp_pkt.clone(), rtcp_src, &mut marshal_buf)
            .await;
        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(initial_rtcp_addr),
            "a single RTCP packet must not re-latch the RTCP destination"
        );
        // …but repetition is the real sender's proof.
        conn.receive(rtcp_pkt, rtcp_src, &mut marshal_buf).await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should latch its own destination after repetition"
        );
        assert!(conn.rtcp_latched.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_rtcp_does_not_re_latch_after_locked() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        conn.set_remote_rtcp_addr(Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4001)));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(rtp_pkt, rtp_src, &mut marshal_buf).await;

        let rtcp_pkt = Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]);
        let rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5001);
        conn.receive(rtcp_pkt.clone(), rtcp_src, &mut marshal_buf)
            .await;
        conn.receive(rtcp_pkt, rtcp_src, &mut marshal_buf).await;
        assert_eq!(*conn.remote_rtcp_addr.read(), Some(rtcp_src));

        let rogue_rtcp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 6001);
        conn.receive(
            Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]),
            rogue_rtcp_src,
            &mut marshal_buf,
        )
        .await;

        assert_eq!(
            *conn.remote_rtcp_addr.read(),
            Some(rtcp_src),
            "RTCP should not re-latch after already latched"
        );
    }

    #[tokio::test]
    async fn test_rtcp_ignored_in_mux_mode() {
        let (_tx, rx) = watch::channel(None);
        let rtp_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000);
        let conn = IceConn::new(rx, rtp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let rtp_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5000);
        let rtp_pkt = Bytes::from_static(&[
            0x80, 0x80, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(rtp_pkt, rtp_src, &mut marshal_buf).await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);

        conn.receive(
            Bytes::from_static(&[0x80, 0xC8, 0x00, 0x00]),
            rtp_src,
            &mut marshal_buf,
        )
        .await;
        assert_eq!(*conn.remote_addr.read(), rtp_src);
        assert!(
            conn.remote_rtcp_addr.read().is_none(),
            "RTCP address should remain None in mux mode"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_port_mismatch() {
        // Simulates the VoLTE/NAT scenario: the answer SDP advertises
        // remote port 4162, but real RTP arrives from port 17687.
        // Latching should succeed because the SSRC matches.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let real_addr: SocketAddr = "112.96.43.157:17687".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Build a minimal 12-byte RTP packet with the matching SSRC.
        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&expected_ssrc.to_be_bytes()); // bytes 8-11

        // Send a second packet (seq=0x1099) to get consecutive_count=1,
        // then a third to trigger consecutive_count>=2 with total>=3.
        let mut pkt2 = vec![0x80u8, 0x00, 0x10, 0x99, 0x00, 0x00, 0x00, 0xa1];
        pkt2.extend_from_slice(&expected_ssrc.to_be_bytes());
        let mut marshal_buf = Vec::new();
        conn.receive(Bytes::from(pkt.clone()), real_addr, &mut marshal_buf)
            .await;
        conn.receive(Bytes::from(pkt2.clone()), real_addr, &mut marshal_buf)
            .await;

        // Third packet: seq=0x109a
        let mut pkt3 = vec![0x80u8, 0x00, 0x10, 0x9a, 0x00, 0x00, 0x00, 0xa2];
        pkt3.extend_from_slice(&expected_ssrc.to_be_bytes());
        conn.receive(Bytes::from(pkt3), real_addr, &mut marshal_buf)
            .await;

        assert_eq!(
            *conn.remote_addr.read(),
            real_addr,
            "Should latch to real NAT address when SSRC matches"
        );
        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should be set after SSRC match"
        );
    }

    #[tokio::test]
    async fn test_ssrc_based_latch_ignores_wrong_ssrc() {
        // A stray packet with a different SSRC should not trigger latching.
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.17.230.54:4162".parse().unwrap();
        let rogue_addr: SocketAddr = "1.2.3.4:9999".parse().unwrap();
        let expected_ssrc: u32 = 787_088_145;
        let wrong_ssrc: u32 = 99_999_999;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(expected_ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut pkt = vec![0x80u8, 0x00, 0x10, 0x98, 0x00, 0x00, 0x00, 0xa0];
        pkt.extend_from_slice(&wrong_ssrc.to_be_bytes());

        let mut marshal_buf = Vec::new();
        conn.receive(Bytes::from(pkt), rogue_addr, &mut marshal_buf)
            .await;

        assert_eq!(
            *conn.remote_addr.read(),
            sdp_addr,
            "Should NOT latch when SSRC does not match"
        );
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "rtp_latched should remain false for wrong SSRC"
        );
    }

    #[tokio::test]
    async fn test_address_based_latch_fallback_when_no_expected_ssrc() {
        // When no expected SSRC is configured, latching falls back to
        // the original address-mismatch logic (current behaviour).
        let (_tx, rx) = watch::channel(None);
        let initial_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let new_addr: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        let conn = IceConn::new(rx, initial_addr, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));
        // expected_ssrc stays 0 — no SDP SSRC hint

        // Send 3 sequential packets to trigger consecutive_count >= 2
        for seq in 1u16..=3 {
            let pkt = Bytes::from(vec![
                0x80,
                0x00,
                (seq >> 8) as u8,
                seq as u8,
                0x00,
                0x00,
                0x00,
                seq as u8,
                0x00,
                0x00,
                0x01,
                0x23,
            ]);
            let mut marshal_buf = Vec::new();
            conn.receive(pkt, new_addr, &mut marshal_buf).await;
        }

        assert_eq!(*conn.remote_addr.read(), new_addr);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
    }

    // ── Probation-specific tests ───────────────────────────────────────────

    /// Minimal 12-byte RTP packet helper for the latch tests.
    fn rtp(seq: u16, ssrc: u32, marker: bool) -> Bytes {
        let mut p = vec![0x80u8, if marker { 0x80 } else { 0x00 }];
        p.extend_from_slice(&seq.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00, 0x00, 0x01]); // timestamp
        p.extend_from_slice(&ssrc.to_be_bytes());
        Bytes::from(p)
    }

    /// Reproduce the Wireshark scenario: port 4114 sends seq=21466 first,
    /// then port 4014 sends seq=21465 with marker=true.  The latch MUST
    /// resolve to port 4014.  A marker packet no longer wins by itself —
    /// the real source wins because its marker-carrying flow is also the
    /// one showing consecutive sequence numbers.
    #[tokio::test]
    async fn test_probation_marker_source_wins_by_dominance() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "223.104.80.120:4000".parse().unwrap();
        let port_4114: SocketAddr = "223.104.80.120:4114".parse().unwrap();
        let port_4014: SocketAddr = "223.104.80.120:4014".parse().unwrap();
        let ssrc: u32 = 0x6c0d_1ca5;

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_expected_ssrc(ssrc);
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        // Frame 508072: port 4114, seq=21466, marker=false (arrives first)
        conn.receive(rtp(21466, ssrc, false), port_4114, &mut marshal_buf)
            .await;
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "one packet from a stray source must not latch"
        );

        // Frame 508078: port 4014, seq=21465 (lower!), marker=true (real
        // start).  Still no latch — a lone marker packet must not move the
        // egress address.
        conn.receive(rtp(21465, ssrc, true), port_4014, &mut marshal_buf)
            .await;
        assert!(
            !conn.rtp_latched.load(Ordering::Relaxed),
            "a lone marker packet must not latch"
        );

        // The real source continues its run: 3 packets in a row from port
        // 4014 is consecutive dominance (run length 3 = consecutive_count
        // 2, 4 observed) — port 4014 wins over the stray first packet.
        conn.receive(rtp(21466, ssrc, false), port_4014, &mut marshal_buf)
            .await;
        conn.receive(rtp(21467, ssrc, false), port_4014, &mut marshal_buf)
            .await;
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
        assert_eq!(
            *conn.remote_addr.read(),
            port_4014,
            "the marker-carrying real source wins by consecutive dominance"
        );
    }

    /// When a single source sends consecutively, it wins by dominance rule
    /// even without a marker bit.
    #[tokio::test]
    async fn test_probation_consecutive_dominance() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let real_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let stray_src: SocketAddr = "10.0.0.1:5001".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // One stray packet from a different port
        let stray = Bytes::from(vec![
            0x80, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(stray, stray_src, &mut marshal_buf).await;

        // Three consecutive packets from real source (seq 1,2,3)
        for seq in 1u16..=3 {
            let pkt = Bytes::from(vec![
                0x80, 0x00, 0x00, seq as u8, 0x00, 0x00, 0x00, seq as u8, 0x00, 0x00, 0x00, 0x01,
            ]);
            conn.receive(pkt, real_src, &mut marshal_buf).await;
        }

        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "Should latch after consecutive dominance"
        );
        assert_eq!(
            *conn.remote_addr.read(),
            real_src,
            "Should latch to the source with consecutive packets"
        );
    }

    /// After PROBATION_MAX_PACKETS total observations with no clear winner,
    /// the candidate with most packets wins (fallback rule).
    #[tokio::test]
    async fn test_probation_timeout_fallback_selects_dominant() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let dominant: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let minor: SocketAddr = "10.0.0.1:5001".parse().unwrap();

        let probation_max = 6u8;
        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(probation_max));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Send 1 non-sequential packet from the minor source
        let minor_pkt = Bytes::from(vec![
            0x80, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x02,
        ]);
        let mut marshal_buf = Vec::new();
        conn.receive(minor_pkt, minor, &mut marshal_buf).await;

        // Send (probation_max - 1) non-sequential packets from dominant
        for i in 0..(probation_max - 1) {
            // Use non-sequential seq values (skip every other) to avoid
            // triggering the consecutive-dominance rule.
            let seq = i * 2 + 10;
            let pkt = Bytes::from(vec![
                0x80, 0x00, 0x00, seq, 0x00, 0x00, 0x00, seq, 0x00, 0x00, 0x00, 0x01,
            ]);
            conn.receive(pkt, dominant, &mut marshal_buf).await;
        }

        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "Should latch after PROBATION_MAX_PACKETS total packets"
        );
        assert_eq!(
            *conn.remote_addr.read(),
            dominant,
            "Should latch to source with most packets"
        );
    }

    /// Once latched, a few packets from a different address must NOT move
    /// the latched remote — a takeover requires sustained flow (see the
    /// competitive re-latch tests below).
    #[tokio::test]
    async fn test_probation_latch_is_sticky_after_commit() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let good_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let rogue_src: SocketAddr = "10.0.0.1:6000".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        // Latch to good_src via consecutive dominance (3 packets).
        let mut marshal_buf = Vec::new();
        for seq in 1u16..=3 {
            conn.receive(rtp(seq, 0x01, false), good_src, &mut marshal_buf)
                .await;
        }
        assert!(conn.rtp_latched.load(Ordering::Relaxed));
        assert_eq!(*conn.remote_addr.read(), good_src);

        // A rogue source below the takeover threshold must not flip it.
        for seq in 2u16..=4 {
            conn.receive(rtp(seq, 0x99, false), rogue_src, &mut marshal_buf)
                .await;
        }
        assert_eq!(
            *conn.remote_addr.read(),
            good_src,
            "a few stray packets must not change the latched remote"
        );
        assert_eq!(conn.relatch_count(), 0, "no re-latch committed");
    }

    /// reset_latch() clears the latch so a new source can be selected
    /// (used on re-INVITE).  Also clears the re-latch probe and cooldown.
    #[tokio::test]
    async fn test_reset_latch_allows_re_latching() {
        let (_tx, rx) = watch::channel(None);
        let sdp_addr: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first_src: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let second_src: SocketAddr = "10.0.0.2:5000".parse().unwrap();

        let conn = IceConn::new(rx, sdp_addr, None);
        conn.set_probation_max_packets(Some(6));
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        for seq in 1u16..=3 {
            conn.receive(rtp(seq, 0x01, false), first_src, &mut marshal_buf)
                .await;
        }
        assert_eq!(*conn.remote_addr.read(), first_src);

        conn.reset_latch();
        assert!(!conn.rtp_latched.load(Ordering::Relaxed));

        // After reset, the new source wins once it shows persistence too.
        for seq in 1u16..=3 {
            conn.receive(rtp(seq, 0x02, false), second_src, &mut marshal_buf)
                .await;
        }
        assert_eq!(
            *conn.remote_addr.read(),
            second_src,
            "Should re-latch to new source after reset_latch()"
        );
    }

    // ── Competitive re-latch tests ─────────────────────────────────────────

    /// NAT rebinding: after the initial latch, the peer reappears from a
    /// different ip:port with the same SSRC.  `RELATCH_PACKETS` consecutive
    /// packets take over the egress path, and both the initial latch and the
    /// re-latch surface as `SourceChange` events.
    #[tokio::test]
    async fn test_relatch_after_sustained_new_source() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let rebound: SocketAddr = "10.0.0.2:6000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp(); // max_packets = 0 → immediate latch
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let (change_tx, mut change_rx) = crate::platform::sync::mpsc::unbounded_channel();
        conn.set_source_change_sender(change_tx);

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;
        assert_eq!(*conn.remote_addr.read(), first);
        assert!(conn.rtp_latched.load(Ordering::Relaxed));

        // The peer reappears from a new source with the same SSRC.
        for seq in 100..104u16 {
            conn.receive(rtp(seq, ssrc, false), rebound, &mut marshal_buf)
                .await;
        }

        assert_eq!(
            *conn.remote_addr.read(),
            rebound,
            "sustained flow from the new source must take over the egress path"
        );
        assert!(
            conn.rtp_latched.load(Ordering::Relaxed),
            "latch stays committed across a re-latch"
        );
        assert_eq!(conn.relatch_count(), 1);

        // Events: initial latch (switch 0), then the re-latch (switch 1).
        let e0 = change_rx.recv().await.expect("initial latch event");
        assert_eq!((e0.from, e0.to, e0.switch), (initial, first, 0));
        let e1 = change_rx.recv().await.expect("re-latch event");
        assert_eq!((e1.from, e1.to, e1.ssrc, e1.switch), (first, rebound, ssrc, 1));
        assert!(
            change_rx.try_recv().is_err(),
            "no further source-change events expected"
        );
    }

    /// Below the takeover threshold a new source must not flip the address.
    #[tokio::test]
    async fn test_relatch_requires_sustained_flow() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let contender: SocketAddr = "10.0.0.9:7000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;

        // RELATCH_PACKETS - 1 packets: not enough.
        for seq in 100..103u16 {
            conn.receive(rtp(seq, ssrc, false), contender, &mut marshal_buf)
                .await;
        }

        assert_eq!(*conn.remote_addr.read(), first);
        assert_eq!(conn.relatch_count(), 0);
    }

    /// The probe identity is addr+SSRC: a contender whose SSRC drifts keeps
    /// restarting its probe and never takes over.
    #[tokio::test]
    async fn test_relatch_ssrc_drift_restarts_probe() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let contender: SocketAddr = "10.0.0.9:7000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;

        // Four packets, but the SSRC flips every packet — no consistent
        // ip:port + SSRC identity, no credit.
        conn.receive(rtp(100, 0x2222, false), contender, &mut marshal_buf)
            .await;
        conn.receive(rtp(101, 0x3333, false), contender, &mut marshal_buf)
            .await;
        conn.receive(rtp(102, 0x2222, false), contender, &mut marshal_buf)
            .await;
        conn.receive(rtp(103, 0x3333, false), contender, &mut marshal_buf)
            .await;

        assert_eq!(*conn.remote_addr.read(), first);
        assert_eq!(conn.relatch_count(), 0);
    }

    /// A packet from the incumbent proves the old path is alive and resets
    /// any pending takeover probe.
    #[tokio::test]
    async fn test_relatch_incumbent_packet_resets_probe() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let rebound: SocketAddr = "10.0.0.2:6000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;

        // Contender builds up 2 packets of credit…
        conn.receive(rtp(100, ssrc, false), rebound, &mut marshal_buf)
            .await;
        conn.receive(rtp(101, ssrc, false), rebound, &mut marshal_buf)
            .await;
        // …then the incumbent reasserts itself…
        conn.receive(rtp(5, ssrc, false), first, &mut marshal_buf)
            .await;
        // …so the contender's next two packets only reach 2 consecutive
        // again — far from the takeover threshold.
        conn.receive(rtp(102, ssrc, false), rebound, &mut marshal_buf)
            .await;
        conn.receive(rtp(103, ssrc, false), rebound, &mut marshal_buf)
            .await;

        assert_eq!(
            *conn.remote_addr.read(),
            first,
            "incumbent liveness must reset the takeover probe"
        );
        assert_eq!(conn.relatch_count(), 0);
    }

    /// Immediately after a committed switch the cooldown suppresses further
    /// probes (anti flapping between paths).
    #[tokio::test]
    async fn test_relatch_cooldown_blocks_flapping() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let a: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let b: SocketAddr = "10.0.0.2:5000".parse().unwrap();
        let c: SocketAddr = "10.0.0.3:5000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), a, &mut marshal_buf).await;

        // A → B commits.
        for seq in 100..104u16 {
            conn.receive(rtp(seq, ssrc, false), b, &mut marshal_buf)
                .await;
        }
        assert_eq!(*conn.remote_addr.read(), b);
        assert_eq!(conn.relatch_count(), 1);

        // C starts immediately — inside the cooldown window.
        for seq in 200..204u16 {
            conn.receive(rtp(seq, ssrc, false), c, &mut marshal_buf)
                .await;
        }
        assert_eq!(
            *conn.remote_addr.read(),
            b,
            "cooldown must suppress a third source right after a switch"
        );
        assert_eq!(conn.relatch_count(), 1);
    }

    /// After `RELATCH_MAX_SWITCHES` commits the egress address is frozen —
    /// even a sustained contender is ignored until signaling retargets.
    #[tokio::test]
    async fn test_relatch_budget_exhausted() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let hops: Vec<SocketAddr> = vec![
            "10.0.1.1:5000".parse().unwrap(),
            "10.0.2.1:5000".parse().unwrap(),
            "10.0.3.1:5000".parse().unwrap(),
            "10.0.4.1:5000".parse().unwrap(),
        ];
        let frozen: SocketAddr = "10.0.5.1:5000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;

        // Four hops, each past the cooldown of the previous one.
        for (i, hop) in hops.iter().enumerate() {
            conn.test_advance_clock_ms(RELATCH_COOLDOWN_MS + 1_000);
            let base = 100u16.wrapping_add((i as u16) * 100);
            for seq in base..base + 4 {
                conn.receive(rtp(seq, ssrc, false), *hop, &mut marshal_buf)
                    .await;
            }
        }
        assert_eq!(*conn.remote_addr.read(), hops[3]);
        assert_eq!(conn.relatch_count(), RELATCH_MAX_SWITCHES);

        // A fifth contender proves persistence too — but the budget is gone.
        conn.test_advance_clock_ms(RELATCH_COOLDOWN_MS + 1_000);
        for seq in 900..904u16 {
            conn.receive(rtp(seq, ssrc, false), frozen, &mut marshal_buf)
                .await;
        }
        assert_eq!(
            *conn.remote_addr.read(),
            hops[3],
            "egress must stay frozen once the re-latch budget is exhausted"
        );
        assert_eq!(conn.relatch_count(), RELATCH_MAX_SWITCHES);
    }

    /// A probe that trickles in slower than the window expires and restarts —
    /// it must not accumulate credit across the gap.
    #[tokio::test]
    async fn test_relatch_probe_window_expiry() {
        let (_tx, rx) = watch::channel(None);
        let initial: SocketAddr = "10.0.0.1:4000".parse().unwrap();
        let first: SocketAddr = "10.0.0.1:5000".parse().unwrap();
        let contender: SocketAddr = "10.0.0.9:7000".parse().unwrap();
        let ssrc: u32 = 0x1234;

        let conn = IceConn::new(rx, initial, None);
        conn.enable_latch_on_rtp();
        conn.set_rtp_receiver(Arc::new(NoopReceiver));

        let mut marshal_buf = Vec::new();
        conn.receive(rtp(1, ssrc, false), first, &mut marshal_buf)
            .await;

        // Two packets now…
        conn.receive(rtp(100, ssrc, false), contender, &mut marshal_buf)
            .await;
        conn.receive(rtp(101, ssrc, false), contender, &mut marshal_buf)
            .await;
        // …then a gap longer than the probe window…
        conn.test_advance_clock_ms(RELATCH_WINDOW_MS + 1);
        // …and two more: the probe restarted, so credit never accumulates.
        conn.receive(rtp(102, ssrc, false), contender, &mut marshal_buf)
            .await;
        conn.receive(rtp(103, ssrc, false), contender, &mut marshal_buf)
            .await;

        assert_eq!(*conn.remote_addr.read(), first);
        assert_eq!(conn.relatch_count(), 0);
    }

    // ---------------------------------------------------------------------------
    // TCP / RFC 4571 framing tests
    // ---------------------------------------------------------------------------

    /// Helper: bind a TCP listener and connect to it, returning the server-side
    /// stream and a split client-side IceSocketWrapper::TcpStream.
    async fn tcp_loopback_pair() -> (tokio::net::TcpStream, IceSocketWrapper) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let server_addr = listener.local_addr().unwrap();

        let client_stream = tokio::net::TcpStream::connect(server_addr).await.unwrap();
        let (server_stream, _) = listener.accept().await.unwrap();

        let wrapper = {
            let (read, write) = client_stream.into_split();
            IceSocketWrapper::TcpStream(
                Arc::new(tokio::sync::Mutex::new(read)),
                Arc::new(tokio::sync::Mutex::new(write)),
                server_addr,
            )
        };

        (server_stream, wrapper)
    }

    /// RFC 4571 framing round-trip: write framed data via IceSocketWrapper::TcpStream
    /// and read it back on the raw server-side TCP socket.
    #[tokio::test]
    async fn test_tcp_rfc4571_framing_roundtrip() {
        let (mut server_stream, wrapper) = tcp_loopback_pair().await;

        let payload = b"hello rfc4571";
        let len = payload.len() as u16;
        let mut expected_frame = Vec::with_capacity(2 + payload.len());
        expected_frame.extend_from_slice(&len.to_be_bytes());
        expected_frame.extend_from_slice(payload);

        // Send via wrapper
        wrapper
            .send_to(payload, server_stream.local_addr().unwrap())
            .await
            .unwrap();

        // Read framed data on server side
        let mut len_buf = [0u8; 2];
        let s = &mut server_stream;
        s.read_exact(&mut len_buf).await.unwrap();
        let frame_len = u16::from_be_bytes(len_buf) as usize;
        let mut frame = vec![0u8; frame_len];
        s.read_exact(&mut frame).await.unwrap();
        assert_eq!(&frame, payload);
    }

    /// Send multiple messages via IceSocketWrapper::TcpStream; verify they arrive
    /// correctly as separate RFC 4571 frames.
    #[tokio::test]
    async fn test_tcp_rfc4571_multiple_writes() {
        let (mut server_stream, wrapper) = tcp_loopback_pair().await;

        let msgs: &[&[u8]] = &[b"msg-a", b"msg-bb", b"msg-ccc"];
        for msg in msgs {
            wrapper
                .send_to(msg, server_stream.local_addr().unwrap())
                .await
                .unwrap();
        }

        let s = &mut server_stream;
        for expected in msgs {
            let mut len_buf = [0u8; 2];
            s.read_exact(&mut len_buf).await.unwrap();
            let frame_len = u16::from_be_bytes(len_buf) as usize;
            let mut frame = vec![0u8; frame_len];
            s.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, expected);
        }
    }

    /// recv_from on IceSocketWrapper::TcpStream: write a valid RFC 4571 frame
    /// to the server stream, then read it back via the wrapper.
    #[tokio::test]
    async fn test_tcp_recv_from_rfc4571() {
        let (mut server_stream, wrapper) = tcp_loopback_pair().await;
        let server_addr = server_stream.local_addr().unwrap();

        let payload = b"recv-test-payload";
        let len = payload.len() as u16;
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&len.to_be_bytes());
        frame.extend_from_slice(payload);

        // Write from server side
        server_stream.writable().await.unwrap();
        let s = &mut server_stream;
        s.write_all(&frame).await.unwrap();

        // Read via wrapper recv_from
        let mut buf = [0u8; 2048];
        let (n, addr) = wrapper.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], payload);
        assert_eq!(addr, server_addr);
    }

    /// send_dtls_record_batch over TCP sends RFC 4571-framed records in a single
    /// syscall; verify all records arrive correctly on the server side.
    #[tokio::test]
    async fn test_send_dtls_record_batch_tcp() {
        let (mut server_stream, wrapper) = tcp_loopback_pair().await;
        let server_addr = server_stream.local_addr().unwrap();

        let (socket_tx, socket_rx) = watch::channel(Some(wrapper));
        let conn = IceConn::new(socket_rx, server_addr, Some("test-tcp".into()));
        drop(socket_tx);

        let records: Vec<Vec<u8>> = vec![
            b"dtls-record-1".to_vec(),
            b"dtls-record-22".to_vec(),
            b"dtls-record-333".to_vec(),
        ];

        conn.send_dtls_record_batch(&records).await.unwrap();

        let s = &mut server_stream;
        for expected in &records {
            let mut len_buf = [0u8; 2];
            s.read_exact(&mut len_buf).await.unwrap();
            let frame_len = u16::from_be_bytes(len_buf) as usize;
            let mut frame = vec![0u8; frame_len];
            s.read_exact(&mut frame).await.unwrap();
            assert_eq!(&frame, expected.as_slice());
        }
    }

    /// send_dtls_record_batch on a UDP socket should fall through to individual
    /// send calls.  Verify all records arrive.
    #[tokio::test]
    async fn test_send_dtls_record_batch_udp_fallback() {
        let udp = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let wrapper = IceSocketWrapper::Udp(udp.clone());
        let (socket_tx, socket_rx) = watch::channel(Some(wrapper));

        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let receiver_addr = receiver.local_addr().unwrap();

        let conn = IceConn::new(socket_rx, receiver_addr, None);
        drop(socket_tx);

        let records: Vec<Vec<u8>> = vec![b"rec-a".to_vec(), b"rec-b".to_vec()];
        conn.send_dtls_record_batch(&records).await.unwrap();

        // Read all datagrams (may arrive as separate UDP packets)
        let mut buf = [0u8; 2048];
        for expected in &records {
            let (len, _) = receiver.recv_from(&mut buf).await.unwrap();
            assert_eq!(&buf[..len], expected.as_slice());
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod packet_diagnostics_tests {
    use super::*;
    #[tokio::test]
    async fn packet_diagnostics_counts_fast_udp_send_and_preparse_receiver_drops() {
        let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let socket = Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap());
        socket.writable().await.unwrap();
        let (_tx, rx) = watch::channel(Some(IceSocketWrapper::Udp(socket)));
        let addr = peer.local_addr().unwrap();
        let conn = IceConn::new(rx, addr, None);
        assert_eq!(conn.try_send(b"fast").unwrap(), 4);
        let mut buf = [0; 16];
        let (len, _) =
            tokio::time::timeout(core::time::Duration::from_secs(1), peer.recv_from(&mut buf))
                .await
                .unwrap()
                .unwrap();
        assert_eq!(&buf[..len], b"fast");
        let mut marshal = Vec::new();
        for packet in [
            Bytes::from_static(&[22, 0]),
            Bytes::from_static(&[0x80, 0]),
            Bytes::from_static(&[0x80, 201]),
            Bytes::from_static(&[65]),
        ] {
            conn.receive(packet, addr, &mut marshal).await;
        }
        let diag = conn.packet_diagnostics();
        assert_eq!(diag.send_attempts.packets, 1);
        assert_eq!(diag.send_sync_success.packets, 1);
        assert_eq!(diag.send_sync_success.bytes, 4);
        assert_eq!(diag.send_deferred_queued.packets, 0);
        assert_eq!(diag.send_async_completed.packets, 0);
        assert_eq!(diag.received.packets, 4);
        assert_eq!(diag.dtls.packets, 1);
        assert_eq!(diag.rtp.packets, 1);
        assert_eq!(diag.rtcp.packets, 1);
        assert_eq!(diag.unknown.packets, 1);
        assert_eq!(diag.dtls_no_receiver.packets, 1);
        assert_eq!(diag.rtp_no_receiver.packets, 2);
        assert!(diag.dtls_no_receiver.last_age_ms.is_some());
        let (closed_tx, closed_rx) = mpsc::unbounded_channel();
        drop(closed_rx);
        conn.deferred_send_tx.set(closed_tx).ok().unwrap();
        // Exercise the real queue boundary without creating a fake completion.
        conn.defer_async_send(
            IceSocketWrapper::Udp(Arc::new(
                tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap(),
            )),
            b"closed",
            addr,
        );
        let diag = conn.packet_diagnostics();
        assert_eq!(diag.send_queue_closed.packets, 1);
        assert_eq!(diag.send_async_completed.packets, 0);
    }
}
