use crate::errors::RtcResult;
use crate::peer_connection::{RtpReceiverInterceptor, RtpSenderInterceptor};
use crate::platform::atomic64::AtomicU64;
use crate::platform::{sync::Mutex, time::Instant};
use crate::prelude::*;
use crate::rtp::{
    ReceiverReport, ReportBlock, RtcpPacket, RtpPacket, SenderReport, SourceDescription,
};
use crate::stats::{StatsEntry, StatsId, StatsKind, StatsProvider};
use async_trait::async_trait;
use core::sync::atomic::Ordering;
use core::time::Duration;
use serde_json::json;

#[cfg(not(feature = "std"))]
use crate::platform::time::Instant as RttInstant;
/// Clock for `sent_sr_times` (RTT from LSR/DLSR, RFC 3550 §6.4.1).
///
/// The platform `Instant` is wall-clock milliseconds, which quantizes a
/// loopback round trip to zero and drops the RTT sample entirely. std uses
/// the monotonic clock for sub-millisecond resolution; no_std has no timer
/// yet (WP3), where `elapsed()` stays zero so RTT samples remain unset.
#[cfg(feature = "std")]
use std::time::Instant as RttInstant;

/// Entries in `sent_sr_times` older than this are stale for RTT computation and
/// eligible for eviction (prevents unbounded growth over long calls).
const SENT_SR_TIME_MAX_AGE: Duration = Duration::from_secs(60);
/// High-water mark for `sent_sr_times`; eviction runs once it is reached.
const SENT_SR_TIME_HIGH_WATERMARK: usize = 64;
/// High-water mark for the per-SSRC stats maps. Beyond this, stale SSRCs from
/// long-gone streams (SSRC churn / re-INVITE) are dropped to bound memory.
const SSRC_STATS_HIGH_WATERMARK: usize = 64;
/// Minimum interval between opportunistic Receiver Reports from the receive path.
const RR_MIN_INTERVAL: Duration = Duration::from_secs(3);

#[derive(Debug, Clone)]
struct RemoteInboundStats {
    packets_lost: i32,
    fraction_lost: u8,
    jitter: u32,
    round_trip_time: Option<f64>,
    last_seen: Instant,
}

impl Default for RemoteInboundStats {
    fn default() -> Self {
        Self {
            packets_lost: 0,
            fraction_lost: 0,
            jitter: 0,
            round_trip_time: None,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Debug, Clone)]
struct RemoteOutboundStats {
    packets_sent: u32,
    bytes_sent: u32,
    remote_timestamp: u32,
    /// Compact NTP timestamp (middle 32 bits) of the last SR from this SSRC (for LSR).
    last_sr_compact_ntp: u32,
    /// When we received that SR (for DLSR).
    last_sr_received_at: Option<Instant>,
    last_seen: Instant,
}

impl Default for RemoteOutboundStats {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            bytes_sent: 0,
            remote_timestamp: 0,
            last_sr_compact_ntp: 0,
            last_sr_received_at: None,
            last_seen: Instant::now(),
        }
    }
}

/// Per-SSRC reception tracking used to build RFC 3550 report blocks.
#[derive(Debug, Clone)]
struct LocalInboundStats {
    packets_received: u64,
    bytes_received: u64,
    /// First sequence number seen (unwrapped base).
    base_seq: u32,
    /// Highest sequence number seen, including wrap cycles in high 16 bits.
    max_seq: u32,
    cycles: u16,
    initialized: bool,
    /// Interarrival jitter estimate (RTP timestamp units).
    jitter: u32,
    /// The same, times 16: RFC 3550 A.8 fixed point (see `jitter_step`).
    jitter_q4: u32,
    last_rtp_ts: u32,
    last_arrival_rtp: u32,
    transit_init: bool,
    expected_prior: u32,
    received_prior: u32,
    clock_rate: u32,
    last_seen: Instant,
}

impl Default for LocalInboundStats {
    fn default() -> Self {
        Self {
            packets_received: 0,
            bytes_received: 0,
            base_seq: 0,
            max_seq: 0,
            cycles: 0,
            initialized: false,
            jitter: 0,
            jitter_q4: 0,
            last_rtp_ts: 0,
            last_arrival_rtp: 0,
            transit_init: false,
            expected_prior: 0,
            received_prior: 0,
            clock_rate: 90000,
            last_seen: Instant::now(),
        }
    }
}

impl LocalInboundStats {
    fn update(&mut self, seq: u16, rtp_ts: u32, clock_rate: u32, now: Instant) {
        self.clock_rate = if clock_rate == 0 { 90000 } else { clock_rate };
        self.last_seen = now;
        if !self.initialized {
            self.initialized = true;
            self.base_seq = seq as u32;
            self.max_seq = seq as u32;
            self.cycles = 0;
        } else {
            let udelta = seq.wrapping_sub(self.max_seq as u16);
            if udelta < 0x8000 {
                if seq < self.max_seq as u16 {
                    self.cycles = self.cycles.wrapping_add(1);
                }
                self.max_seq = ((self.cycles as u32) << 16) | seq as u32;
            }
            // else: out-of-order / duplicate — ignore for max_seq
        }
        self.packets_received += 1;

        // RFC 3550 A.8 interarrival jitter (arrival in RTP timestamp units).
        // The arrival time comes from `RttInstant`: on std the monotonic
        // clock, not the platform `Instant`, which is whole milliseconds
        // (8 units at 8 kHz, as much as the jitter of a good network).
        static START: crate::platform::sync::OnceLock<RttInstant> =
            crate::platform::sync::OnceLock::new();
        let start = START.get_or_init(RttInstant::now);
        let arrival_units =
            arrival_units(RttInstant::now().duration_since(*start), self.clock_rate);

        if self.transit_init {
            self.jitter_q4 = jitter_step(
                self.jitter_q4,
                arrival_units.wrapping_sub(self.last_arrival_rtp),
                rtp_ts.wrapping_sub(self.last_rtp_ts),
                self.clock_rate,
            );
            self.jitter = self.jitter_q4 >> 4;
        } else {
            self.transit_init = true;
        }
        self.last_rtp_ts = rtp_ts;
        self.last_arrival_rtp = arrival_units;
    }

    fn extended_max(&self) -> u32 {
        self.max_seq
    }

    fn expected(&self) -> u32 {
        if !self.initialized {
            return 0;
        }
        self.extended_max()
            .wrapping_sub(self.base_seq)
            .wrapping_add(1)
    }

    fn packets_lost(&self) -> i32 {
        let expected = self.expected() as i64;
        let received = self.packets_received as i64;
        (expected - received).clamp(i32::MIN as i64, i32::MAX as i64) as i32
    }

    /// Build a report block and advance the prior counters used for fraction lost.
    fn take_report_block(
        &mut self,
        ssrc: u32,
        last_sr: u32,
        delay_since_last_sr: u32,
    ) -> ReportBlock {
        let expected = self.expected();
        let expected_interval = expected.wrapping_sub(self.expected_prior);
        let received_interval = (self.packets_received as u32).wrapping_sub(self.received_prior);
        let lost_interval = expected_interval as i32 - received_interval as i32;
        let fraction = if expected_interval == 0 || lost_interval <= 0 {
            0u8
        } else {
            (((lost_interval as u32) << 8) / expected_interval) as u8
        };
        self.expected_prior = expected;
        self.received_prior = self.packets_received as u32;
        ReportBlock {
            ssrc,
            fraction_lost: fraction,
            packets_lost: self.packets_lost(),
            highest_sequence: self.extended_max(),
            jitter: self.jitter,
            last_sender_report: last_sr,
            delay_since_last_sender_report: delay_since_last_sr,
        }
    }
}

/// The arrival time in RTP timestamp units, modulo 2^32 like an RTP
/// timestamp. A plain `as u32` saturates: after 2^32 units of process
/// uptime (24.8 hours at 48 kHz) the arrival time stopped, and every packet
/// interval counted as jitter.
fn arrival_units(since_start: core::time::Duration, clock_rate: u32) -> u32 {
    (since_start.as_secs_f64() * clock_rate as f64) as u64 as u32
}

/// See `jitter_step`.
const JITTER_MAX_D_SECS: i64 = 5;

/// One step of the RFC 3550 A.8 jitter estimate, J += (|D| - J) / 16, with
/// J times 16 (`jitter_q4`) as in the RFC's fixed-point code. With J in
/// whole units, the integer division dropped every change under 16 units
/// (2 ms at 8 kHz): the estimate stayed at 0 on a good network.
///
/// The two deltas are wrapping differences of the arrival times and of the
/// RTP timestamps: an RTP timestamp starts at random, so it can wrap in any
/// call, and a plain difference made one huge D there.
///
/// A D of more than `JITTER_MAX_D_SECS` is skipped (J stays as it is; the
/// caller still moves on to this packet, so the next one compares against
/// it). Such a D is a jump of the sender's RTP timestamp within one SSRC,
/// not jitter: an SBC that goes from early media to the answered call can
/// keep the SSRC and the sequence numbers and start a new timestamp base.
/// Seen with Netelip: one D of about 16 hours put J at an hour, and it took
/// seconds to decay. libwebrtc skips these too ("crazy jumps in TS for the
/// same stream", 5 s at 90 kHz). A network stall that long is skipped too.
fn jitter_step(jitter_q4: u32, arrival_delta: u32, rtp_ts_delta: u32, clock_rate: u32) -> u32 {
    let d = (arrival_delta as i32 as i64) - (rtp_ts_delta as i32 as i64);
    if d.abs() > JITTER_MAX_D_SECS * clock_rate as i64 {
        return jitter_q4;
    }
    let j = jitter_q4 as i64;
    (j + d.abs() - ((j + 8) >> 4)).clamp(0, u32::MAX as i64) as u32
}

#[derive(Debug, Clone)]
struct LocalOutboundStats {
    packets_sent: u64,
    bytes_sent: u64,
    last_seen: Instant,
}

impl Default for LocalOutboundStats {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            bytes_sent: 0,
            last_seen: Instant::now(),
        }
    }
}

#[derive(Default)]
pub struct StatsCollector {
    remote_inbound: Mutex<BTreeMap<u32, RemoteInboundStats>>,
    remote_outbound: Mutex<BTreeMap<u32, RemoteOutboundStats>>,
    local_inbound: Mutex<BTreeMap<u32, LocalInboundStats>>,
    local_outbound: Mutex<BTreeMap<u32, LocalOutboundStats>>,
    /// Maps compact NTP → send time for outgoing Sender Reports, used to compute
    /// round-trip time from the LSR/DLSR fields of incoming Receiver Reports.
    sent_sr_times: Mutex<BTreeMap<u32, RttInstant>>,
    last_rr_sent: Mutex<Option<Instant>>,
    /// Monotonic counter used only to pace RR emission.
    packets_since_rr: AtomicU64,
    /// The SSRC and CNAME of our first sender, known before it sends
    /// anything: the SSRC an RR carries as its sender's, and the CNAME of
    /// the SDES that goes with it (see `add_local_source`).
    local_source: Mutex<Option<(u32, Arc<str>)>>,
}

/// Bound a per-SSRC stats map so long-lived SSRC churn (re-INVITE, simulcast
/// layer switches, relay rewrite) cannot grow it without bound. First drops
/// entries not seen within `SENT_SR_TIME_MAX_AGE`; if the map is still over the
/// high-water mark (all entries fresh), trims the least-recently-seen half.
fn evict_stale_ssrcs<V>(map: &mut BTreeMap<u32, V>, last_seen: impl Fn(&V) -> Instant) {
    if map.len() < SSRC_STATS_HIGH_WATERMARK {
        return;
    }
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(last_seen(v)) < SENT_SR_TIME_MAX_AGE);
    if map.len() >= SSRC_STATS_HIGH_WATERMARK {
        let mut by_age: Vec<(u32, Instant)> = map.iter().map(|(k, v)| (*k, last_seen(v))).collect();
        by_age.sort_by_key(|(_, t)| *t);
        let excess = map.len() - SSRC_STATS_HIGH_WATERMARK / 2;
        for (k, _) in by_age.into_iter().take(excess) {
            map.remove(&k);
        }
    }
}

fn delay_since_sr(received_at: Instant) -> u32 {
    let secs = received_at.elapsed().as_secs_f64();
    (secs * 65536.0) as u32
}

impl StatsCollector {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn process_rtcp(&self, packet: &RtcpPacket) {
        match packet {
            RtcpPacket::SenderReport(sr) => self.handle_sr(sr),
            RtcpPacket::ReceiverReport(rr) => self.handle_rr(rr),
            _ => {}
        }
    }

    // Delay units are 1/65536 seconds as per RFC 3550 §6.4.1
    fn dlsr_to_secs(dlsr: u32) -> f64 {
        dlsr as f64 / 65536.0
    }

    /// A sender of ours exists with this SSRC and CNAME. The RRs we send
    /// carry the SSRC of their sender (RFC 3550 §6.4.2), also before we send
    /// any RTP: early media comes in before the call is answered. Without
    /// this they said 0 until our first packet went out.
    pub(crate) fn add_local_source(&self, ssrc: u32, cname: Arc<str>) {
        self.local_source.lock().get_or_insert((ssrc, cname));
    }

    /// `report` (an RR from `observe_packet`) as a compound RTCP packet: the
    /// report, then the SDES with our CNAME (RFC 3550 §6.1). Without a
    /// sender of ours there is no CNAME to send: the report goes alone.
    pub(crate) fn compound(&self, report: RtcpPacket) -> Vec<RtcpPacket> {
        let sdes = match (&report, &*self.local_source.lock()) {
            (RtcpPacket::ReceiverReport(rr), Some((ssrc, cname))) if rr.sender_ssrc == *ssrc => {
                Some(RtcpPacket::SourceDescription(SourceDescription::cname(
                    *ssrc, cname,
                )))
            }
            _ => None,
        };
        let mut packets = vec![report];
        packets.extend(sdes);
        packets
    }

    pub fn record_sr_sent(&self, _ssrc: u32, compact_ntp: u32) {
        let mut times = self.sent_sr_times.lock();
        // Evict stale entries once the high-water mark is reached so the map
        // does not grow without bound over a long-lived call. RTT samples older
        // than `SENT_SR_TIME_MAX_AGE` are no longer useful anyway.
        if times.len() >= SENT_SR_TIME_HIGH_WATERMARK {
            let now = RttInstant::now();
            times.retain(|_, t| now.duration_since(*t) < SENT_SR_TIME_MAX_AGE);
        }
        times.insert(compact_ntp, RttInstant::now());
    }

    /// Build RFC 3550 reception report blocks for all locally received SSRCs.
    pub fn build_report_blocks(&self) -> Vec<ReportBlock> {
        let remote = self.remote_outbound.lock();
        let mut inbound = self.local_inbound.lock();
        let mut blocks = Vec::new();
        for (ssrc, stats) in inbound.iter_mut() {
            if !stats.initialized || stats.packets_received == 0 {
                continue;
            }
            let (lsr, dlsr) = remote
                .get(ssrc)
                .map(|r| {
                    let lsr = r.last_sr_compact_ntp;
                    let dlsr = r.last_sr_received_at.map(delay_since_sr).unwrap_or(0);
                    (lsr, dlsr)
                })
                .unwrap_or((0, 0));
            blocks.push(stats.take_report_block(*ssrc, lsr, dlsr));
        }
        blocks
    }

    fn handle_sr(&self, sr: &SenderReport) {
        {
            let mut outbound = self.remote_outbound.lock();
            evict_stale_ssrcs(&mut outbound, |v| v.last_seen);
            let stats = outbound.entry(sr.sender_ssrc).or_default();
            stats.packets_sent = sr.packet_count;
            stats.bytes_sent = sr.octet_count;
            stats.remote_timestamp = sr.ntp_least;
            stats.last_sr_compact_ntp = sr.compact_ntp();
            stats.last_sr_received_at = Some(Instant::now());
            stats.last_seen = Instant::now();
        }

        // SR also contains report blocks for our streams
        for block in &sr.report_blocks {
            let mut inbound = self.remote_inbound.lock();
            evict_stale_ssrcs(&mut inbound, |v| v.last_seen);
            let stats = inbound.entry(block.ssrc).or_default();
            stats.packets_lost = block.packets_lost;
            stats.fraction_lost = block.fraction_lost;
            stats.jitter = block.jitter;
            stats.last_seen = Instant::now();
        }
    }

    fn handle_rr(&self, rr: &ReceiverReport) {
        for block in &rr.report_blocks {
            let mut inbound = self.remote_inbound.lock();
            evict_stale_ssrcs(&mut inbound, |v| v.last_seen);
            let stats = inbound.entry(block.ssrc).or_default();
            stats.packets_lost = block.packets_lost;
            stats.fraction_lost = block.fraction_lost;
            stats.jitter = block.jitter;
            stats.last_seen = Instant::now();

            // Compute RTT from LSR / DLSR (RFC 3550 §6.4.1):
            //   RTT = now - when_we_sent_sr_with_this_ntp - DLSR
            //   where DLSR is in 1/65536-second units.
            if block.last_sender_report != 0 {
                let sent_times = self.sent_sr_times.lock();
                if let Some(&sent_instant) = sent_times.get(&block.last_sender_report) {
                    let dlsr = Self::dlsr_to_secs(block.delay_since_last_sender_report);
                    let rtt = sent_instant.elapsed().as_secs_f64() - dlsr;
                    if rtt > 0.0 {
                        stats.round_trip_time = Some(rtt);
                    }
                }
            }
        }
    }

    pub(crate) fn observe_packet(&self, packet: &RtpPacket, clock_rate: u32) -> Option<RtcpPacket> {
        let size = Self::packet_size(packet);
        let now = Instant::now();
        {
            let mut inbound = self.local_inbound.lock();
            evict_stale_ssrcs(&mut inbound, |v| v.last_seen);
            let stats = inbound.entry(packet.header.ssrc).or_default();
            stats.bytes_received += size;
            stats.update(
                packet.header.sequence_number,
                packet.header.timestamp,
                clock_rate,
                now,
            );
        }
        // Opportunistic RR so recv-only / silent-send legs still emit feedback.
        self.maybe_receiver_report(0)
    }

    fn packet_size(packet: &RtpPacket) -> u64 {
        let mut size = 12 + packet.header.csrcs.len() * 4;
        if let Some(ext) = &packet.header.extension {
            size += 4 + ext.data.len();
        }
        size += packet.payload.len();
        size += packet.padding_len as usize;
        size as u64
    }

    fn maybe_receiver_report(&self, _feedback_ssrc: u32) -> Option<RtcpPacket> {
        let n = self.packets_since_rr.fetch_add(1, Ordering::Relaxed) + 1;
        let due = {
            let last = self.last_rr_sent.lock();
            match *last {
                None => n >= 50,
                Some(t) => t.elapsed() >= RR_MIN_INTERVAL && n >= 10,
            }
        };
        if !due {
            return None;
        }
        let blocks = self.build_report_blocks();
        if blocks.is_empty() {
            return None;
        }
        // 0 only for a peer connection with no sender at all.
        let sender_ssrc = (self.local_source.lock().as_ref().map(|(ssrc, _)| *ssrc))
            .or_else(|| self.local_outbound.lock().keys().next().copied())
            .unwrap_or(0);
        *self.last_rr_sent.lock() = Some(Instant::now());
        self.packets_since_rr.store(0, Ordering::Relaxed);
        Some(RtcpPacket::ReceiverReport(ReceiverReport {
            sender_ssrc,
            report_blocks: blocks,
        }))
    }
}

#[async_trait]
impl RtpSenderInterceptor for StatsCollector {
    async fn on_packet_sent(
        &self,
        packet: &RtpPacket,
        _dst_addr: core::net::SocketAddr,
        _local_addr: core::net::SocketAddr,
    ) {
        let size = Self::packet_size(packet);
        let mut outbound = self.local_outbound.lock();
        evict_stale_ssrcs(&mut outbound, |v| v.last_seen);
        let stats = outbound.entry(packet.header.ssrc).or_default();
        stats.packets_sent += 1;
        stats.bytes_sent += size;
        stats.last_seen = Instant::now();
    }

    fn on_sr_sent(&self, ssrc: u32, compact_ntp: u32) {
        self.record_sr_sent(ssrc, compact_ntp);
    }

    fn reception_report_blocks(&self) -> Vec<ReportBlock> {
        self.build_report_blocks()
    }
}

#[async_trait]
impl RtpReceiverInterceptor for StatsCollector {
    async fn on_packet_received(
        &self,
        packet: &RtpPacket,
        _src_addr: core::net::SocketAddr,
        _local_addr: core::net::SocketAddr,
    ) -> Option<RtcpPacket> {
        self.observe_packet(packet, 90000)
    }
}

impl StatsProvider for StatsCollector {
    fn collect(&self) -> RtcResult<Vec<StatsEntry>> {
        let mut entries = Vec::new();

        {
            let inbound = self.remote_inbound.lock();
            for (ssrc, stats) in inbound.iter() {
                let id = StatsId::new(format!("remote-inbound-rtp-{}", ssrc));
                let mut entry = StatsEntry::new(id, StatsKind::RemoteInboundRtp);
                entry = entry
                    .with_value("ssrc", json!(ssrc))
                    .with_value("packetsLost", json!(stats.packets_lost))
                    .with_value("fractionLost", json!(stats.fraction_lost))
                    .with_value("jitter", json!(stats.jitter));

                if let Some(rtt) = stats.round_trip_time {
                    entry = entry.with_value("roundTripTime", json!(rtt));
                }

                entries.push(entry);
            }
        }

        {
            let outbound = self.remote_outbound.lock();
            for (ssrc, stats) in outbound.iter() {
                let id = StatsId::new(format!("remote-outbound-rtp-{}", ssrc));
                let mut entry = StatsEntry::new(id, StatsKind::RemoteOutboundRtp);
                entry = entry
                    .with_value("ssrc", json!(ssrc))
                    .with_value("packetsSent", json!(stats.packets_sent))
                    .with_value("bytesSent", json!(stats.bytes_sent));

                entries.push(entry);
            }
        }

        {
            let inbound = self.local_inbound.lock();
            for (ssrc, stats) in inbound.iter() {
                let id = StatsId::new(format!("inbound-rtp-{}", ssrc));
                let mut entry = StatsEntry::new(id, StatsKind::InboundRtp);
                entry = entry
                    .with_value("ssrc", json!(ssrc))
                    .with_value("packetsReceived", json!(stats.packets_received))
                    .with_value("bytesReceived", json!(stats.bytes_received))
                    .with_value("jitter", json!(stats.jitter))
                    .with_value("packetsLost", json!(stats.packets_lost()));

                entries.push(entry);
            }
        }

        {
            let outbound = self.local_outbound.lock();
            for (ssrc, stats) in outbound.iter() {
                let id = StatsId::new(format!("outbound-rtp-{}", ssrc));
                let mut entry = StatsEntry::new(id, StatsKind::OutboundRtp);
                entry = entry
                    .with_value("ssrc", json!(ssrc))
                    .with_value("packetsSent", json!(stats.packets_sent))
                    .with_value("bytesSent", json!(stats.bytes_sent));

                entries.push(entry);
            }
        }

        Ok(entries)
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {

    fn test_addr() -> core::net::SocketAddr {
        core::net::SocketAddr::new(
            core::net::IpAddr::V4(core::net::Ipv4Addr::new(127, 0, 0, 1)),
            5000,
        )
    }
    use super::*;
    use crate::rtp::{ReportBlock, SenderReport};

    #[tokio::test]
    async fn test_stats_collector_sr_lsr() {
        let collector = StatsCollector::new();
        let sr = SenderReport {
            sender_ssrc: 12345,
            ntp_most: 0x1234_5678,
            ntp_least: 0x9abc_def0,
            rtp_timestamp: 0,
            packet_count: 50,
            octet_count: 5000,
            report_blocks: vec![ReportBlock {
                ssrc: 67890,
                fraction_lost: 10,
                packets_lost: 5,
                highest_sequence: 100,
                jitter: 20,
                last_sender_report: 0,
                delay_since_last_sender_report: 0,
            }],
        };

        let packet = RtpPacket::new(
            crate::rtp::RtpHeader::new(0, 1, 160, 12345),
            vec![0xff; 160],
        );
        collector
            .on_packet_received(&packet, test_addr(), test_addr())
            .await;
        collector.process_rtcp(&RtcpPacket::SenderReport(sr));
        let blocks = collector.build_report_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(
            blocks[0].last_sender_report, 0x5678_9abc,
            "RFC 3550 LSR is the middle 32 NTP bits, including seconds"
        );

        let stats = collector.collect().unwrap();
        assert_eq!(stats.len(), 3);

        let remote_outbound = stats
            .iter()
            .find(|s| s.kind == StatsKind::RemoteOutboundRtp)
            .unwrap();
        assert_eq!(remote_outbound.values["ssrc"], 12345);
        assert_eq!(remote_outbound.values["packetsSent"], 50);
        assert_eq!(remote_outbound.values["bytesSent"], 5000);

        let remote_inbound = stats
            .iter()
            .find(|s| s.kind == StatsKind::RemoteInboundRtp)
            .unwrap();
        assert_eq!(remote_inbound.values["ssrc"], 67890);
        assert_eq!(remote_inbound.values["packetsLost"], 5);
        assert_eq!(remote_inbound.values["fractionLost"], 10);
        assert_eq!(remote_inbound.values["jitter"], 20);
    }

    #[tokio::test]
    async fn test_stats_collector_interceptor() {
        let collector = StatsCollector::new();
        let mut header = crate::rtp::RtpHeader::new(96, 0, 0, 12345);
        let payload = vec![0u8; 100];
        let packet = RtpPacket::new(header.clone(), payload.clone());

        // Test outbound interception
        collector
            .on_packet_sent(&packet, test_addr(), test_addr())
            .await;

        // Send another one
        collector
            .on_packet_sent(&packet, test_addr(), test_addr())
            .await;

        // Test inbound interception
        header.ssrc = 67890;
        let packet_in = RtpPacket::new(header, payload);
        collector
            .on_packet_received(&packet_in, test_addr(), test_addr())
            .await;

        let stats = collector.collect().unwrap();

        let outbound = stats
            .iter()
            .find(|s| s.kind == StatsKind::OutboundRtp)
            .unwrap();
        assert_eq!(outbound.values["ssrc"], 12345);
        assert_eq!(outbound.values["packetsSent"], 2);
        // Header (12) + Payload (100) = 112 * 2 = 224
        assert_eq!(outbound.values["bytesSent"], 224);

        let inbound = stats
            .iter()
            .find(|s| s.kind == StatsKind::InboundRtp)
            .unwrap();
        assert_eq!(inbound.values["ssrc"], 67890);
        assert_eq!(inbound.values["packetsReceived"], 1);
        assert_eq!(inbound.values["bytesReceived"], 112);
    }

    #[tokio::test]
    async fn test_report_blocks_from_inbound() {
        let collector = StatsCollector::new();
        let mut header = crate::rtp::RtpHeader::new(111, 1, 960, 42);
        for seq in 1u16..=20 {
            header.sequence_number = seq;
            header.timestamp = seq as u32 * 960;
            let packet = RtpPacket::new(header.clone(), vec![0u8; 20]);
            collector
                .on_packet_received(&packet, test_addr(), test_addr())
                .await;
        }
        // Simulate a gap (loss)
        header.sequence_number = 25;
        header.timestamp = 25 * 960;
        let packet = RtpPacket::new(header, vec![0u8; 20]);
        collector
            .on_packet_received(&packet, test_addr(), test_addr())
            .await;

        let blocks = collector.build_report_blocks();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].ssrc, 42);
        assert!(blocks[0].packets_lost >= 4);
    }

    #[test]
    fn early_rr_carries_our_ssrc() {
        // Early media: 50 packets come in before we send anything.
        let collector = StatsCollector::new();
        collector.add_local_source(4242, "our-cname".into());
        let mut header = crate::rtp::RtpHeader::new(8, 1, 0, 77);
        let mut report = None;
        for seq in 1u16..=50 {
            header.sequence_number = seq;
            header.timestamp = seq as u32 * 160;
            let packet = RtpPacket::new(header.clone(), vec![0u8; 160]);
            report = report.or(collector.observe_packet(&packet, 8000));
        }
        let report = report.expect("an RR");
        match &report {
            RtcpPacket::ReceiverReport(rr) => assert_eq!(rr.sender_ssrc, 4242),
            other => panic!("expected an RR, got {other:?}"),
        }
        // It goes out as a compound packet: the RR, then our CNAME.
        let compound = collector.compound(report);
        assert_eq!(compound.len(), 2);
        assert_eq!(
            compound[1],
            RtcpPacket::SourceDescription(SourceDescription::cname(4242, "our-cname"))
        );
    }

    /// A peer connection with senders but no `add_local_source` call site
    /// reachable: the RR falls back to the SSRC we actually send with
    /// (the only source before #77), never 0.
    #[tokio::test]
    async fn rr_sender_ssrc_falls_back_to_the_first_outbound() {
        let collector = StatsCollector::new();
        let mut header = crate::rtp::RtpHeader::new(8, 1, 0, 77);
        let mut report = None;
        for seq in 1u16..=49 {
            header.sequence_number = seq;
            header.timestamp = seq as u32 * 160;
            let packet = RtpPacket::new(header.clone(), vec![0u8; 160]);
            report = report.or(collector.observe_packet(&packet, 8000));
        }
        // Our first outbound packet registers the sender SSRC.
        let mut out_header = crate::rtp::RtpHeader::new(8, 1, 0, 4242);
        out_header.sequence_number = 1;
        out_header.timestamp = 160;
        let packet = RtpPacket::new(out_header, vec![0u8; 160]);
        collector
            .on_packet_sent(&packet, test_addr(), test_addr())
            .await;
        header.sequence_number = 50;
        header.timestamp = 50 * 160;
        let packet = RtpPacket::new(header, vec![0u8; 160]);
        report = report.or(collector.observe_packet(&packet, 8000));
        match report {
            Some(RtcpPacket::ReceiverReport(rr)) => {
                assert_eq!(rr.sender_ssrc, 4242, "fallback to the outbound SSRC");
                assert_eq!(rr.report_blocks.len(), 1);
            }
            other => panic!("expected an RR, got {other:?}"),
        }
    }

    /// Run the jitter estimate over (arrival delta, RTP timestamp delta)
    /// steps. Returns J in units.
    fn run_jitter(steps: impl IntoIterator<Item = (u32, u32)>) -> u32 {
        let mut q4 = 0;
        for (arrival, ts) in steps {
            q4 = jitter_step(q4, arrival, ts, 8000);
        }
        q4 >> 4
    }

    #[test]
    fn jitter_sees_small_differences() {
        // 8 kHz, packets every 160 units, arriving 4 units (0.5 ms) early and
        // late in turn: |D| is 8 every time, so J tends to 8. With J in whole
        // units, (8 - J) / 16 was 0 and J stayed 0.
        let steps = (0..500).map(|i| (if i % 2 == 0 { 168 } else { 152 }, 160));
        assert_eq!(run_jitter(steps), 7);
        // Perfect pacing: no jitter.
        assert_eq!(run_jitter((0..500).map(|_| (160, 160))), 0);
    }

    #[test]
    fn jitter_skips_timestamp_jumps() {
        // 8 kHz, 20 ms packets, 0.5 ms early and late in turn: J tends to 8.
        let normal = |n| (0..n).map(|i| (if i % 2 == 0 { 168 } else { 152 }, 160));
        // Then the sender's timestamp jumps by about 16 hours (Netelip at the
        // answer), then the stream goes on as before from the new base.
        let jump = 160u32.wrapping_add(455_000_000);
        let steps = normal(500).chain([(160, jump)]).chain(normal(100));
        assert_eq!(run_jitter(steps), 7, "the jump is no jitter");
        // A D under 5 s still counts: a 4 s stall puts J at 4 s / 16.
        let stall = normal(500).chain([(160 + 4 * 8000, 160)]);
        assert_eq!(run_jitter(stall), 7 + 4 * 8000 / 16);
    }

    #[test]
    fn jitter_jump_threshold_scales_with_clock_rate() {
        // The 5 s jump threshold is in units of the stream's own clock, not
        // a fixed rate: the same wall-clock stall counts at any clock rate,
        // and a jump is skipped once it passes 5 s.
        // 90 kHz: a 3 s stall (D = 270000) is under the threshold, J = D / 16.
        let stall = jitter_step(0, 3 * 90_000, 0, 90_000);
        assert_eq!(stall >> 4, 3 * 90_000 / 16);
        // Exactly 5 s is on the counted side, as in libwebrtc.
        let boundary = jitter_step(0, 5 * 90_000, 0, 90_000);
        assert_eq!(boundary >> 4, 5 * 90_000 / 16);
        // Just over: skipped, J keeps its previous value.
        let skipped = jitter_step(1234 << 4, 5 * 90_000 + 1, 0, 90_000);
        assert_eq!(skipped, 1234 << 4);
    }

    #[test]
    fn jitter_across_wraps() {
        // The RTP timestamp wraps between two packets 960 units apart: the
        // wrapping difference is 960, not -2^32 + 960.
        let ts_delta = 100u32.wrapping_sub(u32::MAX - 859);
        assert_eq!(ts_delta, 960);
        assert_eq!(run_jitter([(960, ts_delta)]), 0);
        // The arrival time wraps too: after 25 hours at 48 kHz it goes on,
        // modulo 2^32, instead of stopping at u32::MAX.
        let day = core::time::Duration::from_secs(25 * 3600);
        let a = arrival_units(day, 48_000);
        let b = arrival_units(day + core::time::Duration::from_millis(20), 48_000);
        assert_ne!(a, u32::MAX);
        assert_eq!(b.wrapping_sub(a), 960);
    }
}
