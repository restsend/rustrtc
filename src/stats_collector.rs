use crate::errors::RtcResult;
use crate::peer_connection::{RtpReceiverInterceptor, RtpSenderInterceptor};
use crate::rtp::{ReceiverReport, ReportBlock, RtcpPacket, RtpPacket, SenderReport};
use crate::stats::{StatsEntry, StatsId, StatsKind, StatsProvider};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

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
    /// NTP least-significant 32 bits of the last SR from this SSRC (for LSR).
    last_sr_ntp_least: u32,
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
            last_sr_ntp_least: 0,
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
        static START: std::sync::OnceLock<Instant> = std::sync::OnceLock::new();
        let start = START.get_or_init(Instant::now);
        let arrival_units =
            (now.duration_since(*start).as_secs_f64() * self.clock_rate as f64) as u32;

        if self.transit_init {
            let d = (arrival_units as i64 - self.last_arrival_rtp as i64)
                - (rtp_ts as i64 - self.last_rtp_ts as i64);
            let ad = d.unsigned_abs() as i64;
            self.jitter = ((self.jitter as i64) + ((ad - self.jitter as i64) / 16)) as u32;
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
    remote_inbound: Mutex<HashMap<u32, RemoteInboundStats>>,
    remote_outbound: Mutex<HashMap<u32, RemoteOutboundStats>>,
    local_inbound: Mutex<HashMap<u32, LocalInboundStats>>,
    local_outbound: Mutex<HashMap<u32, LocalOutboundStats>>,
    /// Maps ntp_least → Instant for outgoing Sender Reports, used to compute
    /// round-trip time from the LSR/DLSR fields of incoming Receiver Reports.
    sent_sr_times: Mutex<HashMap<u32, std::time::Instant>>,
    last_rr_sent: Mutex<Option<Instant>>,
    /// Monotonic counter used only to pace RR emission.
    packets_since_rr: AtomicU64,
}

/// Bound a per-SSRC stats map so long-lived SSRC churn (re-INVITE, simulcast
/// layer switches, relay rewrite) cannot grow it without bound. First drops
/// entries not seen within `SENT_SR_TIME_MAX_AGE`; if the map is still over the
/// high-water mark (all entries fresh), trims the least-recently-seen half.
fn evict_stale_ssrcs<V>(map: &mut HashMap<u32, V>, last_seen: impl Fn(&V) -> Instant) {
    if map.len() < SSRC_STATS_HIGH_WATERMARK {
        return;
    }
    let now = Instant::now();
    map.retain(|_, v| now.duration_since(last_seen(v)) < SENT_SR_TIME_MAX_AGE);
    if map.len() >= SSRC_STATS_HIGH_WATERMARK {
        let mut by_age: Vec<(u32, Instant)> =
            map.iter().map(|(k, v)| (*k, last_seen(v))).collect();
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

    pub fn record_sr_sent(&self, _ssrc: u32, ntp_least: u32) {
        let mut times = self.sent_sr_times.lock();
        // Evict stale entries once the high-water mark is reached so the map
        // does not grow without bound over a long-lived call. RTT samples older
        // than `SENT_SR_TIME_MAX_AGE` are no longer useful anyway.
        if times.len() >= SENT_SR_TIME_HIGH_WATERMARK {
            let now = Instant::now();
            times.retain(|_, t| now.duration_since(*t) < SENT_SR_TIME_MAX_AGE);
        }
        times.insert(ntp_least, Instant::now());
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
                    let lsr = r.last_sr_ntp_least;
                    let dlsr = r
                        .last_sr_received_at
                        .map(delay_since_sr)
                        .unwrap_or(0);
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
            stats.last_sr_ntp_least = sr.ntp_least;
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
        let sender_ssrc = self
            .local_outbound
            .lock()
            .keys()
            .next()
            .copied()
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
        _dst_addr: std::net::SocketAddr,
        _local_addr: std::net::SocketAddr,
    ) {
        let size = Self::packet_size(packet);
        let mut outbound = self.local_outbound.lock();
        evict_stale_ssrcs(&mut outbound, |v| v.last_seen);
        let stats = outbound.entry(packet.header.ssrc).or_default();
        stats.packets_sent += 1;
        stats.bytes_sent += size;
        stats.last_seen = Instant::now();
    }

    fn on_sr_sent(&self, ssrc: u32, ntp_least: u32) {
        self.record_sr_sent(ssrc, ntp_least);
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
        _src_addr: std::net::SocketAddr,
        _local_addr: std::net::SocketAddr,
    ) -> Option<RtcpPacket> {
        let size = Self::packet_size(packet);
        let now = Instant::now();
        {
            let mut inbound = self.local_inbound.lock();
            evict_stale_ssrcs(&mut inbound, |v| v.last_seen);
            let stats = inbound.entry(packet.header.ssrc).or_default();
            stats.bytes_received += size;
            // Clock rate unknown here; jitter uses 90k default until known.
            // Audio (8k/48k) still produces a usable relative estimate.
            stats.update(
                packet.header.sequence_number,
                packet.header.timestamp,
                stats.clock_rate,
                now,
            );
        }
        // Opportunistic RR so recv-only / silent-send legs still emit feedback.
        self.maybe_receiver_report(0)
    }
}

#[async_trait]
impl StatsProvider for StatsCollector {
    async fn collect(&self) -> RtcResult<Vec<StatsEntry>> {
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

#[cfg(test)]
mod tests {

    fn test_addr() -> std::net::SocketAddr {
        std::net::SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
            5000,
        )
    }
    use super::*;
    use crate::rtp::{ReportBlock, SenderReport};

    #[tokio::test]
    async fn test_stats_collector_sr() {
        let collector = StatsCollector::new();
        let sr = SenderReport {
            sender_ssrc: 12345,
            ntp_most: 0,
            ntp_least: 1000,
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

        collector.process_rtcp(&RtcpPacket::SenderReport(sr));

        let stats = collector.collect().await.unwrap();
        assert_eq!(stats.len(), 2);

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

        let stats = collector.collect().await.unwrap();

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
}
