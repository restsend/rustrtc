use crate::errors::RtcResult;
use crate::peer_connection::{RtpReceiverInterceptor, RtpSenderInterceptor};
use crate::rtp::{ReceiverReport, RtcpPacket, RtpPacket, SenderReport};
use crate::stats::{StatsEntry, StatsId, StatsKind, StatsProvider};
use async_trait::async_trait;
use parking_lot::Mutex;
use serde_json::json;
use std::collections::HashMap;

#[derive(Debug, Clone, Default)]
struct RemoteInboundStats {
    packets_lost: i32,
    fraction_lost: u8,
    jitter: u32,
    round_trip_time: Option<f64>,
}

#[derive(Debug, Clone, Default)]
struct RemoteOutboundStats {
    packets_sent: u32,
    bytes_sent: u32,
    remote_timestamp: u32,
}

#[derive(Debug, Clone, Default)]
struct LocalInboundStats {
    packets_received: u64,
    bytes_received: u64,
}

#[derive(Debug, Clone, Default)]
struct LocalOutboundStats {
    packets_sent: u64,
    bytes_sent: u64,
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
        self.sent_sr_times
            .lock()
            .insert(ntp_least, std::time::Instant::now());
    }

    fn handle_sr(&self, sr: &SenderReport) {
        {
            let mut outbound = self.remote_outbound.lock();
            let stats = outbound.entry(sr.sender_ssrc).or_default();
            stats.packets_sent = sr.packet_count;
            stats.bytes_sent = sr.octet_count;
            stats.remote_timestamp = sr.ntp_least; // simplified
        }

        // SR also contains report blocks for our streams
        for block in &sr.report_blocks {
            let mut inbound = self.remote_inbound.lock();
            let stats = inbound.entry(block.ssrc).or_default();
            stats.packets_lost = block.packets_lost;
            stats.fraction_lost = block.fraction_lost;
            stats.jitter = block.jitter;
        }
    }

    fn handle_rr(&self, rr: &ReceiverReport) {
        for block in &rr.report_blocks {
            let mut inbound = self.remote_inbound.lock();
            let stats = inbound.entry(block.ssrc).or_default();
            stats.packets_lost = block.packets_lost;
            stats.fraction_lost = block.fraction_lost;
            stats.jitter = block.jitter;

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
        let stats = outbound.entry(packet.header.ssrc).or_default();
        stats.packets_sent += 1;
        stats.bytes_sent += size;
    }

    fn on_sr_sent(&self, ssrc: u32, ntp_least: u32) {
        self.record_sr_sent(ssrc, ntp_least);
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
        let mut inbound = self.local_inbound.lock();
        let stats = inbound.entry(packet.header.ssrc).or_default();
        stats.packets_received += 1;
        stats.bytes_received += size;
        None
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
                    .with_value("bytesReceived", json!(stats.bytes_received));

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
        let dummy = "0.0.0.0:0".parse().unwrap();

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
}
