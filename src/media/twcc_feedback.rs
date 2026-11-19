//! Transport-wide congestion control (TWCC) feedback generation
//! (draft-holmer-rmcat-transport-wide-cc-01).
//!
//! When the transport-cc RTP header extension is negotiated, the remote sender
//! stamps every RTP packet with a 16-bit transport-wide sequence number and
//! expects periodic [`RtcpPacket::TransportWideCc`] feedback describing which
//! packets arrived and with what inter-arrival deltas.
//!
//! [`TwccFeedbackGenerator`] observes inbound RTP packets on the receive path
//! and, on a 100 ms cadence, encodes and
//! sends the feedback report. Status encoding uses 2-bit-symbol status vector
//! chunks with 1-byte (250 µs units) or 2-byte (250 µs units) recv deltas —
//! the subset Chrome and pion emit in practice.

use crate::prelude::*;
use core::sync::atomic::{AtomicU8, AtomicU16, AtomicU32, Ordering};
use crate::platform::atomic64::AtomicU64;
use crate::platform::time::Instant;

use crate::platform::sync::Mutex;

use crate::rtp::{RtcpPacket, RtpPacket, TransportWideCc};
use crate::transports::rtp::RtpTransport;

/// How often pending feedback is flushed.
const FLUSH_INTERVAL: core::time::Duration = core::time::Duration::from_millis(100);
/// Hard cap on statuses in one feedback packet (MTU safety: ~500 packets).
const MAX_STATUSES_PER_REPORT: usize = 480;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaSize {
    /// Packet not received.
    Lost,
    /// Fits in 1 byte (250 µs units, unsigned 8-bit).
    Small(u8),
    /// Fits in 2 bytes (250 µs units, signed 16-bit).
    Large(i16),
}

struct PendingRecord {
    seq: u16,
    arrival_us: u64,
}

#[derive(Default)]
struct PendingFeedback {
    media_ssrc: u32,
    records: Vec<PendingRecord>,
}

/// Generates TWCC feedback for a transport's incoming RTP sequence space.
pub struct TwccFeedbackGenerator {
    /// Negotiated extmap id of the transport-cc header extension (0 = unknown;
    /// packets are ignored until negotiation populates this).
    ext_id: AtomicU8,
    /// Our RTCP sender SSRC (the local RTP SSRC of this receiver direction).
    feedback_ssrc: AtomicU32,
    /// Running feedback packet sequence number (wraps at 8 bits).
    feedback_seq: AtomicU16,
    /// Reference clock for arrival-time deltas.
    clock: Instant,
    /// BUNDLE interleaves audio, video and RTX in a single sequence space.
    pending: Mutex<PendingFeedback>,
    /// Diagnostics.
    pub packets_observed: AtomicU64,
    pub feedback_sent: AtomicU64,
}

impl Default for TwccFeedbackGenerator {
    fn default() -> Self {
        Self::new()
    }
}

impl TwccFeedbackGenerator {
    pub fn new() -> Self {
        Self {
            ext_id: AtomicU8::new(0),
            feedback_ssrc: AtomicU32::new(0),
            feedback_seq: AtomicU16::new(rand_u16()),
            clock: Instant::now(),
            pending: Mutex::new(PendingFeedback::default()),
            packets_observed: AtomicU64::new(0),
            feedback_sent: AtomicU64::new(0),
        }
    }

    /// Set the negotiated extmap id for the transport-cc extension.
    pub fn set_ext_id(&self, id: u8) {
        self.ext_id.store(id, Ordering::SeqCst);
    }

    pub fn ext_id(&self) -> u8 {
        self.ext_id.load(Ordering::SeqCst)
    }

    /// Set our RTCP sender SSRC (usually the local sender's SSRC so the peer
    /// can attribute the feedback; 0 is acceptable when unknown).
    pub fn set_feedback_ssrc(&self, ssrc: u32) {
        self.feedback_ssrc.store(ssrc, Ordering::SeqCst);
    }

    /// Extract the transport-wide sequence number from an RTP packet's
    /// one-byte header extensions, if present.
    fn extract_tcc_seq(&self, packet: &RtpPacket) -> Option<u16> {
        let id = self.ext_id.load(Ordering::SeqCst);
        if id == 0 {
            return None;
        }
        let data = packet.header.get_extension(id)?;
        if data.len() < 2 {
            return None;
        }
        Some(u16::from_be_bytes([data[0], data[1]]))
    }

    /// Record an observed RTP packet before any rewriting.
    pub fn observe(&self, packet: &RtpPacket) {
        let Some(seq) = self.extract_tcc_seq(packet) else {
            return;
        };
        self.packets_observed.fetch_add(1, Ordering::Relaxed);
        let arrival_us = self.clock.elapsed().as_micros() as u64;
        let mut pending = self.pending.lock();
        pending.media_ssrc = packet.header.ssrc;
        if pending.records.last().is_none_or(|record| record.seq != seq) {
            pending.records.push(PendingRecord { seq, arrival_us });
        }
    }

    /// Build and send feedback for all pending records. Returns the number of
    /// RTCP feedback packets sent.
    pub async fn flush(&self, transport: &RtpTransport) -> usize {
        let PendingFeedback { media_ssrc, mut records } =
            core::mem::take(&mut *self.pending.lock());
        let Some(anchor) = records.first().map(|record| record.seq) else {
            return 0;
        };
        // Sort around the first arrival so reordering (including across a
        // sequence-number wrap) does not look like loss.
        records.sort_by_key(|record| (record.seq.wrapping_sub(anchor) as i16, record.arrival_us));
        records.dedup_by_key(|record| record.seq);

        let mut sent = 0;
        let feedback_ssrc = self.feedback_ssrc.load(Ordering::SeqCst);
        let mut remaining = records.as_slice();
        while let Some(first) = remaining.first() {
            let count = remaining.partition_point(|record| {
                usize::from(record.seq.wrapping_sub(first.seq)) < MAX_STATUSES_PER_REPORT
            });
            let (window, rest) = remaining.split_at(count);
            remaining = rest;
            if let Some(feedback) = self.build_feedback(media_ssrc, feedback_ssrc, window)
                && transport
                    .send_rtcp(&[RtcpPacket::TransportWideCc(feedback)])
                    .await
                    .is_ok()
            {
                sent += 1;
                self.feedback_sent.fetch_add(1, Ordering::Relaxed);
            }
        }
        sent
    }

    /// Encode one feedback packet for a window of records.
    fn build_feedback(
        &self,
        media_ssrc: u32,
        feedback_ssrc: u32,
        records: &[PendingRecord],
    ) -> Option<TransportWideCc> {
        if records.is_empty() {
            return None;
        }

        let base_seq = records[0].seq;
        let reference_time = records[0].arrival_us / 64_000;
        let mut previous_arrival = (reference_time * 64_000) as i64;
        let mut statuses = Vec::with_capacity(records.len());
        let mut expected = base_seq;
        for record in records {
            let missing = usize::from(record.seq.wrapping_sub(expected));
            statuses.extend(core::iter::repeat_n(DeltaSize::Lost, missing));

            // The first delta starts at the 64 ms reference time, and the
            // rest start at the previous encoded arrival to avoid roundoff
            // accumulating. Sequence-sorted records can need negative deltas.
            let delta_us = record.arrival_us as i64 - previous_arrival;
            let units = (delta_us + delta_us.signum() * 125) / 250;
            let units = units.clamp(i64::from(i16::MIN), i64::from(i16::MAX));
            let delta = match u8::try_from(units) {
                Ok(small) => DeltaSize::Small(small),
                Err(_) => DeltaSize::Large(units as i16),
            };
            statuses.push(delta);
            previous_arrival += units * 250;
            expected = record.seq.wrapping_add(1);
        }
        let packet_status_count = statuses.len() as u16;

        let mut payload = Vec::with_capacity(statuses.len() / 3 + statuses.len());
        // Status chunks in the draft-holmer wire format (what Chrome/pion
        // parse): |T(1)|S|...|. Runs of identical statuses become run-length
        // chunks; mixed runs become S=1 status vector chunks (7 two-bit
        // symbols per chunk, zero-padded — receivers stop at
        // packet_status_count).
        let mut idx = 0usize;
        while idx < statuses.len() {
            let sym = symbol_bits(&statuses[idx]);
            // Length of the run of identical symbols starting here.
            let mut run = 1usize;
            while idx + run < statuses.len() && symbol_bits(&statuses[idx + run]) == sym {
                run += 1;
            }
            if run >= 3 {
                // Run length chunk: T=0 | S(2) | run(13).
                let chunk = (sym << 13) | (run as u16 & 0x1fff);
                payload.extend_from_slice(&chunk.to_be_bytes());
                idx += run;
            } else {
                // Status vector chunk: T=1 | S=1 | 7×2-bit symbols.
                let mut chunk: u16 = 0b11 << 14;
                for i in 0..7usize {
                    let s = statuses
                        .get(idx + i)
                        .map(|s| match s {
                            DeltaSize::Lost => 0b00u16,
                            DeltaSize::Small(_) => 0b01,
                            DeltaSize::Large(_) => 0b10,
                        })
                        .unwrap_or(0b00);
                    chunk |= s << (12 - 2 * i);
                }
                payload.extend_from_slice(&chunk.to_be_bytes());
                idx += 7;
            }
        }
        // Recv deltas in the same order as the statuses.
        for status in statuses {
            match status {
                DeltaSize::Lost => {}
                DeltaSize::Small(units) => payload.push(units),
                DeltaSize::Large(units) => payload.extend_from_slice(&units.to_be_bytes()),
            }
        }

        let seq = self.feedback_seq.fetch_add(1, Ordering::SeqCst);
        Some(TransportWideCc {
            sender_ssrc: feedback_ssrc,
            media_ssrc,
            base_sequence: base_seq,
            packet_status_count,
            // Reference time: 24-bit, 64 ms units, from our clock epoch.
            reference_time_64ms: reference_time as u32 & 0x00FF_FFFF,
            feedback_packet_count: (seq & 0xff) as u8,
            payload,
        })
    }

    /// Periodically flush an explicitly configured receiver's feedback.
    pub async fn run_flush_loop(self: Arc<Self>, transport: Arc<RtpTransport>) {
        let weak_transport = Arc::downgrade(&transport);
        drop(transport);
        Self::run_transport_flush_loop(Arc::downgrade(&self), weak_transport).await;
    }

    /// Exit when a transport is dropped or its negotiated feedback changes.
    pub(crate) async fn run_transport_flush_loop(
        feedback: Weak<Self>,
        transport: Weak<RtpTransport>,
    ) {
        let mut ticker = crate::platform::task::interval_after(FLUSH_INTERVAL, FLUSH_INTERVAL);
        ticker.set_missed_tick_behavior(crate::platform::task::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let (Some(feedback), Some(transport)) = (feedback.upgrade(), transport.upgrade()) else {
                return;
            };
            feedback.flush(&transport).await;
        }
    }
}

/// Wire symbol (2-bit) for a status.
fn symbol_bits(s: &DeltaSize) -> u16 {
    match s {
        DeltaSize::Lost => 0b00,
        DeltaSize::Small(_) => 0b01,
        DeltaSize::Large(_) => 0b10,
    }
}

fn rand_u16() -> u16 {
    (crate::transports::ice::stun::random_u32() & 0xffff) as u16
}

use crate::peer_connection::RtpReceiverInterceptor;
use async_trait::async_trait;

#[async_trait]
impl RtpReceiverInterceptor for TwccFeedbackGenerator {
    async fn on_packet_received(
        &self,
        packet: &RtpPacket,
        _src_addr: core::net::SocketAddr,
        _local_addr: core::net::SocketAddr,
    ) -> Option<RtcpPacket> {
        self.observe(packet);
        None
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::rtp::RtpHeader;

    #[test]
    fn feedback_packet_shape() {
        let generator = TwccFeedbackGenerator::new();
        generator.set_ext_id(5);
        generator.set_feedback_ssrc(0x1234_5678);

        // 15 packets arriving 40 ms apart use 1-byte deltas (160 units).
        let mut records = Vec::new();
        let t0 = 1_000_000u64;
        for i in 0..15u16 {
            records.push(PendingRecord {
                seq: 100 + i,
                arrival_us: t0 + i as u64 * 40_000,
            });
        }
        let fb = generator
            .build_feedback(0xAA_BB_CC_DD, 0x1234_5678, &records)
            .unwrap();
        assert_eq!(fb.media_ssrc, 0xAA_BB_CC_DD);
        assert_eq!(fb.base_sequence, 100);
        assert_eq!(fb.packet_status_count, 15);
        assert_eq!(fb.payload.len(), 2 + 15);
        let decoded = crate::rtp::decode_twcc_feedback(&fb);
        assert_eq!(fb.reference_time_64ms, 15);
        assert_eq!(decoded[0], (100, Some(40_000)));
    }

    #[test]
    fn small_deltas_use_one_byte() {
        let generator = TwccFeedbackGenerator::new();
        generator.set_ext_id(1);
        let records: Vec<PendingRecord> = (0..10u16)
            .map(|i| PendingRecord {
                seq: 5 + i,
                arrival_us: 500_000 + i as u64 * 5_000, // 5 ms → 20 units → 1 byte
            })
            .collect();
        let fb = generator.build_feedback(1, 2, &records).unwrap();
        assert_eq!(fb.payload.len(), 2 + 10); // 1 run-length chunk + 10 one-byte deltas
    }

    #[test]
    fn gaps_marked_not_received() {
        let generator = TwccFeedbackGenerator::new();
        generator.set_ext_id(1);
        // seq 10, then 12 (11 lost), then 13.
        let records = vec![
            PendingRecord {
                seq: 10,
                arrival_us: 0,
            },
            PendingRecord {
                seq: 12,
                arrival_us: 1_000,
            },
            PendingRecord {
                seq: 13,
                arrival_us: 2_000,
            },
        ];
        let fb = generator.build_feedback(1, 2, &records).unwrap();
        assert_eq!(fb.packet_status_count, 4); // 10, 11(lost), 12, 13
        // First status chunk symbol for seq 11 must be 00.
        // Chunk bytes: [10, symbols...] — decode via decode helper.
        let decoded = crate::rtp::decode_twcc_feedback(&fb);
        assert_eq!(decoded.len(), 4);
        assert!(decoded.iter().any(|(seq, d)| *seq == 11 && d.is_none()));
        assert_eq!(decoded[0], (10, Some(0)));
        assert_eq!(decoded[3], (13, Some(1_000)));
    }

    #[test]
    fn observe_ignores_packets_without_ext() {
        let generator = TwccFeedbackGenerator::new();
        let mut header = RtpHeader::new(96, 1, 9000, 42);
        header.set_extension(3, &[1, 2, 3, 4]).unwrap();
        generator.observe(&RtpPacket::new(header, vec![0u8; 10]));
        assert!(generator.pending.lock().records.is_empty());
    }
}
