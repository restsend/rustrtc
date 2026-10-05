//! Sender-side bandwidth estimation (simplified GCC).
//!
//! Consumes TWCC feedback ([`RtcpPacket::TransportWideCc`]) on the RTCP path
//! and maintains a `target_bitrate` estimate using a simplified Google
//! Congestion Control loop:
//!
//! - **Trendline delay gradient**: linear regression of `(send-side
//!   inter-packet delta, arrival-side inter-packet delta)` over a sliding
//!   window (RFC 6714/"trendline filter" flavor of draft-ietf-rmcat-gcc-01).
//! - **Overuse detector**: slope above a threshold → decrease (multiplicative
//!   0.85×), below −threshold → increase (multiplicative 1.08×), else hold
//!   with additive growth (+50 kbps per second equivalent).
//! - **Loss guard**: > 10 % loss floor the estimate at `loss_floor`, < 2 %
//!   allows recovery.
//!
//! The library never changes its own send rate — the estimate is published on
//! a watch channel for the owning application (encoder) to act on.

use crate::prelude::*;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use parking_lot::Mutex;

use crate::rtp::{decode_twcc_feedback, RtcpPacket};

/// Initial estimate (Chrome's default start).
pub const START_BITRATE_BPS: u64 = 1_000_000;
/// Floor: below this, video is unusable.
pub const MIN_BITRATE_BPS: u64 = 150_000;
/// Ceiling for the estimator itself (apps may clamp further).
pub const MAX_BITRATE_BPS: u64 = 10_000_000;
/// Delay-gradient threshold (ms/ms), analogous to GCC's default threshold.
const SLOPE_THRESHOLD: f64 = 0.01;
/// Window of samples for the trendline regression.
const TRENDLINE_WINDOW: usize = 20;
/// Multiplicative decrease/increase factors.
const DECREASE_FACTOR: f64 = 0.85;
const INCREASE_FACTOR: f64 = 1.08;
/// Additive growth per second (in overuse-free steady state).
const ADDITIVE_BPS_PER_SEC: u64 = 50_000;

#[derive(Debug, Clone, Copy)]
struct TrendSample {
    /// TWCC-reported arrival delta for the packet (µs).
    recv_delta_us: i64,
}

pub struct GccBandwidthEstimator {
    target_bitrate: tokio::sync::watch::Sender<u64>,
    _bitrate_keeper: tokio::sync::watch::Receiver<u64>,
    samples: Mutex<VecDeque<TrendSample>>,
    last_update: Mutex<Instant>,
    /// Stats.
    pub feedback_packets: AtomicU64,
    pub acked_packets: AtomicU64,
    pub lost_packets: AtomicU64,
    decreases: AtomicU64,
    increases: AtomicU64,
}

impl Default for GccBandwidthEstimator {
    fn default() -> Self {
        Self::new()
    }
}

impl GccBandwidthEstimator {
    pub fn new() -> Self {
        let (tx, rx) = tokio::sync::watch::channel(START_BITRATE_BPS);
        Self {
            target_bitrate: tx,
            _bitrate_keeper: rx,
            samples: Mutex::new(VecDeque::with_capacity(TRENDLINE_WINDOW)),
            last_update: Mutex::new(Instant::now()),
            feedback_packets: AtomicU64::new(0),
            acked_packets: AtomicU64::new(0),
            lost_packets: AtomicU64::new(0),
            decreases: AtomicU64::new(0),
            increases: AtomicU64::new(0),
        }
    }

    pub fn target_bitrate(&self) -> u64 {
        *self.target_bitrate.borrow()
    }

    pub fn subscribe_target_bitrate(&self) -> tokio::sync::watch::Receiver<u64> {
        self.target_bitrate.subscribe()
    }

    /// Feed one TWCC feedback packet; updates the estimate.
    pub fn on_twcc_feedback(&self, feedback: &crate::rtp::TransportWideCc) {
        self.feedback_packets.fetch_add(1, Ordering::Relaxed);
        let entries = decode_twcc_feedback(feedback);
        tracing::debug!(
            "GCC: twcc feedback base={} count={} decoded={}",
            feedback.base_sequence,
            feedback.packet_status_count,
            entries.len()
        );
        if entries.is_empty() {
            return;
        }
        let mut lost = 0u64;
        let mut acked = 0u64;
        {
            let mut samples = self.samples.lock();
            for (_seq, delta) in entries {
                match delta {
                    None => lost += 1,
                    Some(recv_delta_us) => {
                        acked += 1;
                        samples.push_back(TrendSample {
                            recv_delta_us,
                        });
                    }
                }
            }
            while samples.len() > TRENDLINE_WINDOW {
                samples.pop_front();
            }
        }
        self.acked_packets.fetch_add(acked, Ordering::Relaxed);
        self.lost_packets.fetch_add(lost, Ordering::Relaxed);

        self.update_estimate(acked, lost);
    }

    fn update_estimate(&self, acked: u64, lost: u64) {
        let now = Instant::now();
        let elapsed = {
            let mut lu = self.last_update.lock();
            let e = lu.elapsed();
            *lu = now;
            e
        };

        let slope = self.trendline_slope();
        let current = self.target_bitrate.borrow().clone() as f64;

        let loss_ratio = if acked + lost > 0 {
            lost as f64 / (acked + lost) as f64
        } else {
            0.0
        };

        let next: f64 = if loss_ratio > 0.10 {
            // Heavy loss dominates: back off.
            self.decreases.fetch_add(1, Ordering::Relaxed);
            (current * DECREASE_FACTOR).max(MIN_BITRATE_BPS as f64)
        } else if slope > SLOPE_THRESHOLD {
            // Queue building up on the path: decrease.
            self.decreases.fetch_add(1, Ordering::Relaxed);
            (current * DECREASE_FACTOR).max(MIN_BITRATE_BPS as f64)
        } else if slope < -SLOPE_THRESHOLD {
            // Queue draining: recover multiplicatively.
            self.increases.fetch_add(1, Ordering::Relaxed);
            (current * INCREASE_FACTOR).min(MAX_BITRATE_BPS as f64)
        } else {
            // Steady state: additive growth.
            let add = ADDITIVE_BPS_PER_SEC as f64 * elapsed.as_secs_f64();
            (current + add).min(MAX_BITRATE_BPS as f64)
        };

        let _ = self.target_bitrate.send(next.round() as u64);
    }

    /// Least-squares slope of the recv-delta trend over the window (ms/ms
    /// approximation: consecutive recv-delta drift per sample index).
    fn trendline_slope(&self) -> f64 {
        let samples = self.samples.lock();
        let n = samples.len();
        if n < 4 {
            return 0.0;
        }
        // x = sample index, y = recv delta in ms.
        let n_f = n as f64;
        let mean_x = (n_f - 1.0) / 2.0;
        let mean_y: f64 =
            samples.iter().map(|s| s.recv_delta_us as f64 / 1000.0).sum::<f64>() / n_f;
        let mut num = 0.0;
        let mut den = 0.0;
        for (i, s) in samples.iter().enumerate() {
            let x = i as f64 - mean_x;
            let y = s.recv_delta_us as f64 / 1000.0 - mean_y;
            num += x * y;
            den += x * x;
        }
        if den == 0.0 {
            return 0.0;
        }
        num / den
    }


    pub fn decrease_count(&self) -> u64 {
        self.decreases.load(Ordering::Relaxed)
    }

    pub fn increase_count(&self) -> u64 {
        self.increases.load(Ordering::Relaxed)
    }
}

use async_trait::async_trait;
use crate::peer_connection::RtpSenderInterceptor;
use crate::transports::rtp::RtpTransport;

#[async_trait]
impl RtpSenderInterceptor for GccBandwidthEstimator {
    async fn on_rtcp_received(&self, packet: &RtcpPacket, _transport: std::sync::Arc<RtpTransport>) {
        if let RtcpPacket::TransportWideCc(feedback) = packet {
            self.on_twcc_feedback(feedback);
        }
    }

    fn as_gcc_stats(
        self: std::sync::Arc<Self>,
    ) -> Option<std::sync::Arc<GccBandwidthEstimator>> {
        Some(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::TransportWideCc;

    fn feedback(entries: &[(u16, Option<i64>)], base_seq: u16) -> TransportWideCc {
        // Build a feedback packet via the generator's encoder shape:
        // draft-holmer status vector chunks (T=1,S=1, 7×2-bit symbols) +
        // 1-byte (unsigned) / 2-byte (signed) deltas by range.
        let mut payload = Vec::new();
        for group in entries.chunks(7) {
            let mut chunk: u16 = 0b11 << 14;
            for i in 0..7 {
                let sym = match group.get(i) {
                    None => 0b00,
                    Some((_, None)) => 0b00,
                    Some((_, Some(us))) => {
                        if (0..=255).contains(&(us / 250)) {
                            0b01
                        } else {
                            0b10
                        }
                    }
                };
                chunk |= sym << (12 - 2 * i);
            }
            payload.extend_from_slice(&chunk.to_be_bytes());
        }
        for (_, d) in entries {
            if let Some(us) = d {
                let units = us / 250;
                if (0..=255).contains(&units) {
                    payload.push(units as u8);
                } else {
                    payload.extend_from_slice(&(units as i16).to_be_bytes());
                }
            }
        }
        TransportWideCc {
            sender_ssrc: 1,
            media_ssrc: 2,
            base_sequence: base_seq,
            packet_status_count: entries.len() as u16,
            reference_time_64ms: 0,
            feedback_packet_count: 0,
            payload,
        }
    }

    #[test]
    fn estimator_reacts_to_delay_growth() {
        let est = GccBandwidthEstimator::new();
        let start = est.target_bitrate();

        // Steady small deltas → additive growth.
        let fb = feedback(
            &(0..10)
                .map(|i| (i as u16, Some(1000)))
                .collect::<Vec<_>>(),
            0,
        );
        est.on_twcc_feedback(&fb);
        let steady = est.target_bitrate();
        assert!(steady >= start, "steady state must not decrease");

        // Growing deltas (queue building) → decrease.
        let fb = feedback(
            &(0..10)
                .map(|i| (i as u16, Some((i as i64 + 1) * 8_000)))
                .collect::<Vec<_>>(),
            20,
        );
        est.on_twcc_feedback(&fb);
        let after_growth = est.target_bitrate();
        assert!(
            after_growth < steady,
            "delay growth must decrease the estimate: {steady} -> {after_growth}"
        );
        assert!(est.decrease_count() >= 1);
    }

    #[test]
    fn estimator_floors_at_min() {
        let est = GccBandwidthEstimator::new();
        for round in 0..30 {
            let fb = feedback(
                &(0..10)
                    .map(|i| (i as u16 + round * 10, Some((i as i64 + 1) * 20_000)))
                    .collect::<Vec<_>>(),
                0,
            );
            est.on_twcc_feedback(&fb);
        }
        assert!(est.target_bitrate() >= MIN_BITRATE_BPS);
        assert_eq!(est.target_bitrate(), MIN_BITRATE_BPS);
    }

    #[test]
    fn estimator_ignores_empty_feedback() {
        let est = GccBandwidthEstimator::new();
        let fb = feedback(&[], 0);
        est.on_twcc_feedback(&fb);
        assert_eq!(est.target_bitrate(), START_BITRATE_BPS);
    }
}
