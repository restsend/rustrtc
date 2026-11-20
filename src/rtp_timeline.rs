//! Outbound RTP timeline of one outgoing SSRC.
//!
//! A leg's outgoing media keeps one SSRC for the whole call while its packets
//! come from different places over time. The timeline distinguishes peer
//! packets from generated media:
//!
//! - **Peer packets** (`write_peer`: relayed peers or locally packetized video)
//!   carry a source SSRC, sequence number, and timestamp. The timeline anchors
//!   on the first packet of a run and maps following packets from that anchor
//!   (scaling timestamp deltas when `in_clock != out_clock`), preserving source
//!   loss, reordering, retransmission, and spacing. It re-anchors when there is
//!   no anchor, the source SSRC changes, or the stream jumps
//!   (sequence leaves `SEQ_REORDER_WINDOW` or timestamp steps beyond 2 s).
//! - **Generated frames** (`write_frame`: playback, silence, transcoding)
//!   advance `seq + 1` and `ts + ptime` in steady state, catching up by real
//!   elapsed time (and setting the RTP marker bit) when leaving a peer/DTMF
//!   anchor or after a silent gap (> 200 ms).
//!
//! `write_peer` never modifies the RTP marker bit. Late peer packets are sent
//! with their mapped values without rewinding the cursor.

use core::time::Duration;
use crate::platform::sync::Mutex;
use crate::platform::time::Instant;
use crate::prelude::*;

/// Sequence distance (reordering, loss, and RTCP NACK lookback) accepted on an
/// active anchor before treating a step as a stream jump.
const SEQ_REORDER_WINDOW: u16 = 256;
/// Timestamp step (either direction) from `cur_ts` treated as a jump.
const MAX_TS_STEP: Duration = Duration::from_secs(2);
/// Default generated audio frame interval.
const DEFAULT_PTIME: Duration = Duration::from_millis(20);
/// Silence gap threshold before generated audio catches up to wall time.
const PLAYBACK_GAP: Duration = Duration::from_millis(200);

#[derive(Clone, Copy, Debug)]
struct Anchor {
    ssrc: u32,
    seq_offset: u16,
    nack_span: u16,
    in_ts: u32,
    out_ts: u32,
}

#[derive(Debug)]
struct State {
    clock_rate: u32,
    ptime: Duration,
    cur_seq: u16,
    cur_ts: u32,
    /// Monotonic instant when `cur_ts` last moved forward.
    cur_ts_at: Instant,
    anchor: Option<Anchor>,
}

impl State {
    fn ticks(&self, dur: Duration) -> u32 {
        (dur.as_nanos() * u128::from(self.clock_rate) / 1_000_000_000) as u32
    }

    fn push(&mut self, ticks: u32) -> (u16, u32) {
        self.cur_seq = self.cur_seq.wrapping_add(1);
        self.cur_ts = self.cur_ts.wrapping_add(ticks);
        self.cur_ts_at = Instant::now();
        (self.cur_seq, self.cur_ts)
    }
}

/// The shared outgoing timeline of one SSRC. See the module docs.
#[derive(Debug)]
pub struct OutboundTimeline {
    ssrc: u32,
    state: Mutex<State>,
}

impl OutboundTimeline {
    /// Create a timeline seeded at `(initial_seq, initial_ts)`. Every packet
    /// advances from the current cursor.
    pub fn new(ssrc: u32, clock_rate: u32, initial_seq: u16, initial_ts: u32) -> Arc<Self> {
        assert!(clock_rate > 0, "RTP clock_rate must be non-zero");
        Arc::new(Self {
            ssrc,
            state: Mutex::new(State {
                clock_rate,
                ptime: DEFAULT_PTIME,
                cur_seq: initial_seq,
                cur_ts: initial_ts,
                cur_ts_at: Instant::now(),
                anchor: None,
            }),
        })
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn clock_rate(&self) -> u32 {
        self.state.lock().clock_rate
    }

    /// Update the RTP clock rate (e.g. after a codec change). Ignores 0.
    pub fn set_clock_rate(&self, clock_rate: u32) {
        if clock_rate != 0 {
            let mut state = self.state.lock();
            if state.clock_rate != clock_rate {
                state.clock_rate = clock_rate;
                state.anchor = None;
            }
        }
    }

    /// Set the duration of the generated audio frames provided by the local
    /// source (default 20 ms). Ignores zero.
    pub fn set_ptime(&self, ptime: Duration) {
        if !ptime.is_zero() {
            self.state.lock().ptime = ptime;
        }
    }

    /// Sequence number the next packet will carry.
    pub fn next_sequence_number(&self) -> u16 {
        self.state.lock().cur_seq.wrapping_add(1)
    }

    /// Map a peer or packetized video RTP packet onto this timeline in place,
    /// scaling timestamp deltas when `in_clock` differs from this timeline's
    /// clock rate.
    pub fn write_peer(&self, packet: &mut crate::rtp::RtpPacket, in_clock: u32) {
        let mut state = self.state.lock();
        let out_clock = state.clock_rate;
        let ssrc = packet.header.ssrc;
        let seq = packet.header.sequence_number;
        let ts = packet.header.timestamp;
        let max_step = state.ticks(MAX_TS_STEP);
        if let Some(mut anchor) = state.anchor
            && anchor.ssrc == ssrc
        {
            let out_seq = seq.wrapping_add(anchor.seq_offset);
            let (out_ts, exact) = if in_clock == out_clock {
                (anchor.out_ts.wrapping_add(ts.wrapping_sub(anchor.in_ts)), true)
            } else {
                let delta_in = i64::from(ts.wrapping_sub(anchor.in_ts) as i32);
                let num = delta_in * i64::from(out_clock);
                let delta_out = (num / i64::from(in_clock)) as i32;
                (
                    anchor.out_ts.wrapping_add(delta_out as u32),
                    num % i64::from(in_clock) == 0,
                )
            };
            let dseq = out_seq.wrapping_sub(state.cur_seq) as i16;
            let dts = out_ts.wrapping_sub(state.cur_ts) as i32;
            if dseq.unsigned_abs() <= SEQ_REORDER_WINDOW && dts.unsigned_abs() <= max_step {
                if dseq > 0 {
                    state.cur_seq = out_seq;
                    anchor.nack_span = (anchor.nack_span + dseq as u16).min(SEQ_REORDER_WINDOW);
                }
                if dts > 0 {
                    state.cur_ts = out_ts;
                    state.cur_ts_at = Instant::now();
                    if exact {
                        anchor.in_ts = ts;
                        anchor.out_ts = out_ts;
                    }
                }
                state.anchor = Some(anchor);
                packet.header.ssrc = self.ssrc;
                packet.header.sequence_number = out_seq;
                packet.header.timestamp = out_ts;
                return;
            }
        }

        let elapsed = state.cur_ts_at.elapsed();
        let step = state.ticks(elapsed.max(state.ptime)).max(1);
        let (out_seq, out_ts) = state.push(step);
        state.anchor = Some(Anchor {
            ssrc,
            seq_offset: out_seq.wrapping_sub(seq),
            nack_span: 0,
            in_ts: ts,
            out_ts,
        });
        packet.header.ssrc = self.ssrc;
        packet.header.sequence_number = out_seq;
        packet.header.timestamp = out_ts;
    }

    /// Advance generated audio by one `ptime` interval in place, catching up by
    /// elapsed wall time (with marker set) when leaving a peer/DTMF run or after
    /// a silent gap (> 200 ms).
    pub fn write_frame(&self, packet: &mut crate::rtp::RtpPacket) {
        let mut state = self.state.lock();
        let was_peer = state.anchor.take().is_some();
        let ptime_ticks = state.ticks(state.ptime).max(1);
        let elapsed = state.cur_ts_at.elapsed();
        let ticks = if was_peer || elapsed > PLAYBACK_GAP {
            packet.header.marker = true;
            state.ticks(elapsed).max(ptime_ticks)
        } else {
            ptime_ticks
        };
        let (seq, ts) = state.push(ticks);
        packet.header.ssrc = self.ssrc;
        packet.header.sequence_number = seq;
        packet.header.timestamp = ts;
    }

    /// Peer currently supplying this output; local sources (`ssrc == 0`) and
    /// generated media have no upstream peer to receive a keyframe request.
    pub fn peer_source_ssrc(&self) -> Option<u32> {
        self.state.lock().anchor.map(|a| a.ssrc).filter(|&s| s != 0)
    }

    /// Reverse-map NACKs within the active peer's run, capped at
    /// `SEQ_REORDER_WINDOW` behind `cur_seq`.
    pub fn translate_nack(&self, source_ssrc: u32, lost: &[u16]) -> Vec<u16> {
        let state = self.state.lock();
        let Some(anchor) = state.anchor.filter(|a| a.ssrc == source_ssrc) else {
            return Vec::new();
        };
        lost.iter()
            .copied()
            .filter(|&seq| state.cur_seq.wrapping_sub(seq) <= anchor.nack_span)
            .map(|seq| seq.wrapping_sub(anchor.seq_offset))
            .collect()
    }

    /// Map a repair's original sequence and timestamp through the active video
    /// run. RTX uses the same clock as its primary. The repair does not move
    /// the primary timeline or establish a new anchor.
    pub(crate) fn translate_rtx(
        &self,
        source_ssrc: Option<u32>,
        repair_ssrc: u32,
        original_sequence: u16,
        timestamp: u32,
    ) -> Option<(u16, u32)> {
        let state = self.state.lock();
        let anchor = state.anchor?;
        if anchor.ssrc == 0
            || anchor.ssrc == repair_ssrc
            || source_ssrc.is_some_and(|ssrc| ssrc != anchor.ssrc)
        {
            return None;
        }
        let sequence = original_sequence.wrapping_add(anchor.seq_offset);
        let timestamp = anchor.out_ts.wrapping_add(timestamp.wrapping_sub(anchor.in_ts));
        let timestamp_step = timestamp.wrapping_sub(state.cur_ts) as i32;
        (state.cur_seq.wrapping_sub(sequence) <= anchor.nack_span
            && timestamp_step.unsigned_abs() <= state.ticks(MAX_TS_STEP))
            .then_some((sequence, timestamp))
    }

    /// RTP timestamp for an RTCP Sender Report at "now".
    pub fn timestamp(&self) -> u32 {
        let state = self.state.lock();
        state
            .cur_ts
            .wrapping_add(state.ticks(state.cur_ts_at.elapsed()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::{RtpHeader, RtpPacket};

    fn advance_clock(t: &OutboundTimeline, ms: u64) {
        let mut s = t.state.lock();
        s.cur_ts_at = s.cur_ts_at - Duration::from_millis(ms);
    }

    fn send_peer(t: &OutboundTimeline, ssrc: u32, seq: u16, ts: u32) -> (u16, u32) {
        let mut pkt = RtpPacket::new(RtpHeader::new(0, seq, ts, ssrc), Vec::new());
        t.write_peer(&mut pkt, t.clock_rate());
        (pkt.header.sequence_number, pkt.header.timestamp)
    }

    fn send_frame(t: &OutboundTimeline) -> (u16, u32) {
        let mut pkt = RtpPacket::new(RtpHeader::new(0, 0, 0, 0), Vec::new());
        t.write_frame(&mut pkt);
        (pkt.header.sequence_number, pkt.header.timestamp)
    }

    fn timeline() -> Arc<OutboundTimeline> {
        OutboundTimeline::new(0xA1, 8000, 999, 50_000 - 160)
    }

    #[test]
    fn peer_packets_map_with_a_fixed_offset_including_loss_and_reordering() {
        let t = timeline();
        assert_eq!(send_peer(&t, 0xB, 300, 9_000), (1000, 50_000));
        assert_eq!(send_peer(&t, 0xB, 303, 9_480), (1003, 50_480));
        assert_eq!(send_peer(&t, 0xB, 302, 9_320), (1002, 50_320));
        assert_eq!(send_peer(&t, 0xB, 300, 9_000), (1000, 50_000));
        assert_eq!(t.next_sequence_number(), 1004);
        assert_eq!(send_peer(&t, 0xB, 304, 17_480), (1004, 58_480));
    }

    #[test]
    fn cross_clock_peer_scales_deltas_across_u32_wraparound() {
        let t = timeline();
        let mut p1 = RtpPacket::new(RtpHeader::new(101, 10, u32::MAX - 960, 0xB), Vec::new());
        t.write_peer(&mut p1, 48_000);
        assert_eq!(
            (p1.header.sequence_number, p1.header.timestamp),
            (1000, 50_000)
        );
        let mut p2 = RtpPacket::new(RtpHeader::new(101, 11, u32::MAX - 960, 0xB), Vec::new());
        t.write_peer(&mut p2, 48_000);
        assert_eq!(
            (p2.header.sequence_number, p2.header.timestamp),
            (1001, 50_000)
        );
        let next_in_ts = (u32::MAX - 960).wrapping_add(8_160);
        let mut p3 = RtpPacket::new(RtpHeader::new(101, 12, next_in_ts, 0xB), Vec::new());
        t.write_peer(&mut p3, 48_000);
        assert_eq!(
            (p3.header.sequence_number, p3.header.timestamp),
            (1002, 51_360)
        );
    }

    #[test]
    fn lone_peer_keeps_non_monotonic_timestamps() {
        let t = timeline();
        send_peer(&t, 0xB, 1, 0);
        send_peer(&t, 0xB, 2, 480);
        assert_eq!(send_peer(&t, 0xB, 3, 160), (1002, 50_160));
        assert_eq!(send_peer(&t, 0xB, 4, 320), (1003, 50_320));
    }

    #[test]
    fn ssrc_change_and_jump_anchor_after_the_cursor_with_wall_clock() {
        let t = timeline();
        send_peer(&t, 0xB, 10, 0);
        send_peer(&t, 0xB, 11, 160);
        advance_clock(&t, 500);
        let (_, ts_c) = send_peer(&t, 0xC, 7, 123);
        assert!((50_160 + 4_000..=50_160 + 4_080).contains(&ts_c));
        assert_eq!(send_peer(&t, 0xC, 8, 283), (1003, ts_c + 160));
        assert_eq!(send_peer(&t, 0xC, 5_000, 443), (1004, ts_c + 320));
        assert_eq!(send_peer(&t, 0xC, 5_001, 999_999), (1005, ts_c + 480));
    }

    #[test]
    fn generated_frames_step_past_dtmf_and_continue_by_ptime() {
        let t = timeline();
        assert_eq!(send_frame(&t), (1000, 50_000));
        advance_clock(&t, 20);
        let (seq, event_ts) = send_peer(&t, 0xB, 300, 9_000);
        assert_eq!(seq, 1001);
        assert!((50_160..=50_240).contains(&event_ts), "ts={event_ts}");
        advance_clock(&t, 20);
        for i in 1..6u16 {
            assert_eq!(send_peer(&t, 0xB, 300 + i, 9_000), (1001 + i, event_ts));
            advance_clock(&t, 20);
        }
        // cur_ts_at stayed at pkt 1 of the digit (120 ms ago = 960 ticks).
        let (seq, ts) = send_frame(&t);
        assert_eq!(seq, 1007);
        assert!((event_ts + 960..=event_ts + 1_040).contains(&ts), "ts={ts}");
        assert_eq!(send_frame(&t), (1008, ts + 160));
    }

    #[test]
    fn frame_after_a_silent_gap_anchors_on_the_wall_clock() {
        let t = timeline();
        send_frame(&t);
        send_frame(&t);
        advance_clock(&t, 3_000);
        let (seq, ts) = send_frame(&t);
        assert_eq!(seq, 1002);
        assert!((50_160 + 3_000 * 8..=50_160 + 3_050 * 8).contains(&ts));
        assert_eq!(send_frame(&t), (1003, ts + 160));
    }

    #[test]
    fn buffered_playback_ahead_of_wall_clock_keeps_frame_duration() {
        let t = timeline();
        for i in 0..15u32 {
            assert_eq!(send_frame(&t), (1000 + i as u16, 50_000 + i * 160));
        }
    }

    #[test]
    fn configured_ptime_controls_frame_step() {
        let t = OutboundTimeline::new(0xA1, 8000, 999, 50_000 - 80);
        t.set_ptime(Duration::from_millis(10));
        let (_, ts0) = send_frame(&t);
        assert_eq!(send_frame(&t).1, ts0 + 80);
        t.set_ptime(Duration::from_millis(30));
        assert_eq!(send_frame(&t).1, ts0 + 320);
        t.set_ptime(Duration::from_millis(20));
        assert_eq!(send_frame(&t).1, ts0 + 480);
    }

    #[test]
    fn local_ssrc_zero_maps_like_peer_without_reporting_peer_source() {
        let t = OutboundTimeline::new(1, 90000, 99, 50000 - 1800);
        assert_eq!(send_peer(&t, 0, 0, 9000).0, 100);
        assert_eq!(send_peer(&t, 0, 1, 9000).0, 101);
        assert_eq!(t.peer_source_ssrc(), None);
        send_peer(&t, 42, 7, 100);
        assert_eq!(t.peer_source_ssrc(), Some(42));
        send_peer(&t, 0, 3, 12600);
        assert_eq!(t.peer_source_ssrc(), None);
    }

    #[test]
    fn nack_translation_uses_active_anchor_and_window() {
        let t = OutboundTimeline::new(1, 8000, 99, 10000 - 160);
        send_peer(&t, 42, 1, 0);
        send_peer(&t, 42, 4, 480);
        assert_eq!(
            t.translate_nack(42, &[100, 101, 102, 103, 500]),
            vec![1, 2, 3, 4]
        );
        let generated = send_frame(&t);
        assert!(t.translate_nack(42, &[101, generated.0]).is_empty());
        let switched = send_peer(&t, 99, 30, 0);
        assert_eq!(t.peer_source_ssrc(), Some(99));
        assert!(t.translate_nack(42, &[switched.0]).is_empty());
        assert_eq!(t.translate_nack(99, &[switched.0 - 1, switched.0, switched.0 + 10]), vec![30]);
    }

    #[test]
    fn nack_translation_handles_wrap_and_caps_window() {
        let t = OutboundTimeline::new(1, 8000, 65533, 10000 - 160);
        send_peer(&t, 42, 700, 0);
        send_peer(&t, 42, 703, 480);
        assert_eq!(t.translate_nack(42, &[65535, 0, 1]), vec![701, 702, 703]);
        let mut latest = 0;
        for i in 4..=5000u16 {
            latest = send_peer(&t, 42, 700u16.wrapping_add(i), u32::from(i) * 160).0;
        }
        assert!(t.translate_nack(42, &[65535]).is_empty());
        assert_eq!(t.translate_nack(42, &[latest]), vec![700 + 5000]);
    }
}
