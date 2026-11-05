//! Reordering buffer for inbound RTP media, with two ways to take the
//! media out:
//!
//! - [`JitterBuffer::pop`], by arrival time: each sample is released once it
//!   has waited `min_delay` (or `max_delay` while the one before it is
//!   missing), so the sender's timing passes through.
//! - [`JitterBuffer::tick`], on a playout clock: call it once per packet
//!   time ([`JitterBuffer::ptime`]) and get the next sample in sequence
//!   order, or [`Playout::Lost`] when one is due but missing, so the gap
//!   can be concealed where it belongs. Playout starts once `min_delay` of
//!   audio is buffered, the delay that absorbs jitter; `max_delay` caps how
//!   much is buffered. A sample missing while later ones are buffered is
//!   lost. One missing with nothing buffered may only be late: it's
//!   reported lost but its slot kept, and after
//!   [`PlayoutConfig::max_conceal`] of that the buffer rebuffers. A sender
//!   going quiet ([`JitterBuffer::pause`]) rebuffers without reporting
//!   losses. Delay built up by underruns is trimmed after
//!   [`PlayoutConfig::trim_after`] above the target.
//!
//! Use one or the other on a buffer, not both. Either way, samples are
//! reordered, late ones and duplicates dropped, and a new SSRC, a large
//! sequence gap or a timestamp jump restarts the stream.

use crate::media::frame::MediaSample;
use crate::platform::time::Instant;
#[cfg_attr(feature = "std", allow(unused_imports))]
#[cfg_attr(not(feature = "std"), allow(unused_imports))]
use crate::prelude::*;
use alloc::collections::BTreeMap;
use core::time::Duration;

/// What [`JitterBuffer::tick`] has to play.
#[derive(Debug)]
pub enum Playout {
    /// The next sample, in sequence order.
    Sample(MediaSample),
    /// A sample is due but missing: conceal it. [`JitterBuffer::following`]
    /// is the one after it, when already buffered (for in-band FEC).
    Lost,
    /// Nothing to play: not started, rebuffering, or the sender is quiet.
    Idle,
}

/// Clocked playout settings (see [`JitterBuffer::tick`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlayoutConfig {
    /// How long an underrun is reported as loss before the buffer gives up
    /// on the missing samples and rebuffers. Default 100 ms.
    pub max_conceal: Duration,
    /// How long the buffer may hold more than a packet time above its
    /// target before one sample is dropped to bring the delay back down.
    /// Default 2 s.
    pub trim_after: Duration,
}

impl Default for PlayoutConfig {
    fn default() -> Self {
        Self {
            max_conceal: Duration::from_millis(100),
            trim_after: Duration::from_secs(2),
        }
    }
}

/// Counters since the buffer was created ([`JitterBuffer::reset`] doesn't
/// clear them).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct JitterBufferStats {
    /// Samples pushed with a sequence number.
    pub received: u64,
    /// Samples delivered, by `pop` or `tick`.
    pub played: u64,
    /// Missing while later samples were buffered (`tick`).
    pub lost: u64,
    /// Reported lost with nothing buffered (`tick`).
    pub underruns: u64,
    /// Arrived after their slot was played or given up.
    pub late: u64,
    pub duplicates: u64,
    /// Dropped to stay within capacity or `max_delay`, or to trim delay.
    pub dropped: u64,
    /// Stream restarts: a new SSRC, a sequence gap or a timestamp jump, or
    /// a `reset` call.
    pub resets: u64,
    /// Times the sender went quiet (`tick`, see [`JitterBuffer::pause`]).
    pub pauses: u64,
}

/// Packet time assumed until the sender's is measured.
const DEFAULT_PTIME: Duration = Duration::from_millis(20);
/// Packet times followed, measured from RTP timestamps.
const MIN_PTIME: Duration = Duration::from_millis(10);
const MAX_PTIME: Duration = Duration::from_millis(120);
/// Consecutive samples measuring a new packet time before it's followed.
const PTIME_CONFIRM: u32 = 5;
/// RFC 3389 comfort noise: the sender goes quiet after it.
const COMFORT_NOISE_PT: u8 = 13;

#[derive(Debug)]
struct BufferedSample {
    sample: MediaSample,
    arrival: Instant,
}

pub struct JitterBuffer {
    samples: BTreeMap<u16, BufferedSample>,
    last_delivered_seq: Option<u16>,
    last_delivered_timestamp: Option<u32>,
    last_ssrc: Option<u32>,
    max_delay: Duration,
    min_delay: Duration,
    capacity: usize,
    playout_config: PlayoutConfig,
    /// `tick` is playing out (not waiting for the buffer to fill).
    playing: bool,
    /// Consecutive samples `tick` reported lost.
    concealed_run: u32,
    /// Consecutive ticks with the buffer more than a sample above target.
    above_target_ticks: u32,
    ptime: Duration,
    /// A packet time other than `ptime` the last samples measured, and
    /// for how many in a row.
    other_ptime: (Duration, u32),
    /// Sequence number and timestamp of the last sample pushed.
    last_pushed: Option<(u16, u32)>,
    stats: JitterBufferStats,
}

/// Sequence gap larger than this (relative to last delivered) is treated as a
/// stream restart (re-INVITE / latch / rewrite), not ordinary reordering.
const MAX_SEQ_GAP: u16 = 64;
/// Audio timestamp jump (seconds of clock_rate) that forces a buffer reset.
/// re-INVITE / hold-resume often remaps the RTP clock without changing SSRC.
const AUDIO_TS_JUMP_SECS: u32 = 2;
/// Video timestamp jump threshold (seconds @ 90 kHz).
const VIDEO_TS_JUMP_SECS: u32 = 5;

impl JitterBuffer {
    pub fn new(min_delay: Duration, max_delay: Duration, capacity: usize) -> Self {
        Self {
            samples: BTreeMap::new(),
            last_delivered_seq: None,
            last_delivered_timestamp: None,
            last_ssrc: None,
            max_delay,
            min_delay,
            capacity,
            playout_config: PlayoutConfig::default(),
            playing: false,
            concealed_run: 0,
            above_target_ticks: 0,
            ptime: DEFAULT_PTIME,
            other_ptime: (DEFAULT_PTIME, 0),
            last_pushed: None,
            stats: JitterBufferStats::default(),
        }
    }

    /// Settings for [`JitterBuffer::tick`].
    pub fn set_playout_config(&mut self, config: PlayoutConfig) {
        self.playout_config = config;
    }

    /// Reset the jitter buffer state, clearing all samples and the stream's
    /// state. Call when a stream discontinuity is detected (SSRC change,
    /// re-INVITE). The counters in [`JitterBuffer::stats`] carry on.
    pub fn reset(&mut self) {
        self.samples.clear();
        self.last_delivered_seq = None;
        self.last_delivered_timestamp = None;
        self.last_ssrc = None;
        self.playing = false;
        self.concealed_run = 0;
        self.above_target_ticks = 0;
        self.last_pushed = None;
        self.stats.resets += 1;
    }

    pub fn stats(&self) -> &JitterBufferStats {
        &self.stats
    }

    /// Samples buffered.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// The packet time to call [`JitterBuffer::tick`] at: the sender's,
    /// measured from RTP timestamps once a few samples in a row agree on
    /// it, else the one set with [`JitterBuffer::set_ptime`] (20 ms by
    /// default).
    pub fn ptime(&self) -> Duration {
        self.ptime
    }

    /// The packet time to assume until the sender's is measured, e.g. the
    /// negotiated one.
    pub fn set_ptime(&mut self, ptime: Duration) {
        self.ptime = ptime;
        self.other_ptime = (ptime, 0);
    }

    /// Follow the sender's packet time, measured between consecutive
    /// samples, so `tick` neither drains nor fills the buffer.
    fn measure_ptime(&mut self, seq: u16, timestamp: u32, clock_rate: u32) {
        if let Some((last_seq, last_ts)) = self.last_pushed
            && seq == last_seq.wrapping_add(1)
            && clock_rate > 0
        {
            let ticks = timestamp.wrapping_sub(last_ts) as u64;
            let measured = Duration::from_micros(ticks * 1_000_000 / clock_rate as u64);
            if measured == self.ptime || !(MIN_PTIME..=MAX_PTIME).contains(&measured) {
                self.other_ptime = (self.ptime, 0);
            } else if measured == self.other_ptime.0 {
                self.other_ptime.1 += 1;
            } else {
                self.other_ptime = (measured, 1);
            }
            if self.other_ptime.1 >= PTIME_CONFIRM {
                tracing::debug!(?measured, "JitterBuffer: packet time changed");
                self.ptime = measured;
                self.other_ptime = (measured, 0);
            }
        }
        self.last_pushed = Some((seq, timestamp));
    }

    /// Samples `duration` of audio is, at the packet time.
    fn frames(&self, duration: Duration) -> usize {
        let ptime = self.ptime.as_micros().max(1);
        duration.as_micros().div_ceil(ptime) as usize
    }

    /// Samples `tick` buffers before starting to play.
    fn target_frames(&self) -> usize {
        self.frames(self.min_delay).max(1)
    }

    /// Samples `tick` buffers at most.
    fn max_frames(&self) -> usize {
        (self.max_delay.as_micros() / self.ptime.as_micros().max(1)) as usize
    }

    /// Drop the oldest buffered sample (in sequence order, across
    /// wraparound), its slot given up.
    fn drop_oldest(&mut self) {
        if let Some(oldest) = self.get_first_seq() {
            self.samples.remove(&oldest);
            self.stats.dropped += 1;
            if self.playing {
                self.last_delivered_seq = Some(oldest);
            }
        }
    }

    /// Take the sample due on a playout clock: call once per
    /// [`JitterBuffer::ptime`]. See the module docs.
    pub fn tick(&mut self) -> Playout {
        if !self.playing {
            if self.samples.len() < self.target_frames() {
                return Playout::Idle;
            }
            // play from the oldest buffered, as if the one before it was
            // delivered: older ones arriving now are late
            let first = self.get_first_seq().expect("buffer not empty");
            self.last_delivered_seq = Some(first.wrapping_sub(1));
            self.playing = true;
            self.concealed_run = 0;
            self.above_target_ticks = 0;
        }

        let max_frames = self.max_frames().max(self.target_frames() + 1);
        while self.samples.len() > max_frames {
            self.drop_oldest();
        }

        // delay grown by underruns (or a sender clock running fast): once
        // well above target for long, drop a sample to win it back
        if self.samples.len() > self.target_frames() + 1 {
            self.above_target_ticks += 1;
        } else {
            self.above_target_ticks = 0;
        }
        let trim_ticks = self.frames(self.playout_config.trim_after).max(1) as u32;
        let mut next = self.last_delivered_seq.expect("playing").wrapping_add(1);
        if self.above_target_ticks >= trim_ticks && self.samples.remove(&next).is_some() {
            self.stats.dropped += 1;
            self.above_target_ticks = 0;
            self.last_delivered_seq = Some(next);
            next = next.wrapping_add(1);
        }

        if let Some(buffered) = self.samples.remove(&next) {
            self.last_delivered_seq = Some(next);
            let comfort_noise = match &buffered.sample {
                MediaSample::Audio(f) => {
                    self.last_delivered_timestamp = Some(f.rtp_timestamp);
                    f.payload_type == Some(COMFORT_NOISE_PT)
                }
                MediaSample::Video(f) => {
                    self.last_delivered_timestamp = Some(f.rtp_timestamp);
                    false
                }
            };
            self.concealed_run = 0;
            self.stats.played += 1;
            if comfort_noise {
                self.pause();
            }
            return Playout::Sample(buffered.sample);
        }
        let max_conceal = self.frames(self.playout_config.max_conceal) as u32;
        if !self.samples.is_empty() {
            // later samples are here, so this one is lost
            self.last_delivered_seq = Some(next);
            self.concealed_run += 1;
            self.stats.lost += 1;
            return Playout::Lost;
        }
        if self.concealed_run < max_conceal {
            // nothing buffered: it may only be late, so keep its slot
            self.concealed_run += 1;
            self.stats.underruns += 1;
            return Playout::Lost;
        }
        // the stream paused (hold, a sender gone quiet without saying so):
        // rebuffer
        self.playing = false;
        self.concealed_run = 0;
        Playout::Idle
    }

    /// After [`Playout::Lost`], the sample right after the lost one, when
    /// it's already buffered: what in-band FEC (Opus) rebuilds the lost one
    /// from. `None` on an underrun, with nothing buffered.
    pub fn following(&self) -> Option<&MediaSample> {
        let next = self.last_delivered_seq?.wrapping_add(1);
        self.samples.get(&next).map(|b| &b.sample)
    }

    /// The sample `tick` just played said the sender went quiet (a codec's
    /// DTX or SID frame): what's missing after it is silence, not loss.
    /// Playout stops without reporting losses and restarts, rebuffered,
    /// when the sender resumes; samples already buffered play on as usual.
    /// Comfort noise (RFC 3389, payload type 13) does this by itself.
    pub fn pause(&mut self) {
        if self.playing && self.samples.is_empty() {
            self.playing = false;
            self.concealed_run = 0;
            self.stats.pauses += 1;
        }
    }

    pub fn last_ssrc(&self) -> Option<u32> {
        self.last_ssrc
    }

    pub fn push(&mut self, sample: MediaSample) {
        let (seq_opt, timestamp, ssrc, marker, clock_rate) = match &sample {
            MediaSample::Audio(f) => (
                f.sequence_number,
                f.rtp_timestamp,
                sample_ssrc(&sample),
                f.marker,
                if f.clock_rate == 0 {
                    8000
                } else {
                    f.clock_rate
                },
            ),
            MediaSample::Video(f) => (
                f.sequence_number,
                f.rtp_timestamp,
                sample_ssrc(&sample),
                f.is_last_packet,
                90000,
            ),
        };

        let Some(seq) = seq_opt else {
            return;
        };
        self.stats.received += 1;
        if let MediaSample::Audio(f) = &sample {
            self.measure_ptime(seq, timestamp, f.clock_rate);
        }

        let now = Instant::now();

        // SSRC change (re-INVITE, IVR handoff, rewrite bridge) → hard reset.
        if let Some(ssrc) = ssrc {
            if let Some(prev) = self.last_ssrc {
                if prev != ssrc {
                    tracing::debug!(
                        old = prev,
                        new = ssrc,
                        "JitterBuffer: SSRC change, resetting"
                    );
                    self.reset();
                    self.last_ssrc = Some(ssrc);
                    self.samples.insert(
                        seq,
                        BufferedSample {
                            sample,
                            arrival: now,
                        },
                    );
                    return;
                }
            } else {
                self.last_ssrc = Some(ssrc);
            }
        }

        // Already delivered this or an older seq → drop (duplicate / late).
        if let Some(last) = self.last_delivered_seq
            && !is_newer(seq, last)
        {
            self.stats.late += 1;
            return;
        }

        // Large forward seq jump after we have been delivering → stream restart
        // (re-INVITE remapped sequence space) rather than ordinary reordering.
        if let Some(last) = self.last_delivered_seq {
            let gap = seq.wrapping_sub(last);
            if gap > MAX_SEQ_GAP && gap < 32768 {
                tracing::debug!(
                    last,
                    seq,
                    gap,
                    "JitterBuffer: large sequence gap, resetting"
                );
                self.reset();
                if let Some(ssrc) = ssrc {
                    self.last_ssrc = Some(ssrc);
                }
                self.samples.insert(
                    seq,
                    BufferedSample {
                        sample,
                        arrival: now,
                    },
                );
                return;
            }
        }

        // Timestamp discontinuity (clock remap on re-INVITE / hold-resume).
        if let Some(last_ts) = self.last_delivered_timestamp {
            let max_reasonable_jump: u32 = match &sample {
                MediaSample::Audio(_) => clock_rate.saturating_mul(AUDIO_TS_JUMP_SECS),
                MediaSample::Video(_) => 90000u32.saturating_mul(VIDEO_TS_JUMP_SECS),
            };

            let ts_diff = timestamp.wrapping_sub(last_ts);

            if ts_diff > max_reasonable_jump && ts_diff < (u32::MAX / 2) {
                tracing::debug!(
                    ts_diff,
                    marker,
                    "JitterBuffer: forward timestamp jump (re-INVITE/stream switch), resetting"
                );
                self.reset();
                if let Some(ssrc) = ssrc {
                    self.last_ssrc = Some(ssrc);
                }
                self.samples.insert(
                    seq,
                    BufferedSample {
                        sample,
                        arrival: now,
                    },
                );
                return;
            } else if ts_diff > (u32::MAX / 2) {
                let backward_diff = last_ts.wrapping_sub(timestamp);
                if backward_diff > max_reasonable_jump {
                    tracing::debug!(
                        backward_diff,
                        "JitterBuffer: backward timestamp jump, resetting"
                    );
                    self.reset();
                    if let Some(ssrc) = ssrc {
                        self.last_ssrc = Some(ssrc);
                    }
                    self.samples.insert(
                        seq,
                        BufferedSample {
                            sample,
                            arrival: now,
                        },
                    );
                    return;
                }
            }

            // Marker after a substantial gap (≥ 0.5 s) → new talkspurt after
            // silence/DTX; reset so stale buffered seqs do not block playout.
            let half_sec = clock_rate / 2;
            if marker && ts_diff > half_sec && ts_diff < (u32::MAX / 2) && !self.samples.is_empty()
            {
                tracing::debug!(
                    ts_diff,
                    "JitterBuffer: marker after silence gap, clearing stale buffer"
                );
                self.samples.clear();
            }
        }

        if self.samples.contains_key(&seq) {
            self.stats.duplicates += 1;
            return;
        }
        if self.samples.len() >= self.capacity {
            self.drop_oldest();
        }

        self.samples.insert(
            seq,
            BufferedSample {
                sample,
                arrival: now,
            },
        );
    }

    pub fn pop(&mut self) -> Option<MediaSample> {
        let first_seq = self.get_first_seq()?;
        let buffered = self.samples.get(&first_seq).unwrap();
        let now = Instant::now();
        let age = now.duration_since(buffered.arrival);

        let is_next = if let Some(last) = self.last_delivered_seq {
            first_seq == last.wrapping_add(1)
        } else {
            true
        };

        let should_deliver = if is_next {
            age >= self.min_delay
        } else {
            age >= self.max_delay
        };

        if should_deliver {
            let buffered = self.samples.remove(&first_seq).unwrap();
            self.last_delivered_seq = Some(first_seq);
            self.stats.played += 1;

            let timestamp = match &buffered.sample {
                MediaSample::Audio(f) => f.rtp_timestamp,
                MediaSample::Video(f) => f.rtp_timestamp,
            };
            self.last_delivered_timestamp = Some(timestamp);

            Some(buffered.sample)
        } else {
            None
        }
    }

    /// Returns the duration to wait until the next packet might be ready to pop.
    pub fn next_pop_wait(&self) -> Option<Duration> {
        let first_seq = self.get_first_seq()?;
        let buffered = self.samples.get(&first_seq).unwrap();
        let now = Instant::now();
        let age = now.duration_since(buffered.arrival);

        let is_next = if let Some(last) = self.last_delivered_seq {
            first_seq == last.wrapping_add(1)
        } else {
            true
        };

        let target_delay = if is_next {
            self.min_delay
        } else {
            self.max_delay
        };

        if age >= target_delay {
            Some(Duration::from_millis(0))
        } else {
            Some(target_delay - age)
        }
    }

    /// True when we have delivered media before and the buffer is currently empty
    /// (caller may inject CNG / PLC until the next packet arrives).
    pub fn awaiting_next(&self) -> bool {
        self.last_delivered_seq.is_some() && self.samples.is_empty()
    }

    fn get_first_seq(&self) -> Option<u16> {
        if self.samples.is_empty() {
            return None;
        }
        let last = match self.last_delivered_seq {
            Some(l) => l,
            None => {
                let k0 = *self.samples.keys().next()?;
                let kn = *self.samples.keys().next_back()?;
                if !is_newer(k0, kn) {
                    return Some(k0);
                }
                // across wraparound (e.g. 65534, 65535, 0, 1): the oldest is
                // the lowest of the numbers just below the wrap, all more
                // than half the sequence space above `k0`
                return self.samples.range(k0 + 32768..).next().map(|(&s, _)| s);
            }
        };

        let next_expected = last.wrapping_add(1);

        if next_expected > last {
            self.samples
                .range(next_expected..)
                .next()
                .map(|(&s, _)| s)
                .or_else(|| self.samples.keys().next().copied())
        } else {
            self.samples.range(0..).next().map(|(&s, _)| s)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }
}

fn sample_ssrc(sample: &MediaSample) -> Option<u32> {
    match sample {
        MediaSample::Audio(f) => f.raw_packet.as_ref().map(|p| p.header.ssrc),
        MediaSample::Video(f) => f.raw_packet.as_ref().map(|p| p.header.ssrc),
    }
}

fn is_newer(seq: u16, last: u16) -> bool {
    if seq == last {
        return false;
    }
    let diff = seq.wrapping_sub(last);
    diff < 32768
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use crate::media::frame::{AudioFrame, VideoFrame};
    use crate::rtp::{RtpHeader, RtpPacket};
    use bytes::Bytes;
    use core::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn make_sample(seq: u16) -> MediaSample {
        MediaSample::Audio(AudioFrame {
            sequence_number: Some(seq),
            rtp_timestamp: seq as u32 * 160,
            payload_type: Some(0),
            clock_rate: 8000,
            data: Bytes::from(vec![0u8; 160]),
            ..Default::default()
        })
    }

    fn make_sample_with_ssrc(seq: u16, ssrc: u32, ts: u32) -> MediaSample {
        let header = RtpHeader::new(0, seq, ts, ssrc);
        let packet = RtpPacket {
            header,
            payload: Bytes::from(vec![0u8; 160]),
            padding_len: 0,
        };
        MediaSample::Audio(AudioFrame {
            sequence_number: Some(seq),
            rtp_timestamp: ts,
            payload_type: Some(0),
            clock_rate: 8000,
            data: Bytes::from(vec![0u8; 160]),
            raw_packet: Some(packet),
            source_addr: Some(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5004)),
            ..Default::default()
        })
    }

    fn make_video_sample(seq: u16) -> MediaSample {
        MediaSample::Video(VideoFrame {
            sequence_number: Some(seq),
            rtp_timestamp: seq as u32 * 3000,
            ..Default::default()
        })
    }

    fn get_seq(sample: MediaSample) -> u16 {
        match sample {
            MediaSample::Audio(f) => f.sequence_number.unwrap(),
            MediaSample::Video(f) => f.sequence_number.unwrap(),
        }
    }

    #[test]
    fn test_jitter_buffer_ordering() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(2));
        jb.push(make_sample(1));
        jb.push(make_sample(3));

        assert_eq!(get_seq(jb.pop().unwrap()), 1);
        assert_eq!(get_seq(jb.pop().unwrap()), 2);
        assert_eq!(get_seq(jb.pop().unwrap()), 3);
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_min_delay() {
        let mut jb = JitterBuffer::new(Duration::from_millis(50), Duration::from_millis(100), 10);
        jb.push(make_sample(1));
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_reset() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        jb.push(make_sample(2));
        assert!(!jb.is_empty());

        jb.reset();
        assert!(jb.is_empty());
        assert!(jb.last_delivered_seq.is_none());
        assert!(jb.last_delivered_timestamp.is_none());
        assert!(jb.last_ssrc.is_none());
    }

    #[test]
    fn test_jitter_buffer_ssrc_change() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample_with_ssrc(1, 100, 160));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);
        assert_eq!(jb.last_ssrc(), Some(100));

        // Same seq space but new SSRC (re-INVITE / rewrite) — must reset.
        jb.push(make_sample_with_ssrc(2, 200, 320));
        assert_eq!(jb.samples.len(), 1);
        assert_eq!(jb.last_ssrc(), Some(200));
        assert_eq!(get_seq(jb.pop().unwrap()), 2);
    }

    #[test]
    fn test_jitter_buffer_seq_gap_reset() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        // Jump by > MAX_SEQ_GAP — re-INVITE remapped sequences.
        jb.push(make_sample(100));
        assert_eq!(jb.samples.len(), 1);
        assert_eq!(get_seq(jb.pop().unwrap()), 100);
    }

    #[test]
    fn test_jitter_buffer_ts_jump_reinvite() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        // 3 seconds @ 8 kHz — above AUDIO_TS_JUMP_SECS=2.
        let mut new_sample = make_sample(2);
        if let MediaSample::Audio(ref mut f) = new_sample {
            f.rtp_timestamp = 8000 * 3;
        }
        jb.push(new_sample);
        assert_eq!(jb.samples.len(), 1);
        assert_eq!(get_seq(jb.pop().unwrap()), 2);
    }

    #[test]
    fn test_jitter_buffer_ssrc_change_forward_jump() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        let mut new_sample = make_sample(2);
        if let MediaSample::Audio(ref mut f) = new_sample {
            f.rtp_timestamp = 800000;
        }

        jb.push(new_sample);
        assert_eq!(jb.samples.len(), 1);
        let popped = jb.pop().unwrap();
        assert_eq!(get_seq(popped), 2);
    }

    #[test]
    fn test_jitter_buffer_ssrc_change_backward_jump() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        let mut first_sample = make_sample(1);
        if let MediaSample::Audio(ref mut f) = first_sample {
            f.rtp_timestamp = 800000;
        }
        jb.push(first_sample);
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        let new_sample = make_sample(2);
        jb.push(new_sample);

        assert_eq!(jb.samples.len(), 1);
        let popped = jb.pop().unwrap();
        assert_eq!(get_seq(popped), 2);
    }

    #[test]
    fn test_awaiting_next() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);
        assert!(!jb.awaiting_next());
        jb.push(make_sample(1));
        assert!(!jb.awaiting_next());
        let _ = jb.pop();
        assert!(jb.awaiting_next());
    }

    /// A buffer for clocked playout of 20 ms frames: plays from 40 ms
    /// buffered, holds at most 200 ms.
    fn playout() -> JitterBuffer {
        JitterBuffer::new(Duration::from_millis(40), Duration::from_millis(200), 50)
    }

    /// `Some(seq)` for a sample, `None` for a loss, `Some(u16::MAX)` never:
    /// idle ticks are left out by `ticks`.
    #[derive(Debug, PartialEq)]
    enum Out {
        S(u16),
        Lost,
        Idle,
    }

    fn tick(jb: &mut JitterBuffer) -> Out {
        match jb.tick() {
            Playout::Sample(s) => Out::S(get_seq(s)),
            Playout::Lost => Out::Lost,
            Playout::Idle => Out::Idle,
        }
    }

    fn ticks(jb: &mut JitterBuffer, n: usize) -> Vec<Out> {
        (0..n).map(|_| tick(jb)).collect()
    }

    use Out::{Idle, Lost, S};

    #[test]
    fn tick_waits_for_min_delay_then_plays_in_order() {
        let mut jb = playout();
        jb.push(make_sample(10));
        assert_eq!(tick(&mut jb), Idle);
        jb.push(make_sample(11));
        assert_eq!(tick(&mut jb), S(10));
        jb.push(make_sample(12));
        assert_eq!(ticks(&mut jb, 2), [S(11), S(12)]);
    }

    #[test]
    fn tick_reorders() {
        let mut jb = playout();
        for seq in [2, 1, 3] {
            jb.push(make_sample(seq));
        }
        assert_eq!(ticks(&mut jb, 3), [S(1), S(2), S(3)]);
    }

    #[test]
    fn tick_plays_video_samples_in_order() {
        let mut jb = playout();
        for seq in [2, 1, 3] {
            jb.push(make_video_sample(seq));
        }
        assert_eq!(ticks(&mut jb, 3), [S(1), S(2), S(3)]);
        assert_eq!(jb.stats().played, 3);
    }

    #[test]
    fn tick_reports_a_gap_with_later_samples_as_lost() {
        let mut jb = playout();
        for seq in [1, 2, 4, 6] {
            jb.push(make_sample(seq));
        }
        assert_eq!(ticks(&mut jb, 3), [S(1), S(2), Lost]);
        assert_eq!(jb.following().map(|s| get_seq(s.clone())), Some(4));
        assert_eq!(ticks(&mut jb, 3), [S(4), Lost, S(6)]);
        assert_eq!(jb.stats().lost, 2);
        // an underrun: nothing after it yet
        assert_eq!(tick(&mut jb), Lost);
        assert!(jb.following().is_none());
    }

    #[test]
    fn tick_drops_a_sample_late_for_its_slot() {
        let mut jb = playout();
        for seq in [1, 2, 4] {
            jb.push(make_sample(seq));
        }
        assert_eq!(ticks(&mut jb, 3), [S(1), S(2), Lost]);
        jb.push(make_sample(3));
        assert_eq!(jb.stats().late, 1);
        assert_eq!(tick(&mut jb), S(4));
    }

    #[test]
    fn tick_keeps_the_slot_of_a_sample_missing_on_an_underrun() {
        let mut jb = playout();
        jb.push(make_sample(1));
        jb.push(make_sample(2));
        assert_eq!(ticks(&mut jb, 2), [S(1), S(2)]);
        // 3 is late, not lost
        assert_eq!(tick(&mut jb), Lost);
        jb.push(make_sample(3));
        assert_eq!(tick(&mut jb), S(3));
        assert_eq!((jb.stats().underruns, jb.stats().late), (1, 0));
    }

    #[test]
    fn tick_rebuffers_after_max_conceal() {
        let mut jb = playout();
        jb.push(make_sample(1));
        jb.push(make_sample(2));
        ticks(&mut jb, 2);
        // 100 ms of underruns, then the buffer gives up
        assert_eq!(
            ticks(&mut jb, 7),
            [Lost, Lost, Lost, Lost, Lost, Idle, Idle]
        );
        // the sender comes back: buffered to min_delay before playing again
        jb.push(make_sample(3));
        assert_eq!(tick(&mut jb), Idle);
        jb.push(make_sample(4));
        assert_eq!(ticks(&mut jb, 2), [S(3), S(4)]);
    }

    #[test]
    fn pause_stops_playout_without_reporting_losses() {
        let mut jb = playout();
        jb.push(make_sample(1));
        jb.push(make_sample(2));
        assert_eq!(ticks(&mut jb, 2), [S(1), S(2)]);
        // 2 said the sender went quiet
        jb.pause();
        assert_eq!(ticks(&mut jb, 3), [Idle, Idle, Idle]);
        assert_eq!((jb.stats().underruns, jb.stats().pauses), (0, 1));
        // a sample from before the pause, arriving now, is still late
        jb.push(make_sample(0));
        assert_eq!(jb.stats().late, 1);
        // the sender resumes: rebuffered, then played in order
        jb.push(make_sample(3));
        assert_eq!(tick(&mut jb), Idle);
        jb.push(make_sample(4));
        assert_eq!(ticks(&mut jb, 2), [S(3), S(4)]);
    }

    #[test]
    fn pause_with_samples_still_buffered_plays_them() {
        let mut jb = playout();
        for seq in [1, 2, 4] {
            jb.push(make_sample(seq));
        }
        assert_eq!(tick(&mut jb), S(1));
        jb.pause();
        assert_eq!(ticks(&mut jb, 3), [S(2), Lost, S(4)]);
        assert_eq!(jb.stats().pauses, 0);
    }

    #[test]
    fn comfort_noise_pauses_playout() {
        let mut jb = playout();
        jb.push(make_sample(1));
        jb.push(make_sample(2));
        let mut cn = make_sample(3);
        if let MediaSample::Audio(ref mut f) = cn {
            f.payload_type = Some(COMFORT_NOISE_PT);
            f.data = Bytes::from_static(&[70]);
        }
        jb.push(cn);
        assert_eq!(ticks(&mut jb, 6), [S(1), S(2), S(3), Idle, Idle, Idle]);
        assert_eq!((jb.stats().underruns, jb.stats().pauses), (0, 1));
    }

    #[test]
    fn tick_keeps_order_across_sequence_wraparound() {
        let mut jb = playout();
        for seq in [65534, 65535, 1, 0] {
            jb.push(make_sample(seq));
        }
        assert_eq!(ticks(&mut jb, 4), [S(65534), S(65535), S(0), S(1)]);
    }

    #[test]
    fn tick_drops_the_oldest_beyond_max_delay() {
        let mut jb = playout();
        for seq in 0..12 {
            jb.push(make_sample(seq));
        }
        // 200 ms at 20 ms: 10 samples
        assert_eq!(tick(&mut jb), S(2));
        assert_eq!(jb.stats().dropped, 2);
    }

    #[test]
    fn capacity_drops_the_oldest_across_wraparound() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 3);
        for seq in [65534, 65535, 0, 1] {
            jb.push(make_sample(seq));
        }
        // 65534 is the oldest, not 0
        assert_eq!(get_seq(jb.pop().unwrap()), 65535);
        assert_eq!(jb.stats().dropped, 1);
    }

    #[test]
    fn duplicate_sample_is_dropped_without_replacing_the_buffered_copy() {
        let mut jb = playout();
        let mut first = make_sample(1);
        if let MediaSample::Audio(ref mut f) = first {
            f.data = Bytes::from_static(&[1]);
        }
        let mut duplicate = make_sample(1);
        if let MediaSample::Audio(ref mut f) = duplicate {
            f.data = Bytes::from_static(&[2]);
        }
        jb.push(first);
        jb.push(duplicate);
        jb.push(make_sample(2));

        assert_eq!(jb.stats().duplicates, 1);
        match jb.tick() {
            Playout::Sample(MediaSample::Audio(f)) => assert_eq!(f.data.as_ref(), &[1]),
            _ => panic!("expected the first copy of the sample"),
        }
    }

    #[test]
    fn stats_survive_a_stream_reset() {
        let mut jb = playout();
        jb.push(make_sample_with_ssrc(1, 1, 160));
        jb.push(make_sample_with_ssrc(2, 1, 320));
        assert_eq!(jb.stats().received, 2);
        assert_eq!(ticks(&mut jb, 2), [S(1), S(2)]);
        assert_eq!(jb.stats().played, 2);

        jb.push(make_sample_with_ssrc(3, 2, 100));
        assert_eq!(jb.stats().resets, 1);
        assert_eq!(jb.stats().received, 3);
        assert_eq!(
            jb.stats().played,
            2,
            "a reset clears the stream, not the counters"
        );
        assert_eq!(jb.len(), 1);
        assert_eq!(tick(&mut jb), Idle, "the new stream must rebuffer first");
    }

    #[test]
    fn tick_on_an_empty_buffer_is_idle() {
        let mut jb = playout();
        assert_eq!(ticks(&mut jb, 3), [Idle, Idle, Idle]);
        assert_eq!(jb.stats().played, 0);
        assert_eq!((jb.stats().lost, jb.stats().underruns), (0, 0));
    }

    #[test]
    fn tick_trims_delay_grown_by_underruns() {
        let mut jb = playout();
        jb.set_playout_config(PlayoutConfig {
            trim_after: Duration::from_millis(60),
            ..Default::default()
        });
        let mut seq = 0u16;
        let mut push = |jb: &mut JitterBuffer, n: usize| {
            for _ in 0..n {
                jb.push(make_sample(seq));
                seq += 1;
            }
        };
        // a burst leaves 5 samples buffered on a steady one-in-one-out stream
        push(&mut jb, 6);
        let mut played = vec![];
        for _ in 0..3 {
            if let S(s) = tick(&mut jb) {
                played.push(s);
            }
            push(&mut jb, 1);
        }
        assert_eq!(jb.stats().dropped, 1);
        assert!(jb.len() < 6, "delay not trimmed: {} buffered", jb.len());
        assert!(played.windows(2).all(|w| w[0] < w[1]));
    }

    #[test]
    fn ptime_follows_the_sender() {
        let mut jb = playout();
        assert_eq!(jb.ptime(), Duration::from_millis(20));
        let sample = |seq: u16| {
            let mut s = make_sample(seq);
            if let MediaSample::Audio(ref mut f) = s {
                // 40 ms at 8 kHz
                f.rtp_timestamp = seq as u32 * 320;
            }
            s
        };
        for seq in 0..5 {
            jb.push(sample(seq));
        }
        assert_eq!(jb.ptime(), Duration::from_millis(20), "followed too soon");
        jb.push(sample(5));
        assert_eq!(jb.ptime(), Duration::from_millis(40));
        // 40 ms of min_delay is now one sample
        let mut jb = playout();
        for seq in 0..6 {
            jb.push(sample(seq));
        }
        jb.reset();
        jb.set_ptime(Duration::from_millis(40));
        jb.push(sample(10));
        assert_eq!(tick(&mut jb), S(10));
    }

    #[test]
    fn tick_restarts_on_a_new_stream() {
        let mut jb = playout();
        jb.push(make_sample_with_ssrc(100, 1, 16000));
        jb.push(make_sample_with_ssrc(101, 1, 16160));
        assert_eq!(tick(&mut jb), S(100));
        // the new stream's numbers land just behind the old ones
        jb.push(make_sample_with_ssrc(90, 2, 500));
        jb.push(make_sample_with_ssrc(91, 2, 660));
        assert_eq!(jb.stats().resets, 1);
        assert_eq!(jb.stats().late, 0);
        assert_eq!(ticks(&mut jb, 2), [S(90), S(91)]);
    }
}
