use crate::media::frame::MediaSample;
use std::collections::BTreeMap;
use std::time::{Duration, Instant};

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
        }
    }

    /// Reset the jitter buffer state, clearing all samples and statistics.
    /// Call when a stream discontinuity is detected (SSRC change, re-INVITE).
    pub fn reset(&mut self) {
        self.samples.clear();
        self.last_delivered_seq = None;
        self.last_delivered_timestamp = None;
        self.last_ssrc = None;
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
                if f.clock_rate == 0 { 8000 } else { f.clock_rate },
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

        if self.samples.len() >= self.capacity {
            self.samples.pop_first();
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
                return if is_newer(k0, kn) { Some(kn) } else { Some(k0) };
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::media::frame::AudioFrame;
    use crate::rtp::{RtpHeader, RtpPacket};
    use bytes::Bytes;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

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
}
