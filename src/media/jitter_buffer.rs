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
    max_delay: Duration,
    min_delay: Duration,
    capacity: usize,
}

impl JitterBuffer {
    pub fn new(min_delay: Duration, max_delay: Duration, capacity: usize) -> Self {
        Self {
            samples: BTreeMap::new(),
            last_delivered_seq: None,
            last_delivered_timestamp: None,
            max_delay,
            min_delay,
            capacity,
        }
    }

    /// Reset the jitter buffer state, clearing all samples and statistics.
    /// This should be called when a stream discontinuity is detected (e.g., SSRC change).
    pub fn reset(&mut self) {
        self.samples.clear();
        self.last_delivered_seq = None;
        self.last_delivered_timestamp = None;
    }

    pub fn push(&mut self, sample: MediaSample) {
        let (seq_opt, timestamp) = match &sample {
            MediaSample::Audio(f) => (f.sequence_number, f.rtp_timestamp),
            MediaSample::Video(f) => (f.sequence_number, f.rtp_timestamp),
        };

        let Some(seq) = seq_opt else {
            return;
        };

        // If we already delivered this or a newer sequence (with wrap-around check), ignore it
        if let Some(last) = self.last_delivered_seq
            && !is_newer(seq, last)
        {
            return;
        }

        // Validate timestamp continuity to reject interleaved streams with different timestamp bases
        if let Some(last_ts) = self.last_delivered_timestamp {
            // Calculate expected timestamp increment based on sample rate
            // For audio at 8kHz with 20ms packets: 160 samples
            // For video at 90kHz with 33ms packets: ~3000 samples
            // We allow up to 10 seconds of jump to handle legitimate gaps
            let max_reasonable_jump: u32 = match &sample {
                MediaSample::Audio(f) => f.clock_rate * 10, // 10 seconds
                MediaSample::Video(_) => 90000 * 10,        // 10 seconds at 90kHz
            };

            let ts_diff = timestamp.wrapping_sub(last_ts);

            // Detect stream discontinuity and reset buffer instead of rejecting
            // Using wrapping math: if ts_diff > half of u32::MAX, it's a backward jump
            if ts_diff > max_reasonable_jump && ts_diff < (u32::MAX / 2) {
                // Massive forward jump - likely SSRC change or stream switch
                tracing::info!(
                    "JitterBuffer: Detected stream switch (timestamp jump {}s), resetting buffer",
                    ts_diff / 8000
                );
                self.reset();
                // Accept this packet as the start of new stream
                self.samples.insert(
                    seq,
                    BufferedSample {
                        sample,
                        arrival: Instant::now(),
                    },
                );
                return;
            } else if ts_diff > (u32::MAX / 2) {
                // Backward jump (wrapped subtraction)
                let backward_diff = last_ts.wrapping_sub(timestamp);
                if backward_diff > max_reasonable_jump {
                    tracing::info!(
                        "JitterBuffer: Detected backward stream switch (timestamp jump -{}s), resetting buffer",
                        backward_diff / 8000
                    );
                    self.reset();
                    // Accept this packet as the start of new stream
                    self.samples.insert(
                        seq,
                        BufferedSample {
                            sample,
                            arrival: Instant::now(),
                        },
                    );
                    return;
                }
            }
        }

        if self.samples.len() >= self.capacity {
            // Buffer full, drop the oldest one
            self.samples.pop_first();
        }

        self.samples.insert(
            seq,
            BufferedSample {
                sample,
                arrival: Instant::now(),
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

            // Update last delivered timestamp
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

    fn get_first_seq(&self) -> Option<u16> {
        if self.samples.is_empty() {
            return None;
        }
        let last = match self.last_delivered_seq {
            Some(l) => l,
            None => {
                // Find the oldest packet in the buffer
                let mut oldest: Option<u16> = None;
                for &seq in self.samples.keys() {
                    match oldest {
                        None => oldest = Some(seq),
                        Some(o) => {
                            if is_newer(o, seq) {
                                oldest = Some(seq);
                            }
                        }
                    }
                }
                return oldest;
            }
        };

        // Try to find the first sequence number after 'last'
        // We look in [last+1, 65535] first, then [0, last-1]
        let next_expected = last.wrapping_add(1);

        if next_expected > last {
            // Normal case, no wrap around in the range we are looking for
            self.samples
                .range(next_expected..)
                .next()
                .map(|(&s, _)| s)
                .or_else(|| self.samples.keys().next().copied())
        } else {
            // next_expected is 0, last was 65535
            self.samples.range(0..).next().map(|(&s, _)| s)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
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
    use bytes::Bytes;

    fn make_sample(seq: u16) -> MediaSample {
        MediaSample::Audio(AudioFrame {
            sequence_number: Some(seq),
            rtp_timestamp: seq as u32 * 160,
            payload_type: Some(0),
            clock_rate: 8000, // Set proper clock rate
            data: Bytes::from(vec![0u8; 160]),
            ..Default::default()
        })
    }

    #[test]
    fn test_jitter_buffer_ordering() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        // Push out of order
        jb.push(make_sample(2));
        jb.push(make_sample(1));
        jb.push(make_sample(3));

        // Should pop in order: 1, 2, 3
        assert_eq!(get_seq(jb.pop().unwrap()), 1);
        assert_eq!(get_seq(jb.pop().unwrap()), 2);
        assert_eq!(get_seq(jb.pop().unwrap()), 3);
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_min_delay() {
        let mut jb = JitterBuffer::new(Duration::from_millis(50), Duration::from_millis(100), 10);
        jb.push(make_sample(1));

        // Immediate pop should be None due to min_delay
        assert!(jb.pop().is_none());

        // We can't easily mock time in standard tests without extra crates,
        // but we can verify it doesn't pop immediately.
    }

    #[test]
    fn test_jitter_buffer_gap_waiting() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(50), 10);

        jb.push(make_sample(1));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        jb.push(make_sample(3)); // Gap: 2 is missing

        // Should not pop 3 immediately because we are waiting for 2 (need max_delay to pass)
        std::thread::sleep(Duration::from_millis(10));
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_wrap_around() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(65535));
        jb.push(make_sample(0));
        jb.push(make_sample(1));

        assert_eq!(get_seq(jb.pop().unwrap()), 65535);
        assert_eq!(get_seq(jb.pop().unwrap()), 0);
        assert_eq!(get_seq(jb.pop().unwrap()), 1);
    }

    #[test]
    fn test_jitter_buffer_duplicate() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        jb.push(make_sample(1)); // Duplicate

        assert_eq!(get_seq(jb.pop().unwrap()), 1);
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_outdated() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        jb.push(make_sample(10));
        assert_eq!(get_seq(jb.pop().unwrap()), 10);

        jb.push(make_sample(5)); // Outdated
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_capacity() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 2);

        jb.push(make_sample(1));
        jb.push(make_sample(2));
        jb.push(make_sample(3)); // Should drop 1

        assert_eq!(get_seq(jb.pop().unwrap()), 2);
        assert_eq!(get_seq(jb.pop().unwrap()), 3);
        assert!(jb.pop().is_none());
    }

    #[test]
    fn test_jitter_buffer_next_pop_wait() {
        let min_delay = Duration::from_millis(50);
        let mut jb = JitterBuffer::new(min_delay, Duration::from_millis(100), 10);

        jb.push(make_sample(1));
        let wait = jb.next_pop_wait().unwrap();
        assert!(wait > Duration::from_millis(0));
        assert!(wait <= min_delay);
    }

    fn get_seq(sample: MediaSample) -> u16 {
        match sample {
            MediaSample::Audio(f) => f.sequence_number.unwrap(),
            MediaSample::Video(f) => f.sequence_number.unwrap(),
        }
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
    }

    #[test]
    fn test_jitter_buffer_ssrc_change_forward_jump() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        // First stream
        jb.push(make_sample(1));
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        // SSRC change causes massive timestamp jump (simulate 100 seconds)
        let mut new_sample = make_sample(2);
        if let MediaSample::Audio(ref mut f) = new_sample {
            f.rtp_timestamp = 800000; // 100 seconds at 8kHz
        }

        jb.push(new_sample);

        // Buffer should reset and accept new stream
        assert_eq!(jb.samples.len(), 1);
        let popped = jb.pop().unwrap();
        assert_eq!(get_seq(popped), 2);
    }

    #[test]
    fn test_jitter_buffer_ssrc_change_backward_jump() {
        let mut jb = JitterBuffer::new(Duration::from_millis(0), Duration::from_millis(100), 10);

        // First stream with high timestamp
        let mut first_sample = make_sample(1);
        if let MediaSample::Audio(ref mut f) = first_sample {
            f.rtp_timestamp = 800000; // High timestamp
        }
        jb.push(first_sample);
        assert_eq!(get_seq(jb.pop().unwrap()), 1);

        // SSRC change causes backward timestamp jump (new stream starts from 0)
        let new_sample = make_sample(2); // timestamp = 320 (2 * 160)

        jb.push(new_sample);

        // Buffer should reset and accept new stream
        assert_eq!(jb.samples.len(), 1);
        let popped = jb.pop().unwrap();
        assert_eq!(get_seq(popped), 2);
    }
}
