#![cfg(feature = "std")]

//! `SampleStreamSource` is `Clone + Send + Sync`, so several threads may send
//! into one track through their own clones. Every sample a send accepted
//! must come out of the track exactly once.
use bytes::Bytes;
use rustrtc::media::MediaError;
use rustrtc::media::MediaStreamTrack;
use rustrtc::media::frame::{AudioFrame, MediaKind, MediaSample};
use rustrtc::media::track::sample_track;
use std::collections::HashSet;
use std::sync::{Arc, Barrier, Mutex};
use std::time::Duration;

const PRODUCERS: u32 = 4;
const SAMPLES_PER_PRODUCER: u32 = 20_000;
const ROUNDS: usize = 10;

fn tagged(producer: u32, seq: u32) -> MediaSample {
    let mut tag = producer.to_be_bytes().to_vec();
    tag.extend_from_slice(&seq.to_be_bytes());
    MediaSample::Audio(AudioFrame {
        data: Bytes::from(tag),
        ..AudioFrame::default()
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_sends_from_clones_lose_no_samples() {
    for round in 0..ROUNDS {
        // Large enough that no send ever finds the queue full.
        let capacity = (PRODUCERS * SAMPLES_PER_PRODUCER) as usize * 2;
        let (source, track, _feedback) = sample_track(MediaKind::Audio, capacity);

        let start = Arc::new(Barrier::new(PRODUCERS as usize));
        let producers: Vec<_> = (0..PRODUCERS)
            .map(|producer| {
                let source = source.clone();
                let start = start.clone();
                std::thread::spawn(move || {
                    start.wait();
                    for seq in 0..SAMPLES_PER_PRODUCER {
                        source.send(tagged(producer, seq)).expect("send");
                    }
                })
            })
            .collect();
        for producer in producers {
            producer.join().expect("producer thread");
        }

        let mut seen = HashSet::new();
        while let Ok(Ok(MediaSample::Audio(frame))) =
            tokio::time::timeout(Duration::from_millis(50), track.recv()).await
        {
            assert!(
                seen.insert(frame.data.clone()),
                "round {round}: sample delivered twice"
            );
        }
        assert_eq!(
            seen.len(),
            (PRODUCERS * SAMPLES_PER_PRODUCER) as usize,
            "round {round}: every accepted sample must be delivered"
        );
    }
}

/// Under multi-producer contention `try_send` may decline a push with
/// `WouldBlock` (lock held by a sibling producer, or queue full), but every
/// push it *accepted* must still be delivered exactly once, and it must never
/// fail with anything other than `WouldBlock`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn concurrent_try_sends_either_accept_or_decline_and_never_corrupt() {
    let (source, track, _feedback) = sample_track(MediaKind::Audio, 4096);

    const PRODUCERS: u32 = 4;
    const ATTEMPTS: u32 = 20_000;

    let accepted: Arc<Mutex<HashSet<(u32, u32)>>> = Arc::new(Mutex::new(HashSet::new()));
    let start = Arc::new(Barrier::new(PRODUCERS as usize));

    let producers: Vec<_> = (0..PRODUCERS)
        .map(|producer| {
            let source = source.clone();
            let start = start.clone();
            let accepted = accepted.clone();
            std::thread::spawn(move || {
                start.wait();
                for seq in 0..ATTEMPTS {
                    match source.try_send(tagged(producer, seq)) {
                        Ok(()) => {
                            accepted.lock().unwrap().insert((producer, seq));
                        }
                        Err(err) => assert!(
                            matches!(err, MediaError::WouldBlock),
                            "try_send failed with {err:?}"
                        ),
                    }
                }
            })
        })
        .collect();
    for producer in producers {
        producer.join().expect("producer thread");
    }

    let expected = accepted.lock().unwrap().clone();
    let mut seen = HashSet::new();
    while let Ok(Ok(MediaSample::Audio(frame))) =
        tokio::time::timeout(Duration::from_millis(50), track.recv()).await
    {
        let tag = frame.data.as_ref();
        let identity = (
            u32::from_be_bytes(tag[0..4].try_into().unwrap()),
            u32::from_be_bytes(tag[4..8].try_into().unwrap()),
        );
        assert!(
            expected.contains(&identity),
            "delivered a sample that no producer had accepted: {identity:?}"
        );
        assert!(
            seen.insert(identity),
            "sample {:?} delivered twice",
            identity
        );
    }
    assert_eq!(
        seen, expected,
        "the delivered set must equal the accepted set"
    );
}
