use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

use async_trait::async_trait;
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::warn;

use crate::{
    media::error::{MediaError, MediaResult},
    media::frame::{AudioFrame, MediaKind, MediaSample, VideoFrame},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrackState {
    Live,
    Ended,
}

#[async_trait]
pub trait MediaStreamTrack: Send + Sync {
    fn id(&self) -> &str;
    fn kind(&self) -> MediaKind;
    fn state(&self) -> TrackState;
    async fn recv(&self) -> MediaResult<MediaSample>;
}

#[async_trait]
pub trait AudioStreamTrack: MediaStreamTrack {
    async fn recv_audio(&self) -> MediaResult<AudioFrame> {
        match self.recv().await? {
            MediaSample::Audio(frame) => Ok(frame),
            MediaSample::Video(_) => Err(MediaError::KindMismatch {
                expected: MediaKind::Audio,
                actual: MediaKind::Video,
            }),
        }
    }
}

#[async_trait]
pub trait VideoStreamTrack: MediaStreamTrack {
    async fn recv_video(&self) -> MediaResult<VideoFrame> {
        match self.recv().await? {
            MediaSample::Video(frame) => Ok(frame),
            MediaSample::Audio(_) => Err(MediaError::KindMismatch {
                expected: MediaKind::Video,
                actual: MediaKind::Audio,
            }),
        }
    }
}

pub struct SampleStreamTrack {
    id: Arc<str>,
    kind: MediaKind,
    receiver: Mutex<mpsc::Receiver<MediaSample>>,
    ended: AtomicBool,
}

impl SampleStreamTrack {
    pub fn id(&self) -> &str {
        &self.id
    }
}

#[derive(Clone)]
pub struct SampleStreamSource {
    id: Arc<str>,
    kind: MediaKind,
    sender: mpsc::Sender<MediaSample>,
}

static TRACK_COUNTER: AtomicU64 = AtomicU64::new(1);
static RELAY_TRACK_COUNTER: AtomicU64 = AtomicU64::new(1);

fn next_track_id() -> Arc<str> {
    let value = TRACK_COUNTER.fetch_add(1, Ordering::Relaxed);
    Arc::<str>::from(format!("track-{value}"))
}

fn next_relay_track_id(base: &str) -> Arc<str> {
    let suffix = RELAY_TRACK_COUNTER.fetch_add(1, Ordering::Relaxed);
    Arc::<str>::from(format!("{base}-relay-{suffix}"))
}

pub fn sample_track(
    kind: MediaKind,
    capacity: usize,
) -> (SampleStreamSource, Arc<SampleStreamTrack>) {
    let (sender, receiver) = mpsc::channel(capacity);
    let id = next_track_id();
    let track = Arc::new(SampleStreamTrack {
        id: id.clone(),
        kind,
        receiver: Mutex::new(receiver),
        ended: AtomicBool::new(false),
    });
    let source = SampleStreamSource { id, kind, sender };
    (source, track)
}

impl SampleStreamSource {
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub async fn send_audio(&self, frame: AudioFrame) -> MediaResult<()> {
        self.send(MediaSample::Audio(frame)).await
    }

    pub async fn send_video(&self, frame: VideoFrame) -> MediaResult<()> {
        self.send(MediaSample::Video(frame)).await
    }

    pub async fn send(&self, sample: MediaSample) -> MediaResult<()> {
        if sample.kind() != self.kind {
            return Err(MediaError::KindMismatch {
                expected: self.kind,
                actual: sample.kind(),
            });
        }
        self.sender
            .send(sample)
            .await
            .map_err(|_| MediaError::Closed)
    }
}

const RELAY_CAPACITY_DEFAULT: usize = 32;

#[derive(Clone)]
pub struct MediaRelay {
    inner: Arc<RelayInner>,
}

#[derive(Debug, Clone)]
enum RelayEvent {
    Sample(MediaSample),
    End,
}

struct RelayInner {
    base_id: Arc<str>,
    kind: MediaKind,
    track: Arc<dyn MediaStreamTrack>,
    sender: broadcast::Sender<RelayEvent>,
    started: AtomicBool,
    ended: AtomicBool,
}

impl MediaRelay {
    pub fn new<T>(track: Arc<T>) -> Self
    where
        T: MediaStreamTrack + 'static,
    {
        Self::with_capacity(track, RELAY_CAPACITY_DEFAULT)
    }

    pub fn with_capacity<T>(track: Arc<T>, capacity: usize) -> Self
    where
        T: MediaStreamTrack + 'static,
    {
        assert!(
            capacity > 0,
            "MediaRelay capacity must be greater than zero"
        );
        let base_id = Arc::<str>::from(track.id().to_string());
        let kind = track.kind();
        let (sender, _) = broadcast::channel(capacity);
        let dyn_track: Arc<dyn MediaStreamTrack> = track;
        Self {
            inner: Arc::new(RelayInner {
                base_id,
                kind,
                track: dyn_track,
                sender,
                started: AtomicBool::new(false),
                ended: AtomicBool::new(false),
            }),
        }
    }

    pub fn subscribe(&self) -> Arc<RelayStreamTrack> {
        self.inner.ensure_started();
        Arc::new(RelayStreamTrack::new(
            next_relay_track_id(&self.inner.base_id),
            self.inner.kind,
            self.inner.sender.subscribe(),
            self.inner.ended.load(Ordering::SeqCst),
        ))
    }
}

impl RelayInner {
    fn ensure_started(self: &Arc<Self>) {
        if self
            .started
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            let this = Arc::clone(self);
            tokio::spawn(async move {
                loop {
                    match this.track.recv().await {
                        Ok(sample) => {
                            let _ = this.sender.send(RelayEvent::Sample(sample));
                        }
                        Err(MediaError::Lagged) => {
                            warn!(target: "rustrtc::media", track = %this.base_id, "source track lagged; dropping sample");
                            continue;
                        }
                        Err(MediaError::KindMismatch { .. }) => {
                            warn!(target: "rustrtc::media", track = %this.base_id, "source track returned mismatched sample kind");
                            this.ended.store(true, Ordering::SeqCst);
                            let _ = this.sender.send(RelayEvent::End);
                            break;
                        }
                        Err(MediaError::Closed) | Err(MediaError::EndOfStream) => {
                            this.ended.store(true, Ordering::SeqCst);
                            let _ = this.sender.send(RelayEvent::End);
                            break;
                        }
                    }
                }
            });
        }
    }
}

pub struct RelayStreamTrack {
    id: Arc<str>,
    kind: MediaKind,
    receiver: Mutex<broadcast::Receiver<RelayEvent>>,
    ended: AtomicBool,
}

impl RelayStreamTrack {
    fn new(
        id: Arc<str>,
        kind: MediaKind,
        receiver: broadcast::Receiver<RelayEvent>,
        ended: bool,
    ) -> Self {
        Self {
            id,
            kind,
            receiver: Mutex::new(receiver),
            ended: AtomicBool::new(ended),
        }
    }
}

#[async_trait]
impl MediaStreamTrack for SampleStreamTrack {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> MediaKind {
        self.kind
    }

    fn state(&self) -> TrackState {
        if self.ended.load(Ordering::SeqCst) {
            TrackState::Ended
        } else {
            TrackState::Live
        }
    }

    async fn recv(&self) -> MediaResult<MediaSample> {
        let mut rx = self.receiver.lock().await;
        match rx.recv().await {
            Some(sample) => Ok(sample),
            None => {
                self.ended.store(true, Ordering::SeqCst);
                Err(MediaError::EndOfStream)
            }
        }
    }
}

#[async_trait]
impl MediaStreamTrack for RelayStreamTrack {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> MediaKind {
        self.kind
    }

    fn state(&self) -> TrackState {
        if self.ended.load(Ordering::SeqCst) {
            TrackState::Ended
        } else {
            TrackState::Live
        }
    }

    async fn recv(&self) -> MediaResult<MediaSample> {
        if self.ended.load(Ordering::SeqCst) {
            return Err(MediaError::EndOfStream);
        }
        let mut rx = self.receiver.lock().await;
        match rx.recv().await {
            Ok(RelayEvent::Sample(sample)) => Ok(sample),
            Ok(RelayEvent::End) => {
                self.ended.store(true, Ordering::SeqCst);
                Err(MediaError::EndOfStream)
            }
            Err(broadcast::error::RecvError::Lagged(_)) => Err(MediaError::Lagged),
            Err(broadcast::error::RecvError::Closed) => {
                self.ended.store(true, Ordering::SeqCst);
                Err(MediaError::EndOfStream)
            }
        }
    }
}

impl AudioStreamTrack for SampleStreamTrack {}
impl VideoStreamTrack for SampleStreamTrack {}
impl AudioStreamTrack for RelayStreamTrack {}
impl VideoStreamTrack for RelayStreamTrack {}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use bytes::Bytes;

    use super::*;
    use crate::media::frame::{AudioSampleFormat, VideoPixelFormat};

    #[tokio::test]
    async fn audio_sample_flow() {
        let (source, track) = sample_track(MediaKind::Audio, 8);
        let frame = AudioFrame {
            timestamp: Duration::from_millis(10),
            sample_rate: 48_000,
            channels: 2,
            samples: 960,
            format: AudioSampleFormat::S16,
            data: Bytes::from_static(&[0u8; 10]),
        };
        source.send_audio(frame.clone()).await.unwrap();
        let sample = track.recv().await.unwrap();
        match sample {
            MediaSample::Audio(out) => assert_eq!(out.samples, 960),
            _ => panic!("expected audio sample"),
        }
    }

    #[tokio::test]
    async fn mismatched_kind_is_error() {
        let (source, _track) = sample_track(MediaKind::Audio, 1);
        let video = VideoFrame {
            timestamp: Duration::from_secs(1),
            width: 640,
            height: 480,
            format: VideoPixelFormat::Rgba,
            rotation_deg: 0,
            is_last_packet: false,
            data: Bytes::new(),
        };
        let err = source.send_video(video).await.unwrap_err();
        assert!(matches!(err, MediaError::KindMismatch { .. }));
    }

    #[tokio::test]
    async fn end_of_stream() {
        let (source, track) = sample_track(MediaKind::Video, 1);
        drop(source);
        let result = track.recv().await;
        assert!(matches!(result, Err(MediaError::EndOfStream)));
    }

    #[tokio::test]
    async fn relay_fan_out_delivers_samples() {
        let (source, track) = sample_track(MediaKind::Audio, 4);
        let relay = MediaRelay::new(track.clone());
        let subscriber_a = relay.subscribe();
        let subscriber_b = relay.subscribe();

        let frame = AudioFrame {
            timestamp: Duration::from_millis(5),
            sample_rate: 48_000,
            channels: 2,
            samples: 480,
            format: AudioSampleFormat::S16,
            data: Bytes::from_static(&[1u8; 4]),
        };
        source.send_audio(frame.clone()).await.unwrap();

        let sample_a = subscriber_a.recv().await.unwrap();
        let sample_b = subscriber_b.recv().await.unwrap();

        match (sample_a, sample_b) {
            (MediaSample::Audio(a), MediaSample::Audio(b)) => {
                assert_eq!(a.samples, frame.samples);
                assert_eq!(b.samples, frame.samples);
            }
            _ => panic!("expected audio samples"),
        }
    }

    #[tokio::test]
    async fn relay_propagates_end_of_stream() {
        let (source, track) = sample_track(MediaKind::Video, 1);
        let relay = MediaRelay::new(track.clone());
        let subscriber = relay.subscribe();
        drop(source);
        let result = subscriber.recv().await;
        assert!(matches!(result, Err(MediaError::EndOfStream)));
    }

    #[tokio::test]
    async fn audio_trait_helper_returns_frame() {
        let (source, track) = sample_track(MediaKind::Audio, 1);
        let frame = AudioFrame::default();
        source.send_audio(frame.clone()).await.unwrap();
        let output = track.recv_audio().await.unwrap();
        assert_eq!(output.samples, frame.samples);
    }

    #[tokio::test]
    async fn relay_trait_helper_handles_audio() {
        let (source, track) = sample_track(MediaKind::Audio, 2);
        let relay = MediaRelay::new(track.clone());
        let subscriber = relay.subscribe();
        source
            .send_audio(AudioFrame {
                samples: 240,
                ..AudioFrame::default()
            })
            .await
            .unwrap();
        let frame = subscriber.recv_audio().await.unwrap();
        assert_eq!(frame.samples, 240);
    }
}
