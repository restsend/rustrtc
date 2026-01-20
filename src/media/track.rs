use crate::{
    media::{
        error::{MediaError, MediaResult},
        frame::{AudioFrame, MediaKind, MediaSample, VideoFrame},
    },
    transports::ice::stun::random_u64,
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use tokio::sync::{Mutex, broadcast, mpsc};
use tracing::{debug, warn};

#[derive(Debug, Clone)]
pub enum FeedbackEvent {
    RequestKeyFrame,
}

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
    async fn request_key_frame(&self) -> MediaResult<()>;
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
    feedback_tx: mpsc::Sender<FeedbackEvent>,
}

impl SampleStreamTrack {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Stop this track by marking it as ended
    pub fn stop(&self) {
        self.ended.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[derive(Clone)]
pub struct SampleStreamSource {
    id: Arc<str>,
    kind: MediaKind,
    sender: mpsc::Sender<MediaSample>,
}

fn next_track_id() -> Arc<str> {
    let value = random_u64();
    Arc::<str>::from(format!("track-{value}"))
}

fn next_relay_track_id(base: &str) -> Arc<str> {
    let suffix = random_u64();
    Arc::<str>::from(format!("{base}-relay-{suffix}"))
}

pub fn sample_track(
    kind: MediaKind,
    capacity: usize,
) -> (
    SampleStreamSource,
    Arc<SampleStreamTrack>,
    mpsc::Receiver<FeedbackEvent>,
) {
    let (sender, receiver) = mpsc::channel(capacity);
    let (feedback_tx, feedback_rx) = mpsc::channel(10);
    let id = next_track_id();
    let track = Arc::new(SampleStreamTrack {
        id: id.clone(),
        kind,
        receiver: Mutex::new(receiver),
        ended: AtomicBool::new(false),
        feedback_tx,
    });
    let source = SampleStreamSource { id, kind, sender };
    (source, track, feedback_rx)
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
    feedback_tx: mpsc::Sender<FeedbackEvent>,
    feedback_rx: std::sync::Mutex<Option<mpsc::Receiver<FeedbackEvent>>>,
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
        let (feedback_tx, feedback_rx) = mpsc::channel(10);
        let dyn_track: Arc<dyn MediaStreamTrack> = track;
        Self {
            inner: Arc::new(RelayInner {
                base_id,
                kind,
                track: dyn_track,
                sender,
                started: AtomicBool::new(false),
                ended: AtomicBool::new(false),
                feedback_tx,
                feedback_rx: std::sync::Mutex::new(Some(feedback_rx)),
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
            self.inner.feedback_tx.clone(),
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
            let mut rx_guard = self.feedback_rx.lock().unwrap();
            let mut feedback_rx = rx_guard.take().unwrap();

            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        res = this.track.recv() => {
                            match res {
                                Ok(sample) => {
                                    let _ = this.sender.send(RelayEvent::Sample(sample));
                                }
                                Err(MediaError::Lagged) => {
                                    debug!(target: "rustrtc::media", track = %this.base_id, "source track lagged; dropping sample");
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
                        Some(event) = feedback_rx.recv() => {
                            match event {
                                FeedbackEvent::RequestKeyFrame => {
                                    if let Err(e) = this.track.request_key_frame().await {
                                        debug!(target: "rustrtc::media", track = %this.base_id, "failed to forward key frame request: {}", e);
                                    }
                                }
                            }
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
    feedback_tx: mpsc::Sender<FeedbackEvent>,
}

impl RelayStreamTrack {
    fn new(
        id: Arc<str>,
        kind: MediaKind,
        receiver: broadcast::Receiver<RelayEvent>,
        ended: bool,
        feedback_tx: mpsc::Sender<FeedbackEvent>,
    ) -> Self {
        Self {
            id,
            kind,
            receiver: Mutex::new(receiver),
            ended: AtomicBool::new(ended),
            feedback_tx,
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

    async fn request_key_frame(&self) -> MediaResult<()> {
        self.feedback_tx
            .send(FeedbackEvent::RequestKeyFrame)
            .await
            .map_err(|_| MediaError::Closed)
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

    async fn request_key_frame(&self) -> MediaResult<()> {
        self.feedback_tx
            .send(FeedbackEvent::RequestKeyFrame)
            .await
            .map_err(|_| MediaError::Closed)
    }
}

impl AudioStreamTrack for SampleStreamTrack {}
impl VideoStreamTrack for SampleStreamTrack {}
impl AudioStreamTrack for RelayStreamTrack {}
impl VideoStreamTrack for RelayStreamTrack {}

pub struct SelectorTrack {
    id: Arc<str>,
    kind: MediaKind,
    current_track: Mutex<Arc<dyn MediaStreamTrack>>,
    switch_notify: Arc<tokio::sync::Notify>,
}

impl SelectorTrack {
    pub fn new(initial_track: Arc<dyn MediaStreamTrack>) -> Self {
        Self {
            id: next_relay_track_id(initial_track.id()),
            kind: initial_track.kind(),
            current_track: Mutex::new(initial_track),
            switch_notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub async fn switch_to(&self, track: Arc<dyn MediaStreamTrack>) -> MediaResult<()> {
        if track.kind() != self.kind {
            return Err(MediaError::KindMismatch {
                expected: self.kind,
                actual: track.kind(),
            });
        }
        {
            let mut current = self.current_track.lock().await;
            *current = track;
        }
        self.switch_notify.notify_waiters();
        Ok(())
    }
}

#[async_trait]
impl MediaStreamTrack for SelectorTrack {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> MediaKind {
        self.kind
    }

    fn state(&self) -> TrackState {
        // We could check the current track state, but for a selector,
        // it's live as long as it can switch.
        // Simplification: just return Live.
        TrackState::Live
    }

    async fn recv(&self) -> MediaResult<MediaSample> {
        loop {
            let track = self.current_track.lock().await.clone();
            tokio::select! {
                res = track.recv() => return res,
                _ = self.switch_notify.notified() => {
                    // Track switched, loop again to pick up new track
                    continue;
                }
            }
        }
    }

    async fn request_key_frame(&self) -> MediaResult<()> {
        let track = self.current_track.lock().await.clone();
        track.request_key_frame().await
    }
}

impl AudioStreamTrack for SelectorTrack {}
impl VideoStreamTrack for SelectorTrack {}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::media::frame::VideoPixelFormat;

    #[tokio::test]
    async fn selector_switches_source() {
        let (source_a, track_a, _) = sample_track(MediaKind::Audio, 10);
        let (source_b, track_b, _) = sample_track(MediaKind::Audio, 10);

        let selector = Arc::new(SelectorTrack::new(track_a));

        // Send on A
        source_a
            .send_audio(AudioFrame {
                ..Default::default()
            })
            .await
            .unwrap();
        let _sample = selector.recv_audio().await.unwrap();

        // Switch to B
        selector.switch_to(track_b).await.unwrap();

        // Send on B
        source_b
            .send_audio(AudioFrame {
                ..Default::default()
            })
            .await
            .unwrap();
        let _sample = selector.recv_audio().await.unwrap();
    }

    #[tokio::test]
    async fn selector_propagates_key_frame_request() {
        let (_source_a, track_a, mut feedback_a) = sample_track(MediaKind::Video, 10);
        let (_source_b, track_b, mut feedback_b) = sample_track(MediaKind::Video, 10);

        let selector = Arc::new(SelectorTrack::new(track_a));

        // Request on A
        selector.request_key_frame().await.unwrap();
        assert!(matches!(
            feedback_a.recv().await.unwrap(),
            FeedbackEvent::RequestKeyFrame
        ));

        // Switch to B
        selector.switch_to(track_b).await.unwrap();

        // Request on B
        selector.request_key_frame().await.unwrap();
        assert!(matches!(
            feedback_b.recv().await.unwrap(),
            FeedbackEvent::RequestKeyFrame
        ));
    }

    #[tokio::test]
    async fn mismatched_kind_is_error() {
        let (source, _track, _) = sample_track(MediaKind::Audio, 1);
        let video = VideoFrame {
            rtp_timestamp: 0,
            width: 640,
            height: 480,
            format: VideoPixelFormat::Rgba,
            rotation_deg: 0,
            is_last_packet: false,
            data: Bytes::new(),
            header_extension: None,
            csrcs: Vec::new(),
            sequence_number: None,
            payload_type: None,
        };
        let err = source.send_video(video).await.unwrap_err();
        assert!(matches!(err, MediaError::KindMismatch { .. }));
    }

    #[tokio::test]
    async fn end_of_stream() {
        let (source, track, _) = sample_track(MediaKind::Video, 1);
        drop(source);
        let result = track.recv().await;
        assert!(matches!(result, Err(MediaError::EndOfStream)));
    }

    #[tokio::test]
    async fn relay_fan_out_delivers_samples() {
        let (source, track, _) = sample_track(MediaKind::Audio, 4);
        let relay = MediaRelay::new(track.clone());
        let subscriber_a = relay.subscribe();
        let subscriber_b = relay.subscribe();

        let frame = AudioFrame {
            rtp_timestamp: 0,
            clock_rate: 48_000,
            data: Bytes::from_static(&[1u8; 4]),
            sequence_number: None,
            payload_type: None,
            marker: false,
        };
        source.send_audio(frame.clone()).await.unwrap();

        let sample_a = subscriber_a.recv().await.unwrap();
        let sample_b = subscriber_b.recv().await.unwrap();

        match (sample_a, sample_b) {
            (MediaSample::Audio(a), MediaSample::Audio(b)) => {
                assert_eq!(a.clock_rate, frame.clock_rate);
                assert_eq!(b.payload_type, frame.payload_type);
            }
            _ => panic!("expected audio samples"),
        }
    }

    #[tokio::test]
    async fn relay_propagates_end_of_stream() {
        let (source, track, _) = sample_track(MediaKind::Video, 1);
        let relay = MediaRelay::new(track.clone());
        let subscriber = relay.subscribe();
        drop(source);
        let result = subscriber.recv().await;
        assert!(matches!(result, Err(MediaError::EndOfStream)));
    }

    #[tokio::test]
    async fn audio_trait_helper_returns_frame() {
        let (source, track, _) = sample_track(MediaKind::Audio, 1);
        let frame = AudioFrame::default();
        source.send_audio(frame.clone()).await.unwrap();
        let output = track.recv_audio().await.unwrap();
        assert_eq!(output.payload_type, frame.payload_type);
    }

    #[tokio::test]
    async fn relay_propagates_key_frame_request() {
        let (_source, track, mut feedback_rx) = sample_track(MediaKind::Video, 1);
        let relay = MediaRelay::new(track.clone());
        let subscriber = relay.subscribe();

        // Subscriber requests key frame
        subscriber.request_key_frame().await.unwrap();

        // Source should receive the request
        let event = feedback_rx.recv().await.unwrap();
        assert!(matches!(event, FeedbackEvent::RequestKeyFrame));
    }
}
