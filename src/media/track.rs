use crate::platform::atomic64::AtomicU64;
use crate::prelude::*;
use crate::{
    media::{
        error::{MediaError, MediaResult},
        frame::{AudioFrame, MediaKind, MediaSample, VideoFrame},
        spsc::SpscRing,
    },
    platform::{
        select::{Either, select2},
        sync,
        sync::broadcast::TryRecvError as BroadcastTryRecvError,
        task::spawn,
    },
    transports::ice::stun::random_u64,
};
use async_trait::async_trait;
use core::sync::atomic::{AtomicBool, Ordering};
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
    fn drop_count(&self) -> u64 {
        0
    }
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
    queue: Arc<SpscRing<MediaSample>>,
    notify: Arc<sync::Notify>,
    pop_lock: Arc<sync::Mutex<()>>,
    source_closed: Arc<AtomicBool>,
    ended: AtomicBool,
    feedback_tx: sync::mpsc::Sender<FeedbackEvent>,
    drop_count: Arc<AtomicU64>,
}

impl SampleStreamTrack {
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Stop this track by marking it as ended
    pub fn stop(&self) {
        self.ended.store(true, core::sync::atomic::Ordering::SeqCst);
        self.notify.notify_waiters();
    }
}

pub struct SampleStreamSource {
    id: Arc<str>,
    kind: MediaKind,
    queue: Arc<SpscRing<MediaSample>>,
    notify: Arc<sync::Notify>,
    pop_lock: Arc<sync::Mutex<()>>,
    /// Serializes pushes: `queue` is single-producer, but clones of a source
    /// share it.
    push_lock: Arc<sync::Mutex<()>>,
    source_closed: Arc<AtomicBool>,
    active_senders: Arc<core::sync::atomic::AtomicUsize>,
    drop_count: Arc<AtomicU64>,
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
    sync::mpsc::Receiver<FeedbackEvent>,
) {
    let queue = Arc::new(SpscRing::with_capacity(capacity));
    let notify = Arc::new(sync::Notify::new());
    let pop_lock = Arc::new(sync::Mutex::new(()));
    let source_closed = Arc::new(AtomicBool::new(false));
    let active_senders = Arc::new(core::sync::atomic::AtomicUsize::new(1));
    let drop_count = Arc::new(AtomicU64::new(0));
    let (feedback_tx, feedback_rx) = sync::mpsc::channel(10);
    let id = next_track_id();
    let track = Arc::new(SampleStreamTrack {
        id: id.clone(),
        kind,
        queue: queue.clone(),
        notify: notify.clone(),
        pop_lock: pop_lock.clone(),
        source_closed: source_closed.clone(),
        ended: AtomicBool::new(false),
        feedback_tx,
        drop_count: drop_count.clone(),
    });
    let source = SampleStreamSource {
        id,
        kind,
        queue,
        notify,
        pop_lock,
        push_lock: Arc::new(sync::Mutex::new(())),
        source_closed,
        active_senders,
        drop_count,
    };
    (source, track, feedback_rx)
}

impl Clone for SampleStreamSource {
    fn clone(&self) -> Self {
        self.active_senders
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        Self {
            id: self.id.clone(),
            kind: self.kind,
            queue: self.queue.clone(),
            notify: self.notify.clone(),
            pop_lock: self.pop_lock.clone(),
            push_lock: self.push_lock.clone(),
            source_closed: self.source_closed.clone(),
            active_senders: self.active_senders.clone(),
            drop_count: self.drop_count.clone(),
        }
    }
}

impl SampleStreamSource {
    fn try_send_drop_oldest(&self, sample: MediaSample) -> MediaResult<()> {
        if self.source_closed.load(Ordering::Acquire) {
            return Err(MediaError::Closed);
        }

        let _push_guard = self.push_lock.lock();
        let sample = match self.queue.push(sample) {
            Ok(()) => {
                self.notify.notify_one();
                return Ok(());
            }
            Err(sample) => sample,
        };

        // Queue full: try drop-oldest under a short critical section.
        let _pop_guard = match self.pop_lock.try_lock() {
            Some(guard) => guard,
            None => return Ok(()),
        };

        let _ = self.queue.pop();
        if self.queue.push(sample).is_ok() {
            self.notify.notify_one();
        }

        Ok(())
    }

    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn kind(&self) -> MediaKind {
        self.kind
    }

    pub fn send_audio(&self, frame: AudioFrame) -> MediaResult<()> {
        self.send(MediaSample::Audio(frame))
    }

    pub fn send_video(&self, frame: VideoFrame) -> MediaResult<()> {
        self.send(MediaSample::Video(frame))
    }

    pub fn send(&self, sample: MediaSample) -> MediaResult<()> {
        if sample.kind() != self.kind {
            return Err(MediaError::KindMismatch {
                expected: self.kind,
                actual: sample.kind(),
            });
        }
        self.try_send_drop_oldest(sample)
    }

    pub fn send_many<I>(&self, samples: I) -> MediaResult<()>
    where
        I: IntoIterator<Item = MediaSample>,
    {
        for sample in samples {
            if sample.kind() != self.kind {
                return Err(MediaError::KindMismatch {
                    expected: self.kind,
                    actual: sample.kind(),
                });
            }

            self.try_send_drop_oldest(sample)?;
        }

        Ok(())
    }

    pub fn try_send_audio(&self, frame: AudioFrame) -> MediaResult<()> {
        self.try_send(MediaSample::Audio(frame))
    }

    pub fn try_send_video(&self, frame: VideoFrame) -> MediaResult<()> {
        self.try_send(MediaSample::Video(frame))
    }

    pub fn try_send(&self, sample: MediaSample) -> MediaResult<()> {
        if sample.kind() != self.kind {
            return Err(MediaError::KindMismatch {
                expected: self.kind,
                actual: sample.kind(),
            });
        }
        if self.source_closed.load(Ordering::Acquire) {
            return Err(MediaError::Closed);
        }

        let _push_guard = self.push_lock.try_lock().ok_or(MediaError::WouldBlock)?;
        self.queue
            .push(sample)
            .map_err(|_| MediaError::WouldBlock)?;
        self.notify.notify_one();
        Ok(())
    }

    /// Increments the drop count (called by RtpReceiver when depacketizer drops frames).
    pub fn increment_drop_count(&self) {
        self.drop_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Returns the current drop count.
    pub fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }
}

impl Drop for SampleStreamSource {
    fn drop(&mut self) {
        if self
            .active_senders
            .fetch_sub(1, core::sync::atomic::Ordering::AcqRel)
            == 1
        {
            self.source_closed.store(true, Ordering::Release);
            self.notify.notify_waiters();
        }
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
    sender: sync::broadcast::Sender<RelayEvent>,
    started: AtomicBool,
    ended: AtomicBool,
    feedback_tx: sync::mpsc::Sender<FeedbackEvent>,
    feedback_rx: sync::Mutex<Option<sync::mpsc::Receiver<FeedbackEvent>>>,
    /// Serializes the "no subscribers → shut down" transition against a racing
    /// `subscribe()` so the relay task cannot exit while a new subscriber is
    /// being attached (and vice-versa).
    lifecycle: sync::Mutex<()>,
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
        let (sender, _) = sync::broadcast::channel(capacity);
        let (feedback_tx, feedback_rx) = sync::mpsc::channel(10);
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
                feedback_rx: sync::Mutex::new(Some(feedback_rx)),
                lifecycle: sync::Mutex::new(()),
            }),
        }
    }

    pub fn subscribe(&self) -> Arc<RelayStreamTrack> {
        // Hold the lifecycle lock so the relay task cannot observe a transient
        // receiver_count==0 and shut down while we are attaching a subscriber.
        let _guard = self.inner.lifecycle.lock();
        // Increment receiver_count FIRST, then ensure the task is running.
        let receiver = self.inner.sender.subscribe();
        self.inner.ensure_started();
        Arc::new(RelayStreamTrack::new(
            next_relay_track_id(&self.inner.base_id),
            self.inner.kind,
            receiver,
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
            let mut rx_guard = self.feedback_rx.lock();
            let mut feedback_rx = rx_guard.take().unwrap();

            spawn(async move {
                // select2 parity of the former tokio::select!: its
                // `Some(event) =` pattern disabled the feedback arm once the
                // channel closed. select2 has no arm patterns, so openness
                // is tracked with a flag; afterwards we wait on the source
                // track alone.
                let mut feedback_open = true;
                loop {
                    enum Arm {
                        Sample(Result<MediaSample, MediaError>),
                        Feedback(FeedbackEvent),
                    }
                    let arm = if feedback_open {
                        // tokio's `Recv` future is !Unpin; the seam's select2
                        // takes Unpin futures, so pin to the stack (no_std
                        // backend futures are Unpin and pass through pin!).
                        let feedback_fut = feedback_rx.recv();
                        match select2(this.track.recv(), core::pin::pin!(feedback_fut)).await {
                            Either::A(res) => Arm::Sample(res),
                            Either::B(Some(event)) => Arm::Feedback(event),
                            Either::B(None) => {
                                feedback_open = false;
                                continue;
                            }
                        }
                    } else {
                        Arm::Sample(this.track.recv().await)
                    };
                    match arm {
                        Arm::Sample(res) => {
                            match res {
                                Ok(sample) => {
                                    // sync::broadcast::send returns Err when there are
                                    // no active receivers. When that happens the
                                    // relay has no consumers; shut down (race-free
                                    // w.r.t. subscribe() via the lifecycle lock) so
                                    // this task, the source track Arc and the
                                    // feedback channel don't linger until the
                                    // upstream track happens to close.
                                    if this.sender.send(RelayEvent::Sample(sample)).is_err() {
                                        let guard = this.lifecycle.lock();
                                        // A subscriber may have arrived between the
                                        // failed send and acquiring the lock; only
                                        // shut down if still nobody is listening.
                                        if this.sender.receiver_count() == 0 {
                                            this.started.store(false, Ordering::SeqCst);
                                            drop(guard);
                                            break;
                                        }
                                        // Otherwise a new subscriber just attached;
                                        // keep relaying (the current sample is lost).
                                    }
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
                                Err(MediaError::WouldBlock) => {
                                    // This shouldn't happen in recv path, but handle it gracefully
                                    debug!(target: "rustrtc::media", track = %this.base_id, "unexpected WouldBlock in recv");
                                    continue;
                                }
                                Err(MediaError::Closed) | Err(MediaError::EndOfStream) => {
                                    this.ended.store(true, Ordering::SeqCst);
                                    let _ = this.sender.send(RelayEvent::End);
                                    break;
                                }
                            }
                        }
                        Arm::Feedback(FeedbackEvent::RequestKeyFrame) => {
                            if let Err(e) = this.track.request_key_frame().await {
                                debug!(target: "rustrtc::media", track = %this.base_id, "failed to forward key frame request: {}", e);
                            }
                        }
                    }
                }
                debug!(target: "rustrtc::media", track = %this.base_id, "MediaRelay task exiting (no subscribers or source ended)");
            });
        }
    }
}

pub struct RelayStreamTrack {
    id: Arc<str>,
    kind: MediaKind,
    receiver: sync::AsyncMutex<sync::broadcast::Receiver<RelayEvent>>,
    ended: AtomicBool,
    feedback_tx: sync::mpsc::Sender<FeedbackEvent>,
}

impl RelayStreamTrack {
    fn new(
        id: Arc<str>,
        kind: MediaKind,
        receiver: sync::broadcast::Receiver<RelayEvent>,
        ended: bool,
        feedback_tx: sync::mpsc::Sender<FeedbackEvent>,
    ) -> Self {
        Self {
            id,
            kind,
            receiver: sync::AsyncMutex::new(receiver),
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
        loop {
            if self.ended.load(Ordering::SeqCst) {
                return Err(MediaError::EndOfStream);
            }

            {
                let _pop_guard = self.pop_lock.lock();
                if let Some(sample) = self.queue.pop() {
                    return Ok(sample);
                }

                if self.source_closed.load(Ordering::Acquire) {
                    self.ended.store(true, Ordering::SeqCst);
                    return Err(MediaError::EndOfStream);
                }
            }

            self.notify.notified().await;
            if self.source_closed.load(Ordering::Acquire) && self.queue.is_empty() {
                self.ended.store(true, Ordering::SeqCst);
                return Err(MediaError::EndOfStream);
            }
        }
    }

    async fn request_key_frame(&self) -> MediaResult<()> {
        self.feedback_tx
            .send(FeedbackEvent::RequestKeyFrame)
            .await
            .map_err(|_| MediaError::Closed)
    }

    fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
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

        match rx.try_recv() {
            Ok(RelayEvent::Sample(sample)) => return Ok(sample),
            Ok(RelayEvent::End) => {
                self.ended.store(true, Ordering::SeqCst);
                return Err(MediaError::EndOfStream);
            }
            Err(BroadcastTryRecvError::Empty) => {}
            Err(BroadcastTryRecvError::Lagged(_)) => return Err(MediaError::Lagged),
            Err(BroadcastTryRecvError::Closed) => {
                self.ended.store(true, Ordering::SeqCst);
                return Err(MediaError::EndOfStream);
            }
        }

        match rx.recv().await {
            Ok(RelayEvent::Sample(sample)) => Ok(sample),
            Ok(RelayEvent::End) => {
                self.ended.store(true, Ordering::SeqCst);
                Err(MediaError::EndOfStream)
            }
            Err(sync::broadcast::RecvError::Lagged(_)) => Err(MediaError::Lagged),
            Err(sync::broadcast::RecvError::Closed) => {
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
    current_track: sync::AsyncMutex<Arc<dyn MediaStreamTrack>>,
    switch_notify: Arc<sync::Notify>,
}

impl SelectorTrack {
    pub fn new(initial_track: Arc<dyn MediaStreamTrack>) -> Self {
        Self {
            id: next_relay_track_id(initial_track.id()),
            kind: initial_track.kind(),
            current_track: sync::AsyncMutex::new(initial_track),
            switch_notify: Arc::new(sync::Notify::new()),
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
            let notified = self.switch_notify.notified();
            match select2(track.recv(), core::pin::pin!(notified)).await {
                Either::A(res) => return res,
                Either::B(()) => {
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

// Tests drive real async runtimes (tokio); they stay std-only. no_std
// behavior parity for the seam types is covered by the WP3 host-parity suite.
#[cfg(all(test, feature = "std"))]
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
            .unwrap();
        let _sample = selector.recv_audio().await.unwrap();

        // Switch to B
        selector.switch_to(track_b).await.unwrap();

        // Send on B
        source_b
            .send_audio(AudioFrame {
                ..Default::default()
            })
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
            ..Default::default()
        };
        let err = source.send_video(video).unwrap_err();
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
            ..Default::default()
        };
        source.send_audio(frame.clone()).unwrap();

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
        source.send_audio(frame.clone()).unwrap();
        let output = track.recv_audio().await.unwrap();
        assert_eq!(output.payload_type, frame.payload_type);
    }

    #[tokio::test]
    async fn send_drops_when_queue_is_full() {
        let (source, _track, _) = sample_track(MediaKind::Audio, 1);
        source.send_audio(AudioFrame::default()).unwrap();
        source.send_audio(AudioFrame::default()).unwrap();
    }

    #[tokio::test]
    async fn send_full_queue_drops_oldest_sample() {
        let (source, track, _) = sample_track(MediaKind::Audio, 1);
        let first = AudioFrame {
            data: Bytes::from_static(&[1u8]),
            ..Default::default()
        };
        let second = AudioFrame {
            data: Bytes::from_static(&[2u8]),
            ..Default::default()
        };

        source.send_audio(first).unwrap();
        source.send_audio(second.clone()).unwrap();

        let recv = track.recv_audio().await.unwrap();
        assert_eq!(recv.data, second.data);
    }

    #[tokio::test]
    #[allow(clippy::await_holding_lock)] // intentionally held to prove send_audio doesn't deadlock
    async fn send_does_not_block_when_receiver_lock_is_held() {
        let (source, _track, _) = sample_track(MediaKind::Audio, 1);
        source.send_audio(AudioFrame::default()).unwrap();

        let _pop_lock = source.pop_lock.lock();
        source
            .send_audio(AudioFrame::default())
            .expect("send should not block while receiver lock is held");
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
