use crate::{
    media::error::{MediaError, MediaResult},
    media::frame::{MediaKind, MediaSample},
    media::spsc::SpscRing,
    media::track::{MediaStreamTrack, SampleStreamSource, SampleStreamTrack, sample_track},
};
use async_trait::async_trait;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::{sync::Notify, task::JoinHandle};

#[async_trait]
pub trait MediaSource: Send + Sync {
    fn id(&self) -> &str;
    fn kind(&self) -> MediaKind;
    async fn next_sample(&mut self) -> MediaResult<MediaSample>;
}

#[async_trait]
pub trait MediaSink: Send + Sync {
    fn kind(&self) -> MediaKind;
    async fn consume(&self, sample: MediaSample) -> MediaResult<()>;
}

pub struct TrackMediaSource {
    track: Arc<dyn MediaStreamTrack>,
}

impl TrackMediaSource {
    pub fn new<T>(track: Arc<T>) -> Self
    where
        T: MediaStreamTrack + 'static,
    {
        Self { track }
    }
}

#[async_trait]
impl MediaSource for TrackMediaSource {
    fn id(&self) -> &str {
        self.track.id()
    }

    fn kind(&self) -> MediaKind {
        self.track.kind()
    }

    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        self.track.recv().await
    }
}

pub struct ChannelMediaSink {
    kind: MediaKind,
    sender: SampleQueueSender,
}

pub struct ChannelMediaSource {
    id: Arc<str>,
    kind: MediaKind,
    receiver: SampleQueueReceiver,
    ended: bool,
}

pub struct SampleQueueSender {
    queue: Arc<SpscRing<MediaSample>>,
    notify: Arc<Notify>,
    pop_lock: Arc<parking_lot::Mutex<()>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

pub struct SampleQueueReceiver {
    queue: Arc<SpscRing<MediaSample>>,
    notify: Arc<Notify>,
    pop_lock: Arc<parking_lot::Mutex<()>>,
    closed: Arc<std::sync::atomic::AtomicBool>,
}

fn sample_queue_channel(capacity: usize) -> (SampleQueueSender, SampleQueueReceiver) {
    let queue = Arc::new(SpscRing::with_capacity(capacity));
    let notify = Arc::new(Notify::new());
    let pop_lock = Arc::new(parking_lot::Mutex::new(()));
    let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    (
        SampleQueueSender {
            queue: queue.clone(),
            notify: notify.clone(),
            pop_lock: pop_lock.clone(),
            closed: closed.clone(),
        },
        SampleQueueReceiver {
            queue,
            notify,
            pop_lock,
            closed,
        },
    )
}

impl SampleQueueSender {
    pub async fn send(&self, sample: MediaSample) -> Result<(), ()> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(());
        }

        let sample = match self.queue.push(sample) {
            Ok(()) => {
                self.notify.notify_one();
                return Ok(());
            }
            Err(sample) => sample,
        };

        let _guard = match self.pop_lock.try_lock() {
            Some(g) => g,
            None => return Ok(()),
        };

        let _ = self.queue.pop();
        if self.queue.push(sample).is_ok() {
            self.notify.notify_one();
        }
        Ok(())
    }

    pub fn try_send(&self, sample: MediaSample) -> Result<(), MediaSample> {
        if self.closed.load(std::sync::atomic::Ordering::Acquire) {
            return Err(sample);
        }

        match self.queue.push(sample) {
            Ok(()) => {
                self.notify.notify_one();
                Ok(())
            }
            Err(sample) => Err(sample),
        }
    }
}

impl Drop for SampleQueueSender {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }
}

impl SampleQueueReceiver {
    pub async fn recv(&mut self) -> Option<MediaSample> {
        loop {
            {
                let _guard = self.pop_lock.lock();
                if let Some(sample) = self.queue.pop() {
                    return Some(sample);
                }
                if self.closed.load(std::sync::atomic::Ordering::Acquire) {
                    return None;
                }
            }

            let notified = self.notify.notified();
            if self.queue.is_empty() && !self.closed.load(std::sync::atomic::Ordering::Acquire) {
                notified.await;
            }
        }
    }
}

impl Drop for SampleQueueReceiver {
    fn drop(&mut self) {
        self.closed
            .store(true, std::sync::atomic::Ordering::Release);
        self.notify.notify_waiters();
    }
}

static CHANNEL_SOURCE_COUNTER: AtomicU64 = AtomicU64::new(1);

impl ChannelMediaSink {
    pub fn new(kind: MediaKind, sender: SampleQueueSender) -> Self {
        Self { kind, sender }
    }

    pub fn channel(kind: MediaKind, capacity: usize) -> (Self, SampleQueueReceiver) {
        let (sender, receiver) = sample_queue_channel(capacity);
        (Self::new(kind, sender), receiver)
    }
}

impl ChannelMediaSource {
    pub fn new(id: Arc<str>, kind: MediaKind, receiver: SampleQueueReceiver) -> Self {
        Self {
            id,
            kind,
            receiver,
            ended: false,
        }
    }

    pub fn channel(kind: MediaKind, capacity: usize) -> (SampleQueueSender, Self) {
        let (sender, receiver) = sample_queue_channel(capacity);
        let id = next_channel_source_id();
        (sender, Self::new(id, kind, receiver))
    }
}

fn next_channel_source_id() -> Arc<str> {
    let value = CHANNEL_SOURCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    Arc::<str>::from(format!("channel-source-{value}"))
}

#[async_trait]
impl MediaSink for ChannelMediaSink {
    fn kind(&self) -> MediaKind {
        self.kind
    }

    async fn consume(&self, sample: MediaSample) -> MediaResult<()> {
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

#[async_trait]
impl MediaSource for ChannelMediaSource {
    fn id(&self) -> &str {
        &self.id
    }

    fn kind(&self) -> MediaKind {
        self.kind
    }

    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        if self.ended {
            return Err(MediaError::EndOfStream);
        }
        match self.receiver.recv().await {
            Some(sample) => Ok(sample),
            None => {
                self.ended = true;
                Err(MediaError::EndOfStream)
            }
        }
    }
}

pub struct TrackMediaSink {
    source: Arc<SampleStreamSource>,
    kind: MediaKind,
}

impl TrackMediaSink {
    pub fn new(source: Arc<SampleStreamSource>) -> Self {
        let kind = source.kind();
        Self { source, kind }
    }

    pub fn source(&self) -> Arc<SampleStreamSource> {
        Arc::clone(&self.source)
    }
}

#[async_trait]
impl MediaSink for TrackMediaSink {
    fn kind(&self) -> MediaKind {
        self.kind
    }

    async fn consume(&self, sample: MediaSample) -> MediaResult<()> {
        self.source.send(sample).await
    }
}

pub type DynMediaSource = dyn MediaSource + Send + Sync + 'static;
pub type DynMediaSink = dyn MediaSink + Send + Sync + 'static;

pub fn spawn_media_pump(
    mut source: Box<DynMediaSource>,
    sink: Arc<DynMediaSink>,
) -> MediaResult<JoinHandle<MediaResult<()>>> {
    if source.kind() != sink.kind() {
        return Err(MediaError::KindMismatch {
            expected: source.kind(),
            actual: sink.kind(),
        });
    }

    Ok(tokio::spawn(async move {
        loop {
            let sample = match source.next_sample().await {
                Ok(sample) => sample,
                Err(MediaError::EndOfStream) => return Ok(()),
                Err(err) => return Err(err),
            };

            sink.consume(sample).await?;
        }
    }))
}

pub fn track_from_source(
    source: Box<DynMediaSource>,
    capacity: usize,
) -> MediaResult<(Arc<SampleStreamTrack>, JoinHandle<MediaResult<()>>)> {
    let kind = source.kind();
    let (sample_source, track, _feedback_rx) = sample_track(kind, capacity);
    let sink: Arc<DynMediaSink> = Arc::new(TrackMediaSink::new(Arc::new(sample_source)));
    let pump = spawn_media_pump(source, sink)?;
    Ok((track, pump))
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;
    use crate::{media::frame::AudioFrame, media::track::sample_track};

    #[tokio::test]
    async fn track_media_source_yields_samples() {
        let (source, track, _) = sample_track(MediaKind::Audio, 1);
        let mut track_source = TrackMediaSource::new(track.clone());
        source
            .send_audio(AudioFrame {
                data: Bytes::from_static(&[1; 4]),
                ..AudioFrame::default()
            })
            .await
            .unwrap();
        let sample = track_source.next_sample().await.unwrap();
        assert!(matches!(sample, MediaSample::Audio(_)));
    }

    #[tokio::test]
    async fn channel_media_sink_forwards_samples() {
        let (sink, mut receiver) = ChannelMediaSink::channel(MediaKind::Audio, 1);
        let frame = MediaSample::Audio(AudioFrame::default());
        sink.consume(frame.clone()).await.unwrap();
        let received = receiver.recv().await.unwrap();
        assert_eq!(received, frame);
    }

    #[tokio::test]
    async fn channel_media_source_provides_samples() {
        let (sender, mut source) = ChannelMediaSource::channel(MediaKind::Audio, 1);
        let sample = MediaSample::Audio(AudioFrame {
            ..AudioFrame::default()
        });
        sender.send(sample.clone()).await.unwrap();
        let output = source.next_sample().await.unwrap();
        assert_eq!(output, sample);
    }

    #[tokio::test]
    async fn track_media_sink_pushes_samples() {
        let (sample_source, track, _) = sample_track(MediaKind::Audio, 1);
        let sink = TrackMediaSink::new(Arc::new(sample_source));
        sink.consume(MediaSample::Audio(AudioFrame::default()))
            .await
            .unwrap();
        let received = track.recv().await.unwrap();
        assert!(matches!(received, MediaSample::Audio(_)));
    }

    #[tokio::test]
    async fn media_pump_moves_samples_until_end_of_stream() {
        let (source_handle, track, _) = sample_track(MediaKind::Audio, 1);
        let source: Box<DynMediaSource> = Box::new(TrackMediaSource::new(track.clone()));
        let (sink_impl, mut receiver) = ChannelMediaSink::channel(MediaKind::Audio, 1);
        let sink: Arc<DynMediaSink> = Arc::new(sink_impl);
        let pump = spawn_media_pump(source, sink).unwrap();

        source_handle
            .send_audio(AudioFrame {
                ..AudioFrame::default()
            })
            .await
            .unwrap();

        let received = receiver.recv().await.unwrap();
        assert!(matches!(received, MediaSample::Audio(_)));

        drop(source_handle);
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn media_pump_rejects_kind_mismatch() {
        let (_source_handle, track, _) = sample_track(MediaKind::Audio, 1);
        let source: Box<DynMediaSource> = Box::new(TrackMediaSource::new(track));
        let (sink_impl, _receiver) = ChannelMediaSink::channel(MediaKind::Video, 1);
        let sink: Arc<DynMediaSink> = Arc::new(sink_impl);
        let err = spawn_media_pump(source, sink).unwrap_err();
        assert!(matches!(err, MediaError::KindMismatch { .. }));
    }

    #[tokio::test]
    async fn media_pump_propagates_sink_error() {
        let (source_handle, track, _) = sample_track(MediaKind::Audio, 1);
        let source: Box<DynMediaSource> = Box::new(TrackMediaSource::new(track));
        let (sink_impl, receiver) = ChannelMediaSink::channel(MediaKind::Audio, 1);
        drop(receiver);
        let sink: Arc<DynMediaSink> = Arc::new(sink_impl);
        let pump = spawn_media_pump(source, sink).unwrap();

        source_handle
            .send_audio(AudioFrame::default())
            .await
            .unwrap();

        let err = pump.await.unwrap().unwrap_err();
        assert!(matches!(err, MediaError::Closed));
    }

    #[tokio::test]
    async fn channel_source_with_pump_to_track_sink() {
        let (sender, channel_source) = ChannelMediaSource::channel(MediaKind::Audio, 1);
        let source: Box<DynMediaSource> = Box::new(channel_source);
        let (track_source, track, _) = sample_track(MediaKind::Audio, 1);
        let sink: Arc<DynMediaSink> = Arc::new(TrackMediaSink::new(Arc::new(track_source)));
        let pump = spawn_media_pump(source, sink).unwrap();

        sender
            .send(MediaSample::Audio(AudioFrame {
                ..AudioFrame::default()
            }))
            .await
            .unwrap();

        let sample = track.recv().await.unwrap();
        assert!(matches!(sample, MediaSample::Audio(_)));

        drop(sender);
        pump.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn track_from_source_creates_track_and_pump() {
        let (producer, upstream_track, _) = sample_track(MediaKind::Audio, 1);
        let media_source: Box<DynMediaSource> = Box::new(TrackMediaSource::new(upstream_track));
        let (track, pump) = track_from_source(media_source, 1).unwrap();

        producer
            .send_audio(AudioFrame {
                ..AudioFrame::default()
            })
            .await
            .unwrap();

        let received = track.recv().await.unwrap();
        assert!(matches!(received, MediaSample::Audio(_)));

        drop(producer);
        pump.await.unwrap().unwrap();
    }
}
