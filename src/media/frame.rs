use std::time::Duration;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum AudioSampleFormat {
    S16,
    S32,
    F32,
    F64,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum VideoPixelFormat {
    I420,
    Nv12,
    Rgba,
    Bgra,
    #[default]
    Unspecified,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioFrame {
    pub timestamp: Duration,
    pub sample_rate: u32,
    pub channels: u8,
    pub samples: u32,
    pub format: AudioSampleFormat,
    pub data: Bytes,
}

impl Default for AudioFrame {
    fn default() -> Self {
        Self {
            timestamp: Duration::default(),
            sample_rate: 48_000,
            channels: 2,
            samples: 0,
            format: AudioSampleFormat::default(),
            data: Bytes::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoFrame {
    pub timestamp: Duration,
    pub width: u16,
    pub height: u16,
    pub format: VideoPixelFormat,
    pub rotation_deg: u16,
    pub is_last_packet: bool,
    pub data: Bytes,
}

impl Default for VideoFrame {
    fn default() -> Self {
        Self {
            timestamp: Duration::default(),
            width: 0,
            height: 0,
            format: VideoPixelFormat::default(),
            rotation_deg: 0,
            is_last_packet: false,
            data: Bytes::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaSample {
    Audio(AudioFrame),
    Video(VideoFrame),
}

impl MediaSample {
    pub fn kind(&self) -> MediaKind {
        match self {
            MediaSample::Audio(_) => MediaKind::Audio,
            MediaSample::Video(_) => MediaKind::Video,
        }
    }
}
