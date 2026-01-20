use bytes::Bytes;
use serde::{Deserialize, Serialize};

use crate::rtp::{RtpHeader, RtpHeaderExtension, RtpPacket};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
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
    pub rtp_timestamp: u32,
    pub clock_rate: u32,
    pub data: Bytes,
    pub sequence_number: Option<u16>,
    pub payload_type: Option<u8>,
    pub marker: bool,
}

impl Default for AudioFrame {
    fn default() -> Self {
        Self {
            rtp_timestamp: 0,
            clock_rate: 0,
            data: Bytes::new(),
            sequence_number: None,
            payload_type: None,
            marker: false,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoFrame {
    pub rtp_timestamp: u32,
    pub width: u16,
    pub height: u16,
    pub format: VideoPixelFormat,
    pub rotation_deg: u16,
    pub is_last_packet: bool,
    pub data: Bytes,
    pub header_extension: Option<RtpHeaderExtension>,
    pub csrcs: Vec<u32>,
    pub sequence_number: Option<u16>,
    pub payload_type: Option<u8>,
}

impl Default for VideoFrame {
    fn default() -> Self {
        Self {
            rtp_timestamp: 0,
            width: 0,
            height: 0,
            format: VideoPixelFormat::default(),
            rotation_deg: 0,
            is_last_packet: false,
            data: Bytes::new(),
            header_extension: None,
            csrcs: Vec::new(),
            sequence_number: None,
            payload_type: None,
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

    pub fn into_rtp_packet(
        self,
        ssrc: u32,
        default_payload_type: u8,
        sequence_number: &mut u16,
    ) -> RtpPacket {
        let (payload, marker, rtp_timestamp, csrcs, frame_seq, frame_pt, extension) = match self {
            MediaSample::Audio(f) => (
                f.data,
                f.marker,
                f.rtp_timestamp,
                Vec::new(),
                f.sequence_number,
                f.payload_type,
                None,
            ),
            MediaSample::Video(f) => (
                f.data,
                f.is_last_packet,
                f.rtp_timestamp,
                f.csrcs,
                f.sequence_number,
                f.payload_type,
                f.header_extension,
            ),
        };

        let seq = frame_seq.unwrap_or(*sequence_number);
        if frame_seq.is_none() {
            *sequence_number = sequence_number.wrapping_add(1);
        }

        let pt = frame_pt.unwrap_or(default_payload_type);
        let mut header = RtpHeader::new(pt, seq, rtp_timestamp, ssrc);
        header.marker = marker;
        header.csrcs = csrcs;
        header.extension = extension;

        RtpPacket::new(header, payload.to_vec())
    }

    pub fn from_rtp_packet(packet: RtpPacket, kind: MediaKind, clock_rate: u32) -> Self {
        let data = bytes::Bytes::from(packet.payload);

        match kind {
            MediaKind::Audio => MediaSample::Audio(AudioFrame {
                rtp_timestamp: packet.header.timestamp,
                clock_rate,
                data,
                sequence_number: Some(packet.header.sequence_number),
                payload_type: Some(packet.header.payload_type),
                marker: packet.header.marker,
            }),
            MediaKind::Video => MediaSample::Video(VideoFrame {
                rtp_timestamp: packet.header.timestamp,
                width: 0,
                height: 0,
                format: VideoPixelFormat::Unspecified,
                rotation_deg: 0,
                is_last_packet: packet.header.marker,
                data,
                header_extension: packet.header.extension,
                csrcs: packet.header.csrcs,
                sequence_number: Some(packet.header.sequence_number),
                payload_type: Some(packet.header.payload_type),
            }),
        }
    }
}
