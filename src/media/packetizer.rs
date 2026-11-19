use crate::prelude::*;
use std::collections::VecDeque;

use async_trait::async_trait;
use bytes::Bytes;

use crate::media::{
    DynMediaSource, MediaKind, MediaResult, MediaSample, MediaSource, VideoFrame, VideoPixelFormat,
};

/// Payloader splits a frame into RTP payloads
pub trait Payloader: Send + Sync {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes>;
}

/// Packetizer wraps a MediaSource and splits frames into packets
pub struct Packetizer {
    source: Box<DynMediaSource>,
    mtu: usize,
    payloader: Box<dyn Payloader>,
    pending: VecDeque<MediaSample>,
}

impl Packetizer {
    pub fn new(source: Box<DynMediaSource>, mtu: usize, payloader: Box<dyn Payloader>) -> Self {
        Self {
            source,
            mtu,
            payloader,
            pending: VecDeque::new(),
        }
    }

    fn packetize_and_push(&mut self, sample: MediaSample) {
        match sample {
            MediaSample::Video(frame) => {
                let payloads = self.payloader.payload(self.mtu, frame.data.clone());
                let count = payloads.len();
                for (i, payload) in payloads.into_iter().enumerate() {
                    let mut f = frame.clone();
                    f.data = payload;
                    f.is_last_packet = i == count - 1;
                    self.pending.push_back(MediaSample::Video(f));
                }
            }
            MediaSample::Audio(_) => {
                self.pending.push_back(sample);
            }
        }
    }
}

#[async_trait]
impl MediaSource for Packetizer {
    fn id(&self) -> &str {
        self.source.id()
    }

    fn kind(&self) -> MediaKind {
        self.source.kind()
    }

    async fn next_sample(&mut self) -> MediaResult<MediaSample> {
        loop {
            if let Some(sample) = self.pending.pop_front() {
                return Ok(sample);
            }

            let sample = self.source.next_sample().await?;
            self.packetize_and_push(sample);

            if let Some(s) = self.pending.pop_front() {
                return Ok(s);
            }
        }
    }
}

pub struct Vp8Payloader;

impl Payloader for Vp8Payloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        if data.is_empty() {
            return payloads;
        }

        // Max payload size excluding VP8 payload descriptor (min 1 byte)
        let max_payload_size = mtu - 1;

        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = std::cmp::min(remaining, max_payload_size);

            let mut payload = Vec::with_capacity(chunk_size + 1);

            // VP8 Payload Descriptor
            // S bit is 1 for the first packet of the frame
            // RFC 7741 Section 4.2
            let s_bit = if offset == 0 { 0x10 } else { 0x00 };
            payload.push(s_bit);

            payload.extend_from_slice(&data[offset..offset + chunk_size]);
            payloads.push(Bytes::from(payload));

            offset += chunk_size;
        }

        payloads
    }
}

/// VP9 payloader (RFC 9628), flexible mode with a 15-bit Picture ID.
///
/// Descriptor per packet: `[I=1, P=0, L=0, F=1, B, E, V=0, Z=0]` followed by a
/// 15-bit Picture ID. `P` is always 0 (frame claimed self-contained): the
/// [`Payloader`] API carries no keyframe signal, and receivers (Chrome) refuse
/// to start on a delta frame without a prior keyframe, so claiming keyframes
/// is the safe default for raw frame sources. The Picture ID increments once
/// per frame and wraps at 0x7fff.
pub struct Vp9Payloader {
    picture_id: std::sync::atomic::AtomicU16,
}

impl Default for Vp9Payloader {
    fn default() -> Self {
        Self::new()
    }
}

impl Vp9Payloader {
    pub fn new() -> Self {
        use crate::transports::ice::stun::random_u32;
        Self {
            picture_id: std::sync::atomic::AtomicU16::new((random_u32() & 0x7fff) as u16),
        }
    }
}

impl Payloader for Vp9Payloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        if data.is_empty() {
            return payloads;
        }

        // Max payload size excluding the descriptor (1 octet + 2-octet PID).
        let max_payload_size = mtu.saturating_sub(3).max(1);

        // Advance the Picture ID once per frame (15 bits, wraps at 0x7fff).
        let pid = self
            .picture_id
            .fetch_update(
                std::sync::atomic::Ordering::SeqCst,
                std::sync::atomic::Ordering::SeqCst,
                |v| Some((v + 1) & 0x7fff),
            )
            .unwrap_or(0);

        let mut offset = 0;
        let total = data.len();
        while offset < total {
            let remaining = total - offset;
            let chunk_size = remaining.min(max_payload_size);
            let first = offset == 0;
            let last = offset + chunk_size >= total;

            // Descriptor byte 0: I | P(0) | L(0) | F | B | E | V(0) | Z(0)
            let mut b0: u8 = 0x80 | 0x10; // I + F
            if first {
                b0 |= 0x08; // B
            }
            if last {
                b0 |= 0x04; // E
            }

            let mut payload = Vec::with_capacity(chunk_size + 3);
            payload.push(b0);
            // 15-bit Picture ID: M=1 then 8 low bits (RFC 9628 §4.2).
            payload.push(0x80 | ((pid >> 8) as u8));
            payload.push((pid & 0xff) as u8);
            payload.extend_from_slice(&data[offset..offset + chunk_size]);
            payloads.push(Bytes::from(payload));

            offset += chunk_size;
        }

        payloads
    }
}

pub struct SimplePayloader;

impl Payloader for SimplePayloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        let mut payloads = Vec::new();
        let mut offset = 0;
        while offset < data.len() {
            let remaining = data.len() - offset;
            let chunk_size = std::cmp::min(remaining, mtu);
            payloads.push(data.slice(offset..offset + chunk_size));
            offset += chunk_size;
        }
        payloads
    }
}

#[cfg(all(test, feature = "std"))]
mod vp9_tests {
    use super::*;
    use crate::media::Depacketizer;
    use crate::media::depacketizer::{Vp9Depacketizer, parse_vp9_descriptor};
    use crate::media::frame::MediaKind;
    use crate::rtp::{RtpHeader, RtpPacket};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    fn dummy_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234)
    }

    fn vp9_packet(payload: Vec<u8>, seq: u16, ts: u32, marker: bool) -> RtpPacket {
        let mut header = RtpHeader::new(98, seq, ts, 12345);
        header.marker = marker;
        RtpPacket::new(header, payload)
    }

    #[test]
    fn vp9_single_packet_roundtrip() {
        let p = Vp9Payloader::new();
        let frame = Bytes::from(vec![0xAAu8; 500]);
        let payloads = p.payload(1200, frame.clone());
        assert_eq!(payloads.len(), 1);

        let desc = parse_vp9_descriptor(&payloads[0]).unwrap();
        assert!(desc.start_of_frame && desc.end_of_frame);
        assert!(!desc.inter_predicted, "P must be 0 (claimed keyframe)");
        assert!(desc.flexible);
        assert_eq!(payloads[0].len(), desc.header_len + 500);

        let mut dep = Vp9Depacketizer::new();
        let pkt = vp9_packet(payloads[0].to_vec(), 100, 9000, true);
        let samples = dep
            .push(pkt, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(samples.len(), 1);
        match &samples[0] {
            crate::media::MediaSample::Video(f) => {
                assert_eq!(f.data, frame);
                assert!(f.is_last_packet);
            }
            other => panic!("expected video sample, got {:?}", other),
        }
    }

    #[test]
    fn vp9_multi_packet_roundtrip() {
        let p = Vp9Payloader::new();
        let frame = Bytes::from(vec![0x42u8; 3500]);
        let payloads = p.payload(1200, frame.clone());
        assert_eq!(payloads.len(), 3);

        // B on first, E on last, neither in the middle.
        let first = parse_vp9_descriptor(&payloads[0]).unwrap();
        let mid = parse_vp9_descriptor(&payloads[1]).unwrap();
        let last = parse_vp9_descriptor(&payloads[2]).unwrap();
        assert!(first.start_of_frame && !first.end_of_frame);
        assert!(!mid.start_of_frame && !mid.end_of_frame);
        assert!(!last.start_of_frame && last.end_of_frame);

        // Same Picture ID across the frame's packets.
        assert_eq!(first.picture_id, mid.picture_id);
        assert_eq!(mid.picture_id, last.picture_id);

        let mut dep = Vp9Depacketizer::new();
        let mut samples = Vec::new();
        for (i, pl) in payloads.iter().enumerate() {
            let pkt = vp9_packet(pl.to_vec(), 200 + i as u16, 9000, i == 2);
            samples.extend(
                dep.push(pkt, 90000, dummy_addr(), MediaKind::Video)
                    .unwrap(),
            );
        }
        assert_eq!(samples.len(), 1);
        match &samples[0] {
            crate::media::MediaSample::Video(f) => assert_eq!(f.data, frame),
            other => panic!("expected video sample, got {:?}", other),
        }
    }

    #[test]
    fn vp9_picture_id_advances_per_frame() {
        let p = Vp9Payloader::new();
        let pid1 = parse_vp9_descriptor(&p.payload(1200, Bytes::from(vec![1u8; 10]))[0])
            .unwrap()
            .picture_id
            .unwrap();
        let pid2 = parse_vp9_descriptor(&p.payload(1200, Bytes::from(vec![2u8; 10]))[0])
            .unwrap()
            .picture_id
            .unwrap();
        assert_eq!(pid2, (pid1 + 1) & 0x7fff);
    }

    #[test]
    fn vp9_loss_mid_frame_drops_continuations() {
        let p = Vp9Payloader::new();
        let payloads = p.payload(1200, Bytes::from(vec![0x11u8; 3000]));
        assert!(payloads.len() >= 3);

        let mut dep = Vp9Depacketizer::new();
        // Deliver first packet (B), lose the rest, then feed a later frame's
        // first packet with a new timestamp.
        dep.push(
            vp9_packet(payloads[0].to_vec(), 1, 9000, false),
            90000,
            dummy_addr(),
            MediaKind::Video,
        )
        .unwrap();
        // Non-B packet with the SAME timestamp but lost predecessor context is
        // fine only if a frame is in progress; deliver the second packet of the
        // same frame to prove accumulation works, then a B packet at a new ts
        // discards the incomplete frame.
        dep.push(
            vp9_packet(payloads[1].to_vec(), 2, 9000, false),
            90000,
            dummy_addr(),
            MediaKind::Video,
        )
        .unwrap();
        let samples = dep
            .push(
                vp9_packet(payloads[0].to_vec(), 3, 9360, false),
                90000,
                dummy_addr(),
                MediaKind::Video,
            )
            .unwrap();
        assert!(samples.is_empty(), "incomplete frame must not be emitted");

        // Complete the new frame.
        let done = dep
            .push(
                vp9_packet(payloads[1].to_vec(), 4, 9360, true),
                90000,
                dummy_addr(),
                MediaKind::Video,
            )
            .unwrap();
        assert_eq!(done.len(), 1);
    }

    #[test]
    fn vp9_descriptor_parses_chrome_non_flexible_layer_indices() {
        // Chrome sends non-flexible (F=0) with layer indices (L=1) + TL0PICIDX.
        // Descriptor: I|P|L|F=0|B|E + 15-bit PID + TID/U/SID/D + TL0PICIDX.
        let mut payload = vec![0b1110_1100u8]; // I,P,L,F=0,B,E
        payload.extend_from_slice(&[0x81, 0x2C]); // M=1, PID=300
        payload.push(0b000_0_000_0); // TID=0,U=0,SID=0,D=0
        payload.push(0x42); // TL0PICIDX
        payload.extend_from_slice(&[0xDE, 0xAD, 0xBE, 0xEF]);

        let desc = parse_vp9_descriptor(&payload).unwrap();
        assert_eq!(desc.picture_id, Some(300));
        assert!(desc.inter_predicted);
        assert!(desc.start_of_frame && desc.end_of_frame);
        assert_eq!(desc.header_len, 5);
        assert_eq!(&payload[desc.header_len..], &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn vp9_descriptor_parses_flexible_reference_indices() {
        // Flexible delta: I|P|F + PID(15) + 2 chained reference indices.
        let mut payload = vec![0b1101_1000u8]; // I,P,L=0,F,B=0,E=0
        payload.extend_from_slice(&[0x80 | 0x01, 0x2C]); // M=1, PID=300
        payload.push(0b00000011); // P_DIFF=1, N=1
        payload.push(0b00000010); // P_DIFF=2, N=0
        payload.extend_from_slice(&[0xCA, 0xFE]);

        let desc = parse_vp9_descriptor(&payload).unwrap();
        assert_eq!(desc.picture_id, Some(300));
        assert!(desc.inter_predicted && desc.flexible);
        assert_eq!(desc.header_len, 5);
        assert_eq!(&payload[desc.header_len..], &[0xCA, 0xFE]);
    }

    #[test]
    fn vp9_descriptor_parses_ss_data() {
        // V=1, one spatial layer with resolution, G=0: N_S=0,Y=1,G=0.
        let mut payload = vec![0b1000_0010u8]; // I, V
        payload.extend_from_slice(&[0x81, 0x2C]); // PID 300
        payload.push(0b000_1_0_000); // N_S=0, Y=1, G=0
        payload.extend_from_slice(&[0x05, 0x00, 0x02, 0xD0]); // 1280x720
        payload.extend_from_slice(&[0x01, 0x02, 0x03]);

        let desc = parse_vp9_descriptor(&payload).unwrap();
        assert_eq!(desc.header_len, 8); // b0 + PID(2) + SS(1) + WxH(4)
        assert_eq!(&payload[desc.header_len..], &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn vp9_descriptor_rejects_truncated() {
        assert!(parse_vp9_descriptor(&[]).is_none());
        assert!(parse_vp9_descriptor(&[0x80]).is_none()); // I set, PID missing
        assert!(parse_vp9_descriptor(&[0x80, 0x81]).is_none()); // M=1, second byte missing
    }

    // ── H264 packetizer ──
    #[test]
    fn h264_small_nal_is_single_packet() {
        let p = H264Packetizer::new();
        let nal = [0x65u8, 1, 2, 3];
        let frags = p.packetize_from_raw(&nal, 1000);
        assert_eq!(frags.len(), 1);
        let frames = frags.into_frames(640, 480);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].is_last_packet);
        assert_eq!(frames[0].rtp_timestamp, 1000);
        assert_eq!(frames[0].data.to_vec(), nal.to_vec());
    }

    #[test]
    fn h264_large_nal_uses_fu_a() {
        let p = H264Packetizer::new();
        let mut nal = vec![0x65u8];
        nal.extend(std::iter::repeat(0xAB).take(4000));
        let frags = p.packetize(&nal);
        assert!(frags.len() > 1, "must fragment");
        let frames = frags.into_frames(1280, 720);
        for f in &frames {
            assert_eq!(f.data[0] & 0x1F, 28);
        }
        assert_eq!(frames[0].data[1] & 0x80, 0x80);
        let last = frames.last().unwrap();
        assert_eq!(last.data[1] & 0x40, 0x40);
        assert!(last.is_last_packet);
        assert!(!frames[0].is_last_packet);
    }

    #[test]
    fn h264_start_code_is_stripped() {
        let p = H264Packetizer::new();
        let nal = vec![0, 0, 0, 1, 0x65, 9, 9];
        let frames = p.packetize(&nal).into_frames(1, 1);
        assert_eq!(frames[0].data.to_vec(), vec![0x65, 9, 9]);
        let nal3 = vec![0, 0, 1, 0x41, 7];
        let frames3 = p.packetize(&nal3).into_frames(1, 1);
        assert_eq!(frames3[0].data.to_vec(), vec![0x41, 7]);
    }

    #[test]
    fn h264_timestamp_advances() {
        let mut p = H264Packetizer::new();
        assert_eq!(p.timestamp(), 0);
        p.advance();
        assert_eq!(p.timestamp(), H264_TS_PER_FRAME);
        let nal = [0x41u8, 1];
        let frames = p.packetize(&nal).into_frames(1, 1);
        assert_eq!(frames[0].rtp_timestamp, H264_TS_PER_FRAME);
    }

    #[test]
    fn h264_empty_input() {
        let p = H264Packetizer::new();
        assert!(p.packetize(&[]).is_empty());
        assert_eq!(p.packetize(&[0, 0, 1]).len(), 1);
    }
}

// ── H.264 (RFC 6184) ──────────────────────────────────────────────────────
// Single NAL below MTU, FU-A above. STAP-A aggregation is not implemented.

const H264_FU_A_INDICATOR: u8 = 0x1C;
const H264_NAL_TYPE_MASK: u8 = 0x1F;
const H264_FU_A_START: u8 = 0x80;
const H264_FU_A_END: u8 = 0x40;
const H264_MTU: usize = 1200;

/// 90000 / 25 fps timestamp step.
pub const H264_TS_PER_FRAME: u32 = 3600;

/// FU-A fragmentation into RTP payloads at the given MTU.
pub struct H264Payloader;

impl Payloader for H264Payloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        if data.is_empty() {
            return Vec::new();
        }
        let nal_type = data[0] & H264_NAL_TYPE_MASK;
        let nri = data[0] & 0x60;
        let payload = &data[1..];
        let max_frag = mtu.saturating_sub(2).max(1);
        if payload.len() < mtu {
            vec![data]
        } else {
            let mut fragments = Vec::new();
            let total = payload.len();
            let mut offset = 0;
            while offset < total {
                let remaining = total - offset;
                let frag_size = remaining.min(max_frag);
                let is_start = offset == 0;
                let is_end = offset + frag_size >= total;
                let fu_indicator = nri | H264_FU_A_INDICATOR;
                let mut fu_header = nal_type;
                if is_start {
                    fu_header |= H264_FU_A_START;
                }
                if is_end {
                    fu_header |= H264_FU_A_END;
                }
                let mut fragment = Vec::with_capacity(2 + frag_size);
                fragment.push(fu_indicator);
                fragment.push(fu_header);
                fragment.extend_from_slice(&payload[offset..offset + frag_size]);
                fragments.push(Bytes::from(fragment));
                offset += frag_size;
            }
            fragments
        }
    }
}

/// Tracks the 90 kHz RTP clock; NALs (Annex-B or raw) → fragment lists.
pub struct H264Packetizer {
    timestamp: u32,
}

impl Default for H264Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

impl H264Packetizer {
    pub fn new() -> Self {
        Self { timestamp: 0 }
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    pub fn advance(&mut self) {
        self.timestamp = self.timestamp.wrapping_add(H264_TS_PER_FRAME);
    }

    pub fn packetize_from_raw(&self, nal_data: &[u8], ts: u32) -> H264Fragments {
        if nal_data.is_empty() {
            return H264Fragments::empty();
        }
        let payloads = H264Payloader.payload(H264_MTU, Bytes::copy_from_slice(nal_data));
        H264Fragments {
            data: payloads.into_iter().map(|b| b.to_vec()).collect(),
            timestamp: ts,
        }
    }

    /// Packetize one Annex-B NAL (3/4-byte start code stripped if present).
    pub fn packetize(&self, nal: &[u8]) -> H264Fragments {
        let start_code =
            if nal.len() > 4 && nal[0] == 0 && nal[1] == 0 && nal[2] == 0 && nal[3] == 1 {
                4
            } else if nal.len() > 3 && nal[0] == 0 && nal[1] == 0 && nal[2] == 1 {
                3
            } else {
                0
            };
        self.packetize_from_raw(&nal[start_code..], self.timestamp)
    }
}

/// One access unit's RTP payloads sharing one timestamp (last = marker).
pub struct H264Fragments {
    data: Vec<Vec<u8>>,
    timestamp: u32,
}

impl H264Fragments {
    fn empty() -> Self {
        Self {
            data: Vec::new(),
            timestamp: 0,
        }
    }

    /// Fragment payloads, in transmission order.
    pub fn payloads(&self) -> &[Vec<u8>] {
        &self.data
    }

    /// Build from raw fragment payloads sharing one timestamp.
    pub fn from_payloads(data: Vec<Vec<u8>>, timestamp: u32) -> Self {
        Self { data, timestamp }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn into_frames(self, width: u16, height: u16) -> Vec<VideoFrame> {
        let count = self.data.len();
        let ts = self.timestamp;
        self.data
            .into_iter()
            .enumerate()
            .map(|(i, data)| VideoFrame {
                data: Bytes::from(data),
                width,
                height,
                format: VideoPixelFormat::Unspecified,
                is_last_packet: i + 1 == count,
                rtp_timestamp: ts,
                ..Default::default()
            })
            .collect()
    }
}

// ── H.265 / HEVC (RFC 7798) ───────────────────────────────────────────────
// Single NAL below MTU, FU (type 49) above. AP/PACI are not produced.

const H265_FU_TYPE: u8 = 49;
const H265_MTU: usize = 1200;

/// 90000 / 25 fps timestamp step.
pub const H265_TS_PER_FRAME: u32 = 3600;

/// FU fragmentation into RTP payloads at the given MTU (RFC 7798 §4.4.3).
///
/// The 2-byte NAL header is preserved in every fragment's PayloadHdr with the
/// Type field set to 49; the FU header carries S/E plus the original NAL type.
/// No DONL is emitted (`sprop-max-don-diff=0`, the WebRTC default).
pub struct H265Payloader;

impl Payloader for H265Payloader {
    fn payload(&self, mtu: usize, data: Bytes) -> Vec<Bytes> {
        if data.len() < 2 {
            return Vec::new();
        }
        if data.len() <= mtu {
            return vec![data];
        }
        let nal_type = (data[0] >> 1) & 0x3F;
        let payload_hdr0 = (data[0] & 0x81) | (H265_FU_TYPE << 1);
        let payload_hdr1 = data[1];
        let max_frag = mtu.saturating_sub(3).max(1);
        let mut fragments = Vec::new();
        let mut offset = 2; // skip the 2-byte NAL header
        while offset < data.len() {
            let remaining = data.len() - offset;
            let frag_size = remaining.min(max_frag);
            let is_start = offset == 2;
            let is_end = offset + frag_size >= data.len();
            let mut fu = nal_type;
            if is_start {
                fu |= 0x80;
            }
            if is_end {
                fu |= 0x40;
            }
            let mut fragment = Vec::with_capacity(3 + frag_size);
            fragment.push(payload_hdr0);
            fragment.push(payload_hdr1);
            fragment.push(fu);
            fragment.extend_from_slice(&data[offset..offset + frag_size]);
            fragments.push(Bytes::from(fragment));
            offset += frag_size;
        }
        fragments
    }
}

/// Tracks the 90 kHz RTP clock; NALs (Annex-B or raw) → fragment lists.
pub struct H265Packetizer {
    timestamp: u32,
}

impl Default for H265Packetizer {
    fn default() -> Self {
        Self::new()
    }
}

impl H265Packetizer {
    pub fn new() -> Self {
        Self { timestamp: 0 }
    }

    pub fn timestamp(&self) -> u32 {
        self.timestamp
    }

    pub fn advance(&mut self) {
        self.timestamp = self.timestamp.wrapping_add(H265_TS_PER_FRAME);
    }

    pub fn packetize_from_raw(&self, nal_data: &[u8], ts: u32) -> H265Fragments {
        if nal_data.len() < 2 {
            return H265Fragments::empty();
        }
        let payloads = H265Payloader.payload(H265_MTU, Bytes::copy_from_slice(nal_data));
        H265Fragments {
            data: payloads.into_iter().map(|b| b.to_vec()).collect(),
            timestamp: ts,
        }
    }

    /// Packetize one Annex-B NAL (3/4-byte start code stripped if present).
    pub fn packetize(&self, nal: &[u8]) -> H265Fragments {
        let start_code =
            if nal.len() > 4 && nal[0] == 0 && nal[1] == 0 && nal[2] == 0 && nal[3] == 1 {
                4
            } else if nal.len() > 3 && nal[0] == 0 && nal[1] == 0 && nal[2] == 1 {
                3
            } else {
                0
            };
        self.packetize_from_raw(&nal[start_code..], self.timestamp)
    }
}

/// One access unit's RTP payloads sharing one timestamp (last = marker).
pub struct H265Fragments {
    data: Vec<Vec<u8>>,
    timestamp: u32,
}

impl H265Fragments {
    fn empty() -> Self {
        Self {
            data: Vec::new(),
            timestamp: 0,
        }
    }

    /// Fragment payloads, in transmission order.
    pub fn payloads(&self) -> &[Vec<u8>] {
        &self.data
    }

    /// Build from raw fragment payloads sharing one timestamp.
    pub fn from_payloads(data: Vec<Vec<u8>>, timestamp: u32) -> Self {
        Self { data, timestamp }
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn into_frames(self, width: u16, height: u16) -> Vec<VideoFrame> {
        let count = self.data.len();
        let ts = self.timestamp;
        self.data
            .into_iter()
            .enumerate()
            .map(|(i, data)| VideoFrame {
                data: Bytes::from(data),
                width,
                height,
                format: VideoPixelFormat::Unspecified,
                is_last_packet: i + 1 == count,
                rtp_timestamp: ts,
                ..Default::default()
            })
            .collect()
    }
}

#[cfg(all(test, feature = "std"))]
mod h265_tests {
    use super::*;

    fn nal(nal_type: u8, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        // F=0, Type=nal_type, LayerId=0, TID=1
        v[0] = (nal_type & 0x3F) << 1;
        v[1] = 0x01;
        for (i, b) in v.iter_mut().enumerate().skip(2) {
            *b = (i % 251) as u8;
        }
        v
    }

    #[test]
    fn h265_small_nal_is_single_packet() {
        let data = Bytes::from(nal(32, 100)); // VPS
        let payloads = H265Payloader.payload(1200, data.clone());
        assert_eq!(payloads.len(), 1);
        assert_eq!(payloads[0], data);
    }

    #[test]
    fn h265_large_nal_uses_fu() {
        let original = nal(19, 4000); // IDR_W_RADL
        let payloads = H265Payloader.payload(1200, Bytes::from(original.clone()));
        assert!(payloads.len() > 1, "must fragment 4000B at MTU 1200");
        let last = payloads.len() - 1;
        let mut rebuilt = Vec::new();
        for (i, p) in payloads.iter().enumerate() {
            assert_eq!((p[0] >> 1) & 0x3F, 49, "FU type");
            assert_eq!(p[0] & 0x81, original[0] & 0x81, "F + LayerId high bit");
            assert_eq!(p[1], original[1], "LayerId low bits + TID");
            let fu = p[2];
            assert_eq!(fu & 0x3F, 19, "original NAL type in FU header");
            assert_eq!(fu & 0x80 != 0, i == 0, "S bit only on the first");
            assert_eq!(fu & 0x40 != 0, i == last, "E bit only on the last");
            if i == 0 {
                rebuilt.push((p[0] & 0x81) | ((fu & 0x3F) << 1));
                rebuilt.push(p[1]);
            }
            rebuilt.extend_from_slice(&p[3..]);
            assert!(p.len() <= 1200, "fragment must fit the MTU");
        }
        assert_eq!(rebuilt, original, "reassembled NAL must be byte-identical");
    }

    #[test]
    fn h265_start_code_is_stripped() {
        let mut annex_b = vec![0, 0, 0, 1];
        annex_b.extend_from_slice(&nal(32, 50));
        let packetizer = H265Packetizer::new();
        let frags = packetizer.packetize(&annex_b);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags.payloads()[0][0] & 0xFE, (32 << 1) as u8 & 0xFE);
    }

    #[test]
    fn h265_timestamp_advances() {
        let mut p = H265Packetizer::new();
        assert_eq!(p.timestamp(), 0);
        let f0 = p.packetize_from_raw(&nal(32, 10), p.timestamp());
        assert_eq!(f0.payloads().len(), 1);
        p.advance();
        assert_eq!(p.timestamp(), H265_TS_PER_FRAME);
    }

    #[test]
    fn h265_empty_input() {
        assert!(H265Payloader.payload(1200, Bytes::new()).is_empty());
        assert!(H265Packetizer::new().packetize(&[]).is_empty());
    }
}
