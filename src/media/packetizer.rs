use crate::prelude::*;
use std::collections::VecDeque;

use async_trait::async_trait;
use bytes::Bytes;

use crate::media::{DynMediaSource, MediaKind, MediaResult, MediaSample, MediaSource};

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

#[cfg(test)]
mod vp9_tests {
    use super::*;
    use crate::media::Depacketizer;
    use crate::media::depacketizer::{Vp9Depacketizer, parse_vp9_descriptor};
    use crate::rtp::{RtpHeader, RtpPacket};
    use crate::media::frame::MediaKind;
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
        let samples = dep.push(pkt, 90000, dummy_addr(), MediaKind::Video).unwrap();
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
            samples.extend(dep.push(pkt, 90000, dummy_addr(), MediaKind::Video).unwrap());
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
}
