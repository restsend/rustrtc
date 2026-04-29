use crate::media::MediaResult;
use crate::media::frame::{MediaKind, MediaSample, VideoFrame, VideoPixelFormat};
use crate::rtp::RtpPacket;
use bytes::Bytes;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

pub trait Depacketizer: Send + Sync {
    fn push(
        &mut self,
        packet: RtpPacket,
        clock_rate: u32,
        addr: SocketAddr,
        kind: MediaKind,
    ) -> MediaResult<Vec<MediaSample>>;

    fn drop_count(&self) -> u64 {
        0
    }
}

pub struct PassThroughDepacketizer;

impl Depacketizer for PassThroughDepacketizer {
    fn push(
        &mut self,
        packet: RtpPacket,
        clock_rate: u32,
        addr: SocketAddr,
        kind: MediaKind,
    ) -> MediaResult<Vec<MediaSample>> {
        Ok(vec![MediaSample::from_rtp_packet(
            packet, kind, clock_rate, addr,
        )])
    }
}

/// H.264 Depacketizer (RFC 6184)
/// Handles Single NAL Unit, STAP-A, and FU-A.
pub struct H264Depacketizer {
    // Buffer for reassembling FU-A packets
    fua_buffer: Vec<u8>,
    // Expected sequence number for the next FU-A packet
    last_seq: Option<u16>,
    // Timestamp for the current frame being reassembled
    current_timestamp: u32,
    // Counter of frames dropped due to depacketization errors (FU-A/STAP-A corruption)
    drop_count: Arc<AtomicU64>,
}

impl H264Depacketizer {
    pub fn new() -> Self {
        Self {
            fua_buffer: Vec::new(),
            last_seq: None,
            current_timestamp: 0,
            drop_count: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Returns a shared reference to the atomic drop counter.
    pub fn drop_counter(&self) -> Arc<AtomicU64> {
        self.drop_count.clone()
    }
}

impl Depacketizer for H264Depacketizer {
    fn drop_count(&self) -> u64 {
        self.drop_count.load(Ordering::Relaxed)
    }

    fn push(
        &mut self,
        packet: RtpPacket,
        clock_rate: u32,
        addr: SocketAddr,
        kind: MediaKind,
    ) -> MediaResult<Vec<MediaSample>> {
        if kind == MediaKind::Audio {
            return Ok(vec![MediaSample::from_rtp_packet(
                packet, kind, clock_rate, addr,
            )]);
        }

        let raw_packet = packet.clone();
        let payload = packet.payload;
        if payload.is_empty() {
            // Treat empty payload as a keep-alive/padding frame and pass it through
            return Ok(vec![MediaSample::from_rtp_packet(
                raw_packet, kind, clock_rate, addr,
            )]);
        }

        let header = payload[0];
        let nal_type = header & 0x1F;
        let mut samples = Vec::new();

        let create_video_sample = |data: Bytes, timestamp: u32, is_last: bool, pkt: &RtpPacket| {
            MediaSample::Video(VideoFrame {
                rtp_timestamp: timestamp,
                width: 0,
                height: 0,
                format: VideoPixelFormat::Unspecified,
                rotation_deg: 0,
                is_last_packet: is_last,
                data,
                header_extension: pkt.header.extension.clone(),
                csrcs: pkt.header.csrcs.clone(),
                sequence_number: Some(pkt.header.sequence_number),
                payload_type: Some(pkt.header.payload_type),
                source_addr: Some(addr),
                raw_packet: Some(pkt.clone()),
            })
        };

        match nal_type {
            // STAP-A (Single-Time Aggregation Packet type A)
            24 => {
                let mut offset = 1; // Skip STAP-A header
                let data = Bytes::from(payload);
                let len = data.len();
                let packet_marker = raw_packet.header.marker;

                while offset + 2 < len {
                    let nal_len = u16::from_be_bytes([data[offset], data[offset + 1]]) as usize;
                    offset += 2;

                    if offset + nal_len > len {
                        tracing::warn!("STAP-A NAL length exceeds packet size");
                        self.drop_count.fetch_add(1, Ordering::Relaxed);
                        break;
                    }

                    let nal_data = data.slice(offset..offset + nal_len);
                    offset += nal_len;

                    let is_last = (offset == len) && packet_marker;

                    samples.push(create_video_sample(
                        nal_data,
                        raw_packet.header.timestamp,
                        is_last,
                        &raw_packet,
                    ));
                }
            }
            // FU-A (Fragmentation Unit type A)
            28 => {
                if payload.len() < 2 {
                    return Ok(vec![]);
                }

                let fu_header = payload[1];
                let s_bit = (fu_header & 0x80) != 0;
                let e_bit = (fu_header & 0x40) != 0;
                let original_nal_type = fu_header & 0x1F;

                if s_bit {
                    // Start
                    let nri = header & 0x60;
                    let reconstructed_header = nri | original_nal_type;

                    self.fua_buffer.clear();
                    self.fua_buffer.push(reconstructed_header);
                    self.fua_buffer.extend_from_slice(&payload[2..]);

                    self.current_timestamp = raw_packet.header.timestamp;
                    self.last_seq = Some(raw_packet.header.sequence_number);
                } else {
                    // Continuation or End
                    if let Some(last_seq) = self.last_seq {
                        let expected = last_seq.wrapping_add(1);
                        if raw_packet.header.sequence_number != expected {
                            tracing::warn!(
                                "FU-A Sequence mismatch: expected {}, got {}",
                                expected,
                                raw_packet.header.sequence_number
                            );
                            self.drop_count.fetch_add(1, Ordering::Relaxed);
                            self.fua_buffer.clear();
                            self.last_seq = None;
                            return Ok(vec![]);
                        }
                    } else {
                        return Ok(vec![]); // Missing start
                    }

                    if raw_packet.header.timestamp != self.current_timestamp {
                        tracing::warn!("FU-A timestamp mismatch inside frame");
                        self.drop_count.fetch_add(1, Ordering::Relaxed);
                        self.fua_buffer.clear();
                        self.last_seq = None;
                        return Ok(vec![]);
                    }

                    self.fua_buffer.extend_from_slice(&payload[2..]);
                    self.last_seq = Some(raw_packet.header.sequence_number);

                    if e_bit {
                        // End of fragment, emit frame
                        let data = Bytes::from(self.fua_buffer.clone());
                        samples.push(create_video_sample(
                            data,
                            self.current_timestamp,
                            raw_packet.header.marker,
                            &raw_packet,
                        ));

                        self.fua_buffer.clear();
                        self.last_seq = None;
                    }
                }
            }
            // Single NAL unit (1-23)
            1..=23 => {
                let data = Bytes::from(payload);
                samples.push(create_video_sample(
                    data,
                    raw_packet.header.timestamp,
                    raw_packet.header.marker,
                    &raw_packet,
                ));
            }
            // Unknown or unsupported type headers (fallback)
            _ => {
                let data = Bytes::from(payload);
                samples.push(create_video_sample(
                    data,
                    raw_packet.header.timestamp,
                    raw_packet.header.marker,
                    &raw_packet,
                ));
            }
        }

        Ok(samples)
    }
}

pub trait DepacketizerFactory: std::fmt::Debug + Send + Sync {
    fn create(&self, kind: MediaKind) -> Box<dyn Depacketizer>;
}

#[derive(Debug, Default)]
pub struct DefaultDepacketizerFactory;

impl DepacketizerFactory for DefaultDepacketizerFactory {
    fn create(&self, kind: MediaKind) -> Box<dyn Depacketizer> {
        match kind {
            MediaKind::Video => Box::new(H264Depacketizer::new()),
            _ => Box::new(PassThroughDepacketizer),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpHeader;
    use std::net::{IpAddr, Ipv4Addr};

    fn create_packet(
        payload: Vec<u8>,
        sequence_number: u16,
        timestamp: u32,
        marker: bool,
    ) -> RtpPacket {
        let mut header = RtpHeader::new(96, sequence_number, timestamp, 12345);
        header.marker = marker;
        RtpPacket::new(header, payload)
    }

    fn dummy_addr() -> SocketAddr {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234)
    }

    #[test]
    fn test_single_nal() {
        let mut depacketizer = H264Depacketizer::new();
        let payload = vec![0x65, 0x01, 0x02, 0x03]; // IDR slice (type 5)
        let packet = create_packet(payload.clone(), 1, 100, true);

        let frames = depacketizer
            .push(packet, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            MediaSample::Video(v) => {
                assert_eq!(v.data, Bytes::from(payload));
                assert_eq!(v.rtp_timestamp, 100);
                assert!(v.is_last_packet);
            }
            _ => panic!("Expected Video sample"),
        }
    }

    #[test]
    fn test_stap_a() {
        let mut depacketizer = H264Depacketizer::new();
        // STAP-A header (24)
        let mut payload = vec![24];

        let nal1 = vec![0x67, 0x10]; // SPS
        let len1 = (nal1.len() as u16).to_be_bytes();
        payload.extend_from_slice(&len1);
        payload.extend_from_slice(&nal1);

        let nal2 = vec![0x68, 0x20, 0x30]; // PPS
        let len2 = (nal2.len() as u16).to_be_bytes();
        payload.extend_from_slice(&len2);
        payload.extend_from_slice(&nal2);

        let packet = create_packet(payload, 2, 200, true); // Marker true
        let frames = depacketizer
            .push(packet, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();

        assert_eq!(frames.len(), 2);

        match &frames[0] {
            MediaSample::Video(v) => {
                assert_eq!(v.data, Bytes::from(nal1));
                assert_eq!(v.rtp_timestamp, 200);
                assert_eq!(v.is_last_packet, false); // Not last in packet
            }
            _ => panic!("Expected Video sample"),
        }

        match &frames[1] {
            MediaSample::Video(v) => {
                assert_eq!(v.data, Bytes::from(nal2));
                assert_eq!(v.rtp_timestamp, 200);
                assert_eq!(v.is_last_packet, true); // Last in packet inherits marker
            }
            _ => panic!("Expected Video sample"),
        }
    }

    #[test]
    fn test_fu_a() {
        let mut depacketizer = H264Depacketizer::new();
        let timestamp = 300;

        // Start: FU Indicator 0x7C (Type 28), FU Header 0x85 (S=1, Type=5)
        let packet1 = create_packet(vec![0x7C, 0x85, 0x01, 0x02], 10, timestamp, false);
        let frames1 = depacketizer
            .push(packet1, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(frames1.len(), 0);

        // Middle
        let packet2 = create_packet(vec![0x7C, 0x05, 0x03], 11, timestamp, false);
        let frames2 = depacketizer
            .push(packet2, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(frames2.len(), 0);

        // End: FU Header 0x45 (E=1, Type=5)
        let packet3 = create_packet(vec![0x7C, 0x45, 0x04], 12, timestamp, true);
        let frames3 = depacketizer
            .push(packet3, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(frames3.len(), 1);

        let expected_nal = vec![0x65, 0x01, 0x02, 0x03, 0x04];
        match &frames3[0] {
            MediaSample::Video(v) => {
                assert_eq!(v.data, Bytes::from(expected_nal));
                assert_eq!(v.rtp_timestamp, timestamp);
                assert!(v.is_last_packet);
            }
            _ => panic!("Expected Video sample"),
        }
    }

    #[test]
    fn test_passthrough() {
        let mut depacketizer = PassThroughDepacketizer;
        let payload = vec![0x01, 0x02, 0x03];
        let packet = create_packet(payload.clone(), 1, 100, true);

        let frames = depacketizer
            .push(packet, 48000, dummy_addr(), MediaKind::Audio)
            .unwrap();
        assert_eq!(frames.len(), 1);
        match &frames[0] {
            MediaSample::Audio(a) => {
                assert_eq!(a.data, Bytes::from(payload));
                assert_eq!(a.clock_rate, 48000);
            }
            _ => panic!("Expected Audio sample"),
        }
    }

    #[test]
    fn test_default_factory() {
        let factory = DefaultDepacketizerFactory;

        // Video should produce H264Depacketizer
        // Verify it's not passthrough by sending a partitioned H264 packet (FU-A Start).
        let mut depacketizer = factory.create(MediaKind::Video);
        let timestamp = 12345;
        // FU-A Start: Indicator 0x7C (Avg seq), Header 0x85 (S=1)
        let packet1 = create_packet(vec![0x7C, 0x85, 0x01], 10, timestamp, false);
        let res = depacketizer
            .push(packet1, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(res.len(), 0, "H264 depacketizer should buffer FU-A start");

        // Audio should produce PassThrough
        let mut depacketizer = factory.create(MediaKind::Audio);
        let packet2 = create_packet(vec![0x01, 0x02], 20, timestamp, true);
        let res = depacketizer
            .push(packet2, 48000, dummy_addr(), MediaKind::Audio)
            .unwrap();
        assert_eq!(res.len(), 1, "PassThrough should emit immediately");
    }

    #[test]
    fn test_fu_a_loss() {
        let mut depacketizer = H264Depacketizer::new();
        let timestamp = 44444;

        // Start (Seq 10)
        let packet1 = create_packet(vec![0x7C, 0x85, 0x01], 10, timestamp, false);
        let _ = depacketizer
            .push(packet1, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();

        // Skip Middle (Seq 11 missing)

        // End (Seq 12)
        let packet3 = create_packet(vec![0x7C, 0x45, 0x02], 12, timestamp, true);
        let frames = depacketizer
            .push(packet3, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();

        assert_eq!(
            frames.len(),
            0,
            "Should drop frame if sequence gap detected"
        );
    }

    #[test]
    fn test_drop_count_fu_a_loss() {
        let mut depacketizer = H264Depacketizer::new();
        assert_eq!(depacketizer.drop_count(), 0, "Initial drop count should be 0");

        let timestamp = 55555;

        // Start (Seq 10)
        let packet1 = create_packet(vec![0x7C, 0x85, 0x01], 10, timestamp, false);
        let _ = depacketizer
            .push(packet1, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(depacketizer.drop_count(), 0, "FU-A start should not increment drop count");

        // Skip Middle (Seq 11 missing) - send End (Seq 12)
        let packet3 = create_packet(vec![0x7C, 0x45, 0x02], 12, timestamp, true);
        let _ = depacketizer
            .push(packet3, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(
            depacketizer.drop_count(),
            1,
            "FU-A sequence mismatch should increment drop count"
        );

        // Second loss should increment again
        let packet4 = create_packet(vec![0x7C, 0x85, 0x03], 20, timestamp + 1, false);
        let _ = depacketizer
            .push(packet4, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(depacketizer.drop_count(), 1, "FU-A start should not count");

        let packet5 = create_packet(vec![0x7C, 0x45, 0x04], 22, timestamp + 1, true);
        let _ = depacketizer
            .push(packet5, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(
            depacketizer.drop_count(),
            2,
            "Second FU-A loss should increment again"
        );
    }

    #[test]
    fn test_drop_count_stap_a_corrupt() {
        let mut depacketizer = H264Depacketizer::new();
        assert_eq!(depacketizer.drop_count(), 0, "Initial drop count should be 0");

        // STAP-A with malformed NAL length (claims size > packet)
        // STAP-A header (nal_type=24), then NAL length of 0xFFFF (65535 bytes), but only 3 bytes remain
        let payload = vec![
            24,        // STAP-A header
            0xFF, 0xFF, // NAL length = 65535 (impossible, packet is only 3 bytes)
            0x01,      // barely enough for the length field but no room for NAL data
        ];
        let packet = create_packet(payload, 1, 100, true);
        let _ = depacketizer
            .push(packet, 90000, dummy_addr(), MediaKind::Video)
            .unwrap();
        assert_eq!(
            depacketizer.drop_count(),
            1,
            "STAP-A NAL length exceed should increment drop count"
        );
    }

    #[test]
    fn test_drop_count_passthrough_audio() {
        // Audio packets on H264 depacketizer should be unaffected
        let mut depacketizer = H264Depacketizer::new();
        let packet = create_packet(vec![0x01, 0x02], 1, 100, true);
        let _ = depacketizer
            .push(packet, 48000, dummy_addr(), MediaKind::Audio)
            .unwrap();
        assert_eq!(
            depacketizer.drop_count(),
            0,
            "Audio packets should not affect drop count"
        );
    }

    #[test]
    fn test_drop_count_via_trait() {
        let mut depacketizer = H264Depacketizer::new();
        // Verify drop_count works through the trait
        let d: &mut dyn Depacketizer = &mut depacketizer;
        assert_eq!(d.drop_count(), 0, "Trait method should return 0 initially");

        let timestamp = 66666;
        // FU-A start
        let p1 = create_packet(vec![0x7C, 0x85, 0x01], 10, timestamp, false);
        let _ = d.push(p1, 90000, dummy_addr(), MediaKind::Video).unwrap();

        // FU-A end with seq gap (11 -> 13)
        let p2 = create_packet(vec![0x7C, 0x45, 0x02], 13, timestamp, true);
        let _ = d.push(p2, 90000, dummy_addr(), MediaKind::Video).unwrap();

        assert_eq!(d.drop_count(), 1, "Trait method should reflect incremented count");
    }
}
