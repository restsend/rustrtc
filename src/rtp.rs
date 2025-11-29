use crate::errors::{RtpError, RtpResult};
use serde::{Deserialize, Serialize};

const RTP_VERSION: u8 = 2;
pub const RTCP_SR: u8 = 200;
pub const RTCP_RR: u8 = 201;
pub const RTCP_SDES: u8 = 202;
pub const RTCP_BYE: u8 = 203;
pub const RTCP_RTPFB: u8 = 205;
pub const RTCP_PSFB: u8 = 206;

pub const RTCP_RTPFB_NACK: u8 = 1;
pub const RTCP_RTPFB_TWCC: u8 = 15;

pub const RTCP_PSFB_PLI: u8 = 1;
pub const RTCP_PSFB_FIR: u8 = 4;
pub const RTCP_PSFB_APP: u8 = 15; // REMB lives under APP-format payload feedback

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RtpHeaderExtension {
    pub profile: u16,
    pub data: Vec<u8>,
}

impl RtpHeaderExtension {
    pub fn new(profile: u16, data: Vec<u8>) -> Self {
        Self { profile, data }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpHeader {
    pub marker: bool,
    pub payload_type: u8,
    pub sequence_number: u16,
    pub timestamp: u32,
    pub ssrc: u32,
    pub csrcs: Vec<u32>,
    pub extension: Option<RtpHeaderExtension>,
}

impl RtpHeader {
    pub fn new(payload_type: u8, sequence_number: u16, timestamp: u32, ssrc: u32) -> Self {
        Self {
            marker: false,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrcs: Vec::new(),
            extension: None,
        }
    }

    fn validate(&self) -> RtpResult<()> {
        if self.csrcs.len() > 15 {
            return Err(RtpError::InvalidHeader("too many CSRC entries"));
        }
        if let Some(ext) = &self.extension
            && ext.data.len() % 4 != 0
        {
            return Err(RtpError::InvalidHeader(
                "header extension payload must be 32-bit aligned",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RtpPacket {
    pub header: RtpHeader,
    pub payload: Vec<u8>,
    pub padding_len: u8,
}

impl RtpPacket {
    pub fn new(header: RtpHeader, payload: Vec<u8>) -> Self {
        Self {
            header,
            payload,
            padding_len: 0,
        }
    }

    pub fn parse(raw: &[u8]) -> RtpResult<Self> {
        if raw.len() < 12 {
            return Err(RtpError::PacketTooShort);
        }
        let b0 = raw[0];
        let b1 = raw[1];
        let version = b0 >> 6;
        if version != RTP_VERSION {
            return Err(RtpError::UnsupportedVersion(version));
        }
        let padding = (b0 & 0x20) != 0;
        let extension = (b0 & 0x10) != 0;
        let csrc_count = (b0 & 0x0F) as usize;
        let marker = (b1 & 0x80) != 0;
        let payload_type = b1 & 0x7F;

        let mut offset = 12usize;
        if raw.len() < offset + csrc_count * 4 {
            return Err(RtpError::PacketTooShort);
        }
        let sequence_number = u16::from_be_bytes([raw[2], raw[3]]);
        let timestamp = u32::from_be_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let ssrc = u32::from_be_bytes([raw[8], raw[9], raw[10], raw[11]]);

        let mut csrcs = Vec::with_capacity(csrc_count);
        for _ in 0..csrc_count {
            let value = u32::from_be_bytes([
                raw[offset],
                raw[offset + 1],
                raw[offset + 2],
                raw[offset + 3],
            ]);
            csrcs.push(value);
            offset += 4;
        }

        let mut extension_header = None;
        if extension {
            if raw.len() < offset + 4 {
                return Err(RtpError::PacketTooShort);
            }
            let profile = u16::from_be_bytes([raw[offset], raw[offset + 1]]);
            let length_words = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
            offset += 4;
            let extension_len = length_words * 4;
            if raw.len() < offset + extension_len {
                return Err(RtpError::PacketTooShort);
            }
            extension_header = Some(RtpHeaderExtension::new(
                profile,
                raw[offset..offset + extension_len].to_vec(),
            ));
            offset += extension_len;
        }

        let mut payload_end = raw.len();
        let mut padding_len = 0u8;
        if padding {
            padding_len = *raw.last().ok_or(RtpError::PacketTooShort)?;
            if padding_len as usize > raw.len().saturating_sub(offset) {
                return Err(RtpError::InvalidHeader("padding larger than payload"));
            }
            payload_end -= padding_len as usize;
        }
        let payload = raw[offset..payload_end].to_vec();

        let header = RtpHeader {
            marker,
            payload_type,
            sequence_number,
            timestamp,
            ssrc,
            csrcs,
            extension: extension_header,
        };

        Ok(Self {
            header,
            payload,
            padding_len,
        })
    }

    pub fn marshal(&self) -> RtpResult<Vec<u8>> {
        self.header.validate()?;
        let mut buffer = Vec::with_capacity(12 + self.header.csrcs.len() * 4 + self.payload.len());
        let mut b0 = RTP_VERSION << 6;
        if self.padding_len > 0 {
            b0 |= 0x20;
        }
        if self.header.extension.is_some() {
            b0 |= 0x10;
        }
        b0 |= (self.header.csrcs.len() & 0x0F) as u8;
        let mut b1 = self.header.payload_type & 0x7F;
        if self.header.marker {
            b1 |= 0x80;
        }
        buffer.push(b0);
        buffer.push(b1);
        buffer.extend_from_slice(&self.header.sequence_number.to_be_bytes());
        buffer.extend_from_slice(&self.header.timestamp.to_be_bytes());
        buffer.extend_from_slice(&self.header.ssrc.to_be_bytes());
        for csrc in &self.header.csrcs {
            buffer.extend_from_slice(&csrc.to_be_bytes());
        }
        if let Some(extension) = &self.header.extension {
            let length_words = (extension.data.len() / 4) as u16;
            buffer.extend_from_slice(&extension.profile.to_be_bytes());
            buffer.extend_from_slice(&length_words.to_be_bytes());
            buffer.extend_from_slice(&extension.data);
        }
        buffer.extend_from_slice(&self.payload);
        if self.padding_len > 0 {
            buffer.extend(std::iter::repeat_n(
                self.padding_len,
                self.padding_len as usize,
            ));
        }
        Ok(buffer)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReportBlock {
    pub ssrc: u32,
    pub fraction_lost: u8,
    pub packets_lost: i32,
    pub highest_sequence: u32,
    pub jitter: u32,
    pub last_sender_report: u32,
    pub delay_since_last_sender_report: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SenderReport {
    pub sender_ssrc: u32,
    pub ntp_most: u32,
    pub ntp_least: u32,
    pub rtp_timestamp: u32,
    pub packet_count: u32,
    pub octet_count: u32,
    pub report_blocks: Vec<ReportBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReceiverReport {
    pub sender_ssrc: u32,
    pub report_blocks: Vec<ReportBlock>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PictureLossIndication {
    pub sender_ssrc: u32,
    pub media_ssrc: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirRequest {
    pub ssrc: u32,
    pub sequence_number: u8,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FullIntraRequest {
    pub sender_ssrc: u32,
    pub requests: Vec<FirRequest>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GenericNack {
    pub sender_ssrc: u32,
    pub media_ssrc: u32,
    pub lost_packets: Vec<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteBitrateEstimate {
    pub sender_ssrc: u32,
    pub bitrate_bps: u64,
    pub ssrcs: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransportWideCc {
    pub sender_ssrc: u32,
    pub media_ssrc: u32,
    pub base_sequence: u16,
    pub packet_status_count: u16,
    pub reference_time_64ms: u32,
    pub feedback_packet_count: u8,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesItem {
    pub ty: u8,
    pub text: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdesChunk {
    pub ssrc: u32,
    pub items: Vec<SdesItem>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceDescription {
    pub chunks: Vec<SdesChunk>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Goodbye {
    pub sources: Vec<u32>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RtcpPacket {
    SenderReport(SenderReport),
    ReceiverReport(ReceiverReport),
    SourceDescription(SourceDescription),
    Goodbye(Goodbye),
    PictureLossIndication(PictureLossIndication),
    FullIntraRequest(FullIntraRequest),
    GenericNack(GenericNack),
    RemoteBitrateEstimate(RemoteBitrateEstimate),
    TransportWideCc(TransportWideCc),
}

pub fn parse_rtcp_packets(raw: &[u8]) -> RtpResult<Vec<RtcpPacket>> {
    let mut packets = Vec::new();
    let mut offset = 0usize;
    while offset + 4 <= raw.len() {
        let vrc = raw[offset];
        let version = vrc >> 6;
        if version != RTP_VERSION {
            return Err(RtpError::InvalidRtcp("invalid RTCP version"));
        }
        let padding = (vrc & 0x20) != 0;
        let fmt = vrc & 0x1F;
        let packet_type = raw[offset + 1];
        let length_words = u16::from_be_bytes([raw[offset + 2], raw[offset + 3]]) as usize;
        let packet_len = (length_words + 1) * 4;
        if raw.len() < offset + packet_len {
            return Err(RtpError::LengthMismatch);
        }
        let body_len = packet_len.saturating_sub(4);
        let mut body_end = offset + packet_len;
        if padding {
            let pad = raw[body_end - 1] as usize;
            if pad == 0 || pad > body_len {
                return Err(RtpError::InvalidRtcp("invalid padding in RTCP packet"));
            }
            body_end -= pad;
        }
        let body = &raw[offset + 4..body_end];
        let packet = match packet_type {
            RTCP_SR => RtcpPacket::SenderReport(parse_sender_report(fmt, body)?),
            RTCP_RR => RtcpPacket::ReceiverReport(parse_receiver_report(fmt, body)?),
            RTCP_SDES => RtcpPacket::SourceDescription(parse_sdes(fmt, body)?),
            RTCP_BYE => RtcpPacket::Goodbye(parse_goodbye(fmt, body)?),
            RTCP_RTPFB => parse_rtcp_rtpfb(fmt, body)?,
            RTCP_PSFB => parse_rtcp_psfb(fmt, body)?,
            _ => return Err(RtpError::InvalidRtcp("unsupported RTCP packet type")),
        };
        packets.push(packet);
        offset += packet_len;
    }
    Ok(packets)
}

pub fn marshal_rtcp_packets(packets: &[RtcpPacket]) -> RtpResult<Vec<u8>> {
    let mut out = Vec::new();
    for packet in packets {
        match packet {
            RtcpPacket::SenderReport(sr) => write_rtcp_packet(
                &mut out,
                sr.report_blocks.len() as u8,
                RTCP_SR,
                build_sender_report_body(sr)?,
            ),
            RtcpPacket::ReceiverReport(rr) => write_rtcp_packet(
                &mut out,
                rr.report_blocks.len() as u8,
                RTCP_RR,
                build_receiver_report_body(rr)?,
            ),
            RtcpPacket::SourceDescription(sdes) => write_rtcp_packet(
                &mut out,
                sdes.chunks.len() as u8,
                RTCP_SDES,
                build_sdes_body(sdes),
            ),
            RtcpPacket::Goodbye(bye) => write_rtcp_packet(
                &mut out,
                bye.sources.len() as u8,
                RTCP_BYE,
                build_goodbye_body(bye),
            ),
            RtcpPacket::PictureLossIndication(pli) => write_rtcp_packet(
                &mut out,
                RTCP_PSFB_PLI,
                RTCP_PSFB,
                build_psfb_common(pli.sender_ssrc, pli.media_ssrc),
            ),
            RtcpPacket::FullIntraRequest(fir) => {
                write_rtcp_packet(&mut out, RTCP_PSFB_FIR, RTCP_PSFB, build_fir_body(fir))
            }
            RtcpPacket::GenericNack(nack) => write_rtcp_packet(
                &mut out,
                RTCP_RTPFB_NACK,
                RTCP_RTPFB,
                build_nack_body(nack)?,
            ),
            RtcpPacket::RemoteBitrateEstimate(remb) => {
                write_rtcp_packet(&mut out, RTCP_PSFB_APP, RTCP_PSFB, build_remb_body(remb)?)
            }
            RtcpPacket::TransportWideCc(twcc) => {
                write_rtcp_packet(&mut out, RTCP_RTPFB_TWCC, RTCP_RTPFB, build_twcc_body(twcc))
            }
        }
    }
    Ok(out)
}

fn write_rtcp_packet(out: &mut Vec<u8>, fmt: u8, packet_type: u8, mut body: Vec<u8>) {
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    let length = ((body.len() + 4) / 4).saturating_sub(1) as u16;
    out.push((RTP_VERSION << 6) | (fmt & 0x1F));
    out.push(packet_type);
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(&body);
}

fn parse_sender_report(fmt: u8, body: &[u8]) -> RtpResult<SenderReport> {
    if body.len() < 24 {
        return Err(RtpError::InvalidRtcp("sender report too short"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let ntp_most = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let ntp_least = u32::from_be_bytes([body[8], body[9], body[10], body[11]]);
    let rtp_timestamp = u32::from_be_bytes([body[12], body[13], body[14], body[15]]);
    let packet_count = u32::from_be_bytes([body[16], body[17], body[18], body[19]]);
    let octet_count = u32::from_be_bytes([body[20], body[21], body[22], body[23]]);
    let mut offset = 24;
    let mut report_blocks = Vec::with_capacity(fmt as usize);
    for _ in 0..fmt {
        if body.len() < offset + 24 {
            return Err(RtpError::LengthMismatch);
        }
        report_blocks.push(parse_report_block(&body[offset..offset + 24]));
        offset += 24;
    }
    Ok(SenderReport {
        sender_ssrc,
        ntp_most,
        ntp_least,
        rtp_timestamp,
        packet_count,
        octet_count,
        report_blocks,
    })
}

fn parse_receiver_report(fmt: u8, body: &[u8]) -> RtpResult<ReceiverReport> {
    if body.len() < 4 {
        return Err(RtpError::InvalidRtcp("receiver report too short"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut offset = 4;
    let mut report_blocks = Vec::with_capacity(fmt as usize);
    for _ in 0..fmt {
        if body.len() < offset + 24 {
            return Err(RtpError::LengthMismatch);
        }
        report_blocks.push(parse_report_block(&body[offset..offset + 24]));
        offset += 24;
    }
    Ok(ReceiverReport {
        sender_ssrc,
        report_blocks,
    })
}

fn parse_sdes(count: u8, body: &[u8]) -> RtpResult<SourceDescription> {
    let mut chunks = Vec::with_capacity(count as usize);
    let mut offset = 0;
    for _ in 0..count {
        if body.len() < offset + 4 {
            return Err(RtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ]);
        offset += 4;
        let mut items = Vec::new();
        loop {
            if offset >= body.len() {
                break;
            }
            let ty = body[offset];
            offset += 1;
            if ty == 0 {
                // End of list, skip padding until 32-bit boundary
                while offset % 4 != 0 {
                    if offset >= body.len() {
                        break;
                    }
                    offset += 1;
                }
                break;
            }
            if offset >= body.len() {
                return Err(RtpError::PacketTooShort);
            }
            let len = body[offset] as usize;
            offset += 1;
            if body.len() < offset + len {
                return Err(RtpError::PacketTooShort);
            }
            let text = String::from_utf8_lossy(&body[offset..offset + len]).to_string();
            items.push(SdesItem { ty, text });
            offset += len;
        }
        chunks.push(SdesChunk { ssrc, items });
    }
    Ok(SourceDescription { chunks })
}

fn parse_goodbye(count: u8, body: &[u8]) -> RtpResult<Goodbye> {
    let mut sources = Vec::with_capacity(count as usize);
    let mut offset = 0;
    for _ in 0..count {
        if body.len() < offset + 4 {
            return Err(RtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ]);
        sources.push(ssrc);
        offset += 4;
    }

    let mut reason = None;
    if offset < body.len() {
        let len = body[offset] as usize;
        offset += 1;
        if body.len() < offset + len {
            return Err(RtpError::PacketTooShort);
        }
        reason = Some(String::from_utf8_lossy(&body[offset..offset + len]).to_string());
    }

    Ok(Goodbye { sources, reason })
}

fn parse_report_block(bytes: &[u8]) -> ReportBlock {
    let ssrc = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    let fraction_lost = bytes[4];
    let packets_lost =
        (((bytes[5] as i32) << 16) | ((bytes[6] as i32) << 8) | bytes[7] as i32) << 8 >> 8;
    let highest_sequence = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    let jitter = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    let last_sender_report = u32::from_be_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    let delay_since_last_sender_report =
        u32::from_be_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]);
    ReportBlock {
        ssrc,
        fraction_lost,
        packets_lost,
        highest_sequence,
        jitter,
        last_sender_report,
        delay_since_last_sender_report,
    }
}

fn parse_rtcp_rtpfb(fmt: u8, body: &[u8]) -> RtpResult<RtcpPacket> {
    match fmt {
        RTCP_RTPFB_NACK => Ok(RtcpPacket::GenericNack(parse_nack_body(body)?)),
        RTCP_RTPFB_TWCC => Ok(RtcpPacket::TransportWideCc(parse_twcc_body(body)?)),
        _ => Err(RtpError::InvalidRtcp("unsupported RTP feedback format")),
    }
}

fn parse_rtcp_psfb(fmt: u8, body: &[u8]) -> RtpResult<RtcpPacket> {
    match fmt {
        RTCP_PSFB_PLI => Ok(RtcpPacket::PictureLossIndication(parse_psfb_common(body)?)),
        RTCP_PSFB_FIR => Ok(RtcpPacket::FullIntraRequest(parse_fir_body(body)?)),
        RTCP_PSFB_APP => Ok(RtcpPacket::RemoteBitrateEstimate(parse_remb_body(body)?)),
        _ => Err(RtpError::InvalidRtcp("unsupported payload feedback format")),
    }
}

fn parse_psfb_common(body: &[u8]) -> RtpResult<PictureLossIndication> {
    if body.len() < 8 {
        return Err(RtpError::InvalidRtcp("payload feedback body too short"));
    }
    Ok(PictureLossIndication {
        sender_ssrc: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
        media_ssrc: u32::from_be_bytes([body[4], body[5], body[6], body[7]]),
    })
}

fn parse_fir_body(body: &[u8]) -> RtpResult<FullIntraRequest> {
    if body.len() < 8 {
        return Err(RtpError::InvalidRtcp("FIR body too short"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let mut offset = 8; // bytes 4..7 are reserved
    let mut requests = Vec::new();
    while offset + 8 <= body.len() {
        requests.push(FirRequest {
            ssrc: u32::from_be_bytes([
                body[offset],
                body[offset + 1],
                body[offset + 2],
                body[offset + 3],
            ]),
            sequence_number: body[offset + 4],
        });
        offset += 8;
    }
    Ok(FullIntraRequest {
        sender_ssrc,
        requests,
    })
}

fn parse_nack_body(body: &[u8]) -> RtpResult<GenericNack> {
    if body.len() < 8 {
        return Err(RtpError::InvalidRtcp("NACK body too short"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let media_ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let mut lost_packets = Vec::new();
    let mut offset = 8;
    while offset + 4 <= body.len() {
        let pid = u16::from_be_bytes([body[offset], body[offset + 1]]);
        let blp = u16::from_be_bytes([body[offset + 2], body[offset + 3]]);
        lost_packets.push(pid);
        for bit in 0..16 {
            if (blp >> bit) & 1 == 1 {
                lost_packets.push(pid.wrapping_add(bit + 1));
            }
        }
        offset += 4;
    }
    Ok(GenericNack {
        sender_ssrc,
        media_ssrc,
        lost_packets,
    })
}

fn parse_remb_body(body: &[u8]) -> RtpResult<RemoteBitrateEstimate> {
    if body.len() < 16 || &body[8..12] != b"REMB" {
        return Err(RtpError::InvalidRtcp("invalid REMB payload"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let num_ssrc = body[12] as usize;
    let exponent = (body[13] & 0xFC) >> 2;
    let mantissa = ((u32::from(body[13] & 0x03) << 16)
        | (u32::from(body[14]) << 8)
        | u32::from(body[15])) as u64;
    let bitrate_bps = mantissa << exponent;
    let mut ssrcs = Vec::with_capacity(num_ssrc);
    let mut offset = 16;
    for _ in 0..num_ssrc {
        if body.len() < offset + 4 {
            return Err(RtpError::LengthMismatch);
        }
        ssrcs.push(u32::from_be_bytes([
            body[offset],
            body[offset + 1],
            body[offset + 2],
            body[offset + 3],
        ]));
        offset += 4;
    }
    Ok(RemoteBitrateEstimate {
        sender_ssrc,
        bitrate_bps,
        ssrcs,
    })
}

fn parse_twcc_body(body: &[u8]) -> RtpResult<TransportWideCc> {
    if body.len() < 16 {
        return Err(RtpError::InvalidRtcp("TWCC body too short"));
    }
    let sender_ssrc = u32::from_be_bytes([body[0], body[1], body[2], body[3]]);
    let media_ssrc = u32::from_be_bytes([body[4], body[5], body[6], body[7]]);
    let base_sequence = u16::from_be_bytes([body[8], body[9]]);
    let packet_status_count = u16::from_be_bytes([body[10], body[11]]);
    let reference_time_64ms = u32::from_be_bytes([0, body[12], body[13], body[14]]);
    let feedback_packet_count = body[15];
    let payload = body[16..].to_vec();
    Ok(TransportWideCc {
        sender_ssrc,
        media_ssrc,
        base_sequence,
        packet_status_count,
        reference_time_64ms,
        feedback_packet_count,
        payload,
    })
}

fn build_sender_report_body(sr: &SenderReport) -> RtpResult<Vec<u8>> {
    let mut body = Vec::with_capacity(24 + sr.report_blocks.len() * 24);
    body.extend_from_slice(&sr.sender_ssrc.to_be_bytes());
    body.extend_from_slice(&sr.ntp_most.to_be_bytes());
    body.extend_from_slice(&sr.ntp_least.to_be_bytes());
    body.extend_from_slice(&sr.rtp_timestamp.to_be_bytes());
    body.extend_from_slice(&sr.packet_count.to_be_bytes());
    body.extend_from_slice(&sr.octet_count.to_be_bytes());
    for block in &sr.report_blocks {
        body.extend_from_slice(&build_report_block(block));
    }
    Ok(body)
}

fn build_receiver_report_body(rr: &ReceiverReport) -> RtpResult<Vec<u8>> {
    let mut body = Vec::with_capacity(4 + rr.report_blocks.len() * 24);
    body.extend_from_slice(&rr.sender_ssrc.to_be_bytes());
    for block in &rr.report_blocks {
        body.extend_from_slice(&build_report_block(block));
    }
    Ok(body)
}

fn build_sdes_body(sdes: &SourceDescription) -> Vec<u8> {
    let mut body = Vec::new();
    for chunk in &sdes.chunks {
        body.extend_from_slice(&chunk.ssrc.to_be_bytes());
        for item in &chunk.items {
            body.push(item.ty);
            body.push(item.text.len() as u8);
            body.extend_from_slice(item.text.as_bytes());
        }
        body.push(0); // End of list
        while body.len() % 4 != 0 {
            body.push(0);
        }
    }
    body
}

fn build_goodbye_body(bye: &Goodbye) -> Vec<u8> {
    let mut body = Vec::new();
    for ssrc in &bye.sources {
        body.extend_from_slice(&ssrc.to_be_bytes());
    }
    if let Some(reason) = &bye.reason {
        let bytes = reason.as_bytes();
        let len = bytes.len().min(255) as u8;
        body.push(len);
        body.extend_from_slice(&bytes[..len as usize]);
        // Padding to 32-bit boundary is handled by write_rtcp_packet
    }
    body
}

fn build_report_block(block: &ReportBlock) -> [u8; 24] {
    let mut buf = [0u8; 24];
    buf[0..4].copy_from_slice(&block.ssrc.to_be_bytes());
    buf[4] = block.fraction_lost;
    let clamped = block.packets_lost.clamp(-(1 << 23), (1 << 23) - 1);
    let lost_bytes = (clamped as u32 & 0x00FF_FFFF).to_be_bytes();
    buf[5..8].copy_from_slice(&lost_bytes[1..]);
    buf[8..12].copy_from_slice(&block.highest_sequence.to_be_bytes());
    buf[12..16].copy_from_slice(&block.jitter.to_be_bytes());
    buf[16..20].copy_from_slice(&block.last_sender_report.to_be_bytes());
    buf[20..24].copy_from_slice(&block.delay_since_last_sender_report.to_be_bytes());
    buf
}

fn build_psfb_common(sender_ssrc: u32, media_ssrc: u32) -> Vec<u8> {
    let mut body = Vec::with_capacity(8);
    body.extend_from_slice(&sender_ssrc.to_be_bytes());
    body.extend_from_slice(&media_ssrc.to_be_bytes());
    body
}

fn build_fir_body(fir: &FullIntraRequest) -> Vec<u8> {
    let mut body = Vec::with_capacity(8 + fir.requests.len() * 8);
    body.extend_from_slice(&fir.sender_ssrc.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    for entry in &fir.requests {
        body.extend_from_slice(&entry.ssrc.to_be_bytes());
        body.push(entry.sequence_number);
        body.extend_from_slice(&[0u8; 3]);
    }
    body
}

fn build_nack_body(nack: &GenericNack) -> RtpResult<Vec<u8>> {
    if nack.lost_packets.is_empty() {
        return Err(RtpError::InvalidRtcp("NACK requires at least one packet"));
    }
    let pairs = pack_nack_pairs(&nack.lost_packets);
    let mut body = Vec::with_capacity(8 + pairs.len() * 4);
    body.extend_from_slice(&nack.sender_ssrc.to_be_bytes());
    body.extend_from_slice(&nack.media_ssrc.to_be_bytes());
    for (pid, blp) in pairs {
        body.extend_from_slice(&pid.to_be_bytes());
        body.extend_from_slice(&blp.to_be_bytes());
    }
    Ok(body)
}

fn build_remb_body(remb: &RemoteBitrateEstimate) -> RtpResult<Vec<u8>> {
    if remb.ssrcs.len() > 0xFF {
        return Err(RtpError::InvalidRtcp("too many REMB SSRC entries"));
    }
    let mut body = Vec::with_capacity(16 + remb.ssrcs.len() * 4);
    body.extend_from_slice(&remb.sender_ssrc.to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes());
    body.extend_from_slice(b"REMB");
    body.push(remb.ssrcs.len() as u8);
    let mut exponent = 0u8;
    let mut mantissa = remb.bitrate_bps;
    while mantissa > 0x3FFFF {
        mantissa >>= 1;
        exponent += 1;
    }
    let mantissa_u32 = mantissa as u32;
    body.push(((exponent & 0x3F) << 2) | ((mantissa_u32 >> 16) as u8 & 0x03));
    body.push(((mantissa_u32 >> 8) & 0xFF) as u8);
    body.push((mantissa_u32 & 0xFF) as u8);
    for ssrc in &remb.ssrcs {
        body.extend_from_slice(&ssrc.to_be_bytes());
    }
    Ok(body)
}

fn build_twcc_body(twcc: &TransportWideCc) -> Vec<u8> {
    let mut body = Vec::with_capacity(16 + twcc.payload.len());
    body.extend_from_slice(&twcc.sender_ssrc.to_be_bytes());
    body.extend_from_slice(&twcc.media_ssrc.to_be_bytes());
    body.extend_from_slice(&twcc.base_sequence.to_be_bytes());
    body.extend_from_slice(&twcc.packet_status_count.to_be_bytes());
    let ref_time = twcc.reference_time_64ms & 0x00FF_FFFF;
    body.extend_from_slice(&ref_time.to_be_bytes()[1..]);
    body.push(twcc.feedback_packet_count);
    body.extend_from_slice(&twcc.payload);
    body
}

fn pack_nack_pairs(packets: &[u16]) -> Vec<(u16, u16)> {
    let mut seqs = packets.to_vec();
    seqs.sort_unstable();
    seqs.dedup();
    let mut pairs = Vec::new();
    let mut idx = 0;
    while idx < seqs.len() {
        let pid = seqs[idx];
        idx += 1;
        let mut blp = 0u16;
        while idx < seqs.len() {
            let diff = seqs[idx].wrapping_sub(pid);
            if diff == 0 {
                idx += 1;
                continue;
            }
            if diff > 16 {
                break;
            }
            blp |= 1 << (diff - 1);
            idx += 1;
        }
        pairs.push((pid, blp));
    }
    pairs
}

pub fn is_rtcp(packet: &[u8]) -> bool {
    packet.len() >= 2 && (192..=208).contains(&packet[1])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtp_roundtrip() {
        let mut header = RtpHeader::new(96, 1000, 42, 0x1234_5678);
        header.marker = true;
        header.csrcs = vec![0x0102_0304];
        header.extension = Some(RtpHeaderExtension::new(0xBEDE, vec![0, 1, 2, 3]));
        let packet = RtpPacket {
            header,
            payload: vec![9, 8, 7, 6],
            padding_len: 0,
        };
        let serialized = packet.marshal().unwrap();
        let parsed = RtpPacket::parse(&serialized).unwrap();
        assert_eq!(parsed.header.payload_type, 96);
        assert_eq!(parsed.header.sequence_number, 1000);
        assert!(parsed.header.marker);
        assert_eq!(parsed.payload, vec![9, 8, 7, 6]);
    }

    #[test]
    fn remb_roundtrip() {
        let remb = RemoteBitrateEstimate {
            sender_ssrc: 1,
            bitrate_bps: 750_000,
            ssrcs: vec![2, 3],
        };
        let bytes =
            marshal_rtcp_packets(&[RtcpPacket::RemoteBitrateEstimate(remb.clone())]).unwrap();
        let parsed = parse_rtcp_packets(&bytes).unwrap();
        match &parsed[0] {
            RtcpPacket::RemoteBitrateEstimate(decoded) => {
                assert_eq!(decoded.sender_ssrc, remb.sender_ssrc);
                assert_eq!(decoded.ssrcs, remb.ssrcs);
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn nack_pair_encoding() {
        let pairs = pack_nack_pairs(&[10, 11, 12, 30]);
        assert_eq!(pairs, vec![(10, 0b0000_0000_0000_0011), (30, 0)]);
    }

    #[test]
    fn pli_roundtrip() {
        let pli = RtcpPacket::PictureLossIndication(PictureLossIndication {
            sender_ssrc: 1,
            media_ssrc: 2,
        });
        let bytes = marshal_rtcp_packets(&[pli.clone()]).unwrap();
        let parsed = parse_rtcp_packets(&bytes).unwrap();
        assert!(matches!(parsed[0], RtcpPacket::PictureLossIndication(_)));
    }

    #[test]
    fn generic_nack_roundtrip() {
        let nack = RtcpPacket::GenericNack(GenericNack {
            sender_ssrc: 5,
            media_ssrc: 6,
            lost_packets: vec![100, 102],
        });
        let bytes = marshal_rtcp_packets(&[nack.clone()]).unwrap();
        let parsed = parse_rtcp_packets(&bytes).unwrap();
        match &parsed[0] {
            RtcpPacket::GenericNack(out) => {
                assert_eq!(out.sender_ssrc, 5);
                assert_eq!(out.media_ssrc, 6);
                assert_eq!(out.lost_packets.len(), 2);
            }
            other => panic!("unexpected packet: {other:?}"),
        }
    }

    #[test]
    fn rtcp_detection() {
        let pli =
            marshal_rtcp_packets(&[RtcpPacket::PictureLossIndication(PictureLossIndication {
                sender_ssrc: 1,
                media_ssrc: 2,
            })])
            .unwrap();
        assert!(is_rtcp(&pli));
    }
}
