//! RFC 4588 RTX (Retransmission) helpers.
//!
//! Packet format: RTX payload = 2-byte Original Sequence Number (OSN, network order)
//! followed by the original RTP payload. RTX uses a dedicated SSRC and payload type
//! associated with the primary codec via `a=fmtp:<rtx-pt> apt=<primary-pt>`.

use crate::rtp::{RtpHeader, RtpPacket};
use bytes::{BufMut, BytesMut};
use std::collections::HashMap;

/// Sender-side RTX parameters negotiated for a primary media stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtxSenderConfig {
    pub rtx_ssrc: u32,
    pub rtx_payload_type: u8,
}

/// Association parsed from SDP: RTX payload type → primary (associated) payload type.
pub type RtxAptMap = HashMap<u8, u8>;

/// Wrap a primary media packet into an RFC 4588 RTX retransmission packet.
pub fn wrap_rtx_packet(
    original: &RtpPacket,
    config: &RtxSenderConfig,
    rtx_sequence_number: u16,
) -> RtpPacket {
    let mut payload = BytesMut::with_capacity(2 + original.payload.len());
    payload.put_u16(original.header.sequence_number);
    payload.extend_from_slice(&original.payload);

    let mut header = RtpHeader::new(
        config.rtx_payload_type,
        rtx_sequence_number,
        original.header.timestamp,
        config.rtx_ssrc,
    );
    header.marker = original.header.marker;
    // RTX packets intentionally omit CSRCs / header extensions from the primary
    // packet; browsers recover media from the OSN + payload only.

    RtpPacket {
        header,
        payload: payload.freeze(),
        padding_len: 0,
    }
}

/// Unwrap an RTX packet back into a primary media packet.
///
/// Returns `None` when the RTX payload is shorter than the 2-byte OSN header.
pub fn unwrap_rtx_packet(
    rtx: &RtpPacket,
    primary_ssrc: u32,
    primary_payload_type: u8,
) -> Option<RtpPacket> {
    if rtx.payload.len() < 2 {
        return None;
    }
    let osn = u16::from_be_bytes([rtx.payload[0], rtx.payload[1]]);
    let mut header = RtpHeader::new(
        primary_payload_type,
        osn,
        rtx.header.timestamp,
        primary_ssrc,
    );
    header.marker = rtx.header.marker;

    Some(RtpPacket {
        header,
        payload: rtx.payload.slice(2..),
        padding_len: 0,
    })
}

/// Parse `apt=<pt>` from an SDP fmtp value (e.g. `"apt=96"` or `"apt=96;rtx-time=3000"`).
pub fn parse_apt(fmtp: &str) -> Option<u8> {
    for part in fmtp.split(';') {
        let part = part.trim();
        if let Some(rest) = part
            .strip_prefix("apt=")
            .or_else(|| part.strip_prefix("APT="))
        {
            return rest.trim().parse().ok();
        }
    }
    None
}

/// Build RTX PT → primary PT map from media-section attributes.
///
/// Looks for `a=rtpmap:<pt> rtx/...` plus `a=fmtp:<pt> apt=<primary>`.
pub fn extract_rtx_apt_map(attributes: &[(String, Option<String>)]) -> RtxAptMap {
    let mut rtx_pts = Vec::new();
    for (key, value) in attributes {
        if key != "rtpmap" {
            continue;
        }
        let Some(val) = value else { continue };
        let mut parts = val.split_whitespace();
        let Some(pt_str) = parts.next() else { continue };
        let Some(codec) = parts.next() else { continue };
        let Ok(pt) = pt_str.parse::<u8>() else {
            continue;
        };
        let codec_name = codec.split('/').next().unwrap_or("");
        if codec_name.eq_ignore_ascii_case("rtx") {
            rtx_pts.push(pt);
        }
    }

    let mut map = RtxAptMap::new();
    for (key, value) in attributes {
        if key != "fmtp" {
            continue;
        }
        let Some(val) = value else { continue };
        let mut parts = val.splitn(2, ' ');
        let Some(pt_str) = parts.next() else { continue };
        let Some(fmtp) = parts.next() else { continue };
        let Ok(pt) = pt_str.parse::<u8>() else {
            continue;
        };
        if !rtx_pts.contains(&pt) {
            // Still accept apt= even if rtpmap order differs / was missed.
            if parse_apt(fmtp).is_none() {
                continue;
            }
        }
        if let Some(primary) = parse_apt(fmtp) {
            map.insert(pt, primary);
        }
    }
    map
}

/// Convenience over SDP `Attribute` list.
pub fn extract_rtx_apt_map_from_attrs(attrs: &[crate::sdp::Attribute]) -> RtxAptMap {
    let pairs: Vec<(String, Option<String>)> = attrs
        .iter()
        .map(|a| (a.key.clone(), a.value.clone()))
        .collect();
    extract_rtx_apt_map(&pairs)
}

/// Pick a free dynamic payload type (96–127) not in `used`.
pub fn allocate_rtx_payload_type(used: &[u8]) -> Option<u8> {
    (96u8..=127).find(|pt| !used.contains(pt))
}

/// Append RTX rtpmap/fmtp lines and the PT to `formats` for a primary codec.
pub fn append_rtx_to_section(
    formats: &mut Vec<String>,
    attributes: &mut Vec<crate::sdp::Attribute>,
    primary_pt: u8,
    rtx_pt: u8,
    clock_rate: u32,
) {
    let rtx_pt_str = rtx_pt.to_string();
    if !formats.iter().any(|f| f == &rtx_pt_str) {
        formats.push(rtx_pt_str);
    }
    let rtpmap = format!("{rtx_pt} rtx/{clock_rate}");
    let already = attributes
        .iter()
        .any(|a| a.key == "rtpmap" && a.value.as_deref() == Some(rtpmap.as_str()));
    if !already {
        attributes.push(crate::sdp::Attribute::new("rtpmap", Some(rtpmap)));
        attributes.push(crate::sdp::Attribute::new(
            "fmtp",
            Some(format!("{rtx_pt} apt={primary_pt}")),
        ));
    }
}

/// Find RTX payload type associated with `primary_pt` in an apt map.
pub fn rtx_pt_for_primary(apt_map: &RtxAptMap, primary_pt: u8) -> Option<u8> {
    apt_map
        .iter()
        .find_map(|(rtx_pt, primary)| (*primary == primary_pt).then_some(*rtx_pt))
}

/// Encode OSN as big-endian bytes (test / debug helper).
pub fn encode_osn(osn: u16) -> [u8; 2] {
    osn.to_be_bytes()
}

/// Decode OSN from the first two bytes of an RTX payload.
pub fn decode_osn(payload: &[u8]) -> Option<u16> {
    if payload.len() < 2 {
        None
    } else {
        Some(u16::from_be_bytes([payload[0], payload[1]]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::RtpHeader;

    #[test]
    fn wrap_unwrap_round_trip() {
        let original = RtpPacket {
            header: {
                let mut h = RtpHeader::new(96, 12345, 99_000, 0xAABB_CCDD);
                h.marker = true;
                h
            },
            payload: bytes::Bytes::from_static(&[1, 2, 3, 4, 5]),
            padding_len: 0,
        };
        let cfg = RtxSenderConfig {
            rtx_ssrc: 0x1122_3344,
            rtx_payload_type: 97,
        };
        let rtx = wrap_rtx_packet(&original, &cfg, 7);
        assert_eq!(rtx.header.ssrc, cfg.rtx_ssrc);
        assert_eq!(rtx.header.payload_type, 97);
        assert_eq!(rtx.header.sequence_number, 7);
        assert_eq!(rtx.header.timestamp, 99_000);
        assert!(rtx.header.marker);
        assert_eq!(decode_osn(&rtx.payload), Some(12345));
        assert_eq!(&rtx.payload[2..], &[1, 2, 3, 4, 5]);

        let restored = unwrap_rtx_packet(&rtx, original.header.ssrc, 96).unwrap();
        assert_eq!(restored.header.ssrc, original.header.ssrc);
        assert_eq!(restored.header.payload_type, 96);
        assert_eq!(restored.header.sequence_number, 12345);
        assert_eq!(restored.header.timestamp, original.header.timestamp);
        assert_eq!(restored.header.marker, original.header.marker);
        assert_eq!(restored.payload, original.payload);
    }

    #[test]
    fn unwrap_rejects_short_payload() {
        let rtx = RtpPacket {
            header: RtpHeader::new(97, 1, 0, 1),
            payload: bytes::Bytes::from_static(&[0x12]),
            padding_len: 0,
        };
        assert!(unwrap_rtx_packet(&rtx, 2, 96).is_none());
    }

    #[test]
    fn parse_apt_variants() {
        assert_eq!(parse_apt("apt=96"), Some(96));
        assert_eq!(parse_apt("apt=96;rtx-time=3000"), Some(96));
        assert_eq!(parse_apt("rtx-time=3000;apt=100"), Some(100));
        assert_eq!(parse_apt("nope"), None);
    }

    #[test]
    fn extract_apt_map_from_sdp_attrs() {
        let attrs = vec![
            ("rtpmap".into(), Some("96 VP8/90000".into())),
            ("rtpmap".into(), Some("97 rtx/90000".into())),
            ("fmtp".into(), Some("97 apt=96".into())),
        ];
        let map = extract_rtx_apt_map(&attrs);
        assert_eq!(map.get(&97), Some(&96));
        assert_eq!(rtx_pt_for_primary(&map, 96), Some(97));
    }

    #[test]
    fn extract_apt_map_accepts_fmtp_without_rtpmap() {
        let attrs = vec![("fmtp".into(), Some("97 apt=96".into()))];
        let map = extract_rtx_apt_map(&attrs);
        assert_eq!(map.get(&97), Some(&96));
    }

    #[test]
    fn wrap_copies_timestamp_and_uses_independent_seq() {
        let original = RtpPacket {
            header: RtpHeader::new(96, 100, 55_000, 1),
            payload: bytes::Bytes::from_static(&[0xAA]),
            padding_len: 0,
        };
        let cfg = RtxSenderConfig {
            rtx_ssrc: 2,
            rtx_payload_type: 97,
        };
        let rtx = wrap_rtx_packet(&original, &cfg, 9);
        assert_eq!(rtx.header.timestamp, 55_000);
        assert_eq!(rtx.header.sequence_number, 9);
        assert_ne!(rtx.header.sequence_number, original.header.sequence_number);
        assert_eq!(encode_osn(100), [0x00, 0x64]);
    }

    #[test]
    fn allocate_avoids_used_pts() {
        assert_eq!(allocate_rtx_payload_type(&[96, 97]), Some(98));
        let all: Vec<u8> = (96..=127).collect();
        assert_eq!(allocate_rtx_payload_type(&all), None);
    }
}
