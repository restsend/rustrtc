use bytes::Bytes;

pub const ACCEPTABLE_SEQ_NO_OFFSET: i32 = 2000;

pub const IND_MAX_BASE: i32 = 15;

pub const IND_EXT_BASE: i32 = 16;

pub const IND_MAX: i32 = 22;

pub const DATA_MAX_BASE: i32 = 8;

pub const DATA_EXT_BASE: i32 = 9;

pub const DATA_MAX: i32 = 14;

pub const FIELD_MAX_BASE: i32 = 7;

pub const FIELD_EXT_BASE: i32 = 8;

pub const FIELD_MAX: i32 = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireDataField {
    pub field_type: i32,
    pub data: Bytes,
}

impl WireDataField {
    pub fn new(field_type: i32, data: impl Into<Bytes>) -> Self {
        Self {
            field_type,
            data: data.into(),
        }
    }
}

pub fn encode_wire_indicator(t38_version: u8, indicator: i32) -> Option<Vec<u8>> {
    if (0..=IND_MAX_BASE).contains(&indicator) {
        Some(vec![(indicator << 1) as u8])
    } else if t38_version != 0 && (IND_EXT_BASE..=IND_MAX).contains(&indicator) {
        let v = 0x2000u16 | (((indicator - IND_EXT_BASE) << 6) as u16);
        Some(v.to_be_bytes().to_vec())
    } else {
        None
    }
}

pub fn encode_wire_data(
    t38_version: u8,
    data_type: i32,
    fields: &[WireDataField],
) -> Option<Vec<u8>> {
    let est = 2 + 1 + fields.iter().map(|f| f.data.len() + 4).sum::<usize>();
    let mut buf = Vec::with_capacity(est);

    let data_field_present = !fields.is_empty();

    let dfp_bit8: u8 = if data_field_present { 0x80 } else { 0 };

    if (0..=DATA_MAX_BASE).contains(&data_type) {
        buf.push(dfp_bit8 | 0x40 | ((data_type as u8) << 1));
    } else if t38_version != 0 && (DATA_EXT_BASE..=DATA_MAX).contains(&data_type) {
        let v = (u16::from(dfp_bit8) << 8) | 0x6000 | (((data_type - DATA_EXT_BASE) as u16) << 6);
        buf.extend_from_slice(&v.to_be_bytes());
    } else {
        return None;
    }

    if data_field_present {
        let mut encoded_len: usize = 0;
        loop {
            let value = fields.len() - encoded_len;
            let enclen: usize = if value < 0x80 {
                buf.push(value as u8);
                value
            } else if value < 0x4000 {
                buf.extend_from_slice(&((0x8000u16 | value as u16).to_be_bytes()));
                value
            } else {
                let multiplier = (value / 0x4000).min(4);
                buf.push(0xC0 | multiplier as u8);
                0x4000 * multiplier
            };

            let fragment_len = enclen;
            let prev_len = encoded_len;
            encoded_len += fragment_len;

            for field in &fields[prev_len..encoded_len] {
                let field_data_present = !field.data.is_empty();
                if t38_version == 0 {
                    if !(0..=FIELD_MAX_BASE).contains(&field.field_type) {
                        return None;
                    }
                    buf.push(((field_data_present as u8) << 7) | ((field.field_type as u8) << 4));
                } else if (0..=FIELD_MAX_BASE).contains(&field.field_type) {
                    buf.push(((field_data_present as u8) << 7) | ((field.field_type as u8) << 3));
                } else if (FIELD_EXT_BASE..=FIELD_MAX).contains(&field.field_type) {
                    let off = (field.field_type - FIELD_EXT_BASE) as u8;
                    buf.push(((field_data_present as u8) << 7) | 0x40 | (off >> 2));
                    buf.push((off << 6) & 0xC0);
                } else {
                    return None;
                }

                if field_data_present {
                    if field.data.len() > 65535 {
                        return None;
                    }
                    buf.extend_from_slice(&((field.data.len() - 1) as u16).to_be_bytes());
                    buf.extend_from_slice(&field.data);
                }
            }

            if encoded_len == fields.len() && fragment_len < 16384 {
                break;
            }
        }
    }

    Some(buf)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WireRxEvent {
    Indicator(i32),
    Data {
        data_type: i32,
        field_type: i32,
        payload: Bytes,
    },

    Missing {
        expected: i32,
        actual: i32,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum WireRxError {
    #[error("T.38 wire: truncated packet")]
    Truncated,

    #[error("T.38 wire: protocol violation")]
    Protocol,

    #[error("T.38 wire: invalid length for packet")]
    BadLength,
}

impl From<WireRxError> for crate::errors::RtcError {
    fn from(e: WireRxError) -> Self {
        crate::errors::RtcError::Protocol(e.to_string())
    }
}

pub fn classify_seq_no_offset(expected: i32, actual: i32) -> i32 {
    if expected > actual {
        if expected > actual + 0x10000 - ACCEPTABLE_SEQ_NO_OFFSET {
            return 1;
        }
        if expected < actual + ACCEPTABLE_SEQ_NO_OFFSET {
            return -1;
        }
    } else {
        if expected + ACCEPTABLE_SEQ_NO_OFFSET > actual {
            return 1;
        }
        if expected + 0x10000 - ACCEPTABLE_SEQ_NO_OFFSET < actual {
            return -1;
        }
    }
    0
}

#[derive(Debug, Clone)]
pub struct T38CoreRx {
    pub t38_version: u8,
    pub check_sequence_numbers: bool,

    expected_seq_no: i32,
    missing_packets: u32,
}

impl T38CoreRx {
    pub fn new(t38_version: u8) -> Self {
        Self {
            t38_version,
            check_sequence_numbers: true,
            expected_seq_no: -1,
            missing_packets: 0,
        }
    }

    pub fn missing_packets(&self) -> u32 {
        self.missing_packets
    }

    pub fn feed(&mut self, seq_no: u16, buf: &[u8]) -> Result<Vec<WireRxEvent>, WireRxError> {
        self.feed_bytes(seq_no, Bytes::copy_from_slice(buf))
    }

    pub fn feed_bytes(&mut self, seq_no: u16, buf: Bytes) -> Result<Vec<WireRxEvent>, WireRxError> {
        let mut events = Vec::new();

        if self.check_sequence_numbers {
            let seq = i32::from(seq_no);
            if seq != self.expected_seq_no {
                if self.expected_seq_no != -1 {
                    if ((seq + 1) & 0xFFFF) == self.expected_seq_no {
                        return Ok(events);
                    }
                    match classify_seq_no_offset(self.expected_seq_no, seq) {
                        -1 => return Ok(events),
                        1 => {
                            events.push(WireRxEvent::Missing {
                                expected: self.expected_seq_no,
                                actual: seq,
                            });
                            self.missing_packets = self
                                .missing_packets
                                .saturating_add((seq - self.expected_seq_no) as u32);
                        }
                        _ => {
                            events.push(WireRxEvent::Missing {
                                expected: -1,
                                actual: -1,
                            });
                            self.missing_packets = self.missing_packets.saturating_add(1);
                        }
                    }
                }
                self.expected_seq_no = seq;
            }
        }

        if buf.is_empty() {
            return Err(WireRxError::Truncated);
        }

        self.expected_seq_no = (self.expected_seq_no + 1) & 0xFFFF;

        let ptr = rx_ifp_stream(self.t38_version, &buf, &mut events)?;
        if ptr != buf.len() {
            return Err(WireRxError::BadLength);
        }
        Ok(events)
    }
}

fn rx_ifp_stream(
    t38_version: u8,
    buf: &Bytes,
    events: &mut Vec<WireRxEvent>,
) -> Result<usize, WireRxError> {
    let pkt_len = buf.len();
    let mut ptr = 0usize;

    if ptr + 1 > pkt_len {
        return Err(WireRxError::Truncated);
    }

    let data_field_present = buf[ptr] & 0x80 != 0;
    let msg_type = (buf[ptr] >> 6) & 1;

    match msg_type {
        0 => {
            if data_field_present {
                return Err(WireRxError::Protocol);
            }
            let indicator;
            if buf[ptr] & 0x20 != 0 {
                if ptr + 2 > pkt_len {
                    return Err(WireRxError::Truncated);
                }
                let v = IND_EXT_BASE
                    + (((i32::from(buf[ptr]) << 2) & 0x3C)
                        | ((i32::from(buf[ptr + 1]) >> 6) & 0x3));
                if v > IND_MAX {
                    return Err(WireRxError::Protocol);
                }
                indicator = v;
                ptr += 2;
            } else {
                indicator = (i32::from(buf[ptr]) >> 1) & 0xF;
                ptr += 1;
            }
            events.push(WireRxEvent::Indicator(indicator));
        }
        1 => {
            let data_type;
            if buf[ptr] & 0x20 != 0 {
                if ptr + 2 > pkt_len {
                    return Err(WireRxError::Truncated);
                }
                let v = DATA_EXT_BASE
                    + (((i32::from(buf[ptr]) << 2) & 0x3C)
                        | ((i32::from(buf[ptr + 1]) >> 6) & 0x3));
                if v > DATA_MAX {
                    return Err(WireRxError::Protocol);
                }
                data_type = v;
                ptr += 2;
            } else {
                data_type = (i32::from(buf[ptr]) >> 1) & 0xF;
                if data_type > DATA_MAX_BASE {
                    return Err(WireRxError::Protocol);
                }
                ptr += 1;
            }

            if !data_field_present {
                return Ok(ptr);
            }
            if ptr >= pkt_len {
                return Err(WireRxError::Truncated);
            }

            let count = usize::from(buf[ptr]);
            ptr += 1;

            let mut other_half = false;
            for _ in 0..count {
                if ptr >= pkt_len {
                    return Err(WireRxError::Truncated);
                }
                let field_data_present;
                let field_type;
                if t38_version == 0 {
                    if other_half {
                        field_data_present = (buf[ptr] >> 3) & 1 == 1;
                        field_type = i32::from(buf[ptr] & 0x7);
                        ptr += 1;
                        other_half = false;
                    } else {
                        field_data_present = (buf[ptr] >> 7) & 1 == 1;
                        field_type = (i32::from(buf[ptr]) >> 4) & 0x7;
                        if field_data_present {
                            ptr += 1;
                        } else {
                            other_half = true;
                        }
                        if field_type > FIELD_MAX_BASE {
                            return Err(WireRxError::Protocol);
                        }
                    }
                } else {
                    field_data_present = (buf[ptr] >> 7) & 1 == 1;
                    if buf[ptr] & 0x40 != 0 {
                        if ptr + 2 > pkt_len {
                            return Err(WireRxError::Truncated);
                        }
                        field_type = FIELD_EXT_BASE
                            + (((i32::from(buf[ptr]) << 2) & 0x3C)
                                | ((i32::from(buf[ptr + 1]) >> 6) & 0x3));
                        if field_type > FIELD_MAX {
                            return Err(WireRxError::Protocol);
                        }
                        ptr += 2;
                    } else {
                        field_type = (i32::from(buf[ptr]) >> 3) & 0x7;
                        ptr += 1;
                    }
                }

                let payload = if field_data_present {
                    if ptr + 2 > pkt_len {
                        return Err(WireRxError::Truncated);
                    }
                    let numocts = usize::from(u16::from_be_bytes([buf[ptr], buf[ptr + 1]])) + 1;
                    let end = ptr + 2 + numocts;
                    if end > pkt_len {
                        return Err(WireRxError::Truncated);
                    }
                    let payload = buf.slice(ptr + 2..end);
                    ptr = end;
                    payload
                } else {
                    Bytes::new()
                };
                events.push(WireRxEvent::Data {
                    data_type,
                    field_type,
                    payload,
                });
            }
            if other_half {
                ptr += 1;
            }
        }
        _ => return Err(WireRxError::Protocol),
    }
    if ptr > pkt_len {
        return Err(WireRxError::Truncated);
    }
    Ok(ptr)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WirePacket {
    Indicator(Vec<crate::t38::ifp::T30Indicator>),
    Data {
        data_type: u8,
        fields: Vec<WireDataField>,
    },
}

pub fn decode_wire(buf: &[u8]) -> Result<WirePacket, WireRxError> {
    decode_wire_bytes(Bytes::copy_from_slice(buf))
}

/// Zero-copy variant: field payloads are slices of `buf`.
pub fn decode_wire_bytes(buf: Bytes) -> Result<WirePacket, WireRxError> {
    let mut events = Vec::new();
    let consumed = rx_ifp_stream(3, &buf, &mut events)?;
    if consumed != buf.len() {
        return Err(WireRxError::BadLength);
    }
    match events.first() {
        Some(WireRxEvent::Indicator(ind)) => {
            let t =
                crate::t38::ifp::T30Indicator::from_u8(*ind as u8).ok_or(WireRxError::Protocol)?;
            Ok(WirePacket::Indicator(vec![t]))
        }
        Some(WireRxEvent::Data { data_type, .. }) => {
            let data_type = *data_type;

            let mut fields = Vec::with_capacity(events.len());
            for event in events {
                let WireRxEvent::Data {
                    field_type,
                    payload,
                    ..
                } = event
                else {
                    continue;
                };
                fields.push(WireDataField {
                    field_type,
                    data: payload,
                });
            }
            Ok(WirePacket::Data {
                data_type: data_type as u8,
                fields,
            })
        }

        Some(WireRxEvent::Missing { .. }) | None => Err(WireRxError::Protocol),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indicator_known_answers() {
        assert_eq!(
            encode_wire_indicator(3, 1).unwrap(),
            Bytes::from_static(&[0x02])
        );
        assert_eq!(
            encode_wire_indicator(3, 2).unwrap(),
            Bytes::from_static(&[0x04])
        );
        assert_eq!(
            encode_wire_indicator(3, 3).unwrap(),
            Bytes::from_static(&[0x06])
        );
        assert_eq!(
            encode_wire_indicator(3, 0).unwrap(),
            Bytes::from_static(&[0x00])
        );
        assert_eq!(
            encode_wire_indicator(3, 16).unwrap(),
            Bytes::from_static(&[0x20, 0x00])
        );
        assert_eq!(
            encode_wire_indicator(3, 22).unwrap(),
            Bytes::from_static(&[0x21, 0x80])
        );
        assert_eq!(encode_wire_indicator(0, 16), None);
        assert_eq!(encode_wire_indicator(3, 23), None);
    }

    #[test]
    fn data_known_answers() {
        assert_eq!(
            encode_wire_data(3, 0, &[WireDataField::new(0, vec![0xA5u8])],).unwrap(),
            Bytes::from_static(&[0xC0, 0x01, 0x80, 0x00, 0x00, 0xA5])
        );

        assert_eq!(
            encode_wire_data(3, 9, &[]).unwrap(),
            Bytes::from_static(&[0x60, 0x00])
        );

        assert_eq!(encode_wire_data(0, 9, &[]), None);
        assert_eq!(
            encode_wire_data(0, 0, &[WireDataField::new(8, Vec::new())]),
            None
        );

        assert_eq!(
            encode_wire_data(3, 14, &[WireDataField::new(11, vec![0xA5])]).unwrap(),
            Bytes::from_static(&[0xE1, 0x40, 0x01, 0xC0, 0xC0, 0x00, 0x00, 0xA5])
        );
    }

    #[test]
    fn count_two_octet_form() {
        let fields: Vec<_> = (0..128)
            .map(|i| WireDataField::new(0, vec![i as u8; 3]))
            .collect();
        let enc = encode_wire_data(3, 0, &fields).unwrap();

        assert_eq!(&enc[..6], &[0xC0, 0x80, 0x80, 0x80, 0x00, 0x02]);
    }

    #[test]
    fn seq_state_machine() {
        let mut rx = T38CoreRx::new(3);

        assert_eq!(
            rx.feed(1000, &[0x02]).unwrap(),
            vec![WireRxEvent::Indicator(1)]
        );
        assert_eq!(
            rx.feed(1001, &[0x02]).unwrap(),
            vec![WireRxEvent::Indicator(1)]
        );

        assert!(rx.feed(1001, &[0x02]).unwrap().is_empty());

        assert!(rx.feed(1000, &[0x02]).unwrap().is_empty());

        assert_eq!(
            rx.feed(1004, &[0x02]).unwrap(),
            vec![
                WireRxEvent::Missing {
                    expected: 1002,
                    actual: 1004
                },
                WireRxEvent::Indicator(1),
            ]
        );

        assert_eq!(
            rx.feed(5000, &[0x02]).unwrap(),
            vec![
                WireRxEvent::Missing {
                    expected: -1,
                    actual: -1
                },
                WireRxEvent::Indicator(1),
            ]
        );
    }

    #[test]
    fn seq_rollover() {
        let mut rx = T38CoreRx::new(3);
        assert_eq!(
            rx.feed(65535, &[0x02]).unwrap(),
            vec![WireRxEvent::Indicator(1)]
        );

        assert_eq!(
            rx.feed(0, &[0x02]).unwrap(),
            vec![WireRxEvent::Indicator(1)]
        );

        let mut rx = T38CoreRx::new(3);
        assert_eq!(
            rx.feed(65535, &[0x02]).unwrap(),
            vec![WireRxEvent::Indicator(1)]
        );
        let ev = rx.feed(1, &[0x02]).unwrap();
        assert!(matches!(
            &ev[..],
            [
                WireRxEvent::Missing {
                    expected: 0,
                    actual: 1
                },
                WireRxEvent::Indicator(1)
            ]
        ));
    }

    #[test]
    fn v0_nibble_quirk() {
        let bytes = [0xC0, 0x01, 0x70];
        let mut rx = T38CoreRx::new(0);
        let ev = rx.feed(0, &bytes).unwrap();
        assert_eq!(
            ev,
            vec![WireRxEvent::Data {
                data_type: 0,
                field_type: 7,
                payload: Bytes::new()
            }]
        );
    }

    #[test]
    fn decode_wire_typed() {
        let pkt = decode_wire(&[0x02]).unwrap();
        assert_eq!(
            pkt,
            WirePacket::Indicator(vec![crate::t38::ifp::T30Indicator::Cng])
        );
        let bytes = encode_wire_data(3, 0, &[WireDataField::new(2, vec![1, 2, 3])]).unwrap();
        let pkt = decode_wire(&bytes).unwrap();
        assert_eq!(
            pkt,
            WirePacket::Data {
                data_type: 0,
                fields: vec![WireDataField::new(2, vec![1, 2, 3])]
            }
        );
        assert!(decode_wire(&[0x02, 0x00]).is_err());
    }

    #[test]
    fn decode_wire_preserves_all_fields() {
        let fields = vec![
            WireDataField::new(0, vec![0x01u8]),
            WireDataField::new(2, vec![0xFF, 0xFF, 0x13]),
            WireDataField::new(7, Vec::<u8>::new()),
        ];
        let bytes = encode_wire_data(3, 0, &fields).unwrap();
        let WirePacket::Data {
            data_type,
            fields: got,
        } = decode_wire(&bytes).unwrap()
        else {
            panic!("expected data packet");
        };
        assert_eq!(data_type, 0);
        assert_eq!(got, fields);
    }

    #[test]
    fn truncation_sweep_never_panics() {
        let fields: Vec<_> = (0..5u8)
            .map(|i| WireDataField::new((i % 8) as i32, vec![i; (i % 4) as usize + 1]))
            .collect();
        let bytes = encode_wire_data(3, 4, &fields).unwrap();
        for cut in 0..=bytes.len() {
            let slice = &bytes[..cut];
            let _ = decode_wire(slice);
            let mut rx = T38CoreRx::new(3);
            let _ = rx.feed(0, slice);
            let mut rx0 = T38CoreRx::new(0);
            let _ = rx0.feed(0, slice);
        }

        assert!(decode_wire(&bytes).is_ok());
    }

    #[test]
    fn random_garbage_never_panics() {
        let mut state = 0x9E37_79B9_7F4A_7C15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for _ in 0..10_000 {
            let len = (next() % 65) as usize;
            let buf: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let _ = decode_wire(&buf);
            let mut rx = T38CoreRx::new((next() & 1) as u8);
            let _ = rx.feed((next() % 65536) as u16, &buf);
        }
    }

    #[test]
    fn encode_fragmentation_encodes_each_field_once() {
        let fields: Vec<_> = (0..20_000u32)
            .map(|i| WireDataField::new(0, vec![(i & 0xFF) as u8; 3]))
            .collect();
        let bytes = encode_wire_data(3, 0, &fields).unwrap();

        assert_eq!(bytes.len(), 1 + 3 + 20_000 * 6);

        let count = bytes.windows(2).filter(|w| *w == [0x00, 0x02]).count();
        assert_eq!(count, 20_000);
    }
}
