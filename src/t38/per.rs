use crate::errors::RtcResult;

/// ASN.1 PER (Packed Encoding Rules, aligned variant) encoder/decoder.
pub struct PerCodec;

impl PerCodec {
    /// Encode a boolean as 1 bit.
    pub fn encode_bool(val: bool, buf: &mut BitWriter) {
        buf.write_bit(val);
    }

    /// Decode a boolean from 1 bit.
    pub fn decode_bool(buf: &mut BitReader) -> RtcResult<bool> {
        buf.read_bit()
    }

    /// Encode an integer with range [min, max].
    /// Returns number of bits needed: ceil(log2(max - min + 1)).
    pub fn encode_int(val: u64, min: i64, max: i64, buf: &mut BitWriter) -> RtcResult<()> {
        if val < min as u64 || val > max as u64 {
            return Err(crate::errors::RtcError::Protocol(format!(
                "PER integer {} out of range [{}, {}]",
                val, min, max
            )));
        }
        let range = (max as i128 - min as i128 + 1) as u64;
        let bits = bits_needed(range);
        let offset = val - min as u64;
        if bits > 0 {
            buf.write_bits(offset, bits);
        }
        Ok(())
    }

    /// Decode an integer with range [min, max].
    pub fn decode_int(buf: &mut BitReader, min: i64, max: i64) -> RtcResult<u64> {
        let range = (max as i128 - min as i128 + 1) as u64;
        let bits = bits_needed(range);
        let offset = if bits > 0 { buf.read_bits(bits)? } else { 0 };
        Ok(offset + min as u64)
    }

    /// Encode an octet string with length prefix.
    pub fn encode_octet_string(data: &[u8], max_len: u16, buf: &mut BitWriter) -> RtcResult<()> {
        let len = data.len() as u16;
        if len > max_len {
            return Err(crate::errors::RtcError::Protocol(format!(
                "PER octet string length {} exceeds max {}",
                len, max_len
            )));
        }
        let len_bits = bits_needed(max_len as u64 + 1);
        if len_bits > 0 {
            buf.write_bits(len as u64, len_bits);
        }
        // Align to byte boundary before octet data
        buf.align();
        for &byte in data {
            buf.write_bits(byte as u64, 8);
        }
        Ok(())
    }

    /// Decode an octet string with length prefix.
    pub fn decode_octet_string(buf: &mut BitReader, max_len: u16) -> RtcResult<Vec<u8>> {
        let len_bits = bits_needed(max_len as u64 + 1);
        let len = if len_bits > 0 {
            buf.read_bits(len_bits)?
        } else {
            0
        } as usize;
        buf.align();
        let mut data = Vec::with_capacity(len);
        for _ in 0..len {
            data.push(buf.read_bits(8)? as u8);
        }
        Ok(data)
    }

    /// Encode a choice index (0-based) with the given number of choices.
    pub fn encode_choice_index(
        idx: usize,
        num_choices: usize,
        buf: &mut BitWriter,
    ) -> RtcResult<()> {
        if idx >= num_choices {
            return Err(crate::errors::RtcError::Protocol(format!(
                "PER choice index {} out of range [0, {})",
                idx, num_choices
            )));
        }
        let bits = bits_needed(num_choices as u64);
        if bits > 0 {
            buf.write_bits(idx as u64, bits);
        }
        Ok(())
    }

    /// Decode a choice index (0-based).
    pub fn decode_choice_index(buf: &mut BitReader, num_choices: usize) -> RtcResult<usize> {
        let bits = bits_needed(num_choices as u64);
        let idx = if bits > 0 {
            buf.read_bits(bits)? as usize
        } else {
            0
        };
        Ok(idx)
    }

    /// Encode a SEQUENCE OF length. `max` is the maximum allowed length (None = unbounded -> 16 bits).
    pub fn encode_length(len: usize, max: Option<usize>, buf: &mut BitWriter) -> RtcResult<()> {
        let limit = max.unwrap_or(65535);
        if len > limit {
            return Err(crate::errors::RtcError::Protocol(format!(
                "PER length {} exceeds limit {}",
                len, limit
            )));
        }
        let bits = bits_needed((limit + 1) as u64);
        if bits > 0 {
            buf.write_bits(len as u64, bits);
        }
        Ok(())
    }

    /// Decode a SEQUENCE OF length.
    pub fn decode_length(buf: &mut BitReader, max: Option<usize>) -> RtcResult<usize> {
        let limit = max.unwrap_or(65535);
        let bits = bits_needed((limit + 1) as u64);
        let len = if bits > 0 {
            buf.read_bits(bits)? as usize
        } else {
            0
        };
        Ok(len)
    }

    /// Encode a small-range integer directly in bits (no alignment).
    pub fn encode_small_int(val: u8, min: u8, max: u8, buf: &mut BitWriter) {
        let range = (max - min + 1) as u64;
        let bits = bits_needed(range);
        if bits > 0 {
            buf.write_bits((val - min) as u64, bits);
        }
    }

    /// Decode a small-range integer.
    pub fn decode_small_int(buf: &mut BitReader, min: u8, max: u8) -> u8 {
        let range = (max - min + 1) as u64;
        let bits = bits_needed(range);
        if bits > 0 {
            buf.read_bits(bits).unwrap_or(0) as u8 + min
        } else {
            min
        }
    }
}

/// Compute the minimum number of bits needed to represent `range` distinct values.
fn bits_needed(range: u64) -> usize {
    if range <= 1 {
        return 0;
    }
    let mut bits = 0;
    let mut r = range - 1;
    while r > 0 {
        bits += 1;
        r >>= 1;
    }
    bits
}

/// Bit-level writer (MSB first).
pub struct BitWriter {
    data: Vec<u8>,
    pos: usize, // bit position within data
}

impl Default for BitWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl BitWriter {
    pub fn new() -> Self {
        Self {
            data: Vec::new(),
            pos: 0,
        }
    }

    /// Write a single bit (0 or 1).
    pub fn write_bit(&mut self, bit: bool) {
        let byte_idx = self.pos >> 3;
        let bit_idx = 7 - (self.pos & 7);
        if byte_idx >= self.data.len() {
            self.data.push(0);
        }
        if bit {
            self.data[byte_idx] |= 1 << bit_idx;
        }
        self.pos += 1;
    }

    /// Write `count` bits of `val` (MSB first).
    pub fn write_bits(&mut self, val: u64, count: usize) {
        for i in (0..count).rev() {
            self.write_bit((val >> i) & 1 == 1);
        }
    }

    /// Align to next byte boundary (pad with zeros).
    pub fn align(&mut self) {
        let remainder = self.pos & 7;
        if remainder != 0 {
            let pad = 8 - remainder;
            for _ in 0..pad {
                self.write_bit(false);
            }
        }
    }

    /// Finalize and return the encoded byte buffer.
    pub fn into_bytes(self) -> Vec<u8> {
        let needed = (self.pos + 7) >> 3;
        let mut result = self.data;
        result.resize(needed, 0);
        result
    }

    /// Current bit position.
    pub fn bit_pos(&self) -> usize {
        self.pos
    }

    /// Current byte length (rounded up).
    pub fn byte_len(&self) -> usize {
        (self.pos + 7) >> 3
    }
}

/// Bit-level reader (MSB first).
pub struct BitReader {
    data: Vec<u8>,
    pos: usize, // bit position
}

impl BitReader {
    pub fn new(data: Vec<u8>) -> Self {
        Self { data, pos: 0 }
    }

    /// Read a single bit.
    pub fn read_bit(&mut self) -> RtcResult<bool> {
        let byte_idx = self.pos >> 3;
        let bit_idx = 7 - (self.pos & 7);
        if byte_idx >= self.data.len() {
            return Err(crate::errors::RtcError::Protocol(
                "PER: unexpected end of data".into(),
            ));
        }
        let bit = (self.data[byte_idx] >> bit_idx) & 1 == 1;
        self.pos += 1;
        Ok(bit)
    }

    /// Read `count` bits (MSB first), returns as u64.
    pub fn read_bits(&mut self, count: usize) -> RtcResult<u64> {
        let mut val = 0u64;
        for _ in 0..count {
            val = (val << 1) | (self.read_bit()? as u64);
        }
        Ok(val)
    }

    /// Align to next byte boundary.
    pub fn align(&mut self) {
        let remainder = self.pos & 7;
        if remainder != 0 {
            self.pos += 8 - remainder;
        }
    }

    /// Current bit position.
    pub fn bit_pos(&self) -> usize {
        self.pos
    }

    /// Remaining bits in the buffer.
    pub fn remaining_bits(&self) -> isize {
        (self.data.len() * 8) as isize - self.pos as isize
    }

    /// Whether we've reached the end.
    pub fn is_empty(&self) -> bool {
        self.remaining_bits() <= 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bit_writer_reader_basic() {
        let mut w = BitWriter::new();
        w.write_bit(true);
        w.write_bit(false);
        w.write_bit(true);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0b10100000]);

        let mut r = BitReader::new(bytes);
        assert_eq!(r.read_bit().unwrap(), true);
        assert_eq!(r.read_bit().unwrap(), false);
        assert_eq!(r.read_bit().unwrap(), true);
    }

    #[test]
    fn test_bit_writer_multi_byte() {
        let mut w = BitWriter::new();
        // Write 0xAB in 8 bits
        w.write_bits(0xAB, 8);
        // Write 0xCD in 8 bits
        w.write_bits(0xCD, 8);
        let bytes = w.into_bytes();
        assert_eq!(bytes, vec![0xAB, 0xCD]);

        let mut r = BitReader::new(bytes);
        assert_eq!(r.read_bits(8).unwrap(), 0xAB);
        assert_eq!(r.read_bits(8).unwrap(), 0xCD);
    }

    #[test]
    fn test_bits_needed() {
        assert_eq!(bits_needed(1), 0);
        assert_eq!(bits_needed(2), 1);
        assert_eq!(bits_needed(3), 2);
        assert_eq!(bits_needed(4), 2);
        assert_eq!(bits_needed(8), 3);
        assert_eq!(bits_needed(256), 8);
    }

    #[test]
    fn test_encode_decode_bool() {
        let mut w = BitWriter::new();
        PerCodec::encode_bool(true, &mut w);
        PerCodec::encode_bool(false, &mut w);
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        assert!(PerCodec::decode_bool(&mut r).unwrap());
        assert!(!PerCodec::decode_bool(&mut r).unwrap());
    }

    #[test]
    fn test_encode_decode_int() {
        // range [0, 15] -> 4 bits
        let mut w = BitWriter::new();
        PerCodec::encode_int(7, 0, 15, &mut w).unwrap();
        PerCodec::encode_int(0, 0, 15, &mut w).unwrap();
        PerCodec::encode_int(15, 0, 15, &mut w).unwrap();
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        assert_eq!(PerCodec::decode_int(&mut r, 0, 15).unwrap(), 7);
        assert_eq!(PerCodec::decode_int(&mut r, 0, 15).unwrap(), 0);
        assert_eq!(PerCodec::decode_int(&mut r, 0, 15).unwrap(), 15);
    }

    #[test]
    fn test_encode_decode_int_with_offset() {
        // range [5, 10] -> 3 bits (6 values)
        let mut w = BitWriter::new();
        PerCodec::encode_int(5, 5, 10, &mut w).unwrap();
        PerCodec::encode_int(7, 5, 10, &mut w).unwrap();
        PerCodec::encode_int(10, 5, 10, &mut w).unwrap();
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        assert_eq!(PerCodec::decode_int(&mut r, 5, 10).unwrap(), 5);
        assert_eq!(PerCodec::decode_int(&mut r, 5, 10).unwrap(), 7);
        assert_eq!(PerCodec::decode_int(&mut r, 5, 10).unwrap(), 10);
    }

    #[test]
    fn test_int_out_of_range() {
        let mut w = BitWriter::new();
        assert!(PerCodec::encode_int(16, 0, 15, &mut w).is_err());
    }

    #[test]
    fn test_encode_decode_octet_string() {
        let data = vec![0x01, 0x02, 0x03, 0x04];
        let mut w = BitWriter::new();
        PerCodec::encode_octet_string(&data, 255, &mut w).unwrap();
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        let decoded = PerCodec::decode_octet_string(&mut r, 255).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn test_encode_decode_choice_index() {
        // 3 choices -> 2 bits
        let mut w = BitWriter::new();
        PerCodec::encode_choice_index(1, 3, &mut w).unwrap();
        PerCodec::encode_choice_index(0, 3, &mut w).unwrap();
        PerCodec::encode_choice_index(2, 3, &mut w).unwrap();
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        assert_eq!(PerCodec::decode_choice_index(&mut r, 3).unwrap(), 1);
        assert_eq!(PerCodec::decode_choice_index(&mut r, 3).unwrap(), 0);
        assert_eq!(PerCodec::decode_choice_index(&mut r, 3).unwrap(), 2);
    }

    #[test]
    fn test_encode_decode_length() {
        let mut w = BitWriter::new();
        PerCodec::encode_length(5, Some(31), &mut w).unwrap();
        PerCodec::encode_length(0, Some(31), &mut w).unwrap();
        PerCodec::encode_length(31, Some(31), &mut w).unwrap();
        let bytes = w.into_bytes();

        let mut r = BitReader::new(bytes);
        assert_eq!(PerCodec::decode_length(&mut r, Some(31)).unwrap(), 5);
        assert_eq!(PerCodec::decode_length(&mut r, Some(31)).unwrap(), 0);
        assert_eq!(PerCodec::decode_length(&mut r, Some(31)).unwrap(), 31);
    }

    #[test]
    fn test_small_int_roundtrip() {
        for min in 0..=5u8 {
            for max in min..=min + 10 {
                for val in min..=max {
                    let mut w = BitWriter::new();
                    PerCodec::encode_small_int(val, min, max, &mut w);
                    let bytes = w.into_bytes();
                    let mut r = BitReader::new(bytes);
                    let decoded = PerCodec::decode_small_int(&mut r, min, max);
                    assert_eq!(decoded, val, "failed for val={} in [{}, {}]", val, min, max);
                }
            }
        }
    }

    #[test]
    fn test_align() {
        let mut w = BitWriter::new();
        w.write_bits(0xFF, 4); // 4 bits
        assert_eq!(w.bit_pos(), 4);
        w.align(); // pad to byte
        assert_eq!(w.bit_pos(), 8);
        w.write_bits(0xAB, 8);
        let bytes = w.into_bytes();
        assert_eq!(bytes.len(), 2);
        assert_eq!(bytes[1], 0xAB);
    }
}
