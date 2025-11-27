use anyhow::{Result, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentType {
    ChangeCipherSpec = 20,
    Alert = 21,
    Handshake = 22,
    ApplicationData = 23,
    Heartbeat = 24,
}

impl TryFrom<u8> for ContentType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            20 => Ok(ContentType::ChangeCipherSpec),
            21 => Ok(ContentType::Alert),
            22 => Ok(ContentType::Handshake),
            23 => Ok(ContentType::ApplicationData),
            24 => Ok(ContentType::Heartbeat),
            _ => bail!("Invalid ContentType: {}", value),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProtocolVersion {
    pub major: u8,
    pub minor: u8,
}

impl ProtocolVersion {
    pub const DTLS_1_0: Self = Self {
        major: 254,
        minor: 255,
    };
    pub const DTLS_1_2: Self = Self {
        major: 254,
        minor: 253,
    };
}

#[derive(Debug, Clone)]
pub struct DtlsRecord {
    pub content_type: ContentType,
    pub version: ProtocolVersion,
    pub epoch: u16,
    pub sequence_number: u64, // 48-bit
    pub payload: Bytes,
}

impl DtlsRecord {
    pub const HEADER_SIZE: usize = 13;

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.content_type as u8);
        buf.put_u8(self.version.major);
        buf.put_u8(self.version.minor);
        buf.put_u16(self.epoch);

        // 48-bit sequence number
        buf.put_u8((self.sequence_number >> 40) as u8);
        buf.put_u8((self.sequence_number >> 32) as u8);
        buf.put_u8((self.sequence_number >> 24) as u8);
        buf.put_u8((self.sequence_number >> 16) as u8);
        buf.put_u8((self.sequence_number >> 8) as u8);
        buf.put_u8(self.sequence_number as u8);

        buf.put_u16(self.payload.len() as u16);
        buf.put_slice(&self.payload);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Option<Self>> {
        if buf.len() < Self::HEADER_SIZE {
            return Ok(None);
        }

        let content_type = ContentType::try_from(buf[0])?;
        let major = buf[1];
        let minor = buf[2];
        let version = ProtocolVersion { major, minor };

        let epoch = u16::from_be_bytes([buf[3], buf[4]]);

        let mut seq_bytes = [0u8; 8];
        seq_bytes[2..8].copy_from_slice(&buf[5..11]);
        let sequence_number = u64::from_be_bytes(seq_bytes);

        let length = u16::from_be_bytes([buf[11], buf[12]]) as usize;

        if buf.len() < Self::HEADER_SIZE + length {
            return Ok(None);
        }

        buf.advance(Self::HEADER_SIZE);
        let payload = buf.split_to(length);

        Ok(Some(Self {
            content_type,
            version,
            epoch,
            sequence_number,
            payload,
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dtls_record_encode_decode() {
        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::DTLS_1_2,
            epoch: 1,
            sequence_number: 12345,
            payload: Bytes::from_static(b"hello world"),
        };

        let mut buf = BytesMut::new();
        record.encode(&mut buf);

        let mut decode_buf = buf.freeze();
        let decoded = DtlsRecord::decode(&mut decode_buf).unwrap().unwrap();

        assert_eq!(decoded.content_type, record.content_type);
        assert_eq!(decoded.version, record.version);
        assert_eq!(decoded.epoch, record.epoch);
        assert_eq!(decoded.sequence_number, record.sequence_number);
        assert_eq!(decoded.payload, record.payload);
    }
}
