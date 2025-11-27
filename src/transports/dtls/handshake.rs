use super::record::ProtocolVersion;
use anyhow::{Result, bail};
use bytes::{Buf, BufMut, Bytes, BytesMut};
use tracing::trace;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    HelloRequest = 0,
    ClientHello = 1,
    ServerHello = 2,
    HelloVerifyRequest = 3,
    Certificate = 11,
    ServerKeyExchange = 12,
    CertificateRequest = 13,
    ServerHelloDone = 14,
    CertificateVerify = 15,
    ClientKeyExchange = 16,
    Finished = 20,
}

impl TryFrom<u8> for HandshakeType {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(HandshakeType::HelloRequest),
            1 => Ok(HandshakeType::ClientHello),
            2 => Ok(HandshakeType::ServerHello),
            3 => Ok(HandshakeType::HelloVerifyRequest),
            11 => Ok(HandshakeType::Certificate),
            12 => Ok(HandshakeType::ServerKeyExchange),
            13 => Ok(HandshakeType::CertificateRequest),
            14 => Ok(HandshakeType::ServerHelloDone),
            15 => Ok(HandshakeType::CertificateVerify),
            16 => Ok(HandshakeType::ClientKeyExchange),
            20 => Ok(HandshakeType::Finished),
            _ => bail!("Invalid HandshakeType: {}", value),
        }
    }
}

#[derive(Debug, Clone)]
pub struct HandshakeMessage {
    pub msg_type: HandshakeType,
    pub message_seq: u16,
    pub fragment_offset: u32, // 24-bit
    pub fragment_length: u32, // 24-bit
    pub body: Bytes,
}

impl HandshakeMessage {
    pub const HEADER_SIZE: usize = 12;

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.msg_type as u8);

        // Length (24-bit) - length of the body (not fragment)
        // For simple non-fragmented messages, this is body.len()
        let len = self.body.len() as u32;
        buf.put_u8((len >> 16) as u8);
        buf.put_u8((len >> 8) as u8);
        buf.put_u8(len as u8);

        buf.put_u16(self.message_seq);

        buf.put_u8((self.fragment_offset >> 16) as u8);
        buf.put_u8((self.fragment_offset >> 8) as u8);
        buf.put_u8(self.fragment_offset as u8);

        buf.put_u8((self.fragment_length >> 16) as u8);
        buf.put_u8((self.fragment_length >> 8) as u8);
        buf.put_u8(self.fragment_length as u8);

        buf.put_slice(&self.body);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Option<Self>> {
        if buf.len() < Self::HEADER_SIZE {
            return Ok(None);
        }

        let msg_type = HandshakeType::try_from(buf[0])?;

        let _length = u32::from_be_bytes([0, buf[1], buf[2], buf[3]]);
        let message_seq = u16::from_be_bytes([buf[4], buf[5]]);
        let fragment_offset = u32::from_be_bytes([0, buf[6], buf[7], buf[8]]);
        let fragment_length = u32::from_be_bytes([0, buf[9], buf[10], buf[11]]);

        if buf.len() < Self::HEADER_SIZE + fragment_length as usize {
            return Ok(None);
        }

        buf.advance(Self::HEADER_SIZE);
        let body = buf.split_to(fragment_length as usize);

        Ok(Some(Self {
            msg_type,
            message_seq,
            fragment_offset,
            fragment_length,
            body,
        }))
    }
}

#[derive(Debug, Clone)]
pub struct Random {
    pub gmt_unix_time: u32,
    pub random_bytes: [u8; 28],
}

impl Default for Random {
    fn default() -> Self {
        Self::new()
    }
}

impl Random {
    pub fn new() -> Self {
        use std::time::{SystemTime, UNIX_EPOCH};
        let start = SystemTime::now();
        let since_the_epoch = start.duration_since(UNIX_EPOCH).unwrap();
        let gmt_unix_time = since_the_epoch.as_secs() as u32;

        let mut random_bytes = [0u8; 28];
        use rand_core::{OsRng, RngCore};
        OsRng.fill_bytes(&mut random_bytes);

        Self {
            gmt_unix_time,
            random_bytes,
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u32(self.gmt_unix_time);
        buf.put_slice(&self.random_bytes);
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = BytesMut::new();
        self.encode(&mut buf);
        buf.to_vec()
    }
}

#[derive(Debug, Clone)]
pub struct ClientHello {
    pub version: ProtocolVersion,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cookie: Vec<u8>,
    pub cipher_suites: Vec<u16>,
    pub compression_methods: Vec<u8>,
    pub extensions: Vec<u8>,
}

impl ClientHello {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version.major);
        buf.put_u8(self.version.minor);

        self.random.encode(buf);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u8(self.cookie.len() as u8);
        buf.put_slice(&self.cookie);

        buf.put_u16((self.cipher_suites.len() * 2) as u16);
        for suite in &self.cipher_suites {
            buf.put_u16(*suite);
        }

        buf.put_u8(self.compression_methods.len() as u8);
        buf.put_slice(&self.compression_methods);

        if !self.extensions.is_empty() {
            buf.put_u16(self.extensions.len() as u16);
            buf.put_slice(&self.extensions);
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 34 {
            // Version(2) + Random(32)
            bail!("ClientHello too short");
        }

        let major = buf.get_u8();
        let minor = buf.get_u8();
        let version = ProtocolVersion { major, minor };

        let gmt_unix_time = buf.get_u32();
        let mut random_bytes = [0u8; 28];
        buf.copy_to_slice(&mut random_bytes);
        let random = Random {
            gmt_unix_time,
            random_bytes,
        };

        let session_id_len = buf.get_u8() as usize;
        if buf.len() < session_id_len {
            bail!("ClientHello too short for session_id");
        }
        let session_id = buf.split_to(session_id_len).to_vec();

        if buf.is_empty() {
            bail!("ClientHello too short for cookie length");
        }
        let cookie_len = buf.get_u8() as usize;
        if buf.len() < cookie_len {
            bail!("ClientHello too short for cookie");
        }
        let cookie = buf.split_to(cookie_len).to_vec();

        if buf.len() < 2 {
            bail!("ClientHello too short for cipher suites length");
        }
        let cipher_suites_len = buf.get_u16() as usize;
        if buf.len() < cipher_suites_len {
            bail!("ClientHello too short for cipher suites");
        }
        let mut cipher_suites = Vec::new();
        let mut cs_buf = buf.split_to(cipher_suites_len);
        while cs_buf.len() >= 2 {
            cipher_suites.push(cs_buf.get_u16());
        }

        if buf.is_empty() {
            bail!("ClientHello too short for compression methods length");
        }
        let compression_methods_len = buf.get_u8() as usize;
        if buf.len() < compression_methods_len {
            bail!("ClientHello too short for compression methods");
        }
        let compression_methods = buf.split_to(compression_methods_len).to_vec();

        let extensions = if buf.len() >= 2 {
            let ext_len = buf.get_u16() as usize;
            if buf.len() < ext_len {
                bail!("ClientHello too short for extensions");
            }
            buf.split_to(ext_len).to_vec()
        } else {
            vec![]
        };

        Ok(Self {
            version,
            random,
            session_id,
            cookie,
            cipher_suites,
            compression_methods,
            extensions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct ServerHello {
    pub version: ProtocolVersion,
    pub random: Random,
    pub session_id: Vec<u8>,
    pub cipher_suite: u16,
    pub compression_method: u8,
    pub extensions: Vec<u8>,
}

impl ServerHello {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version.major);
        buf.put_u8(self.version.minor);

        self.random.encode(buf);

        buf.put_u8(self.session_id.len() as u8);
        buf.put_slice(&self.session_id);

        buf.put_u16(self.cipher_suite);
        buf.put_u8(self.compression_method);

        if !self.extensions.is_empty() {
            buf.put_u16(self.extensions.len() as u16);
            buf.put_slice(&self.extensions);
        }
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 34 {
            // Version(2) + Random(32)
            bail!("ServerHello too short");
        }

        let major = buf.get_u8();
        let minor = buf.get_u8();
        let version = ProtocolVersion { major, minor };

        let gmt_unix_time = buf.get_u32();
        let mut random_bytes = [0u8; 28];
        buf.copy_to_slice(&mut random_bytes);
        let random = Random {
            gmt_unix_time,
            random_bytes,
        };

        let session_id_len = buf.get_u8() as usize;
        if buf.len() < session_id_len {
            bail!("ServerHello too short for session_id");
        }
        let session_id = buf.split_to(session_id_len).to_vec();

        if buf.len() < 3 {
            bail!("ServerHello too short for cipher suite and compression");
        }
        let cipher_suite = buf.get_u16();
        let compression_method = buf.get_u8();

        let extensions = if buf.len() >= 2 {
            let ext_len = buf.get_u16() as usize;
            if buf.len() < ext_len {
                bail!("ServerHello too short for extensions");
            }
            buf.split_to(ext_len).to_vec()
        } else {
            vec![]
        };

        Ok(Self {
            version,
            random,
            session_id,
            cipher_suite,
            compression_method,
            extensions,
        })
    }
}

#[derive(Debug, Clone)]
pub struct HelloVerifyRequest {
    pub version: ProtocolVersion,
    pub cookie: Vec<u8>,
}

impl HelloVerifyRequest {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_u8(self.version.major);
        buf.put_u8(self.version.minor);
        buf.put_u8(self.cookie.len() as u8);
        buf.put_slice(&self.cookie);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 3 {
            bail!("HelloVerifyRequest too short");
        }
        let major = buf.get_u8();
        let minor = buf.get_u8();
        let version = ProtocolVersion { major, minor };

        let cookie_len = buf.get_u8() as usize;
        if buf.len() < cookie_len {
            bail!("HelloVerifyRequest too short for cookie");
        }
        let cookie = buf.split_to(cookie_len).to_vec();

        Ok(Self { version, cookie })
    }
}

#[derive(Debug, Clone)]
pub struct ServerHelloDone {}

impl ServerHelloDone {
    pub fn encode(&self, _buf: &mut BytesMut) {
        // Empty body
    }
}

#[derive(Debug, Clone)]
pub struct ServerKeyExchange {
    pub curve_type: u8,
    pub named_curve: u16,
    pub public_key: Vec<u8>,
    pub signature: Vec<u8>,
}

impl ServerKeyExchange {
    pub fn encode(&self, buf: &mut BytesMut) {
        let start_len = buf.len();
        trace!(
            "Encoding ServerKeyExchange: curve_type={}, named_curve={}, pubkey_len={}, sig_len={}",
            self.curve_type,
            self.named_curve,
            self.public_key.len(),
            self.signature.len()
        );
        buf.put_u8(self.curve_type);
        buf.put_u16(self.named_curve);
        buf.put_u8(self.public_key.len() as u8);
        buf.put_slice(&self.public_key);

        // Signature and Hash Algorithm
        // SHA256
        buf.put_u8(4);
        // ECDSA
        buf.put_u8(3);

        buf.put_u16(self.signature.len() as u16);
        buf.put_slice(&self.signature);

        let end_len = buf.len();
        let encoded = &buf[start_len..end_len];
        trace!("Encoded ServerKeyExchange bytes: {:02X?}", encoded);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        if buf.len() < 4 {
            bail!("ServerKeyExchange too short");
        }
        let curve_type = buf.get_u8();
        let named_curve = buf.get_u16();

        let public_key_len = buf.get_u8() as usize;
        if buf.len() < public_key_len {
            bail!("ServerKeyExchange too short for public key");
        }
        let public_key = buf.split_to(public_key_len).to_vec();

        if buf.len() < 4 {
            bail!("ServerKeyExchange too short for signature header");
        }
        let _hash_algo = buf.get_u8();
        let _sig_algo = buf.get_u8();

        let sig_len = buf.get_u16() as usize;
        if buf.len() < sig_len {
            bail!("ServerKeyExchange too short for signature");
        }
        let signature = buf.split_to(sig_len).to_vec();

        Ok(Self {
            curve_type,
            named_curve,
            public_key,
            signature,
        })
    }
}

#[derive(Debug, Clone)]
pub struct CertificateMessage {
    pub certificates: Vec<Vec<u8>>,
}

impl CertificateMessage {
    pub fn encode(&self, buf: &mut BytesMut) {
        let mut total_len = 0;
        for cert in &self.certificates {
            total_len += 3 + cert.len(); // 3 bytes for length + cert data
        }

        buf.put_u24(total_len as u32);

        for cert in &self.certificates {
            buf.put_u24(cert.len() as u32);
            buf.put_slice(cert);
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientKeyExchange {
    pub identity_hint: Vec<u8>,
    pub public_key: Vec<u8>,
}

impl ClientKeyExchange {
    pub fn encode(&self, buf: &mut BytesMut) {
        if !self.identity_hint.is_empty() {
            buf.put_u16(self.identity_hint.len() as u16);
            buf.put_slice(&self.identity_hint);
        }

        buf.put_u8(self.public_key.len() as u8);
        buf.put_slice(&self.public_key);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        // For ECDH:
        if buf.is_empty() {
            bail!("ClientKeyExchange too short");
        }
        trace!("ClientKeyExchange raw body: {:?}", buf);
        let public_key_len = buf.get_u8() as usize;
        if buf.len() < public_key_len {
            bail!("ClientKeyExchange too short for public key");
        }
        let public_key = buf.split_to(public_key_len).to_vec();

        Ok(Self {
            identity_hint: vec![], // TODO: Parse identity hint if present
            public_key,
        })
    }
}

#[derive(Debug, Clone)]
pub struct Finished {
    pub verify_data: Vec<u8>,
}

impl Finished {
    pub fn encode(&self, buf: &mut BytesMut) {
        buf.put_slice(&self.verify_data);
    }

    pub fn decode(buf: &mut Bytes) -> Result<Self> {
        let verify_data = buf.to_vec();
        buf.advance(verify_data.len());
        Ok(Self { verify_data })
    }
}

trait BufMutExt {
    fn put_u24(&mut self, n: u32);
}

impl<T: BufMut> BufMutExt for T {
    fn put_u24(&mut self, n: u32) {
        self.put_u8((n >> 16) as u8);
        self.put_u8((n >> 8) as u8);
        self.put_u8(n as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_handshake_message_encode_decode() {
        let msg = HandshakeMessage {
            msg_type: HandshakeType::ClientHello,
            message_seq: 1,
            fragment_offset: 0,
            fragment_length: 5,
            body: Bytes::from_static(b"hello"),
        };

        let mut buf = BytesMut::new();
        msg.encode(&mut buf);

        let mut decode_buf = buf.freeze();
        let decoded = HandshakeMessage::decode(&mut decode_buf).unwrap().unwrap();

        assert_eq!(decoded.msg_type, msg.msg_type);
        assert_eq!(decoded.message_seq, msg.message_seq);
        assert_eq!(decoded.fragment_offset, msg.fragment_offset);
        assert_eq!(decoded.fragment_length, msg.fragment_length);
        assert_eq!(decoded.body, msg.body);
    }

    #[test]
    fn test_client_hello_encode() {
        let client_hello = ClientHello {
            version: ProtocolVersion::DTLS_1_2,
            random: Random::new(),
            session_id: vec![1, 2, 3],
            cookie: vec![4, 5],
            cipher_suites: vec![0xC02B],
            compression_methods: vec![0],
            extensions: vec![],
        };

        let mut buf = BytesMut::new();
        client_hello.encode(&mut buf);

        assert!(buf.len() > 0);
        // Basic length check:
        // Version (2) + Random (32) + SessionID Len (1) + SessionID (3) +
        // Cookie Len (1) + Cookie (2) + CipherSuites Len (2) + CipherSuites (2) +
        // CompressionMethods Len (1) + CompressionMethods (1) = 47 bytes
        assert_eq!(buf.len(), 47);
    }

    #[test]
    fn test_server_hello_encode() {
        let server_hello = ServerHello {
            version: ProtocolVersion::DTLS_1_2,
            random: Random::new(),
            session_id: vec![1, 2, 3, 4],
            cipher_suite: 0xC02B,
            compression_method: 0,
            extensions: vec![],
        };

        let mut buf = BytesMut::new();
        server_hello.encode(&mut buf);

        assert!(buf.len() > 0);
        // Basic length check:
        // Version (2) + Random (32) + SessionID Len (1) + SessionID (4) +
        // CipherSuite (2) + CompressionMethod (1) = 42 bytes
        assert_eq!(buf.len(), 42);
    }
}
