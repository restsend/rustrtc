use anyhow::{Result, bail};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tracing::trace;

const MAGIC_COOKIE: u32 = 0x2112A442;
const FINGERPRINT_XOR: u32 = 0x5354_554e;

type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone)]
pub struct StunMessage {
    pub class: StunClass,
    pub method: StunMethod,
    pub transaction_id: [u8; 12],
    pub attributes: Vec<StunAttribute>,
}

impl StunMessage {
    pub fn binding_request(transaction_id: [u8; 12], software: Option<&str>) -> Self {
        let mut attrs = Vec::new();
        if let Some(name) = software {
            attrs.push(StunAttribute::Software(name.to_string()));
        }
        Self {
            class: StunClass::Request,
            method: StunMethod::Binding,
            transaction_id,
            attributes: attrs,
        }
    }

    pub fn binding_success_response(transaction_id: [u8; 12], xor_addr: SocketAddr) -> Self {
        Self {
            class: StunClass::SuccessResponse,
            method: StunMethod::Binding,
            transaction_id,
            attributes: vec![StunAttribute::XorMappedAddress(xor_addr)],
        }
    }

    pub fn allocate_request(transaction_id: [u8; 12], attributes: Vec<StunAttribute>) -> Self {
        Self {
            class: StunClass::Request,
            method: StunMethod::Allocate,
            transaction_id,
            attributes,
        }
    }

    pub fn encode(&self, integrity_key: Option<&[u8]>, fingerprint: bool) -> Result<Vec<u8>> {
        encode_stun_message(self, integrity_key, fingerprint)
    }

    pub fn decode(data: &[u8]) -> Result<StunDecoded> {
        decode_stun_message(data)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StunMethod {
    Binding,
    Allocate,
    CreatePermission,
    Send,
    Data,
}

#[derive(Debug, Clone)]
pub enum StunAttribute {
    Username(String),
    Realm(String),
    Nonce(String),
    Software(String),
    RequestedTransport(u8),
    Lifetime(u32),
    Priority(u32),
    IceControlling(u64),
    IceControlled(u64),
    UseCandidate,
    XorPeerAddress(SocketAddr),
    XorMappedAddress(SocketAddr),
    Data(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct StunDecoded {
    pub class: StunClass,
    pub method: StunMethod,
    pub transaction_id: [u8; 12],
    pub xor_mapped_address: Option<SocketAddr>,
    pub xor_relayed_address: Option<SocketAddr>,
    pub xor_peer_address: Option<SocketAddr>,
    pub error_code: Option<u16>,
    pub realm: Option<String>,
    pub nonce: Option<String>,
    pub data: Option<Vec<u8>>,
    pub use_candidate: bool,
}

fn encode_stun_message(
    msg: &StunMessage,
    integrity_key: Option<&[u8]>,
    fingerprint: bool,
) -> Result<Vec<u8>> {
    let mut buffer = vec![0u8; 20];
    let method_bits = match msg.method {
        StunMethod::Binding => 0x0001,
        StunMethod::Allocate => 0x0003,
        StunMethod::CreatePermission => 0x0008,
        StunMethod::Send => 0x0006,
        StunMethod::Data => 0x0007,
    };
    let class_bits = match msg.class {
        StunClass::Request => 0x0000,
        StunClass::Indication => 0x0010,
        StunClass::SuccessResponse => 0x0100,
        StunClass::ErrorResponse => 0x0110,
    };
    let msg_type = method_bits | class_bits;
    buffer[0..2].copy_from_slice(&(msg_type as u16).to_be_bytes());
    buffer[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buffer[8..20].copy_from_slice(&msg.transaction_id);

    for attr in &msg.attributes {
        append_attribute(&mut buffer, attr, &msg.transaction_id);
    }

    update_length_field(&mut buffer);

    if let Some(key) = integrity_key {
        // RFC 5389: The length field in the STUN header MUST contain the length of the message
        // up to, and including, the MESSAGE-INTEGRITY attribute itself.
        // MI attribute is 4 bytes header + 20 bytes value = 24 bytes.
        let len_including_mi = (buffer.len() - 20) + 24;
        write_length_field(&mut buffer, len_including_mi);

        trace!("HMAC key: {:?}", String::from_utf8_lossy(key));
        let hmac = hmac_sha1(key, &buffer);
        append_raw_attribute(&mut buffer, 0x0008, &hmac);
        update_length_field(&mut buffer);
    }

    if fingerprint {
        // RFC 5389: The Message Length field in the STUN header MUST contain the length
        // of the message up to, and including, the FINGERPRINT attribute.
        // Fingerprint attribute is 4 bytes header + 4 bytes value = 8 bytes.
        let len_including_fp = (buffer.len() - 20) + 8;
        write_length_field(&mut buffer, len_including_fp);

        let crc = crc32(&buffer) ^ FINGERPRINT_XOR;
        append_raw_attribute(&mut buffer, 0x8028, &crc.to_be_bytes());
    }

    update_length_field(&mut buffer);

    Ok(buffer)
}

fn append_attribute(buffer: &mut Vec<u8>, attr: &StunAttribute, tx_id: &[u8; 12]) {
    match attr {
        StunAttribute::Username(value) => append_string_attr(buffer, 0x0006, value),
        StunAttribute::Realm(value) => append_string_attr(buffer, 0x0014, value),
        StunAttribute::Nonce(value) => append_string_attr(buffer, 0x0015, value),
        StunAttribute::Software(value) => append_string_attr(buffer, 0x8022, value),
        StunAttribute::RequestedTransport(v) => {
            buffer.extend_from_slice(&0x0019u16.to_be_bytes());
            buffer.extend_from_slice(&4u16.to_be_bytes());
            buffer.push(*v);
            buffer.extend_from_slice(&[0u8; 3]);
        }
        StunAttribute::Lifetime(value) => {
            buffer.extend_from_slice(&0x000Du16.to_be_bytes());
            buffer.extend_from_slice(&4u16.to_be_bytes());
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        StunAttribute::Priority(value) => {
            buffer.extend_from_slice(&0x0024u16.to_be_bytes());
            buffer.extend_from_slice(&4u16.to_be_bytes());
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        StunAttribute::IceControlling(value) => {
            buffer.extend_from_slice(&0x802Au16.to_be_bytes());
            buffer.extend_from_slice(&8u16.to_be_bytes());
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        StunAttribute::IceControlled(value) => {
            buffer.extend_from_slice(&0x8029u16.to_be_bytes());
            buffer.extend_from_slice(&8u16.to_be_bytes());
            buffer.extend_from_slice(&value.to_be_bytes());
        }
        StunAttribute::UseCandidate => {
            buffer.extend_from_slice(&0x0025u16.to_be_bytes());
            buffer.extend_from_slice(&0u16.to_be_bytes());
        }
        StunAttribute::XorPeerAddress(addr) => {
            append_xor_address(buffer, 0x0012, addr, tx_id);
            return;
        }
        StunAttribute::XorMappedAddress(addr) => {
            append_xor_address(buffer, 0x0020, addr, tx_id);
            return;
        }
        StunAttribute::Data(value) => append_raw_attribute(buffer, 0x0013, value),
    }
    pad_four_bytes(buffer);
}

fn append_string_attr(buffer: &mut Vec<u8>, typ: u16, value: &str) {
    append_raw_attribute(buffer, typ, value.as_bytes());
}

fn append_raw_attribute(buffer: &mut Vec<u8>, typ: u16, value: &[u8]) {
    buffer.extend_from_slice(&typ.to_be_bytes());
    buffer.extend_from_slice(&(value.len() as u16).to_be_bytes());
    buffer.extend_from_slice(value);
    pad_four_bytes(buffer);
}

fn append_xor_address(buffer: &mut Vec<u8>, typ: u16, addr: &SocketAddr, tx_id: &[u8; 12]) {
    match addr {
        SocketAddr::V4(v4) => {
            buffer.extend_from_slice(&typ.to_be_bytes());
            buffer.extend_from_slice(&8u16.to_be_bytes());
            buffer.push(0);
            buffer.push(0x01);
            let mut port = v4.port();
            port ^= (MAGIC_COOKIE >> 16) as u16;
            buffer.extend_from_slice(&port.to_be_bytes());
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for (i, byte) in v4.ip().octets().iter().enumerate() {
                buffer.push(byte ^ cookie[i]);
            }
        }
        SocketAddr::V6(v6) => {
            buffer.extend_from_slice(&typ.to_be_bytes());
            buffer.extend_from_slice(&20u16.to_be_bytes());
            buffer.push(0);
            buffer.push(0x02);
            let mut port = v6.port();
            port ^= (MAGIC_COOKIE >> 16) as u16;
            buffer.extend_from_slice(&port.to_be_bytes());
            let cookie = MAGIC_COOKIE.to_be_bytes();
            let segments = v6.ip().octets();
            for i in 0..4 {
                buffer.push(segments[i] ^ cookie[i]);
            }
            for i in 0..12 {
                buffer.push(segments[4 + i] ^ tx_id[i]);
            }
        }
    }
    pad_four_bytes(buffer);
}

fn pad_four_bytes(buffer: &mut Vec<u8>) {
    let pad = (4 - (buffer.len() % 4)) % 4;
    buffer.extend(std::iter::repeat_n(0, pad));
}

fn update_length_field(buffer: &mut [u8]) {
    let length = buffer.len() - 20;
    write_length_field(buffer, length);
}

fn write_length_field(buffer: &mut [u8], length: usize) {
    buffer[2..4].copy_from_slice(&(length as u16).to_be_bytes());
}

fn decode_stun_message(bytes: &[u8]) -> Result<StunDecoded> {
    if bytes.len() < 20 {
        bail!("STUN message too short");
    }
    let msg_type = u16::from_be_bytes([bytes[0], bytes[1]]);
    let length = u16::from_be_bytes([bytes[2], bytes[3]]) as usize;
    if length + 20 != bytes.len() {
        bail!("STUN message length mismatch");
    }
    let method = match msg_type & 0x3EEF {
        0x0001 => StunMethod::Binding,
        0x0003 => StunMethod::Allocate,
        0x0008 => StunMethod::CreatePermission,
        0x0006 => StunMethod::Send,
        0x0007 => StunMethod::Data,
        _ => bail!("unsupported STUN method"),
    };
    let class = match msg_type & 0x0110 {
        0x0000 => StunClass::Request,
        0x0010 => StunClass::Indication,
        0x0100 => StunClass::SuccessResponse,
        0x0110 => StunClass::ErrorResponse,
        _ => bail!("unsupported STUN class"),
    };
    let mut transaction_id = [0u8; 12];
    transaction_id.copy_from_slice(&bytes[8..20]);
    let mut offset = 20;
    let mut xor_mapped_address = None;
    let mut xor_relayed_address = None;
    let mut xor_peer_address = None;
    let mut error_code = None;
    let mut realm = None;
    let mut nonce = None;
    let mut data = None;
    let mut use_candidate = false;
    while offset + 4 <= bytes.len() {
        let typ = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
        let len = u16::from_be_bytes([bytes[offset + 2], bytes[offset + 3]]) as usize;
        offset += 4;
        if offset + len > bytes.len() {
            break;
        }
        let value = &bytes[offset..offset + len];
        match typ {
            0x0020 => {
                if let Some(addr) = parse_xor_address(value, &transaction_id)? {
                    xor_mapped_address = Some(addr);
                }
            }
            0x0016 => {
                if let Some(addr) = parse_xor_address(value, &transaction_id)? {
                    xor_relayed_address = Some(addr);
                }
            }
            0x0012 => {
                if let Some(addr) = parse_xor_address(value, &transaction_id)? {
                    xor_peer_address = Some(addr);
                }
            }
            0x0009 => {
                if value.len() >= 4 {
                    let code = (value[2] as u16) * 100 + value[3] as u16;
                    error_code = Some(code);
                }
            }
            0x0014 => {
                if let Ok(text) = std::str::from_utf8(value) {
                    realm = Some(text.to_string());
                }
            }
            0x0015 => {
                if let Ok(text) = std::str::from_utf8(value) {
                    nonce = Some(text.to_string());
                }
            }
            0x0013 => {
                data = Some(value.to_vec());
            }
            0x0025 => {
                use_candidate = true;
            }
            _ => {}
        }
        offset += len;
        offset += (4 - (len % 4)) % 4;
    }
    Ok(StunDecoded {
        class,
        method,
        transaction_id,
        xor_mapped_address,
        xor_relayed_address,
        xor_peer_address,
        error_code,
        realm,
        nonce,
        data,
        use_candidate,
    })
}

fn parse_xor_address(value: &[u8], transaction_id: &[u8; 12]) -> Result<Option<SocketAddr>> {
    if value.len() < 4 {
        return Ok(None);
    }
    let family = value[1];
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    port ^= (MAGIC_COOKIE >> 16) as u16;
    match family {
        0x01 => {
            if value.len() < 8 {
                return Ok(None);
            }
            let mut addr = [0u8; 4];
            addr.copy_from_slice(&value[4..8]);
            let cookie = MAGIC_COOKIE.to_be_bytes();
            for i in 0..4 {
                addr[i] ^= cookie[i];
            }
            let ip = Ipv4Addr::from(addr);
            Ok(Some(SocketAddr::from((ip, port))))
        }
        0x02 => {
            if value.len() < 20 {
                return Ok(None);
            }
            let mut addr = [0u8; 16];
            addr.copy_from_slice(&value[4..20]);
            let cookie_bytes = MAGIC_COOKIE.to_be_bytes();
            for (i, byte) in addr.iter_mut().enumerate().take(4) {
                *byte ^= cookie_bytes[i];
            }
            for i in 0..12 {
                addr[4 + i] ^= transaction_id[i];
            }
            let ip = Ipv6Addr::from(addr);
            Ok(Some(SocketAddr::from((ip, port))))
        }
        _ => Ok(None),
    }
}

fn hmac_sha1(key: &[u8], data: &[u8]) -> [u8; 20] {
    let mut mac = HmacSha1::new_from_slice(key).expect("HMAC key init");
    mac.update(data);
    let result = mac.finalize().into_bytes();
    let mut output = [0u8; 20];
    output.copy_from_slice(&result);
    output
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        let mut x = (crc ^ (*byte as u32)) & 0xFF;
        for _ in 0..8 {
            let mask = -(x as i32 & 1) as u32;
            x = (x >> 1) ^ (0xEDB8_8320 & mask);
        }
        crc = (crc >> 8) ^ x;
    }
    !crc
}

use std::fs::File;
use std::io::{Read, Result as IoResult};
use std::time::{SystemTime, UNIX_EPOCH};

pub fn random_bytes<const N: usize>() -> [u8; N] {
    let mut buf = [0u8; N];
    if fill_random_from_urandom(&mut buf).is_err() {
        fallback_random(&mut buf);
    }
    buf
}

pub fn random_u64() -> u64 {
    u64::from_be_bytes(random_bytes::<8>())
}

pub fn random_u32() -> u32 {
    u32::from_be_bytes(random_bytes::<4>())
}

fn fill_random_from_urandom(buf: &mut [u8]) -> IoResult<()> {
    let mut file = File::open("/dev/urandom")?;
    file.read_exact(buf)
}

fn fallback_random(buf: &mut [u8]) {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut seed = now as u64;
    for byte in buf {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        *byte = (seed & 0xFF) as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crc32() {
        let data = b"123456789";
        assert_eq!(crc32(data), 0xCBF43926);
    }

    #[test]
    fn test_hmac_sha1() {
        let key = b"key";
        let data = b"The quick brown fox jumps over the lazy dog";
        let expected = [
            0xde, 0x7c, 0x9b, 0x85, 0xb8, 0xb7, 0x8a, 0xa6, 0xbc, 0x8a, 0x7a, 0x36, 0xf7, 0x0a,
            0x90, 0x70, 0x1c, 0x9d, 0xb4, 0xd9,
        ];
        assert_eq!(hmac_sha1(key, data), expected);
    }
}
