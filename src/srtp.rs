use crate::{
    errors::{SrtpError, SrtpResult},
    rtp::RtpPacket,
};
use aes::Aes128;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use ctr::cipher::{KeyIvInit, StreamCipher, generic_array::GenericArray};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrtpProfile {
    Aes128Sha1_80,
    Aes128Sha1_32,
    AeadAes128Gcm,
    #[default]
    NullCipherHmac,
}

impl SrtpProfile {
    fn tag_len(&self) -> usize {
        match self {
            Self::Aes128Sha1_80 | Self::NullCipherHmac => 10,
            Self::Aes128Sha1_32 => 4,
            Self::AeadAes128Gcm => 16,
        }
    }

    fn salt_len(&self) -> usize {
        match self {
            Self::AeadAes128Gcm => 12,
            _ => 14,
        }
    }

    fn key_len(&self) -> usize {
        16
    }
}

#[derive(Debug, Clone)]
pub struct SrtpKeyingMaterial {
    pub master_key: Vec<u8>,
    pub master_salt: Vec<u8>,
}

impl SrtpKeyingMaterial {
    pub fn new(master_key: Vec<u8>, master_salt: Vec<u8>) -> Self {
        Self {
            master_key,
            master_salt,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SrtpDirection {
    Sender,
    Receiver,
}

pub struct SrtpSession {
    profile: SrtpProfile,
    tx_keying: SrtpKeyingMaterial,
    rx_keying: SrtpKeyingMaterial,
    tx_contexts: HashMap<u32, SrtpContext>,
    rx_contexts: HashMap<u32, SrtpContext>,
}

impl SrtpSession {
    pub fn new(
        profile: SrtpProfile,
        tx_keying: SrtpKeyingMaterial,
        rx_keying: SrtpKeyingMaterial,
    ) -> Result<Self, SrtpError> {
        Ok(Self {
            profile,
            tx_keying,
            rx_keying,
            tx_contexts: HashMap::new(),
            rx_contexts: HashMap::new(),
        })
    }

    pub fn protect_rtp(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        let ssrc = packet.header.ssrc;
        let ctx = self.tx_contexts.entry(ssrc).or_insert_with(|| {
            SrtpContext::new(
                ssrc,
                self.profile,
                self.tx_keying.clone(),
                SrtpDirection::Sender,
            ).unwrap()
        });
        ctx.protect(packet)
    }

    pub fn unprotect_rtp(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        let ssrc = packet.header.ssrc;
        let ctx = self.rx_contexts.entry(ssrc).or_insert_with(|| {
            SrtpContext::new(
                ssrc,
                self.profile,
                self.rx_keying.clone(),
                SrtpDirection::Receiver,
            ).unwrap()
        });
        ctx.unprotect(packet)
    }
}

#[derive(Debug, Clone)]
pub struct SrtpContext {
    ssrc: u32,
    _profile: SrtpProfile,
    cipher_key: Vec<u8>,
    auth_key: Vec<u8>,
    salt: Vec<u8>,
    direction: SrtpDirection,
    rollover_counter: u32,
    last_sequence: Option<u16>,
}

impl SrtpContext {
    pub fn new(
        ssrc: u32,
        profile: SrtpProfile,
        keying: SrtpKeyingMaterial,
        direction: SrtpDirection,
    ) -> SrtpResult<Self> {
        if keying.master_key.len() < profile.key_len()
            || keying.master_salt.len() < profile.salt_len()
        {
            return Err(SrtpError::UnsupportedProfile);
        }
        let cipher_key = keying.master_key.clone();
        let auth_key = keying.master_key.clone();
        let salt = keying.master_salt.clone();
        Ok(Self {
            ssrc,
            _profile: profile,
            cipher_key,
            auth_key,
            salt,
            direction,
            rollover_counter: 0,
            last_sequence: None,
        })
    }

    pub fn protect(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        self.update_rollover(packet.header.sequence_number);

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(packet.header.sequence_number);
            let cipher = Aes128Gcm::new_from_slice(&self.cipher_key)
                .map_err(|_| SrtpError::UnsupportedProfile)?;

            // For GCM, AAD is the RTP header.
            // We need to marshal the header to get bytes for AAD.
            // Note: packet.marshal() includes payload, but we only want header.
            // We can temporarily clear payload to marshal header, or implement header marshal.
            // Since RtpHeader doesn't expose marshal publicly in a way we can use easily without payload,
            // we can use packet.marshal() with empty payload.
            let original_payload = std::mem::take(&mut packet.payload);
            let aad = packet.marshal()?;
            packet.payload = original_payload;

            let payload = Payload {
                msg: &packet.payload,
                aad: &aad,
            };

            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?; // Encryption failure usually means something else but mapping to AuthFailed for now or add new error

            packet.payload = ciphertext;
            return Ok(());
        }

        self.cipher_payload(packet)?;
        let auth_input = packet.marshal()?;
        let tag = self.auth_tag(&auth_input)?;
        packet.payload.extend_from_slice(&tag);
        Ok(())
    }

    pub fn unprotect(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        let tag_len = self._profile.tag_len();
        if packet.payload.len() < tag_len {
            return Err(SrtpError::PacketTooShort);
        }

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(packet.header.sequence_number);
            let cipher = Aes128Gcm::new_from_slice(&self.cipher_key)
                .map_err(|_| SrtpError::UnsupportedProfile)?;

            // Separate payload (ciphertext + tag) from header for AAD
            let original_payload = std::mem::take(&mut packet.payload);
            let aad = packet.marshal()?;
            packet.payload = original_payload;

            let payload = Payload {
                msg: &packet.payload,
                aad: &aad,
            };

            let plaintext = cipher
                .decrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?;

            packet.payload = plaintext;
            self.update_rollover(packet.header.sequence_number);
            return Ok(());
        }

        let split = packet.payload.len() - tag_len;
        let tag = packet.payload[split..].to_vec();
        packet.payload.truncate(split);
        let auth_input = packet.marshal()?;
        let expected = self.auth_tag(&auth_input)?;
        if !constant_time_eq(&tag, &expected) {
            return Err(SrtpError::AuthenticationFailed);
        }
        self.cipher_payload(packet)?;
        self.update_rollover(packet.header.sequence_number);
        Ok(())
    }

    fn cipher_payload(&self, packet: &mut RtpPacket) -> SrtpResult<()> {
        if packet.payload.is_empty() {
            return Ok(());
        }
        match self._profile {
            SrtpProfile::NullCipherHmac => Ok(()),
            SrtpProfile::Aes128Sha1_80 | SrtpProfile::Aes128Sha1_32 => {
                let iv = self.build_iv(packet.header.sequence_number);
                let mut cipher = Aes128Ctr::new(
                    GenericArray::from_slice(&self.cipher_key[..16]),
                    GenericArray::from_slice(&iv),
                );
                cipher.apply_keystream(&mut packet.payload);
                Ok(())
            }
            SrtpProfile::AeadAes128Gcm => Ok(()), // Handled in protect/unprotect
        }
    }

    fn auth_tag(&self, data: &[u8]) -> SrtpResult<Vec<u8>> {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.auth_key)
            .map_err(|_| SrtpError::UnsupportedProfile)?;
        mac.update(data);
        mac.update(&self.rollover_counter.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let tag_len = self._profile.tag_len();
        Ok(result[..tag_len].to_vec())
    }

    fn build_gcm_nonce(&self, sequence: u16) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&self.salt[..12]);

        let mut block = [0u8; 12];
        block[2..6].copy_from_slice(&self.ssrc.to_be_bytes());
        block[6..10].copy_from_slice(&self.rollover_counter.to_be_bytes());
        block[10..12].copy_from_slice(&sequence.to_be_bytes());

        for i in 0..12 {
            iv[i] ^= block[i];
        }
        iv
    }

    fn build_iv(&self, sequence: u16) -> [u8; 16] {
        let index = ((self.rollover_counter as u64) << 16) | sequence as u64;
        let mut iv = [0u8; 16];
        for (i, byte) in self.salt.iter().enumerate().take(14) {
            iv[i] = *byte;
        }
        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        block[8..16].copy_from_slice(&index.to_be_bytes());
        for i in 0..16 {
            iv[i] ^= block[i];
        }
        iv
    }

    fn update_rollover(&mut self, sequence: u16) {
        if let Some(last) = self.last_sequence {
            if sequence < last {
                self.rollover_counter = self.rollover_counter.saturating_add(1);
            }
        }
        self.last_sequence = Some(sequence);
    }

    pub fn ssrc(&self) -> u32 {
        self.ssrc
    }

    pub fn direction(&self) -> SrtpDirection {
        self.direction
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rtp::{RtpHeader, RtpPacket};

    fn sample_packet(seq: u16) -> RtpPacket {
        let header = RtpHeader::new(96, seq, 1234, 0xdead_beef);
        RtpPacket::new(header, vec![1, 2, 3])
    }

    fn material() -> SrtpKeyingMaterial {
        SrtpKeyingMaterial::new(vec![0; 16], vec![0; 14])
    }

    #[test]
    fn protect_and_unprotect_roundtrip() {
        let mut session =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut packet = sample_packet(1);
        let original = packet.payload.clone();
        session.protect_rtp(&mut packet).unwrap();
        assert_eq!(packet.payload.len(), original.len() + 10);
        assert_ne!(packet.payload[..original.len()], original[..]);
        session.unprotect_rtp(&mut packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn protect_and_unprotect_roundtrip_gcm() {
        let mut session =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        let mut packet = sample_packet(1);
        let original = packet.payload.clone();
        session.protect_rtp(&mut packet).unwrap();
        assert_eq!(packet.payload.len(), original.len() + 16);
        assert_ne!(packet.payload[..original.len()], original[..]);
        session.unprotect_rtp(&mut packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn authentication_failure_returns_error() {
        let mut ctx = SrtpContext::new(
            42,
            SrtpProfile::Aes128Sha1_80,
            material(),
            SrtpDirection::Receiver,
        )
        .unwrap();
        let mut packet = sample_packet(1);
        ctx.protect(&mut packet).unwrap();
        packet.payload[0] ^= 0xFF;
        let err = ctx.unprotect(&mut packet).unwrap_err();
        assert!(matches!(err, SrtpError::AuthenticationFailed));
    }

    #[test]
    fn null_cipher_still_authenticates() {
        let mut ctx = SrtpContext::new(
            7,
            SrtpProfile::NullCipherHmac,
            material(),
            SrtpDirection::Sender,
        )
        .unwrap();
        let mut packet = sample_packet(10);
        ctx.protect(&mut packet).unwrap();
        assert_eq!(packet.payload.len(), 3 + 10);
    }
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}
