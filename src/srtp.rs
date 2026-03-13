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
use std::fmt;

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

    fn auth_key_len(&self) -> usize {
        match self {
            Self::Aes128Sha1_80 | Self::NullCipherHmac => 20,
            Self::Aes128Sha1_32 => 20,
            Self::AeadAes128Gcm => 0, // GCM doesn't use separate auth key
        }
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
            )
            .unwrap()
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
            )
            .unwrap()
        });
        ctx.unprotect(packet)
    }

    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        if packet.len() < 8 {
            return Err(SrtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let ctx = self.tx_contexts.entry(ssrc).or_insert_with(|| {
            SrtpContext::new(
                ssrc,
                self.profile,
                self.tx_keying.clone(),
                SrtpDirection::Sender,
            )
            .unwrap()
        });
        ctx.protect_rtcp(packet)
    }

    pub fn unprotect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        if packet.len() < 14 {
            // Header(8) + Index(4) + Tag(>=2)
            return Err(SrtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        let ctx = self.rx_contexts.entry(ssrc).or_insert_with(|| {
            SrtpContext::new(
                ssrc,
                self.profile,
                self.rx_keying.clone(),
                SrtpDirection::Receiver,
            )
            .unwrap()
        });
        ctx.unprotect_rtcp(packet)
    }
}

#[derive(Debug, Clone)]
struct SessionKeys {
    cipher_key: Vec<u8>,
    auth_key: Vec<u8>,
    salt: Vec<u8>,
}

#[derive(Debug, Clone, Default)]
struct ReplayWindow {
    max_index: Option<u64>,
    bitmap: u64,
}

impl ReplayWindow {
    fn check_and_accept(&mut self, index: u64) -> SrtpResult<()> {
        let Some(max_index) = self.max_index else {
            self.max_index = Some(index);
            self.bitmap = 1;
            return Ok(());
        };

        if index > max_index {
            let delta = index - max_index;
            // Jumping past the full bitmap discards all older history at once.
            self.bitmap = if delta >= u64::BITS as u64 {
                1
            } else {
                (self.bitmap << (delta as u32)) | 1
            };
            self.max_index = Some(index);
            return Ok(());
        }

        let delta = max_index - index;
        if delta >= u64::BITS as u64 {
            return Err(SrtpError::PacketTooOld);
        }

        let mask = 1u64 << (delta as u32);
        if self.bitmap & mask != 0 {
            return Err(SrtpError::ReplayDetected);
        }

        self.bitmap |= mask;
        Ok(())
    }
}

#[derive(Clone)]
pub struct SrtpContext {
    ssrc: u32,
    _profile: SrtpProfile,
    rtp_keys: SessionKeys,
    rtcp_keys: SessionKeys,
    rtp_gcm_cipher: Option<Aes128Gcm>,
    rtcp_gcm_cipher: Option<Aes128Gcm>,
    rtp_auth_prototype: Option<HmacSha1>,
    direction: SrtpDirection,
    rollover_counter: u32,
    last_sequence: Option<u16>,
    rtp_replay_window: ReplayWindow,
    next_rtcp_index: u32,
    rtcp_replay_window: ReplayWindow,
}

impl fmt::Debug for SrtpContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SrtpContext")
            .field("ssrc", &self.ssrc)
            .field("_profile", &self._profile)
            .field("direction", &self.direction)
            .field("rollover_counter", &self.rollover_counter)
            .finish()
    }
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

        let (rtp_keys, rtcp_keys) = Self::derive_keys(profile, &keying)?;

        let rtp_gcm_cipher = if let SrtpProfile::AeadAes128Gcm = profile {
            Some(
                Aes128Gcm::new_from_slice(&rtp_keys.cipher_key)
                    .map_err(|_| SrtpError::UnsupportedProfile)?,
            )
        } else {
            None
        };

        let rtcp_gcm_cipher = if let SrtpProfile::AeadAes128Gcm = profile {
            Some(
                Aes128Gcm::new_from_slice(&rtcp_keys.cipher_key)
                    .map_err(|_| SrtpError::UnsupportedProfile)?,
            )
        } else {
            None
        };

        let rtp_auth_prototype = if !rtp_keys.auth_key.is_empty() {
            Some(
                <HmacSha1 as Mac>::new_from_slice(&rtp_keys.auth_key)
                    .map_err(|_| SrtpError::UnsupportedProfile)?,
            )
        } else {
            None
        };

        Ok(Self {
            ssrc,
            _profile: profile,
            rtp_keys,
            rtcp_keys,
            rtp_gcm_cipher,
            rtcp_gcm_cipher,
            rtp_auth_prototype,
            direction,
            rollover_counter: 0,
            last_sequence: None,
            rtp_replay_window: ReplayWindow::default(),
            next_rtcp_index: 0,
            rtcp_replay_window: ReplayWindow::default(),
        })
    }

    fn derive_keys(
        profile: SrtpProfile,
        keying: &SrtpKeyingMaterial,
    ) -> SrtpResult<(SessionKeys, SessionKeys)> {
        let key_len = profile.key_len();
        let salt_len = profile.salt_len();
        let auth_len = profile.auth_key_len();

        // RTP Keys
        let rtp_cipher = Self::kdf(key_len, 0x00, &keying.master_key, &keying.master_salt)?;
        let rtp_auth = if auth_len > 0 {
            Self::kdf(auth_len, 0x01, &keying.master_key, &keying.master_salt)?
        } else {
            Vec::new()
        };
        let rtp_salt = Self::kdf(salt_len, 0x02, &keying.master_key, &keying.master_salt)?;

        // RTCP Keys
        let rtcp_cipher = Self::kdf(key_len, 0x03, &keying.master_key, &keying.master_salt)?;
        let rtcp_auth = if auth_len > 0 {
            Self::kdf(auth_len, 0x04, &keying.master_key, &keying.master_salt)?
        } else {
            Vec::new()
        };
        let rtcp_salt = Self::kdf(salt_len, 0x05, &keying.master_key, &keying.master_salt)?;

        Ok((
            SessionKeys {
                cipher_key: rtp_cipher,
                auth_key: rtp_auth,
                salt: rtp_salt,
            },
            SessionKeys {
                cipher_key: rtcp_cipher,
                auth_key: rtcp_auth,
                salt: rtcp_salt,
            },
        ))
    }

    fn kdf(len: usize, label: u8, master_key: &[u8], master_salt: &[u8]) -> SrtpResult<Vec<u8>> {
        // RFC 3711 Section 4.3. Key Derivation
        // AES-CM PRF
        // x = (label << 48) XOR master_salt
        // We assume r=0 (index) for session keys.

        let mut iv = [0u8; 16];
        // Copy salt (14 bytes)
        for (i, &b) in master_salt.iter().take(14).enumerate() {
            iv[i] = b;
        }

        // XOR label into byte 7 (see discussion on bit layout)
        // This matches libsrtp and other implementations for the standard layout
        iv[7] ^= label;

        // Run AES-CM
        let mut out = vec![0u8; len];
        let mut cipher = Aes128Ctr::new(
            GenericArray::from_slice(&master_key[..16]),
            GenericArray::from_slice(&iv),
        );
        cipher.apply_keystream(&mut out);

        Ok(out)
    }

    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        self.next_rtcp_index += 1;
        let index = self.next_rtcp_index;
        // E-bit = 1 (Encrypted)
        let index_with_e = index | 0x8000_0000;

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_rtcp_nonce(index);
            let cipher = self
                .rtcp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;

            // AAD = Header (8 bytes) || Index (4 bytes, WITH E-bit)
            let mut aad = Vec::with_capacity(12);
            aad.extend_from_slice(&packet[..8]);
            aad.extend_from_slice(&index_with_e.to_be_bytes());

            // Payload = Packet body (after header)
            let payload_data = &packet[8..];

            let payload = Payload {
                msg: payload_data,
                aad: &aad,
            };

            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?;

            // Reconstruct packet: Header || Ciphertext || Index
            packet.truncate(8);
            packet.extend_from_slice(&ciphertext);
            packet.extend_from_slice(&index_with_e.to_be_bytes());

            return Ok(());
        }

        // Encrypt payload (everything after first 8 bytes of header)
        // RFC 3711: The first 8 octets of the RTCP header are not encrypted.
        if packet.len() > 8 {
            self.cipher_rtcp(packet, index)?;
        }

        // Append SRTCP Index
        packet.extend_from_slice(&index_with_e.to_be_bytes());

        // Authenticate
        let tag = self.auth_tag_rtcp(packet)?;
        packet.extend_from_slice(&tag);

        Ok(())
    }

    pub fn unprotect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        let tag_len = self._profile.tag_len();
        if packet.len() < tag_len + 4 {
            return Err(SrtpError::PacketTooShort);
        }

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            // Read Index
            let index_bytes = &packet[packet.len() - 4..];
            let index_with_e = u32::from_be_bytes([
                index_bytes[0],
                index_bytes[1],
                index_bytes[2],
                index_bytes[3],
            ]);
            let index = index_with_e & 0x7FFF_FFFF;

            let nonce = self.build_gcm_rtcp_nonce(index);
            let cipher = self
                .rtcp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;

            // AAD = Header (8 bytes) || Index (4 bytes, WITH E-bit)
            let mut aad = Vec::with_capacity(12);
            aad.extend_from_slice(&packet[..8]);
            aad.extend_from_slice(&index_with_e.to_be_bytes());

            // Ciphertext = Packet body (after header, before index)
            // Note: Tag is appended to ciphertext in GCM encrypt output.
            // So Ciphertext + Tag is what we have between Header and Index.
            let ciphertext_and_tag = &packet[8..packet.len() - 4];

            let payload = Payload {
                msg: ciphertext_and_tag,
                aad: &aad,
            };

            let plaintext = cipher
                .decrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?;

            // Reconstruct packet: Header || Plaintext
            packet.truncate(8);
            packet.extend_from_slice(&plaintext);
            self.rtcp_replay_window.check_and_accept(index as u64)?;

            return Ok(());
        }

        // Split tag
        let split = packet.len() - tag_len;
        let tag = packet[split..].to_vec();
        packet.truncate(split);

        // Verify tag
        let expected = self.auth_tag_rtcp(packet)?;
        if !constant_time_eq(&tag, &expected) {
            return Err(SrtpError::AuthenticationFailed);
        }

        // Read Index
        let index_bytes = &packet[packet.len() - 4..];
        let index_with_e = u32::from_be_bytes([
            index_bytes[0],
            index_bytes[1],
            index_bytes[2],
            index_bytes[3],
        ]);
        packet.truncate(packet.len() - 4);

        let e_bit = (index_with_e & 0x8000_0000) != 0;
        let index = index_with_e & 0x7FFF_FFFF;

        if e_bit && packet.len() > 8 {
            self.cipher_rtcp(packet, index)?;
        }

        self.rtcp_replay_window.check_and_accept(index as u64)?;

        Ok(())
    }

    fn cipher_rtcp(&self, packet: &mut [u8], index: u32) -> SrtpResult<()> {
        // IV = (salt << 16) XOR (SSRC << 64) XOR (SRTCP_INDEX << 16)
        // Actually:
        // IV = (k_s * 2^16) XOR (SSRC * 2^64) XOR (SRTCP_INDEX * 2^16)

        let mut iv = [0u8; 16];
        for (i, &b) in self.rtcp_keys.salt.iter().take(14).enumerate() {
            iv[i] = b;
        }

        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        block[10..14].copy_from_slice(&index.to_be_bytes());

        for i in 0..16 {
            iv[i] ^= block[i];
        }

        // Keystream
        let mut cipher = Aes128Ctr::new(
            GenericArray::from_slice(&self.rtcp_keys.cipher_key[..16]),
            GenericArray::from_slice(&iv),
        );

        // Encrypt/Decrypt payload (offset 8)
        cipher.apply_keystream(&mut packet[8..]);

        Ok(())
    }

    fn auth_tag_rtcp(&self, data: &[u8]) -> SrtpResult<Vec<u8>> {
        let mut mac = <HmacSha1 as Mac>::new_from_slice(&self.rtcp_keys.auth_key)
            .map_err(|_| SrtpError::UnsupportedProfile)?;
        mac.update(data);
        let result = mac.finalize().into_bytes();
        let tag_len = self._profile.tag_len();
        Ok(result[..tag_len].to_vec())
    }

    pub fn protect(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        let roc = self.estimate_roc(packet.header.sequence_number);

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(packet.header.sequence_number, roc);
            let cipher = self
                .rtp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;

            // For GCM, AAD is the RTP header.
            let original_payload = std::mem::take(&mut packet.payload);
            let aad = packet.marshal()?;
            packet.payload = original_payload;

            let payload = Payload {
                msg: &packet.payload,
                aad: &aad,
            };

            let ciphertext = cipher
                .encrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?;

            packet.payload = ciphertext;
            self.update(packet.header.sequence_number, roc);
            return Ok(());
        }

        self.cipher_payload(packet, roc)?;
        let auth_input = packet.marshal()?;
        let tag = self.auth_tag(&auth_input, roc)?;
        packet.payload.extend_from_slice(&tag);
        self.update(packet.header.sequence_number, roc);
        Ok(())
    }

    pub fn unprotect(&mut self, packet: &mut RtpPacket) -> SrtpResult<()> {
        let tag_len = self._profile.tag_len();
        if packet.payload.len() < tag_len {
            return Err(SrtpError::PacketTooShort);
        }

        let roc = self.estimate_roc(packet.header.sequence_number);
        let packet_index = Self::packet_index(packet.header.sequence_number, roc);

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(packet.header.sequence_number, roc);
            let cipher = self
                .rtp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;

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
            self.rtp_replay_window.check_and_accept(packet_index)?;
            self.update(packet.header.sequence_number, roc);
            return Ok(());
        }

        let split = packet.payload.len() - tag_len;
        let tag = packet.payload[split..].to_vec();
        packet.payload.truncate(split);
        let auth_input = packet.marshal()?;
        let expected = self.auth_tag(&auth_input, roc)?;
        if !constant_time_eq(&tag, &expected) {
            return Err(SrtpError::AuthenticationFailed);
        }
        self.cipher_payload(packet, roc)?;
        self.rtp_replay_window.check_and_accept(packet_index)?;
        self.update(packet.header.sequence_number, roc);
        Ok(())
    }

    fn cipher_payload(&self, packet: &mut RtpPacket, roc: u32) -> SrtpResult<()> {
        if packet.payload.is_empty() {
            return Ok(());
        }
        match self._profile {
            SrtpProfile::NullCipherHmac => Ok(()),
            SrtpProfile::Aes128Sha1_80 | SrtpProfile::Aes128Sha1_32 => {
                let iv = self.build_iv(packet.header.sequence_number, roc);
                let mut cipher = Aes128Ctr::new(
                    GenericArray::from_slice(&self.rtp_keys.cipher_key[..16]),
                    GenericArray::from_slice(&iv),
                );
                cipher.apply_keystream(&mut packet.payload);
                Ok(())
            }
            _ => Err(SrtpError::UnsupportedProfile),
        }
    }

    fn auth_tag(&self, data: &[u8], roc: u32) -> SrtpResult<Vec<u8>> {
        let mut mac = self
            .rtp_auth_prototype
            .as_ref()
            .ok_or(SrtpError::UnsupportedProfile)?
            .clone();
        mac.update(data);
        mac.update(&roc.to_be_bytes());
        let result = mac.finalize().into_bytes();
        let tag_len = self._profile.tag_len();
        Ok(result[..tag_len].to_vec())
    }

    fn build_gcm_rtcp_nonce(&self, index: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&self.rtcp_keys.salt[..12]);

        let mut block = [0u8; 12];
        block[2..6].copy_from_slice(&self.ssrc.to_be_bytes());
        block[8..12].copy_from_slice(&index.to_be_bytes());

        for i in 0..12 {
            iv[i] ^= block[i];
        }
        iv
    }

    fn build_gcm_nonce(&self, sequence: u16, roc: u32) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv.copy_from_slice(&self.rtp_keys.salt[..12]);

        let mut block = [0u8; 12];
        block[2..6].copy_from_slice(&self.ssrc.to_be_bytes());
        block[6..10].copy_from_slice(&roc.to_be_bytes());
        block[10..12].copy_from_slice(&sequence.to_be_bytes());

        for i in 0..12 {
            iv[i] ^= block[i];
        }
        iv
    }

    fn build_iv(&self, sequence: u16, roc: u32) -> [u8; 16] {
        let index = Self::packet_index(sequence, roc);
        let mut iv = [0u8; 16];
        for (i, byte) in self.rtp_keys.salt.iter().enumerate().take(14) {
            iv[i] = *byte;
        }
        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        // IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (Index * 2^16)
        // We need to shift index left by 16 bits.
        let iv_part = index << 16;
        block[8..16].copy_from_slice(&iv_part.to_be_bytes());

        for i in 0..16 {
            iv[i] ^= block[i];
        }
        iv
    }

    fn packet_index(sequence: u16, roc: u32) -> u64 {
        ((roc as u64) << 16) | sequence as u64
    }

    fn estimate_roc(&self, sequence: u16) -> u32 {
        let Some(last_seq) = self.last_sequence else {
            return self.rollover_counter;
        };

        let roc = self.rollover_counter;
        let diff = (sequence as i32) - (last_seq as i32);

        if diff < -32768 {
            roc.wrapping_add(1)
        } else if diff > 32768 {
            roc.wrapping_sub(1)
        } else {
            roc
        }
    }

    fn update(&mut self, sequence: u16, roc: u32) {
        if self.last_sequence.is_none() {
            self.last_sequence = Some(sequence);
            self.rollover_counter = roc;
            return;
        }

        let current_index =
            ((self.rollover_counter as u64) << 16) | (self.last_sequence.unwrap() as u64);
        let new_index = Self::packet_index(sequence, roc);

        if new_index > current_index {
            self.rollover_counter = roc;
            self.last_sequence = Some(sequence);
        }
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

    #[test]
    fn roc_rollover_handling() {
        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();

        // Send packet near rollover
        let mut p1 = sample_packet(65535);
        sender.protect_rtp(&mut p1).unwrap();

        // Send packet after rollover
        let mut p2 = sample_packet(0);
        sender.protect_rtp(&mut p2).unwrap();

        // Receive in order
        receiver.unprotect_rtp(&mut p1).unwrap();
        receiver.unprotect_rtp(&mut p2).unwrap();
    }

    #[test]
    fn roc_rollover_reordered() {
        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();

        // Send p0 (seq 50000) to sync
        let mut p0 = sample_packet(50000);
        sender.protect_rtp(&mut p0).unwrap();
        receiver.unprotect_rtp(&mut p0).unwrap();

        // Send packet near rollover
        let mut p1 = sample_packet(65535);
        sender.protect_rtp(&mut p1).unwrap();

        // Send packet after rollover
        let mut p2 = sample_packet(0);
        sender.protect_rtp(&mut p2).unwrap();

        // Receive out of order: p2 (seq 0) then p1 (seq 65535)

        let mut p1_recv = p1.clone();
        let mut p2_recv = p2.clone();

        receiver.unprotect_rtp(&mut p2_recv).unwrap();
        receiver.unprotect_rtp(&mut p1_recv).unwrap();
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
