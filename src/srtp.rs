use crate::{
    errors::{SrtpError, SrtpResult},
    rtp::{RtpHeader, RtpPacket},
};
use aes::Aes128;
use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, AeadInPlace, KeyInit, Payload},
};
use bytes::BytesMut;
use ctr::cipher::{InnerIvInit, StreamCipher};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;

type Aes128Ctr = ctr::Ctr128BE<Aes128>;
type HmacSha1 = Hmac<Sha1>;

/// Maximum HMAC-SHA1 digest length (used for fixed-size auth-tag buffers).
const SHA1_LEN: usize = 20;

/// A received SRTP datagram split into its clear RTP header and protected body.
/// Unprotection consumes this value and returns a plaintext [`RtpPacket`].
#[derive(Debug)]
pub struct SrtpPacket {
    header: RtpHeader,
    body: BytesMut,
    has_padding: bool,
}

impl SrtpPacket {
    pub fn parse(mut raw: BytesMut) -> crate::errors::RtpResult<Self> {
        let (header, has_padding) = RtpHeader::parse(&mut raw)?;
        Ok(Self {
            header,
            body: raw,
            has_padding,
        })
    }

    pub fn header(&self) -> &RtpHeader {
        &self.header
    }

    fn marshal_header_into(&self, raw: &mut Vec<u8>) {
        raw.resize(self.header.encoded_len(), 0);
        self.header.write_to(self.has_padding, &mut raw[..]);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SrtpProfile {
    #[default]
    Aes128Sha1_80,
    Aes128Sha1_32,
    AeadAes128Gcm,
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

/// Above this many per-SSRC contexts, stale ones (not seen for
/// `SSRC_INACTIVITY_EVICT`) are evicted. Caps unbounded growth from SSRC churn
/// (re-INVITE, simulcast layer switch, SSRC collision, relay rewrite) while
/// staying well above realistic active-SSRC counts.
const SSRC_CONTEXT_HIGH_WATERMARK: usize = 32;
/// Inactivity threshold after which an SRTP context is considered stale and
/// eligible for eviction. A real media SSRC silent this long has almost
/// certainly ended (or rotated), so dropping its ROC state is safe.
const SSRC_INACTIVITY_EVICT: std::time::Duration = std::time::Duration::from_secs(60);

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

    pub fn protected_rtp_len(&self, packet: &RtpPacket) -> usize {
        packet.header.encoded_len()
            + packet.payload.len()
            + packet.padding_len as usize
            + self.profile.tag_len()
    }

    pub fn protect_rtp(&mut self, packet: &RtpPacket, output: &mut [u8]) -> SrtpResult<()> {
        let ssrc = packet.header.ssrc;
        self.evict_stale_tx(ssrc);
        let ctx = match self.tx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(SrtpContext::new(
                ssrc,
                self.profile,
                self.tx_keying.clone(),
                SrtpDirection::Sender,
            )?),
        };
        ctx.last_used = std::time::Instant::now();
        ctx.protect(packet, output)
    }

    pub fn unprotect_rtp(&mut self, packet: SrtpPacket) -> SrtpResult<RtpPacket> {
        let ssrc = packet.header.ssrc;
        self.evict_stale_rx(ssrc);
        let ctx = match self.rx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(SrtpContext::new(
                ssrc,
                self.profile,
                self.rx_keying.clone(),
                SrtpDirection::Receiver,
            )?),
        };
        ctx.last_used = std::time::Instant::now();
        ctx.unprotect(packet)
    }

    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        if packet.len() < 8 {
            return Err(SrtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        self.evict_stale_tx(ssrc);
        let ctx = match self.tx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(SrtpContext::new(
                ssrc,
                self.profile,
                self.tx_keying.clone(),
                SrtpDirection::Sender,
            )?),
        };
        ctx.last_used = std::time::Instant::now();
        ctx.protect_rtcp(packet)
    }

    pub fn unprotect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        if packet.len() < 14 {
            // Header(8) + Index(4) + Tag(>=2)
            return Err(SrtpError::PacketTooShort);
        }
        let ssrc = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);

        self.evict_stale_rx(ssrc);
        let ctx = match self.rx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => e.insert(SrtpContext::new(
                ssrc,
                self.profile,
                self.rx_keying.clone(),
                SrtpDirection::Receiver,
            )?),
        };
        ctx.last_used = std::time::Instant::now();
        ctx.unprotect_rtcp(packet)
    }

    /// Evict stale transmit contexts once the map crosses the high-water mark.
    /// `keep_ssrc` (the SSRC of the packet currently being processed) is never
    /// evicted.
    fn evict_stale_tx(&mut self, keep_ssrc: u32) {
        if self.tx_contexts.len() <= SSRC_CONTEXT_HIGH_WATERMARK {
            return;
        }
        let now = std::time::Instant::now();
        self.tx_contexts.retain(|s, c| {
            *s == keep_ssrc || now.duration_since(c.last_used) < SSRC_INACTIVITY_EVICT
        });
    }

    /// Evict stale receive contexts once the map crosses the high-water mark.
    fn evict_stale_rx(&mut self, keep_ssrc: u32) {
        if self.rx_contexts.len() <= SSRC_CONTEXT_HIGH_WATERMARK {
            return;
        }
        let now = std::time::Instant::now();
        self.rx_contexts.retain(|s, c| {
            *s == keep_ssrc || now.duration_since(c.last_used) < SSRC_INACTIVITY_EVICT
        });
    }
}

#[derive(Debug, Clone)]
struct SessionKeys {
    cipher_key: Vec<u8>,
    auth_key: Vec<u8>,
    salt: Vec<u8>,
}

#[derive(Clone)]
pub struct SrtpContext {
    ssrc: u32,
    _profile: SrtpProfile,
    rtp_keys: SessionKeys,
    rtcp_keys: SessionKeys,
    /// Pre-expanded AES-128 round keys for the RTP session cipher key. Building
    /// this once avoids re-running the AES key schedule on every packet (the
    /// `ctr` cipher is reconstructed per packet from this cached key + a
    /// per-packet IV, which is a cheap clone of the round keys, not a re-key).
    rtp_aes_key: Aes128,
    rtcp_aes_key: Aes128,
    rtp_gcm_cipher: Option<Aes128Gcm>,
    rtcp_gcm_cipher: Option<Aes128Gcm>,
    rtp_auth_prototype: Option<HmacSha1>,
    rtcp_auth_prototype: Option<HmacSha1>,
    direction: SrtpDirection,
    rollover_counter: u32,
    last_sequence: Option<u16>,
    rtcp_index: u32,
    /// Reusable receive-side scratch buffer holding the reconstructed clear RTP
    /// header for authentication after the protected body has been split off.
    auth_scratch: Vec<u8>,
    /// Wall-clock time of the most recent protect/unprotect call, used to evict
    /// contexts for SSRCs that have gone away (prevents unbounded growth as
    /// SSRCs churn across a long call / relay).
    last_used: std::time::Instant,
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

        // Pre-expand the AES-128 key schedules once (instead of per packet).
        let mut rtp_key_bytes = [0u8; 16];
        rtp_key_bytes.copy_from_slice(&rtp_keys.cipher_key[..16]);
        let mut rtcp_key_bytes = [0u8; 16];
        rtcp_key_bytes.copy_from_slice(&rtcp_keys.cipher_key[..16]);
        let rtp_aes_key = <Aes128 as ctr::cipher::KeyInit>::new(&rtp_key_bytes.into());
        let rtcp_aes_key = <Aes128 as ctr::cipher::KeyInit>::new(&rtcp_key_bytes.into());

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
                <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(&rtp_keys.auth_key)
                    .map_err(|_| SrtpError::UnsupportedProfile)?,
            )
        } else {
            None
        };

        let rtcp_auth_prototype = if !rtcp_keys.auth_key.is_empty() {
            Some(
                <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(&rtcp_keys.auth_key)
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
            rtp_aes_key,
            rtcp_aes_key,
            rtp_gcm_cipher,
            rtcp_gcm_cipher,
            rtp_auth_prototype,
            rtcp_auth_prototype,
            direction,
            rollover_counter: 0,
            last_sequence: None,
            rtcp_index: 0,
            auth_scratch: Vec::new(),
            last_used: std::time::Instant::now(),
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
        let mut cipher = <Aes128Ctr as ctr::cipher::KeyIvInit>::new_from_slices(&master_key[..16], &iv)
            .map_err(|_| SrtpError::UnsupportedProfile)?;
        cipher.apply_keystream(&mut out);

        Ok(out)
    }

    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        self.rtcp_index += 1;
        let index = self.rtcp_index;
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
            self.cipher_rtcp(packet, index);
        }

        // Append SRTCP Index
        packet.extend_from_slice(&index_with_e.to_be_bytes());

        // Authenticate
        let mut tag = [0u8; SHA1_LEN];
        self.auth_tag_rtcp_into(packet, &mut tag)?;
        packet.extend_from_slice(&tag[..self._profile.tag_len()]);

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

            // Replay check
            if index > self.rtcp_index {
                self.rtcp_index = index;
            }

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

            return Ok(());
        }

        // Split tag
        let split = packet.len() - tag_len;
        let mut tag = [0u8; SHA1_LEN];
        tag[..tag_len].copy_from_slice(&packet[split..split + tag_len]);
        packet.truncate(split);

        // Verify tag
        let mut expected = [0u8; SHA1_LEN];
        self.auth_tag_rtcp_into(packet, &mut expected)?;
        if !constant_time_eq(&tag[..tag_len], &expected[..tag_len]) {
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

        // Replay check (simplified: just check if index is newer than last seen?)
        // For now, we just update.
        if index > self.rtcp_index {
            self.rtcp_index = index;
        }

        if e_bit && packet.len() > 8 {
            self.cipher_rtcp(packet, index);
        }

        Ok(())
    }

    /// Build an AES-128-CTR cipher from a pre-expanded key schedule and a
    /// per-packet IV. This reuses the cached round keys (a cheap clone) instead
    /// of re-running the AES key expansion on every packet.
    #[inline]
    fn ctr_from_key(key: &Aes128, iv: [u8; 16]) -> Aes128Ctr {
        let core = <ctr::CtrCore<Aes128, ctr::flavors::Ctr128BE> as InnerIvInit>::inner_iv_init(
            key.clone(),
            &iv.into(),
        );
        Aes128Ctr::from_core(core)
    }

    fn cipher_rtcp(&self, packet: &mut [u8], index: u32) {
        // IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (SRTCP_INDEX * 2^16)
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.rtcp_keys.salt[..14]);

        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&self.ssrc.to_be_bytes());
        block[10..14].copy_from_slice(&index.to_be_bytes());

        for (a, &b) in iv.iter_mut().zip(block.iter()) {
            *a ^= b;
        }

        // Reuse the cached AES key schedule (a clone of the expanded round
        // keys) instead of re-running AES key expansion on every RTCP packet.
        let mut cipher = Self::ctr_from_key(&self.rtcp_aes_key, iv);
        cipher.apply_keystream(&mut packet[8..]);
    }

    /// Compute the RTCP auth tag (HMAC-SHA1, truncated) into `out`, reusing the
    /// cached HMAC prototype to avoid re-padding the key (and a `Vec` alloc) on
    /// every RTCP packet.
    fn auth_tag_rtcp_into(&self, data: &[u8], out: &mut [u8; SHA1_LEN]) -> SrtpResult<()> {
        let mut mac = self
            .rtcp_auth_prototype
            .as_ref()
            .ok_or(SrtpError::UnsupportedProfile)?
            .clone();
        mac.update(data);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(())
    }

    pub fn protected_rtp_len(&self, packet: &RtpPacket) -> usize {
        packet.header.encoded_len()
            + packet.payload.len()
            + packet.padding_len as usize
            + self._profile.tag_len()
    }

    pub fn protect(&mut self, packet: &RtpPacket, output: &mut [u8]) -> SrtpResult<()> {
        packet.header.validate()?;
        let sequence_number = packet.header.sequence_number;
        let roc = self.estimate_roc(sequence_number);
        let tag_len = self._profile.tag_len();
        let header_len = packet.header.encoded_len();
        let body_len = packet.payload.len() + packet.padding_len as usize;
        let body_end = header_len + body_len;
        let protected_len = body_end + tag_len;

        if output.len() != protected_len {
            return Err(SrtpError::Internal(format!(
                "protected RTP output length mismatch: expected {protected_len}, got {}",
                output.len()
            )));
        }

        packet
            .header
            .write_to(packet.padding_len != 0, &mut output[..header_len]);
        output[header_len..header_len + packet.payload.len()].copy_from_slice(&packet.payload);
        if packet.padding_len != 0 {
            output[header_len + packet.payload.len()..body_end].fill(packet.padding_len);
        }

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(sequence_number, roc);
            let cipher = self
                .rtp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;
            let (header, protected_body) = output.split_at_mut(header_len);
            let (body, tag_output) = protected_body.split_at_mut(body_len);
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), header, body)
                .map_err(|_| SrtpError::AuthenticationFailed)?;
            tag_output.copy_from_slice(&tag);
        } else {
            let encrypts = !matches!(self._profile, SrtpProfile::NullCipherHmac);
            if body_len != 0 && encrypts {
                let iv = self.build_iv(sequence_number, roc);
                let mut cipher = Self::ctr_from_key(&self.rtp_aes_key, iv);
                cipher.apply_keystream(&mut output[header_len..body_end]);
            }

            let mut mac = self
                .rtp_auth_prototype
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?
                .clone();
            mac.update(&output[..body_end]);
            mac.update(&roc.to_be_bytes());
            let result = mac.finalize().into_bytes();
            output[body_end..].copy_from_slice(&result[..tag_len]);
        }

        self.update(sequence_number, roc);
        Ok(())
    }

    pub fn unprotect(&mut self, mut packet: SrtpPacket) -> SrtpResult<RtpPacket> {
        let tag_len = self._profile.tag_len();
        if packet.body.len() < tag_len {
            return Err(SrtpError::PacketTooShort);
        }

        let sequence_number = packet.header.sequence_number;
        let roc = self.estimate_roc(sequence_number);
        packet.marshal_header_into(&mut self.auth_scratch);

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            let nonce = self.build_gcm_nonce(sequence_number, roc);
            let cipher = self
                .rtp_gcm_cipher
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?;
            let split = packet.body.len() - tag_len;
            let tag = aes_gcm::Tag::clone_from_slice(&packet.body[split..]);
            packet.body.truncate(split);
            cipher
                .decrypt_in_place_detached(
                    Nonce::from_slice(&nonce),
                    &self.auth_scratch,
                    &mut packet.body,
                    &tag,
                )
                .map_err(|_| SrtpError::AuthenticationFailed)?;
        } else {
            let split = packet.body.len() - tag_len;
            if let Some(proto) = self.rtp_auth_prototype.as_ref() {
                let mut mac = proto.clone();
                mac.update(&self.auth_scratch);
                mac.update(&packet.body[..split]);
                mac.update(&roc.to_be_bytes());
                let result = mac.finalize().into_bytes();
                if !constant_time_eq(&packet.body[split..], &result[..tag_len]) {
                    return Err(SrtpError::AuthenticationFailed);
                }
            }
            packet.body.truncate(split);

            let decrypts = !matches!(self._profile, SrtpProfile::NullCipherHmac);
            if !packet.body.is_empty() && decrypts {
                let iv = self.build_iv(sequence_number, roc);
                let mut cipher = Self::ctr_from_key(&self.rtp_aes_key, iv);
                cipher.apply_keystream(&mut packet.body);
            }
        }

        let padding_len = if packet.has_padding {
            let padding_len = *packet.body.last().ok_or(SrtpError::PacketTooShort)?;
            if padding_len == 0 || padding_len as usize > packet.body.len() {
                return Err(SrtpError::Internal(
                    "invalid decrypted RTP padding length".to_string(),
                ));
            }
            packet.body.truncate(packet.body.len() - padding_len as usize);
            padding_len
        } else {
            0
        };

        self.update(sequence_number, roc);
        Ok(RtpPacket {
            header: packet.header,
            payload: packet.body.freeze(),
            padding_len,
        })
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
        let index = ((roc as u64) << 16) | sequence as u64;
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&self.rtp_keys.salt[..14]);

        let mut block = [0u8; 16];
        block[4..8].copy_from_slice(&self.ssrc.to_be_bytes());

        // IV = (salt * 2^16) XOR (SSRC * 2^64) XOR (Index * 2^16)
        let iv_part = index << 16;
        block[8..16].copy_from_slice(&iv_part.to_be_bytes());

        for (a, &b) in iv.iter_mut().zip(block.iter()) {
            *a ^= b;
        }
        iv
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
        let new_index = ((roc as u64) << 16) | (sequence as u64);

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
    use crate::rtp::{RtpHeader, RtpHeaderExtension, RtpPacket};

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
        let packet = sample_packet(1);
        let original = packet.payload.clone();
        let mut raw = BytesMut::new();
        raw.resize(session.protected_rtp_len(&packet), 0);
        session.protect_rtp(&packet, &mut raw).unwrap();
        let header_len = packet.header.encoded_len();
        assert_eq!(raw.len(), header_len + original.len() + 10);
        assert_ne!(raw[header_len..header_len + original.len()], original[..]);
        let packet = SrtpPacket::parse(raw).unwrap();
        let packet = session.unprotect_rtp(packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn protect_and_unprotect_roundtrip_gcm() {
        let mut session =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        let packet = sample_packet(1);
        let original = packet.payload.clone();
        let mut raw = BytesMut::new();
        raw.resize(session.protected_rtp_len(&packet), 0);
        session.protect_rtp(&packet, &mut raw).unwrap();
        let header_len = packet.header.encoded_len();
        assert_eq!(raw.len(), header_len + original.len() + 16);
        assert_ne!(raw[header_len..header_len + original.len()], original[..]);
        let packet = SrtpPacket::parse(raw).unwrap();
        let packet = session.unprotect_rtp(packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn aes_cm_padding_is_encrypted_and_resolved_after_parsing() {
        let mut sender = SrtpContext::new(
            0xdead_beef,
            SrtpProfile::Aes128Sha1_80,
            material(),
            SrtpDirection::Sender,
        )
        .unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut packet = sample_packet(7);
        packet.header.extension = Some(RtpHeaderExtension::new(0xBEDE, vec![1, 2, 3, 4]));
        packet.padding_len = 4;
        let original = packet.payload.clone();

        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect(&packet, &mut raw).unwrap();
        let packet = SrtpPacket::parse(raw).unwrap();
        let body_ptr = packet.body.as_ptr();
        let packet = receiver.unprotect_rtp(packet).unwrap();

        assert_eq!(packet.payload, original);
        assert_eq!(packet.padding_len, 4);
        assert_eq!(packet.payload.as_ptr(), body_ptr);
    }

    #[test]
    fn gcm_padding_is_encrypted_and_resolved_after_parsing() {
        let mut sender = SrtpContext::new(
            0xdead_beef,
            SrtpProfile::AeadAes128Gcm,
            material(),
            SrtpDirection::Sender,
        )
        .unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        let mut packet = sample_packet(8);
        packet.padding_len = 4;
        let original = packet.payload.clone();

        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect(&packet, &mut raw).unwrap();
        let packet = SrtpPacket::parse(raw).unwrap();
        let body_ptr = packet.body.as_ptr();
        let packet = receiver.unprotect_rtp(packet).unwrap();

        assert_eq!(packet.payload, original);
        assert_eq!(packet.padding_len, 4);
        assert_eq!(packet.payload.as_ptr(), body_ptr);
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
        let packet = sample_packet(1);
        let mut raw = BytesMut::new();
        raw.resize(ctx.protected_rtp_len(&packet), 0);
        ctx.protect(&packet, &mut raw).unwrap();
        let mut packet = SrtpPacket::parse(raw).unwrap();
        packet.body[0] ^= 0xFF;
        let err = ctx.unprotect(packet).unwrap_err();
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
        let packet = sample_packet(10);
        let mut raw = BytesMut::new();
        raw.resize(ctx.protected_rtp_len(&packet), 0);
        ctx.protect(&packet, &mut raw).unwrap();
        assert_eq!(raw.len(), packet.header.encoded_len() + 3 + 10);
    }

    #[test]
    fn roc_rollover_handling() {
        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();

        let packet = sample_packet(65535);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let p1 = SrtpPacket::parse(raw).unwrap();

        let packet = sample_packet(0);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let p2 = SrtpPacket::parse(raw).unwrap();

        // Receive in order
        receiver.unprotect_rtp(p1).unwrap();
        receiver.unprotect_rtp(p2).unwrap();
    }

    #[test]
    fn roc_rollover_reordered() {
        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();

        let packet = sample_packet(50000);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let p0 = SrtpPacket::parse(raw).unwrap();
        receiver.unprotect_rtp(p0).unwrap();

        let packet = sample_packet(65535);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let p1 = SrtpPacket::parse(raw).unwrap();

        let packet = sample_packet(0);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let p2 = SrtpPacket::parse(raw).unwrap();

        // Receive out of order: p2 (seq 0) then p1 (seq 65535)

        receiver.unprotect_rtp(p2).unwrap();
        receiver.unprotect_rtp(p1).unwrap();
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

#[cfg(test)]
mod security_tests {
    use super::*;
    use crate::rtp::{RtpHeader, RtpPacket};

    fn sample_packet(seq: u16) -> RtpPacket {
        let header = RtpHeader::new(96, seq, 1234, 0xdead_beef);
        RtpPacket::new(header, vec![1, 2, 3])
    }

    #[test]
    fn default_profile_is_encrypting_not_null() {
        // Security: default must be an encrypting profile, never NullCipherHmac
        let default_profile = SrtpProfile::default();
        assert_eq!(
            default_profile,
            SrtpProfile::Aes128Sha1_80,
            "Default SRTP profile must be Aes128Sha1_80 (encrypting), not NullCipherHmac"
        );
    }

    #[test]
    fn null_cipher_must_be_explicit() {
        // NullCipherHmac should never be selected accidentally
        let profiles = [
            SrtpProfile::default(),
            SrtpProfile::Aes128Sha1_80,
            SrtpProfile::Aes128Sha1_32,
            SrtpProfile::AeadAes128Gcm,
        ];
        for p in &profiles {
            assert_ne!(
                *p,
                SrtpProfile::NullCipherHmac,
                "Production profiles must exclude NullCipherHmac: {:?}",
                p
            );
        }
    }

    #[test]
    fn null_cipher_protect_is_transparent_but_authenticates() {
        // NullCipherHmac adds auth tag but doesn't encrypt payload
        let mut ctx = SrtpContext::new(
            42,
            SrtpProfile::NullCipherHmac,
            SrtpKeyingMaterial::new(vec![0; 16], vec![0; 14]),
            SrtpDirection::Sender,
        )
        .unwrap();
        let packet = sample_packet(100);
        let original_payload = packet.payload.clone();
        let mut raw = BytesMut::new();
        raw.resize(ctx.protected_rtp_len(&packet), 0);
        ctx.protect(&packet, &mut raw).unwrap();
        let header_len = packet.header.encoded_len();
        assert_eq!(raw.len(), header_len + original_payload.len() + 10);
        assert_eq!(
            &raw[header_len..header_len + original_payload.len()],
            &original_payload[..]
        );
        // Must still verify
        let mut rx_ctx = SrtpContext::new(
            42,
            SrtpProfile::NullCipherHmac,
            SrtpKeyingMaterial::new(vec![0; 16], vec![0; 14]),
            SrtpDirection::Receiver,
        )
        .unwrap();
        let packet = SrtpPacket::parse(raw).unwrap();
        let packet = rx_ctx.unprotect(packet).unwrap();
        assert_eq!(packet.payload, original_payload);
    }
}
