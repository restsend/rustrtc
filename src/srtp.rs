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

/// RFC 4568 caps the negotiated MKI length at 128 octets.
pub const MKI_MAX_LEN: usize = 128;

/// Negotiated MKI configuration for an [`SrtpSession`] (RFC 3711 §4.2,
/// RFC 4568 §4.1.2).
///
/// When an `a=crypto` line carries `|<mki-value>:<mki-length>`, senders append
/// a `mki-length`-octet MKI field between the (padded) payload and the
/// authentication tag, and the MKI is NOT covered by the authentication tag.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MkiParams {
    /// Outbound MKI: raw bytes written on protect (big-endian encoding of the
    /// negotiated decimal MKI value) and its length in octets.
    pub tx: Option<(Vec<u8>, usize)>,
    /// Inbound MKI length expected on unprotect. The received MKI value is
    /// ignored (single-master-key sessions only need the length to locate the
    /// authentication tag and payload boundary).
    pub rx_len: Option<usize>,
}

impl MkiParams {
    /// Outbound MKI length in octets (0 when not negotiated).
    pub fn tx_len(&self) -> usize {
        self.tx.as_ref().map_or(0, |(_, len)| *len)
    }

    /// Inbound MKI length in octets (0 when not negotiated).
    pub fn rx_len(&self) -> usize {
        self.rx_len.unwrap_or(0)
    }
}

pub struct SrtpSession {
    profile: SrtpProfile,
    tx_keying: SrtpKeyingMaterial,
    rx_keying: SrtpKeyingMaterial,
    tx_contexts: HashMap<u32, SrtpContext>,
    rx_contexts: HashMap<u32, SrtpContext>,
    /// MKI negotiated from the SDES `a=crypto` attributes.
    mki: MkiParams,
    /// Adaptive inbound MKI mode for SRTCP (session-wide: one RTCP remote per
    /// session), settled on the first authenticated packet.
    rtcp_rx_mki_active: Option<bool>,
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
            mki: MkiParams::default(),
            rtcp_rx_mki_active: None,
        })
    }

    /// Configure the outbound MKI (RFC 4568): every protected RTP/SRTCP packet
    /// carries `value` (`len` octets, network byte order) between the payload
    /// and the authentication tag. The MKI is excluded from the MAC.
    pub fn set_tx_mki(&mut self, value: Vec<u8>, len: usize) -> Result<(), SrtpError> {
        if len == 0 || len > MKI_MAX_LEN {
            return Err(SrtpError::Internal(format!(
                "MKI length {len} out of range 1..={MKI_MAX_LEN}"
            )));
        }
        if value.len() != len {
            return Err(SrtpError::Internal(format!(
                "MKI value is {} bytes but negotiated length is {len}",
                value.len()
            )));
        }
        self.mki.tx = Some((value, len));
        Ok(())
    }

    /// Configure the inbound MKI length (RFC 4568): packets from the remote may
    /// carry an `len`-octet MKI field before the authentication tag. The value
    /// is ignored; only the length matters to locate the tag.
    pub fn set_rx_mki_len(&mut self, len: usize) -> Result<(), SrtpError> {
        if len == 0 || len > MKI_MAX_LEN {
            return Err(SrtpError::Internal(format!(
                "MKI length {len} out of range 1..={MKI_MAX_LEN}"
            )));
        }
        self.mki.rx_len = Some(len);
        Ok(())
    }

    /// MKI configuration currently applied to this session.
    pub fn mki_params(&self) -> &MkiParams {
        &self.mki
    }

    pub fn protected_rtp_len(&self, packet: &RtpPacket) -> usize {
        packet.header.encoded_len()
            + packet.payload.len()
            + packet.padding_len as usize
            + self.profile.tag_len()
            + self.mki.tx_len()
    }

    pub fn protect_rtp(&mut self, packet: &RtpPacket, output: &mut [u8]) -> SrtpResult<()> {
        let ssrc = packet.header.ssrc;
        self.evict_stale_tx(ssrc);
        let mki = self.mki.clone();
        let ctx = match self.tx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let mut ctx = SrtpContext::new(
                    ssrc,
                    self.profile,
                    self.tx_keying.clone(),
                    SrtpDirection::Sender,
                )?;
                ctx.mki = mki;
                e.insert(ctx)
            }
        };
        ctx.last_used = std::time::Instant::now();
        ctx.protect(packet, output)
    }

    pub fn unprotect_rtp(&mut self, packet: SrtpPacket) -> SrtpResult<RtpPacket> {
        let ssrc = packet.header.ssrc;
        self.evict_stale_rx(ssrc);
        let mki = self.mki.clone();
        let ctx = match self.rx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let mut ctx = SrtpContext::new(
                    ssrc,
                    self.profile,
                    self.rx_keying.clone(),
                    SrtpDirection::Receiver,
                )?;
                ctx.mki = mki;
                e.insert(ctx)
            }
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
        let mki = self.mki.clone();
        let ctx = match self.tx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let mut ctx = SrtpContext::new(
                    ssrc,
                    self.profile,
                    self.tx_keying.clone(),
                    SrtpDirection::Sender,
                )?;
                ctx.mki = mki;
                e.insert(ctx)
            }
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
        let mki = self.mki.clone();
        let ctx = match self.rx_contexts.entry(ssrc) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let mut ctx = SrtpContext::new(
                    ssrc,
                    self.profile,
                    self.rx_keying.clone(),
                    SrtpDirection::Receiver,
                )?;
                ctx.mki = mki;
                e.insert(ctx)
            }
        };
        ctx.last_used = std::time::Instant::now();

        // Adaptive inbound MKI, mirroring the RTP path: some deployed stacks
        // advertise `|...|1:1` in SDP but never send the MKI field, so try the
        // advertised length first, then fall back to no-MKI. The winning mode
        // is cached session-wide (one RTCP remote per session).
        let advertised_mki_len = self.mki.rx_len();
        let candidates: Vec<usize> = match self.rtcp_rx_mki_active {
            Some(true) => vec![advertised_mki_len],
            Some(false) => vec![0],
            None => {
                let mut v = Vec::with_capacity(2);
                if advertised_mki_len > 0 {
                    v.push(advertised_mki_len);
                }
                v.push(0);
                v
            }
        };

        let original = if candidates.len() > 1 {
            packet.clone()
        } else {
            Vec::new()
        };
        let mut last_err = SrtpError::AuthenticationFailed;

        for (idx, &mki_len) in candidates.iter().enumerate() {
            match ctx.unprotect_rtcp_with_mki(packet, mki_len) {
                Ok(()) => {
                    self.rtcp_rx_mki_active = Some(mki_len > 0);
                    return Ok(());
                }
                Err(e) => {
                    last_err = e;
                    if idx + 1 < candidates.len() {
                        *packet = original.clone();
                    }
                }
            }
        }
        Err(last_err)
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
    /// Negotiated MKI handling (RFC 4568/RFC 3711): outbound MKI bytes are
    /// appended on protect; inbound packets are expected to carry an MKI of
    /// `mki.rx_len()` octets before the auth tag.
    mki: MkiParams,
    /// Adaptive inbound MKI mode (see [`SrtpContext::unprotect`]): `None`
    /// until the first packet settles it, then locked per SSRC.
    rx_mki_active: Option<bool>,
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
            mki: MkiParams::default(),
            rx_mki_active: None,
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
        let mut cipher =
            <Aes128Ctr as ctr::cipher::KeyIvInit>::new_from_slices(&master_key[..16], &iv)
                .map_err(|_| SrtpError::UnsupportedProfile)?;
        cipher.apply_keystream(&mut out);

        Ok(out)
    }

    pub fn protect_rtcp(&mut self, packet: &mut Vec<u8>) -> SrtpResult<()> {
        self.rtcp_index += 1;
        let index = self.rtcp_index;
        // E-bit = 1 (Encrypted)
        let index_with_e = index | 0x8000_0000;
        let mki_len = self.mki.tx_len();

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

            // Reconstruct packet: Header || Ciphertext || Index || [MKI]
            packet.truncate(8);
            packet.extend_from_slice(&ciphertext);
            packet.extend_from_slice(&index_with_e.to_be_bytes());
            if let Some((value, _)) = self.mki.tx.as_ref() {
                packet.extend_from_slice(&value[..mki_len]);
            }

            return Ok(());
        }

        // Encrypt payload (everything after first 8 bytes of header)
        // RFC 3711: The first 8 octets of the RTCP header are not encrypted.
        if packet.len() > 8 {
            self.cipher_rtcp(packet, index);
        }

        // Append SRTCP Index
        packet.extend_from_slice(&index_with_e.to_be_bytes());

        // Authenticate: the tag covers the packet up to and including the
        // SRTCP index — the MKI (appended after the index) is excluded
        // (RFC 3711 §3.4).
        let mut tag = [0u8; SHA1_LEN];
        self.auth_tag_rtcp_into(packet, &mut tag)?;
        if let Some((value, _)) = self.mki.tx.as_ref() {
            packet.extend_from_slice(&value[..mki_len]);
        }
        packet.extend_from_slice(&tag[..self._profile.tag_len()]);

        Ok(())
    }

    /// Attempt the SRTCP unprotect of `packet` assuming an inbound MKI field
    /// of `mki_len` octets. On success the clear RTCP packet is written back
    /// into `packet`; on failure the caller must restore the original bytes
    /// before retrying with a different `mki_len`.
    pub(crate) fn unprotect_rtcp_with_mki(
        &mut self,
        packet: &mut Vec<u8>,
        mki_len: usize,
    ) -> SrtpResult<()> {
        let tag_len = self._profile.tag_len();
        if packet.len() < tag_len + mki_len + 4 {
            return Err(SrtpError::PacketTooShort);
        }

        if let SrtpProfile::AeadAes128Gcm = self._profile {
            // Layout: Header || Ciphertext+Tag || Index || [MKI]
            let mki_start = packet.len() - mki_len;
            let index_start = mki_start - 4;
            let index_bytes = &packet[index_start..mki_start];
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

            // Ciphertext = Packet body (after header, before index).
            // Note: Tag is appended to ciphertext in GCM encrypt output.
            let ciphertext_and_tag = &packet[8..index_start];

            let payload = Payload {
                msg: ciphertext_and_tag,
                aad: &aad,
            };

            let plaintext = cipher
                .decrypt(Nonce::from_slice(&nonce), payload)
                .map_err(|_| SrtpError::AuthenticationFailed)?;

            // Replay check (only after successful authentication)
            if index > self.rtcp_index {
                self.rtcp_index = index;
            }

            // Reconstruct packet: Header || Plaintext
            packet.truncate(8);
            packet.extend_from_slice(&plaintext);

            return Ok(());
        }

        // Layout: Header || Payload || Index || [MKI] || Tag. The MKI sits
        // between the index and the tag and is NOT authenticated (RFC 3711
        // §3.4), so it must be stripped before verifying the tag.
        let tag_start = packet.len() - tag_len;
        let mut tag = [0u8; SHA1_LEN];
        tag[..tag_len].copy_from_slice(&packet[tag_start..tag_start + tag_len]);
        packet.truncate(tag_start);
        packet.truncate(packet.len() - mki_len);

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

        // Replay check (only after successful authentication)
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
            + self.mki.tx_len()
    }

    pub fn protect(&mut self, packet: &RtpPacket, output: &mut [u8]) -> SrtpResult<()> {
        packet.header.validate()?;
        let sequence_number = packet.header.sequence_number;
        let roc = self.estimate_roc(sequence_number);
        let tag_len = self._profile.tag_len();
        let mki_len = self.mki.tx_len();
        let header_len = packet.header.encoded_len();
        let body_len = packet.payload.len() + packet.padding_len as usize;
        let body_end = header_len + body_len;
        let protected_len = body_end + mki_len + tag_len;

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
            // Packet layout: header || ciphertext || [MKI] || tag. The MKI is
            // a trailer: neither encrypted nor part of the AEAD AAD.
            let (body_and_mki, tag_output) = protected_body.split_at_mut(body_len + mki_len);
            let (body, mki_output) = body_and_mki.split_at_mut(body_len);
            let tag = cipher
                .encrypt_in_place_detached(Nonce::from_slice(&nonce), header, body)
                .map_err(|_| SrtpError::AuthenticationFailed)?;
            if let Some((value, _)) = self.mki.tx.as_ref() {
                mki_output.copy_from_slice(&value[..mki_len]);
            }
            tag_output.copy_from_slice(&tag);
        } else {
            let encrypts = !matches!(self._profile, SrtpProfile::NullCipherHmac);
            if body_len != 0 && encrypts {
                let iv = self.build_iv(sequence_number, roc);
                let mut cipher = Self::ctr_from_key(&self.rtp_aes_key, iv);
                cipher.apply_keystream(&mut output[header_len..body_end]);
            }

            // The authentication tag covers the RTP header, the payload and
            // the ROC — NOT the MKI (RFC 3711 §4.2: the MKI is a trailer).
            let mut mac = self
                .rtp_auth_prototype
                .as_ref()
                .ok_or(SrtpError::UnsupportedProfile)?
                .clone();
            mac.update(&output[..body_end]);
            mac.update(&roc.to_be_bytes());
            let result = mac.finalize().into_bytes();
            if let Some((value, _)) = self.mki.tx.as_ref() {
                output[body_end..body_end + mki_len].copy_from_slice(&value[..mki_len]);
            }
            output[body_end + mki_len..].copy_from_slice(&result[..tag_len]);
        }

        self.update(sequence_number, roc);
        Ok(())
    }

    pub fn unprotect(&mut self, mut packet: SrtpPacket) -> SrtpResult<RtpPacket> {
        let advertised_mki_len = self.mki.rx_len();
        // Adaptive inbound MKI (see `unprotect_with_mki`): try the peer's
        // negotiated MKI length first, then fall back to no-MKI — some
        // deployed stacks advertise `|...|1:1` in SDP (e.g. rustrtc
        // ≤ 0.3.138, restsend/sipbot builds) but never actually send the
        // MKI field. The winning mode is cached per SSRC.
        let candidates: Vec<usize> = match self.rx_mki_active {
            Some(true) => vec![advertised_mki_len],
            Some(false) => vec![0],
            None => {
                let mut v = Vec::with_capacity(2);
                if advertised_mki_len > 0 {
                    v.push(advertised_mki_len);
                }
                v.push(0);
                v
            }
        };

        let original_body = if candidates.len() > 1 {
            packet.body.clone()
        } else {
            BytesMut::new()
        };
        let mut last_err = SrtpError::AuthenticationFailed;

        for (idx, &mki_len) in candidates.iter().enumerate() {
            match self.unprotect_with_mki(&mut packet, mki_len) {
                Ok(unprotected) => {
                    self.rx_mki_active = Some(mki_len > 0);
                    return Ok(unprotected);
                }
                Err(e) => {
                    last_err = e;
                    if idx + 1 < candidates.len() {
                        packet.body = original_body.clone();
                    }
                }
            }
        }
        Err(last_err)
    }

    /// Attempt the unprotect of `packet` assuming an inbound MKI field of
    /// `mki_len` octets. On success the clear RTP packet is returned; on
    /// failure the packet must be restored by the caller before retrying
    /// with a different `mki_len`.
    fn unprotect_with_mki(
        &mut self,
        packet: &mut SrtpPacket,
        mki_len: usize,
    ) -> SrtpResult<RtpPacket> {
        let tag_len = self._profile.tag_len();
        if packet.body.len() < tag_len + mki_len {
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
            // Layout: header || ciphertext || [MKI] || tag.
            let tag_start = packet.body.len() - tag_len;
            let split = packet.body.len() - tag_len - mki_len;
            let tag = aes_gcm::Tag::clone_from_slice(&packet.body[tag_start..]);
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
            // Layout: header || payload(+padding) || [MKI] || tag. The sender
            // computed the tag over header+payload+ROC only, so the MKI must
            // be excluded from the MAC input here.
            let split = packet.body.len() - tag_len - mki_len;
            if let Some(proto) = self.rtp_auth_prototype.as_ref() {
                let mut mac = proto.clone();
                mac.update(&self.auth_scratch);
                mac.update(&packet.body[..split]);
                mac.update(&roc.to_be_bytes());
                let result = mac.finalize().into_bytes();
                if !constant_time_eq(&packet.body[split + mki_len..], &result[..tag_len]) {
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
            packet
                .body
                .truncate(packet.body.len() - padding_len as usize);
            padding_len
        } else {
            0
        };
        self.update(sequence_number, roc);
        Ok(RtpPacket {
            header: packet.header.clone(),
            payload: packet.body.split().freeze(),
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

    fn mki_session(direction: SrtpDirection) -> SrtpSession {
        let mut session =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        match direction {
            // Sender advertised `a=crypto:1 ... inline:...|2^31|1:1`.
            SrtpDirection::Sender => session.set_tx_mki(vec![0x01], 1).unwrap(),
            SrtpDirection::Receiver => session.set_rx_mki_len(1).unwrap(),
        }
        session
    }

    fn srtp_rtcp_packet(ssrc: u32) -> Vec<u8> {
        // Minimal RTCP Sender Report: V=2, PT=201, one 32-bit word of body.
        let mut packet = Vec::new();
        packet.extend_from_slice(&[0x81, 0xC8, 0x00, 0x01]);
        packet.extend_from_slice(&ssrc.to_be_bytes());
        packet.extend_from_slice(&[0x00; 4]);
        packet
    }

    #[test]
    fn mki_roundtrip_sha1_80() {
        let mut sender = mki_session(SrtpDirection::Sender);
        let mut receiver = mki_session(SrtpDirection::Receiver);

        let packet = sample_packet(1);
        let original = packet.payload.clone();
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();

        // MKI (1 octet) sits between the payload and the 10-byte auth tag and
        // carries the negotiated MKI value.
        let header_len = packet.header.encoded_len();
        assert_eq!(raw.len(), header_len + original.len() + 1 + 10);
        assert_eq!(raw[header_len + original.len()], 0x01);

        let packet = SrtpPacket::parse(raw).unwrap();
        let packet = receiver.unprotect_rtp(packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    #[test]
    fn mki_roundtrip_gcm() {
        let mut sender =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        sender.set_tx_mki(vec![0x01], 1).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        receiver.set_rx_mki_len(1).unwrap();

        let packet = sample_packet(2);
        let original = packet.payload.clone();
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        assert_eq!(
            raw.len(),
            packet.header.encoded_len() + original.len() + 1 + 16
        );

        let packet = SrtpPacket::parse(raw).unwrap();
        let packet = receiver.unprotect_rtp(packet).unwrap();
        assert_eq!(packet.payload, original);
    }

    /// Regression test for the Groundwire interop failure (rustpbx issue
    /// #281): a peer that negotiated `|1:1` MKI appends the MKI octet before
    /// the auth tag. A receiver without MKI support must reject those packets
    /// with an authentication failure (not silently accept corrupted
    /// payloads), and a receiver WITH the negotiated MKI length must accept
    /// them.
    #[test]
    fn sender_mki_requires_receiver_mki_support() {
        let mut sender = mki_session(SrtpDirection::Sender);

        let packet = sample_packet(3);
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();
        let srtp_packet = SrtpPacket::parse(raw.clone()).unwrap();

        // Receiver without negotiated MKI: tag check must fail (previously
        // every such packet was dropped as "SRTP authentication failed").
        let mut plain =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let err = plain
            .unprotect_rtp(SrtpPacket::parse(raw.clone()).unwrap())
            .unwrap_err();
        assert!(matches!(err, SrtpError::AuthenticationFailed));

        // Receiver with the negotiated MKI length accepts the packet.
        let mut receiver = mki_session(SrtpDirection::Receiver);
        receiver.unprotect_rtp(srtp_packet).unwrap();
    }

    /// A "lying" peer: advertises `|1:1` MKI in its SDP (the way rustrtc
    /// ≤ 0.3.138 and old sipbot/rustpbx community builds do) but never
    /// actually sends MKI bytes. The adaptive receiver must still
    /// authenticate those packets after the first failed attempt.
    #[test]
    fn adaptive_receiver_accepts_mki_advertising_peer_without_mki_bytes() {
        // The remote "protects" with no MKI even though its SDP said 1:1.
        let mut remote =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();

        // We negotiated rx_mki_len=1 from the remote's advertised crypto.
        let mut receiver = mki_session(SrtpDirection::Receiver);

        for seq in [11u16, 12, 13] {
            let packet = sample_packet(seq);
            let original = packet.payload.clone();
            let mut raw = BytesMut::new();
            raw.resize(remote.protected_rtp_len(&packet), 0);
            remote.protect_rtp(&packet, &mut raw).unwrap();

            let packet = receiver
                .unprotect_rtp(SrtpPacket::parse(raw).unwrap())
                .unwrap();
            assert_eq!(packet.payload, original);
        }
    }

    #[test]
    fn srtcp_mki_roundtrip_and_without_support_fails() {
        let mut sender = mki_session(SrtpDirection::Sender);
        let mut receiver = mki_session(SrtpDirection::Receiver);

        let mut packet = srtp_rtcp_packet(0xdead_beef);
        sender.protect_rtcp(&mut packet).unwrap();

        // Packet(12) + index(4) + MKI(1) + tag(10)
        assert_eq!(packet.len(), 12 + 4 + 1 + 10);

        let mut without_mki =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        let mut rejected = packet.clone();
        assert!(matches!(
            without_mki.unprotect_rtcp(&mut rejected),
            Err(SrtpError::AuthenticationFailed)
        ));

        receiver.unprotect_rtcp(&mut packet).unwrap();
        assert_eq!(packet, srtp_rtcp_packet(0xdead_beef));
    }

    /// SRTCP counterpart of the Groundwire regression: a "lying" peer whose
    /// SDP advertises `|1:1` MKI but whose packets carry no MKI field must
    /// still be accepted by the adaptive fallback.
    #[test]
    fn srtcp_adaptive_accepts_mki_advertising_peer_without_mki_bytes() {
        // Remote advertises MKI but protects WITHOUT one (old rustrtc builds).
        let mut remote =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        // We negotiated rx_mki_len=1 from the remote's advertised crypto.
        let mut receiver = mki_session(SrtpDirection::Receiver);

        for ssrc in [0x1111_2222u32, 0x3333_4444] {
            let mut packet = srtp_rtcp_packet(ssrc);
            remote.protect_rtcp(&mut packet).unwrap();
            receiver.unprotect_rtcp(&mut packet).unwrap();
            assert_eq!(packet, srtp_rtcp_packet(ssrc));
        }
    }

    #[test]
    fn srtcp_mki_roundtrip_gcm() {
        let mut sender =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        sender.set_tx_mki(vec![0x05], 1).unwrap();
        let mut receiver =
            SrtpSession::new(SrtpProfile::AeadAes128Gcm, material(), material()).unwrap();
        receiver.set_rx_mki_len(1).unwrap();

        let mut packet = srtp_rtcp_packet(0x1234);
        sender.protect_rtcp(&mut packet).unwrap();
        receiver.unprotect_rtcp(&mut packet).unwrap();
        assert_eq!(packet, srtp_rtcp_packet(0x1234));
    }

    #[test]
    fn set_mki_validates_lengths() {
        let mut session =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, material(), material()).unwrap();
        assert!(session.set_tx_mki(vec![0x01; 2], 1).is_err());
        assert!(session.set_tx_mki(vec![0x01], 0).is_err());
        assert!(
            session
                .set_tx_mki(
                    vec![0x01; crate::srtp::MKI_MAX_LEN + 1],
                    crate::srtp::MKI_MAX_LEN + 1
                )
                .is_err()
        );
        assert!(session.set_rx_mki_len(0).is_err());
        assert!(session.set_rx_mki_len(crate::srtp::MKI_MAX_LEN).is_ok());
        assert_eq!(session.mki_params().rx_len, Some(crate::srtp::MKI_MAX_LEN));
    }

    // ── Independent RFC 3711 wire-format verification ──────────────────────
    //
    // The roundtrip tests above prove rustrtc ↔ rustrtc consistency, but a
    // shared misreading of the spec would pass them both. The helpers below
    // re-implement the AES-CM key derivation, the AES-CM counter IV, and the
    // HMAC-SHA1 authentication input exactly as specified by RFC 3711 (and
    // verified line-by-line against libsrtp's srtp_kdf_generate /
    // srtp_protect), so a regression in KDF labels, IV layout, ROC handling
    // or MKI framing fails here even if both sides regress identically.

    /// RFC 3711 §4.3 AES-CM key derivation: AES-CTR keystream under the master
    /// key with IV = (master_salt || 00 00) XOR (label << 64).
    fn rfc3711_kdf(master_key: &[u8], master_salt: &[u8], label: u8, out_len: usize) -> Vec<u8> {
        let mut iv = [0u8; 16];
        iv[..master_salt.len()].copy_from_slice(master_salt);
        iv[7] ^= label; // label * 2^64 in the big-endian block
        let mut out = vec![0u8; out_len];
        <Aes128Ctr as ctr::cipher::KeyIvInit>::new_from_slices(master_key, &iv)
            .expect("kdf cipher")
            .apply_keystream(&mut out);
        out
    }

    /// RFC 3711 §4.1.1 AES-CM packet IV (verified against libsrtp
    /// srtp_protect): salt || 00 00, XOR ssrc@4..8, XOR index(48-bit)<<16 in
    /// the trailing 64-bit word.
    fn rfc3711_rtp_iv(session_salt: &[u8], ssrc: u32, roc: u32, seq: u16) -> [u8; 16] {
        let index = ((roc as u64) << 16) | seq as u64;
        let mut iv = [0u8; 16];
        iv[..14].copy_from_slice(&session_salt[..14]);
        for (i, b) in ssrc.to_be_bytes().iter().enumerate() {
            iv[4 + i] ^= b;
        }
        let shifted = (index << 16).to_be_bytes();
        for (i, b) in shifted.iter().enumerate() {
            iv[8 + i] ^= b;
        }
        iv
    }

    /// Groundwire wire format (rustpbx issue #281), verified without going
    /// through SrtpSession's own KDF/MAC: protect a packet with a 1-octet MKI
    /// under a fixed master key, then independently derive the session keys,
    /// decrypt the payload and recompute the HMAC-SHA1 tag.
    #[test]
    fn rfc3711_wire_format_independent_verification() {
        let master_key = vec![0x5au8; 16];
        let master_salt = vec![0xa5u8; 14];
        let keying = SrtpKeyingMaterial::new(master_key.clone(), master_salt.clone());

        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone()).unwrap();
        sender.set_tx_mki(vec![0x7f], 1).unwrap();

        let seq: u16 = 0x3047;
        let roc: u32 = 0;
        let packet = sample_packet(seq);
        let original = packet.payload.clone();
        let ssrc = packet.header.ssrc;

        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();

        // Independent key derivation (labels per RFC 3711 §4.3).
        let session_key = rfc3711_kdf(&master_key, &master_salt, 0x00, 16);
        let auth_key = rfc3711_kdf(&master_key, &master_salt, 0x01, 20);
        let session_salt = rfc3711_kdf(&master_key, &master_salt, 0x02, 14);

        let header_len = packet.header.encoded_len();
        let payload = &raw[header_len..header_len + original.len()];
        assert_eq!(
            raw[header_len + original.len()],
            0x7f,
            "MKI must sit between payload and tag"
        );

        // Independent AES-CM decryption of the payload.
        let iv = rfc3711_rtp_iv(&session_salt, ssrc, roc, seq);
        let mut clear = payload.to_vec();
        <Aes128Ctr as ctr::cipher::KeyIvInit>::new_from_slices(&session_key, &iv)
            .expect("packet cipher")
            .apply_keystream(&mut clear);
        assert_eq!(clear, original, "payload must decrypt with the RFC 3711 IV");

        // Independent HMAC-SHA1 tag over header || encrypted payload || ROC
        // (the MKI is NOT part of the authenticated portion, RFC 3711 §4.2 —
        // libsrtp srtp_protect authenticates auth_start..rtp_len then mixes
        // the ROC via srtp_auth_compute).
        let mut mac =
            <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(&auth_key).expect("auth key");
        mac.update(&raw[..header_len + original.len()]);
        mac.update(&roc.to_be_bytes());
        let expected = mac.finalize().into_bytes();
        let tag = &raw[header_len + original.len() + 1..];
        assert_eq!(tag.len(), 10, "SHA1_80 tag length");
        assert_eq!(
            tag,
            &expected[..10],
            "tag must match an independent HMAC computation"
        );
    }

    /// The same independent verification for a packet WITHOUT MKI (the plain
    /// Groundwire-offered crypto shape on the caller leg).
    #[test]
    fn rfc3711_wire_format_without_mki() {
        let master_key = vec![0x3cu8; 16];
        let master_salt = vec![0xc3u8; 14];
        let keying = SrtpKeyingMaterial::new(master_key.clone(), master_salt.clone());
        let mut sender =
            SrtpSession::new(SrtpProfile::Aes128Sha1_80, keying.clone(), keying.clone()).unwrap();

        let seq: u16 = 7;
        let packet = sample_packet(seq);
        let original = packet.payload.clone();
        let ssrc = packet.header.ssrc;
        let mut raw = BytesMut::new();
        raw.resize(sender.protected_rtp_len(&packet), 0);
        sender.protect_rtp(&packet, &mut raw).unwrap();

        let session_key = rfc3711_kdf(&master_key, &master_salt, 0x00, 16);
        let auth_key = rfc3711_kdf(&master_key, &master_salt, 0x01, 20);
        let session_salt = rfc3711_kdf(&master_key, &master_salt, 0x02, 14);

        let header_len = packet.header.encoded_len();
        let payload = &raw[header_len..header_len + original.len()];
        assert_eq!(payload.len(), original.len());
        let mut clear = payload.to_vec();
        let iv = rfc3711_rtp_iv(&session_salt, ssrc, 0, seq);
        <Aes128Ctr as ctr::cipher::KeyIvInit>::new_from_slices(&session_key, &iv)
            .expect("packet cipher")
            .apply_keystream(&mut clear);
        assert_eq!(clear, original);

        let mut mac =
            <HmacSha1 as hmac::digest::KeyInit>::new_from_slice(&auth_key).expect("auth key");
        mac.update(&raw[..header_len + original.len()]);
        mac.update(&0u32.to_be_bytes());
        let expected = mac.finalize().into_bytes();
        assert_eq!(&raw[header_len + original.len()..], &expected[..10]);
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
