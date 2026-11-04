use crate::media::depacketizer::{DefaultDepacketizerFactory, DepacketizerFactory};
#[cfg(feature = "std")]
#[cfg(feature = "std")]
use crate::peer_connection::{RtpReceiverInterceptor, RtpSenderInterceptor};
use crate::prelude::*;

/// Spawn-pinning handle. std: tokio runtime handle; no_std: unused
/// placeholder (embassy tasks are spawned by the embedder's executor).
#[cfg(feature = "std")]
pub type RuntimeHandle = tokio::runtime::Handle;
/// no_std placeholder: nothing to pin, see the `std` variant.
#[cfg(not(feature = "std"))]
#[derive(Debug, Clone, Default)]
pub struct RuntimeHandle;
use alloc::sync::Arc;
use core::fmt::{Debug, Formatter};
use core::net::IpAddr;
use serde::{Deserialize, Serialize};

/// Describes how credentials are conveyed for a given ICE server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "lowercase")]
pub enum IceCredentialType {
    /// Long-term credentials: `username` + `credential` (a shared secret).
    /// Serialized as `"password"`.
    #[default]
    Password,
    /// OAuth 2.0 tokens per RFC 7635. Serialized as `"oauth"`.
    Oauth,
}

/// Mirrors the W3C `RTCIceServer` dictionary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    /// Server URLs: `stun:host:port`, `turn:host:port?transport=udp`,
    /// `turns:host:port` (TLS), `turns:host:port?transport=tcp`.
    pub urls: Vec<String>,
    /// Username for TURN authentication (`credential_type` decides the
    /// mechanism).
    pub username: Option<String>,
    /// Secret or token matching `username`.
    pub credential: Option<String>,
    /// Credential mechanism. Default: [`IceCredentialType::Password`].
    #[serde(default)]
    pub credential_type: IceCredentialType,
}

impl IceServer {
    /// A server (or a list of URLs for one server) without credentials.
    pub fn new<T: Into<Vec<String>>>(urls: T) -> Self {
        Self {
            urls: urls.into(),
            username: None,
            credential: None,
            credential_type: IceCredentialType::default(),
        }
    }

    /// Set long-term credentials (see [`IceCredentialType::Password`]).
    pub fn with_credential(
        mut self,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.credential = Some(credential.into());
        self
    }

    /// Set the credential mechanism.
    pub fn credential_type(mut self, kind: IceCredentialType) -> Self {
        self.credential_type = kind;
        self
    }
}

impl Default for IceServer {
    fn default() -> Self {
        Self::new(Vec::new())
    }
}

/// Which candidate types ICE may use.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IceTransportPolicy {
    /// All candidates: host, server-reflexive and relay. Serialized as
    /// `"All"`.
    #[default]
    All,
    /// Relay candidates only: media always flows through a TURN server.
    /// Serialized as `"Relay"`.
    Relay,
}

/// Controls ICE TCP candidate support (RFC 6544).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IceTcpPolicy {
    /// Do not gather or use TCP candidates.
    #[default]
    Disabled,
    /// Gather and use TCP candidates (both active and passive).
    Enabled,
    /// Only gather and use passive TCP candidates.
    PassiveOnly,
}

/// Which m-lines of an offer have a transport of their own (RFC 9429
/// §4.1.1). An offer with two or more m-lines proposes BUNDLE (RFC 8843):
/// when the answer accepts it, all m-lines share one transport. The policy
/// decides what a peer without BUNDLE gets. The other m-lines are offered
/// bundle-only (port 0): such a peer rejects them. An answer to an offer
/// without BUNDLE rejects the m-lines that the policy gives no transport.
///
/// Full ICE has one ICE agent: it always works as `MaxBundle`. Serialized
/// as the variant name: `"Balanced"`, `"MaxCompat"`, `"MaxBundle"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum BundlePolicy {
    /// A transport for the first m-line of each kind (audio, video, data).
    /// A peer without BUNDLE gets one m-line of each kind.
    Balanced,
    /// A transport for every m-line. A peer without BUNDLE gets them all.
    MaxCompat,
    /// A transport for the first m-line only. A peer without BUNDLE gets
    /// only the first m-line. RFC 9429 calls it "must-bundle".
    MaxBundle,
}

/// RTP/RTCP multiplexing on one port (RFC 5761, RFC 9429 §4.1.1). Offers
/// propose it with `a=rtcp-mux`; answers accept it when the offer has it.
///
/// Full ICE gathers no RTCP component: it always works as `Require`.
/// Serialized as the variant name: `"Require"`, `"Negotiate"`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum RtcpMuxPolicy {
    /// The peer must multiplex. Offers also carry `a=rtcp-mux-only`
    /// (RFC 8858) and reserve no RTCP port. A remote description with an
    /// RTP m-line without `a=rtcp-mux` is an error.
    Require,
    /// Offers reserve an RTCP port and advertise it with `a=rtcp`, for an
    /// answer that does not multiplex (RFC 5761 §5.1.1). Use this for SIP
    /// peers: many of them do not multiplex.
    Negotiate,
}

/// How the media path to the peer is found. Any value works with any
/// [`Keying`]. Serialized as the variant name: `"Sdp"`, `"IceLite"`,
/// `"Ice"`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Connectivity {
    /// The c=/m= address of the peer's SDP (corrected by latching, when on).
    /// A direct transport: no ICE agent.
    Sdp,
    /// ICE-lite (RFC 8445 §2.5): a direct transport that answers the full-ICE
    /// peer's checks and follows its nomination.
    IceLite,
    /// Full ICE: gathering, connectivity checks, nomination.
    Ice,
}

impl Connectivity {
    /// A direct transport (no full ICE agent): `Sdp` or `IceLite`.
    pub(crate) fn is_direct(self) -> bool {
        self != Connectivity::Ice
    }
}

/// How the SRTP keys are exchanged. Any value works with any
/// [`Connectivity`]. Data channels (SCTP) need `Dtls`. Serialized as the
/// variant name: `"None"`, `"Sdes"`, `"Dtls"`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Keying {
    /// Plain RTP (RTP/AVP).
    None,
    /// SDES, `a=crypto` (RFC 4568), RTP/SAVP.
    Sdes,
    /// DTLS-SRTP, `a=fingerprint` (RFC 5763/5764), UDP/TLS/RTP/SAVPF.
    Dtls,
}

/// Strategy for dropping packets when the receive buffer is full.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BufferDropStrategy {
    /// Drop the packet that just arrived; keep the oldest buffered ones.
    /// Serialized as `"DropNew"`.
    #[default]
    DropNew,
    /// Drop the oldest buffered packet to make room. Serialized as
    /// `"DropOldest"`.
    DropOldest,
}

/// How `external_ips` are advertised in ICE candidates.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum ExternalIpCandidateType {
    /// Replace each non-loopback host candidate's address with the external
    /// address of its family.
    #[default]
    Host,
    /// Keep the host candidate on the bind address and advertise the
    /// external address of its family alongside it as a server-reflexive
    /// candidate (1:1 NAT, RFC 8445 §5.1.1.2). Full ICE only.
    ServerReflexive,
}

/// Tracks user-supplied certificate material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertificateConfig {
    /// Certificate chain in PEM (leaf first, then intermediates).
    pub pem_chain: Vec<String>,
    /// Matching private key in PEM (PKCS#8 or SEC1).
    pub private_key_pem: Option<String>,
}

/// One audio codec offered in SDP, with its parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioCapability {
    /// RTP payload type to offer (0-96 static, 96-127 dynamic).
    pub payload_type: u8,
    /// Encoding name as it appears in `a=rtpmap` (e.g. `"opus"`, `"PCMU"`).
    pub codec_name: String,
    /// RTP timestamp clock rate in Hz (e.g. 48000 for Opus, 8000 for PCMU).
    pub clock_rate: u32,
    /// Number of audio channels (`a=rtpmap` channels part; Opus is 2).
    pub channels: u8,
    /// `a=fmtp` parameters without the `a=fmtp:<pt> ` prefix.
    pub fmtp: Option<String>,
    /// RTCP feedback types to offer in `a=rtcp-fb` (e.g. `"nack"`,
    /// `"ccm fir"`). Empty: none.
    pub rtcp_fbs: Vec<String>,
}

impl Default for AudioCapability {
    fn default() -> Self {
        Self {
            payload_type: 111,
            codec_name: "opus".to_string(),
            clock_rate: 48000,
            channels: 2,
            fmtp: Some("minptime=10;useinbandfec=1;stereo=1".to_string()),
            rtcp_fbs: vec![],
        }
    }
}

impl AudioCapability {
    /// Opus, payload type 111, 48 kHz stereo, `minptime=10;useinbandfec=1;
    /// stereo=1` (the default `AudioCapability`).
    pub fn opus() -> Self {
        Self::default()
    }

    /// G.711 µ-law, payload type 0, 8 kHz mono.
    pub fn pcmu() -> Self {
        Self {
            payload_type: 0,
            codec_name: "PCMU".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        }
    }

    /// G.711 A-law, payload type 8, 8 kHz mono.
    pub fn pcma() -> Self {
        Self {
            payload_type: 8,
            codec_name: "PCMA".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        }
    }

    /// G.722, payload type 9, 8 kHz (the RTP clock rate for G.722 is 8000
    /// despite sampling at 16 kHz, per RFC 3551).
    pub fn g722() -> Self {
        Self {
            payload_type: 9,
            codec_name: "G722".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        }
    }

    /// G.729, payload type 18, 8 kHz mono.
    pub fn g729() -> Self {
        Self {
            payload_type: 18,
            codec_name: "G729".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: None,
            rtcp_fbs: vec![],
        }
    }

    /// DTMF tones (RFC 4733), payload type 101, `0-16` events.
    pub fn telephone_event() -> Self {
        Self {
            payload_type: 101,
            codec_name: "telephone-event".to_string(),
            clock_rate: 8000,
            channels: 1,
            fmtp: Some("0-16".to_string()),
            rtcp_fbs: vec![],
        }
    }
}

/// One video codec offered in SDP, with its parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoCapability {
    /// RTP payload type to offer.
    pub payload_type: u8,
    /// Encoding name as it appears in `a=rtpmap` (e.g. `"VP8"`, `"VP9"`).
    pub codec_name: String,
    /// RTP timestamp clock rate in Hz (90000 for all video codecs).
    pub clock_rate: u32,
    /// `a=fmtp` parameters without the `a=fmtp:<pt> ` prefix.
    pub fmtp: Option<String>,
    /// RTCP feedback types to offer in `a=rtcp-fb` (e.g. `"nack"`,
    /// `"nack pli"`, `"transport-cc"`).
    pub rtcp_fbs: Vec<String>,
    /// Associated RTX payload type (RFC 4588). When set, SDP offers include
    /// `a=rtpmap:<pt> rtx/<clock_rate>` and `a=fmtp:<pt> apt=<primary>`.
    /// Default `None` preserves single-codec SDP; answers still accept remote RTX.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rtx_payload_type: Option<u8>,
}

impl Default for VideoCapability {
    fn default() -> Self {
        Self {
            payload_type: 96,
            codec_name: "VP8".to_string(),
            clock_rate: 90000,
            fmtp: None,
            rtcp_fbs: vec![
                "nack".to_string(),
                "nack pli".to_string(),
                "ccm fir".to_string(),
                "goog-remb".to_string(),
                "transport-cc".to_string(),
            ],
            rtx_payload_type: None,
        }
    }
}

impl VideoCapability {
    /// H.264 constrained-baseline, payload type 96, `packetization-mode=1;
    /// profile-level-id=42e01f`, NACK/PLI/FIR feedback.
    pub fn h264() -> Self {
        Self {
            payload_type: 96,
            codec_name: "H264".to_string(),
            clock_rate: 90000,
            fmtp: Some("packetization-mode=1;profile-level-id=42e01f".to_string()),
            rtcp_fbs: vec![
                "nack".to_string(),
                "nack pli".to_string(),
                "ccm fir".to_string(),
            ],
            rtx_payload_type: None,
        }
    }

    /// VP8 with RTX enabled (common browser interop profile).
    pub fn vp8_with_rtx(rtx_payload_type: u8) -> Self {
        Self {
            rtx_payload_type: Some(rtx_payload_type),
            ..Self::default()
        }
    }

    /// VP9 (RFC 9628), profile 0 — the browser default.
    pub fn vp9() -> Self {
        Self {
            payload_type: 98,
            codec_name: "VP9".to_string(),
            clock_rate: 90000,
            fmtp: Some("profile-id=0".to_string()),
            rtcp_fbs: vec![
                "nack".to_string(),
                "nack pli".to_string(),
                "ccm fir".to_string(),
                "goog-remb".to_string(),
                "transport-cc".to_string(),
            ],
            rtx_payload_type: None,
        }
    }

    /// VP9 with RTX enabled.
    pub fn vp9_with_rtx(rtx_payload_type: u8) -> Self {
        Self {
            rtx_payload_type: Some(rtx_payload_type),
            ..Self::vp9()
        }
    }
}

/// The data-channel m-line: the SCTP port we offer in `a=sctp-port`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationCapability {
    /// SCTP port number to offer (default 5000, the UDP-encapsulated
    /// SCTP default per RFC 8261 §5).
    pub sctp_port: u16,
}

impl Default for ApplicationCapability {
    fn default() -> Self {
        Self { sctp_port: 5000 }
    }
}

/// T.38 fax rate management (SDP `T38FaxRateManagement`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum T38FaxRateManagement {
    /// The receiving terminal trains with TCF and confirms in the C: line
    /// of CFR (the ITU default; the peer sends training). Serialized as
    /// `"transferredTCF"`.
    #[serde(rename = "transferredTCF")]
    #[default]
    TransferredTCF,
    /// We train locally and skip the peer's TCF (robust on lossy links).
    /// Serialized as `"localTCF"`.
    #[serde(rename = "localTCF")]
    LocalTCF,
}

impl core::fmt::Display for T38FaxRateManagement {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TransferredTCF => write!(f, "transferredTCF"),
            Self::LocalTCF => write!(f, "localTCF"),
        }
    }
}

/// T.38 UDPTL error correction (SDP `T38UDPEC`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum T38UdpEC {
    /// Redundancy coding: repeat the previous N primary packets verbatim.
    /// Serialized as `"t38UDPRedundancy"`.
    #[serde(rename = "t38UDPRedundancy")]
    #[default]
    T38UDPRedundancy,
    /// Forward error correction: parity data computed over a window of
    /// packets. Serialized as `"t38UDPFEC"`.
    #[serde(rename = "t38UDPFEC")]
    T38UDPFEC,
}

impl core::fmt::Display for T38UdpEC {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::T38UDPRedundancy => write!(f, "t38UDPRedundancy"),
            Self::T38UDPFEC => write!(f, "t38UDPFEC"),
        }
    }
}

/// One image (T.38 fax) codec offered in SDP, with its T.38 parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct T38Capability {
    /// RTP payload type to offer for the image media.
    pub payload_type: u8,
    /// T.38 version (0-3)
    pub version: u8,
    /// Max bit rate in bps (e.g. 14400, 9600, 4800, 2400)
    pub max_bitrate: u32,
    /// Rate management method
    pub rate_management: T38FaxRateManagement,
    /// Max buffer size in bytes
    pub max_buffer: u16,
    /// Max datagram size in bytes
    pub max_datagram: u16,
    /// UDP error correction method
    pub udp_ec: T38UdpEC,
    /// Extra `a=fmtp` parameters beyond the standard T.38 fields.
    pub fmtp: Option<String>,
}

impl Default for T38Capability {
    fn default() -> Self {
        Self {
            payload_type: 98,
            version: 0,
            max_bitrate: 14400,
            rate_management: T38FaxRateManagement::default(),
            max_buffer: 1024,
            max_datagram: 238,
            udp_ec: T38UdpEC::default(),
            fmtp: None,
        }
    }
}

impl T38Capability {
    /// The default T.38 profile: payload type 98, version 0, 14400 bps,
    /// transferredTCF, 1024-byte buffer, 238-byte datagrams, redundancy EC.
    pub fn default_t38() -> Self {
        Self::default()
    }
}

/// Which audio, video, data and image codecs are offered in SDP.
/// `None` (the default): built-ins — Opus + PCMU, VP8, an SCTP data
/// section, no image.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaCapabilities {
    /// Audio codecs to offer, in offer order.
    pub audio: Vec<AudioCapability>,
    /// Video codecs to offer, in offer order.
    pub video: Vec<VideoCapability>,
    /// Some: offer an `m=application` (data channel) section with this
    /// SCTP port. `None`: no data-channel offer.
    pub application: Option<ApplicationCapability>,
    /// Image (T.38 fax) codecs to offer, in offer order.
    pub image: Vec<T38Capability>,
}

impl Default for MediaCapabilities {
    fn default() -> Self {
        Self {
            audio: vec![AudioCapability::opus(), AudioCapability::pcmu()],
            video: vec![VideoCapability::default()],
            application: Some(ApplicationCapability::default()),
            image: vec![],
        }
    }
}

/// The pluggable per-media-kind RTP depacketizer factory.
#[derive(Clone)]
pub struct DepacketizerStrategy {
    /// Builds the depacketizer for each received media kind. Default:
    /// the built-in factory (VP8, H264, Opus; VP9 when the `vp9` feature
    /// is on).
    pub factory: Arc<dyn DepacketizerFactory>,
}

impl Default for DepacketizerStrategy {
    fn default() -> Self {
        Self {
            factory: Arc::new(DefaultDepacketizerFactory),
        }
    }
}

impl Debug for DepacketizerStrategy {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        self.factory.fmt(f)
    }
}

impl PartialEq for DepacketizerStrategy {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.factory, &other.factory)
    }
}

impl Eq for DepacketizerStrategy {}

fn default_enable_gcc() -> bool {
    true
}

fn default_rtp_buffer_capacity() -> usize {
    100
}

fn default_buffer_stats_log_interval() -> core::time::Duration {
    core::time::Duration::from_secs(10)
}

fn default_enable_upnp() -> bool {
    false
}

fn default_upnp_lease_duration() -> u32 {
    3600
}

fn default_upnp_discovery_timeout() -> core::time::Duration {
    core::time::Duration::from_secs(1)
}

fn default_upnp_refresh_interval() -> core::time::Duration {
    core::time::Duration::from_secs(30)
}

/// Primary configuration for a `PeerConnection`.
///
/// There is no default: start from the kind of peer,
/// [`RtcConfiguration::webrtc`] or [`RtcConfiguration::sip`], and change
/// what you need. They differ in `connectivity`, `keying`,
/// `webrtc_extensions`, `rtcp_mux_policy` and `bundle_policy`; the other
/// fields have the same values.
///
/// Note on serde: `connectivity`, `keying`, `webrtc_extensions`,
/// `bundle_policy` and `rtcp_mux_policy` have no defaults — a serialized
/// config must carry all five, so a config file written before 0.6 fails
/// to deserialize and must be migrated.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcConfiguration {
    /// STUN/TURN servers for candidate gathering (full ICE only; direct
    /// transports gather no server candidates). Empty: host candidates
    /// only.
    pub ice_servers: Vec<IceServer>,
    /// Which candidate types ICE may use. Default:
    /// [`IceTransportPolicy::All`].
    pub ice_transport_policy: IceTransportPolicy,
    /// Which m-lines of an offer have a transport of their own. See
    /// [`BundlePolicy`].
    pub bundle_policy: BundlePolicy,
    /// RTP/RTCP multiplexing policy. See [`RtcpMuxPolicy`].
    pub rtcp_mux_policy: RtcpMuxPolicy,
    /// Unused: vestigial from the W3C `RTCConfiguration.certificates`
    /// mirror. DTLS-SRTP key material goes in `dtls_certificate`; nothing
    /// reads this field.
    pub certificates: Vec<CertificateConfig>,
    /// How the media path is found.
    pub connectivity: Connectivity,
    /// How the SRTP keys are exchanged.
    pub keying: Keying,
    /// The peer is a WebRTC endpoint (a browser, an SFU): offers claim
    /// header extension ids for rid, repaired-rid and abs-send-time; with
    /// `enable_gcc`, descriptions carry transport-cc and we send TWCC
    /// feedback; descriptions carry `msid`. Answers echo the rid and
    /// abs-send-time ids the remote offered either way. SIP peers do not use
    /// these: set it to false for them. (sdes:mid goes with BUNDLE, see
    /// [`BundlePolicy`].)
    pub webrtc_extensions: bool,
    /// Size of the per-SSRC NACK retransmission-request buffer, in
    /// packets (default 200): how far back lost-sequence tracking looks.
    pub nack_buffer_size: usize,
    /// Enable the TWCC + GCC bandwidth-adaptation loop: stamp outgoing RTP
    /// with the transport-cc sequence-number extension, generate TWCC feedback
    /// for inbound streams, and expose a sender `target_bitrate` estimate.
    /// Only with `webrtc_extensions`.
    /// Default: true (no in-library send-rate limiting; apps opt in via
    /// `RtpSender::subscribe_target_bitrate`).
    #[serde(default = "default_enable_gcc")]
    pub enable_gcc: bool,
    /// Which audio, video, data and image codecs to offer. `None` (the
    /// default): the built-in codec set (Opus + PCMU, VP8, SCTP data,
    /// no image). See [`MediaCapabilities`].
    pub media_capabilities: Option<MediaCapabilities>,
    /// Public addresses to advertise instead of the local ones (1:1 NAT, a
    /// router that forwards the RTP ports), at most one per family. A
    /// candidate takes the external address of its family, and so do `c=`
    /// and `o=`; a family with none advertises the local address. The local
    /// address is the candidate's `related_address` (its base).
    pub external_ips: Vec<IpAddr>,
    /// How ICE candidates advertise `external_ips`.
    #[serde(default)]
    pub external_ip_candidate_type: ExternalIpCandidateType,
    /// Override the advertised port in SDP `m=` line and candidates
    /// (for NAT port forwarding).
    ///
    /// When set, the SDP will advertise this port instead of the local
    /// bind port. This is useful when you have configured NAT port
    /// forwarding (e.g. external port 30000 → local port 20000) and need
    /// the remote peer to send RTP to the external port.
    ///
    /// Works independently or combined with `external_ips`.
    /// Only applies to direct transports (`Connectivity::Sdp` /
    /// `Connectivity::IceLite`). Not used with full ICE.
    pub external_port: Option<u16>,
    /// Local addresses to bind media sockets on: one socket on each. Empty:
    /// chosen for us (full ICE: every interface; a direct transport: the
    /// address of the default route). A socket on `::` serves IPv4 and IPv6
    /// (`IPV6_V6ONLY` off), and has a candidate for each family: the
    /// external address of the family, else the local address of its
    /// default route. A socket on a given address serves its family only.
    pub bind_ips: Vec<IpAddr>,
    /// Our offers on a direct transport (see [`Connectivity`]) put an IPv6 candidate in
    /// `c=` and the `m=` port when there is one; else IPv4 goes first. An
    /// answer takes the family of the offer (RFC 6157 §4.1), and once a pair
    /// is selected, later descriptions keep its family. Default: false.
    #[serde(default)]
    pub prefer_ipv6: bool,
    /// Do not gather or use IPv6 candidates or addresses. Default: false.
    pub disable_ipv6: bool,
    /// The SSRC of the first sender; later senders count up from it. Random
    /// by default, as RFC 3550 §8.1 asks: a fixed start gives every peer
    /// connection the same SSRCs.
    pub ssrc_start: u32,
    /// Timeout for one STUN transaction to a server (retransmission
    /// schedule ends here). Default 5 s.
    pub stun_timeout: core::time::Duration,
    /// Upper bound on STUN/TURN *server* candidate gathering. A slow or hung
    /// server must not delay the offer past this: candidates that arrived in
    /// time are advertised, the rest are dropped. `ZERO` (the default) means
    /// unbounded — the historical behaviour; embedders with tight call-setup
    /// windows (rtcembed's WebRTC profile) set a small bound.
    pub ice_gather_timeout: core::time::Duration,
    /// Timeout for the ICE nomination binding check (USE-CANDIDATE).
    /// This should be larger than `stun_timeout` to allow more retransmissions
    /// and reduce the probability of nomination failures under packet loss.
    pub nomination_timeout: core::time::Duration,
    /// How long to keep collecting successful pairs after the first one
    /// before nominating. A short grace favours fast setup but lets a
    /// low-priority relay pair (checks complete in ~1 RTT to the TURN
    /// server) beat a higher-priority direct pair that needs a cross-ISP
    /// round trip (~300 ms in practice) — the session then stays on relay
    /// even though a direct path validates moments later. Port-forwarding
    /// and tunnel use cases should raise this (e.g. 500 ms) so relay
    /// stays a true last resort.
    pub nomination_grace: core::time::Duration,
    /// Timeout without any STUN response before the ICE transport goes
    /// to `Failed` (the hard failure threshold; see
    /// `ice_disconnect_threshold` for the recoverable path). Default
    /// 120 s.
    pub ice_connection_timeout: core::time::Duration,
    /// How long without receiving any packet (STUN/DTLS/SCTP) before the ICE
    /// transport is demoted from `Connected` to `Disconnected`.
    ///
    /// `Disconnected` is a recoverable state — the SCTP association is **not**
    /// torn down (see `peer_connection.rs`); the transport waits for traffic to
    /// resume. Keep this comfortably below `ice_connection_timeout`, which is
    /// the hard, non-recoverable failure threshold.
    ///
    /// Default: 30s. Raise it further (e.g. 120s) for long-lived
    /// tunnels (SSH/port-forwarding) over lossy links where brief blackouts are
    /// expected and must not even flap the SCTP association.
    pub ice_disconnect_threshold: core::time::Duration,
    /// How long to wait in `Disconnected` state before tearing down the
    /// PeerConnection (SCTP/DTLS). When ICE goes `Disconnected` the transport
    /// is given this long to recover before the connection is closed.
    ///
    /// This is distinct from `ice_connection_timeout` which operates at the
    /// ICE transport layer. This grace period gives the application a chance
    /// to observe `PeerConnectionState::Disconnected` and react, while still
    /// bounding how long a dead connection lingers.
    ///
    /// Set to 0 to tear down immediately on ICE Disconnected.
    /// Default: 60s
    pub ice_disconnect_grace: core::time::Duration,
    /// Initial SCTP retransmission timeout (RFC 9294 RTO). Default 3 s.
    pub sctp_rto_initial: core::time::Duration,
    /// Lower bound of the SCTP retransmission timeout. Default 200 ms.
    pub sctp_rto_min: core::time::Duration,
    /// Upper bound of the SCTP retransmission timeout. Default 60 s.
    pub sctp_rto_max: core::time::Duration,
    /// SCTP retransmissions of the INIT/HEARTBEAT chunk before the
    /// association is declared dead. Default 20.
    pub sctp_max_association_retransmits: u32,
    /// SCTP advertised receiver window in bytes. Default 128 KB.
    pub sctp_receive_window: usize,
    /// Interval between SCTP HEARTBEAT chunks on idle associations.
    /// Default 15 s.
    pub sctp_heartbeat_interval: core::time::Duration,
    /// Missed HEARTBEAT acks before an idle association is declared dead.
    /// Default 4.
    pub sctp_max_heartbeat_failures: u32,
    /// How often one DATA chunk is retransmitted before the association
    /// aborts. Default 8.
    pub sctp_max_tsn_retransmits: u32,
    /// Cap on DATA chunks sent per CWND window ("burst control"); 0 uses
    /// the built-in heuristic. Default 0.
    pub sctp_max_burst: usize,
    /// Congestion-window ceiling in bytes. Default 256 KB.
    pub sctp_max_cwnd: usize,
    /// Per-data-channel send-side buffered-amount limit in bytes (sum of
    /// in-flight + queued payload bytes). The sender blocks when the total
    /// exceeds this threshold, bounding per-channel peak RSS regardless of
    /// peer speed. Default 256 KB;  0 disables the gate (unbounded).
    pub sctp_max_buffered_amount: usize,
    /// DTLS record read-buffer size in bytes. Default 2048 (fits a full
    /// MTU record).
    pub dtls_buffer_size: usize,
    /// Pre-provisioned DTLS leaf certificate (DER) + PKCS#8 private key.
    /// Required for DTLS keying without `std` (no certificate generation
    /// on embedded); ignored with other keying. When unset on `std`, a fresh
    /// self-signed certificate is generated per connection.
    #[serde(skip)]
    pub dtls_certificate: Option<Arc<crate::transports::dtls::Certificate>>,
    /// Lower bound of the UDP port range for media sockets (RTP/ICE).
    /// `None`: any ephemeral port.
    pub rtp_start_port: Option<u16>,
    /// Upper bound of the UDP port range for media sockets (RTP/ICE).
    /// `None`: any ephemeral port.
    pub rtp_end_port: Option<u16>,
    /// Gather UDP host candidates on the local interfaces (with
    /// [`IceTransportPolicy::All`]). Default: true. When false, offers
    /// carry only server-reflexive, relay and ICE-TCP candidates — local
    /// IPs stay out of the SDP.
    pub ice_gather_udp_hosts: bool,
    /// Whether to gather and advertise loopback (127.0.0.1 / ::1) host
    /// candidates when no explicit `bind_ips` are configured.
    ///
    /// Default: false — loopback candidates are unreachable by any remote
    /// peer: they leak host internals in SDP and make remote agents waste
    /// TURN permissions and connectivity checks on dead candidates (a same-
    /// host TURN relay can even forward them back to itself). Set to `true`
    /// for same-host testing where no non-loopback interface exists. An
    /// explicit `bind_ips = [127.0.0.1]` is unaffected by this flag.
    #[serde(default)]
    pub ice_include_loopback_candidates: bool,
    /// Lower bound of the TCP listen range for passive ICE-TCP candidates
    /// (with [`IceTcpPolicy::Enabled`]/[`IceTcpPolicy::PassiveOnly`]).
    /// `None`: OS-assigned.
    pub tcp_port_range_start: Option<u16>,
    /// Upper bound of the TCP listen range for passive ICE-TCP candidates.
    /// `None`: OS-assigned.
    pub tcp_port_range_end: Option<u16>,
    /// Detect the peer's real media address from the first arriving
    /// packets, and send there — for peers whose SDP address is wrong
    /// (behind symmetric NAT). Direct transports
    /// ([`Connectivity::Sdp`] / [`Connectivity::IceLite`]) only; see the
    /// README's RTP Latching section. Default: false.
    pub enable_latching: bool,
    /// packets to observe before committing a latched address; `None`
    /// (the default) uses the built-in budget. A single packet never
    /// moves the egress address.
    pub probation_max_packets: Option<u8>,
    /// When true, demote host candidates with private (RFC 1918) local IPs
    /// below server-reflexive candidates in the connectivity check ordering.
    /// This avoids DTLS handshake failures behind NATs where a host candidate
    /// can pass a single STUN binding check but cannot sustain bidirectional
    /// DTLS traffic.  Same-LAN pairs (both sides private) are not affected.
    /// Default: false (standard RFC 5245 behavior).
    #[serde(default)]
    pub prefer_srflx_over_natted_host: bool,
    /// Enable UPnP IGD for automatic port mapping
    #[serde(default = "default_enable_upnp")]
    pub enable_upnp: bool,
    /// Advertise host candidates via mDNS (draft-ietf-rtcweb-mdns): the SDP
    /// carries `<random>.local` hostnames instead of local IPs, and an mDNS
    /// responder answers A/AAAA lookups for them. Real addresses are kept
    /// internally, so connectivity is unaffected. Default: false.
    #[serde(default)]
    pub enable_mdns: bool,
    /// UPnP port mapping lease duration in seconds
    #[serde(default = "default_upnp_lease_duration")]
    pub upnp_lease_duration: u32,
    /// UPnP gateway discovery timeout
    #[serde(default = "default_upnp_discovery_timeout")]
    pub upnp_discovery_timeout: core::time::Duration,
    /// How often to refresh UPnP port mappings before the router lease expires.
    /// Re-issuing AddPortMapping with the same external port renews the lease on
    /// most IGDs without deleting the mapping, so long-lived sessions survive
    /// the default lease (3600s) without inbound path loss.
    #[serde(default = "default_upnp_refresh_interval")]
    pub upnp_refresh_interval: core::time::Duration,
    /// Per-media-kind RTP depacketizer factory (see
    /// [`DepacketizerStrategy`]). Default: the built-in factory.
    #[serde(skip, default)]
    pub depacketizer_strategy: DepacketizerStrategy,
    /// Per-SSRC receive (jitter) buffer capacity in packets. Default 100.
    #[serde(default = "default_rtp_buffer_capacity")]
    pub rtp_buffer_capacity: usize,
    /// What to drop when the receive buffer is full. Default:
    /// [`BufferDropStrategy::DropNew`].
    #[serde(default)]
    pub buffer_drop_strategy: BufferDropStrategy,
    /// How often to log receive-buffer occupancy stats. Default 10 s.
    #[serde(default = "default_buffer_stats_log_interval")]
    pub buffer_stats_log_interval: core::time::Duration,
    /// Controls ICE TCP candidate support (RFC 6544).
    /// Default: Disabled — only UDP candidates are gathered and used.
    #[serde(default)]
    pub ice_tcp_policy: IceTcpPolicy,
    /// Enable process-wide shared ICE UDP socket (single-port multiplexing).
    ///
    /// When `true`, multiple `PeerConnection`s share one `UdpSocket` bound to
    /// `ice_udp_mux_port`. Incoming UDP packets are demultiplexed by the server
    /// ufrag embedded in the first STUN Binding Request's `USERNAME` attribute,
    /// and — once a pair is established — by the remote source address.
    ///
    /// Requires `ice_udp_mux_port` to be set. Useful for SFU/WHEP deployments
    /// that need to advertise a single public UDP port for many sessions.
    #[serde(default)]
    pub ice_udp_mux: bool,
    /// UDP port to bind the shared mux socket on. Required when `ice_udp_mux`
    /// is enabled. All `PeerConnection`s sharing this port must agree on it.
    #[serde(default)]
    pub ice_udp_mux_port: Option<u16>,
    /// Free-form label for this connection (logs, diagnostics). Not
    /// serialized.
    #[serde(skip, default)]
    pub label: Option<String>,
    /// RTCP SDES CNAME to advertise. `None`: derived from the SSRC /
    /// random. Not serialized.
    #[serde(skip, default)]
    pub cname: Option<String>,
    /// Runtime handle for spawning internal tasks (ICE runner, DTLS, RTCP,
    /// etc.). When set, ALL rustrtc `tokio::spawn` calls use this handle,
    /// pinning media tasks to a dedicated runtime instead of the caller's.
    /// Falls back to `Handle::current()` when `None` (backward-compatible).
    #[serde(skip, default)]
    pub runtime_handle: Option<RuntimeHandle>,
    /// Recording / tapping interceptors installed on every transceiver
    /// created by this PC. Receiver interceptors fire on incoming RTP
    /// (pre-depacketize); sender interceptors fire on outgoing RTP
    /// (post seq/timestamp rewrite, pre-wire).
    #[serde(skip, default)]
    pub recorder_interceptors: RecorderInterceptors,
}

impl PartialEq for RtcConfiguration {
    fn eq(&self, other: &Self) -> bool {
        // Compare all fields except runtime_handle (Handle does not implement Eq).
        self.ice_servers == other.ice_servers
            && self.ice_transport_policy == other.ice_transport_policy
            && self.bundle_policy == other.bundle_policy
            && self.rtcp_mux_policy == other.rtcp_mux_policy
            && self.certificates == other.certificates
            && self.connectivity == other.connectivity
            && self.keying == other.keying
            && self.webrtc_extensions == other.webrtc_extensions
            && self.nack_buffer_size == other.nack_buffer_size
            && self.enable_gcc == other.enable_gcc
            && self.media_capabilities == other.media_capabilities
            && self.external_ips == other.external_ips
            && self.external_ip_candidate_type == other.external_ip_candidate_type
            && self.external_port == other.external_port
            && self.bind_ips == other.bind_ips
            && self.prefer_ipv6 == other.prefer_ipv6
            && self.disable_ipv6 == other.disable_ipv6
            && self.ssrc_start == other.ssrc_start
            && self.stun_timeout == other.stun_timeout
            && self.ice_gather_timeout == other.ice_gather_timeout
            && self.nomination_timeout == other.nomination_timeout
            && self.nomination_grace == other.nomination_grace
            && self.ice_connection_timeout == other.ice_connection_timeout
            && self.ice_disconnect_threshold == other.ice_disconnect_threshold
            && self.ice_disconnect_grace == other.ice_disconnect_grace
            && self.sctp_rto_initial == other.sctp_rto_initial
            && self.sctp_rto_min == other.sctp_rto_min
            && self.sctp_rto_max == other.sctp_rto_max
            && self.sctp_max_association_retransmits == other.sctp_max_association_retransmits
            && self.sctp_receive_window == other.sctp_receive_window
            && self.sctp_heartbeat_interval == other.sctp_heartbeat_interval
            && self.sctp_max_heartbeat_failures == other.sctp_max_heartbeat_failures
            && self.sctp_max_tsn_retransmits == other.sctp_max_tsn_retransmits
            && self.sctp_max_burst == other.sctp_max_burst
            && self.sctp_max_cwnd == other.sctp_max_cwnd
            && self.sctp_max_buffered_amount == other.sctp_max_buffered_amount
            && self.dtls_buffer_size == other.dtls_buffer_size
            && self.dtls_certificate == other.dtls_certificate
            && self.rtp_start_port == other.rtp_start_port
            && self.rtp_end_port == other.rtp_end_port
            && self.ice_gather_udp_hosts == other.ice_gather_udp_hosts
            && self.ice_include_loopback_candidates == other.ice_include_loopback_candidates
            && self.tcp_port_range_start == other.tcp_port_range_start
            && self.tcp_port_range_end == other.tcp_port_range_end
            && self.enable_latching == other.enable_latching
            && self.probation_max_packets == other.probation_max_packets
            && self.prefer_srflx_over_natted_host == other.prefer_srflx_over_natted_host
            && self.enable_upnp == other.enable_upnp
            && self.upnp_lease_duration == other.upnp_lease_duration
            && self.upnp_discovery_timeout == other.upnp_discovery_timeout
            && self.upnp_refresh_interval == other.upnp_refresh_interval
            && self.depacketizer_strategy == other.depacketizer_strategy
            && self.rtp_buffer_capacity == other.rtp_buffer_capacity
            && self.buffer_drop_strategy == other.buffer_drop_strategy
            && self.buffer_stats_log_interval == other.buffer_stats_log_interval
            && self.ice_tcp_policy == other.ice_tcp_policy
            && self.ice_udp_mux == other.ice_udp_mux
            && self.ice_udp_mux_port == other.ice_udp_mux_port
            && self.label == other.label
            && self.cname == other.cname
        // runtime_handle is intentionally omitted
    }
}

impl Eq for RtcConfiguration {}

impl RtcConfiguration {
    /// For a WebRTC peer (a browser, an SFU): full ICE, DTLS-SRTP, the
    /// WebRTC header extensions, RTCP multiplexing required, one transport
    /// for all m-lines (BUNDLE).
    pub fn webrtc() -> Self {
        Self::new(
            Connectivity::Ice,
            Keying::Dtls,
            true,
            RtcpMuxPolicy::Require,
            BundlePolicy::MaxBundle,
        )
    }

    /// For a SIP peer (a trunk, a phone, a PBX): the address of its SDP (no
    /// ICE), plain RTP, no WebRTC header extensions, RTCP multiplexing when
    /// the peer accepts it, a transport for each kind of media without
    /// BUNDLE. Change `keying` for SDES-SRTP, `connectivity` for ICE-lite.
    pub fn sip() -> Self {
        Self::new(
            Connectivity::Sdp,
            Keying::None,
            false,
            RtcpMuxPolicy::Negotiate,
            BundlePolicy::Balanced,
        )
    }

    fn new(
        connectivity: Connectivity,
        keying: Keying,
        webrtc_extensions: bool,
        rtcp_mux_policy: RtcpMuxPolicy,
        bundle_policy: BundlePolicy,
    ) -> Self {
        Self {
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::default(),
            bundle_policy,
            rtcp_mux_policy,
            certificates: Vec::new(),
            connectivity,
            keying,
            webrtc_extensions,
            nack_buffer_size: 200,
            enable_gcc: default_enable_gcc(),
            media_capabilities: None,
            external_ips: Vec::new(),
            external_ip_candidate_type: ExternalIpCandidateType::default(),
            external_port: None,
            bind_ips: Vec::new(),
            prefer_ipv6: false,
            disable_ipv6: false,
            ssrc_start: crate::transports::ice::stun::random_u32(),
            stun_timeout: core::time::Duration::from_secs(5),
            ice_gather_timeout: core::time::Duration::ZERO,
            nomination_timeout: core::time::Duration::from_secs(10),
            nomination_grace: core::time::Duration::from_millis(200),
            ice_connection_timeout: core::time::Duration::from_secs(120),
            ice_disconnect_threshold: core::time::Duration::from_secs(30),
            ice_disconnect_grace: core::time::Duration::from_secs(60),
            sctp_rto_initial: core::time::Duration::from_secs(3),
            sctp_rto_min: core::time::Duration::from_millis(200),
            sctp_rto_max: core::time::Duration::from_secs(60),
            sctp_max_association_retransmits: 20,
            sctp_receive_window: 128 * 1024, // 128KB - reduced for lower memory footprint
            sctp_heartbeat_interval: core::time::Duration::from_secs(15),
            sctp_max_heartbeat_failures: 4,
            sctp_max_tsn_retransmits: 8,
            sctp_max_burst: 0,                    // 0 = use default heuristic
            sctp_max_cwnd: 256 * 1024,            // 256 KB
            sctp_max_buffered_amount: 256 * 1024, // 256 KB
            dtls_buffer_size: 2048,
            dtls_certificate: None,
            rtp_start_port: None,
            rtp_end_port: None,
            ice_gather_udp_hosts: true,
            ice_include_loopback_candidates: false,
            tcp_port_range_start: None,
            tcp_port_range_end: None,
            enable_latching: false,
            probation_max_packets: None,
            prefer_srflx_over_natted_host: false,
            enable_upnp: default_enable_upnp(),
            enable_mdns: false,
            upnp_lease_duration: default_upnp_lease_duration(),
            upnp_discovery_timeout: default_upnp_discovery_timeout(),
            upnp_refresh_interval: default_upnp_refresh_interval(),
            depacketizer_strategy: DepacketizerStrategy::default(),
            rtp_buffer_capacity: default_rtp_buffer_capacity(),
            buffer_drop_strategy: BufferDropStrategy::default(),
            buffer_stats_log_interval: default_buffer_stats_log_interval(),
            ice_tcp_policy: IceTcpPolicy::default(),
            ice_udp_mux: false,
            ice_udp_mux_port: None,
            label: None,
            cname: None,
            runtime_handle: None,
            recorder_interceptors: RecorderInterceptors::default(),
        }
    }
}

/// Builder over [`RtcConfiguration`]. Start from the kind of peer,
/// [`RtcConfigurationBuilder::webrtc`] or [`RtcConfigurationBuilder::sip`],
/// chain the setters you need, then [`RtcConfigurationBuilder::build`].
pub struct RtcConfigurationBuilder {
    inner: RtcConfiguration,
}

/// Wrapper for interceptor lists so that `RtcConfiguration` can still derive
/// `Debug / Clone / PartialEq / Eq` — the actual interceptor trait objects
/// are opaque and only compared by count.
#[derive(Clone, Default)]
pub struct RecorderInterceptors {
    /// Fire on every incoming RTP packet, pre-depacketize.
    #[cfg(feature = "std")]
    pub receivers: Vec<Arc<dyn RtpReceiverInterceptor>>,
    /// Fire on every outgoing RTP packet, post seq/timestamp rewrite.
    #[cfg(feature = "std")]
    pub senders: Vec<Arc<dyn RtpSenderInterceptor>>,
}

impl Debug for RecorderInterceptors {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        #[cfg(feature = "std")]
        {
            return f
                .debug_struct("RecorderInterceptors")
                .field("receivers_len", &self.receivers.len())
                .field("senders_len", &self.senders.len())
                .finish();
        }
        #[cfg(not(feature = "std"))]
        {
            f.debug_struct("RecorderInterceptors").finish()
        }
    }
}

impl PartialEq for RecorderInterceptors {
    #[cfg_attr(not(feature = "std"), allow(unused_variables))]
    fn eq(&self, other: &Self) -> bool {
        #[cfg(feature = "std")]
        {
            self.receivers.len() == other.receivers.len()
                && self.senders.len() == other.senders.len()
        }
        #[cfg(not(feature = "std"))]
        {
            true
        }
    }
}

impl Eq for RecorderInterceptors {}

impl RtcConfigurationBuilder {
    /// Start from [`RtcConfiguration::webrtc`].
    pub fn webrtc() -> Self {
        Self {
            inner: RtcConfiguration::webrtc(),
        }
    }

    /// Start from [`RtcConfiguration::sip`].
    pub fn sip() -> Self {
        Self {
            inner: RtcConfiguration::sip(),
        }
    }

    /// See [`RtcConfiguration::enable_latching`].
    pub fn enable_latching(mut self, enable: bool) -> Self {
        self.inner.enable_latching = enable;
        self
    }

    /// See [`RtcConfiguration::probation_max_packets`].
    pub fn probation_max_packets(mut self, max: Option<u8>) -> Self {
        self.inner.probation_max_packets = max;
        self
    }

    /// See [`RtcConfiguration::prefer_srflx_over_natted_host`].
    pub fn prefer_srflx_over_natted_host(mut self, enable: bool) -> Self {
        self.inner.prefer_srflx_over_natted_host = enable;
        self
    }

    /// Enable UPnP IGD automatic port mapping (default false).
    pub fn enable_upnp(mut self, enable: bool) -> Self {
        self.inner.enable_upnp = enable;
        self
    }

    /// Advertise host candidates via mDNS (default false). See
    /// [`RtcConfiguration::enable_mdns`].
    pub fn enable_mdns(mut self, enable: bool) -> Self {
        self.inner.enable_mdns = enable;
        self
    }

    /// Enable the TWCC + GCC bandwidth-adaptation loop (default true).
    /// Only with `webrtc_extensions`. See
    /// [`RtcConfiguration::enable_gcc`].
    pub fn enable_gcc(mut self, enable: bool) -> Self {
        self.inner.enable_gcc = enable;
        self
    }

    /// UPnP port-mapping lease duration in seconds (default 3600).
    pub fn upnp_lease_duration(mut self, duration_secs: u32) -> Self {
        self.inner.upnp_lease_duration = duration_secs;
        self
    }

    /// UPnP gateway discovery timeout (default 1 s).
    pub fn upnp_discovery_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.upnp_discovery_timeout = timeout;
        self
    }

    /// Set how often UPnP port mappings are refreshed to keep the router lease alive.
    pub fn upnp_refresh_interval(mut self, interval: core::time::Duration) -> Self {
        self.inner.upnp_refresh_interval = interval;
        self
    }

    /// Append a STUN/TURN server. Full ICE only.
    pub fn ice_server(mut self, server: IceServer) -> Self {
        self.inner.ice_servers.push(server);
        self
    }

    /// Which candidate types ICE may use (default all). See
    /// [`IceTransportPolicy`].
    pub fn ice_transport_policy(mut self, policy: IceTransportPolicy) -> Self {
        self.inner.ice_transport_policy = policy;
        self
    }

    /// Set which m-lines get their own transport. See [`BundlePolicy`].
    pub fn bundle_policy(mut self, policy: BundlePolicy) -> Self {
        self.inner.bundle_policy = policy;
        self
    }

    /// Set the RTP/RTCP multiplexing policy. See [`RtcpMuxPolicy`].
    pub fn rtcp_mux_policy(mut self, policy: RtcpMuxPolicy) -> Self {
        self.inner.rtcp_mux_policy = policy;
        self
    }

    /// Append a certificate (see
    /// [`RtcConfiguration::certificates`] — currently unused).
    pub fn certificate(mut self, cert: CertificateConfig) -> Self {
        self.inner.certificates.push(cert);
        self
    }

    /// Set how the media path is found. See [`Connectivity`].
    pub fn connectivity(mut self, connectivity: Connectivity) -> Self {
        self.inner.connectivity = connectivity;
        self
    }

    /// Set how the SRTP keys are exchanged. See [`Keying`].
    pub fn keying(mut self, keying: Keying) -> Self {
        self.inner.keying = keying;
        self
    }

    /// The peer is a WebRTC endpoint (rid / abs-send-time / transport-cc
    /// extensions, `msid`). See [`RtcConfiguration::webrtc_extensions`].
    pub fn webrtc_extensions(mut self, enable: bool) -> Self {
        self.inner.webrtc_extensions = enable;
        self
    }

    /// Set which codecs to offer (replaces the built-in set).
    /// See [`MediaCapabilities`].
    pub fn media_capabilities(mut self, capabilities: MediaCapabilities) -> Self {
        self.inner.media_capabilities = Some(capabilities);
        self
    }

    /// Set the public addresses to advertise (1:1 NAT, port forwarding).
    /// See [`RtcConfiguration::external_ips`].
    pub fn external_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.inner.external_ips = ips;
        self
    }

    /// Set how `external_ips` are advertised in ICE candidates. See
    /// [`ExternalIpCandidateType`].
    pub fn external_ip_candidate_type(mut self, typ: ExternalIpCandidateType) -> Self {
        self.inner.external_ip_candidate_type = typ;
        self
    }

    /// Advertise this fixed port in the SDP `m=` line and candidates (NAT
    /// port forwarding). Direct transports only. See
    /// [`RtcConfiguration::external_port`].
    pub fn external_port(mut self, port: u16) -> Self {
        self.inner.external_port = Some(port);
        self
    }

    /// Bind media sockets on these addresses. See
    /// [`RtcConfiguration::bind_ips`].
    pub fn bind_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.inner.bind_ips = ips;
        self
    }

    /// Prefer an IPv6 candidate in `c=`/`m=` on direct transports
    /// (default false). See [`RtcConfiguration::prefer_ipv6`].
    pub fn prefer_ipv6(mut self, prefer: bool) -> Self {
        self.inner.prefer_ipv6 = prefer;
        self
    }

    /// Disable IPv6 gathering (default false). See
    /// [`RtcConfiguration::disable_ipv6`].
    pub fn disable_ipv6(mut self, disable: bool) -> Self {
        self.inner.disable_ipv6 = disable;
        self
    }

    /// Fix the first sender's SSRC (random by default). See
    /// [`RtcConfiguration::ssrc_start`].
    pub fn ssrc_start(mut self, start: u32) -> Self {
        self.inner.ssrc_start = start;
        self
    }

    /// STUN transaction timeout (default 5 s). See
    /// [`RtcConfiguration::stun_timeout`].
    pub fn stun_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.stun_timeout = timeout;
        self
    }

    /// Upper bound on server candidate gathering (default unbounded).
    /// See [`RtcConfiguration::ice_gather_timeout`].
    pub fn ice_gather_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.ice_gather_timeout = timeout;
        self
    }

    /// Nomination (USE-CANDIDATE) check timeout (default 10 s). See
    /// [`RtcConfiguration::nomination_timeout`].
    pub fn nomination_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.nomination_timeout = timeout;
        self
    }

    /// Override the post-first-success nomination grace (see
    /// [`RtcConfiguration::nomination_grace`]).
    pub fn nomination_grace(mut self, grace: core::time::Duration) -> Self {
        self.inner.nomination_grace = grace;
        self
    }

    /// Set the UDP port range for media sockets (RTP/ICE). See
    /// [`RtcConfiguration::rtp_start_port`].
    pub fn rtp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.rtp_start_port = Some(start);
        self.inner.rtp_end_port = Some(end);
        self
    }

    /// Gather UDP host candidates (default true). See
    /// [`RtcConfiguration::ice_gather_udp_hosts`].
    pub fn ice_gather_udp_hosts(mut self, enable: bool) -> Self {
        self.inner.ice_gather_udp_hosts = enable;
        self
    }

    /// Gather and advertise loopback host candidates (default false). See
    /// `RtcConfiguration::ice_include_loopback_candidates`.
    pub fn ice_include_loopback_candidates(mut self, enable: bool) -> Self {
        self.inner.ice_include_loopback_candidates = enable;
        self
    }

    /// Set the TCP listen range for passive ICE-TCP candidates. See
    /// [`RtcConfiguration::tcp_port_range_start`].
    pub fn tcp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.tcp_port_range_start = Some(start);
        self.inner.tcp_port_range_end = Some(end);
        self
    }

    /// DTLS record read-buffer size in bytes (default 2048). See
    /// [`RtcConfiguration::dtls_buffer_size`].
    pub fn dtls_buffer_size(mut self, size: usize) -> Self {
        self.inner.dtls_buffer_size = size;
        self
    }

    /// Pre-provisioned DTLS certificate (DER leaf + PKCS#8 key). Required
    /// for DTLS keying on no_std; on std a self-signed certificate is
    /// generated when this is unset.
    pub fn dtls_certificate(mut self, cert: Arc<crate::transports::dtls::Certificate>) -> Self {
        self.inner.dtls_certificate = Some(cert);
        self
    }

    /// SCTP initial retransmission timeout (default 3 s). See
    /// [`RtcConfiguration::sctp_rto_initial`].
    pub fn sctp_rto_initial(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_initial = duration;
        self
    }

    /// SCTP retransmission-timeout lower bound (default 200 ms). See
    /// [`RtcConfiguration::sctp_rto_min`].
    pub fn sctp_rto_min(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_min = duration;
        self
    }

    /// SCTP retransmission-timeout upper bound (default 60 s). See
    /// [`RtcConfiguration::sctp_rto_max`].
    pub fn sctp_rto_max(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_max = duration;
        self
    }

    /// INIT/HEARTBEAT retransmissions before the association aborts
    /// (default 20). See
    /// [`RtcConfiguration::sctp_max_association_retransmits`].
    pub fn sctp_max_association_retransmits(mut self, count: u32) -> Self {
        self.inner.sctp_max_association_retransmits = count;
        self
    }

    /// SCTP advertised receive window in bytes (default 128 KB). See
    /// [`RtcConfiguration::sctp_receive_window`].
    pub fn sctp_receive_window(mut self, size: usize) -> Self {
        self.inner.sctp_receive_window = size;
        self
    }

    /// SCTP HEARTBEAT interval on idle associations (default 15 s). See
    /// [`RtcConfiguration::sctp_heartbeat_interval`].
    pub fn sctp_heartbeat_interval(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_heartbeat_interval = duration;
        self
    }

    /// Missed HEARTBEAT acks before an idle association aborts (default
    /// 4). See [`RtcConfiguration::sctp_max_heartbeat_failures`].
    pub fn sctp_max_heartbeat_failures(mut self, count: u32) -> Self {
        self.inner.sctp_max_heartbeat_failures = count;
        self
    }

    /// Set the maximum burst size for SCTP in number of MTU-sized packets.
    /// 0 means use the default heuristic (16 packets normal, 4 in recovery).
    /// For rate-limited TURN relays, a value of 2-4 can reduce burst-induced
    /// packet loss.
    pub fn sctp_max_burst(mut self, packets: usize) -> Self {
        self.inner.sctp_max_burst = packets;
        self
    }

    /// Set the maximum congestion window size in bytes.
    /// Default is 256 KB. For high-latency TURN relays, consider 512KB-1MB.
    pub fn sctp_max_cwnd(mut self, size: usize) -> Self {
        self.inner.sctp_max_cwnd = size;
        self
    }

    /// Per-data-channel send-side buffered-amount limit in bytes.
    /// Default is 256 KB. Set to 0 for unbounded (compatibility with pre-0.3.114
    /// behavior that had no gate). A non-zero limit bounds the sum of in-flight
    /// and queued payload bytes per data channel, blocking `send()`/`send_text()`
    /// until the buffer drains below the threshold.
    pub fn sctp_max_buffered_amount(mut self, bytes: usize) -> Self {
        self.inner.sctp_max_buffered_amount = bytes;
        self
    }

    /// ICE hard-failure timeout (default 120 s). See
    /// [`RtcConfiguration::ice_connection_timeout`].
    pub fn ice_connection_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.ice_connection_timeout = timeout;
        self
    }

    /// Connected → Disconnected inactivity threshold (default 30 s). See
    /// [`RtcConfiguration::ice_disconnect_threshold`].
    pub fn ice_disconnect_threshold(mut self, threshold: core::time::Duration) -> Self {
        self.inner.ice_disconnect_threshold = threshold;
        self
    }

    /// Time in `Disconnected` before teardown (default 60 s). See
    /// [`RtcConfiguration::ice_disconnect_grace`].
    pub fn ice_disconnect_grace(mut self, grace: core::time::Duration) -> Self {
        self.inner.ice_disconnect_grace = grace;
        self
    }

    /// Per-SSRC receive buffer capacity in packets (default 100). See
    /// [`RtcConfiguration::rtp_buffer_capacity`].
    pub fn rtp_buffer_capacity(mut self, capacity: usize) -> Self {
        self.inner.rtp_buffer_capacity = capacity;
        self
    }

    /// What to drop when the receive buffer is full. See
    /// [`BufferDropStrategy`].
    pub fn buffer_drop_strategy(mut self, strategy: BufferDropStrategy) -> Self {
        self.inner.buffer_drop_strategy = strategy;
        self
    }

    /// Receive-buffer stats log interval (default 10 s). See
    /// [`RtcConfiguration::buffer_stats_log_interval`].
    pub fn buffer_stats_log_interval(mut self, interval: core::time::Duration) -> Self {
        self.inner.buffer_stats_log_interval = interval;
        self
    }

    /// Set ICE TCP candidate support (RFC 6544; default disabled). See
    /// [`IceTcpPolicy`].
    pub fn ice_tcp_policy(mut self, policy: IceTcpPolicy) -> Self {
        self.inner.ice_tcp_policy = policy;
        self
    }

    /// Enable process-wide shared ICE UDP socket (single-port multiplexing).
    /// Requires `ice_udp_mux_port` to also be set.
    pub fn ice_udp_mux(mut self, enable: bool) -> Self {
        self.inner.ice_udp_mux = enable;
        self
    }

    /// Set the shared UDP mux port. Must be set when `ice_udp_mux` is enabled.
    pub fn ice_udp_mux_port(mut self, port: u16) -> Self {
        self.inner.ice_udp_mux_port = Some(port);
        self
    }

    /// Set the RTCP SDES CNAME to advertise (default: derived). See
    /// [`RtcConfiguration::cname`].
    pub fn cname(mut self, cname: String) -> Self {
        self.inner.cname = Some(cname);
        self
    }

    /// Append a receiver interceptor (fires on every incoming RTP packet,
    /// pre-depacketize).
    #[cfg(feature = "std")]
    pub fn receiver_interceptor(mut self, interceptor: Arc<dyn RtpReceiverInterceptor>) -> Self {
        self.inner.recorder_interceptors.receivers.push(interceptor);
        self
    }

    /// Append a sender interceptor (fires on every outgoing RTP packet,
    /// post seq/timestamp rewrite).
    #[cfg(feature = "std")]
    pub fn sender_interceptor(mut self, interceptor: Arc<dyn RtpSenderInterceptor>) -> Self {
        self.inner.recorder_interceptors.senders.push(interceptor);
        self
    }

    /// Set the runtime handle for spawning internal tasks (ICE runner, DTLS,
    /// RTCP loops, etc.). When set, all rustrtc-internal tokio::spawn calls
    /// go through this runtime instead of the ambient tokio runtime.
    pub fn runtime_handle(mut self, handle: RuntimeHandle) -> Self {
        self.inner.runtime_handle = Some(handle);
        self
    }

    /// Finish the builder.
    pub fn build(self) -> RtcConfiguration {
        self.inner
    }
}

impl From<RtcConfigurationBuilder> for RtcConfiguration {
    fn from(builder: RtcConfigurationBuilder) -> Self {
        builder.build()
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::*;
    use core::time::Duration;

    #[test]
    fn default_ssrc_start_is_random() {
        // Two peer connections must not share SSRCs by default. (A false
        // failure needs two equal random u32s: 1 in 2^32.)
        assert_ne!(
            RtcConfiguration::webrtc().ssrc_start,
            RtcConfiguration::webrtc().ssrc_start
        );
    }

    #[test]
    fn test_rtc_configuration_defaults() {
        let config = RtcConfiguration::webrtc();
        assert_eq!(config.ice_connection_timeout, Duration::from_secs(120));
        assert_eq!(config.ice_disconnect_threshold, Duration::from_secs(30));
        assert_eq!(config.ice_disconnect_grace, Duration::from_secs(60));
        assert_eq!(config.sctp_rto_initial, Duration::from_secs(3));
        assert_eq!(config.sctp_rto_min, Duration::from_millis(200));
        assert_eq!(config.sctp_rto_max, Duration::from_secs(60));
        assert_eq!(config.sctp_max_association_retransmits, 20);
        assert_eq!(config.sctp_heartbeat_interval, Duration::from_secs(15));
        assert_eq!(config.sctp_max_heartbeat_failures, 4);
        assert_eq!(config.sctp_max_burst, 0);
        assert_eq!(config.sctp_max_cwnd, 256 * 1024);
        assert_eq!(config.rtp_buffer_capacity, 100);
        assert_eq!(config.buffer_drop_strategy, BufferDropStrategy::DropNew);
        assert_eq!(config.buffer_stats_log_interval, Duration::from_secs(10));
    }

    #[test]
    fn test_rtc_configuration_builder() {
        let config = RtcConfigurationBuilder::webrtc()
            .stun_timeout(Duration::from_secs(10))
            .build();
        assert_eq!(config.stun_timeout, Duration::from_secs(10));
        // Verify other defaults are still there
        assert_eq!(config.ice_connection_timeout, Duration::from_secs(120));
    }

    #[test]
    fn test_buffer_config_builder() {
        let config = RtcConfigurationBuilder::webrtc()
            .rtp_buffer_capacity(200)
            .buffer_drop_strategy(BufferDropStrategy::DropOldest)
            .buffer_stats_log_interval(Duration::from_secs(5))
            .build();
        assert_eq!(config.rtp_buffer_capacity, 200);
        assert_eq!(config.buffer_drop_strategy, BufferDropStrategy::DropOldest);
        assert_eq!(config.buffer_stats_log_interval, Duration::from_secs(5));
    }

    #[test]
    fn test_sctp_builder_methods() {
        let config = RtcConfigurationBuilder::webrtc()
            .sctp_rto_initial(Duration::from_millis(500))
            .sctp_rto_min(Duration::from_millis(200))
            .sctp_rto_max(Duration::from_secs(10))
            .sctp_max_association_retransmits(30)
            .sctp_receive_window(512 * 1024)
            .sctp_heartbeat_interval(Duration::from_secs(10))
            .sctp_max_heartbeat_failures(8)
            .sctp_max_burst(4)
            .sctp_max_cwnd(512 * 1024)
            .ice_connection_timeout(Duration::from_secs(60))
            .build();

        assert_eq!(config.sctp_rto_initial, Duration::from_millis(500));
        assert_eq!(config.sctp_rto_min, Duration::from_millis(200));
        assert_eq!(config.sctp_rto_max, Duration::from_secs(10));
        assert_eq!(config.sctp_max_association_retransmits, 30);
        assert_eq!(config.sctp_receive_window, 512 * 1024);
        assert_eq!(config.sctp_heartbeat_interval, Duration::from_secs(10));
        assert_eq!(config.sctp_max_heartbeat_failures, 8);
        assert_eq!(config.sctp_max_burst, 4);
        assert_eq!(config.sctp_max_cwnd, 512 * 1024);
        assert_eq!(config.ice_connection_timeout, Duration::from_secs(60));
    }

    #[test]
    fn test_turn_optimized_config() {
        // Verify a TURN-optimized configuration can be expressed cleanly
        let config = RtcConfigurationBuilder::webrtc()
            .sctp_rto_initial(Duration::from_millis(500))
            .sctp_rto_min(Duration::from_millis(100))
            .sctp_rto_max(Duration::from_secs(10))
            .sctp_max_association_retransmits(30)
            .sctp_max_heartbeat_failures(8)
            .sctp_max_burst(4)
            .stun_timeout(Duration::from_secs(10))
            .nomination_timeout(Duration::from_secs(20))
            .build();

        // Verify the TURN-optimized values are more aggressive than defaults
        let defaults = RtcConfiguration::webrtc();
        assert!(config.sctp_rto_initial < defaults.sctp_rto_initial);
        assert!(config.sctp_rto_min < defaults.sctp_rto_min);
        assert!(config.sctp_rto_max < defaults.sctp_rto_max);
        assert!(
            config.sctp_max_association_retransmits > defaults.sctp_max_association_retransmits
        );
        assert!(config.sctp_max_heartbeat_failures > defaults.sctp_max_heartbeat_failures);
        assert!(config.sctp_max_burst > 0); // Explicit burst limit vs. heuristic
    }

    #[test]
    fn test_external_port_defaults() {
        let config = RtcConfiguration::webrtc();
        assert_eq!(config.external_port, None);
    }

    #[test]
    fn test_external_port_builder() {
        let config = RtcConfigurationBuilder::webrtc()
            .external_port(30000)
            .build();
        assert_eq!(config.external_port, Some(30000));
    }

    #[test]
    fn test_external_port_with_external_ip_builder() {
        let config = RtcConfigurationBuilder::webrtc()
            .external_ips(vec!["203.0.113.5".parse().unwrap()])
            .external_port(30000)
            .build();
        assert_eq!(
            config.external_ips,
            vec!["203.0.113.5".parse::<IpAddr>().unwrap()]
        );
        assert_eq!(config.external_port, Some(30000));
    }

    #[test]
    fn test_upnp_defaults() {
        let config = RtcConfiguration::webrtc();
        assert!(!config.enable_upnp, "UPnP should be disabled by default");
        assert_eq!(config.upnp_lease_duration, 3600);
        assert_eq!(config.upnp_refresh_interval, Duration::from_secs(30));
    }

    #[test]
    fn test_upnp_builder_methods() {
        let config = RtcConfigurationBuilder::webrtc()
            .enable_upnp(false)
            .upnp_lease_duration(7200)
            .build();
        assert!(!config.enable_upnp);
        assert_eq!(config.upnp_lease_duration, 7200);
    }

    #[test]
    fn test_upnp_refresh_interval_builder() {
        let config = RtcConfigurationBuilder::webrtc()
            .upnp_refresh_interval(Duration::from_secs(60))
            .build();
        assert_eq!(config.upnp_refresh_interval, Duration::from_secs(60));

        // Refresh interval participates in PartialEq
        let a = RtcConfigurationBuilder::webrtc()
            .upnp_refresh_interval(Duration::from_secs(60))
            .build();
        let b = RtcConfigurationBuilder::webrtc()
            .upnp_refresh_interval(Duration::from_secs(120))
            .build();
        assert_ne!(a, b);
        assert_eq!(a, a.clone());
    }

    #[test]
    fn test_upnp_optimized_config() {
        let config = RtcConfigurationBuilder::webrtc()
            .enable_upnp(true)
            .upnp_lease_duration(1800)
            .build();

        assert!(config.enable_upnp);
        assert_eq!(config.upnp_lease_duration, 1800);

        // Verify defaults remain for other options
        let defaults = RtcConfiguration::webrtc();
        assert_eq!(
            config.ice_connection_timeout,
            defaults.ice_connection_timeout
        );
    }

    #[test]
    fn test_ice_udp_mux_defaults() {
        let config = RtcConfiguration::webrtc();
        assert!(
            !config.ice_udp_mux,
            "ICE UDP mux should be disabled by default"
        );
        assert_eq!(config.ice_udp_mux_port, None);
    }

    #[test]
    fn test_ice_udp_mux_builder_methods() {
        let config = RtcConfigurationBuilder::webrtc()
            .ice_udp_mux(true)
            .ice_udp_mux_port(30500)
            .build();
        assert!(config.ice_udp_mux);
        assert_eq!(config.ice_udp_mux_port, Some(30500));
    }
}
