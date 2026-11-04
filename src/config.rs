use crate::media::depacketizer::{DefaultDepacketizerFactory, DepacketizerFactory};
#[cfg(feature = "std")]
#[cfg(feature = "std")]
use crate::peer_connection::{RtpReceiverInterceptor, RtpSenderInterceptor};
use crate::prelude::*;

/// Spawn-pinning handle. std: tokio runtime handle; no_std: unused
/// placeholder (embassy tasks are spawned by the embedder's executor).
#[cfg(feature = "std")]
pub type RuntimeHandle = tokio::runtime::Handle;
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
    #[default]
    Password,
    Oauth,
}

/// Mirrors the W3C `RTCIceServer` dictionary.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct IceServer {
    pub urls: Vec<String>,
    pub username: Option<String>,
    pub credential: Option<String>,
    #[serde(default)]
    pub credential_type: IceCredentialType,
}

impl IceServer {
    pub fn new<T: Into<Vec<String>>>(urls: T) -> Self {
        Self {
            urls: urls.into(),
            username: None,
            credential: None,
            credential_type: IceCredentialType::default(),
        }
    }

    pub fn with_credential(
        mut self,
        username: impl Into<String>,
        credential: impl Into<String>,
    ) -> Self {
        self.username = Some(username.into());
        self.credential = Some(credential.into());
        self
    }

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum IceTransportPolicy {
    #[default]
    All,
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
/// Full ICE has one ICE agent: it always works as `MaxBundle`.
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
/// [`Keying`].
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
/// [`Connectivity`]. Data channels (SCTP) need `Dtls`.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Keying {
    /// Plain RTP (RTP/AVP).
    None,
    /// SDES, `a=crypto` (RFC 4568), RTP/SAVP.
    Sdes,
    /// DTLS-SRTP, `a=fingerprint` (RFC 5763/5764), UDP/TLS/RTP/SAVPF.
    Dtls,
}

/// Strategy for dropping packets when buffer is full.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BufferDropStrategy {
    #[default]
    DropNew,
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
    /// candidate (1:1 NAT, RFC 8445 §5.1.1.2). WebRTC mode only.
    ServerReflexive,
}

/// Tracks user-supplied certificate material.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct CertificateConfig {
    pub pem_chain: Vec<String>,
    pub private_key_pem: Option<String>,
}

/// Configuration for audio/video codecs and parameters.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AudioCapability {
    pub payload_type: u8,
    pub codec_name: String,
    pub clock_rate: u32,
    pub channels: u8,
    pub fmtp: Option<String>,
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
    pub fn opus() -> Self {
        Self::default()
    }

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct VideoCapability {
    pub payload_type: u8,
    pub codec_name: String,
    pub clock_rate: u32,
    pub fmtp: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ApplicationCapability {
    pub sctp_port: u16,
}

impl Default for ApplicationCapability {
    fn default() -> Self {
        Self { sctp_port: 5000 }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum T38FaxRateManagement {
    #[serde(rename = "transferredTCF")]
    #[default]
    TransferredTCF,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum T38UdpEC {
    #[serde(rename = "t38UDPRedundancy")]
    #[default]
    T38UDPRedundancy,
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct T38Capability {
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
    pub fn default_t38() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaCapabilities {
    pub audio: Vec<AudioCapability>,
    pub video: Vec<VideoCapability>,
    pub application: Option<ApplicationCapability>,
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

#[derive(Clone)]
pub struct DepacketizerStrategy {
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RtcConfiguration {
    pub ice_servers: Vec<IceServer>,
    pub ice_transport_policy: IceTransportPolicy,
    pub bundle_policy: BundlePolicy,
    pub rtcp_mux_policy: RtcpMuxPolicy,
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
    pub nack_buffer_size: usize,
    /// Enable the TWCC + GCC bandwidth-adaptation loop: stamp outgoing RTP
    /// with the transport-cc sequence-number extension, generate TWCC feedback
    /// for inbound streams, and expose a sender `target_bitrate` estimate.
    /// Only with `webrtc_extensions`.
    /// Default: true (no in-library send-rate limiting; apps opt in via
    /// `RtpSender::subscribe_target_bitrate`).
    #[serde(default = "default_enable_gcc")]
    pub enable_gcc: bool,
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
    /// chosen for us (WebRTC: every interface; RTP and SRTP: the address of
    /// the default route). A socket on `::` serves IPv4 and IPv6
    /// (`IPV6_V6ONLY` off), and has a candidate for each family: the
    /// external address of the family, else the local address of its
    /// default route. A socket on a given address serves its family only.
    pub bind_ips: Vec<IpAddr>,
    /// Our offers on a direct transport (RTP, SRTP) put an IPv6 candidate in
    /// `c=` and the `m=` port when there is one; else IPv4 goes first. An
    /// answer takes the family of the offer (RFC 6157 §4.1), and once a pair
    /// is selected, later descriptions keep its family. Default: false.
    #[serde(default)]
    pub prefer_ipv6: bool,
    pub disable_ipv6: bool,
    /// The SSRC of the first sender; later senders count up from it. Random
    /// by default, as RFC 3550 §8.1 asks: a fixed start gives every peer
    /// connection the same SSRCs.
    pub ssrc_start: u32,
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
    pub sctp_rto_initial: core::time::Duration,
    pub sctp_rto_min: core::time::Duration,
    pub sctp_rto_max: core::time::Duration,
    pub sctp_max_association_retransmits: u32,
    pub sctp_receive_window: usize,
    pub sctp_heartbeat_interval: core::time::Duration,
    pub sctp_max_heartbeat_failures: u32,
    pub sctp_max_tsn_retransmits: u32,
    pub sctp_max_burst: usize,
    pub sctp_max_cwnd: usize,
    /// Per-data-channel send-side buffered-amount limit in bytes (sum of
    /// in-flight + queued payload bytes). The sender blocks when the total
    /// exceeds this threshold, bounding per-channel peak RSS regardless of
    /// peer speed. Default 256 KB;  0 disables the gate (unbounded).
    pub sctp_max_buffered_amount: usize,
    pub dtls_buffer_size: usize,
    /// Pre-provisioned DTLS leaf certificate (DER) + PKCS#8 private key.
    /// Required for DTLS keying without `std` (no certificate generation
    /// on embedded); ignored with other keying. When unset on `std`, a fresh
    /// self-signed certificate is generated per connection.
    #[serde(skip)]
    pub dtls_certificate: Option<Arc<crate::transports::dtls::Certificate>>,
    pub rtp_start_port: Option<u16>,
    pub rtp_end_port: Option<u16>,
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
    pub tcp_port_range_start: Option<u16>,
    pub tcp_port_range_end: Option<u16>,
    pub enable_latching: bool,
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
    #[serde(skip, default)]
    pub depacketizer_strategy: DepacketizerStrategy,
    #[serde(default = "default_rtp_buffer_capacity")]
    pub rtp_buffer_capacity: usize,
    #[serde(default)]
    pub buffer_drop_strategy: BufferDropStrategy,
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
    #[serde(skip, default)]
    pub label: Option<String>,
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

pub struct RtcConfigurationBuilder {
    inner: RtcConfiguration,
}

/// Wrapper for interceptor lists so that `RtcConfiguration` can still derive
/// `Debug / Clone / PartialEq / Eq` — the actual interceptor trait objects
/// are opaque and only compared by count.
#[derive(Clone, Default)]
pub struct RecorderInterceptors {
    #[cfg(feature = "std")]
    pub receivers: Vec<Arc<dyn RtpReceiverInterceptor>>,
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

    pub fn enable_latching(mut self, enable: bool) -> Self {
        self.inner.enable_latching = enable;
        self
    }

    pub fn probation_max_packets(mut self, max: Option<u8>) -> Self {
        self.inner.probation_max_packets = max;
        self
    }

    pub fn prefer_srflx_over_natted_host(mut self, enable: bool) -> Self {
        self.inner.prefer_srflx_over_natted_host = enable;
        self
    }

    pub fn enable_upnp(mut self, enable: bool) -> Self {
        self.inner.enable_upnp = enable;
        self
    }

    pub fn enable_mdns(mut self, enable: bool) -> Self {
        self.inner.enable_mdns = enable;
        self
    }

    pub fn enable_gcc(mut self, enable: bool) -> Self {
        self.inner.enable_gcc = enable;
        self
    }

    pub fn upnp_lease_duration(mut self, duration_secs: u32) -> Self {
        self.inner.upnp_lease_duration = duration_secs;
        self
    }

    pub fn upnp_discovery_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.upnp_discovery_timeout = timeout;
        self
    }

    /// Set how often UPnP port mappings are refreshed to keep the router lease alive.
    pub fn upnp_refresh_interval(mut self, interval: core::time::Duration) -> Self {
        self.inner.upnp_refresh_interval = interval;
        self
    }

    pub fn ice_server(mut self, server: IceServer) -> Self {
        self.inner.ice_servers.push(server);
        self
    }

    pub fn ice_transport_policy(mut self, policy: IceTransportPolicy) -> Self {
        self.inner.ice_transport_policy = policy;
        self
    }

    pub fn bundle_policy(mut self, policy: BundlePolicy) -> Self {
        self.inner.bundle_policy = policy;
        self
    }

    pub fn rtcp_mux_policy(mut self, policy: RtcpMuxPolicy) -> Self {
        self.inner.rtcp_mux_policy = policy;
        self
    }

    pub fn certificate(mut self, cert: CertificateConfig) -> Self {
        self.inner.certificates.push(cert);
        self
    }

    pub fn connectivity(mut self, connectivity: Connectivity) -> Self {
        self.inner.connectivity = connectivity;
        self
    }

    pub fn keying(mut self, keying: Keying) -> Self {
        self.inner.keying = keying;
        self
    }

    pub fn webrtc_extensions(mut self, enable: bool) -> Self {
        self.inner.webrtc_extensions = enable;
        self
    }

    pub fn media_capabilities(mut self, capabilities: MediaCapabilities) -> Self {
        self.inner.media_capabilities = Some(capabilities);
        self
    }

    pub fn external_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.inner.external_ips = ips;
        self
    }

    pub fn external_ip_candidate_type(mut self, typ: ExternalIpCandidateType) -> Self {
        self.inner.external_ip_candidate_type = typ;
        self
    }

    pub fn external_port(mut self, port: u16) -> Self {
        self.inner.external_port = Some(port);
        self
    }

    pub fn bind_ips(mut self, ips: Vec<IpAddr>) -> Self {
        self.inner.bind_ips = ips;
        self
    }

    pub fn prefer_ipv6(mut self, prefer: bool) -> Self {
        self.inner.prefer_ipv6 = prefer;
        self
    }

    pub fn disable_ipv6(mut self, disable: bool) -> Self {
        self.inner.disable_ipv6 = disable;
        self
    }

    pub fn ssrc_start(mut self, start: u32) -> Self {
        self.inner.ssrc_start = start;
        self
    }

    pub fn stun_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.stun_timeout = timeout;
        self
    }

    pub fn ice_gather_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.ice_gather_timeout = timeout;
        self
    }

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

    pub fn rtp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.rtp_start_port = Some(start);
        self.inner.rtp_end_port = Some(end);
        self
    }

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

    pub fn tcp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.tcp_port_range_start = Some(start);
        self.inner.tcp_port_range_end = Some(end);
        self
    }

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

    pub fn sctp_rto_initial(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_initial = duration;
        self
    }

    pub fn sctp_rto_min(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_min = duration;
        self
    }

    pub fn sctp_rto_max(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_rto_max = duration;
        self
    }

    pub fn sctp_max_association_retransmits(mut self, count: u32) -> Self {
        self.inner.sctp_max_association_retransmits = count;
        self
    }

    pub fn sctp_receive_window(mut self, size: usize) -> Self {
        self.inner.sctp_receive_window = size;
        self
    }

    pub fn sctp_heartbeat_interval(mut self, duration: core::time::Duration) -> Self {
        self.inner.sctp_heartbeat_interval = duration;
        self
    }

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

    pub fn ice_connection_timeout(mut self, timeout: core::time::Duration) -> Self {
        self.inner.ice_connection_timeout = timeout;
        self
    }

    pub fn ice_disconnect_threshold(mut self, threshold: core::time::Duration) -> Self {
        self.inner.ice_disconnect_threshold = threshold;
        self
    }

    pub fn ice_disconnect_grace(mut self, grace: core::time::Duration) -> Self {
        self.inner.ice_disconnect_grace = grace;
        self
    }

    pub fn rtp_buffer_capacity(mut self, capacity: usize) -> Self {
        self.inner.rtp_buffer_capacity = capacity;
        self
    }

    pub fn buffer_drop_strategy(mut self, strategy: BufferDropStrategy) -> Self {
        self.inner.buffer_drop_strategy = strategy;
        self
    }

    pub fn buffer_stats_log_interval(mut self, interval: core::time::Duration) -> Self {
        self.inner.buffer_stats_log_interval = interval;
        self
    }

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
