use crate::media::depacketizer::{DefaultDepacketizerFactory, DepacketizerFactory};
use serde::{Deserialize, Serialize};
use std::fmt::{Debug, Formatter};
use std::sync::Arc;

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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BundlePolicy {
    #[default]
    Balanced,
    MaxCompat,
    MaxBundle,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum RtcpMuxPolicy {
    #[default]
    Require,
    Negotiate,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum TransportMode {
    #[default]
    WebRtc,
    Srtp,
    Rtp,
}

/// Strategy for dropping packets when buffer is full.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum BufferDropStrategy {
    #[default]
    DropNew,
    DropOldest,
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
            rtcp_fbs: vec!["nack pli".to_string(), "ccm fir".to_string()],
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

impl std::fmt::Display for T38FaxRateManagement {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl std::fmt::Display for T38UdpEC {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        self.factory.fmt(f)
    }
}

impl PartialEq for DepacketizerStrategy {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.factory, &other.factory)
    }
}

impl Eq for DepacketizerStrategy {}

fn default_rtp_buffer_capacity() -> usize {
    100
}

fn default_buffer_stats_log_interval() -> std::time::Duration {
    std::time::Duration::from_secs(10)
}

/// Controls SDP generation compatibility for interoperability with legacy SIP endpoints.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum SdpCompatibilityMode {
    /// Standard WebRTC / RFC-compliant SDP output (default).
    #[default]
    Standard,
    /// Compatibility mode for legacy SIP endpoints (e.g. Linphone):
    /// omits `a=mid` unless BUNDLE is active, omits `a=rtcp-mux`.
    LegacySip,
}

fn default_enable_upnp() -> bool {
    false
}

fn default_upnp_lease_duration() -> u32 {
    3600
}

/// Primary configuration for a `PeerConnection`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RtcConfiguration {
    pub ice_servers: Vec<IceServer>,
    pub ice_transport_policy: IceTransportPolicy,
    pub bundle_policy: BundlePolicy,
    pub rtcp_mux_policy: RtcpMuxPolicy,
    pub certificates: Vec<CertificateConfig>,
    pub transport_mode: TransportMode,
    pub nack_buffer_size: usize,
    pub media_capabilities: Option<MediaCapabilities>,
    /// Override the advertised IP address in SDP (for NAT traversal).
    /// When set, the `c=`, `o=`, and candidate addresses in the SDP will
    /// use this IP instead of the local bind IP. The local bind address is
    /// stored in `related_address` on the candidate.
    pub external_ip: Option<String>,
    /// Override the advertised port in SDP `m=` line and candidates
    /// (for NAT port forwarding).
    ///
    /// When set, the SDP will advertise this port instead of the local
    /// bind port. This is useful when you have configured NAT port
    /// forwarding (e.g. external port 30000 → local port 20000) and need
    /// the remote peer to send RTP to the external port.
    ///
    /// Works independently or combined with `external_ip`.
    /// Only applies in RTP/SRTP direct mode (`TransportMode::Rtp` /
    /// `TransportMode::Srtp`). Not used in WebRTC mode.
    pub external_port: Option<u16>,
    pub bind_ip: Option<String>,
    pub disable_ipv6: bool,
    pub ssrc_start: u32,
    pub stun_timeout: std::time::Duration,
    /// Timeout for the ICE nomination binding check (USE-CANDIDATE).
    /// This should be larger than `stun_timeout` to allow more retransmissions
    /// and reduce the probability of nomination failures under packet loss.
    pub nomination_timeout: std::time::Duration,
    pub ice_connection_timeout: std::time::Duration,
    pub sctp_rto_initial: std::time::Duration,
    pub sctp_rto_min: std::time::Duration,
    pub sctp_rto_max: std::time::Duration,
    pub sctp_max_association_retransmits: u32,
    pub sctp_receive_window: usize,
    pub sctp_heartbeat_interval: std::time::Duration,
    pub sctp_max_heartbeat_failures: u32,
    pub sctp_max_tsn_retransmits: u32,
    pub sctp_max_burst: usize,
    pub sctp_max_cwnd: usize,
    pub dtls_buffer_size: usize,
    pub rtp_start_port: Option<u16>,
    pub rtp_end_port: Option<u16>,
    pub ice_gather_udp_hosts: bool,
    pub tcp_port_range_start: Option<u16>,
    pub tcp_port_range_end: Option<u16>,
    pub enable_latching: bool,
    pub probation_max_packets: Option<u8>,
    pub enable_ice_lite: bool,
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
    /// UPnP port mapping lease duration in seconds
    #[serde(default = "default_upnp_lease_duration")]
    pub upnp_lease_duration: u32,
    #[serde(skip, default)]
    pub depacketizer_strategy: DepacketizerStrategy,
    #[serde(default = "default_rtp_buffer_capacity")]
    pub rtp_buffer_capacity: usize,
    #[serde(default)]
    pub buffer_drop_strategy: BufferDropStrategy,
    #[serde(default = "default_buffer_stats_log_interval")]
    pub buffer_stats_log_interval: std::time::Duration,
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
    /// SDP generation compatibility mode.
    #[serde(default)]
    pub sdp_compatibility: SdpCompatibilityMode,
    #[serde(skip, default)]
    pub label: Option<String>,
    #[serde(skip, default)]
    pub cname: Option<String>,
}

impl Default for RtcConfiguration {
    fn default() -> Self {
        Self {
            ice_servers: Vec::new(),
            ice_transport_policy: IceTransportPolicy::default(),
            bundle_policy: BundlePolicy::default(),
            rtcp_mux_policy: RtcpMuxPolicy::default(),
            certificates: Vec::new(),
            transport_mode: TransportMode::default(),
            nack_buffer_size: 200,
            media_capabilities: None,
            external_ip: None,
            external_port: None,
            bind_ip: None,
            disable_ipv6: false,
            ssrc_start: 10000,
            stun_timeout: std::time::Duration::from_secs(5),
            nomination_timeout: std::time::Duration::from_secs(10),
            ice_connection_timeout: std::time::Duration::from_secs(30),
            sctp_rto_initial: std::time::Duration::from_secs(3),
            sctp_rto_min: std::time::Duration::from_secs(1),
            sctp_rto_max: std::time::Duration::from_secs(60),
            sctp_max_association_retransmits: 20,
            sctp_receive_window: 128 * 1024, // 128KB - reduced for lower memory footprint
            sctp_heartbeat_interval: std::time::Duration::from_secs(15),
            sctp_max_heartbeat_failures: 4,
            sctp_max_tsn_retransmits: 8,
            sctp_max_burst: 0,         // 0 = use default heuristic
            sctp_max_cwnd: 256 * 1024, // 256 KB
            dtls_buffer_size: 2048,
            rtp_start_port: None,
            rtp_end_port: None,
            ice_gather_udp_hosts: true,
            tcp_port_range_start: None,
            tcp_port_range_end: None,
            enable_latching: false,
            probation_max_packets: None,
            enable_ice_lite: false,
            prefer_srflx_over_natted_host: false,
            enable_upnp: default_enable_upnp(),
            upnp_lease_duration: default_upnp_lease_duration(),
            depacketizer_strategy: DepacketizerStrategy::default(),
            rtp_buffer_capacity: default_rtp_buffer_capacity(),
            buffer_drop_strategy: BufferDropStrategy::default(),
            buffer_stats_log_interval: default_buffer_stats_log_interval(),
            ice_tcp_policy: IceTcpPolicy::default(),
            ice_udp_mux: false,
            ice_udp_mux_port: None,
            sdp_compatibility: SdpCompatibilityMode::default(),
            label: None,
            cname: None,
        }
    }
}

pub struct RtcConfigurationBuilder {
    inner: RtcConfiguration,
}

impl Default for RtcConfigurationBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl RtcConfigurationBuilder {
    pub fn new() -> Self {
        Self {
            inner: RtcConfiguration::default(),
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

    pub fn enable_ice_lite(mut self, enable: bool) -> Self {
        self.inner.enable_ice_lite = enable;
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

    pub fn upnp_lease_duration(mut self, duration_secs: u32) -> Self {
        self.inner.upnp_lease_duration = duration_secs;
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

    pub fn transport_mode(mut self, mode: TransportMode) -> Self {
        self.inner.transport_mode = mode;
        self
    }

    pub fn media_capabilities(mut self, capabilities: MediaCapabilities) -> Self {
        self.inner.media_capabilities = Some(capabilities);
        self
    }

    pub fn external_ip(mut self, ip: String) -> Self {
        self.inner.external_ip = Some(ip);
        self
    }

    pub fn external_port(mut self, port: u16) -> Self {
        self.inner.external_port = Some(port);
        self
    }

    pub fn bind_ip(mut self, ip: String) -> Self {
        self.inner.bind_ip = Some(ip);
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

    pub fn stun_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner.stun_timeout = timeout;
        self
    }

    pub fn nomination_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner.nomination_timeout = timeout;
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

    pub fn tcp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.tcp_port_range_start = Some(start);
        self.inner.tcp_port_range_end = Some(end);
        self
    }

    pub fn dtls_buffer_size(mut self, size: usize) -> Self {
        self.inner.dtls_buffer_size = size;
        self
    }

    pub fn sctp_rto_initial(mut self, duration: std::time::Duration) -> Self {
        self.inner.sctp_rto_initial = duration;
        self
    }

    pub fn sctp_rto_min(mut self, duration: std::time::Duration) -> Self {
        self.inner.sctp_rto_min = duration;
        self
    }

    pub fn sctp_rto_max(mut self, duration: std::time::Duration) -> Self {
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

    pub fn sctp_heartbeat_interval(mut self, duration: std::time::Duration) -> Self {
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

    pub fn ice_connection_timeout(mut self, timeout: std::time::Duration) -> Self {
        self.inner.ice_connection_timeout = timeout;
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

    pub fn buffer_stats_log_interval(mut self, interval: std::time::Duration) -> Self {
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

    pub fn sdp_compatibility(mut self, mode: SdpCompatibilityMode) -> Self {
        self.inner.sdp_compatibility = mode;
        self
    }

    pub fn cname(mut self, cname: String) -> Self {
        self.inner.cname = Some(cname);
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_rtc_configuration_defaults() {
        let config = RtcConfiguration::default();
        assert_eq!(config.ice_connection_timeout, Duration::from_secs(30));
        assert_eq!(config.sctp_rto_initial, Duration::from_secs(3));
        assert_eq!(config.sctp_rto_min, Duration::from_secs(1));
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
        let config = RtcConfigurationBuilder::new()
            .stun_timeout(Duration::from_secs(10))
            .build();
        assert_eq!(config.stun_timeout, Duration::from_secs(10));
        // Verify other defaults are still there
        assert_eq!(config.ice_connection_timeout, Duration::from_secs(30));
    }

    #[test]
    fn test_buffer_config_builder() {
        let config = RtcConfigurationBuilder::new()
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
        let config = RtcConfigurationBuilder::new()
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
        let config = RtcConfigurationBuilder::new()
            .sctp_rto_initial(Duration::from_millis(500))
            .sctp_rto_min(Duration::from_millis(200))
            .sctp_rto_max(Duration::from_secs(10))
            .sctp_max_association_retransmits(30)
            .sctp_max_heartbeat_failures(8)
            .sctp_max_burst(4)
            .stun_timeout(Duration::from_secs(10))
            .nomination_timeout(Duration::from_secs(20))
            .build();

        // Verify the TURN-optimized values are more aggressive than defaults
        let defaults = RtcConfiguration::default();
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
        let config = RtcConfiguration::default();
        assert_eq!(config.external_port, None);
    }

    #[test]
    fn test_external_port_builder() {
        let config = RtcConfigurationBuilder::new().external_port(30000).build();
        assert_eq!(config.external_port, Some(30000));
    }

    #[test]
    fn test_external_port_with_external_ip_builder() {
        let config = RtcConfigurationBuilder::new()
            .external_ip("203.0.113.5".to_string())
            .external_port(30000)
            .build();
        assert_eq!(config.external_ip, Some("203.0.113.5".to_string()));
        assert_eq!(config.external_port, Some(30000));
    }

    #[test]
    fn test_upnp_defaults() {
        let config = RtcConfiguration::default();
        assert!(!config.enable_upnp, "UPnP should be disabled by default");
        assert_eq!(config.upnp_lease_duration, 3600);
    }

    #[test]
    fn test_upnp_builder_methods() {
        let config = RtcConfigurationBuilder::new()
            .enable_upnp(false)
            .upnp_lease_duration(7200)
            .build();
        assert!(!config.enable_upnp);
        assert_eq!(config.upnp_lease_duration, 7200);
    }

    #[test]
    fn test_upnp_optimized_config() {
        let config = RtcConfigurationBuilder::new()
            .enable_upnp(true)
            .upnp_lease_duration(1800)
            .build();

        assert!(config.enable_upnp);
        assert_eq!(config.upnp_lease_duration, 1800);

        // Verify defaults remain for other options
        let defaults = RtcConfiguration::default();
        assert_eq!(
            config.ice_connection_timeout,
            defaults.ice_connection_timeout
        );
    }

    #[test]
    fn test_ice_udp_mux_defaults() {
        let config = RtcConfiguration::default();
        assert!(
            !config.ice_udp_mux,
            "ICE UDP mux should be disabled by default"
        );
        assert_eq!(config.ice_udp_mux_port, None);
    }

    #[test]
    fn test_ice_udp_mux_builder_methods() {
        let config = RtcConfigurationBuilder::new()
            .ice_udp_mux(true)
            .ice_udp_mux_port(30500)
            .build();
        assert!(config.ice_udp_mux);
        assert_eq!(config.ice_udp_mux_port, Some(30500));
    }
}
