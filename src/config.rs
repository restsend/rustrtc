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
            fmtp: Some("minptime=10;useinbandfec=1".to_string()),
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
    pub rtcp_fbs: Vec<String>,
}

impl Default for VideoCapability {
    fn default() -> Self {
        Self {
            payload_type: 96,
            codec_name: "VP8".to_string(),
            clock_rate: 90000,
            rtcp_fbs: vec![
                "nack".to_string(),
                "nack pli".to_string(),
                "ccm fir".to_string(),
                "goog-remb".to_string(),
                "transport-cc".to_string(),
            ],
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaCapabilities {
    pub audio: Vec<AudioCapability>,
    pub video: Vec<VideoCapability>,
    pub application: Option<ApplicationCapability>,
}

impl Default for MediaCapabilities {
    fn default() -> Self {
        Self {
            audio: vec![AudioCapability::opus(), AudioCapability::pcmu()],
            video: vec![VideoCapability::default()],
            application: Some(ApplicationCapability::default()),
        }
    }
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
    pub external_ip: Option<String>,
    pub bind_ip: Option<String>,
    pub disable_ipv6: bool,
    pub ssrc_start: u32,
    pub stun_timeout: std::time::Duration,
    pub ice_connection_timeout: std::time::Duration,
    pub sctp_rto_initial: std::time::Duration,
    pub sctp_rto_min: std::time::Duration,
    pub sctp_rto_max: std::time::Duration,
    pub sctp_max_association_retransmits: u32,
    pub sctp_receive_window: usize,
    pub dtls_buffer_size: usize,
    pub rtp_start_port: Option<u16>,
    pub rtp_end_port: Option<u16>,
    pub enable_latching: bool,
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
            bind_ip: None,
            disable_ipv6: false,
            ssrc_start: 10000,
            stun_timeout: std::time::Duration::from_secs(5),
            ice_connection_timeout: std::time::Duration::from_secs(30),
            sctp_rto_initial: std::time::Duration::from_millis(200),
            sctp_rto_min: std::time::Duration::from_millis(100),
            sctp_rto_max: std::time::Duration::from_secs(60),
            sctp_max_association_retransmits: 8,
            sctp_receive_window: 1024 * 1024,
            dtls_buffer_size: 2048,
            rtp_start_port: None,
            rtp_end_port: None,
            enable_latching: true,
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

    pub fn rtp_port_range(mut self, start: u16, end: u16) -> Self {
        self.inner.rtp_start_port = Some(start);
        self.inner.rtp_end_port = Some(end);
        self
    }

    pub fn dtls_buffer_size(mut self, size: usize) -> Self {
        self.inner.dtls_buffer_size = size;
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
        assert_eq!(config.sctp_rto_initial, Duration::from_millis(200));
        assert_eq!(config.sctp_rto_min, Duration::from_millis(100));
        assert_eq!(config.sctp_rto_max, Duration::from_secs(60));
        assert_eq!(config.sctp_max_association_retransmits, 8);
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
}
