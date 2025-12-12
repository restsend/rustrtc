use crate::config::RtcConfiguration;
use crate::errors::{SdpError, SdpResult};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Write},
    str::FromStr,
};

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SdpType {
    Offer,
    Answer,
    Pranswer,
    Rollback,
}

impl SdpType {
    pub fn as_str(&self) -> &'static str {
        match self {
            SdpType::Offer => "offer",
            SdpType::Answer => "answer",
            SdpType::Pranswer => "pranswer",
            SdpType::Rollback => "rollback",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionDescription {
    pub sdp_type: SdpType,
    pub session: SessionSection,
    pub media_sections: Vec<MediaSection>,
}

impl SessionDescription {
    pub fn new(sdp_type: SdpType) -> Self {
        Self {
            sdp_type,
            session: SessionSection::default(),
            media_sections: Vec::new(),
        }
    }

    pub fn add_candidates(&mut self, candidates: &[String]) {
        for section in &mut self.media_sections {
            section
                .attributes
                .retain(|a| a.key != "candidate" && a.key != "end-of-candidates");
            for c in candidates {
                section
                    .attributes
                    .push(Attribute::new("candidate", Some(c.clone())));
            }
            section
                .attributes
                .push(Attribute::new("end-of-candidates", None));
        }
    }

    pub fn parse(sdp_type: SdpType, raw: &str) -> SdpResult<Self> {
        let mut session = SessionSection::default();
        let mut current_media: Option<MediaSection> = None;
        let mut media_sections = Vec::new();
        let mut saw_version = false;
        let mut saw_origin = false;
        let mut saw_name = false;
        let mut saw_timing = false;

        for (line_no, raw_line) in raw.lines().enumerate() {
            let line = raw_line.trim();
            if line.is_empty() {
                continue;
            }

            let (prefix, value) = line.split_once('=').ok_or_else(|| {
                SdpError::Parse(format!("invalid SDP line {}: {}", line_no + 1, line))
            })?;

            match prefix {
                "v" => {
                    session.version = value.parse().map_err(|_| {
                        SdpError::Parse(format!(
                            "invalid SDP version '{}': line {}",
                            value,
                            line_no + 1
                        ))
                    })?;
                    saw_version = true;
                }
                "o" => {
                    session.origin = Origin::parse(value)?;
                    saw_origin = true;
                }
                "s" => {
                    session.name = value.to_string();
                    saw_name = true;
                }
                "t" => {
                    session.timing = Timing::parse(value)?;
                    saw_timing = true;
                }
                "c" => {
                    if let Some(media) = current_media.as_mut() {
                        media.connection = Some(value.to_string());
                    } else {
                        session.connection = Some(value.to_string());
                    }
                }
                "a" => {
                    let attr = Attribute::from_line(value);
                    if let Some(media) = current_media.as_mut() {
                        media.apply_attribute(attr);
                    } else {
                        session.attributes.push(attr);
                    }
                }
                "m" => {
                    if let Some(media) = current_media.take() {
                        media_sections.push(media);
                    }
                    current_media = Some(MediaSection::from_m_line(value)?);
                }
                _ => {
                    // Unhandled prefixes are preserved as session-level attributes.
                    session
                        .attributes
                        .push(Attribute::new(prefix, Some(value.to_string())));
                }
            }
        }

        if let Some(media) = current_media {
            media_sections.push(media);
        }

        if !saw_version {
            return Err(SdpError::MissingLine("v"));
        }

        if !saw_origin {
            return Err(SdpError::MissingLine("o"));
        }

        if !saw_name {
            return Err(SdpError::MissingLine("s"));
        }

        if !saw_timing {
            return Err(SdpError::MissingLine("t"));
        }

        Ok(Self {
            sdp_type,
            session,
            media_sections,
        })
    }

    pub fn to_sdp_string(&self) -> String {
        let mut out = String::new();
        let _ = self.session.write_lines(&mut out);
        for media in &self.media_sections {
            let _ = media.write_lines(&mut out);
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionSection {
    pub version: u8,
    pub origin: Origin,
    pub name: String,
    pub timing: Timing,
    pub connection: Option<String>,
    pub attributes: Vec<Attribute>,
}

impl Default for SessionSection {
    fn default() -> Self {
        Self {
            version: 0,
            origin: Origin::default(),
            name: "-".to_string(),
            timing: Timing::default(),
            connection: None,
            attributes: Vec::new(),
        }
    }
}

impl SessionSection {
    fn write_lines(&self, out: &mut String) -> fmt::Result {
        write!(out, "v={}\r\n", self.version)?;
        write!(
            out,
            "o={} {} {} {} {} {}\r\n",
            self.origin.username,
            self.origin.session_id,
            self.origin.session_version,
            self.origin.network_type.as_str(),
            self.origin.address_type.as_str(),
            self.origin.unicast_address
        )?;
        write!(out, "s={}\r\n", self.name)?;
        if let Some(connection) = &self.connection {
            write!(out, "c={}\r\n", connection)?;
        }
        write!(out, "t={} {}\r\n", self.timing.start, self.timing.stop)?;
        for attr in &self.attributes {
            attr.write_line(out)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Origin {
    pub username: String,
    pub session_id: u64,
    pub session_version: u64,
    pub network_type: NetworkType,
    pub address_type: AddressType,
    pub unicast_address: String,
}

impl Origin {
    pub fn parse(value: &str) -> SdpResult<Self> {
        let mut parts = value.split_whitespace();
        let username = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing username".into()))?;
        let session_id = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing session id".into()))?
            .parse()
            .map_err(|_| SdpError::Parse("invalid session id".into()))?;
        let session_version = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing session version".into()))?
            .parse()
            .map_err(|_| SdpError::Parse("invalid session version".into()))?;
        let network_type = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing network type".into()))?
            .parse()?;
        let address_type = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing address type".into()))?
            .parse()?;
        let unicast_address = parts
            .next()
            .ok_or_else(|| SdpError::Parse("origin missing address".into()))?;

        Ok(Self {
            username: username.to_string(),
            session_id,
            session_version,
            network_type,
            address_type,
            unicast_address: unicast_address.to_string(),
        })
    }
}

impl Default for Origin {
    fn default() -> Self {
        Self {
            username: "-".into(),
            session_id: 0,
            session_version: 0,
            network_type: NetworkType::Internet,
            address_type: AddressType::Ipv4,
            unicast_address: "0.0.0.0".into(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct Timing {
    pub start: u64,
    pub stop: u64,
}

impl Timing {
    pub fn parse(value: &str) -> SdpResult<Self> {
        let mut parts = value.split_whitespace();
        let start = parts
            .next()
            .ok_or_else(|| SdpError::Parse("timing missing start".into()))?
            .parse()
            .map_err(|_| SdpError::Parse("invalid start".into()))?;
        let stop = parts
            .next()
            .ok_or_else(|| SdpError::Parse("timing missing stop".into()))?
            .parse()
            .map_err(|_| SdpError::Parse("invalid stop".into()))?;
        Ok(Self { start, stop })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Attribute {
    pub key: String,
    pub value: Option<String>,
}

impl Attribute {
    pub fn new(key: impl Into<String>, value: Option<String>) -> Self {
        Self {
            key: key.into(),
            value,
        }
    }

    pub fn from_line(line: &str) -> Self {
        if let Some(idx) = line.find(':') {
            Self::new(line[..idx].to_string(), Some(line[idx + 1..].to_string()))
        } else {
            Self::new(line.to_string(), None)
        }
    }

    fn write_line(&self, out: &mut String) -> fmt::Result {
        match &self.value {
            Some(value) => write!(out, "a={}:{}\r\n", self.key, value),
            None => write!(out, "a={}\r\n", self.key),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Simulcast {
    pub send: Vec<String>,
    pub recv: Vec<String>,
}

impl Simulcast {
    pub fn parse(value: &str) -> Option<Self> {
        let mut send = Vec::new();
        let mut recv = Vec::new();

        // Example: send ~1;2 recv 3
        let parts: Vec<&str> = value.split_whitespace().collect();
        let mut current_dir = "";

        for part in parts {
            if part == "send" || part == "recv" {
                current_dir = part;
                continue;
            }

            if current_dir == "send" {
                send.extend(part.split(';').map(|s| s.to_string()));
            } else if current_dir == "recv" {
                recv.extend(part.split(';').map(|s| s.to_string()));
            }
        }

        if send.is_empty() && recv.is_empty() {
            None
        } else {
            Some(Self { send, recv })
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Rid {
    pub id: String,
    pub direction: Direction,
    pub params: Vec<(String, String)>,
}

impl Rid {
    pub fn parse(value: &str) -> Option<Self> {
        // Example: 1 send pt=100;max-width=1280
        let mut parts = value.split_whitespace();
        let id = parts.next()?.to_string();
        let direction_str = parts.next()?;
        let direction = Direction::from_attribute(direction_str)?;

        let mut params = Vec::new();
        if let Some(params_str) = parts.next() {
            for p in params_str.split(';') {
                if let Some((k, v)) = p.split_once('=') {
                    params.push((k.to_string(), v.to_string()));
                } else {
                    params.push((p.to_string(), "".to_string()));
                }
            }
        }

        Some(Self {
            id,
            direction,
            params,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum NetworkType {
    Internet,
}

impl NetworkType {
    fn as_str(&self) -> &'static str {
        match self {
            NetworkType::Internet => "IN",
        }
    }
}

impl FromStr for NetworkType {
    type Err = SdpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "IN" | "in" => Ok(NetworkType::Internet),
            other => Err(SdpError::Unsupported(format!("network type {other}"))),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AddressType {
    Ipv4,
    Ipv6,
}

impl AddressType {
    fn as_str(&self) -> &'static str {
        match self {
            AddressType::Ipv4 => "IP4",
            AddressType::Ipv6 => "IP6",
        }
    }
}

impl FromStr for AddressType {
    type Err = SdpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_uppercase().as_str() {
            "IP4" => Ok(AddressType::Ipv4),
            "IP6" => Ok(AddressType::Ipv6),
            other => Err(SdpError::Unsupported(format!("address type {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MediaKind {
    Audio,
    Video,
    Application,
}

impl MediaKind {
    fn as_str(&self) -> &'static str {
        match self {
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
            MediaKind::Application => "application",
        }
    }
}

impl FromStr for MediaKind {
    type Err = SdpError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value {
            "audio" => Ok(MediaKind::Audio),
            "video" => Ok(MediaKind::Video),
            "application" => Ok(MediaKind::Application),
            other => Err(SdpError::Unsupported(format!("media kind {other}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum Direction {
    #[default]
    SendRecv,
    SendOnly,
    RecvOnly,
    Inactive,
}

impl Direction {
    fn as_str(&self) -> &'static str {
        match self {
            Direction::SendRecv => "sendrecv",
            Direction::SendOnly => "sendonly",
            Direction::RecvOnly => "recvonly",
            Direction::Inactive => "inactive",
        }
    }

    fn from_attribute(key: &str) -> Option<Self> {
        match key {
            "sendrecv" => Some(Direction::SendRecv),
            "sendonly" => Some(Direction::SendOnly),
            "recvonly" => Some(Direction::RecvOnly),
            "inactive" => Some(Direction::Inactive),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CryptoAttribute {
    pub tag: u16,
    pub crypto_suite: String,
    pub key_params: String,
    pub session_params: Option<String>,
}

impl CryptoAttribute {
    pub fn parse(value: &str) -> Option<Self> {
        // a=crypto:<tag> <crypto-suite> <key-params> [<session-params>]
        let mut parts = value.split_whitespace();
        let tag = parts.next()?.parse().ok()?;
        let crypto_suite = parts.next()?.to_string();
        let key_params = parts.next()?.to_string();
        let session_params = parts.collect::<Vec<&str>>().join(" ");
        let session_params = if session_params.is_empty() {
            None
        } else {
            Some(session_params)
        };

        Some(Self {
            tag,
            crypto_suite,
            key_params,
            session_params,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct MediaSection {
    pub kind: MediaKind,
    pub mid: String,
    pub port: u16,
    pub protocol: String,
    pub formats: Vec<String>,
    pub direction: Direction,
    pub attributes: Vec<Attribute>,
    pub connection: Option<String>,
}

impl MediaSection {
    pub fn new(kind: MediaKind, mid: impl Into<String>) -> Self {
        Self {
            kind,
            mid: mid.into(),
            port: 9,
            protocol: "UDP/TLS/RTP/SAVPF".into(),
            formats: Vec::new(),
            direction: Direction::default(),
            attributes: Vec::new(),
            connection: None,
        }
    }

    pub fn add_format(mut self, fmt: impl Into<String>) -> Self {
        self.formats.push(fmt.into());
        self
    }

    pub fn attribute(mut self, key: impl Into<String>, value: Option<String>) -> Self {
        self.attributes.push(Attribute::new(key, value));
        self
    }

    pub fn get_crypto_attributes(&self) -> Vec<CryptoAttribute> {
        self.attributes
            .iter()
            .filter(|a| a.key == "crypto")
            .filter_map(|a| a.value.as_ref().and_then(|v| CryptoAttribute::parse(v)))
            .collect()
    }

    pub fn apply_config(&mut self, config: &RtcConfiguration) {
        match self.kind {
            MediaKind::Audio => self.apply_audio_config(config),
            MediaKind::Video => self.apply_video_config(config),
            MediaKind::Application => self.apply_application_config(config),
        }
    }

    fn apply_audio_config(&mut self, config: &RtcConfiguration) {
        let default_caps = crate::config::AudioCapability::default();
        let caps = if let Some(c) = &config.media_capabilities {
            if c.audio.is_empty() {
                vec![default_caps]
            } else {
                c.audio.clone()
            }
        } else {
            vec![default_caps]
        };

        self.formats = caps.iter().map(|c| c.payload_type.to_string()).collect();
        self.attributes.push(Attribute::new("rtcp-mux", None));
        for audio in &caps {
            self.attributes.push(Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate, audio.channels
                )),
            ));
            if let Some(fmtp) = &audio.fmtp {
                self.attributes.push(Attribute::new(
                    "fmtp",
                    Some(format!("{} {}", audio.payload_type, fmtp)),
                ));
            }
        }
    }

    fn apply_video_config(&mut self, config: &RtcConfiguration) {
        let default_caps = crate::config::VideoCapability::default();
        let caps = if let Some(c) = &config.media_capabilities {
            if c.video.is_empty() {
                vec![default_caps]
            } else {
                c.video.clone()
            }
        } else {
            vec![default_caps]
        };

        self.formats = caps.iter().map(|c| c.payload_type.to_string()).collect();
        self.attributes.push(Attribute::new("rtcp-mux", None));
        for video in &caps {
            self.attributes.push(Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}",
                    video.payload_type, video.codec_name, video.clock_rate
                )),
            ));
            for fb in &video.rtcp_fbs {
                self.attributes.push(Attribute::new(
                    "rtcp-fb",
                    Some(format!("{} {}", video.payload_type, fb)),
                ));
            }
        }
    }

    fn apply_application_config(&mut self, config: &RtcConfiguration) {
        let default_caps = crate::config::ApplicationCapability::default();
        let port = if let Some(caps) = &config.media_capabilities {
            if let Some(app) = &caps.application {
                app.sctp_port
            } else {
                default_caps.sctp_port
            }
        } else {
            default_caps.sctp_port
        };

        self.protocol = "UDP/DTLS/SCTP".into();
        self.formats = vec!["webrtc-datachannel".into()];
        self.attributes
            .push(Attribute::new("sctp-port", Some(port.to_string())));
    }

    pub fn add_dtls_attributes(&mut self, fingerprint_hash: &str, setup: &str) {
        self.attributes.push(Attribute::new(
            "fingerprint",
            Some(format!("sha-256 {}", fingerprint_hash)),
        ));
        self.attributes
            .push(Attribute::new("setup", Some(setup.to_string())));
    }

    pub fn add_video_extmaps(&mut self, rid_id: Option<String>, repaired_rid_id: Option<String>) {
        if let Some(id) = rid_id {
            self.attributes.push(Attribute::new(
                "extmap",
                Some(format!(
                    "{} urn:ietf:params:rtp-hdrext:sdes:rtp-stream-id",
                    id
                )),
            ));
        }
        if let Some(id) = repaired_rid_id {
            self.attributes.push(Attribute::new(
                "extmap",
                Some(format!(
                    "{} urn:ietf:params:rtp-hdrext:sdes:repaired-rtp-stream-id",
                    id
                )),
            ));
        }
    }

    fn from_m_line(value: &str) -> SdpResult<Self> {
        let mut parts = value.split_whitespace();
        let kind = parts
            .next()
            .ok_or_else(|| SdpError::Parse("media line missing kind".into()))?
            .parse()?;
        let port = parts
            .next()
            .ok_or_else(|| SdpError::Parse("media line missing port".into()))?
            .parse()
            .map_err(|_| SdpError::Parse("invalid media port".into()))?;
        let protocol = parts
            .next()
            .ok_or_else(|| SdpError::Parse("media line missing protocol".into()))?;
        let formats: Vec<String> = parts.map(|s| s.to_string()).collect();
        if formats.is_empty() {
            return Err(SdpError::Parse("media line missing formats".into()));
        }

        Ok(Self {
            kind,
            mid: String::new(),
            port,
            protocol: protocol.to_string(),
            formats,
            direction: Direction::default(),
            attributes: Vec::new(),
            connection: None,
        })
    }

    fn apply_attribute(&mut self, attr: Attribute) {
        if let Some(direction) = Direction::from_attribute(&attr.key) {
            self.direction = direction;
            return;
        }

        if attr.key == "mid" {
            if let Some(value) = attr.value {
                self.mid = value;
            }
            return;
        }

        if attr.key == "connection" {
            self.connection = attr.value;
            return;
        }

        self.attributes.push(attr);
    }

    fn write_lines(&self, out: &mut String) -> fmt::Result {
        write!(
            out,
            "m={} {} {} {}\r\n",
            self.kind.as_str(),
            self.port,
            self.protocol,
            self.formats.join(" ")
        )?;
        if let Some(connection) = &self.connection {
            write!(out, "c={}\r\n", connection)?;
        }
        // Only write a=mid for WebRTC protocols, not for traditional RTP/AVP
        if !self.mid.is_empty()
            && (self.protocol.contains("TLS") || self.protocol.contains("SAVPF"))
        {
            write!(out, "a=mid:{}\r\n", self.mid)?;
        }
        write!(out, "a={}\r\n", self.direction.as_str())?;
        for attr in &self.attributes {
            attr.write_line(out)?;
        }
        Ok(())
    }
}
