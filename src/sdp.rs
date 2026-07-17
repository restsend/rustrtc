use crate::config::RtcConfiguration;
use crate::errors::{SdpError, SdpResult};
use serde::{Deserialize, Serialize};
use std::{
    fmt::{self, Write},
    str::FromStr,
};

pub const ABS_SEND_TIME_URI: &str = "http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time";
pub const SDES_MID_URI: &str = "urn:ietf:params:rtp-hdrext:sdes:mid";

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

    pub fn dtls_fingerprint(&self) -> SdpResult<Option<SdpFingerprint>> {
        let mut fingerprint = None;

        for attr in &self.session.attributes {
            collect_dtls_fingerprint(attr, &mut fingerprint)?;
        }

        for section in &self.media_sections {
            for attr in &section.attributes {
                collect_dtls_fingerprint(attr, &mut fingerprint)?;
            }
        }

        Ok(fingerprint)
    }

    /// Returns all video media sections.
    pub fn video_sections(&self) -> impl Iterator<Item = &MediaSection> {
        self.media_sections
            .iter()
            .filter(|s| s.kind == MediaKind::Video)
    }

    /// Returns all audio media sections.
    pub fn audio_sections(&self) -> impl Iterator<Item = &MediaSection> {
        self.media_sections
            .iter()
            .filter(|s| s.kind == MediaKind::Audio)
    }

    /// Returns all image (T.38 fax) media sections.
    pub fn image_sections(&self) -> impl Iterator<Item = &MediaSection> {
        self.media_sections
            .iter()
            .filter(|s| s.kind == MediaKind::Image)
    }

    /// Returns the first video media section, if any.
    pub fn first_video_section(&self) -> Option<&MediaSection> {
        self.media_sections
            .iter()
            .find(|s| s.kind == MediaKind::Video)
    }

    /// Returns the first audio media section, if any.
    pub fn first_audio_section(&self) -> Option<&MediaSection> {
        self.media_sections
            .iter()
            .find(|s| s.kind == MediaKind::Audio)
    }

    /// Returns the first image (T.38 fax) media section, if any.
    pub fn first_image_section(&self) -> Option<&MediaSection> {
        self.media_sections
            .iter()
            .find(|s| s.kind == MediaKind::Image)
    }

    /// Extracts all video capabilities from all video media sections.
    pub fn to_video_capabilities(&self) -> Vec<crate::config::VideoCapability> {
        self.video_sections()
            .flat_map(|s| s.to_video_capabilities())
            .collect()
    }

    /// Extracts all audio capabilities from all audio media sections.
    pub fn to_audio_capabilities(&self) -> Vec<crate::config::AudioCapability> {
        self.audio_sections()
            .flat_map(|s| s.to_audio_capabilities())
            .collect()
    }

    /// Extracts all T.38 fax capabilities from all image media sections.
    pub fn to_image_capabilities(&self) -> Vec<crate::config::T38Capability> {
        self.image_sections()
            .flat_map(|s| s.to_image_capabilities())
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SdpFingerprint {
    pub algorithm: String,
    pub value: String,
}

impl SdpFingerprint {
    pub fn parse(value: &str) -> SdpResult<Self> {
        let mut parts = value.split_whitespace();
        let algorithm = parts
            .next()
            .ok_or_else(|| SdpError::Parse("fingerprint missing algorithm".into()))?;
        let value = parts
            .next()
            .ok_or_else(|| SdpError::Parse("fingerprint missing value".into()))?;

        if parts.next().is_some() {
            return Err(SdpError::Parse(
                "fingerprint has unexpected trailing data".into(),
            ));
        }

        Ok(Self {
            algorithm: algorithm.to_ascii_lowercase(),
            value: normalize_fingerprint_value(value)?,
        })
    }
}

fn collect_dtls_fingerprint(
    attr: &Attribute,
    current: &mut Option<SdpFingerprint>,
) -> SdpResult<()> {
    if attr.key != "fingerprint" {
        return Ok(());
    }

    let value = attr
        .value
        .as_deref()
        .ok_or_else(|| SdpError::Parse("fingerprint attribute missing value".into()))?;
    let parsed = SdpFingerprint::parse(value)?;

    if let Some(existing) = current {
        if existing != &parsed {
            return Err(SdpError::Parse(
                "conflicting DTLS fingerprint attributes in SDP".into(),
            ));
        }
    } else {
        *current = Some(parsed);
    }

    Ok(())
}

fn normalize_fingerprint_value(value: &str) -> SdpResult<String> {
    let normalized = value
        .chars()
        .filter(|c| !c.is_ascii_whitespace() && *c != ':')
        .collect::<String>()
        .to_ascii_uppercase();

    if normalized.is_empty() || normalized.len() % 2 != 0 {
        return Err(SdpError::Parse("fingerprint hex length is invalid".into()));
    }

    if !normalized.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(SdpError::Parse(
            "fingerprint contains non-hex characters".into(),
        ));
    }

    let mut formatted = String::with_capacity(normalized.len() + normalized.len() / 2);
    for (index, chunk) in normalized.as_bytes().chunks(2).enumerate() {
        if index > 0 {
            formatted.push(':');
        }
        formatted.push(chunk[0] as char);
        formatted.push(chunk[1] as char);
    }

    Ok(formatted)
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
    Image,
}

impl MediaKind {
    fn as_str(&self) -> &'static str {
        match self {
            MediaKind::Audio => "audio",
            MediaKind::Video => "video",
            MediaKind::Application => "application",
            MediaKind::Image => "image",
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
            "image" => Ok(MediaKind::Image),
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

    pub fn get_extmap_id(&self, uri: &str) -> Option<u8> {
        for attr in &self.attributes {
            if attr.key == "extmap"
                && let Some(val) = &attr.value
            {
                let mut parts = val.split_whitespace();
                if let Some(id_str) = parts.next()
                    && let Some(attr_uri) = parts.next()
                    && attr_uri == uri
                {
                    return id_str.parse().ok();
                }
            }
        }
        None
    }

    pub fn to_video_capabilities(&self) -> Vec<crate::config::VideoCapability> {
        if self.kind != MediaKind::Video {
            return Vec::new();
        }

        let mut capabilities = Vec::new();
        let wildcard_rtcp_fbs: Vec<String> = self
            .attributes
            .iter()
            .filter_map(|attr| {
                if attr.key != "rtcp-fb" {
                    return None;
                }
                let value = attr.value.as_ref()?;
                let (pt_part, rest) = value.split_once(' ')?;
                if pt_part == "*" {
                    Some(rest.to_string())
                } else {
                    None
                }
            })
            .collect();

        for fmt in &self.formats {
            let payload_type: u8 = match fmt.parse() {
                Ok(pt) => pt,
                Err(_) => continue,
            };

            // Parse rtpmap for this payload type
            let mut codec_name = String::new();
            let mut clock_rate = 90000u32; // Default for video

            for attr in &self.attributes {
                if attr.key == "rtpmap"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                {
                    // Parse "codec_name/clock_rate"
                    let parts: Vec<&str> = rest.split('/').collect();
                    if !parts.is_empty() {
                        codec_name = parts[0].to_string();
                    }
                    if parts.len() >= 2
                        && let Ok(rate) = parts[1].parse()
                    {
                        clock_rate = rate;
                    }
                }
            }

            // If no rtpmap found, use payload type to guess
            if codec_name.is_empty() {
                codec_name = match payload_type {
                    96..=98 => "VP8",
                    99 | 100 => "H264",
                    101 => "VP9",
                    102 => "AV1",
                    _ => "unknown",
                }
                .to_string();
            }

            // Parse fmtp for this payload type
            let mut fmtp = None;
            for attr in &self.attributes {
                if attr.key == "fmtp"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                {
                    fmtp = Some(rest.to_string());
                    break;
                }
            }

            // Parse rtcp-fb for this payload type
            let mut rtcp_fbs = wildcard_rtcp_fbs.clone();
            for attr in &self.attributes {
                if attr.key == "rtcp-fb"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                    && !rtcp_fbs.iter().any(|existing| existing == rest)
                {
                    rtcp_fbs.push(rest.to_string());
                }
            }

            // RTX is not a primary media codec; associate it onto the apt target below.
            if codec_name.eq_ignore_ascii_case("rtx") {
                continue;
            }

            capabilities.push(crate::config::VideoCapability {
                payload_type,
                codec_name,
                clock_rate,
                fmtp,
                rtcp_fbs,
                rtx_payload_type: None,
            });
        }

        // Attach RTX payload types via fmtp apt= onto the matching primary codec.
        let apt_map = crate::rtx::extract_rtx_apt_map_from_attrs(&self.attributes);
        for cap in &mut capabilities {
            if let Some(rtx_pt) = crate::rtx::rtx_pt_for_primary(&apt_map, cap.payload_type) {
                cap.rtx_payload_type = Some(rtx_pt);
            }
        }

        capabilities
    }

    pub fn to_audio_capabilities(&self) -> Vec<crate::config::AudioCapability> {
        if self.kind != MediaKind::Audio {
            return Vec::new();
        }

        let mut capabilities = Vec::new();

        for fmt in &self.formats {
            let payload_type: u8 = match fmt.parse() {
                Ok(pt) => pt,
                Err(_) => continue,
            };

            // Parse rtpmap for this payload type
            let mut codec_name = String::new();
            let mut clock_rate = 8000u32; // Default for audio
            let mut channels = 1u8;

            for attr in &self.attributes {
                if attr.key == "rtpmap"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                {
                    // Parse "codec_name/clock_rate[/channels]"
                    let parts: Vec<&str> = rest.split('/').collect();
                    if !parts.is_empty() {
                        codec_name = parts[0].to_string();
                    }
                    if parts.len() >= 2
                        && let Ok(rate) = parts[1].parse()
                    {
                        clock_rate = rate;
                    }
                    if parts.len() >= 3
                        && let Ok(ch) = parts[2].parse()
                    {
                        channels = ch;
                    }
                }
            }

            // If no rtpmap found, use payload type to guess common audio codecs
            // These defaults match AudioCapability::{opus,pcmu,pcma,g722,g729,telephone_event}
            if codec_name.is_empty() {
                (codec_name, clock_rate, channels) = match payload_type {
                    0 => ("PCMU".to_string(), 8000, 1),
                    8 => ("PCMA".to_string(), 8000, 1),
                    9 => ("G722".to_string(), 8000, 1),
                    18 => ("G729".to_string(), 8000, 1),
                    111 => ("opus".to_string(), 48000, 2),
                    101 => ("telephone-event".to_string(), 8000, 1),
                    _ => ("unknown".to_string(), 8000, 1),
                };
            }

            // Parse fmtp for this payload type
            let mut fmtp = None;
            for attr in &self.attributes {
                if attr.key == "fmtp"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                {
                    fmtp = Some(rest.to_string());
                    break;
                }
            }

            // Default fmtp for telephone-event (matches AudioCapability::telephone_event)
            if fmtp.is_none() && payload_type == 101 {
                fmtp = Some("0-16".to_string());
            }

            // Parse rtcp-fb for this payload type
            let mut rtcp_fbs = Vec::new();
            for attr in &self.attributes {
                if attr.key == "rtcp-fb"
                    && let Some(value) = &attr.value
                    && let Some((pt_part, rest)) = value.split_once(' ')
                    && let Ok(pt) = pt_part.parse::<u8>()
                    && pt == payload_type
                {
                    rtcp_fbs.push(rest.to_string());
                }
            }

            capabilities.push(crate::config::AudioCapability {
                payload_type,
                codec_name,
                clock_rate,
                channels,
                fmtp,
                rtcp_fbs,
            });
        }

        capabilities
    }

    pub fn apply_config(&mut self, config: &RtcConfiguration) {
        match self.kind {
            MediaKind::Audio => self.apply_audio_config(config),
            MediaKind::Video => self.apply_video_config(config),
            MediaKind::Application => self.apply_application_config(config),
            MediaKind::Image => self.apply_image_config(config),
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
        if config.rtcp_mux_policy == crate::config::RtcpMuxPolicy::Require
            && config.sdp_compatibility != crate::config::SdpCompatibilityMode::LegacySip
        {
            self.attributes.push(Attribute::new("rtcp-mux", None));
        }
        for audio in &caps {
            let rtpmap_value = if audio.channels == 1 {
                format!(
                    "{} {}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate
                )
            } else {
                format!(
                    "{} {}/{}/{}",
                    audio.payload_type, audio.codec_name, audio.clock_rate, audio.channels
                )
            };

            self.attributes
                .push(Attribute::new("rtpmap", Some(rtpmap_value)));
            if let Some(fmtp) = &audio.fmtp {
                self.attributes.push(Attribute::new(
                    "fmtp",
                    Some(format!("{} {}", audio.payload_type, fmtp)),
                ));
            }
            for fb in &audio.rtcp_fbs {
                self.attributes.push(Attribute::new(
                    "rtcp-fb",
                    Some(format!("{} {}", audio.payload_type, fb)),
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
        if config.rtcp_mux_policy == crate::config::RtcpMuxPolicy::Require
            && config.sdp_compatibility != crate::config::SdpCompatibilityMode::LegacySip
        {
            self.attributes.push(Attribute::new("rtcp-mux", None));
        }
        for video in &caps {
            self.attributes.push(Attribute::new(
                "rtpmap",
                Some(format!(
                    "{} {}/{}",
                    video.payload_type, video.codec_name, video.clock_rate
                )),
            ));
            if let Some(fmtp) = &video.fmtp {
                self.attributes.push(Attribute::new(
                    "fmtp",
                    Some(format!("{} {}", video.payload_type, fmtp)),
                ));
            }
            for fb in &video.rtcp_fbs {
                self.attributes.push(Attribute::new(
                    "rtcp-fb",
                    Some(format!("{} {}", video.payload_type, fb)),
                ));
            }
            if let Some(rtx_pt) = video.rtx_payload_type {
                crate::rtx::append_rtx_to_section(
                    &mut self.formats,
                    &mut self.attributes,
                    video.payload_type,
                    rtx_pt,
                    video.clock_rate,
                );
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

    pub fn to_image_capabilities(&self) -> Vec<crate::config::T38Capability> {
        if self.kind != MediaKind::Image {
            return Vec::new();
        }

        let mut capabilities = Vec::new();

        for fmt in &self.formats {
            let payload_type: u8 = fmt.parse().unwrap_or(98);

            let mut version = 0u8;
            let mut max_bitrate = 14400u32;
            let mut rate_management = crate::config::T38FaxRateManagement::TransferredTCF;
            let mut max_buffer = 1024u16;
            let mut max_datagram = 238u16;
            let mut udp_ec = crate::config::T38UdpEC::T38UDPRedundancy;

            for attr in &self.attributes {
                if let Some(value) = &attr.value {
                    match attr.key.as_str() {
                        "T38FaxVersion" => {
                            if let Ok(v) = value.parse::<u8>() {
                                version = v;
                            }
                        }
                        "T38MaxBitRate" => {
                            if let Ok(r) = value.parse::<u32>() {
                                max_bitrate = r;
                            }
                        }
                        "T38FaxRateManagement" => {
                            rate_management = match value.as_str() {
                                "localTCF" => crate::config::T38FaxRateManagement::LocalTCF,
                                _ => crate::config::T38FaxRateManagement::TransferredTCF,
                            };
                        }
                        "T38FaxMaxBuffer" => {
                            if let Ok(b) = value.parse::<u16>() {
                                max_buffer = b;
                            }
                        }
                        "T38FaxMaxDatagram" => {
                            if let Ok(d) = value.parse::<u16>() {
                                max_datagram = d;
                            }
                        }
                        "T38FaxUdpEC" => {
                            udp_ec = match value.as_str() {
                                "t38UDPFEC" => crate::config::T38UdpEC::T38UDPFEC,
                                _ => crate::config::T38UdpEC::T38UDPRedundancy,
                            };
                        }
                        _ => {}
                    }
                }
            }

            capabilities.push(crate::config::T38Capability {
                payload_type,
                version,
                max_bitrate,
                rate_management,
                max_buffer,
                max_datagram,
                udp_ec,
                fmtp: None,
            });
        }

        capabilities
    }

    fn apply_image_config(&mut self, config: &RtcConfiguration) {
        let default_caps = crate::config::T38Capability::default();
        let caps = if let Some(c) = &config.media_capabilities {
            if c.image.is_empty() {
                vec![default_caps]
            } else {
                c.image.clone()
            }
        } else {
            vec![default_caps]
        };

        self.protocol = "udptl".into();
        self.formats = caps.iter().map(|c| c.payload_type.to_string()).collect();

        for t38 in &caps {
            self.attributes.push(Attribute::new(
                "T38FaxVersion",
                Some(t38.version.to_string()),
            ));
            self.attributes.push(Attribute::new(
                "T38MaxBitRate",
                Some(t38.max_bitrate.to_string()),
            ));
            self.attributes.push(Attribute::new(
                "T38FaxRateManagement",
                Some(t38.rate_management.to_string()),
            ));
            self.attributes.push(Attribute::new(
                "T38FaxMaxBuffer",
                Some(t38.max_buffer.to_string()),
            ));
            self.attributes.push(Attribute::new(
                "T38FaxMaxDatagram",
                Some(t38.max_datagram.to_string()),
            ));
            self.attributes
                .push(Attribute::new("T38FaxUdpEC", Some(t38.udp_ec.to_string())));
        }
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
        // Always write a=mid if it is present, as it is required for BUNDLE
        if !self.mid.is_empty() {
            write!(out, "a=mid:{}\r\n", self.mid)?;
        }
        write!(out, "a={}\r\n", self.direction.as_str())?;
        for attr in &self.attributes {
            attr.write_line(out)?;
        }
        Ok(())
    }
}

/// Rewrite every direction attribute (`sendrecv`, `sendonly`, `recvonly`, `inactive`)
/// inside every media section of a raw SDP string to the given `direction`.
///
/// Non-direction lines are preserved verbatim.  Output uses `\r\n` line endings to
/// comply with RFC 4566.
pub fn modify_sdp_direction(sdp: &str, direction: &str) -> String {
    let mut result: Vec<String> = Vec::new();
    let mut in_media_section = false;

    for line in sdp.lines() {
        if line.starts_with("m=") {
            in_media_section = true;
            result.push(line.to_string());
        } else if in_media_section
            && matches!(
                line,
                s if s.starts_with("a=sendrecv")
                    || s.starts_with("a=sendonly")
                    || s.starts_with("a=recvonly")
                    || s.starts_with("a=inactive")
            )
        {
            result.push(format!("a={}", direction));
        } else {
            result.push(line.to_string());
        }
    }

    result.join("\r\n")
}

pub fn parse_bundle_mid_info(sdp: &str) -> Option<(u8, String, String)> {
    let mut extmap_id: Option<u8> = None;
    let mut audio_mid: Option<String> = None;
    let mut video_mid: Option<String> = None;
    let mut in_audio = false;
    let mut in_video = false;

    for line in sdp.lines() {
        let line = line.trim_end_matches('\r');
        if line.starts_with("m=audio") {
            in_audio = true;
            in_video = false;
        } else if line.starts_with("m=video") {
            in_audio = false;
            in_video = true;
        } else if line.starts_with("m=") {
            in_audio = false;
            in_video = false;
        } else if let Some(mid) = line.strip_prefix("a=mid:") {
            if in_audio && audio_mid.is_none() {
                audio_mid = Some(mid.to_string());
            } else if in_video && video_mid.is_none() {
                video_mid = Some(mid.to_string());
            }
        } else if extmap_id.is_none()
            && line.starts_with("a=extmap:")
            && line.contains("sdes:mid")
            && let Some(rest) = line.strip_prefix("a=extmap:")
            && let Some(id_str) = rest.split([' ', '/']).next()
            && let Ok(id) = id_str.parse::<u8>()
        {
            extmap_id = Some(id);
        }
    }

    match (extmap_id, audio_mid, video_mid) {
        (Some(id), Some(a), Some(v)) => Some((id, a, v)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_description_extracts_normalized_dtls_fingerprint() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 aa:bb:cc:dd\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let fingerprint = desc.dtls_fingerprint().unwrap().unwrap();

        assert_eq!(fingerprint.algorithm, "sha-256");
        assert_eq!(fingerprint.value, "AA:BB:CC:DD");
    }

    #[test]
    fn test_session_description_rejects_conflicting_dtls_fingerprints() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n\
a=fingerprint:sha-256 AA:BB:CC:EE\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let err = desc.dtls_fingerprint().unwrap_err();

        assert_eq!(
            err,
            SdpError::Parse("conflicting DTLS fingerprint attributes in SDP".into())
        );
    }

    /// Helper: build a minimal RtcConfiguration with the given media capabilities.
    fn make_config(
        caps: crate::config::MediaCapabilities,
        compat: crate::config::SdpCompatibilityMode,
    ) -> RtcConfiguration {
        let mut c = RtcConfiguration::default();
        c.media_capabilities = Some(caps);
        c.sdp_compatibility = compat;
        c
    }

    // ── VideoCapability::fmtp passthrough ────────────────────────────────────

    #[test]
    fn video_fmtp_is_emitted_when_set() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let video = VideoCapability {
            payload_type: 96,
            codec_name: "H264".to_string(),
            clock_rate: 90000,
            fmtp: Some("packetization-mode=1;profile-level-id=42e01f".to_string()),
            rtcp_fbs: vec![],
            rtx_payload_type: None,
        };

        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![video],
            application: None,
            image: vec![],
        };

        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));

        let fmtp = section
            .attributes
            .iter()
            .find(|a| a.key == "fmtp")
            .expect("a=fmtp should be present for H264");

        assert_eq!(
            fmtp.value.as_deref().unwrap(),
            "96 packetization-mode=1;profile-level-id=42e01f"
        );
    }

    #[test]
    fn video_fmtp_absent_when_not_set() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let video = VideoCapability {
            fmtp: None,
            ..VideoCapability::default()
        };
        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![video],
            application: None,
            image: vec![],
        };

        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));

        assert!(
            section.attributes.iter().all(|a| a.key != "fmtp"),
            "a=fmtp should not be emitted when fmtp is None"
        );
    }

    #[test]
    fn video_h264_constructor_emits_fmtp() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![VideoCapability::h264()],
            application: None,
            image: vec![],
        };

        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));

        let fmtp = section
            .attributes
            .iter()
            .find(|a| a.key == "fmtp")
            .expect("VideoCapability::h264() should produce a=fmtp");
        assert!(
            fmtp.value
                .as_deref()
                .unwrap()
                .contains("packetization-mode"),
            "fmtp should contain packetization-mode"
        );
    }

    // ── rtcp-fb passthrough ─────────────────────────────────────────────────

    #[test]
    fn video_rtcp_fb_emitted_for_each_entry() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let video = VideoCapability {
            payload_type: 96,
            codec_name: "H264".to_string(),
            clock_rate: 90000,
            fmtp: None,
            rtcp_fbs: vec!["nack pli".to_string(), "ccm fir".to_string()],
            rtx_payload_type: None,
        };
        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![video],
            application: None,
            image: vec![],
        };

        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));

        let fbs: Vec<&str> = section
            .attributes
            .iter()
            .filter(|a| a.key == "rtcp-fb")
            .filter_map(|a| a.value.as_deref())
            .collect();
        assert!(
            fbs.contains(&"96 nack pli"),
            "should contain rtcp-fb nack pli, got: {fbs:?}"
        );
        assert!(
            fbs.contains(&"96 ccm fir"),
            "should contain rtcp-fb ccm fir, got: {fbs:?}"
        );
    }

    #[test]
    fn audio_rtcp_fb_emitted_for_each_entry() {
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let audio = AudioCapability {
            payload_type: 111,
            codec_name: "opus".to_string(),
            clock_rate: 48000,
            channels: 2,
            fmtp: None,
            rtcp_fbs: vec!["nack".to_string()],
        };
        let caps = MediaCapabilities {
            audio: vec![audio],
            video: vec![],
            application: None,
            image: vec![],
        };

        let mut section = MediaSection::new(MediaKind::Audio, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));

        let fb = section
            .attributes
            .iter()
            .find(|a| a.key == "rtcp-fb")
            .expect("should have rtcp-fb for audio");
        assert_eq!(fb.value.as_deref().unwrap(), "111 nack");
    }

    // ── SdpCompatibilityMode::LegacySip ─────────────────────────────────────

    #[test]
    fn legacy_sip_mode_omits_rtcp_mux_on_audio() {
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let caps = MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![],
            application: None,
            image: vec![],
        };
        let mut config = make_config(caps, SdpCompatibilityMode::LegacySip);
        config.rtcp_mux_policy = crate::config::RtcpMuxPolicy::Require;

        let mut section = MediaSection::new(MediaKind::Audio, "0");
        section.apply_config(&config);

        assert!(
            section.attributes.iter().all(|a| a.key != "rtcp-mux"),
            "LegacySip mode must not emit a=rtcp-mux"
        );
    }

    #[test]
    fn legacy_sip_mode_omits_rtcp_mux_on_video() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![VideoCapability::default()],
            application: None,
            image: vec![],
        };
        let mut config = make_config(caps, SdpCompatibilityMode::LegacySip);
        config.rtcp_mux_policy = crate::config::RtcpMuxPolicy::Require;

        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&config);

        assert!(
            section.attributes.iter().all(|a| a.key != "rtcp-mux"),
            "LegacySip mode must not emit a=rtcp-mux for video"
        );
    }

    #[test]
    fn standard_mode_emits_rtcp_mux() {
        use crate::config::{AudioCapability, MediaCapabilities, SdpCompatibilityMode};

        let caps = MediaCapabilities {
            audio: vec![AudioCapability::pcma()],
            video: vec![],
            application: None,
            image: vec![],
        };
        let mut config = make_config(caps, SdpCompatibilityMode::Standard);
        config.rtcp_mux_policy = crate::config::RtcpMuxPolicy::Require;

        let mut section = MediaSection::new(MediaKind::Audio, "0");
        section.apply_config(&config);

        assert!(
            section.attributes.iter().any(|a| a.key == "rtcp-mux"),
            "Standard mode with Require policy must emit a=rtcp-mux"
        );
    }

    // ── Media section filtering tests ────────────────────────────────────────

    #[test]
    fn test_first_video_section_returns_video() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=mid:1\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();

        assert!(desc.first_audio_section().is_some());
        assert!(desc.first_video_section().is_some());
        assert_eq!(desc.first_video_section().unwrap().mid, "1");
        assert_eq!(desc.first_audio_section().unwrap().mid, "0");
    }

    #[test]
    fn test_first_video_section_returns_none_when_no_video() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();

        assert!(desc.first_video_section().is_none());
        assert!(desc.first_audio_section().is_some());
    }

    #[test]
    fn test_video_sections_iterates_all_video() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=mid:1\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 97\r\n\
a=mid:2\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();

        let videos: Vec<_> = desc.video_sections().collect();
        assert_eq!(videos.len(), 2);
        assert_eq!(videos[0].mid, "1");
        assert_eq!(videos[1].mid, "2");

        let audios: Vec<_> = desc.audio_sections().collect();
        assert_eq!(audios.len(), 1);
        assert_eq!(audios[0].mid, "0");
    }

    // ── Capability parsing tests ─────────────────────────────────────────────

    #[test]
    fn test_parse_video_capabilities_from_sdp() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
a=mid:0\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=rtpmap:97 H264/90000\r\n\
a=fmtp:97 packetization-mode=1;profile-level-id=42e01f\r\n\
a=rtcp-fb:96 nack pli\r\n\
a=rtcp-fb:97 nack pli\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_video_capabilities();

        assert_eq!(caps.len(), 2);

        // First codec: VP8
        assert_eq!(caps[0].payload_type, 96);
        assert_eq!(caps[0].codec_name, "VP8");
        assert_eq!(caps[0].clock_rate, 90000);
        assert!(caps[0].fmtp.is_none());
        assert_eq!(caps[0].rtcp_fbs, vec!["nack pli"]);

        // Second codec: H264
        assert_eq!(caps[1].payload_type, 97);
        assert_eq!(caps[1].codec_name, "H264");
        assert_eq!(caps[1].clock_rate, 90000);
        assert_eq!(
            caps[1].fmtp.as_deref().unwrap(),
            "packetization-mode=1;profile-level-id=42e01f"
        );
        assert_eq!(caps[1].rtcp_fbs, vec!["nack pli"]);
    }

    #[test]
    fn test_parse_video_capabilities_attaches_rtx_via_apt() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96 97\r\n\
a=mid:0\r\n\
a=rtpmap:96 VP8/90000\r\n\
a=rtpmap:97 rtx/90000\r\n\
a=fmtp:97 apt=96\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_video_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].payload_type, 96);
        assert_eq!(caps[0].rtx_payload_type, Some(97));
    }

    #[test]
    fn apply_video_config_emits_rtx_when_configured() {
        use crate::config::{MediaCapabilities, SdpCompatibilityMode, VideoCapability};

        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![VideoCapability::vp8_with_rtx(97)],
            application: None,
            image: vec![],
        };
        let mut section = MediaSection::new(MediaKind::Video, "0");
        section.apply_config(&make_config(caps, SdpCompatibilityMode::Standard));
        assert!(section.formats.iter().any(|f| f == "97"));
        assert!(
            section
                .attributes
                .iter()
                .any(|a| a.key == "fmtp" && a.value.as_deref() == Some("97 apt=96"))
        );
    }

    #[test]
    fn test_parse_video_capabilities_expands_wildcard_rtcp_fb() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 4016 RTP/AVP 99 100\r\n\
c=IN IP4 192.168.3.7\r\n\
a=rtpmap:99 H264/90000\r\n\
a=fmtp:99 profile-level-id=42e01e; packetization-mode=1\r\n\
a=rtpmap:100 VP8/90000\r\n\
a=rtcp-fb:* nack pli\r\n\
a=rtcp-fb:99 nack pli\r\n\
a=rtcp-fb:99 ccm fir\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_video_capabilities();

        assert_eq!(caps.len(), 2);
        assert_eq!(caps[0].payload_type, 99);
        assert_eq!(caps[0].rtcp_fbs, vec!["nack pli", "ccm fir"]);
        assert_eq!(caps[1].payload_type, 100);
        assert_eq!(caps[1].rtcp_fbs, vec!["nack pli"]);
    }

    #[test]
    fn test_parse_audio_capabilities_from_sdp() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111 0\r\n\
a=mid:0\r\n\
a=rtpmap:111 opus/48000/2\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=fmtp:111 minptime=10;useinbandfec=1\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_audio_capabilities();

        assert_eq!(caps.len(), 2);

        // First codec: opus
        assert_eq!(caps[0].payload_type, 111);
        assert_eq!(caps[0].codec_name, "opus");
        assert_eq!(caps[0].clock_rate, 48000);
        assert_eq!(caps[0].channels, 2);
        assert_eq!(
            caps[0].fmtp.as_deref().unwrap(),
            "minptime=10;useinbandfec=1"
        );

        // Second codec: PCMU
        assert_eq!(caps[1].payload_type, 0);
        assert_eq!(caps[1].codec_name, "PCMU");
        assert_eq!(caps[1].clock_rate, 8000);
        assert_eq!(caps[1].channels, 1);
    }

    #[test]
    fn test_parse_capabilities_empty_for_wrong_kind() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n\
a=rtpmap:111 opus/48000/2\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let audio_section = desc.first_audio_section().unwrap();

        // Video capabilities should be empty for audio section
        let video_caps = audio_section.to_video_capabilities();
        assert!(video_caps.is_empty());

        // But audio capabilities should work
        let audio_caps = audio_section.to_audio_capabilities();
        assert_eq!(audio_caps.len(), 1);
    }

    #[test]
    fn test_parse_video_capability_without_rtpmap() {
        // Test fallback when rtpmap is missing
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=video 9 UDP/TLS/RTP/SAVPF 96\r\n\
a=mid:0\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_video_capabilities();

        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].payload_type, 96);
        // Should use fallback codec name
        assert!(!caps[0].codec_name.is_empty());
        assert_eq!(caps[0].clock_rate, 90000); // Default for video
    }

    #[test]
    fn test_audio_capability_fallback_matches_defaults() {
        // Verify fallback values match AudioCapability constructors
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 0 8 9 18 111 101\r\n\
a=mid:0\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_audio_capabilities();

        assert_eq!(caps.len(), 6);

        // PT 0 = PCMU (matches AudioCapability::pcmu)
        assert_eq!(caps[0].payload_type, 0);
        assert_eq!(caps[0].codec_name, "PCMU");
        assert_eq!(caps[0].clock_rate, 8000);
        assert_eq!(caps[0].channels, 1);

        // PT 8 = PCMA (matches AudioCapability::pcma)
        assert_eq!(caps[1].payload_type, 8);
        assert_eq!(caps[1].codec_name, "PCMA");
        assert_eq!(caps[1].clock_rate, 8000);
        assert_eq!(caps[1].channels, 1);

        // PT 9 = G722 (matches AudioCapability::g722)
        assert_eq!(caps[2].payload_type, 9);
        assert_eq!(caps[2].codec_name, "G722");
        assert_eq!(caps[2].clock_rate, 8000);
        assert_eq!(caps[2].channels, 1);

        // PT 18 = G729 (matches AudioCapability::g729)
        assert_eq!(caps[3].payload_type, 18);
        assert_eq!(caps[3].codec_name, "G729");
        assert_eq!(caps[3].clock_rate, 8000);
        assert_eq!(caps[3].channels, 1);

        // PT 111 = opus (matches AudioCapability::opus/default)
        assert_eq!(caps[4].payload_type, 111);
        assert_eq!(caps[4].codec_name, "opus");
        assert_eq!(caps[4].clock_rate, 48000);
        assert_eq!(caps[4].channels, 2); // Important: opus has 2 channels by default

        // PT 101 = telephone-event (matches AudioCapability::telephone_event)
        assert_eq!(caps[5].payload_type, 101);
        assert_eq!(caps[5].codec_name, "telephone-event");
        assert_eq!(caps[5].clock_rate, 8000);
        assert_eq!(caps[5].channels, 1);
        assert_eq!(caps[5].fmtp.as_deref(), Some("0-16")); // Default fmtp for telephone-event
    }

    // -----------------------------------------------------------------------
    // Tests for modify_sdp_direction
    // -----------------------------------------------------------------------

    #[test]
    fn test_modify_sdp_direction_sendrecv_to_sendonly() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 1234 RTP/AVP 0\r\n\
a=sendrecv\r\n\
m=video 5678 RTP/AVP 96\r\n\
a=sendrecv\r\n";

        let result = modify_sdp_direction(sdp, "sendonly");
        assert!(
            result.contains("a=sendonly"),
            "Direction should be sendonly"
        );
        assert!(!result.contains("a=sendrecv"), "sendrecv should be gone");
    }

    #[test]
    fn test_modify_sdp_direction_sendonly_to_sendrecv() {
        let sdp = "v=0\r\nm=audio 1234 RTP/AVP 0\r\na=sendonly\r\n";
        let result = modify_sdp_direction(sdp, "sendrecv");
        assert!(result.contains("a=sendrecv"));
        assert!(!result.contains("a=sendonly"));
    }

    #[test]
    fn test_modify_sdp_direction_recvonly() {
        let sdp = "v=0\r\nm=audio 1234 RTP/AVP 0\r\na=recvonly\r\n";
        let result = modify_sdp_direction(sdp, "sendrecv");
        assert!(result.contains("a=sendrecv"));
        assert!(!result.contains("a=recvonly"));
    }

    #[test]
    fn test_modify_sdp_direction_inactive() {
        let sdp = "v=0\r\nm=audio 1234 RTP/AVP 0\r\na=inactive\r\n";
        let result = modify_sdp_direction(sdp, "sendrecv");
        assert!(result.contains("a=sendrecv"));
        assert!(!result.contains("a=inactive"));
    }

    #[test]
    fn test_modify_sdp_direction_no_direction_line() {
        // SDP without any direction attribute must pass through unchanged
        let sdp = "v=0\r\nm=audio 1234 RTP/AVP 0\r\na=rtpmap:0 PCMU/8000\r\n";
        let result = modify_sdp_direction(sdp, "sendonly");
        assert!(result.contains("a=rtpmap:0 PCMU/8000"));
        assert!(!result.contains("a=sendonly"));
    }

    #[test]
    fn test_modify_sdp_direction_preserves_other_attrs() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 1234 RTP/AVP 0\r\n\
c=IN IP4 192.0.2.1\r\n\
a=rtpmap:0 PCMU/8000\r\n\
a=fmtp:0 mode=30\r\n\
a=sendrecv\r\n";

        let result = modify_sdp_direction(sdp, "sendonly");
        assert!(result.contains("c=IN IP4 192.0.2.1"));
        assert!(result.contains("a=rtpmap:0 PCMU/8000"));
        assert!(result.contains("a=fmtp:0 mode=30"));
        assert!(result.contains("a=sendonly"));
    }

    // -----------------------------------------------------------------------
    // Tests for parse_bundle_mid_info
    // -----------------------------------------------------------------------

    #[test]
    fn test_parse_bundle_mid_info_linphone_style() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE as vs\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
m=audio 10000 RTP/AVP 0\r\n\
a=mid:as\r\n\
m=video 10002 RTP/AVP 96\r\n\
a=mid:vs\r\n";

        let result = parse_bundle_mid_info(sdp);
        assert_eq!(result, Some((1u8, "as".to_string(), "vs".to_string())));
    }

    #[test]
    fn test_parse_bundle_mid_info_extmap_in_media_section() {
        // extmap can appear inside a media section too
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
m=audio 10000 RTP/AVP 0\r\n\
a=extmap:2 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
a=mid:audio\r\n\
m=video 10002 RTP/AVP 96\r\n\
a=mid:video\r\n";

        let result = parse_bundle_mid_info(sdp);
        assert_eq!(
            result,
            Some((2u8, "audio".to_string(), "video".to_string()))
        );
    }

    #[test]
    fn test_parse_bundle_mid_info_missing_extmap() {
        let sdp = "v=0\r\n\
m=audio 10000 RTP/AVP 0\r\n\
a=mid:as\r\n\
m=video 10002 RTP/AVP 96\r\n\
a=mid:vs\r\n";

        assert!(parse_bundle_mid_info(sdp).is_none());
    }

    #[test]
    fn test_parse_bundle_mid_info_missing_video_mid() {
        let sdp = "v=0\r\n\
a=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\n\
m=audio 10000 RTP/AVP 0\r\n\
a=mid:as\r\n";

        assert!(parse_bundle_mid_info(sdp).is_none());
    }

    #[test]
    fn test_parse_bundle_mid_info_crlf_and_lf_lines() {
        // Mix of CRLF and LF line endings
        let sdp = "v=0\r\na=extmap:1 urn:ietf:params:rtp-hdrext:sdes:mid\r\nm=audio 10000 RTP/AVP 0\r\na=mid:as\r\nm=video 10002 RTP/AVP 96\r\na=mid:vs\r\n";
        let result = parse_bundle_mid_info(sdp);
        assert_eq!(result, Some((1u8, "as".to_string(), "vs".to_string())));
    }

    // ── T.38 / MediaKind::Image tests ───────────────────────────────────────

    #[test]
    fn test_parse_t38_image_sdp() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=image 12345 udptl t38\r\n\
a=mid:0\r\n\
a=T38FaxVersion:0\r\n\
a=T38MaxBitRate:14400\r\n\
a=T38FaxRateManagement:transferredTCF\r\n\
a=T38FaxMaxBuffer:1024\r\n\
a=T38FaxMaxDatagram:238\r\n\
a=T38FaxUdpEC:t38UDPRedundancy\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let sections: Vec<_> = desc.image_sections().collect();
        assert_eq!(sections.len(), 1);
        let section = &sections[0];
        assert_eq!(section.kind, MediaKind::Image);
        assert_eq!(section.port, 12345);
        assert_eq!(section.protocol, "udptl");
        assert_eq!(section.formats, vec!["t38"]);
    }

    #[test]
    fn test_media_kind_image_str() {
        assert_eq!(MediaKind::Image.as_str(), "image");
    }

    #[test]
    fn test_media_kind_image_from_str() {
        assert_eq!("image".parse::<MediaKind>().unwrap(), MediaKind::Image);
        assert!("invalid".parse::<MediaKind>().is_err());
    }

    #[test]
    fn test_apply_image_config_normal() {
        use crate::config::{MediaCapabilities, T38Capability};

        let t38 = T38Capability::default_t38();
        let caps = MediaCapabilities {
            audio: vec![],
            video: vec![],
            application: None,
            image: vec![t38],
        };
        let mut config = RtcConfiguration::default();
        config.media_capabilities = Some(caps);

        let mut section = MediaSection::new(MediaKind::Image, "0");
        section.apply_config(&config);

        assert_eq!(section.protocol, "udptl");
        assert_eq!(section.formats, vec!["98"]);

        let version = section
            .attributes
            .iter()
            .find(|a| a.key == "T38FaxVersion")
            .expect("T38FaxVersion should exist");
        assert_eq!(version.value.as_deref().unwrap(), "0");

        let bitrate = section
            .attributes
            .iter()
            .find(|a| a.key == "T38MaxBitRate")
            .expect("T38MaxBitRate should exist");
        assert_eq!(bitrate.value.as_deref().unwrap(), "14400");

        let rm = section
            .attributes
            .iter()
            .find(|a| a.key == "T38FaxRateManagement")
            .expect("T38FaxRateManagement should exist");
        assert_eq!(rm.value.as_deref().unwrap(), "transferredTCF");

        let ec = section
            .attributes
            .iter()
            .find(|a| a.key == "T38FaxUdpEC")
            .expect("T38FaxUdpEC should exist");
        assert_eq!(ec.value.as_deref().unwrap(), "t38UDPRedundancy");
    }

    #[test]
    fn test_to_image_capabilities_from_sdp() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=image 12345 udptl t38\r\n\
a=mid:0\r\n\
a=T38FaxVersion:0\r\n\
a=T38MaxBitRate:14400\r\n\
a=T38FaxRateManagement:transferredTCF\r\n\
a=T38FaxMaxBuffer:1024\r\n\
a=T38FaxMaxDatagram:238\r\n\
a=T38FaxUdpEC:t38UDPRedundancy\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_image_capabilities();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].version, 0);
        assert_eq!(caps[0].max_bitrate, 14400);
        assert_eq!(
            caps[0].rate_management,
            crate::config::T38FaxRateManagement::TransferredTCF
        );
        assert_eq!(caps[0].max_buffer, 1024);
        assert_eq!(caps[0].max_datagram, 238);
        assert_eq!(caps[0].udp_ec, crate::config::T38UdpEC::T38UDPRedundancy);
    }

    #[test]
    fn test_to_image_capabilities_empty_for_non_image() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        let caps = desc.to_image_capabilities();
        assert!(caps.is_empty());
    }

    #[test]
    fn test_first_image_section() {
        let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n\
m=image 12345 udptl t38\r\n\
a=mid:1\r\n";

        let desc = SessionDescription::parse(SdpType::Offer, sdp).unwrap();
        assert!(desc.first_image_section().is_some());
        assert_eq!(desc.first_image_section().unwrap().mid, "1");
    }
}
