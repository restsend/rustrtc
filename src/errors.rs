use thiserror::Error;

pub type RtcResult<T> = Result<T, RtcError>;
pub type SdpResult<T> = Result<T, SdpError>;
pub type RtpResult<T> = Result<T, RtpError>;
pub type SrtpResult<T> = Result<T, SrtpError>;

#[derive(Debug, Error)]
pub enum RtcError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("internal error: {0}")]
    Internal(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SdpError {
    #[error("missing required line: {0}")]
    MissingLine(&'static str),
    #[error("unsupported value: {0}")]
    Unsupported(String),
    #[error("failed to parse SDP: {0}")]
    Parse(String),
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RtpError {
    #[error("RTP packet too short")]
    PacketTooShort,
    #[error("unsupported RTP version {0}")]
    UnsupportedVersion(u8),
    #[error("invalid RTP header: {0}")]
    InvalidHeader(&'static str),
    #[error("invalid RTCP packet: {0}")]
    InvalidRtcp(&'static str),
    #[error("buffer length mismatch")]
    LengthMismatch,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum SrtpError {
    #[error("unsupported SRTP profile")]
    UnsupportedProfile,
    #[error("SRTP packet too short")]
    PacketTooShort,
    #[error("SRTP authentication failed")]
    AuthenticationFailed,
    #[error("SRTP replay detected")]
    ReplayDetected,
    #[error("SRTP packet is outside the replay window")]
    PacketTooOld,
    #[error("SRTP internal error: {0}")]
    Internal(String),
}

impl SrtpError {
    pub fn is_replay_related(&self) -> bool {
        matches!(self, Self::ReplayDetected | Self::PacketTooOld)
    }
}

impl From<RtpError> for SrtpError {
    fn from(value: RtpError) -> Self {
        SrtpError::Internal(value.to_string())
    }
}
