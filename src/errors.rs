use crate::prelude::*;
use thiserror::Error;

pub type RtcResult<T> = Result<T, RtcError>;
pub type SdpResult<T> = Result<T, SdpError>;
pub type RtpResult<T> = Result<T, RtpError>;
pub type SrtpResult<T> = Result<T, SrtpError>;

#[cfg(feature = "std")]
impl From<std::io::Error> for RtcError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::AddrInUse {
            RtcError::AddrInUse
        } else if e.kind() == std::io::ErrorKind::TimedOut {
            // A real socket timeout must be distinguishable from fatal
            // transport errors: the TURN read loop tolerates timeouts.
            RtcError::Timeout(alloc::format!("io: {e}"))
        } else {
            RtcError::Transport(alloc::format!("io: {e}"))
        }
    }
}

#[derive(Debug, Error)]
pub enum RtcError {
    #[error("invalid configuration: {0}")]
    InvalidConfiguration(String),
    #[error("invalid state: {0}")]
    InvalidState(String),
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
    #[error("protocol error: {0}")]
    Protocol(String),
    #[error("transport error: {0}")]
    Transport(String),
    #[error("internal error: {0}")]
    Internal(String),
    /// A wait elapsed without completing: DNS/TCP connect, STUN/TURN
    /// transaction, idle receive. Distinct variant so callers react to
    /// timeouts by type instead of string-matching Display text.
    #[error("operation timed out: {0}")]
    Timeout(String),
    /// The local address (IP:port) is already bound by another socket.
    /// Distinct variant so port-exhaustion retry loops work on every
    /// backend (std io::Error mapping and future platform sockets).
    #[error("address already in use")]
    AddrInUse,
}

impl RtcError {
    /// True when the error reports a busy local port (see [`RtcError::AddrInUse`]).
    pub fn is_addr_in_use(&self) -> bool {
        matches!(self, RtcError::AddrInUse)
    }

    /// True when the error reports a timed-out wait (see [`RtcError::Timeout`]).
    pub fn is_timeout(&self) -> bool {
        matches!(self, RtcError::Timeout(_))
    }
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
    #[error("SRTP internal error: {0}")]
    Internal(String),
}

impl From<RtpError> for SrtpError {
    fn from(value: RtpError) -> Self {
        SrtpError::Internal(value.to_string())
    }
}

impl From<crate::platform::net::NetError> for RtcError {
    fn from(e: crate::platform::net::NetError) -> Self {
        RtcError::Transport(alloc::format!("net: {e}"))
    }
}

impl From<RtpError> for RtcError {
    fn from(e: RtpError) -> Self {
        RtcError::Protocol(alloc::format!("rtp: {e}"))
    }
}

impl From<SrtpError> for RtcError {
    fn from(e: SrtpError) -> Self {
        RtcError::Protocol(alloc::format!("srtp: {e}"))
    }
}

impl From<alloc::string::FromUtf8Error> for RtcError {
    fn from(e: alloc::string::FromUtf8Error) -> Self {
        RtcError::Internal(alloc::format!("utf-8: {e}"))
    }
}

impl From<core::num::ParseIntError> for RtcError {
    fn from(e: core::num::ParseIntError) -> Self {
        RtcError::Internal(alloc::format!("int parse: {e}"))
    }
}

impl From<core::net::AddrParseError> for RtcError {
    fn from(e: core::net::AddrParseError) -> Self {
        RtcError::Internal(alloc::format!("addr parse: {e}"))
    }
}
