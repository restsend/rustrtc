#![cfg_attr(not(feature = "std"), no_std)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
#![allow(clippy::field_reassign_with_default)]
//! rustrtc — WebRTC / RTP / SRTP / T.38 real-time communication library.

// These lints are opinionated style choices that don't fit this codebase's
// established patterns (large RTC structs naturally have many fields/args and
// use composite shared-state types). Allowed crate-wide to keep `cargo clippy`
// focused on genuinely useful diagnostics.
// `alloc` is a sysroot crate; naming it in std builds is valid and lets the
// data-plane modules share one set of alloc imports across std/no_std.
extern crate alloc;

// Crate-internal prelude: fills the no_std gaps with `alloc` items; in std
// builds the std prelude already covers these (same types).
pub mod prelude {
    pub use alloc::borrow::{Cow, ToOwned};
    pub use alloc::boxed::Box;
    pub use alloc::collections::{BTreeMap, BTreeSet};
    pub use alloc::string::{String, ToString};
    pub use alloc::sync::{Arc, Weak};
    pub use alloc::vec::Vec;
    #[cfg(not(feature = "std"))]
    pub use alloc::{format, vec};
}

// `let mut x = T::default(); x.field = v;` is often clearer than a partial
// struct literal, especially in tests. Pervasive here, so allowed crate-wide.

pub mod config;
pub mod errors;
pub mod media;
pub mod peer_connection;
pub mod platform;
pub mod rtp;
pub mod rtx;
pub mod sdp;
pub mod srtp;
pub mod stats;
pub mod stats_collector;
#[cfg(feature = "t38")]
pub mod t38;

/// doc(hidden) test instrumentation (feature `test-hooks`): how many times
/// the connected-state DTLS monitor loop has iterated, across all peer
/// connections. A parked monitor advances a handful of times per session;
/// the clone-notification busy-loop that starved TURN read tasks advanced
/// thousands of times per second. Downstream integration tests assert the
/// delta over an idle hold window (see `monitor_ice_and_dtls`).
#[cfg(feature = "test-hooks")]
#[doc(hidden)]
pub static DTLS_MONITOR_ITERATIONS: crate::platform::atomic64::AtomicU64 =
    crate::platform::atomic64::AtomicU64::new(0);

pub mod transports;

pub use config::{
    ApplicationCapability, AudioCapability, BundlePolicy, CertificateConfig,
    ExternalIpCandidateType, IceCredentialType, IceServer, IceTcpPolicy, IceTransportPolicy,
    MediaCapabilities, RecorderInterceptors, RtcConfiguration, RtcConfigurationBuilder,
    RtcpMuxPolicy, SdpCompatibilityMode, T38Capability, T38FaxRateManagement, T38UdpEC,
    TransportMode, VideoCapability,
};
pub use errors::{RtcError, RtcResult, SdpError, SdpResult};
#[cfg(feature = "std")]
pub use peer_connection::{
    DisconnectReason, IceConnectionState, IceGatheringState, PeerConnection, PeerConnectionEvent,
    PeerConnectionState, RtpCodecParameters, RtpReceiverInterceptor, RtpSender,
    RtpSenderInterceptor, RtpTransceiver, SignalingState, TransceiverDirection,
    rtcp_fb_enables_nack,
};
#[cfg(feature = "std")]
pub use sdp::{
    AddressType, Attribute, Direction, MediaKind, MediaSection, NetworkType, Origin, SDES_MID_URI,
    SdpType, SessionDescription, SessionSection, Timing, modify_sdp_direction,
    parse_bundle_mid_info,
};
pub use srtp::{SrtpContext, SrtpDirection, SrtpKeyingMaterial, SrtpProfile, SrtpSession};
#[cfg(feature = "std")]
pub use stats::{
    DynProvider, StatsEntry, StatsId, StatsKind, StatsProvider, StatsReport, gather_once,
};
#[cfg(feature = "std")]
pub use transports::ice::{
    DEFAULT_LEASE_DURATION, DEFAULT_UPNP_DISCOVERY_TIMEOUT, IceCandidate, IceCandidatePair,
    IceCandidateType, IceGathererState, IceRole, IceTransport, IceTransportState,
    MAX_LEASE_DURATION, MIN_LEASE_DURATION, TcpType, UpnpPortMapper,
};
#[cfg(feature = "std")]
pub use transports::rtp::{RtpRewriteBridgeOptions, RtpRewriteBridgeParams, RtpRewriteRule};
#[cfg(feature = "std")]
pub use transports::sctp::{DataChannelEvent, DataChannelState, SctpLinkStats};
#[cfg(feature = "std")]
pub use transports::udptl::{UdtlConfig, UdtlReceiveBuffer, UdtlTransport};

#[cfg(feature = "std")]
use std::future::Future;
#[cfg(feature = "std")]
use tracing::Instrument;

/// Spawn a task on the configured runtime handle when one is set, else on the
/// ambient (current) runtime. The future is instrumented with `span` so logs
/// emitted inside inherit the correlation context (pass `tracing::Span::current()`
/// for nested spawns that already run inside an instrumented task).
#[cfg(feature = "std")]
#[inline]
pub(crate) fn spawn_rtc<F>(
    handle: Option<&tokio::runtime::Handle>,
    span: tracing::Span,
    fut: F,
) -> tokio::task::JoinHandle<()>
where
    F: Future<Output = ()> + Send + 'static,
{
    let fut = fut.instrument(span);
    match handle {
        Some(h) => h.spawn(fut),
        None => tokio::spawn(fut),
    }
}

/// no_std counterpart of [`spawn_rtc`]: the injected platform spawner is
/// used; the optional runtime handle and tracing span are ignored.
#[cfg(not(feature = "std"))]
#[inline]
pub(crate) fn spawn_rtc<F>(
    _handle: Option<&crate::config::RuntimeHandle>,
    _span: tracing::Span,
    fut: F,
) where
    F: Future<Output = ()> + Send + 'static,
{
    crate::platform::task::spawn(fut);
}
