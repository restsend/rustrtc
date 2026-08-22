//! rustrtc — WebRTC / RTP / SRTP / T.38 real-time communication library.

// These lints are opinionated style choices that don't fit this codebase's
// established patterns (large RTC structs naturally have many fields/args and
// use composite shared-state types). Allowed crate-wide to keep `cargo clippy`
// focused on genuinely useful diagnostics.
#![allow(clippy::too_many_arguments)]
#![allow(clippy::type_complexity)]
#![allow(clippy::result_large_err)]
#![allow(clippy::large_enum_variant)]
// `let mut x = T::default(); x.field = v;` is often clearer than a partial
// struct literal, especially in tests. Pervasive here, so allowed crate-wide.
#![allow(clippy::field_reassign_with_default)]

pub mod config;
pub mod errors;
pub mod media;
pub mod peer_connection;
pub mod rtp;
pub mod rtx;
pub mod sdp;
pub mod srtp;
pub mod stats;
pub mod stats_collector;
#[cfg(feature = "t38")]
pub mod t38;
pub mod transports;

pub use config::{
    ApplicationCapability, AudioCapability, BundlePolicy, CertificateConfig, IceCredentialType,
    IceServer, IceTcpPolicy, IceTransportPolicy, MediaCapabilities, RecorderInterceptors,
    RtcConfiguration, RtcConfigurationBuilder, RtcpMuxPolicy, SdpCompatibilityMode, T38Capability,
    T38FaxRateManagement, T38UdpEC, TransportMode, VideoCapability,
};
pub use errors::{RtcError, RtcResult, SdpError, SdpResult};
pub use peer_connection::{
    DisconnectReason, IceConnectionState, IceGatheringState, PeerConnection, PeerConnectionEvent,
    PeerConnectionState, RtpCodecParameters, RtpReceiverInterceptor, RtpSender,
    RtpSenderInterceptor, RtpTransceiver, SignalingState, TransceiverDirection, rtcp_fb_enables_nack,
};
pub use sdp::{
    AddressType, Attribute, Direction, MediaKind, MediaSection, NetworkType, Origin, SDES_MID_URI,
    SdpType, SessionDescription, SessionSection, Timing, modify_sdp_direction,
    parse_bundle_mid_info,
};
pub use srtp::{SrtpContext, SrtpDirection, SrtpKeyingMaterial, SrtpProfile, SrtpSession};
pub use stats::{
    DynProvider, StatsEntry, StatsId, StatsKind, StatsProvider, StatsReport, gather_once,
};
pub use transports::ice::{
    DEFAULT_LEASE_DURATION, DEFAULT_UPNP_DISCOVERY_TIMEOUT, IceCandidate, IceCandidatePair,
    IceCandidateType, IceGathererState, IceRole, IceTransport, IceTransportState,
    MAX_LEASE_DURATION, MIN_LEASE_DURATION, TcpType, UpnpPortMapper,
};
pub use transports::rtp::{RtpRewriteBridgeOptions, RtpRewriteBridgeParams, RtpRewriteRule};
pub use transports::sctp::{DataChannelEvent, DataChannelState, SctpLinkStats};
pub use transports::udptl::{UdtlConfig, UdtlReceiveBuffer, UdtlTransport};

use std::future::Future;
use tracing::Instrument;

/// Spawn a task on the configured runtime handle when one is set, else on the
/// ambient (current) runtime. The future is instrumented with `span` so logs
/// emitted inside inherit the correlation context (pass `tracing::Span::current()`
/// for nested spawns that already run inside an instrumented task).
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
