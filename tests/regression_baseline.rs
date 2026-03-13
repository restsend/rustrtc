use async_trait::async_trait;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use rustrtc::media::{MediaKind, MediaStreamTrack, sample_track};
use rustrtc::stats::{DynProvider, StatsEntry, StatsId, StatsKind, StatsProvider, gather_once};
use rustrtc::transports::datachannel::DataChannelState;
use rustrtc::transports::dtls;
use rustrtc::{
    IceTransport, IceTransportState, PeerConnection, RtcConfiguration, SdpType, SessionDescription,
    SignalingState,
};

struct StaticStatsProvider;

#[async_trait]
impl StatsProvider for StaticStatsProvider {
    async fn collect(&self) -> rustrtc::RtcResult<Vec<StatsEntry>> {
        Ok(vec![
            StatsEntry::new(StatsId::new("baseline-transport"), StatsKind::Transport)
                .with_value("state", json!("new")),
        ])
    }
}

// These smoke tests intentionally stay shallow: they exist to catch deleted or
// accidentally disconnected public entrypoints before deeper interop suites run.
#[test]
fn regression_security_entrypoints_exist() {
    let cert = dtls::generate_certificate().expect("certificate generation should remain wired");
    let fingerprint = dtls::fingerprint(&cert);
    assert!(
        !fingerprint.is_empty(),
        "DTLS fingerprint generation should remain available"
    );

    let sdp = "v=0\r\n\
o=- 1 1 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=fingerprint:sha-256 aa:bb:cc:dd\r\n\
m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
a=mid:0\r\n";
    let desc = SessionDescription::parse(SdpType::Offer, sdp)
        .expect("SDP parsing should keep supporting DTLS fingerprints");
    let parsed = desc
        .dtls_fingerprint()
        .expect("fingerprint extraction should remain available")
        .expect("fingerprint should be present in the baseline SDP");
    assert_eq!(parsed.algorithm, "sha-256");
    assert_eq!(parsed.value, "AA:BB:CC:DD");
}

#[tokio::test]
async fn regression_signaling_entrypoints_exist() {
    let pc = PeerConnection::new(RtcConfiguration::default());

    assert_eq!(pc.signaling_state(), SignalingState::Stable);
    assert!(pc.local_description().is_none());
    assert!(pc.remote_description().is_none());

    let state_rx = pc.subscribe_signaling_state();
    assert_eq!(*state_rx.borrow(), SignalingState::Stable);

    pc.close();
}

#[tokio::test]
async fn regression_datachannel_entrypoints_exist() {
    let pc = PeerConnection::new(RtcConfiguration::default());
    let data_channel = pc
        .create_data_channel("baseline", None)
        .expect("data channel creation should remain available");

    assert_eq!(data_channel.label, "baseline");
    assert_eq!(
        data_channel.state.load(Ordering::SeqCst),
        DataChannelState::Connecting as usize
    );

    pc.close();
}

#[test]
fn regression_network_entrypoints_exist() {
    let (transport, _runner) = IceTransport::new(RtcConfiguration::default());
    let params = transport.local_parameters();

    assert_eq!(transport.state(), IceTransportState::New);
    assert!(!params.username_fragment.is_empty());
    assert!(!params.password.is_empty());
}

#[test]
fn regression_media_entrypoints_exist() {
    let (source, track, _feedback_rx) = sample_track(MediaKind::Audio, 4);

    assert_eq!(source.kind(), MediaKind::Audio);
    assert_eq!(track.kind(), MediaKind::Audio);
    assert_eq!(track.id(), source.id());
    assert!(!track.id().is_empty());
}

#[tokio::test]
async fn regression_stats_entrypoints_exist() {
    let provider: Arc<DynProvider> = Arc::new(StaticStatsProvider);
    let report = gather_once(&[provider])
        .await
        .expect("stats gathering should remain available");

    assert_eq!(report.entries.len(), 1);
    assert_eq!(report.entries[0].kind, StatsKind::Transport);
}
