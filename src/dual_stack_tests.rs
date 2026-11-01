//! IPv4 and IPv6 together: the families in SDP, sockets, candidates and the
//! media path, for plain RTP and SRTP (no ICE, ICE-lite) and WebRTC (ICE).

use crate::peer_connection::{PeerConnection, TransceiverDirection};
use crate::sdp::{MediaKind, SdpType, SessionDescription};
use crate::{RtcConfiguration, TransportMode};

fn config(mode: TransportMode) -> RtcConfiguration {
    let mut config = RtcConfiguration::default();
    config.transport_mode = mode;
    config
}

/// Our offer, as text.
async fn offer(config: RtcConfiguration) -> String {
    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await.unwrap();
    pc.close();
    offer.to_sdp_string()
}

fn line<'a>(sdp: &'a str, prefix: &str) -> &'a str {
    sdp.lines()
        .find(|l| l.starts_with(prefix))
        .unwrap_or_else(|| panic!("no {prefix} line:\n{sdp}"))
}

/// An IPv6 address goes in `c=` and `o=` as `IN IP6`, not `IN IP4`.
#[tokio::test]
async fn direct_offer_writes_ip6_for_ipv6() {
    for mode in [TransportMode::Rtp, TransportMode::Srtp] {
        let mut cfg = config(mode.clone());
        cfg.bind_ip = Some("::1".into());
        let sdp = offer(cfg.clone()).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP6 ::1", "{mode:?}:\n{sdp}");

        cfg.external_ip = Some("2001:db8::1".into());
        let sdp = offer(cfg).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP6 2001:db8::1", "{mode:?}:\n{sdp}");
        assert!(
            line(&sdp, "o=").ends_with(" IN IP6 2001:db8::1"),
            "{mode:?}:\n{sdp}"
        );
        SessionDescription::parse(SdpType::Offer, &sdp).expect("our offer parses");
    }
}

/// IPv4 stays `IN IP4`.
#[tokio::test]
async fn direct_offer_writes_ip4_for_ipv4() {
    for mode in [TransportMode::Rtp, TransportMode::Srtp] {
        let mut cfg = config(mode.clone());
        cfg.bind_ip = Some("127.0.0.1".into());
        cfg.external_ip = Some("192.0.2.1".into());
        let sdp = offer(cfg).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP4 192.0.2.1", "{mode:?}:\n{sdp}");
        assert!(line(&sdp, "o=").ends_with(" IN IP4 192.0.2.1"), "{mode:?}");
    }
}
