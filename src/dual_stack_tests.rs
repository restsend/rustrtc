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
/// (Loopback is never mapped to the external address; `o=` is.)
#[tokio::test]
async fn direct_offer_writes_ip6_for_ipv6() {
    for mode in [TransportMode::Rtp, TransportMode::Srtp] {
        let mut cfg = config(mode.clone());
        cfg.bind_ips = vec![ip("::1")];
        let sdp = offer(cfg.clone()).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP6 ::1", "{mode:?}:\n{sdp}");

        cfg.external_ips = vec![ip("2001:db8::1")];
        let sdp = offer(cfg).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP6 ::1", "{mode:?}:\n{sdp}");
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
        cfg.bind_ips = vec![ip("127.0.0.1")];
        cfg.external_ips = vec![ip("192.0.2.1")];
        let sdp = offer(cfg).await;
        assert_eq!(line(&sdp, "c="), "c=IN IP4 127.0.0.1", "{mode:?}:\n{sdp}");
        assert!(line(&sdp, "o=").ends_with(" IN IP4 192.0.2.1"), "{mode:?}");
    }
}

fn ip(s: &str) -> core::net::IpAddr {
    s.parse().unwrap()
}

/// The `a=candidate` lines of a description: (address, port, type).
fn candidates(sdp: &str) -> Vec<(core::net::IpAddr, u16, String)> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=candidate:"))
        .map(|c| {
            let p: Vec<&str> = c.split_whitespace().collect();
            (
                p[4].parse().unwrap(),
                p[5].parse().unwrap(),
                p[7].to_string(),
            )
        })
        .collect()
}

/// A WebRTC offer with its candidates gathered.
async fn gathered_offer(config: RtcConfiguration) -> String {
    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _ = pc.create_offer().await.unwrap();
    pc.wait_for_gathering_complete().await;
    let offer = pc.create_offer().await.unwrap();
    pc.close();
    offer.to_sdp_string()
}

/// One socket on `::` serves both families: a host candidate for each, on
/// the same port, with each family's external address.
#[tokio::test]
async fn dual_stack_socket_has_a_candidate_per_family() {
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("::")];
    cfg.external_ips = vec![ip("192.0.2.1"), ip("2001:db8::1")];
    let sdp = gathered_offer(cfg).await;
    let cands = candidates(&sdp);
    assert_eq!(cands.len(), 2, "{sdp}");
    assert_eq!(
        (cands[0].0, &*cands[0].2),
        (ip("192.0.2.1"), "host"),
        "{sdp}"
    );
    assert_eq!(
        (cands[1].0, &*cands[1].2),
        (ip("2001:db8::1"), "host"),
        "{sdp}"
    );
    assert_eq!(cands[0].1, cands[1].1, "one socket, one port:\n{sdp}");
}

/// Without external addresses, `::` advertises the local address of each
/// family: the default route's IPv4 address and a reachable IPv6 one.
#[tokio::test]
async fn dual_stack_socket_without_external_ips_advertises_local_addresses() {
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("::")];
    let sdp = gathered_offer(cfg).await;
    let cands = candidates(&sdp);
    let expected: Vec<_> = crate::transports::get_local_ip()
        .ok()
        .filter(|ip| ip.is_ipv4())
        .into_iter()
        .chain(crate::transports::get_local_ipv6().map(core::net::IpAddr::V6))
        .collect();
    assert_eq!(
        cands.iter().map(|c| c.0).collect::<Vec<_>>(),
        expected,
        "{sdp}"
    );
    assert!(cands.iter().all(|c| !c.0.is_unspecified()), "{sdp}");
}

/// Only one family has an external address: it maps that family only.
#[tokio::test]
async fn external_ip_maps_only_its_own_family() {
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("::")];
    cfg.external_ips = vec![ip("192.0.2.1")];
    let cands = candidates(&gathered_offer(cfg).await);
    assert_eq!(cands[0].0, ip("192.0.2.1"));
    if let Some(v6) = crate::transports::get_local_ipv6() {
        assert_eq!(cands[1].0, core::net::IpAddr::V6(v6), "IPv6 stays local");
    }

    // A socket of one family never takes the other family's address.
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("0.0.0.0")];
    cfg.external_ips = vec![ip("2001:db8::1")];
    let cands = candidates(&gathered_offer(cfg).await);
    assert_eq!(cands.len(), 1);
    assert!(cands[0].0.is_ipv4(), "{cands:?}");
}

/// Two bind addresses, two sockets: a candidate on each.
#[tokio::test]
async fn one_socket_per_bind_address() {
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("127.0.0.1"), ip("::1")];
    let cands = candidates(&gathered_offer(cfg).await);
    assert_eq!(
        cands.iter().map(|c| c.0).collect::<Vec<_>>(),
        vec![ip("127.0.0.1"), ip("::1")]
    );
}

/// Server-reflexive mode on `::`: a host candidate on each family's local
/// address, and each family's external address as srflx.
#[tokio::test]
async fn external_ips_as_srflx_per_family() {
    let mut cfg = config(TransportMode::WebRtc);
    cfg.bind_ips = vec![ip("::")];
    cfg.external_ips = vec![ip("192.0.2.1"), ip("2001:db8::1")];
    cfg.external_ip_candidate_type = crate::ExternalIpCandidateType::ServerReflexive;
    let sdp = gathered_offer(cfg).await;
    let cands = candidates(&sdp);
    let srflx: Vec<_> = cands
        .iter()
        .filter(|c| c.2 == "srflx")
        .map(|c| c.0)
        .collect();
    let host: Vec<_> = cands
        .iter()
        .filter(|c| c.2 == "host")
        .map(|c| c.0)
        .collect();
    assert!(host.iter().all(|ip| !ip.is_unspecified()), "{sdp}");
    if crate::transports::get_local_ip().is_ok_and(|ip| ip.is_ipv4()) {
        assert!(srflx.contains(&ip("192.0.2.1")), "{sdp}");
    }
    if crate::transports::get_local_ipv6().is_some() {
        assert!(srflx.contains(&ip("2001:db8::1")), "{sdp}");
    }
}

/// A direct transport (RTP, SRTP) binds on every address too; with ICE-lite
/// the answer lists a candidate for each family.
#[tokio::test]
async fn direct_transport_lists_both_families_with_ice_lite() {
    for mode in [TransportMode::Rtp, TransportMode::Srtp] {
        let mut cfg = config(mode.clone());
        cfg.enable_ice_lite = true;
        cfg.bind_ips = vec![ip("::")];
        cfg.external_ips = vec![ip("192.0.2.1"), ip("2001:db8::1")];
        let sdp = offer(cfg).await;
        let cands = candidates(&sdp);
        let rtp: Vec<_> = cands
            .iter()
            .filter(|c| c.2 == "host")
            .map(|c| c.0)
            .collect();
        assert!(rtp.contains(&ip("192.0.2.1")), "{mode:?}:\n{sdp}");
        assert!(rtp.contains(&ip("2001:db8::1")), "{mode:?}:\n{sdp}");
    }
}
