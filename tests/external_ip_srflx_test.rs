//! ServerReflexive mode advertises `external_ip` as a srflx candidate
//! alongside the host candidate (RFC 8445 §5.1.1.2, the 1:1 NAT case).
use anyhow::Result;
use rustrtc::transports::ice::{IceCandidate, IceCandidateType};
use rustrtc::{
    ExternalIpCandidateType, IceTcpPolicy, IceTransportPolicy, MediaKind, PeerConnection,
    RtcConfiguration, TransceiverDirection, TransportMode,
};
use std::net::IpAddr;
use std::time::Duration;

const EXTERNAL: &str = "203.0.113.5";

fn external() -> IpAddr {
    EXTERNAL.parse().unwrap()
}

fn config(typ: Option<ExternalIpCandidateType>) -> RtcConfiguration {
    let mut config = RtcConfiguration {
        external_ip: Some(EXTERNAL.to_string()),
        ..RtcConfiguration::default()
    };
    if let Some(typ) = typ {
        config.external_ip_candidate_type = typ;
    }
    config
}

/// A currently free UDP port for the shared mux socket.
fn free_udp_port() -> u16 {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.local_addr())
        .map(|addr| addr.port())
        .expect("free port")
}

async fn gather(config: RtcConfiguration, transport: &str) -> Result<Vec<IceCandidate>> {
    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _ = pc.create_offer().await?;
    tokio::time::timeout(Duration::from_secs(5), pc.wait_for_gathering_complete()).await?;
    Ok(pc
        .ice_transport()
        .local_candidates()
        .into_iter()
        .filter(|c| c.transport == transport && !c.address.ip().is_loopback())
        .collect())
}

async fn gathered(typ: Option<ExternalIpCandidateType>) -> Result<Vec<IceCandidate>> {
    gather(config(typ), "udp").await
}

#[tokio::test]
async fn default_replaces_the_host_address() -> Result<()> {
    let candidates = gathered(None).await?;
    assert!(!candidates.is_empty());
    for c in &candidates {
        assert_eq!(c.typ, IceCandidateType::Host, "{}", c.to_sdp());
        assert_eq!(c.address.ip(), external(), "{}", c.to_sdp());
    }
    Ok(())
}

#[tokio::test]
async fn server_reflexive_keeps_the_host_candidate() -> Result<()> {
    assert_host_and_srflx(gathered(Some(ExternalIpCandidateType::ServerReflexive)).await?);
    Ok(())
}

#[tokio::test]
async fn server_reflexive_keeps_the_host_candidate_with_udp_mux() -> Result<()> {
    let config = RtcConfiguration {
        ice_udp_mux: true,
        ice_udp_mux_port: Some(free_udp_port()),
        ..config(Some(ExternalIpCandidateType::ServerReflexive))
    };
    assert_host_and_srflx(gather(config, "udp").await?);
    Ok(())
}

#[tokio::test]
async fn server_reflexive_keeps_the_passive_tcp_host_candidate() -> Result<()> {
    let config = RtcConfiguration {
        ice_tcp_policy: IceTcpPolicy::PassiveOnly,
        ..config(Some(ExternalIpCandidateType::ServerReflexive))
    };
    let pc = PeerConnection::new(config);
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _ = pc.create_offer().await?;
    tokio::time::timeout(Duration::from_secs(5), pc.wait_for_gathering_complete()).await?;
    let all: Vec<IceCandidate> = pc
        .ice_transport()
        .local_candidates()
        .into_iter()
        .filter(|c| !c.address.ip().is_loopback())
        .collect();
    let tcp: Vec<IceCandidate> = all
        .iter()
        .filter(|c| c.transport == "tcp")
        .cloned()
        .collect();
    assert_host_and_srflx(tcp);
    let srflx = |transport: &str| {
        all.iter()
            .find(|c| c.typ == IceCandidateType::ServerReflexive && c.transport == transport)
            .cloned()
            .expect("srflx candidate")
    };
    let (tcp_srflx, udp_srflx) = (srflx("tcp"), srflx("udp"));
    assert!(
        tcp_srflx.to_sdp().contains("tcptype passive"),
        "{}",
        tcp_srflx.to_sdp()
    );
    // RFC 8445 §5.1.1.3: same type and base IP but a different transport
    // needs a different foundation.
    assert_eq!(
        tcp_srflx.related_address.map(|a| a.ip()),
        udp_srflx.related_address.map(|a| a.ip())
    );
    assert_ne!(tcp_srflx.foundation, udp_srflx.foundation);
    Ok(())
}

/// Direct SRTP has no ICE: the option does not apply there, `external_ip`
/// is still what the SDP advertises.
#[tokio::test]
async fn srtp_mode_still_advertises_the_external_ip() -> Result<()> {
    let pc = PeerConnection::new(RtcConfiguration {
        transport_mode: TransportMode::Srtp,
        ..config(Some(ExternalIpCandidateType::ServerReflexive))
    });
    pc.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let offer = pc.create_offer().await?;
    let sdp = offer.to_sdp_string();
    assert!(sdp.contains(&format!("c=IN IP4 {EXTERNAL}")), "{sdp}");
    Ok(())
}

fn assert_host_and_srflx(candidates: Vec<IceCandidate>) {
    let hosts: Vec<_> = candidates
        .iter()
        .filter(|c| c.typ == IceCandidateType::Host)
        .collect();
    let srflx: Vec<_> = candidates
        .iter()
        .filter(|c| c.typ == IceCandidateType::ServerReflexive)
        .collect();
    assert!(!hosts.is_empty(), "no host candidate: {candidates:?}");
    assert_eq!(hosts.len(), srflx.len(), "one srflx per host socket");
    for host in &hosts {
        assert_ne!(host.address.ip(), external(), "{}", host.to_sdp());
        assert!(!host.address.ip().is_unspecified(), "{}", host.to_sdp());
        // Same socket: the srflx candidate maps the host port.
        let mapped = srflx
            .iter()
            .find(|c| c.address.port() == host.address.port())
            .expect("srflx for the host socket");
        assert_eq!(mapped.address.ip(), external());
        assert!(mapped.priority < host.priority);
        let line = mapped.to_sdp();
        assert!(
            line.contains("typ srflx") && line.contains(" raddr "),
            "{line}"
        );
    }
}

/// Two peers on the same host still connect when one advertises its
/// external address as srflx.
#[tokio::test]
async fn peers_connect_over_the_host_candidate() -> Result<()> {
    let pc1 = PeerConnection::new(RtcConfiguration {
        external_ip: Some(EXTERNAL.to_string()),
        external_ip_candidate_type: ExternalIpCandidateType::ServerReflexive,
        ..RtcConfiguration::default()
    });
    let pc2 = PeerConnection::new(RtcConfiguration::default());
    pc1.add_transceiver(MediaKind::Audio, TransceiverDirection::SendRecv);
    let _ = pc1.create_offer().await?;
    tokio::time::timeout(Duration::from_secs(5), pc1.wait_for_gathering_complete()).await?;
    let offer = pc1.create_offer().await?;
    assert!(offer.to_sdp_string().contains("typ srflx"));
    pc1.set_local_description(offer.clone())?;
    pc2.set_remote_description(offer).await?;
    let _ = pc2.create_answer().await?;
    tokio::time::timeout(Duration::from_secs(5), pc2.wait_for_gathering_complete()).await?;
    let answer = pc2.create_answer().await?;
    pc2.set_local_description(answer.clone())?;
    pc1.set_remote_description(answer).await?;
    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::try_join!(pc1.wait_for_connected(), pc2.wait_for_connected())
    })
    .await??;
    Ok(())
}

/// With mDNS, the host candidate is obfuscated as usual; the srflx
/// candidate advertises the public address as is (its `raddr` is the base,
/// as for STUN-learned srflx candidates).
#[tokio::test]
async fn server_reflexive_with_mdns_obfuscates_only_the_host() -> Result<()> {
    let config = RtcConfiguration {
        enable_mdns: true,
        ..config(Some(ExternalIpCandidateType::ServerReflexive))
    };
    let candidates = gather(config, "udp").await?;
    assert_host_and_srflx(candidates.clone());
    for c in &candidates {
        let line = c.to_sdp();
        match c.typ {
            IceCandidateType::Host => assert!(line.contains(".local "), "{line}"),
            _ => assert!(line.contains(&format!(" {EXTERNAL} ")), "{line}"),
        }
    }
    Ok(())
}

/// An `external_ip` of the other address family is never paired with the
/// socket: the host candidate alone is advertised.
#[tokio::test]
async fn server_reflexive_skips_an_external_ip_of_the_other_family() -> Result<()> {
    let config = RtcConfiguration {
        external_ip: Some("2001:db8::5".to_string()),
        external_ip_candidate_type: ExternalIpCandidateType::ServerReflexive,
        ..RtcConfiguration::default()
    };
    let candidates = gather(config, "udp").await?;
    assert!(!candidates.is_empty());
    assert!(
        candidates.iter().all(|c| c.typ == IceCandidateType::Host),
        "{candidates:?}"
    );
    Ok(())
}

/// Relay-only: the option adds nothing. Every direct candidate path is
/// skipped as before except the fixed `tcp_port_range_*` listener, which
/// keeps advertising exactly what the default does.
#[tokio::test]
async fn relay_policy_advertises_the_same_as_the_default() -> Result<()> {
    let relay = |typ| RtcConfiguration {
        ice_transport_policy: IceTransportPolicy::Relay,
        ice_tcp_policy: IceTcpPolicy::Enabled,
        tcp_port_range_start: Some(45000),
        tcp_port_range_end: Some(45100),
        ..config(Some(typ))
    };
    let advertised = |candidates: Vec<IceCandidate>| {
        let mut out: Vec<_> = (candidates.into_iter())
            .map(|c| (c.typ, c.transport, c.address.ip()))
            .collect();
        out.sort_by_key(|c| format!("{c:?}"));
        out
    };
    for transport in ["udp", "tcp"] {
        let default = gather(relay(ExternalIpCandidateType::Host), transport).await?;
        let srflx = gather(relay(ExternalIpCandidateType::ServerReflexive), transport).await?;
        assert_eq!(advertised(srflx), advertised(default), "{transport}");
    }
    Ok(())
}
