// Tests for mDNS candidate obfuscation (draft-ietf-rtcweb-mdns):
// 1. With `enable_mdns`, host candidates are advertised as `<random>.local`
//    hostnames in SDP while the internal address stays real — so ICE still
//    connects.
// 2. The mDNS responder answers A queries for the advertised hostname with a
//    real local address.
// 3. A remote offer containing `.local` candidates is tolerated.
#![allow(clippy::field_reassign_with_default)]
use anyhow::Result;
use rustrtc::transports::ice::IceGathererState;
use rustrtc::transports::sctp::{DataChannelConfig, DataChannelEvent};
use rustrtc::{PeerConnection, RtcConfiguration};
use std::time::Duration;
use tokio::time::timeout;

async fn wait_gather_complete(pc: &PeerConnection) {
    loop {
        if pc.ice_transport().gather_state() == IceGathererState::Complete {
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn candidate_lines(sdp: &str) -> Vec<String> {
    sdp.lines()
        .filter_map(|l| l.strip_prefix("a=candidate:"))
        .map(|s| s.to_string())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mdns_candidates_obfuscate_sdp_but_still_connect() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    let config_a = RtcConfiguration {
        enable_mdns: true,
        ..Default::default()
    };
    let pc_a = PeerConnection::new(config_a);
    let pc_b = PeerConnection::new(RtcConfiguration::default());

    let dc_a = pc_a.create_data_channel(
        "mdns",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;
    let dc_b = pc_b.create_data_channel(
        "mdns",
        Some(DataChannelConfig {
            negotiated: Some(0),
            ..Default::default()
        }),
    )?;

    let _ = pc_a.create_offer().await?;
    wait_gather_complete(&pc_a).await;
    let offer = pc_a.create_offer().await?;
    let offer_sdp = offer.to_sdp_string();
    pc_a.set_local_description(offer.clone())?;

    // Host candidates must be advertised as `.local` hostnames.
    let cands = candidate_lines(&offer_sdp);
    assert!(!cands.is_empty(), "offer must carry candidates");
    let host_cands: Vec<&String> = cands.iter().filter(|c| c.contains(" typ host")).collect();
    assert!(
        !host_cands.is_empty(),
        "offer must carry host candidates, got: {cands:?}"
    );
    for c in &host_cands {
        assert!(
            c.contains(".local"),
            "mdns host candidate must advertise a .local hostname: {c}"
        );
    }
    // The internal address must stay real: candidates subscribe events keep
    // the real SocketAddr.
    let internal = pc_a.ice_transport().local_candidates();
    assert!(
        internal.iter().any(|c| c.hostname.is_some()),
        "internal candidates must carry the hostname override"
    );

    // Non-mDNS peer must interop: pc_b cannot resolve `.local` (no mDNS
    // resolution by design — the peer's srflx/resolved candidates carry the
    // real address), so simulate resolution by feeding it the real host
    // candidate. This proves the internal address was preserved end-to-end.
    pc_b.set_remote_description(offer).await?;
    for cand in pc_a.ice_transport().local_candidates() {
        if cand.typ == rustrtc::transports::ice::IceCandidateType::Host {
            pc_b.add_ice_candidate(cand)?;
        }
    }
    let _ = pc_b.create_answer().await?;
    wait_gather_complete(&pc_b).await;
    let answer = pc_b.create_answer().await?;
    pc_b.set_local_description(answer.clone())?;
    pc_a.set_remote_description(answer).await?;

    pc_a.wait_for_connected().await?;
    pc_b.wait_for_connected().await?;
    tokio::time::sleep(Duration::from_millis(400)).await;

    // DataChannel flows across the mDNS-obfuscated offer.
    pc_a.send_data(dc_a.id, b"mdns-ping".to_vec().as_slice())
        .await?;
    let got = timeout(Duration::from_secs(5), async {
        loop {
            if let Some(DataChannelEvent::Message(b)) = dc_b.recv().await {
                break b;
            }
        }
    })
    .await?;
    assert_eq!(b"mdns-ping".to_vec(), got.as_ref());
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mdns_responder_answers_a_query() -> Result<()> {
    use rustrtc::transports::ice::mdns::MdnsResponder;

    let _ = env_logger::builder().is_test(true).try_init();

    let hostname = MdnsResponder::generate_hostname();
    // Advertise loopback for the test (production never does).
    let responder = MdnsResponder::start(
        hostname.clone(),
        vec![std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
    )?;

    // Send a real A query to the multicast group from a socket that is also
    // a group member (multicast replies only reach group members).
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    let _ = s.set_reuse_address(true);
    s.bind(&"0.0.0.0:0".parse::<std::net::SocketAddr>()?.into())?;
    s.join_multicast_v4(
        &std::net::Ipv4Addr::new(224, 0, 0, 251),
        &std::net::Ipv4Addr::UNSPECIFIED,
    )?;
    s.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(std::net::UdpSocket::from(s))?;
    let mut query = vec![0u8; 12];
    query[4] = 0;
    query[5] = 1; // QDCOUNT=1
    for label in hostname.split('.') {
        query.push(label.len() as u8);
        query.extend_from_slice(label.as_bytes());
    }
    query.push(0);
    query.extend_from_slice(&1u16.to_be_bytes()); // QTYPE=A
    query.extend_from_slice(&1u16.to_be_bytes()); // QCLASS=IN

    let dest: std::net::SocketAddr = "224.0.0.251:5353".parse()?;
    socket.send_to(&query, dest).await?;

    let mut buf = vec![0u8; 1500];
    let (len, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf)).await??;
    // Response flags: QR|AA.
    assert_eq!(&buf[2..4], &0x8400u16.to_be_bytes());
    assert_eq!(u16::from_be_bytes([buf[6], buf[7]]), 1, "one answer");
    assert!(
        buf[..len].windows(4).any(|w| w == [127, 0, 0, 1]),
        "answer must carry 127.0.0.1"
    );

    responder.stop().await;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_local_candidates_are_tolerated() -> Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();
    let pc_a = PeerConnection::new(RtcConfiguration::default());
    pc_a.create_data_channel("tol", None)?;

    // An offer whose host candidate uses an mDNS hostname (like Chrome's).
    let sdp = "v=0\r\n\
o=- 123 2 IN IP4 127.0.0.1\r\n\
s=-\r\n\
t=0 0\r\n\
a=group:BUNDLE 0\r\n\
m=application 9 UDP/TLS/RTP/SAVPF 5000\r\n\
c=IN IP4 0.0.0.0\r\n\
a=mid:0\r\n\
a=ice-ufrag:rufr\r\n\
a=ice-pwd:pwdpwdpwdpwdpwdpwdpwd\r\n\
a=candidate:1 1 udp 2113937151 abcd1234-5678-90ab-cdef.local 50000 typ host\r\n\
a=fingerprint:sha-256 00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF\r\n\
a=setup:actpass\r\n\
a=sctp-port:5000\r\n";
    let offer = rustrtc::SessionDescription::parse(rustrtc::SdpType::Offer, sdp)?;
    // Must not error out on the unresolvable candidate.
    pc_a.set_remote_description(offer).await?;
    Ok(())
}
