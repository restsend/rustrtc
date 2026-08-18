//! Regression test for the ICE nomination race across cascaded NAT.
//!
//! Symptom (real deployment): the controlling side (rport client) selected a
//! fast lower-priority pair (srflx/TURN-relay) while the controlled side
//! (rport agent) selected the higher-priority host <-> peer-reflexive pair,
//! leaving the two ends with incompatible pairs and a broken WebRTC DTLS
//! media path (`Data channel closed (reason: DTLS failed)` / data channel
//! never opening).
//!
//! Root cause (rustrtc): the controlling side launched ALL nomination checks
//! in parallel and selected the *first* success, so a slow-but-higher-priority
//! host pair lost the race to a fast relay pair.
//!
//! This test forces that race deterministically: a local TURN server provides
//! relay candidates (lower priority), and the simulator hook delays every
//! direct (non-TURN) STUN response by 100ms so the host path always finishes
//! after the relay path. The controlling side must still select the
//! host -> host pair (the one the controlled side selects).
use std::sync::Arc;
use std::time::Duration;

use rustrtc::{
    transports::sctp::{DataChannelConfig, DataChannelEvent},
    IceCandidateType, IceServer, PeerConnection, PeerConnectionEvent, RtcConfiguration,
};
use tokio::time::timeout;
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use webrtc_util::vnet::net::Net;

/// Minimal long-term-auth TURN server on loopback (mirrors rport-server).
struct TestTurnServer {
    _server: Server,
}

impl TestTurnServer {
    async fn start() -> anyhow::Result<(Self, String, String, String)> {
        let socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let conn: Arc<tokio::net::UdpSocket> = Arc::new(socket);

        let secret = format!("test-secret-{}", std::process::id());
        let relay_addr_generator = Box::new(RelayAddressGeneratorStatic {
            relay_address: "127.0.0.1".parse()?,
            address: "0.0.0.0".to_owned(),
            net: Arc::new(Net::new(None)),
        });
        let auth_handler = turn::auth::LongTermAuthHandler::new(secret.clone());

        let config = ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator,
            }],
            realm: "test.turn".to_owned(),
            auth_handler: Arc::new(auth_handler),
            channel_bind_timeout: Duration::from_secs(600),
            alloc_close_notify: None,
        };

        let server = Server::new(config).await?;
        let (username, password) =
            turn::auth::generate_long_term_credentials(&secret, Duration::from_secs(3600))?;
        let url = format!("turn:127.0.0.1:{}", addr.port());
        Ok((Self { _server: server }, url, username, password))
    }
}

fn turn_ice_servers(url: &str, username: &str, password: &str) -> Vec<IceServer> {
    let mut s = IceServer::new(vec![url.to_string()]);
    s = s.with_credential(username, password);
    vec![s]
}

fn test_config(turn_url: &str, username: &str, password: &str) -> RtcConfiguration {
    RtcConfiguration {
        ice_servers: turn_ice_servers(turn_url, username, password),
        // One host candidate per peer (loopback) so the delayed host path is
        // a single pair, keeping the timing within the nomination grace window.
        bind_ip: Some("127.0.0.1".to_string()),
        ice_connection_timeout: Duration::from_secs(20),
        ice_disconnect_threshold: Duration::from_secs(10),
        ..Default::default()
    }
}

#[tokio::test]
async fn test_controlling_side_selects_highest_priority_pair() -> anyhow::Result<()> {
    let _ = env_logger::builder().is_test(true).try_init();

    // Safety: this test runs in its own test binary, so mutating the
    // process-global env cannot race with other test files.
    unsafe {
        std::env::set_var("RUSTRTC_STUN_RESPOND_DELAY_MS", "100");
    }

    let (_turn, turn_url, username, password) = TestTurnServer::start().await?;
    println!("TURN server at {}", turn_url);

    let config_a = test_config(&turn_url, &username, &password);
    let config_b = config_a.clone();

    // Controlling side (offerer): client role, initiates DTLS.
    let pc_a = PeerConnection::new(config_a);
    let dc_a = pc_a.create_data_channel(
        "ice-priority",
        Some(DataChannelConfig {
            ordered: true,
            ..Default::default()
        }),
    )?;

    // Controlled side (answerer).
    let pc_b = PeerConnection::new(config_b);

    // Exchange SDP (wait for full gathering so relay candidates are in the SDP).
    let offer = pc_a.create_offer().await?;
    pc_a.set_local_description(offer)?;
    pc_a.wait_for_gathering_complete().await;
    let offer = pc_a.local_description().unwrap();

    pc_b.set_remote_description(offer).await?;
    let answer = pc_b.create_answer().await?;
    pc_b.set_local_description(answer)?;
    pc_b.wait_for_gathering_complete().await;
    let answer = pc_b.local_description().unwrap();

    pc_a.set_remote_description(answer).await?;

    // Wait for both sides to connect.
    timeout(Duration::from_secs(15), pc_a.wait_for_connected()).await??;
    timeout(Duration::from_secs(15), pc_b.wait_for_connected()).await??;
    println!("Both peers connected");

    let pair_a = pc_a
        .ice_transport()
        .get_selected_pair()
        .expect("controlling side must have a selected pair");
    let pair_b = pc_b
        .ice_transport()
        .get_selected_pair()
        .expect("controlled side must have a selected pair");
    println!(
        "Controlling selected: local {} {:?} -> remote {} {:?}",
        pair_a.local.address, pair_a.local.typ, pair_a.remote.address, pair_a.remote.typ
    );
    println!(
        "Controlled  selected: local {} {:?} -> remote {} {:?}",
        pair_b.local.address, pair_b.local.typ, pair_b.remote.address, pair_b.remote.typ
    );

    // The controlling side must pick the highest-priority *successful* pair
    // (host -> host), not the fast relay pair that won the old race.
    assert!(
        matches!(pair_a.local.typ, IceCandidateType::Host)
            && matches!(pair_a.remote.typ, IceCandidateType::Host),
        "controlling side selected a lower-priority pair ({} {:?} -> {} {:?}); \
         the host->host pair should win the nomination even when it responds \
         more slowly than the relay path",
        pair_a.local.address, pair_a.local.typ, pair_a.remote.address, pair_a.remote.typ,
    );

    // The two ends must converge on the same path.
    assert_eq!(
        pair_a.remote.address,
        pair_b.local.address,
        "controlling and controlled sides selected incompatible pairs"
    );

    // Sanity: data actually flows end to end over the chosen path.
    let dc_b = {
        let mut received = None;
        while let Ok(Some(event)) =
            timeout(Duration::from_secs(5), pc_b.recv()).await
        {
            if let PeerConnectionEvent::DataChannel(dc) = event {
                received = Some(dc);
                break;
            }
        }
        received.expect("controlled side should receive the incoming data channel")
    };

    let mut dc_a_open = false;
    while let Some(event) = dc_a.recv().await {
        if let DataChannelEvent::Open = event {
            dc_a_open = true;
            break;
        }
    }
    assert!(dc_a_open, "data channel should open on the controlling side");

    pc_a.send_data(dc_a.id, b"hello-over-host-path").await?;
    let mut echoed = false;
    let start = std::time::Instant::now();
    while start.elapsed() < Duration::from_secs(10) {
        if let Ok(Some(DataChannelEvent::Message(msg))) =
            timeout(Duration::from_millis(200), dc_b.recv()).await
        {
            assert_eq!(msg.as_ref(), b"hello-over-host-path");
            echoed = true;
            break;
        }
    }
    assert!(echoed, "data should be delivered over the data channel");

    pc_a.close();
    pc_b.close();
    Ok(())
}
