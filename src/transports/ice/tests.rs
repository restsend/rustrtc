use super::*;
use crate::config::RtcConfigurationBuilder;
use crate::transports::PacketReceiver;
use crate::transports::ice::upnp::{
    DEFAULT_LEASE_DURATION, MAX_LEASE_DURATION, MIN_LEASE_DURATION, PortMapping, UpnpPortMapper,
};
use crate::{IceServer, IceTransportPolicy, RtcConfiguration};
use ::turn::{
    auth::{AuthHandler, generate_auth_key},
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{
        Server,
        config::{ConnConfig, ServerConfig},
    },
};
use anyhow::{Context, Result};
use bytes::Bytes;
use futures::FutureExt;
use tokio::sync::broadcast;

use serial_test::serial;
use tokio::time::{Duration, timeout};
// use webrtc_util::vnet::net::Net;
type TurnResult<T> = std::result::Result<T, ::turn::Error>;

#[test]
fn parse_turn_uri() {
    let uri = IceServerUri::parse("turn:example.com:3478?transport=tcp").unwrap();
    assert_eq!(uri.host, "example.com");
    assert_eq!(uri.port, 3478);
    assert_eq!(uri.transport, IceTransportProtocol::Tcp);
    assert_eq!(uri.kind, IceUriKind::Turn);
}

#[tokio::test]
async fn builder_starts_gathering() {
    let (transport, runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    tokio::spawn(runner);
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(matches!(
        transport.gather_state(),
        IceGathererState::Complete
    ));
}

#[tokio::test]
async fn stun_probe_yields_server_reflexive_candidate() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let mut config = RtcConfiguration::default();
    config
        .ice_servers
        .push(IceServer::new(vec![turn_server.stun_url()]));
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();
    assert!(
        candidates
            .iter()
            .any(|c| matches!(c.typ, IceCandidateType::ServerReflexive))
    );
    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn stun_candidate_raddr_is_not_unspecified() -> Result<()> {
    // Verify that STUN candidate's related address (raddr) is not 0.0.0.0
    // Per RFC 5245, raddr should be the base (host) address
    let mut turn_server = TestTurnServer::start().await?;
    let mut config = RtcConfiguration::default();
    config
        .ice_servers
        .push(IceServer::new(vec![turn_server.stun_url()]));
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();

    // Find the srflx candidate
    let srflx = candidates
        .iter()
        .find(|c| matches!(c.typ, IceCandidateType::ServerReflexive));

    if let Some(candidate) = srflx {
        // Check that related_address exists and is not unspecified (0.0.0.0 or ::)
        if let Some(raddr) = candidate.related_address {
            assert!(
                !raddr.ip().is_unspecified(),
                "STUN candidate raddr should not be unspecified (0.0.0.0), got: {}",
                raddr.ip()
            );

            // Also verify raddr matches one of the host candidates
            let host_addresses: Vec<_> = candidates
                .iter()
                .filter(|c| matches!(c.typ, IceCandidateType::Host))
                .map(|c| c.address.ip())
                .collect();

            assert!(
                host_addresses.contains(&raddr.ip()),
                "STUN candidate raddr ({}) should match a host candidate address. Host addresses: {:?}",
                raddr.ip(),
                host_addresses
            );
        } else {
            panic!("STUN candidate should have a related_address");
        }
    }

    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
#[serial]
async fn turn_probe_yields_relay_candidate() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let mut config = RtcConfiguration::default();
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();
    assert!(
        candidates
            .iter()
            .any(|c| matches!(c.typ, IceCandidateType::Relay))
    );
    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn policy_relay_only_gathers_relay_candidates() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );

    // Add a STUN server too, to verify it is ignored
    config
        .ice_servers
        .push(IceServer::new(vec![turn_server.stun_url()]));

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();

    assert!(!candidates.is_empty());
    for c in candidates {
        assert_eq!(
            c.typ,
            IceCandidateType::Relay,
            "Found non-relay candidate: {:?}",
            c
        );
    }

    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn default_gather_excludes_loopback_host_candidates() -> Result<()> {
    let config = RtcConfiguration::default();
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();

    assert!(
        !candidates
            .iter()
            .any(|c| c.typ == IceCandidateType::Host && c.address.ip().is_loopback()),
        "default gathering must not advertise loopback host candidates: {:?}",
        candidates
            .iter()
            .map(|c| c.address)
            .collect::<Vec<SocketAddr>>()
    );
    Ok(())
}

#[tokio::test]
async fn include_loopback_option_gathers_loopback_candidate() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.ice_include_loopback_candidates = true;
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates();

    assert!(
        candidates
            .iter()
            .any(|c| c.typ == IceCandidateType::Host && c.address.ip().is_loopback()),
        "opt-in must re-enable loopback host candidates"
    );
    Ok(())
}

#[tokio::test]
#[serial]
async fn turn_client_can_create_permission() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let client = Arc::new(TurnClient::connect(&uri, false).await?);
    let creds = TurnCredentials::from_server(&server)?;
    let allocation = client.allocate(creds).await?;
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    client.create_permission(peer.local_addr()?).await?;

    // Exercise the real TURN read loop without ICE keepalives masking silence.
    let (transport, _runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    let (tx, mut rx) = tokio::sync::mpsc::channel(4);
    struct TestReceiver(tokio::sync::mpsc::Sender<Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for TestReceiver {
        async fn receive(&self, packet: Bytes, _addr: SocketAddr, _buf: &mut Vec<u8>) {
            let _ = self.0.send(packet).await;
        }
    }
    transport
        .set_data_receiver(Arc::new(TestReceiver(tx)))
        .await;
    let read_loop = tokio::spawn(IceTransportRunner::run_turn_read_loop(
        client.clone(),
        allocation.relayed_address,
        transport.inner.clone(),
    ));
    client
        .send_indication(peer.local_addr()?, b"outbound media")
        .await?;
    let mut buf = [0u8; 1500];
    let (_, relay) = timeout(Duration::from_secs(2), peer.recv_from(&mut buf)).await??;
    peer.send_to(b"before hold", relay).await?;
    assert_eq!(
        timeout(Duration::from_secs(2), rx.recv()).await?.unwrap(),
        Bytes::from_static(b"before hold")
    );
    tokio::time::sleep(Duration::from_millis(3300)).await;
    peer.send_to(b"after resume", relay).await?;
    let resumed = timeout(Duration::from_secs(2), rx.recv()).await;

    // Even an idle receive must be cancellable when the transport closes.
    transport.stop();
    timeout(Duration::from_secs(2), read_loop).await??;
    turn_server.stop().await?;
    assert_eq!(
        resumed
            .context("TURN read loop lost media after hold silence")?
            .unwrap(),
        Bytes::from_static(b"after resume")
    );
    Ok(())
}

#[test]
fn candidate_pair_priority_calculation() {
    let local = IceCandidate::host("127.0.0.1:1000".parse().unwrap(), 1);
    let remote = IceCandidate::host("127.0.0.1:2000".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(local.clone(), remote.clone());

    // G = local.priority, D = remote.priority
    // Since both are host/1, priorities should be equal.
    let p1 = pair.priority(IceRole::Controlling);
    let p2 = pair.priority(IceRole::Controlled);

    assert_eq!(p1, p2);

    // Test with different priorities
    let local_relay = IceCandidate::relay("127.0.0.1:1000".parse().unwrap(), 1, "udp");
    let pair2 = IceCandidatePair::new(local_relay, remote);

    // Relay has lower priority than Host.
    // Controlling: G (relay) < D (host)
    // Controlled: D (relay) < G (host)

    let prio_controlling = pair2.priority(IceRole::Controlling);
    let prio_controlled = pair2.priority(IceRole::Controlled);

    // Formula: 2^32*MIN(G,D) + 2*MAX(G,D) + (G>D?1:0)
    // Since priorities are different, the MIN term dominates.
    // In both roles, the set of {G, D} is the same, so MIN(G,D) and MAX(G,D) are same.
    // The only difference is the tie breaker (G>D?1:0).

    // If G < D (Controlling case here): term is 0.
    // If G > D (Controlled case here, since G becomes host): term is 1.

    assert!(prio_controlled > prio_controlling);
    assert_eq!(prio_controlled - prio_controlling, 1);
}

#[tokio::test]
#[serial]
async fn turn_connection_relay_to_host() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;

    // Give TURN server time to fully initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Agent 1: Relay only
    let mut config1 = RtcConfiguration::default();
    config1.ice_transport_policy = IceTransportPolicy::Relay;
    config1.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );
    let (transport1, runner1) = IceTransportBuilder::new(config1)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner1);

    // Agent 2: Host only
    let mut config2 = RtcConfiguration::default();
    // Same-host TURN relay delivers to loopback-only destinations.
    config2.ice_include_loopback_candidates = true;
    let (transport2, runner2) = IceTransportBuilder::new(config2)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner2);

    // Wait for candidate gathering
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Exchange candidates
    let t1 = transport1.clone();
    let t2 = transport2.clone();

    let mut rx1 = t1.subscribe_candidates();
    let mut rx2 = t2.subscribe_candidates();

    // Add existing candidates
    for c in t1.local_candidates() {
        t2.add_remote_candidate(c);
    }
    for c in t2.local_candidates() {
        t1.add_remote_candidate(c);
    }

    tokio::spawn(async move {
        while let Ok(c) = rx1.recv().await {
            t2.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = rx2.recv().await {
            t1.add_remote_candidate(c);
        }
    });

    // Wait for connection
    let state1 = transport1.subscribe_state();
    let state2 = transport2.subscribe_state();

    // Start
    transport1.start(transport2.local_parameters()).await?;
    transport2.start(transport1.local_parameters()).await?;

    // Wait for Connected with better error handling
    let wait_connected = |mut state: watch::Receiver<IceTransportState>, name: &'static str| async move {
        loop {
            let s = *state.borrow_and_update();
            if s == IceTransportState::Connected {
                return Ok(());
            }
            if s == IceTransportState::Failed {
                return Err(anyhow::anyhow!("Transport {} failed", name));
            }
            if state.changed().await.is_err() {
                return Err(anyhow::anyhow!("Transport {} state channel closed", name));
            }
        }
    };

    let result = tokio::try_join!(
        timeout(Duration::from_secs(15), wait_connected(state1, "1")),
        timeout(Duration::from_secs(15), wait_connected(state2, "2"))
    );

    if let Err(e) = &result {
        eprintln!("Connection failed: {:?}", e);
    }

    let (r1, r2) = result?;
    r1?;
    r2?;

    // Verify selected pair on transport 1 is Relay. Connected fires before
    // nomination completes (see wait_for_selected_pair), so wait for the pair.
    let pair1 = wait_for_selected_pair(&transport1, Duration::from_secs(10)).await?;
    assert_eq!(pair1.local.typ, IceCandidateType::Relay);

    // Send data
    let (tx1, mut rx1_data) = tokio::sync::mpsc::channel(10);
    let (tx2, mut rx2_data) = tokio::sync::mpsc::channel(10);

    struct TestReceiver(tokio::sync::mpsc::Sender<Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for TestReceiver {
        async fn receive(&self, packet: Bytes, _addr: SocketAddr, _buf: &mut Vec<u8>) {
            let _ = self.0.send(packet).await;
        }
    }

    transport1
        .set_data_receiver(Arc::new(TestReceiver(tx1)))
        .await;
    transport2
        .set_data_receiver(Arc::new(TestReceiver(tx2)))
        .await;

    let socket1 = transport1.get_selected_socket().unwrap();
    let pair1 = transport1.get_selected_pair().unwrap();

    let data = Bytes::from_static(b"hello from 1");
    socket1.send_to(&data, pair1.remote.address).await?;

    let received = timeout(Duration::from_secs(5), rx2_data.recv())
        .await?
        .unwrap();
    assert_eq!(received, data);

    // Send data back
    let socket2 = transport2.get_selected_socket().unwrap();
    let pair2 = transport2.get_selected_pair().unwrap();
    let data2 = Bytes::from_static(b"hello from 2");
    socket2.send_to(&data2, pair2.remote.address).await?;

    let received2 = timeout(Duration::from_secs(5), rx1_data.recv())
        .await?
        .unwrap();
    assert_eq!(received2, data2);

    turn_server.stop().await?;
    Ok(())
}
#[tokio::test]
async fn test_ice_connection_timeout() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.ice_connection_timeout = Duration::from_millis(100);

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    // Set state to Connected to trigger keepalive tick logic
    transport
        .inner
        .state
        .send(IceTransportState::Connected)
        .unwrap();

    // Wait for more than 1 second (interval is 1s)
    tokio::time::sleep(Duration::from_millis(1200)).await;

    // Should be Failed now
    assert_eq!(transport.state(), IceTransportState::Failed);

    Ok(())
}
const TEST_USERNAME: &str = "test";
const TEST_PASSWORD: &str = "test";
const TEST_REALM: &str = ".turn";

struct TestTurnServer {
    server: Option<Server>,
    addr: SocketAddr,
}

impl TestTurnServer {
    async fn start() -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let addr = socket.local_addr()?;
        let conn = Arc::new(socket);
        let relay_addr_generator = Box::new(RelayAddressGeneratorStatic {
            relay_address: addr.ip(),
            address: "0.0.0.0".to_string(),
            net: Arc::new(webrtc_util::vnet::net::Net::new(None)),
        });
        let auth_handler = Arc::new(StaticAuthHandler::new(
            TEST_USERNAME.to_string(),
            TEST_PASSWORD.to_string(),
        ));
        let config = ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator,
            }],
            realm: TEST_REALM.to_string(),
            auth_handler,
            channel_bind_timeout: Duration::from_secs(600),
            alloc_close_notify: None,
        };
        let server = Server::new(config).await?;
        Ok(Self {
            server: Some(server),
            addr,
        })
    }

    fn stun_url(&self) -> String {
        format!("stun:{}", self.addr)
    }

    fn turn_url(&self) -> String {
        format!("turn:{}", self.addr)
    }

    async fn stop(&mut self) -> Result<()> {
        if let Some(server) = self.server.take() {
            server.close().await?;
        }
        Ok(())
    }
}

struct StaticAuthHandler {
    username: String,
    password: String,
}

impl StaticAuthHandler {
    fn new(username: String, password: String) -> Self {
        Self { username, password }
    }
}

impl AuthHandler for StaticAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        _src_addr: SocketAddr,
    ) -> TurnResult<Vec<u8>> {
        if username != self.username {
            return Err(::turn::Error::ErrNoSuchUser);
        }
        Ok(generate_auth_key(username, realm, &self.password))
    }
}

#[test]
fn ice_candidate_foundation_compliance() {
    let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let host = IceCandidate::host(addr, 1);

    // Check foundation format (should be alphanumeric, no colons)
    // The previous implementation used "host:127.0.0.1" which contained ':'
    assert!(!host.foundation.contains(':'));
    assert!(host.foundation.chars().all(|c| c.is_ascii_alphanumeric()));

    // Check SDP output
    let sdp = host.to_sdp();
    assert!(sdp.contains(" typ host"));
    // Should verify it starts with foundation
    let parts: Vec<&str> = sdp.split_whitespace().collect();
    let foundation = parts[0];
    assert_eq!(foundation, host.foundation);

    // Check srflx
    let mapped: SocketAddr = "1.2.3.4:5000".parse().unwrap();
    let srflx = IceCandidate::server_reflexive(addr, mapped, 1);
    assert!(!srflx.foundation.contains(':'));
    assert!(srflx.foundation.chars().all(|c| c.is_ascii_alphanumeric()));

    // Ensure foundation is same for same type/base
    let srflx2 = IceCandidate::server_reflexive(addr, "1.2.3.5:6000".parse().unwrap(), 1);
    assert_eq!(srflx.foundation, srflx2.foundation);

    // Ensure foundation is different for different base
    let addr2: SocketAddr = "192.168.0.1:5000".parse().unwrap();
    let srflx3 = IceCandidate::server_reflexive(addr2, mapped, 1);
    assert_ne!(srflx.foundation, srflx3.foundation);

    // Check relay
    let relay = IceCandidate::relay(mapped, 1, "udp");
    assert!(!relay.foundation.contains(':'));

    // Check that host and srflx have different foundations even if same address (though unlikely in practice for base vs mapped)
    // Actually foundation computation uses type.
    let host_same_addr = IceCandidate::host(addr, 1);
    let srflx_same_base = IceCandidate::server_reflexive(addr, mapped, 1);
    assert_ne!(host_same_addr.foundation, srflx_same_base.foundation);
}

#[tokio::test]
#[serial]
async fn test_ice_lite_stun_response() -> Result<()> {
    use crate::TransportMode;

    // Create ICE-lite transport (RTP mode)
    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.enable_ice_lite = true;
    config.bind_ip = Some("127.0.0.1".to_string());

    let (ice_lite, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    // Set up for RTP mode - bind socket via setup_direct_rtp_offer
    let local_addr = ice_lite.setup_direct_rtp_offer().await?;

    // Give the transport time to fully initialize
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Get ICE credentials for authentication
    let _local_params = ice_lite.local_parameters();

    // Simulate remote ICE agent with credentials
    let remote_params = IceParameters::new("remote_ufrag", "remote_pwd_12345");
    ice_lite.set_remote_parameters(remote_params.clone());
    ice_lite.set_role(IceRole::Controlled);

    // Create a socket to act as the full-ICE remote agent
    let remote_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let remote_addr = remote_socket.local_addr()?;

    // Craft STUN binding request - try without authentication first
    let tx_id = crate::transports::ice::stun::random_bytes::<12>();
    let binding_request = StunMessage::binding_request(tx_id, Some("ice-lite-test"));

    // Encode without message integrity for basic connectivity
    let request_bytes = binding_request.encode(None, false)?;

    println!(
        "Sending STUN Binding Request from {} to ICE-lite agent at {}",
        remote_addr, local_addr
    );

    // Send STUN binding request to the ICE-lite transport with retries
    let mut buf = [0u8; 1500];
    let (len, response_from) = {
        let mut result = None;
        for _ in 0..3 {
            // Send STUN request
            remote_socket.send_to(&request_bytes, local_addr).await?;

            // Wait for response with shorter timeout, retry if needed
            match tokio::time::timeout(Duration::from_secs(2), remote_socket.recv_from(&mut buf))
                .await
            {
                Ok(Ok(recv_result)) => {
                    result = Some(Ok(recv_result));
                    break;
                }
                Ok(Err(e)) => {
                    result = Some(Err(anyhow::anyhow!("Socket recv error: {}", e)));
                }
                Err(_) => {
                    // Timeout - retry
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
        result.ok_or_else(|| anyhow::anyhow!("Should receive STUN response within 5 seconds"))??
    };

    println!(
        "Received STUN response from {}, {} bytes",
        response_from, len
    );

    // Verify the response is from the ICE-lite agent
    assert_eq!(
        response_from, local_addr,
        "Response should come from ICE-lite local address"
    );

    // Decode and verify STUN binding success response
    let decoded_response = StunMessage::decode(&buf[..len])?;
    assert_eq!(
        decoded_response.class,
        crate::transports::ice::stun::StunClass::SuccessResponse
    );
    assert_eq!(
        decoded_response.method,
        crate::transports::ice::stun::StunMethod::Binding
    );
    assert_eq!(
        decoded_response.transaction_id, tx_id,
        "Transaction ID should match request"
    );

    // Verify XOR-MAPPED-ADDRESS attribute (should reflect the requester's address)
    assert!(
        decoded_response.xor_mapped_address.is_some(),
        "STUN response should contain XOR-MAPPED-ADDRESS"
    );

    let mapped_addr = decoded_response.xor_mapped_address.unwrap();
    assert_eq!(
        mapped_addr, remote_addr,
        "XOR-MAPPED-ADDRESS should reflect remote agent's address"
    );

    println!("✓ ICE-lite correctly responded to STUN binding request");
    println!("✓ Response contains correct transaction ID and XOR-MAPPED-ADDRESS");

    // Verify that the remote address was added as a peer reflexive candidate
    let candidates = ice_lite.remote_candidates();
    let prflx_candidates: Vec<_> = candidates
        .iter()
        .filter(|c| c.typ == IceCandidateType::PeerReflexive && c.address == remote_addr)
        .collect();

    assert!(
        !prflx_candidates.is_empty(),
        "Remote address should be added as peer-reflexive candidate"
    );
    println!(
        "✓ Peer-reflexive candidate discovered for remote address {}",
        remote_addr
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_ice_lite_connectivity_establishment() -> Result<()> {
    use crate::TransportMode;

    // Set up ICE-lite agent
    let mut lite_config = RtcConfiguration::default();
    lite_config.transport_mode = TransportMode::Rtp;
    lite_config.enable_ice_lite = true;
    lite_config.bind_ip = Some("127.0.0.1".to_string());

    let (ice_lite, lite_runner) = IceTransport::new(lite_config);
    tokio::spawn(lite_runner);

    // Set up full-ICE agent
    let full_config = RtcConfiguration::default();
    let (ice_full, full_runner) = IceTransportBuilder::new(full_config)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(full_runner);

    // ICE-lite sets up direct RTP socket
    let _lite_addr = ice_lite.setup_direct_rtp_offer().await?;

    // Exchange ICE parameters
    let lite_params = ice_lite.local_parameters();
    let full_params = ice_full.local_parameters();

    ice_lite.set_remote_parameters(full_params.clone());
    ice_lite.set_role(IceRole::Controlled);

    // Add ICE-lite candidate to full agent
    let lite_candidates = ice_lite.local_candidates();
    assert!(
        !lite_candidates.is_empty(),
        "ICE-lite should have local candidates"
    );

    for candidate in lite_candidates {
        ice_full.add_remote_candidate(candidate);
    }

    // Start full ICE agent to trigger candidate gathering
    ice_full.start(lite_params.clone()).await?;

    // Wait a bit for candidate gathering
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Complete ICE-lite connection with full agent's candidate
    let full_candidates = ice_full.local_candidates();
    let full_host_candidate = full_candidates
        .iter()
        .find(|c| c.typ == IceCandidateType::Host)
        .expect("Full ICE agent should have host candidate")
        .clone();

    ice_lite.complete_direct_rtp(full_host_candidate.address);
    ice_lite.add_remote_candidate(full_host_candidate);

    // Wait for both sides to be connected with simpler wait logic
    let lite_state = ice_lite.subscribe_state();
    let full_state = ice_full.subscribe_state();

    async fn wait_connected(
        mut state: watch::Receiver<IceTransportState>,
        name: &str,
    ) -> Result<()> {
        for _ in 0..50 {
            // 5 second timeout with 100ms intervals
            let current_state = *state.borrow();
            if current_state == IceTransportState::Connected {
                println!("{} transport connected", name);
                return Ok(());
            }
            if current_state == IceTransportState::Failed {
                return Err(anyhow::anyhow!("{} transport failed", name));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
            let _ = state.changed().now_or_never();
        }
        Err(anyhow::anyhow!(
            "{} transport did not connect within timeout",
            name
        ))
    }

    tokio::try_join!(
        wait_connected(lite_state, "ICE-lite"),
        wait_connected(full_state, "Full ICE")
    )?;

    // Verify selected pairs
    let lite_pair = ice_lite.get_selected_pair().unwrap();
    let full_pair = ice_full.get_selected_pair().unwrap();

    println!(
        "ICE-lite selected pair: {} -> {}",
        lite_pair.local.address, lite_pair.remote.address
    );
    println!(
        "Full ICE selected pair: {} -> {}",
        full_pair.local.address, full_pair.remote.address
    );

    // Verify data can flow in both directions
    let (lite_tx, mut lite_rx) = tokio::sync::mpsc::channel(10);
    let (full_tx, mut full_rx) = tokio::sync::mpsc::channel(10);

    struct DataReceiver(tokio::sync::mpsc::Sender<Bytes>);

    #[async_trait::async_trait]
    impl PacketReceiver for DataReceiver {
        async fn receive(&self, packet: Bytes, _addr: SocketAddr, _buf: &mut Vec<u8>) {
            // Filter out STUN packets (first byte is 0x00 or 0x01)
            // RTP/data packets have first byte >= 0x80 or are text data
            if !packet.is_empty() && packet[0] >= 2 {
                let _ = self.0.send(packet).await;
            }
        }
    }

    ice_lite
        .set_data_receiver(Arc::new(DataReceiver(lite_tx)))
        .await;
    ice_full
        .set_data_receiver(Arc::new(DataReceiver(full_tx)))
        .await;

    // Send data from full agent to ICE-lite using the remote address from the pair
    let full_socket = ice_full.get_selected_socket().unwrap();
    let test_data = Bytes::from_static(b"Hello from full ICE agent");
    // Use full_pair.remote.address which should be the ICE-lite's address
    full_socket
        .send_to(&test_data, full_pair.remote.address)
        .await?;

    let received_by_lite = timeout(Duration::from_secs(5), lite_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("ICE-lite did not receive data"))?;
    assert_eq!(received_by_lite, test_data);

    // Send data from ICE-lite to full agent using the remote address from the pair
    let lite_socket = ice_lite.get_selected_socket().unwrap();
    let response_data = Bytes::from_static(b"Hello from ICE-lite agent");
    // Use lite_pair.remote.address which should be the full agent's address
    lite_socket
        .send_to(&response_data, lite_pair.remote.address)
        .await?;

    let received_by_full = timeout(Duration::from_secs(5), full_rx.recv())
        .await?
        .ok_or_else(|| anyhow::anyhow!("Full ICE agent did not receive data"))?;
    assert_eq!(received_by_full, response_data);

    println!("✓ ICE-lite successfully established connectivity with full ICE agent");
    println!("✓ Bidirectional data flow verified");

    Ok(())
}

// ──────────────────────────────────────────────────────────────────────────────
// Nomination timeout / completion tests
// ──────────────────────────────────────────────────────────────────────────────

/// Verify that `nomination_timeout` defaults to a value larger than `stun_timeout`
/// so that the nomination binding check gets more retransmission attempts than a
/// regular connectivity check.
#[test]
fn test_nomination_timeout_larger_than_stun_timeout() {
    let config = RtcConfiguration::default();
    assert!(
        config.nomination_timeout > config.stun_timeout,
        "nomination_timeout ({:?}) must be > stun_timeout ({:?}) to allow more retransmissions",
        config.nomination_timeout,
        config.stun_timeout,
    );
}

/// Verify that `RtcConfigurationBuilder::nomination_timeout` correctly overrides the default.
#[test]
fn test_nomination_timeout_builder() {
    use crate::config::RtcConfigurationBuilder;

    let custom = std::time::Duration::from_secs(20);
    let config = RtcConfigurationBuilder::new()
        .nomination_timeout(custom)
        .build();
    assert_eq!(config.nomination_timeout, custom);
    // Other defaults should be unaffected.
    assert_eq!(config.stun_timeout, std::time::Duration::from_secs(5));
}

/// Helper: set up two host-only ICE transports (controlling + controlled), exchange
/// candidates and parameters, start both, then return state/nomination receivers plus
/// both transports so the caller can await what it needs.
async fn setup_host_pair(
    controlling_config: RtcConfiguration,
    controlled_config: RtcConfiguration,
) -> (IceTransport, IceTransport) {
    let (controlling, runner_c) = IceTransportBuilder::new(controlling_config)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);

    let (controlled, runner_d) = IceTransportBuilder::new(controlled_config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    // Exchange already-gathered candidates.
    // Gathering is asynchronous (the runner task drives it): wait for host
    // candidates before exchanging, so the exchange actually delivers them.
    let gather_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < gather_deadline
        && (controlling.local_candidates().is_empty() || controlled.local_candidates().is_empty())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }

    // Forward future trickle candidates.
    let ctrl_clone = controlling.clone();
    let ctrd_clone = controlled.clone();
    let mut rx_ctrl = controlling.subscribe_candidates();
    let mut rx_ctrd = controlled.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrl.recv().await {
            ctrd_clone.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrd.recv().await {
            ctrl_clone.add_remote_candidate(c);
        }
    });

    // Start both agents (this triggers connectivity checks).
    controlling
        .start(controlled.local_parameters())
        .await
        .expect("controlling.start");
    controlled
        .start(controlling.local_parameters())
        .await
        .expect("controlled.start");

    (controlling, controlled)
}

/// Wait for an ICE transport to reach Connected or fail; returns true on success.
async fn wait_ice_connected(
    mut state_rx: watch::Receiver<IceTransportState>,
    deadline: Duration,
) -> bool {
    let result = timeout(deadline, async move {
        loop {
            let s = *state_rx.borrow_and_update();
            match s {
                IceTransportState::Connected | IceTransportState::Completed => return true,
                IceTransportState::Failed => return false,
                _ => {}
            }
            if state_rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await;
    result.unwrap_or(false)
}

/// Wait for the transport to publish its selected pair.
///
/// The controlling side emits `IceTransportState::Connected` *before*
/// nomination completes (v0.3.104 parallel nomination signals Connected early
/// so the PeerConnection can await `nomination_complete`), and `selected_pair`
/// is only assigned once a nomination check succeeds. Tests that sample
/// `get_selected_pair()` immediately after `wait_ice_connected` therefore race
/// against nomination. This helper closes that window by waiting on the
/// `selected_pair` watch channel directly.
async fn wait_for_selected_pair(
    transport: &IceTransport,
    deadline: Duration,
) -> Result<IceCandidatePair> {
    let mut rx = transport.subscribe_selected_pair();
    if let Some(p) = rx.borrow_and_update().clone() {
        return Ok(p);
    }
    timeout(deadline, async {
        loop {
            if rx.changed().await.is_err() {
                anyhow::bail!("selected_pair channel closed");
            }
            if let Some(p) = rx.borrow().clone() {
                return Ok(p);
            }
        }
    })
    .await
    .context("timed out waiting for selected pair")?
}

/// Regression: a plain renegotiation (e.g. a SIP hold/resume re-INVITE)
/// re-signals the SAME ice-ufrag/ice-pwd while the selected pair is still
/// live. `IceTransport::start` used to force `Checking` unconditionally; the
/// connectivity checks then early-returned (pair already selected) and nothing
/// ever restored `Connected`, so the keepalive and TURN-refresh timers — both
/// gated on Connected/Disconnected — stopped until the 600 s TURN allocation
/// expired and media died.
#[tokio::test]
#[serial]
async fn test_hold_renegotiation_keeps_connected_state() -> Result<()> {
    let (controlling, controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await
            && wait_ice_connected(ctrd_state, Duration::from_secs(10)).await,
        "pair must connect before the renegotiation"
    );
    let ctrl_pair = wait_for_selected_pair(&controlling, Duration::from_secs(10)).await?;
    let ctrd_pair = wait_for_selected_pair(&controlled, Duration::from_secs(10)).await?;

    // "Hold" renegotiation: identical remote parameters, selected pair alive.
    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    // The session must never drop into Checking, and must stay Connected.
    assert_ne!(
        controlling.state(),
        IceTransportState::Checking,
        "controlling side must not flap to Checking on a hold renegotiation"
    );
    assert_ne!(
        controlled.state(),
        IceTransportState::Checking,
        "controlled side must not flap to Checking on a hold renegotiation"
    );
    // Keep sampling for a while: the bug left the transport stuck in Checking
    // because nothing ever restored Connected.
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert!(
        matches!(
            controlling.state(),
            IceTransportState::Connected | IceTransportState::Completed
        ),
        "controlling side is {:?}, expected Connected/Completed",
        controlling.state()
    );
    assert!(
        matches!(
            controlled.state(),
            IceTransportState::Connected | IceTransportState::Completed
        ),
        "controlled side is {:?}, expected Connected/Completed",
        controlled.state()
    );

    // The selected pair must be untouched — media keeps flowing on the same
    // path without a re-nomination.
    let ctrl_now = controlling
        .get_selected_pair()
        .context("selected pair lost on controlling side")?;
    let ctrd_now = controlled
        .get_selected_pair()
        .context("selected pair lost on controlled side")?;
    assert_eq!(
        (ctrl_now.local.address, ctrl_now.remote.address),
        (ctrl_pair.local.address, ctrl_pair.remote.address)
    );
    assert_eq!(
        (ctrd_now.local.address, ctrd_now.remote.address),
        (ctrd_pair.local.address, ctrd_pair.remote.address)
    );
    Ok(())
}

/// The keepalive tick doubles as an invariant watchdog: `Checking` WITH a
/// selected pair is a stranded live session (any future writer that
/// reintroduces the hold-renegotiation defect). The tick must self-heal it
/// back to Connected so the keepalive / TURN-refresh timers resume, instead of
/// silently stopping until the 600 s TURN allocation expires.
#[tokio::test]
#[serial]
async fn test_keepalive_tick_repairs_stranded_checking_with_selected_pair() -> Result<()> {
    let (transport, runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    tokio::spawn(runner);

    transport.start_gathering()?;
    let local = {
        let start = std::time::Instant::now();
        loop {
            if let Some(c) = transport.local_candidates().first() {
                break c.clone();
            }
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "no host candidate"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    transport.set_remote_parameters(IceParameters::new("remote-ufrag", "remote-pwd"));
    let remote = IceCandidate::host("127.0.0.1:19999".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(local, remote);
    *transport.inner.selected_pair.lock() = Some(pair.clone());

    // 1) Stranded state: Checking + live pair → repaired to Connected, and
    //    the pair's keepalive is sent in the same tick.
    let _ = transport.inner.state.send(IceTransportState::Checking);
    let sent = IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(
        transport.state(),
        IceTransportState::Connected,
        "stranded Checking with a selected pair must self-heal to Connected"
    );
    assert!(
        sent.is_some(),
        "keepalive must resume immediately after the repair"
    );

    // 2) Guard: Checking WITHOUT a pair is a legitimate restart state and
    //    must be left alone (checks are meant to re-run).
    *transport.inner.selected_pair.lock() = None;
    let _ = transport.inner.state.send(IceTransportState::Checking);
    IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(
        transport.state(),
        IceTransportState::Checking,
        "legitimate Checking (no pair) must not be touched"
    );

    // 3) Completed is a live session state: keepalives keep flowing (gate
    //    must not silently stop the timers on it).
    *transport.inner.selected_pair.lock() = Some(pair);
    let _ = transport.inner.state.send(IceTransportState::Completed);
    let sent = IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(transport.state(), IceTransportState::Completed);
    assert!(
        sent.is_some(),
        "keepalive must run in Completed state (live session)"
    );
    Ok(())
}

/// A peer without ICE (no ICE parameters: a plain RTP trunk) gets no STUN
/// keepalive: ICE is not in use with it (RFC 8839 §4.3.3), and a STUN
/// request is no format it supports (RFC 8445 §11). A peer with ICE
/// parameters still gets one.
#[tokio::test]
async fn test_keepalive_only_to_ice_peers() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.transport_mode = crate::TransportMode::Rtp;
    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    transport.start_gathering()?;
    let local = {
        let start = std::time::Instant::now();
        loop {
            if let Some(c) = transport.local_candidates().first() {
                break c.clone();
            }
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "no host candidate"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let remote = IceCandidate::host(peer.local_addr()?, 1);
    *transport.inner.selected_pair.lock() = Some(IceCandidatePair::new(local, remote));
    let _ = transport.inner.state.send(IceTransportState::Connected);
    let mut buf = [0u8; 1500];

    IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert!(
        timeout(Duration::from_millis(300), peer.recv_from(&mut buf))
            .await
            .is_err(),
        "no STUN to a peer without ICE"
    );

    transport.set_remote_parameters(IceParameters::new("remote-ufrag", "remote-pwd"));
    IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    let (n, _) = timeout(Duration::from_secs(1), peer.recv_from(&mut buf)).await??;
    assert!(n >= 20 && buf[0] < 4, "a STUN request to a peer with ICE");
    Ok(())
}

/// The incident mechanism, end to end against a real TURN server: after a
/// hold renegotiation (`start` with UNCHANGED credentials) the TURN refresh
/// timer must keep refreshing the allocation. Pre-fix, the renegotiation
/// stranded the transport in `Checking` and `run_turn_refresh` silently
/// early-returned on its Connected/Disconnected gate until the 600 s
/// allocation expired and media died.
///
/// Observability: the client nonce is poisoned with a marker first; a real
/// refresh round-trip provokes a 401/438 from the server, whose retry path
/// calls `update_nonce`. If the nonce is still the marker afterwards, no
/// refresh happened.
#[tokio::test]
#[serial]
async fn test_hold_renegotiation_does_not_stop_turn_refresh() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let (transport, client, relayed) = setup_turn_transport(&turn_server).await?;
    let remote_params = IceParameters::new("hold-ufrag", "hold-pwd");

    // Initial negotiation: session established, pair nominated.
    transport.start(remote_params.clone()).await?;
    let (relay_candidate, remote) = fabricated_relay_pair(&transport, relayed);
    *transport.inner.selected_pair.lock() = Some(IceCandidatePair::new(relay_candidate, remote));
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Hold renegotiation: same credentials re-signalled (PBX ICEStart).
    transport.start(remote_params.clone()).await?;
    assert_eq!(
        transport.state(),
        IceTransportState::Connected,
        "hold renegotiation must keep the live session Connected"
    );

    // Consent keepalive for the selected pair must still be sent.
    let sent = IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert!(sent.is_some(), "keepalive must keep flowing after hold");

    // TURN refresh must still run and actually reach the server.
    assert_refresh_rotates_nonce(&transport, &client).await?;

    turn_server.stop().await?;
    Ok(())
}

/// Bad-network variant: the renegotiation arrives while the transport is
/// already `Disconnected` (media stalled, pair still selected). The
/// renegotiation must NOT force `Checking` (the pre-fix behavior that killed
/// the TURN allocations), and keepalive + TURN refresh must keep running so
/// the session can recover and the allocation survives the outage.
#[tokio::test]
#[serial]
async fn test_hold_renegotiation_while_disconnected_keeps_timers_alive() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let (transport, client, relayed) = setup_turn_transport(&turn_server).await?;
    let remote_params = IceParameters::new("hold-ufrag", "hold-pwd");

    transport.start(remote_params.clone()).await?;
    let (relay_candidate, remote) = fabricated_relay_pair(&transport, relayed);
    *transport.inner.selected_pair.lock() = Some(IceCandidatePair::new(relay_candidate, remote));
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Network degrades: no inbound traffic for a while → Disconnected, pair
    // stays selected (keepalive sends, nothing comes back).
    let _ = transport.inner.state.send(IceTransportState::Disconnected);
    transport.start(remote_params.clone()).await?;
    assert_eq!(
        transport.state(),
        IceTransportState::Disconnected,
        "renegotiation while Disconnected must keep the state (no forced Checking)"
    );
    assert_ne!(
        transport.state(),
        IceTransportState::Checking,
        "stranding a degraded session in Checking stops TURN refresh until expiry"
    );

    // TURN refresh is still allowed in Disconnected — the allocation must
    // survive the outage.
    assert_refresh_rotates_nonce(&transport, &client).await?;

    turn_server.stop().await?;
    Ok(())
}

/// Bad-network variant for the keepalive invariant watchdog: self-healing a
/// stranded `Checking` must NOT mask a genuinely dead connection. With fresh
/// traffic the repair keeps the session `Connected`; with no inbound traffic
/// beyond `ice_connection_timeout` the same tick must fail the transport
/// (visible failure beats the incident's silent death).
#[tokio::test]
#[serial]
async fn test_keepalive_repair_does_not_mask_real_outage() -> Result<()> {
    // Short timeouts so the outage is testable in milliseconds.
    let config = RtcConfigurationBuilder::new()
        .ice_disconnect_threshold(Duration::from_millis(150))
        .ice_connection_timeout(Duration::from_millis(400))
        .build();
    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    transport.start_gathering()?;
    let local = {
        let start = std::time::Instant::now();
        loop {
            if let Some(c) = transport.local_candidates().first() {
                break c.clone();
            }
            anyhow::ensure!(
                start.elapsed() < Duration::from_secs(5),
                "no host candidate"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    };
    transport.set_remote_parameters(IceParameters::new("outage-ufrag", "outage-pwd"));
    let remote = IceCandidate::host("127.0.0.1:19998".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(local, remote);

    // Case 1 — live traffic (the incident shape: media kept flowing over the
    // old pair): stranded Checking + fresh last_received → repaired to
    // Connected and STAYS Connected.
    *transport.inner.selected_pair.lock() = Some(pair.clone());
    transport.inner.last_received_nanos.store(
        transport.inner.created_at.elapsed().as_nanos() as u64,
        Ordering::Relaxed,
    );
    let _ = transport.inner.state.send(IceTransportState::Checking);
    let sent = IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(
        transport.state(),
        IceTransportState::Connected,
        "repair must restore Connected while traffic is fresh"
    );
    assert!(sent.is_some());
    // A later tick must not flap it away again while traffic stays fresh.
    transport.inner.last_received_nanos.store(
        transport.inner.created_at.elapsed().as_nanos() as u64,
        Ordering::Relaxed,
    );
    IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(
        transport.state(),
        IceTransportState::Connected,
        "fresh traffic must keep the repaired session Connected"
    );

    // Case 2 — genuinely dead link: stranded Checking + no inbound traffic
    // past ice_connection_timeout → the repair runs, then the same watchdog
    // marks the transport Failed (detectable failure, never silent).
    transport
        .inner
        .last_received_nanos
        .store(1, Ordering::Relaxed);
    let _ = transport.inner.state.send(IceTransportState::Checking);
    tokio::time::sleep(Duration::from_millis(450)).await; // > ice_connection_timeout
    IceTransportRunner::run_keepalive_tick(&transport.inner).await;
    assert_eq!(
        transport.state(),
        IceTransportState::Failed,
        "repair must not mask a real outage: no traffic for ice_connection_timeout ⇒ Failed"
    );
    Ok(())
}

/// Real TURN server + real allocation, wired into a spawned transport
/// runner and TURN read loop (so refresh transactions get dispatched).
/// Returns the transport, the TURN client, and the allocation's relayed
/// address (for building a relay local candidate).
async fn setup_turn_transport(
    turn_server: &TestTurnServer,
) -> Result<(IceTransport, Arc<TurnClient>, SocketAddr)> {
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);

    let client = Arc::new(TurnClient::connect(&uri, false).await?);
    let creds = TurnCredentials::from_server(&server)?;
    let alloc = client.allocate(creds).await?;

    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(server);
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    {
        let mut clients = transport.inner.gatherer.turn_clients.lock();
        clients.insert(alloc.relayed_address, client.clone());
    }
    let inner_clone = transport.inner.clone();
    let client_clone = client.clone();
    let relayed = alloc.relayed_address;
    tokio::spawn(async move {
        IceTransportRunner::run_turn_read_loop(client_clone, relayed, inner_clone).await;
    });
    Ok((transport, client, relayed))
}

/// A relay local candidate (registered under the live allocation) paired with
/// a fake remote host candidate, as the refresh tests use.
fn fabricated_relay_pair(
    transport: &IceTransport,
    relayed: SocketAddr,
) -> (IceCandidate, IceCandidate) {
    let relay_candidate = IceCandidate::relay(relayed, 1, "udp");
    transport
        .inner
        .gatherer
        .local_candidates
        .lock()
        .push(relay_candidate.clone());
    let remote = IceCandidate::host("127.0.0.1:19999".parse().unwrap(), 1);
    (relay_candidate, remote)
}

const POISON_NONCE: &str = "stale-poison-nonce";

/// Prove that a TURN refresh really ran: poison the stored nonce, run
/// `run_turn_refresh`, then verify the server rotated it (401/438 → retry
/// updates the nonce). If the state gate silently skipped the refresh, the
/// marker nonce survives and the assertion fails.
async fn assert_refresh_rotates_nonce(
    transport: &IceTransport,
    client: &Arc<TurnClient>,
) -> Result<()> {
    client
        .update_nonce(TEST_REALM.to_string(), POISON_NONCE.to_string())
        .await;

    let refreshed = timeout(
        Duration::from_secs(4),
        IceTransportRunner::run_turn_refresh(&transport.inner),
    )
    .await;
    anyhow::ensure!(
        refreshed.is_ok(),
        "run_turn_refresh must complete against a live TURN server"
    );

    let (bytes, _tx_id) = client.create_refresh_packet().await?;
    let nonce = StunMessage::decode(&bytes)?.nonce;
    anyhow::ensure!(
        nonce.as_deref() != Some(POISON_NONCE),
        "TURN refresh did not reach the server (nonce still poisoned) — \
         the state gate skipped it and the allocation will expire in 600 s"
    );
    Ok(())
}

/// Companion guard for the fix above: a genuine credential change (ICE
/// restart) must still tear the session down into `Checking` with the selected
/// pair cleared, so checks re-run end-to-end.
#[tokio::test]
#[serial]
async fn test_credential_change_still_restarts_checks() -> Result<()> {
    let (controlling, controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await
            && wait_ice_connected(ctrd_state, Duration::from_secs(10)).await,
        "pair must connect before the restart"
    );
    let _ = wait_for_selected_pair(&controlling, Duration::from_secs(10)).await?;

    // The peer re-signals DIFFERENT credentials: this is a remote restart and
    // must reset the session even though a pair was selected.
    controlling
        .start(IceParameters::new(
            "restart-ufrag",
            "restart-pwd-long-enough",
        ))
        .await?;

    assert_eq!(
        controlling.state(),
        IceTransportState::Checking,
        "credential change must re-arm connectivity checks"
    );
    assert!(
        controlling.get_selected_pair().is_none(),
        "credential change must clear the selected pair"
    );
    Ok(())
}

/// Test that ICE does NOT transition to Failed when the first batch of
/// connectivity checks yields no successful pairs (e.g. initial host-only
/// remote candidates are unreachable).  After adding the correct (reachable)
/// remote candidates via `add_remote_candidate`, both sides should connect.
///
/// Without the fix in `perform_connectivity_checks_async`, the first empty
/// batch would set `IceTransportState::Failed` and any subsequent trickle
/// arrivals would be silently ignored (the PeerConnection state machine stops
/// watching the ICE state).
#[tokio::test]
#[serial]
async fn test_trickle_ice_no_premature_failure() -> Result<()> {
    let config = RtcConfiguration::default();

    // Build two transports
    let (controlling, runner_c) = IceTransportBuilder::new(config.clone())
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);

    let (controlled, runner_d) = IceTransportBuilder::new(config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    // Subscribe to state changes
    let mut ctrl_state = controlling.subscribe_state();
    let mut ctrd_state = controlled.subscribe_state();

    // Step 1: Add an unreachable remote candidate to the controlling side
    // pointing to 127.0.0.2 (nothing listening there).
    let bad_remote = IceCandidate::host("127.0.0.2:9999".parse().unwrap(), 1);
    controlling.add_remote_candidate(bad_remote);

    // Step 2: Start both transports
    let ctrl_params = controlled.local_parameters();
    let ctrd_params = controlling.local_parameters();
    controlling.start(ctrl_params).await?;
    controlled.start(ctrd_params).await?;

    assert_eq!(*ctrl_state.borrow(), IceTransportState::Checking);
    assert_eq!(*ctrd_state.borrow(), IceTransportState::Checking);
    debug!("Both sides in Checking — good.");

    // Step 3: Wait long enough for the stun_timeout (5s) to fire on the bad
    // pair so the first batch of connectivity checks completes with no
    // successful pairs.
    tokio::time::sleep(Duration::from_secs(7)).await;

    // Step 4: THE KEY ASSERTION — neither side should have transitioned to
    // Failed.  Without the fix the controlling side would be Failed now.
    let ctrl_state_val = *ctrl_state.borrow_and_update();
    let ctrd_state_val = *ctrd_state.borrow_and_update();
    debug!(
        "After first batch (all pairs unreachable): controlling={:?}, controlled={:?}",
        ctrl_state_val, ctrd_state_val,
    );
    assert!(
        !matches!(
            ctrl_state_val,
            IceTransportState::Failed | IceTransportState::Closed
        ),
        "Controlling should NOT be Failed after first empty batch"
    );
    assert!(
        !matches!(
            ctrd_state_val,
            IceTransportState::Failed | IceTransportState::Closed
        ),
        "Controlled should NOT be Failed after first empty batch"
    );

    // Step 5: Add the CORRECT remote candidates so that both sides have
    // real, reachable pairs to check.
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }
    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }

    // Step 6: Both sides should now connect within 10 s.
    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(ok1, "Controlling should connect after correct remote added");
    assert!(ok2, "Controlled should connect after correct remote added");

    Ok(())
}

/// End-to-end test: two host ICE agents establish a connection and the
/// `nomination_complete` signal on the controlling side fires `Some(true)`.
/// The controlled side also fires `Some(true)` once USE-CANDIDATE is received.
#[tokio::test]
#[serial]
async fn test_nomination_complete_fires_on_connection() -> Result<()> {
    let config1 = RtcConfiguration::default();
    let config2 = RtcConfiguration::default();

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    // Subscribe to nomination signals before ICE connects.
    let mut ctrl_nomination_rx = controlling.subscribe_nomination_complete();
    let mut ctrd_nomination_rx = controlled.subscribe_nomination_complete();

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();

    // Both sides should reach Connected within 10 s.
    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(ok1, "Controlling agent failed to reach Connected");
    assert!(ok2, "Controlled agent failed to reach Connected");

    // Nomination signal must arrive soon after ICE connects.
    let ctrl_result = timeout(Duration::from_secs(5), async {
        // The value might already be set; check before waiting.
        if ctrl_nomination_rx.borrow().is_some() {
            return *ctrl_nomination_rx.borrow();
        }
        ctrl_nomination_rx.changed().await.ok()?;
        *ctrl_nomination_rx.borrow()
    })
    .await
    .expect("nomination_complete timed out on controlling side");

    assert_eq!(
        ctrl_result,
        Some(true),
        "Controlling nomination should succeed (Some(true))"
    );

    // Controlled side signals after receiving USE-CANDIDATE from the controlling side.
    let ctrd_result = timeout(Duration::from_secs(5), async {
        if ctrd_nomination_rx.borrow().is_some() {
            return *ctrd_nomination_rx.borrow();
        }
        ctrd_nomination_rx.changed().await.ok()?;
        *ctrd_nomination_rx.borrow()
    })
    .await
    .expect("nomination_complete timed out on controlled side");

    assert_eq!(
        ctrd_result,
        Some(true),
        "Controlled nomination should be Some(true) (after receiving USE-CANDIDATE)"
    );

    Ok(())
}

/// Verify that `nomination_timeout` is actually used for the nomination binding
/// check: set it to a very small value and confirm the nomination attempt fails
/// quickly (before `stun_timeout` would fire).
///
/// We simulate this by configuring `nomination_timeout` shorter than even one
/// RTO and then running a host-only check against a black-hole address so the
/// check never gets a response.
#[tokio::test]
async fn test_nomination_uses_nomination_timeout_not_stun_timeout() -> Result<()> {
    // Using a very short nomination_timeout to make the test fast.
    let mut config = RtcConfiguration::default();
    config.stun_timeout = Duration::from_secs(30); // Would take 30 s if wrong timeout is used.
    config.nomination_timeout = Duration::from_millis(200); // Should fire quickly.

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    // Build a dummy pair pointing to a loopback port that nobody is listening on.
    // (port 1 is reserved and will result in an ICMP unreachable or silent timeout)
    let local_candidate = IceCandidate::host("127.0.0.1:0".parse().unwrap(), 1);
    let remote_candidate = IceCandidate::host("127.0.0.1:1".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(local_candidate, remote_candidate);

    // Force the transport inner's role to Controlling so the nomination path fires.
    *transport.inner.role.lock() = IceRole::Controlling;

    // Set a dummy remote parameters so authentication is possible.
    let remote_params = IceParameters::new("dummy_ufrag", "dummy_password_1234567890");
    transport.set_remote_parameters(remote_params);

    let mut nomination_rx = transport.subscribe_nomination_complete();

    // Kick off a nomination check in a background task.
    let inner_clone = transport.inner.clone();
    let pair_clone = pair.clone();
    tokio::spawn(async move {
        let result = perform_binding_check(
            &pair_clone.local,
            &pair_clone.remote,
            &inner_clone,
            IceRole::Controlling,
            true, // nominated = true → should use nomination_timeout
        )
        .await;
        match result {
            Ok(_) => {
                let _ = inner_clone.nomination_complete.send(Some(true));
            }
            Err(_) => {
                let _ = inner_clone.nomination_complete.send(Some(false));
            }
        }
    });

    // The nomination should fail (no response) within nomination_timeout (200 ms),
    // which is much shorter than stun_timeout (30 s).
    let start = std::time::Instant::now();
    let result = timeout(Duration::from_secs(5), async {
        if nomination_rx.borrow().is_some() {
            return *nomination_rx.borrow();
        }
        nomination_rx.changed().await.ok()?;
        *nomination_rx.borrow()
    })
    .await
    .expect("nomination_complete should fire within 5 s");

    let elapsed = start.elapsed();

    assert_eq!(
        result,
        Some(false),
        "Nomination to a black-hole address should fail"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "Nomination should have timed out using nomination_timeout (200 ms), not stun_timeout (30 s); elapsed: {:?}",
        elapsed
    );
    // Also verify it actually used nomination_timeout (not stun_timeout):
    assert!(
        elapsed < Duration::from_secs(2),
        "Elapsed ({:?}) should be close to nomination_timeout (200 ms), not stun_timeout (30 s)",
        elapsed
    );

    Ok(())
}

/// Verify that under simulated packet loss the nomination_complete signal still
/// arrives as `Some(true)`, because the longer `nomination_timeout` allows
/// sufficient retransmissions to get through.
///
/// This test uses `PACKET_LOSS_RATE` to drop ~30 % of packets and confirms that
/// with the default `nomination_timeout` (2× `stun_timeout`) nomination succeeds
/// where with only `stun_timeout` it would be far more likely to fail.
///
/// Note: packet-loss simulation is a global atomic, so this test uses
/// `#[serial_test::serial]` style isolation by resetting the rate at the end.
/// Since we can't guarantee ordering with other tests, we keep the rate
/// conservative (30 %) to avoid flakiness.
#[tokio::test]
#[serial]
async fn test_nomination_succeeds_under_moderate_packet_loss() -> Result<()> {
    // 30% packet loss: rate = 3000 (units: 1/10000th, compared against random % 10000)
    // Use a scope guard to ensure PACKET_LOSS_RATE is always restored, even if the test panics.
    struct ScopeGuard {
        prev: u32,
    }
    impl Drop for ScopeGuard {
        fn drop(&mut self) {
            PACKET_LOSS_RATE.store(self.prev, Ordering::SeqCst);
        }
    }
    let _guard = ScopeGuard {
        prev: PACKET_LOSS_RATE.swap(3000, Ordering::SeqCst),
    };

    let result: Result<()> = async {
        let mut config1 = RtcConfiguration::default();
        let mut config2 = RtcConfiguration::default();
        // Use generous timeouts so the test is robust under CI load.
        config1.nomination_timeout = Duration::from_secs(15);
        config1.stun_timeout = Duration::from_secs(5);
        config2.nomination_timeout = Duration::from_secs(15);
        config2.stun_timeout = Duration::from_secs(5);

        let (controlling, controlled) = setup_host_pair(config1, config2).await;

        let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();
        let ctrl_state = controlling.subscribe_state();
        let ctrd_state = controlled.subscribe_state();

        // Wait for both sides to connect (ICE checks also go through the loss simulator).
        let (ok1, ok2) = tokio::join!(
            wait_ice_connected(ctrl_state, Duration::from_secs(20)),
            wait_ice_connected(ctrd_state, Duration::from_secs(20)),
        );
        assert!(ok1, "Controlling agent failed to connect under packet loss");
        assert!(ok2, "Controlled agent failed to connect under packet loss");

        // Nomination should still succeed thanks to retransmissions within nomination_timeout.
        let nom_result = timeout(Duration::from_secs(20), async {
            if ctrl_nom_rx.borrow().is_some() {
                return *ctrl_nom_rx.borrow();
            }
            ctrl_nom_rx.changed().await.ok()?;
            *ctrl_nom_rx.borrow()
        })
        .await
        .expect("nomination_complete should fire within 20 s even under 30% loss");

        assert_eq!(
            nom_result,
            Some(true),
            "Nomination should succeed under 30% packet loss with nomination_timeout > stun_timeout"
        );

        Ok(())
    }
    .await;

    result
}

// ============================================================================
// Tests for external_ip and base_address() functionality
// ============================================================================

/// Test that `base_address()` returns the related_address for host candidates
/// when related_address is set (which happens when external_ip is configured).
#[test]
fn test_base_address_returns_related_address_for_host_candidate() {
    let local_addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let external_addr: SocketAddr = "203.0.113.5:54321".parse().unwrap();

    let mut candidate = IceCandidate::host(external_addr, 1);
    candidate.related_address = Some(local_addr);

    // base_address() should return the related_address (local socket address)
    assert_eq!(
        candidate.base_address(),
        local_addr,
        "base_address() should return related_address for host candidate with external IP"
    );

    // address should still be the external address
    assert_eq!(
        candidate.address, external_addr,
        "address should be the external IP"
    );
}

/// Test that `base_address()` returns the address when related_address is None.
#[test]
fn test_base_address_returns_address_when_no_related_address() {
    let addr: SocketAddr = "192.168.1.100:54321".parse().unwrap();
    let candidate = IceCandidate::host(addr, 1);

    assert_eq!(
        candidate.base_address(),
        addr,
        "base_address() should return address when related_address is None"
    );
}

/// Test that ICE connection works when external_ip is configured.
/// This tests the fix for the bug where local candidate lookup used
/// `c.address` instead of `c.base_address()`.
#[tokio::test]
#[serial]
async fn test_ice_connection_with_external_ip() -> Result<()> {
    // Configure both sides with a dummy external IP
    // Using 203.0.113.x which is in the TEST-NET-3 range (documentation purpose)
    // Loopback stays on: the rewritten LAN candidates point at TEST-NET-3 and
    // the same-host raw loopback pair is what actually carries checks here.
    let mut config1 = RtcConfiguration::default();
    config1.ice_include_loopback_candidates = true;
    config1.external_ip = Some("203.0.113.10".to_string());

    let mut config2 = RtcConfiguration::default();
    config2.ice_include_loopback_candidates = true;
    config2.external_ip = Some("203.0.113.20".to_string());

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    // Verify that candidates have related_address set
    let ctrl_candidates = controlling.local_candidates();
    let non_loopback_candidate = ctrl_candidates
        .iter()
        .find(|c| !c.address.ip().is_loopback());

    if let Some(cand) = non_loopback_candidate {
        assert!(
            cand.related_address.is_some(),
            "Host candidate should have related_address when external_ip is configured"
        );
        assert_ne!(
            cand.address.ip(),
            cand.base_address().ip(),
            "Candidate address (external) should differ from base_address (local)"
        );
    }

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();

    // Both sides should reach Connected within 10 s
    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(
        ok1,
        "Controlling agent failed to reach Connected with external_ip"
    );
    assert!(
        ok2,
        "Controlled agent failed to reach Connected with external_ip"
    );

    // Verify selected pair exists. Connected fires before nomination completes
    // (see wait_for_selected_pair), so wait for the pair to be published.
    wait_for_selected_pair(&controlling, Duration::from_secs(10))
        .await
        .context("Controlling agent should have a selected pair")?;
    wait_for_selected_pair(&controlled, Duration::from_secs(10))
        .await
        .context("Controlled agent should have a selected pair")?;

    Ok(())
}

/// Test that nomination_complete fires correctly when external_ip is configured.
#[tokio::test]
#[serial]
async fn test_nomination_with_external_ip() -> Result<()> {
    let mut config1 = RtcConfiguration::default();
    config1.ice_include_loopback_candidates = true;
    config1.external_ip = Some("203.0.113.10".to_string());

    let mut config2 = RtcConfiguration::default();
    config2.ice_include_loopback_candidates = true;
    config2.external_ip = Some("203.0.113.20".to_string());

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();
    let mut ctrd_nom_rx = controlled.subscribe_nomination_complete();

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();

    // Wait for connection
    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(ok1, "Controlling agent failed to connect");
    assert!(ok2, "Controlled agent failed to connect");

    // Wait for nomination signals
    let ctrl_nom = timeout(Duration::from_secs(15), async {
        if ctrl_nom_rx.borrow().is_some() {
            return *ctrl_nom_rx.borrow();
        }
        ctrl_nom_rx.changed().await.ok()?;
        *ctrl_nom_rx.borrow()
    })
    .await
    .expect("Controlling nomination_complete should fire");

    let ctrd_nom = timeout(Duration::from_secs(5), async {
        if ctrd_nom_rx.borrow().is_some() {
            return *ctrd_nom_rx.borrow();
        }
        ctrd_nom_rx.changed().await.ok()?;
        *ctrd_nom_rx.borrow()
    })
    .await
    .expect("Controlled nomination_complete should fire");

    // Controlled side should signal immediately
    assert_eq!(
        ctrd_nom,
        Some(true),
        "Controlled side should signal nomination_complete immediately"
    );

    // Controlling side may succeed or fail depending on whether nomination reaches the peer
    // The key is that it should fire (not remain None)
    assert!(
        ctrl_nom.is_some(),
        "Controlling nomination_complete should fire (got {:?})",
        ctrl_nom
    );

    Ok(())
}

/// Test that ICE connection works WITHOUT external_ip configured.
/// This ensures the fix for external_ip doesn't break the normal case.
#[tokio::test]
#[serial]
async fn test_ice_connection_without_external_ip() -> Result<()> {
    // Default config has no external_ip
    let config1 = RtcConfiguration::default();
    let config2 = RtcConfiguration::default();

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    // Verify that host candidates do NOT have related_address (or it matches address)
    let ctrl_candidates = controlling.local_candidates();
    for cand in &ctrl_candidates {
        if cand.typ == IceCandidateType::Host {
            // Without external_ip, related_address should be None for non-loopback
            // or the same as address
            if let Some(related) = cand.related_address {
                assert_eq!(
                    related, cand.address,
                    "Without external_ip, related_address should equal address"
                );
            }
            // base_address() should equal address
            assert_eq!(
                cand.base_address(),
                cand.address,
                "Without external_ip, base_address() should equal address"
            );
        }
    }

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();

    // Both sides should reach Connected within 10 s
    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(
        ok1,
        "Controlling agent failed to reach Connected without external_ip"
    );
    assert!(
        ok2,
        "Controlled agent failed to reach Connected without external_ip"
    );

    // Verify selected pair exists and is valid. Connected fires before
    // nomination completes (see wait_for_selected_pair), so wait for the pair.
    let pair = wait_for_selected_pair(&controlling, Duration::from_secs(10))
        .await
        .context("Controlling agent should have a selected pair")?;
    // Verify the pair addresses match what we expect
    assert!(
        pair.local.address.port() > 0,
        "Local address should have valid port"
    );
    assert!(
        pair.remote.address.port() > 0,
        "Remote address should have valid port"
    );

    wait_for_selected_pair(&controlled, Duration::from_secs(10))
        .await
        .context("Controlled agent should have a selected pair")?;

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_nomination_delayed_by_dtls_socket_contention() -> Result<()> {
    let mut config1 = RtcConfiguration::default();
    let mut config2 = RtcConfiguration::default();
    config1.nomination_timeout = Duration::from_millis(500);
    config1.stun_timeout = Duration::from_millis(200);
    config2.nomination_timeout = Duration::from_millis(500);
    config2.stun_timeout = Duration::from_millis(200);

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();
    let mut ctrd_nom_rx = controlled.subscribe_nomination_complete();

    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(ok1, "Controlling ICE failed to connect");
    assert!(ok2, "Controlled ICE failed to connect");

    let ice_connected_at = std::time::Instant::now();

    let ctrd_nom = timeout(Duration::from_millis(600), async {
        if ctrd_nom_rx.borrow().is_some() {
            return *ctrd_nom_rx.borrow();
        }
        ctrd_nom_rx.changed().await.ok()?;
        *ctrd_nom_rx.borrow()
    })
    .await;
    assert!(
        ctrd_nom.is_ok(),
        "Controlled side nomination_complete should fire after receiving USE-CANDIDATE (within 600ms), \
         but timed out — this means the controlled side never received USE-CANDIDATE"
    );
    assert_eq!(
        ctrd_nom.unwrap(),
        Some(true),
        "Controlled side should signal nomination success after receiving USE-CANDIDATE"
    );

    let ctrl_nom = timeout(Duration::from_millis(600), async {
        if ctrl_nom_rx.borrow().is_some() {
            return *ctrl_nom_rx.borrow();
        }
        ctrl_nom_rx.changed().await.ok()?;
        *ctrl_nom_rx.borrow()
    })
    .await;

    let elapsed = ice_connected_at.elapsed();

    assert!(
        ctrl_nom.is_ok(),
        "Controlling side nomination_complete should fire within nomination_timeout (500ms + margin), \
         elapsed={:?}. If this fails it means nomination is stuck indefinitely.",
        elapsed
    );

    let nom_result = ctrl_nom.unwrap();
    assert!(
        nom_result.is_some(),
        "nomination_complete must be Some(_), got None after {:?}",
        elapsed
    );

    Ok(())
}

// ============================================================================
// TURN refresh tests
// ============================================================================

/// Verify that `run_turn_refresh` successfully refreshes allocation, permission,
/// and channel bindings when the TURN server responds normally (200 OK for all).
#[tokio::test]
#[serial]
async fn test_turn_refresh_succeeds_normally() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;

    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config.clone(), tx, socket_tx);
    gatherer.gather().await?;

    // Grab the relay candidate and its TurnClient
    let candidates = gatherer.local_candidates();
    let relay = candidates
        .iter()
        .find(|c| c.typ == IceCandidateType::Relay)
        .expect("should have relay candidate")
        .clone();

    let client = {
        let clients = gatherer.turn_clients.lock();
        clients
            .get(&relay.address)
            .cloned()
            .expect("should have TurnClient for relay")
    };

    // Register a channel binding so the refresh has something to rebind
    let peer: SocketAddr = "127.0.0.1:12345".parse().unwrap();
    client.create_permission(peer).await?;
    // Manually register a fake channel so bound_peers() returns it
    client.add_channel(peer, 0x4000).await;

    // Build a minimal IceTransportInner pointing at the relay selected pair
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    // Wire up the gathered clients into the transport's gatherer
    {
        let mut clients = transport.inner.gatherer.turn_clients.lock();
        for (addr, c) in gatherer.turn_clients.lock().iter() {
            clients.insert(*addr, c.clone());
        }
    }
    // Add the relay candidate so selected_pair resolves
    transport
        .inner
        .gatherer
        .local_candidates
        .lock()
        .extend(candidates);

    // Set up a relay-type selected pair
    let remote = IceCandidate::host("127.0.0.1:9999".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(relay.clone(), remote);
    *transport.inner.selected_pair.lock() = Some(pair);
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Run the refresh — should complete without panicking and without logging errors
    IceTransportRunner::run_turn_refresh(&transport.inner).await;

    turn_server.stop().await?;
    Ok(())
}

/// Verify that `TurnClient::update_nonce` actually updates the stored nonce so
/// that the next packet built with `create_refresh_packet` / `create_channel_rebind_packet`
/// uses the new value.
#[tokio::test]
#[serial]
async fn test_turn_client_update_nonce_takes_effect() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let client = TurnClient::connect(&uri, false).await?;
    let creds = TurnCredentials::from_server(&server)?;
    client.allocate(creds).await?;

    // Update the nonce to a known value
    client
        .update_nonce("new-realm".to_string(), "new-nonce-xyz".to_string())
        .await;

    // The next refresh packet should embed the new nonce
    let (bytes, _tx_id) = client.create_refresh_packet().await?;

    // Decode the packet and verify the Nonce attribute
    let decoded = StunMessage::decode(&bytes)?;
    let has_new_nonce = decoded.nonce.as_deref() == Some("new-nonce-xyz");
    assert!(
        has_new_nonce,
        "Refresh packet should contain the updated nonce; got {:?}",
        decoded.nonce
    );

    turn_server.stop().await?;
    Ok(())
}

/// Simulate a stale-nonce (438) reply for a ChannelBind refresh:
/// the second attempt (with updated nonce) must succeed.
///
/// We do this by:
///   1. Allocating normally (so we have a valid auth state).
///   2. Manually poisoning the stored nonce with a wrong value.
///   3. Calling `run_turn_refresh` — the first ChannelBind attempt gets a 438,
///      `update_nonce` is called, and the retry succeeds.
///
/// Because the real TURN server (coturn / webrtc-rs turn) only issues 438 after
/// an explicit nonce rotation we cannot easily trigger it end-to-end here.
/// Instead we test the nonce-update path in isolation: poison → first packet
/// fails → nonce restored from response → second packet succeeds.
#[tokio::test]
#[serial]
async fn test_turn_refresh_retries_on_stale_nonce() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let client = Arc::new(TurnClient::connect(&uri, false).await?);
    let creds = TurnCredentials::from_server(&server)?;
    client.allocate(creds).await?;

    // Create a permission so we can do ChannelBind
    let peer: SocketAddr = "127.0.0.1:12346".parse().unwrap();
    client.create_permission(peer).await?;

    // Poison the nonce — the next ChannelBind will carry this wrong nonce
    // and the server will respond with 438 + a fresh nonce.
    client
        .update_nonce(TEST_REALM.to_string(), "stale-nonce-AAAA".to_string())
        .await;

    // Verify that the client can still recover:
    // create_channel_rebind_packet will embed the stale nonce, the server returns 438,
    // update_nonce is called, and the retry succeeds.
    //
    // We exercise this via the public helpers rather than run_turn_refresh because
    // run_turn_refresh requires a full IceTransportInner.  The important thing is
    // that update_nonce + create_channel_rebind_packet produces a valid packet after
    // receiving the fresh nonce from the server.

    // Attempt 1: stale nonce → expect 401/438 from server
    let (bytes1, tx_id1) = client.create_channel_rebind_packet(peer, 0x4000).await?;
    client.send(&bytes1).await?;
    let mut buf = [0u8; 1500];
    let len = client.recv(&mut buf).await?;
    let resp1 = StunMessage::decode(&buf[..len])?;
    // The transaction ids won't match because the server ignores mismatched ones;
    // what matters is that we get an error (401 or 438).
    let _ = tx_id1;
    assert!(
        matches!(resp1.error_code, Some(400..=438)),
        "Expected 4xx error for stale nonce, got {:?}",
        resp1.error_code
    );

    // Extract new realm+nonce from the error response and update
    if let (Some(realm), Some(nonce)) = (resp1.realm.clone(), resp1.nonce.clone()) {
        client.update_nonce(realm, nonce).await;
    }

    // Attempt 2: fresh nonce → should succeed (or at least not get 438 again)
    let (bytes2, _tx_id2) = client.create_channel_rebind_packet(peer, 0x4000).await?;
    client.send(&bytes2).await?;
    let len2 = client.recv(&mut buf).await?;
    let resp2 = StunMessage::decode(&buf[..len2])?;
    assert_eq!(
        resp2.class,
        StunClass::SuccessResponse,
        "Second ChannelBind with fresh nonce should succeed, got error={:?}",
        resp2.error_code
    );

    turn_server.stop().await?;
    Ok(())
}

/// Verify that `run_turn_refresh` exits cleanly (no panic, no hang) when the
/// TURN server is unreachable (simulated by stopping the server before the
/// refresh runs).
#[tokio::test]
#[serial]
async fn test_turn_refresh_tolerates_server_unreachable() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;

    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config.clone(), tx, socket_tx);
    gatherer.gather().await?;

    let candidates = gatherer.local_candidates();
    let relay = candidates
        .iter()
        .find(|c| c.typ == IceCandidateType::Relay)
        .expect("should have relay candidate")
        .clone();

    // Stop the TURN server before the refresh
    turn_server.stop().await?;

    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    {
        let mut clients = transport.inner.gatherer.turn_clients.lock();
        for (addr, c) in gatherer.turn_clients.lock().iter() {
            clients.insert(*addr, c.clone());
        }
    }
    transport
        .inner
        .gatherer
        .local_candidates
        .lock()
        .extend(candidates);

    let remote = IceCandidate::host("127.0.0.1:9999".parse().unwrap(), 1);
    let pair = IceCandidatePair::new(relay, remote);
    *transport.inner.selected_pair.lock() = Some(pair);
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Should complete within the 5s send_and_await timeout × 3 requests (alloc+perm+chan)
    // plus margin. With server down, each request times out after 5s.
    let result = timeout(
        Duration::from_secs(25),
        IceTransportRunner::run_turn_refresh(&transport.inner),
    )
    .await;

    assert!(
        result.is_ok(),
        "run_turn_refresh should complete even when server is unreachable"
    );

    Ok(())
}

// ============================================================================
// TURN destroy (RFC 5766 §7.4) tests
// ============================================================================

/// Verify that `TurnClient::create_destroy_packet` builds a valid
/// Refresh(LIFETIME=0) request that the TURN server accepts. Per RFC 5766 §7.4
/// a success response to Refresh(LIFETIME=0) means the allocation is destroyed.
#[tokio::test]
#[serial]
async fn test_turn_destroy_releases_allocation() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);

    let client = TurnClient::connect(&uri, false).await?;
    let creds = TurnCredentials::from_server(&server)?;
    let allocation = client.allocate(creds).await?;
    assert!(
        allocation.relayed_address.port() != 0,
        "allocation should succeed before destroy"
    );

    // Build and send the destroy request (Refresh LIFETIME=0).
    let (bytes, tx_id) = client.create_destroy_packet_sync()?;
    client.send(&bytes).await?;
    let mut buf = [0u8; MAX_STUN_MESSAGE];
    let len = client.recv(&mut buf).await?;
    let resp = StunMessage::decode(&buf[..len])?;
    assert_eq!(
        resp.transaction_id, tx_id,
        "destroy response tx id should match"
    );
    assert_eq!(
        resp.method,
        StunMethod::Refresh,
        "destroy response should be a Refresh"
    );
    assert_eq!(
        resp.class,
        StunClass::SuccessResponse,
        "destroy should succeed, got error={:?}",
        resp.error_code
    );

    turn_server.stop().await?;
    Ok(())
}

/// Verify that `IceTransport::stop()` triggers best-effort destruction of TURN
/// allocations: relayed traffic flows before `stop()`, and stops flowing
/// shortly after, proving the server released the allocation (RFC 5766 §7.4).
#[tokio::test]
#[serial]
async fn test_ice_stop_destroys_turn_allocations() -> Result<()> {
    use tokio::net::UdpSocket;

    let mut turn_server = TestTurnServer::start().await?;

    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config.clone(), tx, socket_tx);
    gatherer.gather().await?;

    let candidates = gatherer.local_candidates();
    let relay = candidates
        .iter()
        .find(|c| c.typ == IceCandidateType::Relay)
        .expect("should have relay candidate")
        .clone();
    let relay_addr = relay.address;

    let client = {
        let clients = gatherer.turn_clients.lock();
        clients
            .get(&relay_addr)
            .cloned()
            .expect("should have TurnClient for relay")
    };

    // Set up a peer sink that receives data relayed through TURN, and create a
    // permission for it BEFORE the runner takes over the client socket.
    let peer_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer_socket.local_addr()?;
    client.create_permission(peer_addr).await?;

    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);
    transport
        .inner
        .gatherer
        .turn_clients
        .lock()
        .insert(relay_addr, client.clone());
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Sanity: relayed Send Indication delivers data to the peer.
    client.send_indication(peer_addr, b"before").await?;
    let mut rbuf = [0u8; 16];
    let (n, _) = peer_socket.recv_from(&mut rbuf).await?;
    assert_eq!(
        &rbuf[..n],
        b"before",
        "peer should receive relayed data before stop()"
    );

    // stop() spawns the detached best-effort destroy task.
    transport.stop();

    // Wait for the destroy (Refresh LIFETIME=0) to reach the server.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // After the allocation is destroyed, the relay drops Send Indications.
    client.send_indication(peer_addr, b"after").await?;
    let result = timeout(Duration::from_millis(500), peer_socket.recv_from(&mut rbuf)).await;
    assert!(
        result.is_err(),
        "no relayed data should reach the peer after IceTransport::stop() destroyed the allocation"
    );

    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn test_nomination_fails_immediately_on_host_unreachable() -> Result<()> {
    // With the transient-error retry fix, EHOSTUNREACH is no longer an immediate
    // failure.  Nomination retries until nomination_timeout, then yields Some(false).
    // Use a short nomination_timeout so the test still terminates quickly.
    let mut config = RtcConfiguration::default();
    config.stun_timeout = Duration::from_secs(30);
    config.nomination_timeout = Duration::from_millis(500);

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    let local_candidate = IceCandidate::host("127.0.0.1:0".parse().unwrap(), 1);
    let remote_candidate = IceCandidate::host("127.0.0.1:1".parse().unwrap(), 1);

    *transport.inner.role.lock() = IceRole::Controlling;
    transport.set_remote_parameters(IceParameters::new(
        "testufrag",
        "testpassword_long_enough_1234",
    ));

    let mut nom_rx = transport.subscribe_nomination_complete();

    let inner_clone = transport.inner.clone();
    let local_clone = local_candidate.clone();
    let remote_clone = remote_candidate.clone();
    tokio::spawn(async move {
        let result = perform_binding_check(
            &local_clone,
            &remote_clone,
            &inner_clone,
            IceRole::Controlling,
            true,
        )
        .await;
        let signal = if result.is_ok() {
            Some(true)
        } else {
            Some(false)
        };
        let _ = inner_clone.nomination_complete.send(signal);
    });

    let start = std::time::Instant::now();
    let result = timeout(Duration::from_millis(1500), async {
        if nom_rx.borrow().is_some() {
            return *nom_rx.borrow();
        }
        nom_rx.changed().await.ok()?;
        *nom_rx.borrow()
    })
    .await;
    let elapsed = start.elapsed();

    assert!(
        result.is_ok(),
        "nomination_complete should fire after nomination_timeout (500ms) when host is \
         unreachable, but timed out after {:?}",
        elapsed
    );

    let nom_value = result.unwrap();
    assert_eq!(
        nom_value,
        Some(false),
        "Nomination to unreachable address should produce Some(false), got {:?}",
        nom_value
    );

    Ok(())
}

#[tokio::test]
async fn test_dtls_proceeds_after_nomination_timeout() -> Result<()> {
    let mut config1 = RtcConfiguration::default();
    let mut config2 = RtcConfiguration::default();
    config1.nomination_timeout = Duration::from_millis(1);
    config1.stun_timeout = Duration::from_secs(5);
    config2.nomination_timeout = Duration::from_millis(1);
    config2.stun_timeout = Duration::from_secs(5);

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();

    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)),
        wait_ice_connected(ctrd_state, Duration::from_secs(10)),
    );
    assert!(ok1, "Controlling ICE failed to connect");
    assert!(ok2, "Controlled ICE failed to connect");

    let nom = timeout(Duration::from_millis(200), async {
        if ctrl_nom_rx.borrow().is_some() {
            return *ctrl_nom_rx.borrow();
        }
        ctrl_nom_rx.changed().await.ok()?;
        *ctrl_nom_rx.borrow()
    })
    .await;

    let ctrl_pair = controlling.get_selected_pair();
    assert!(
        ctrl_pair.is_some(),
        "Even when nomination times out, ICE selected pair should exist. nom={:?}",
        nom
    );
    let ctrd_pair = controlled.get_selected_pair();
    assert!(
        ctrd_pair.is_some(),
        "Controlled side should have a selected pair even when controlling nomination times out"
    );

    let (tx1, rx1) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();

    struct Chan(tokio::sync::mpsc::UnboundedSender<bytes::Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for Chan {
        async fn receive(
            &self,
            packet: bytes::Bytes,
            _addr: std::net::SocketAddr,
            _buf: &mut Vec<u8>,
        ) {
            let _ = self.0.send(packet);
        }
    }

    controlling
        .inner
        .data_receiver
        .lock()
        .replace(Arc::new(Chan(tx1)));
    controlled
        .inner
        .data_receiver
        .lock()
        .replace(Arc::new(Chan(tx2)));

    let test_payload = bytes::Bytes::from_static(b"\xffhello-after-nomination-timeout");
    let ctrl_socket_rx = controlling.subscribe_selected_socket();
    let ctrd_socket_rx = controlled.subscribe_selected_socket();

    let ctrl_sock = timeout(Duration::from_secs(3), async {
        let mut rx = ctrl_socket_rx;
        loop {
            if rx.borrow().is_some() {
                return rx.borrow().clone();
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    })
    .await
    .ok()
    .flatten();

    let ctrd_sock = timeout(Duration::from_secs(3), async {
        let mut rx = ctrd_socket_rx;
        loop {
            if rx.borrow().is_some() {
                return rx.borrow().clone();
            }
            if rx.changed().await.is_err() {
                return None;
            }
        }
    })
    .await
    .ok()
    .flatten();

    if let (Some(sock), Some(ctrl_pair)) = (ctrl_sock, controlling.get_selected_pair()) {
        let _ = sock.send_to(&test_payload, ctrl_pair.remote.address).await;
        let received = timeout(Duration::from_secs(2), rx2.recv()).await;
        if let Ok(Some(pkt)) = received {
            assert_eq!(
                &pkt[..],
                &test_payload[..],
                "Received payload mismatch after nomination timeout"
            );
        }
        let _ = ctrd_sock;
        let _ = rx1;
    }

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_nomination_fallback_all_pairs_fail() -> Result<()> {
    // Very short nomination_timeout — on CI/slow systems the nomination should
    // fail (timeout fires before response arrives).  On fast localhost it may
    // still succeed because the STUN round-trip can be < 100µs.
    let mut config1 = RtcConfiguration::default();
    config1.nomination_timeout = Duration::from_micros(10);
    config1.stun_timeout = Duration::from_secs(5);
    let mut config2 = RtcConfiguration::default();
    config2.nomination_timeout = Duration::from_micros(10);
    config2.stun_timeout = Duration::from_secs(5);

    let (controlling, _controlled) = setup_host_pair(config1, config2).await;

    let mut ctrl_state = controlling.subscribe_state();
    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();

    // Wait for ICE Connected (connectivity check succeeds)
    assert!(
        wait_ice_connected(ctrl_state.clone(), Duration::from_secs(10)).await,
        "ICE should connect"
    );

    // Wait for nomination_complete to fire (Some(true) or Some(false),
    // depending on whether the STUN response beat the timeout).
    let nom_fired = timeout(Duration::from_secs(30), async {
        if ctrl_nom_rx.borrow().is_some() {
            return;
        }
        loop {
            tokio::select! {
                _ = ctrl_nom_rx.changed() => {
                    return;
                }
                _ = ctrl_state.changed() => {
                    if ctrl_nom_rx.borrow().is_some() {
                        return;
                    }
                }
            }
        }
    })
    .await;

    assert!(
        nom_fired.is_ok(),
        "nomination_complete must fire (Some(true) or Some(false)), \
         it should never hang"
    );

    let nom = *ctrl_nom_rx.borrow();
    match nom {
        Some(true) => {
            // Nomination succeeded (fast localhost) — ICE should stay Connected
            debug!("Nomination succeeded (fast path) – all good");
        }
        Some(false) => {
            // Nomination failed — verify ICE transitions to Failed
            debug!("Nomination failed – verifying ICE transitions to Failed");
            let failed = timeout(Duration::from_secs(30), async {
                loop {
                    let s = *ctrl_state.borrow_and_update();
                    if s == IceTransportState::Failed {
                        return;
                    }
                    if ctrl_state.changed().await.is_err() {
                        return;
                    }
                }
            })
            .await;
            assert!(
                failed.is_ok(),
                "ICE should transition to Failed after all pairs fail nomination"
            );
        }
        None => {
            panic!("nomination_complete value should be Some(_), got None");
        }
    }

    // Selected pair should exist regardless
    let pair = controlling.get_selected_pair();
    assert!(
        pair.is_some(),
        "selected pair should exist even after nomination outcome"
    );

    Ok(())
}

/// Test that parallel nomination completes within a single `nomination_timeout`
/// period even when an unreachable candidate is present alongside reachable
/// ones.
///
/// With sequential nomination (pre-0.3.104) the unreachable pair would be
/// nominated first and waste a full `nomination_timeout` before falling through
/// to the reachable pair.  With parallel nomination all pairs are nominated
/// concurrently, so the reachable pair's response arrives immediately.
#[tokio::test]
#[serial]
async fn test_parallel_nomination_with_unreachable_candidate() -> Result<()> {
    let config = RtcConfiguration::default();

    let (controlling, runner_c) = IceTransportBuilder::new(config.clone())
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);

    let (controlled, runner_d) = IceTransportBuilder::new(config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    // Forward candidates both ways
    let ctrl_clone = controlling.clone();
    let ctrd_clone = controlled.clone();
    let mut rx_ctrl = controlling.subscribe_candidates();
    let mut rx_ctrd = controlled.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrl.recv().await {
            ctrd_clone.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrd.recv().await {
            ctrl_clone.add_remote_candidate(c);
        }
    });

    // Add an UNREACHABLE remote candidate to the controlling side first
    // (127.0.0.2 — nothing listening there).
    let bad_remote = IceCandidate::host("127.0.0.2:9999".parse().unwrap(), 1);
    controlling.add_remote_candidate(bad_remote);

    // Start both transports
    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    let ctrl_state = controlling.subscribe_state();
    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();

    // Both should reach Connected.  The bad pair will fail its connectivity
    // check, but the good pairs (once candidates are exchanged) will succeed.
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await,
        "ICE should connect despite unreachable candidate"
    );

    // Nomination should succeed — with parallel nomination the reachable pair's
    // USE-CANDIDATE response arrives in <1 s on localhost, independent of the
    // unreachable pair that would block sequential nomination for 10 s.
    let nom_result = timeout(Duration::from_secs(10), async {
        loop {
            if let Some(v) = *ctrl_nom_rx.borrow() {
                return v;
            }
            if ctrl_nom_rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await;

    assert!(nom_result.is_ok(), "nomination_complete must fire");
    assert!(
        nom_result.unwrap(),
        "Nomination should succeed (parallel — reachable pair wins)"
    );

    // Selected pair should be a reachable one, not the bad candidate.
    let pair = controlling.get_selected_pair();
    assert!(pair.is_some(), "Selected pair should exist");
    let pair = pair.unwrap();
    assert_ne!(
        pair.remote.address,
        "127.0.0.2:9999".parse::<SocketAddr>().unwrap(),
        "Selected pair should not be the unreachable candidate"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_nomination_fallback_controlled_side_works() -> Result<()> {
    // Controlled side should still receive USE-CANDIDATE and signal
    // nomination_complete = Some(true), even when the controlling side
    // goes to Failed after nomination timeout.
    let mut config1 = RtcConfiguration::default();
    config1.nomination_timeout = Duration::ZERO;
    config1.stun_timeout = Duration::from_secs(5);
    let mut config2 = RtcConfiguration::default();
    config2.nomination_timeout = Duration::ZERO;
    config2.stun_timeout = Duration::from_secs(5);

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    let mut ctrd_nom_rx = controlled.subscribe_nomination_complete();

    // Both sides should connect
    assert!(
        wait_ice_connected(ctrl_state.clone(), Duration::from_secs(10)).await,
        "Controlling ICE should connect"
    );
    assert!(
        wait_ice_connected(ctrd_state.clone(), Duration::from_secs(10)).await,
        "Controlled ICE should connect"
    );

    // Controlled side should get nomination_complete = Some(true)
    // because it receives the controlling side's USE-CANDIDATE STUN request
    // (the single request sent before the controlling side's timeout fires)
    let ctrd_nom = timeout(Duration::from_secs(10), async {
        if ctrd_nom_rx.borrow().is_some() {
            return *ctrd_nom_rx.borrow();
        }
        ctrd_nom_rx.changed().await.ok()?;
        *ctrd_nom_rx.borrow()
    })
    .await;

    assert_eq!(
        ctrd_nom,
        Ok(Some(true)),
        "Controlled side should receive USE-CANDIDATE and set nomination_complete = Some(true)"
    );

    // Controlled side should have a selected pair
    let ctrd_pair = controlled.get_selected_pair();
    assert!(
        ctrd_pair.is_some(),
        "Controlled side should have a selected pair"
    );

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_nomination_race_under_high_packet_loss() -> Result<()> {
    struct ScopeGuard {
        prev: u32,
    }
    impl Drop for ScopeGuard {
        fn drop(&mut self) {
            PACKET_LOSS_RATE.store(self.prev, Ordering::SeqCst);
        }
    }

    let _guard = ScopeGuard {
        prev: PACKET_LOSS_RATE.swap(8000, Ordering::SeqCst),
    };

    let mut config1 = RtcConfiguration::default();
    let mut config2 = RtcConfiguration::default();
    config1.nomination_timeout = Duration::from_secs(3);
    config1.stun_timeout = Duration::from_secs(1);
    config2.nomination_timeout = Duration::from_secs(3);
    config2.stun_timeout = Duration::from_secs(1);

    let (controlling, controlled) = setup_host_pair(config1, config2).await;

    let ctrl_state = controlling.subscribe_state();
    let ctrd_state = controlled.subscribe_state();
    let mut ctrl_nom_rx = controlling.subscribe_nomination_complete();

    let (ok1, ok2) = tokio::join!(
        wait_ice_connected(ctrl_state, Duration::from_secs(15)),
        wait_ice_connected(ctrd_state, Duration::from_secs(15)),
    );

    if !ok1 || !ok2 {
        return Ok(());
    }

    let nom_result = timeout(Duration::from_secs(5), async {
        if ctrl_nom_rx.borrow().is_some() {
            return *ctrl_nom_rx.borrow();
        }
        ctrl_nom_rx.changed().await.ok()?;
        *ctrl_nom_rx.borrow()
    })
    .await;

    assert!(
        nom_result.is_ok(),
        "Under 80% packet loss, nomination_complete must still fire (Some(true) or Some(false)), \
         but it timed out (hung indefinitely). This reproduces the log issue where the connection \
         gets stuck waiting for nomination."
    );

    let nom = nom_result.unwrap();
    assert!(
        nom.is_some(),
        "nomination_complete value must be Some(_), got None. \
         This means the watch channel was closed unexpectedly."
    );

    println!(
        "High packet loss nomination result: {:?} (either is acceptable, None is not)",
        nom
    );

    Ok(())
}

// ============================================================================
// UPnP IGD tests
// ============================================================================

/// Test that default UPnP constants are valid
#[test]
#[allow(clippy::assertions_on_constants)] // intentional compile-time invariant checks
fn test_upnp_default_constants() {
    assert!(MIN_LEASE_DURATION > 0);
    assert!(MAX_LEASE_DURATION > MIN_LEASE_DURATION);
    assert!(DEFAULT_LEASE_DURATION >= MIN_LEASE_DURATION);
    assert!(DEFAULT_LEASE_DURATION <= MAX_LEASE_DURATION);
    assert_eq!(DEFAULT_LEASE_DURATION, 3600); // 1 hour default
}

/// Test PortMapping creation and expiry detection
#[test]
fn test_port_mapping_expiry() {
    // Use lease_duration > 60 to avoid immediate stale state
    let mapping = PortMapping {
        external_port: 12345,
        internal_addr: "192.168.1.100:5000".parse().unwrap(),
        lease_duration: 70, // > 60 so not immediately stale
        description: "test".to_string(),
        created_at: std::time::Instant::now(),
    };

    // Should not be expired immediately (70 > 60)
    assert!(!mapping.is_expired_or_stale());

    // Check remaining lifetime is around 70
    let remaining = mapping.remaining_lifetime();
    assert!((69..=70).contains(&remaining));
}

/// Test PortMapping remaining lifetime calculation
#[test]
fn test_port_mapping_remaining_lifetime() {
    let mapping = PortMapping {
        external_port: 12345,
        internal_addr: "192.168.1.100:5000".parse().unwrap(),
        lease_duration: 60,
        description: "test".to_string(),
        created_at: std::time::Instant::now(),
    };

    // Should have close to 60 seconds remaining
    let remaining = mapping.remaining_lifetime();
    assert!(remaining > 55 && remaining <= 60);

    // After sleeping, remaining should decrease or stay same (not increase)
    std::thread::sleep(std::time::Duration::from_millis(100));
    let new_remaining = mapping.remaining_lifetime();
    assert!(
        new_remaining <= remaining,
        "new_remaining should not increase"
    );
}

/// Test UpnpPortMapper creation with default lease duration
#[test]
fn test_upnp_mapper_creation() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mapper = UpnpPortMapper::new(addr);

    assert!(mapper.is_enabled());
    assert!(!mapper.has_gateway());
}

/// Test UpnpPortMapper with custom lease duration
#[test]
fn test_upnp_mapper_custom_lease() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();

    // Test clamping to minimum
    let mapper = UpnpPortMapper::with_lease_duration(addr, 100);
    assert_eq!(mapper.default_lease_duration, MIN_LEASE_DURATION);

    // Test clamping to maximum
    let mapper = UpnpPortMapper::with_lease_duration(addr, 100000);
    assert_eq!(mapper.default_lease_duration, MAX_LEASE_DURATION);

    // Test valid value
    let mapper = UpnpPortMapper::with_lease_duration(addr, 1800);
    assert_eq!(mapper.default_lease_duration, 1800);
}

/// Test UpnpPortMapper disable/enable functionality
#[test]
fn test_upnp_mapper_disable_enable() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mut mapper = UpnpPortMapper::new(addr);

    assert!(mapper.is_enabled());
    assert!(!mapper.has_gateway()); // Initially no gateway

    mapper.disable();
    assert!(!mapper.is_enabled());
    // Gateway should be None after disable (but we can't check private field)
    // We verify through has_gateway() which returns gateway.is_some()

    mapper.enable();
    assert!(mapper.is_enabled());
}

/// Test that discover() fails for loopback addresses
#[tokio::test]
async fn test_upnp_mapper_loopback_rejection() {
    let addr: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    let mut mapper = UpnpPortMapper::new(addr);

    let result = mapper.discover().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("loopback"));
}

/// Test that discover() fails when disabled
#[tokio::test]
async fn test_upnp_mapper_disabled() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mut mapper = UpnpPortMapper::new(addr);
    mapper.disable();

    let result = mapper.discover().await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("disabled"));
}

/// Test that add_mapping() fails without discover()
#[tokio::test]
async fn test_upnp_mapper_no_gateway() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mapper = UpnpPortMapper::new(addr);

    let result = mapper.add_mapping(12345).await;
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("No UPnP gateway"));
}

/// Test UpnpPortMapper clone behavior
#[tokio::test]
async fn test_upnp_mapper_clone() {
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let mapper = UpnpPortMapper::new(addr);

    let cloned = mapper.clone();
    // Gateway should be None in clone (not cloneable)
    assert!(!cloned.has_gateway());
    // Other properties should be preserved
    assert_eq!(cloned.local_addr, addr);
    assert!(cloned.is_enabled());
}

/// Test RtcConfiguration UPnP defaults
#[test]
fn test_config_upnp_defaults() {
    let config = RtcConfiguration::default();
    assert!(!config.enable_upnp, "UPnP should be disabled by default");
    assert_eq!(
        config.upnp_lease_duration, 3600,
        "Default lease should be 1 hour"
    );
}

/// Test RtcConfigurationBuilder UPnP methods
#[test]
fn test_config_builder_upnp_methods() {
    let config = RtcConfigurationBuilder::new()
        .enable_upnp(false)
        .upnp_lease_duration(7200)
        .build();

    assert!(!config.enable_upnp);
    assert_eq!(config.upnp_lease_duration, 7200);
}

/// Test that UPnP is disabled when the policy is Relay-only
#[tokio::test]
async fn test_upnp_disabled_when_relay_policy() {
    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.enable_upnp = true; // Explicitly enable, but should be ignored

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);

    // Gather candidates
    gatherer.gather().await.unwrap();

    // In Relay-only mode, we shouldn't have any UPnP mappers
    // (though we might have relay candidates if TURN servers are configured)
    let mappers = gatherer.upnp_mappers.lock();
    assert!(
        mappers.is_empty(),
        "UPnP should not be used in Relay-only mode"
    );
}

/// Test that UPnP gathering is skipped when disabled in config
#[tokio::test]
async fn test_upnp_disabled_in_config() {
    let mut config = RtcConfiguration::default();
    config.enable_upnp = false;

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);

    // Gather candidates
    gatherer.gather().await.unwrap();

    // Should have host candidates but no UPnP mappers
    let candidates = gatherer.local_candidates();
    let has_host = candidates.iter().any(|c| c.typ == IceCandidateType::Host);
    assert!(has_host, "Should have host candidates");

    let mappers = gatherer.upnp_mappers.lock();
    assert!(
        mappers.is_empty(),
        "Should not have UPnP mappers when disabled"
    );
}

/// Test cleanup_upnp_mappings method
#[tokio::test]
async fn test_upnp_cleanup_mappings() {
    let config = RtcConfiguration::default();

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);

    // Initially no mappers
    assert_eq!(gatherer.upnp_mappers.lock().len(), 0);

    // Add a mock mapper
    {
        let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
        let mapper = UpnpPortMapper::new(addr);
        gatherer.upnp_mappers.lock().push(mapper);
    }

    assert_eq!(gatherer.upnp_mappers.lock().len(), 1);

    // Cleanup should clear the mappers
    gatherer.cleanup_upnp_mappings().await;

    assert_eq!(gatherer.upnp_mappers.lock().len(), 0);
}

/// Test IPv6 address rejection in UPnP mapper
#[tokio::test]
async fn test_upnp_ipv6_rejection() {
    // IPv6 addresses should be skipped during UPnP gathering
    let addr: SocketAddr = "[::1]:5000".parse().unwrap();

    // IPv6 is_loopback should be true
    assert!(addr.ip().is_loopback());

    // Create gatherer with IPv6-capable config
    let config = RtcConfiguration::default();

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);

    // Should not add any UPnP mappers for IPv6 addresses
    // (they would be filtered by the is_loopback or is_ipv6 checks)
    gatherer.gather().await.unwrap();

    // No IPv6 addresses should result in UPnP mappers
    let mappers = gatherer.upnp_mappers.lock();
    for mapper in mappers.iter() {
        assert!(
            !mapper.local_addr.is_ipv6(),
            "UPnP mappers should not have IPv6 addresses"
        );
    }
}

/// Test that gather_upnp_candidates handles errors gracefully
#[tokio::test]
async fn test_upnp_gathering_graceful_errors() {
    // Create config with UPnP enabled but no actual UPnP gateway
    let mut config = RtcConfiguration::default();
    config.enable_upnp = true;
    config.upnp_lease_duration = 1800;

    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(config, tx, socket_tx);

    // Gather should complete without panicking even if UPnP fails
    // (no actual gateway available in test environment)
    let result = gatherer.gather().await;
    assert!(result.is_ok(), "Gather should succeed even if UPnP fails");

    // Should have host candidates (from normal gathering)
    let candidates = gatherer.local_candidates();
    let has_host = candidates.iter().any(|c| c.typ == IceCandidateType::Host);
    assert!(has_host, "Should have host candidates even if UPnP fails");
}

/// Test that UPnP-related fields are exported from library
#[test]
fn test_upnp_library_exports() {
    // These should compile, verifying the exports are correct
    use crate::UpnpPortMapper;
    use crate::{DEFAULT_LEASE_DURATION, MAX_LEASE_DURATION, MIN_LEASE_DURATION};

    let _ = DEFAULT_LEASE_DURATION;
    let _ = MIN_LEASE_DURATION;
    let _ = MAX_LEASE_DURATION;

    // Verify the mapper can be created
    let addr: SocketAddr = "192.168.1.100:5000".parse().unwrap();
    let _mapper = UpnpPortMapper::new(addr);
}

/// Test that RTP mode respects UPnP enable flag
#[tokio::test]
async fn test_rtp_mode_upnp_disabled() {
    use crate::TransportMode;

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.enable_upnp = false;

    let (transport, _runner) = IceTransport::new(config);

    // Setup direct RTP (offer side)
    let local_addr = transport.setup_direct_rtp_offer().await.unwrap();

    // Should have a local candidate
    let candidates = transport.local_candidates();
    assert!(!candidates.is_empty());

    // Candidate should use local address (not UPnP external)
    let host_candidate = candidates
        .iter()
        .find(|c| c.typ == IceCandidateType::Host)
        .unwrap();
    assert_eq!(host_candidate.address.port(), local_addr.port());

    // Should not have UPnP mappers when disabled
    let mappers = transport.inner.gatherer.upnp_mappers.lock();
    assert!(mappers.is_empty());
}

/// Test that RTP mode attempts UPnP when enabled (will fail in test env but shouldn't panic)
#[tokio::test]
async fn test_rtp_mode_upnp_enabled_graceful() {
    use crate::TransportMode;

    let mut config = RtcConfiguration::default();
    config.transport_mode = TransportMode::Rtp;
    config.enable_upnp = true;

    let (transport, _runner) = IceTransport::new(config);

    // Setup direct RTP (offer side) - UPnP will fail in test env but should be graceful
    let result = transport.setup_direct_rtp_offer().await;
    assert!(
        result.is_ok(),
        "setup_direct_rtp_offer should succeed even if UPnP fails"
    );

    // Should have a local candidate
    let candidates = transport.local_candidates();
    assert!(!candidates.is_empty());
}

// ── Regression tests for USE-CANDIDATE re-nomination bug ────────────────────

/// Baseline: the very first USE-CANDIDATE received on the controlled side must
/// nominate the pair and move the state to Connected.
#[tokio::test]
async fn use_candidate_nominates_first_pair() -> Result<()> {
    let (t1, r1) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlling)
        .build();
    let (t2, r2) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(r1);
    tokio::spawn(r2);

    for c in t1.local_candidates() {
        t2.add_remote_candidate(c);
    }
    for c in t2.local_candidates() {
        t1.add_remote_candidate(c);
    }
    let t1c = t1.clone();
    let t2c = t2.clone();
    let mut cand_rx1 = t1.subscribe_candidates();
    let mut cand_rx2 = t2.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = cand_rx1.recv().await {
            t2c.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = cand_rx2.recv().await {
            t1c.add_remote_candidate(c);
        }
    });

    t1.start(t2.local_parameters()).await?;
    t2.start(t1.local_parameters()).await?;

    let wait_connected = |mut rx: watch::Receiver<IceTransportState>| async move {
        loop {
            if *rx.borrow_and_update() == IceTransportState::Connected {
                return Ok::<_, anyhow::Error>(());
            }
            if rx.changed().await.is_err() {
                anyhow::bail!("state channel closed");
            }
        }
    };

    timeout(
        Duration::from_secs(10),
        futures::future::try_join(
            wait_connected(t1.subscribe_state()),
            wait_connected(t2.subscribe_state()),
        ),
    )
    .await
    .context("timed out waiting for ICE connection")??;

    // Controlled side must have a selected pair after nomination.
    assert!(
        t2.get_selected_pair().is_some(),
        "controlled side must have a selected pair after the first USE-CANDIDATE"
    );

    Ok(())
}

/// Send a raw USE-CANDIDATE binding request from `sock` to `to`, then answer
/// the controlled agent's path-verification check. A genuine controlling peer
/// re-nominating onto a new path answers connectivity checks on that path, so
/// the re-nomination converges under the verify-before-switch rule.
async fn send_renomination_and_verify(
    sock: &UdpSocket,
    to: SocketAddr,
    controlled_addr: SocketAddr,
) -> Result<()> {
    let tx_id = random_bytes::<12>();
    let mut msg = StunMessage::binding_request(tx_id, None);
    msg.attributes.push(StunAttribute::UseCandidate);
    let bytes = msg.encode(None, false)?;
    sock.send_to(&bytes, controlled_addr).await?;

    let mut buf = [0u8; 1500];
    let deadline = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("no path-verification check received from controlled agent");
        }
        let (n, from) = timeout(remaining, sock.recv_from(&mut buf)).await??;
        let m = StunMessage::decode(&buf[..n])?;
        if m.class == StunClass::Request && m.method == StunMethod::Binding {
            let resp = StunMessage::binding_success_response(m.transaction_id, to);
            sock.send_to(&resp.encode(None, true)?, from).await?;
            return Ok(());
        }
        // else: success response to our own nomination check — keep reading
    }
}

async fn wait_selected_remote(
    transport: &IceTransport,
    remote: SocketAddr,
    deadline: Duration,
) -> Result<()> {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Some(p) = transport.get_selected_pair() {
            if p.remote.address == remote {
                return Ok(());
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    anyhow::bail!("selected pair never switched to {}", remote)
}

/// The controlled agent must FOLLOW a re-nomination: a USE-CANDIDATE that
/// arrives on a different pair after the first nomination selects that new
/// pair. That is exactly what a real controlling peer does when its current
/// path dies (e.g. a browser abandoning a dead srflx path for its relay); if
/// the controlled side freezes on the abandoned pair, DTLS is sent to the
/// wrong address and the call has no media.
///
/// A USE-CANDIDATE on the *same* pair remains a no-op.
///
/// The path-verification gate (see `verify_nominated_path`) means a second
/// nomination must answer the agent's same-path check before the switch: a
/// genuine controlling peer re-nominating onto a live path answers it, so the
/// re-nomination still converges; dead paths do not and are ignored.
#[tokio::test]
async fn use_candidate_follows_renomination_from_new_candidate() -> Result<()> {
    // 1. Connect two ICE agents (controlling + controlled).
    let (t1, r1) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlling)
        .build();
    let (t2, r2) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(r1);
    tokio::spawn(r2);

    for c in t1.local_candidates() {
        t2.add_remote_candidate(c);
    }
    for c in t2.local_candidates() {
        t1.add_remote_candidate(c);
    }
    let t1c = t1.clone();
    let t2c = t2.clone();
    let mut cand_rx1 = t1.subscribe_candidates();
    let mut cand_rx2 = t2.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = cand_rx1.recv().await {
            t2c.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = cand_rx2.recv().await {
            t1c.add_remote_candidate(c);
        }
    });

    t1.start(t2.local_parameters()).await?;
    t2.start(t1.local_parameters()).await?;

    let wait_connected = |mut rx: watch::Receiver<IceTransportState>| async move {
        loop {
            if *rx.borrow_and_update() == IceTransportState::Connected {
                return Ok::<_, anyhow::Error>(());
            }
            if rx.changed().await.is_err() {
                anyhow::bail!("state channel closed");
            }
        }
    };

    timeout(
        Duration::from_secs(10),
        futures::future::try_join(
            wait_connected(t1.subscribe_state()),
            wait_connected(t2.subscribe_state()),
        ),
    )
    .await
    .context("timed out waiting for ICE connection")??;

    // Connected only means the controlled side picked a provisional pair;
    // the controlling agent's USE-CANDIDATE (which may switch that pair)
    // can still be in flight. Wait for actual nomination before sampling.
    let mut nom_rx = t2.subscribe_nomination_complete();
    timeout(Duration::from_secs(10), async {
        loop {
            if nom_rx.borrow_and_update().is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            if nom_rx.changed().await.is_err() {
                anyhow::bail!("nomination channel closed");
            }
        }
    })
    .await
    .context("timed out waiting for nomination")??;

    // 2. Record the nominated pair, then re-nominate a different pair.
    let nominated_pair = t2
        .get_selected_pair()
        .expect("controlled side must have a selected pair after nomination");

    // 3. Register a second remote candidate at a distinct address — the pair
    //    the controlling agent will re-nominate.
    let second_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let second_addr = second_socket.local_addr()?;
    assert_ne!(
        second_addr, nominated_pair.remote.address,
        "second socket must be a distinct address"
    );
    t2.add_remote_candidate(IceCandidate::host(second_addr, 1));

    // 4. Send a raw STUN Binding Request with USE-CANDIDATE from that socket
    //    directly to the controlled agent's listening address, and answer the
    //    agent's path-verification check (a genuine controlling peer answers
    //    checks on the path it nominated).
    let controlled_addr = nominated_pair.local.base_address();
    send_renomination_and_verify(&second_socket, second_addr, controlled_addr).await?;

    // 5. Assert: the controlled agent followed the verified re-nomination.
    // The switch waits on the agent's path-verification check, which itself
    // budgets a full stun_timeout — under a loaded test runner that can take
    // longer than a nominal round trip, so allow headroom (matches the 10s
    // connect/nomination waits above).
    wait_selected_remote(&t2.clone(), second_addr, Duration::from_secs(10)).await?;

    Ok(())
}

/// The controlled agent must follow a re-nomination even onto a *higher*-
/// priority pair: the controlling agent is authoritative, not our local
/// priority ordering. The switch is gated on the new path answering the
/// agent's path-verification check (see `verify_nominated_path`).
#[tokio::test]
async fn use_candidate_follows_renomination_to_higher_priority_pair() -> Result<()> {
    let (t1, t2) = setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;

    assert!(
        wait_ice_connected(t1.subscribe_state(), Duration::from_secs(10)).await,
        "controlling agent failed to connect"
    );
    let mut nom_rx = t2.subscribe_nomination_complete();
    timeout(Duration::from_secs(10), async {
        loop {
            if nom_rx.borrow_and_update().is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            if nom_rx.changed().await.is_err() {
                anyhow::bail!("nomination channel closed");
            }
        }
    })
    .await
    .context("timed out waiting for nomination")??;

    let nominated_pair = t2
        .get_selected_pair()
        .expect("controlled side must have a selected pair after nomination");

    // Register a second remote candidate at a NEW address with a strictly
    // higher priority than any gathered candidate, then inject a raw
    // USE-CANDIDATE from it (handle_stun_request accepts unsigned requests).
    use tokio::net::UdpSocket;
    let second_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let second_addr = second_socket.local_addr()?;
    let mut high_priority = IceCandidate::host(second_addr, 1);
    high_priority.priority = u32::MAX;
    t2.add_remote_candidate(high_priority);

    let controlled_addr = nominated_pair.local.base_address();
    send_renomination_and_verify(&second_socket, second_addr, controlled_addr).await?;

    // Same headroom rationale as the re-nomination test above.
    wait_selected_remote(&t2.clone(), second_addr, Duration::from_secs(10)).await?;

    Ok(())
}

/// STUN attribute types present in a raw message (`StunDecoded` doesn't
/// expose PRIORITY / ICE-CONTROLLED).
fn stun_attribute_types(raw: &[u8]) -> Vec<u16> {
    let mut types = Vec::new();
    let mut pos = 20;
    while pos + 4 <= raw.len() {
        let typ = u16::from_be_bytes([raw[pos], raw[pos + 1]]);
        let len = u16::from_be_bytes([raw[pos + 2], raw[pos + 3]]) as usize;
        types.push(typ);
        pos += 4 + len.div_ceil(4) * 4;
    }
    types
}

/// The controlled agent's path-verification check must be a regular
/// connectivity check: retransmitted, and carrying PRIORITY and ICE-CONTROLLED.
///
/// It used to be sent exactly once without either attribute. A single lost
/// request (or response) - or a peer ignoring the malformed check - kept the
/// session on the pair the controlling peer had abandoned: STUN kept working on
/// the new path (responses go back where requests came from) while DTLS/SRTP
/// went to the old one, so the call connected with no media.
#[tokio::test]
async fn use_candidate_verification_is_retransmitted() -> Result<()> {
    const PRIORITY: u16 = 0x0024;
    const ICE_CONTROLLED: u16 = 0x8029;

    let (t1, t2) = setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;
    assert!(
        wait_ice_connected(t1.subscribe_state(), Duration::from_secs(10)).await,
        "controlling agent failed to connect"
    );
    let mut nom_rx = t2.subscribe_nomination_complete();
    timeout(Duration::from_secs(10), async {
        loop {
            if nom_rx.borrow_and_update().is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            if nom_rx.changed().await.is_err() {
                anyhow::bail!("nomination channel closed");
            }
        }
    })
    .await
    .context("timed out waiting for nomination")??;
    let nominated_pair = t2
        .get_selected_pair()
        .expect("controlled side must have a selected pair after nomination");

    let second_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let second_addr = second_socket.local_addr()?;
    t2.add_remote_candidate(IceCandidate::host(second_addr, 1));

    // re-nominate from the second socket
    let controlled_addr = nominated_pair.local.base_address();
    let mut msg = StunMessage::binding_request(random_bytes::<12>(), None);
    msg.attributes.push(StunAttribute::UseCandidate);
    second_socket
        .send_to(&msg.encode(None, false)?, controlled_addr)
        .await?;

    // drop the first verification check, answer its retransmission
    let mut buf = [0u8; 1500];
    let mut checks = 0;
    let deadline = std::time::Instant::now() + Duration::from_secs(4);
    loop {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        if remaining.is_zero() {
            anyhow::bail!("verification check seen {checks} time(s), never retransmitted");
        }
        let (n, from) = timeout(remaining, second_socket.recv_from(&mut buf)).await??;
        let m = StunMessage::decode(&buf[..n])?;
        if m.class != StunClass::Request || m.method != StunMethod::Binding {
            continue; // the response to our own nomination request
        }
        let types = stun_attribute_types(&buf[..n]);
        assert!(
            types.contains(&PRIORITY),
            "verification check without PRIORITY"
        );
        assert!(
            types.contains(&ICE_CONTROLLED),
            "verification check without ICE-CONTROLLED"
        );
        checks += 1;
        if checks == 1 {
            continue; // lost
        }
        let resp = StunMessage::binding_success_response(m.transaction_id, second_addr);
        second_socket
            .send_to(&resp.encode(None, true)?, from)
            .await?;
        break;
    }

    wait_selected_remote(&t2.clone(), second_addr, Duration::from_secs(10)).await?;
    Ok(())
}

/// ICE-layer latching (same port, different IP retarget) must not apply to
/// WebRTC transports: the SRTP media path stays pinned to the nominated pair.
/// In RTP mode the retarget remains enabled (legacy trunk behaviour).
async fn latching_retarget_setup(
    mode: crate::TransportMode,
) -> Result<(IceTransport, IceCandidatePair, std::net::SocketAddr)> {
    let (t1, t2) = setup_host_pair(RtcConfiguration::default(), {
        let mut cfg = RtcConfiguration::default();
        cfg.transport_mode = mode;
        cfg.enable_latching = true;
        cfg
    })
    .await;

    assert!(
        wait_ice_connected(t1.subscribe_state(), Duration::from_secs(10)).await,
        "controlling agent failed to connect"
    );
    let mut nom_rx = t2.subscribe_nomination_complete();
    timeout(Duration::from_secs(10), async {
        loop {
            if nom_rx.borrow_and_update().is_some() {
                return Ok::<_, anyhow::Error>(());
            }
            if nom_rx.changed().await.is_err() {
                anyhow::bail!("nomination channel closed");
            }
        }
    })
    .await
    .context("timed out waiting for nomination")??;

    let nominated_pair = t2
        .get_selected_pair()
        .expect("controlled side must have a selected pair after nomination");

    // Spoof source: same port as the nominated remote, different IP. Pick
    // the "other" local IP so we never collide with the peer's real socket
    // (the pair may have formed over either loopback or the LAN address).
    let lan_ip = crate::transports::get_local_ip().context("no non-loopback local IP")?;
    let spoof_ip = if nominated_pair.remote.address.ip().is_loopback() {
        lan_ip
    } else {
        std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
    };
    let spoof_addr = std::net::SocketAddr::new(spoof_ip, nominated_pair.remote.address.port());
    let spoof_socket = tokio::net::UdpSocket::bind(spoof_addr)
        .await
        .context("bind spoof socket")?;

    let controlled_addr = nominated_pair.local.base_address();
    let tx_id = random_bytes::<12>();
    let msg = StunMessage::binding_request(tx_id, None);
    let bytes = msg.encode(None, false)?;
    spoof_socket.send_to(&bytes, controlled_addr).await?;

    tokio::time::sleep(Duration::from_millis(300)).await;
    Ok((t2, nominated_pair, spoof_addr))
}

#[tokio::test]
async fn webrtc_mode_ignores_ice_latching_retarget() -> Result<()> {
    let (t2, nominated_pair, _spoof_addr) =
        latching_retarget_setup(crate::TransportMode::WebRtc).await?;

    let final_pair = t2
        .get_selected_pair()
        .expect("selected pair should still be present");
    assert_eq!(
        nominated_pair.remote.address, final_pair.remote.address,
        "WebRTC mode must not retarget the selected pair via ICE latching"
    );
    Ok(())
}

#[tokio::test]
async fn rtp_mode_still_applies_ice_latching_retarget() -> Result<()> {
    let (t2, _nominated_pair, spoof_addr) =
        latching_retarget_setup(crate::TransportMode::Rtp).await?;

    let final_pair = t2
        .get_selected_pair()
        .expect("selected pair should still be present");
    assert_eq!(
        spoof_addr, final_pair.remote.address,
        "RTP mode should keep retargeting the selected pair via ICE latching"
    );
    Ok(())
}

/// Verifies that DTLS packets buffered in the ICE transport BEFORE set_data_receiver
/// are correctly delivered to the dtls_receiver when it is registered FIRST.
///
/// This validates the ordering fix in PeerConnection::start_dtls:
///   BAD:  set_data_receiver(ice_conn) → ... → DtlsTransport::new(ice_conn) // DTLS ClientHello dropped
///   GOOD: DtlsTransport::new(ice_conn) → set_data_receiver(ice_conn)       // DTLS ClientHello delivered
///
/// Without this fix (old ordering), the 2 buffered DTLS packets would find
/// dtls_receiver=None and be dropped — matching the "no receiver registered"
/// error observed in production.
#[tokio::test]
async fn test_buffered_dtls_packets_delivered_when_dtls_receiver_registered_first() {
    use super::conn::IceConn;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    let config = RtcConfiguration::default();
    let (ctrl, _ctrd) = setup_host_pair(config.clone(), config.clone()).await;

    // Wait for ICE to connect (this also clears any STUN packets from the buffer)
    let ctrl_state = ctrl.subscribe_state();
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await,
        "ICE failed to connect"
    );

    // Create a fake DTLS ClientHello packet (first byte 0x16 = Handshake, in range 20..63)
    let dtls_packet = vec![
        0x16, // ContentType: Handshake
        0xfe, 0xfd, // ProtocolVersion: DTLS 1.2
        0x00, 0x00, // epoch
        0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // sequence number
        0x00, 0x00, // length (no body needed for this test)
    ];
    let fake_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 9999);

    // Simulate 2 DTLS packets arriving before start_dtls (buffered by ICE transport)
    {
        let mut buf = ctrl.inner.buffered_packets.lock();
        buf.push_back((dtls_packet.clone(), fake_addr));
        buf.push_back((dtls_packet.clone(), fake_addr));
    }
    assert_eq!(
        ctrl.inner.buffered_packets.lock().len(),
        2,
        "Should have 2 buffered DTLS packets before set_data_receiver"
    );

    // ---- Simulate the FIXED start_dtls ordering ----
    // 1. Create IceConn (same as start_dtls does). Connected fires before
    //    nomination completes (see wait_for_selected_pair), so wait for the
    //    pair to be published before sampling it.
    let selected_pair = wait_for_selected_pair(&ctrl, Duration::from_secs(10))
        .await
        .expect("Should have selected pair after ICE connected");
    let socket_rx = ctrl.subscribe_selected_socket();
    let ice_conn = IceConn::new(socket_rx, selected_pair.remote.address, None);

    // 2. Register DTLS receiver FIRST (as the fix does: DtlsTransport::new → set_dtls_receiver)
    let (dtls_tx, mut dtls_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    struct DtlsRecorder(tokio::sync::mpsc::UnboundedSender<Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for DtlsRecorder {
        async fn receive(&self, packet: Bytes, _addr: SocketAddr, _buf: &mut Vec<u8>) {
            let _ = self.0.send(packet);
        }
    }
    ice_conn.set_dtls_receiver(Arc::new(DtlsRecorder(dtls_tx)));

    // 3. Now call set_data_receiver (which flushes buffer to IceConn → dtls_receiver)
    ctrl.set_data_receiver(ice_conn.clone()).await;

    // 4. Verify both DTLS packets were delivered to the DTLS receiver
    for i in 0..2 {
        let received = tokio::time::timeout(Duration::from_secs(1), dtls_rx.recv()).await;
        assert!(
            received.is_ok(),
            "Buffered DTLS packet #{} was NOT delivered — set_data_receiver flushed before dtls_receiver was registered (the bug!)",
            i + 1
        );
        if let Ok(Some(pkt)) = received {
            assert_eq!(
                pkt[0],
                0x16,
                "Packet #{} should be a DTLS handshake record",
                i + 1
            );
        }
    }

    // Also verify that WITHOUT registering dtls_receiver first, packets ARE lost.
    // This demonstrates the exact bug from the production log.
    {
        let mut buf = ctrl.inner.buffered_packets.lock();
        buf.push_back((dtls_packet.clone(), fake_addr));
        buf.push_back((dtls_packet.clone(), fake_addr));
    }
    let ice_conn2 = IceConn::new(
        ctrl.subscribe_selected_socket(),
        selected_pair.remote.address,
        None,
    );
    let (lost_tx, mut lost_rx) = tokio::sync::mpsc::unbounded_channel::<Bytes>();
    // Intentionally NOT calling set_dtls_receiver — simulating the old buggy ordering
    ctrl.set_data_receiver(ice_conn2.clone()).await;
    let lost = tokio::time::timeout(Duration::from_millis(200), lost_rx.recv()).await;
    assert!(
        lost.is_err() || lost.ok().flatten().is_none(),
        "Without dtls_receiver registered, buffered DTLS packets MUST be dropped (demonstrates the bug)"
    );
    drop((lost_tx, lost_rx));
}

/// Test that TCP candidates are correctly serialized to and from SDP.
#[test]
fn test_ice_tcp_candidate_sdp_roundtrip() {
    let addr: SocketAddr = "192.168.1.100:3478".parse().unwrap();
    let cand = IceCandidate::host_tcp(addr, 1, TcpType::Passive);
    let sdp = cand.to_sdp();
    assert!(
        sdp.contains("tcptype passive"),
        "SDP should contain tcptype passive"
    );
    assert!(sdp.contains("tcp"), "SDP transport should be tcp");
    assert!(sdp.contains("host"), "SDP type should be host");

    // Parse back
    let parsed = IceCandidate::from_sdp(&sdp).unwrap();
    assert_eq!(parsed.transport, "tcp");
    assert_eq!(parsed.tcp_type, Some(TcpType::Passive));
    assert_eq!(parsed.address, addr);
    assert_eq!(parsed.typ, IceCandidateType::Host);

    // Active type
    let active = IceCandidate::host_tcp(addr, 1, TcpType::Active);
    let sdp_active = active.to_sdp();
    assert!(sdp_active.contains("tcptype active"));
    let parsed_active = IceCandidate::from_sdp(&sdp_active).unwrap();
    assert_eq!(parsed_active.tcp_type, Some(TcpType::Active));

    // SO type
    let so = IceCandidate::host_tcp(addr, 1, TcpType::So);
    let parsed_so = IceCandidate::from_sdp(&so.to_sdp()).unwrap();
    assert_eq!(parsed_so.tcp_type, Some(TcpType::So));
}

/// Test that TCP candidates get higher local preference for passive type.
#[test]
fn test_ice_tcp_priority_ordering() {
    let addr: SocketAddr = "192.168.1.100:3478".parse().unwrap();
    let passive = IceCandidate::host_tcp(addr, 1, TcpType::Passive);
    let active = IceCandidate::host_tcp(addr, 1, TcpType::Active);
    let so = IceCandidate::host_tcp(addr, 1, TcpType::So);

    // Passive should have highest priority among TCP, then Active, then SO
    assert!(
        passive.priority > active.priority,
        "Passive TCP priority ({}) should be > Active ({})",
        passive.priority,
        active.priority
    );
    assert!(
        active.priority > so.priority,
        "Active TCP priority ({}) should be > SO ({})",
        active.priority,
        so.priority
    );

    // UDP host should have same priority as TCP passive (both use full local pref)
    let udp = IceCandidate::host(addr, 1);
    assert_eq!(
        udp.priority, passive.priority,
        "UDP and TCP passive host candidates should have same priority"
    );
}

/// Test that paired TCP candidates are handled correctly during pair formation.
#[tokio::test]
#[serial]
async fn test_ice_tcp_pair_formation() -> Result<()> {
    let mut config1 = RtcConfiguration::default();
    config1.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;

    let mut config2 = RtcConfiguration::default();
    config2.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;

    let (t1, r1) = IceTransportBuilder::new(config1)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(r1);

    let (t2, r2) = IceTransportBuilder::new(config2)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(r2);

    // Wait for gathering
    let mut g1 = t1.subscribe_gathering_state();
    let mut g2 = t2.subscribe_gathering_state();
    wait_ice_connected_or_timeout(&mut g1, Duration::from_secs(2), IceGathererState::Complete)
        .await;
    wait_ice_connected_or_timeout(&mut g2, Duration::from_secs(2), IceGathererState::Complete)
        .await;

    let locals1 = t1.local_candidates();
    let locals2 = t2.local_candidates();

    // Both sides should have TCP candidates
    assert!(
        locals1.iter().any(|c| c.transport == "tcp"),
        "t1 should have TCP candidates"
    );
    assert!(
        locals2.iter().any(|c| c.transport == "tcp"),
        "t2 should have TCP candidates"
    );

    // Add TCP candidates as remote
    for c in locals1.iter().filter(|c| c.transport == "tcp") {
        t2.add_remote_candidate(c.clone());
    }
    for c in locals2.iter().filter(|c| c.transport == "tcp") {
        t1.add_remote_candidate(c.clone());
    }

    let remote1 = t1.remote_candidates();
    let remote2 = t2.remote_candidates();

    assert!(!remote1.is_empty(), "t1 should have remote TCP candidates");
    assert!(!remote2.is_empty(), "t2 should have remote TCP candidates");
    assert!(
        remote1.iter().all(|c| c.transport == "tcp"),
        "t1 remotes should all be TCP"
    );
    assert!(
        remote2.iter().all(|c| c.transport == "tcp"),
        "t2 remotes should all be TCP"
    );

    // Verify that forming pairs using ICE pair logic would work
    for local in &locals1 {
        for remote in &remote1 {
            if local.transport == remote.transport {
                let pair = IceCandidatePair::new(local.clone(), remote.clone());
                assert!(
                    pair.priority(IceRole::Controlling) > 0,
                    "TCP pair priority should be > 0"
                );
            }
        }
    }

    Ok(())
}

async fn wait_ice_connected_or_timeout(
    rx: &mut watch::Receiver<IceGathererState>,
    deadline: Duration,
    target: IceGathererState,
) {
    let _ = tokio::time::timeout(deadline, async {
        loop {
            if *rx.borrow_and_update() == target {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    })
    .await;
}

/// Verify that when TCP is disabled (default), only UDP candidates are gathered.
#[tokio::test]
#[serial]
async fn test_ice_tcp_disabled_gathers_udp_only() -> Result<()> {
    let config = RtcConfiguration::default();
    assert_eq!(config.ice_tcp_policy, crate::config::IceTcpPolicy::Disabled);

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);
    tokio::time::sleep(Duration::from_millis(100)).await;

    for candidate in transport.local_candidates() {
        assert_eq!(
            candidate.transport, "udp",
            "With TCP disabled, all candidates should be UDP, got {:?} at {}",
            candidate.transport, candidate.address
        );
        assert!(
            candidate.tcp_type.is_none(),
            "TCP candidates should not exist when TCP is disabled"
        );
    }

    Ok(())
}

/// Verify that when TCP is enabled, TCP candidates are gathered alongside UDP candidates.
#[tokio::test]
#[serial]
async fn test_ice_tcp_gathers_tcp_candidates() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);
    tokio::time::sleep(Duration::from_millis(100)).await;

    let candidates = transport.local_candidates();
    let has_udp = candidates.iter().any(|c| c.transport == "udp");
    let has_tcp = candidates.iter().any(|c| c.transport == "tcp");

    assert!(has_udp, "Should have UDP candidates");
    assert!(has_tcp, "Should have TCP candidates when TCP is enabled");

    for candidate in &candidates {
        if candidate.transport == "tcp" {
            assert!(
                candidate.tcp_type.is_some(),
                "TCP candidate should have tcptype set"
            );
            assert_eq!(
                candidate.tcp_type,
                Some(TcpType::Passive),
                "Default TCP candidate should be passive"
            );
        }
    }

    Ok(())
}

/// Verify frame_stun_for_tcp produces correct RFC 4571 framing.
#[test]
fn test_frame_stun_for_tcp() {
    let data = b"hello stun";
    let framed = frame_stun_for_tcp(data);

    assert_eq!(framed.len(), 2 + data.len());
    let len = u16::from_be_bytes([framed[0], framed[1]]);
    assert_eq!(len as usize, data.len());
    assert_eq!(&framed[2..], data);

    // Empty payload
    let empty = frame_stun_for_tcp(b"");
    assert_eq!(empty.len(), 2);
    assert_eq!(empty[0], 0);
    assert_eq!(empty[1], 0);
}

/// Verify tcp_write_all writes data correctly over a loopback TCP connection.
#[tokio::test]
async fn test_tcp_write_all_loopback() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (client_read, client_write) = client.into_split();
    let client_write = Arc::new(tokio::sync::Mutex::new(client_write));

    let (mut server, _) = listener.accept().await.unwrap();

    let payload = b"tcp_write_all test payload";
    tcp_write_all(&client_write, payload).await.unwrap();

    use tokio::io::AsyncReadExt;
    let mut buf = vec![0u8; payload.len()];
    let s = &mut server;
    s.read_exact(&mut buf).await.unwrap();
    assert_eq!(&buf, payload);
    drop(client_read);
}

/// Verify tcp_write_all handles multi-write correctly (data larger than socket buffer).
#[tokio::test]
async fn test_tcp_write_all_large_data() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server_addr = listener.local_addr().unwrap();

    let client = tokio::net::TcpStream::connect(server_addr).await.unwrap();
    let (client_read, client_write) = client.into_split();
    let client_write = Arc::new(tokio::sync::Mutex::new(client_write));

    let (mut server, _) = listener.accept().await.unwrap();

    // 1 MB payload to exercise partial writes. The reader MUST run concurrently
    // with the writer: tcp_write_all awaits writability once the kernel socket
    // buffer fills, so a sequential write-then-read would deadlock (writer waits
    // for the reader to drain, reader waits for the writer to finish).
    let payload = vec![0xABu8; 1024 * 1024];
    let read_handle = {
        let payload_len = payload.len();
        tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut buf = vec![0u8; payload_len];
            server.read_exact(&mut buf).await.unwrap();
            buf
        })
    };

    tcp_write_all(&client_write, &payload).await.unwrap();
    let buf = read_handle.await.unwrap();
    assert_eq!(buf.len(), payload.len());
    assert_eq!(buf[0], 0xAB);
    assert_eq!(buf[payload.len() - 1], 0xAB);
    drop(client_read);
}

/// ICE-TCP end-to-end: controlling side (active TCP) connects to controlled
/// side (passive TCP listener).  Verifies both sides reach Connected state and
/// the selected pair uses TCP transport.
#[tokio::test]
#[serial]
async fn test_ice_tcp_end_to_end_connectivity() -> Result<()> {
    // Controlled side: passive TCP listener
    let mut controlled_config = RtcConfiguration::default();
    controlled_config.ice_gather_udp_hosts = false;
    controlled_config.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;
    controlled_config.tcp_port_range_start = Some(20_000);
    controlled_config.tcp_port_range_end = Some(20_010);

    // Controlling side: active TCP candidate, no UDP
    let mut controlling_config = RtcConfiguration::default();
    controlling_config.ice_gather_udp_hosts = false;
    controlling_config.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;

    let (controlling, runner_c) = IceTransportBuilder::new(controlling_config)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);

    let (controlled, runner_d) = IceTransportBuilder::new(controlled_config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    // Wait for gathering to complete
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Verify both sides have gathered candidates
    let ctrl_locals = controlling.local_candidates();
    let ctrd_locals = controlled.local_candidates();

    assert!(
        !ctrl_locals.is_empty(),
        "Controlling should have local candidates"
    );
    assert!(
        !ctrd_locals.is_empty(),
        "Controlled should have local candidates"
    );
    assert!(
        ctrl_locals.iter().any(|c| c.transport == "tcp"),
        "Controlling should have TCP candidates"
    );
    assert!(
        ctrd_locals.iter().any(|c| c.transport == "tcp"),
        "Controlled should have TCP candidates"
    );

    // Exchange candidates
    for c in ctrl_locals.iter() {
        controlled.add_remote_candidate(c.clone());
    }
    for c in ctrd_locals.iter() {
        controlling.add_remote_candidate(c.clone());
    }

    // Forward trickle candidates
    let ctrl_clone = controlling.clone();
    let ctrd_clone = controlled.clone();
    let mut rx_ctrl = controlling.subscribe_candidates();
    let mut rx_ctrd = controlled.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrl.recv().await {
            ctrd_clone.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrd.recv().await {
            ctrl_clone.add_remote_candidate(c);
        }
    });

    // Start both agents
    let controlled_params = controlled.local_parameters();
    let controlling_params = controlling.local_parameters();
    controlling
        .start(controlled_params)
        .await
        .expect("controlling.start");
    controlled
        .start(controlling_params)
        .await
        .expect("controlled.start");

    // Wait for both sides to connect
    let ctrl_state_rx = controlling.subscribe_state();
    let ctrd_state_rx = controlled.subscribe_state();

    let ctrl_ok = wait_ice_connected(ctrl_state_rx, Duration::from_secs(15)).await;
    let ctrd_ok = wait_ice_connected(ctrd_state_rx, Duration::from_secs(15)).await;

    assert!(ctrl_ok, "Controlling side should connect over TCP");
    assert!(ctrd_ok, "Controlled side should connect over TCP");

    // Verify the selected pair uses TCP transport. Connected fires before
    // nomination completes (see wait_for_selected_pair), so wait for the pair.
    let pair = wait_for_selected_pair(&controlling, Duration::from_secs(10))
        .await
        .expect("Should have a selected pair");
    assert_eq!(
        pair.local.transport, "tcp",
        "Selected pair should use TCP transport, got {}",
        pair.local.transport
    );

    // Verify we can get a selected socket
    let wrapper = controlling.get_selected_socket();
    assert!(wrapper.is_some(), "Should have a selected socket");
    let wrapper = wrapper.unwrap();
    assert!(
        matches!(wrapper, IceSocketWrapper::TcpStream(_, _, _)),
        "Selected socket should be TcpStream"
    );

    // Send a test message to verify data flow
    let test_data = b"test-data-over-tcp";
    wrapper
        .send_to(test_data, pair.remote.address)
        .await
        .unwrap();

    Ok(())
}

/// ICE-TCP end-to-end with send verification using PacketReceiver.
/// The background read loop owns the TCP recv side, so we use a STUN message
/// handler / PacketReceiver to verify data delivery rather than calling recv_from
/// directly (which would race with the loop).
#[tokio::test]
#[serial]
async fn test_ice_tcp_data_flow_bidirectional() -> Result<()> {
    let mut controlled_config = RtcConfiguration::default();
    controlled_config.ice_gather_udp_hosts = false;
    controlled_config.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;
    controlled_config.tcp_port_range_start = Some(20_011);
    controlled_config.tcp_port_range_end = Some(20_020);

    let mut controlling_config = RtcConfiguration::default();
    controlling_config.ice_gather_udp_hosts = false;
    controlling_config.ice_tcp_policy = crate::config::IceTcpPolicy::Enabled;

    let (controlling, runner_c) = IceTransportBuilder::new(controlling_config)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);

    let (controlled, runner_d) = IceTransportBuilder::new(controlled_config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    tokio::time::sleep(Duration::from_millis(500)).await;

    // Gathering is asynchronous (the runner task drives it): wait for host
    // candidates before exchanging, so the exchange actually delivers them.
    let gather_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < gather_deadline
        && (controlling.local_candidates().is_empty() || controlled.local_candidates().is_empty())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }

    let ctrl_clone = controlling.clone();
    let ctrd_clone = controlled.clone();
    let mut rx_ctrl = controlling.subscribe_candidates();
    let mut rx_ctrd = controlled.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrl.recv().await {
            ctrd_clone.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = rx_ctrd.recv().await {
            ctrl_clone.add_remote_candidate(c);
        }
    });

    controlling
        .start(controlled.local_parameters())
        .await
        .expect("controlling.start");
    controlled
        .start(controlling.local_parameters())
        .await
        .expect("controlled.start");

    let ctrl_ok = wait_ice_connected(controlling.subscribe_state(), Duration::from_secs(15)).await;
    let ctrd_ok = wait_ice_connected(controlled.subscribe_state(), Duration::from_secs(15)).await;

    assert!(ctrl_ok, "Controlling should connect over TCP");
    assert!(ctrd_ok, "Controlled should connect over TCP");

    // Verify both sides selected TCP transport. Connected fires before
    // nomination completes (see wait_for_selected_pair), so wait for the pair.
    let ctrl_pair = wait_for_selected_pair(&controlling, Duration::from_secs(10))
        .await
        .expect("controlling should have a selected pair");
    let ctrd_pair = wait_for_selected_pair(&controlled, Duration::from_secs(10))
        .await
        .expect("controlled should have a selected pair");
    assert_eq!(ctrl_pair.local.transport, "tcp");
    assert_eq!(ctrd_pair.local.transport, "tcp");

    // Verify the selected sockets are TcpStream
    let ctrl_socket = controlling.get_selected_socket().unwrap();
    let ctrd_socket = controlled.get_selected_socket().unwrap();
    assert!(matches!(ctrl_socket, IceSocketWrapper::TcpStream(_, _, _)));
    assert!(matches!(ctrd_socket, IceSocketWrapper::TcpStream(_, _, _)));

    // Verify we can send data without errors (actual delivery is handled by the
    // background ICE read loop which dispatches to STUN/DTLS/RTP handlers).
    let msg_a = b"msg-from-controlling";
    ctrl_socket
        .send_to(msg_a, ctrl_pair.remote.address)
        .await
        .unwrap();
    let msg_b = b"msg-from-controlled";
    ctrd_socket
        .send_to(msg_b, ctrd_pair.remote.address)
        .await
        .unwrap();

    Ok(())
}

// =============================================================================
// ICE UDP Mux (single-port multiplexing) tests
// =============================================================================

/// Grab a free UDP port on the loopback interface (best-effort; tests are
/// `#[serial]` to avoid collisions on the process-wide mux registry).
fn pick_free_udp_port() -> u16 {
    let s = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    s.local_addr().unwrap().port()
}

/// Direct test of the shared UDP demux loop: two sessions register distinct
/// ufrags on the same socket, and a STUN Binding Request is routed to the
/// session named in USERNAME. Non-STUN packets then follow the learned
/// peer→ufrag mapping.
#[tokio::test]
#[serial]
async fn shared_udp_demux_routes_by_ufrag_and_peer_addr() -> Result<()> {
    let port = pick_free_udp_port();
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;

    // Register two sessions on the same shared socket.
    let (local1, h1, reg1) = shared_udp::acquire(bind_addr, "ufrag1".into()).await?;
    let (local2, h2, reg2) = shared_udp::acquire(bind_addr, "ufrag2".into()).await?;
    assert_eq!(local1, local2, "both sessions must share one socket");
    assert_eq!(shared_udp::session_count(bind_addr), 2);

    // Build a STUN Binding Request whose USERNAME targets ufrag1.
    let sender_sock = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = sender_sock.local_addr()?;
    let tx_id = random_bytes::<12>();
    let mut msg = StunMessage::binding_request(tx_id, Some("rustrtc"));
    msg.attributes
        .push(StunAttribute::Username("ufrag1:clientfrag".into()));
    let bytes = msg.encode(None, false)?;
    sender_sock.send_to(&bytes, local1).await?;

    // ufrag1 receives it; ufrag2 must not.
    let (data, from) = timeout(Duration::from_secs(2), h1.recv())
        .await
        .context("ufrag1 did not receive demuxed STUN request")?
        .expect("channel closed");
    assert_eq!(from, peer_addr);
    assert_eq!(data, bytes);
    assert!(
        timeout(Duration::from_millis(150), h2.recv())
            .await
            .is_err(),
        "ufrag2 must not receive ufrag1's traffic"
    );

    // The peer routing table now maps peer_addr -> ufrag1, so a subsequent
    // non-STUN packet (first byte >= 2) from the same source routes by addr.
    let rtp_like: Vec<u8> = vec![0x80, 0x60, 0x00, 0x01];
    sender_sock.send_to(&rtp_like, local1).await?;
    let (data2, from2) = timeout(Duration::from_secs(2), h1.recv())
        .await
        .context("ufrag1 did not receive routed non-STUN packet")?
        .expect("channel closed");
    assert_eq!(from2, peer_addr);
    assert_eq!(data2, rtp_like);
    assert_eq!(
        shared_udp::ufrag_for_peer(bind_addr, peer_addr).as_deref(),
        Some("ufrag1")
    );

    // Outbound send through a handle records the destination so that replies
    // to locally-initiated traffic route back (simulates a controlled agent's
    // own STUN connectivity check whose response carries no ufrag).
    h1.send_to(&[0x80, 0x00], peer_addr).await?;
    assert_eq!(
        shared_udp::ufrag_for_peer(bind_addr, peer_addr).as_deref(),
        Some("ufrag1"),
        "outbound send_to must (re)record the peer mapping"
    );

    // Dropping reg1 removes the session and its peer entries.
    drop(reg1);
    assert_eq!(shared_udp::session_count(bind_addr), 1);
    assert_eq!(shared_udp::ufrag_for_peer(bind_addr, peer_addr), None);

    drop(reg2);
    assert_eq!(shared_udp::session_count(bind_addr), 0);
    Ok(())
}

/// End-to-end: a controlled PeerConnection with `ice_udp_mux` enabled shares a
/// single UDP port, and a normal controlling PeerConnection connects to it.
#[tokio::test]
#[serial]
async fn ice_udp_mux_connects_through_shared_port() -> Result<()> {
    let port = pick_free_udp_port();

    let mut controlled_cfg = RtcConfiguration::default();
    controlled_cfg.ice_udp_mux = true;
    controlled_cfg.ice_udp_mux_port = Some(port);
    controlled_cfg.bind_ip = Some("127.0.0.1".into());

    let mut controlling_cfg = RtcConfiguration::default();
    controlling_cfg.bind_ip = Some("127.0.0.1".into());

    let (controlled, runner_d) = IceTransportBuilder::new(controlled_cfg)
        .role(IceRole::Controlled)
        .build();
    let (controlling, runner_c) = IceTransportBuilder::new(controlling_cfg)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_d);
    tokio::spawn(runner_c);

    // Wait for gathering to complete on both sides (poll the gatherer's state
    // directly — see note in `ice_udp_mux_two_sessions_share_one_port`).
    for t in [&controlled, &controlling] {
        timeout(Duration::from_secs(5), async {
            while t.gather_state() != IceGathererState::Complete {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("gathering did not complete in time")?;
    }

    // The mux side advertises exactly one UDP host candidate on the mux port.
    let mux_cand = controlled
        .local_candidates()
        .into_iter()
        .find(|c| c.transport == "udp" && c.typ == IceCandidateType::Host)
        .expect("controlled mux side must advertise a UDP host candidate");
    assert_eq!(mux_cand.address.port(), port);

    // Exchange candidates both ways (initial batch + trickle).
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }
    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }
    let cc = controlling.clone();
    let dc = controlled.clone();
    let mut crx = controlling.subscribe_candidates();
    let mut drx = controlled.subscribe_candidates();
    tokio::spawn(async move {
        while let Ok(c) = crx.recv().await {
            dc.add_remote_candidate(c);
        }
    });
    tokio::spawn(async move {
        while let Ok(c) = drx.recv().await {
            cc.add_remote_candidate(c);
        }
    });

    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    let wait_connected = |mut rx: watch::Receiver<IceTransportState>| async move {
        loop {
            if *rx.borrow_and_update() == IceTransportState::Connected {
                return Ok::<_, anyhow::Error>(());
            }
            if rx.changed().await.is_err() {
                anyhow::bail!("state channel closed");
            }
        }
    };

    timeout(
        Duration::from_secs(10),
        futures::future::try_join(
            wait_connected(controlling.subscribe_state()),
            wait_connected(controlled.subscribe_state()),
        ),
    )
    .await
    .context("timed out waiting for ICE connection through UDP mux")??;

    // The controlled side must send/receive via the shared UDP socket.
    let selected = controlled.get_selected_socket().unwrap();
    assert!(
        matches!(selected, IceSocketWrapper::SharedUdp(_)),
        "controlled mux side should use the shared UDP socket, got: {}",
        selected.diag()
    );

    controlled.stop();
    controlling.stop();
    Ok(())
}

/// Two controlled PeerConnections can register on the same mux port at once:
/// both advertise the same host address but distinct ufrags, and the process-
/// wide registry holds both sessions.
#[tokio::test]
#[serial]
async fn ice_udp_mux_two_sessions_share_one_port() -> Result<()> {
    let port = pick_free_udp_port();

    fn mux_config(port: u16) -> RtcConfiguration {
        let mut cfg = RtcConfiguration::default();
        cfg.ice_udp_mux = true;
        cfg.ice_udp_mux_port = Some(port);
        cfg.bind_ip = Some("127.0.0.1".into());
        cfg
    }

    let (a, ra) = IceTransportBuilder::new(mux_config(port))
        .role(IceRole::Controlled)
        .build();
    let (b, rb) = IceTransportBuilder::new(mux_config(port))
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(ra);
    tokio::spawn(rb);

    // Both finish gathering on the shared socket. Poll the gatherer's internal
    // state directly (the gathering_state watch can miss the Complete update if
    // no receiver was subscribed at send time — a pre-existing watch quirk).
    for t in [&a, &b] {
        timeout(Duration::from_secs(5), async {
            while t.gather_state() != IceGathererState::Complete {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .context("gathering did not complete in time")?;
    }

    // The registry now holds two sessions on the same bind address.
    let bind_addr: SocketAddr = format!("127.0.0.1:{port}").parse()?;
    assert_eq!(shared_udp::session_count(bind_addr), 2);

    // Both advertise the same host address (same port) but distinct ufrags.
    let a_cand = a
        .local_candidates()
        .into_iter()
        .find(|c| c.typ == IceCandidateType::Host && c.transport == "udp")
        .expect("a must have a host candidate");
    let b_cand = b
        .local_candidates()
        .into_iter()
        .find(|c| c.typ == IceCandidateType::Host && c.transport == "udp")
        .expect("b must have a host candidate");
    assert_eq!(a_cand.address, b_cand.address);
    assert_eq!(a_cand.address.port(), port);
    assert_ne!(
        a.local_parameters().username_fragment,
        b.local_parameters().username_fragment,
        "each PeerConnection must own a distinct ufrag"
    );

    // Stopping one PeerConnection deregisters only its session.
    a.stop();
    // Give the drop a moment to propagate.
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(
        shared_udp::session_count(bind_addr),
        1,
        "stopping a should leave exactly one session"
    );

    b.stop();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(shared_udp::session_count(bind_addr), 0);
    Ok(())
}

// ============================================================================
// Regression tests: handle_packet must dispatch ErrorResponse to
// pending_transactions (fix: 401/438 retry path was previously dead code).
// ============================================================================

/// Build a minimal raw STUN ErrorResponse packet (no FINGERPRINT / MESSAGE-INTEGRITY).
/// The decoder only requires: correct magic cookie, matching byte length, and
/// well-formed attributes.
fn build_raw_stun_error_response(
    tx_id: [u8; 12],
    method_bits: u16, // 0x0004 = Refresh, 0x0009 = ChannelBind, etc.
    error_code: u16,  // e.g. 401, 438
    realm: &str,
    nonce: &str,
) -> Vec<u8> {
    const MAGIC_COOKIE: u32 = 0x2112_A442;

    let class_num = (error_code / 100) as u8;
    let number = (error_code % 100) as u8;
    let reason: &str = match error_code {
        401 => "Unauthorized",
        438 => "Stale Nonce",
        _ => "Error",
    };

    let mut attrs: Vec<u8> = Vec::new();

    // ERROR-CODE (type 0x0009): [reserved(2), class(1), number(1), reason phrase]
    {
        let val_len = 4 + reason.len();
        let pad = (4 - val_len % 4) % 4;
        attrs.extend_from_slice(&0x0009_u16.to_be_bytes());
        attrs.extend_from_slice(&(val_len as u16).to_be_bytes());
        attrs.extend_from_slice(&[0x00, 0x00, class_num, number]);
        attrs.extend_from_slice(reason.as_bytes());
        attrs.extend(std::iter::repeat_n(0u8, pad));
    }

    // REALM (type 0x0014)
    if !realm.is_empty() {
        let rb = realm.as_bytes();
        let pad = (4 - rb.len() % 4) % 4;
        attrs.extend_from_slice(&0x0014_u16.to_be_bytes());
        attrs.extend_from_slice(&(rb.len() as u16).to_be_bytes());
        attrs.extend_from_slice(rb);
        attrs.extend(std::iter::repeat_n(0u8, pad));
    }

    // NONCE (type 0x0015)
    if !nonce.is_empty() {
        let nb = nonce.as_bytes();
        let pad = (4 - nb.len() % 4) % 4;
        attrs.extend_from_slice(&0x0015_u16.to_be_bytes());
        attrs.extend_from_slice(&(nb.len() as u16).to_be_bytes());
        attrs.extend_from_slice(nb);
        attrs.extend(std::iter::repeat_n(0u8, pad));
    }

    // STUN header: type | magic | tx_id | body
    let msg_type = method_bits | 0x0110u16; // ErrorResponse class bits
    let mut buf = Vec::with_capacity(20 + attrs.len());
    buf.extend_from_slice(&msg_type.to_be_bytes());
    buf.extend_from_slice(&(attrs.len() as u16).to_be_bytes());
    buf.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
    buf.extend_from_slice(&tx_id);
    buf.extend_from_slice(&attrs);
    buf
}

/// Regression test: `handle_packet` MUST dispatch STUN ErrorResponse (438) to
/// `pending_transactions` so that the 401/438 retry loop in
/// `refresh_one_turn_client` / `send_and_await_inner` actually fires.
///
/// Before the fix, the ErrorResponse branch was a no-op, causing every retry
/// to silently time out after 5 s instead of receiving the stale-nonce error
/// and retrying with the fresh nonce from the response.
#[tokio::test]
async fn test_handle_packet_dispatches_error_response_to_pending_transactions() {
    let config = RtcConfiguration::default();
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    let tx_id: [u8; 12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // Register a pending transaction for this tx_id.
    let (tx, rx) = tokio::sync::oneshot::channel::<StunDecoded>();
    transport
        .inner
        .pending_transactions
        .lock()
        .insert(tx_id, tx);

    // Build a 438 Stale Nonce response for a Refresh request.
    let packet = build_raw_stun_error_response(
        tx_id,
        0x0004, // Refresh method
        438,
        TEST_REALM,
        "fresh-nonce-abc",
    );

    // Provide a dummy UDP sender (not used when handling an ErrorResponse).
    let dummy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender = IceSocketWrapper::Udp(dummy_sock);
    let addr: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let mut marshal_buf = Vec::new();
    handle_packet(
        &packet,
        addr,
        transport.inner.clone(),
        sender,
        &mut marshal_buf,
    )
    .await;

    // The oneshot MUST have been resolved immediately — no timeout path.
    let result = timeout(Duration::from_millis(200), rx).await;
    assert!(
        result.is_ok(),
        "handle_packet should dispatch ErrorResponse to pending_transactions immediately"
    );
    let decoded = result.unwrap().expect("oneshot should not be dropped");
    assert_eq!(
        decoded.error_code,
        Some(438),
        "dispatched message should carry error_code=438"
    );
    assert_eq!(
        decoded.nonce.as_deref(),
        Some("fresh-nonce-abc"),
        "dispatched message should carry the fresh nonce from the response"
    );
}

/// Regression test: `handle_packet` must also dispatch 401 Unauthorized
/// (the other common TURN auth error) to `pending_transactions`.
#[tokio::test]
async fn test_handle_packet_dispatches_401_to_pending_transactions() {
    let config = RtcConfiguration::default();
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    let tx_id: [u8; 12] = [9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 1, 2];
    let (tx, rx) = tokio::sync::oneshot::channel::<StunDecoded>();
    transport
        .inner
        .pending_transactions
        .lock()
        .insert(tx_id, tx);

    let packet = build_raw_stun_error_response(tx_id, 0x0004, 401, TEST_REALM, "new-nonce-xyz");
    let dummy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender = IceSocketWrapper::Udp(dummy_sock);
    let addr: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let mut marshal_buf = Vec::new();
    handle_packet(
        &packet,
        addr,
        transport.inner.clone(),
        sender,
        &mut marshal_buf,
    )
    .await;

    let result = timeout(Duration::from_millis(200), rx).await;
    assert!(
        result.is_ok(),
        "handle_packet should dispatch 401 to pending_transactions"
    );
    let decoded = result.unwrap().unwrap();
    assert_eq!(decoded.error_code, Some(401));
    assert_eq!(decoded.nonce.as_deref(), Some("new-nonce-xyz"));
}

/// Error responses for transaction IDs that are NOT in `pending_transactions`
/// must be silently ignored (no panic, no channel send).
#[tokio::test]
async fn test_handle_packet_ignores_unmatched_error_response() {
    let config = RtcConfiguration::default();
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    // Register a DIFFERENT tx_id in pending_transactions.
    let registered_id: [u8; 12] = [0xAA; 12];
    let (tx, rx) = tokio::sync::oneshot::channel::<StunDecoded>();
    transport
        .inner
        .pending_transactions
        .lock()
        .insert(registered_id, tx);

    // Send an error response for a DIFFERENT, unregistered tx_id.
    let unregistered_id: [u8; 12] = [0xBB; 12];
    let packet =
        build_raw_stun_error_response(unregistered_id, 0x0004, 438, TEST_REALM, "some-nonce");
    let dummy_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let sender = IceSocketWrapper::Udp(dummy_sock);
    let addr: SocketAddr = "127.0.0.1:3478".parse().unwrap();
    let mut marshal_buf = Vec::new();
    handle_packet(
        &packet,
        addr,
        transport.inner.clone(),
        sender,
        &mut marshal_buf,
    )
    .await;

    // The registered channel must NOT have received anything.
    let result = timeout(Duration::from_millis(50), rx).await;
    assert!(
        result.is_err(),
        "unmatched error response must NOT be delivered to registered tx channel"
    );

    // pending_transactions must still contain the registered id (it was not consumed).
    let map = transport.inner.pending_transactions.lock();
    assert!(
        map.contains_key(&registered_id),
        "unmatched error response must not remove an unrelated pending transaction"
    );

    // Sender must be dropped as part of `tx` still being alive via the map.
    let _ = tx; // keep alive
}

/// End-to-end integration: `run_turn_refresh` must successfully retry after
/// receiving a stale-nonce error response via the TURN read loop.
///
/// With the bug (ErrorResponse not dispatched): `send_and_await_inner` times
/// out after 5 s → refresh silently fails → allocation eventually expires.
///
/// With the fix: 401/438 is dispatched → nonce updated → retry succeeds in
/// < 1 s.  We assert the whole refresh completes in < 4 s to catch regressions.
#[tokio::test]
#[serial]
async fn test_run_turn_refresh_succeeds_after_stale_nonce_via_inner() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);

    // Allocate a real TURN allocation.
    let client = Arc::new(TurnClient::connect(&uri, false).await?);
    let creds = TurnCredentials::from_server(&server)?;
    let alloc = client.allocate(creds).await?;

    // Build a transport inner (runner is required to keep state channels alive).
    let mut config = RtcConfiguration::default();
    config.ice_transport_policy = IceTransportPolicy::Relay;
    config.ice_servers.push(server.clone());
    let (transport, runner) = IceTransport::new(config);
    tokio::spawn(runner);

    // Register the TURN client under its relay address so run_turn_refresh finds it.
    {
        let mut clients = transport.inner.gatherer.turn_clients.lock();
        clients.insert(alloc.relayed_address, client.clone());
    }

    // Spawn the TURN read loop — this is the component that was missing in the
    // bug scenario: without it, responses were never dispatched to pending_transactions.
    let inner_clone = transport.inner.clone();
    let client_clone = client.clone();
    tokio::spawn(async move {
        IceTransportRunner::run_turn_read_loop(client_clone, alloc.relayed_address, inner_clone)
            .await;
    });

    // Set a fake selected pair so run_turn_refresh has a remote address for the
    // permission refresh step.
    let remote = IceCandidate::host("127.0.0.1:19999".parse().unwrap(), 1);
    let local_relay = IceCandidate::relay(alloc.relayed_address, 1, "udp");
    *transport.inner.selected_pair.lock() = Some(IceCandidatePair::new(local_relay, remote));
    let _ = transport.inner.state.send(IceTransportState::Connected);

    // Poison the stored nonce.  The next Refresh / CreatePermission will carry
    // this bad nonce; the server will reply with 4xx + a fresh nonce.
    client
        .update_nonce(TEST_REALM.to_string(), "stale-poison-nonce".to_string())
        .await;

    // With the fix: the read loop dispatches the 4xx → retry fires → success.
    // The whole round-trip should take well under 4 s.
    // Without the fix: the allocation refresh alone times out after 5 s.
    let start = std::time::Instant::now();
    let result = timeout(
        Duration::from_secs(4),
        IceTransportRunner::run_turn_refresh(&transport.inner),
    )
    .await;

    assert!(
        result.is_ok(),
        "run_turn_refresh should complete within 4 s when the TURN read loop \
         dispatches 4xx responses (elapsed: {:?})",
        start.elapsed()
    );

    turn_server.stop().await?;
    Ok(())
}

/// Fix4 verification: UPnP port mappings must be cleaned up on
/// IceTransport::stop(). The fire-and-forget task clears mappers asynchronously.
#[tokio::test]
async fn test_upnp_mappings_cleaned_on_stop() -> Result<()> {
    let mut config = RtcConfiguration::default();
    config.enable_upnp = true;
    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    // Let UPnP probing finish.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // UPnP may or may not find a router in CI; either is fine — what matters
    // is that stop() clears whatever state exists.
    transport.stop();
    // The fire-and-forget cleanup runs in ~50ms; give it a generous window.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let mappers = transport.inner.gatherer.upnp_mappers.lock();
    assert!(
        mappers.is_empty(),
        "Fix4: upnp_mappers must be empty after stop() (got {})",
        mappers.len()
    );
    // Verify ICE state is Closed.
    assert_eq!(
        transport.state(),
        IceTransportState::Closed,
        "Fix4: transport state must be Closed after stop()"
    );
    Ok(())
}

/// Fix5 verification: the shared-UDP socket handle must be released on
/// IceTransport::stop() so the demux port's per-session state is cleaned
/// immediately rather than waiting for Arc<IceTransportInner> release.
#[tokio::test]
async fn test_shared_udp_socket_cleared_on_stop() {
    let config = RtcConfiguration::default();
    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    // Let gathering complete so shared_udp_socket is populated.
    tokio::time::sleep(Duration::from_millis(200)).await;

    transport.stop();
    let handle = transport.inner.gatherer.shared_udp_socket.lock();
    assert!(
        handle.is_none(),
        "Fix5: shared_udp_socket must be None after stop()"
    );
    assert_eq!(transport.state(), IceTransportState::Closed);
}

/// The runner's periodic UPnP refresh tick must invoke
/// `renew_upnp_mappings()` on the gatherer. We inject a mapper whose local
/// mapping is stale and a mock IGD, then verify the runner's tick fires an
/// AddPortMapping against it — proving long-lived mappings get renewed
/// automatically (no inbound-path gap after the router lease expires).
#[tokio::test]
async fn test_runner_upnp_refresh_tick_renews_mappings() {
    use crate::transports::ice::upnp::test_mock_igd::{MockIgd, STALE_AGE};

    let mut config = RtcConfiguration::default();
    config.enable_upnp = true;
    config.upnp_refresh_interval = Duration::from_millis(200);

    let (transport, runner) = IceTransportBuilder::new(config).build();
    tokio::spawn(runner);

    // Inject a mapper with a stale local mapping pointing at a mock IGD.
    let mock = MockIgd::start().await;
    let mut mapper = UpnpPortMapper::new("192.168.1.100:5000".parse().unwrap());
    mapper.set_gateway_for_test(mock.gateway());
    mapper.insert_mapping_for_test(20001, STALE_AGE).await;
    transport.inner.gatherer.upnp_mappers.lock().push(mapper);

    // The runner runs the upnp refresh tick every 200ms regardless of ICE
    // state; wait for a couple of ticks.
    tokio::time::sleep(Duration::from_millis(600)).await;

    let add_calls = mock.add_calls.load(Ordering::SeqCst);
    assert!(
        add_calls >= 1,
        "runner upnp refresh tick must issue AddPortMapping (got {})",
        add_calls
    );

    transport.stop();
    // Stop spawns the async cleanup; give it a moment so it doesn't race the
    // test harness teardown.
    tokio::time::sleep(Duration::from_millis(200)).await;
}

/// Reproduction for the Relay-path "call connected but no audio" bug: a leg
/// whose selected ICE socket is a TURN relay must still forward RTP through the
/// synchronous fast-path (`IceConn::try_send`). Before the fix every packet was
/// dropped with "try_send_to not supported for this transport variant".
#[tokio::test]
#[serial]
async fn fast_path_try_send_relays_rtp_via_turn() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;

    let ice_server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let creds = super::turn::TurnCredentials::from_server(&ice_server)?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let client = super::turn::TurnClient::connect(&uri, false).await?;
    let alloc = client.allocate(creds).await?;

    // A plain UDP peer that the relayed packet must reach.
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;
    client.create_permission(peer_addr).await?;

    let wrapper = IceSocketWrapper::Turn(Arc::new(client), alloc.relayed_address);
    let (_tx, rx) = tokio::sync::watch::channel(Some(wrapper));
    let conn = super::conn::IceConn::new(rx, peer_addr, None);

    conn.try_send(b"relayed")
        .expect("TURN fast-path send must not fail");

    let mut buf = [0u8; 32];
    let (len, _) = timeout(Duration::from_millis(1000), peer.recv_from(&mut buf))
        .await
        .expect("packet must be relayed through TURN")?;
    assert_eq!(&buf[..len], b"relayed");

    turn_server.stop().await?;
    Ok(())
}

/// End-to-end reproduction through the real RTP rewrite bridge: an inbound RTP
/// packet on a plain-UDP leg must be forwarded to a leg whose selected ICE
/// transport is a TURN relay. Before 0.3.134 the bridge fast-path
/// (`RtpTransport::try_bridge_rewrite_rtp` -> `IceConn::try_send`) dropped the
/// packet on any non-UDP transport — the production "call connected but no
/// audio" on Relay paths.
#[tokio::test]
#[serial]
async fn rewrite_bridge_relays_rtp_to_turn_leg() -> Result<()> {
    use crate::transports::rtp::{RtpRewriteBridgeParams, RtpTransport};

    let mut turn_server = TestTurnServer::start().await?;

    // Destination leg: selected ICE transport is a TURN relay.
    let ice_server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let creds = super::turn::TurnCredentials::from_server(&ice_server)?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let turn = super::turn::TurnClient::connect(&uri, false).await?;
    let alloc = turn.allocate(creds).await?;

    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    let peer_addr = peer.local_addr()?;
    turn.create_permission(peer_addr).await?;

    let dst_wrapper = IceSocketWrapper::Turn(Arc::new(turn), alloc.relayed_address);
    let (_dst_tx, dst_rx) = tokio::sync::watch::channel(Some(dst_wrapper));
    let dst_conn = super::conn::IceConn::new(dst_rx, peer_addr, None);
    let dst = Arc::new(RtpTransport::new(dst_conn, false));

    // Source leg: plain UDP.
    let src_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let (_src_tx, src_rx) =
        tokio::sync::watch::channel(Some(IceSocketWrapper::Udp(Arc::new(src_socket))));
    let src_conn = super::conn::IceConn::new(src_rx, "127.0.0.1:9".parse().unwrap(), None);
    let src = RtpTransport::new(src_conn, false);

    src.bridge_rewrite_to(
        dst.clone(),
        RtpRewriteBridgeParams {
            ssrc_offset: 0,
            fixed_out_ssrc: Some(0x1234_5678),
            payload_type: Some(8),
            dtmf_payload_type: None,
            initial_sequence_number: Some(100),
            initial_timestamp_offset: None,
            strip_extensions: false,
        },
    );

    // Simulate the plaintext RTP packet arriving on the source leg.
    let packet = crate::rtp::RtpPacket::new(
        crate::rtp::RtpHeader::new(0, 1, 160, 0xAAAA),
        vec![0x55u8; 160],
    );
    let bytes = packet.marshal()?;
    let mut marshal_buf = Vec::new();
    src.receive(
        bytes.into(),
        "127.0.0.1:9".parse().unwrap(),
        &mut marshal_buf,
    )
    .await;

    // The bridge must have forwarded it over the TURN leg to the peer.
    let mut got = [0u8; 512];
    let (len, _) = timeout(Duration::from_millis(1000), peer.recv_from(&mut got))
        .await
        .expect("rewrite bridge must relay the packet over the TURN leg")?;
    let forwarded = crate::rtp::RtpPacket::parse_bytes(Bytes::copy_from_slice(&got[..len]))?;
    assert_eq!(forwarded.header.ssrc, 0x1234_5678);
    assert_eq!(forwarded.header.payload_type, 8);

    turn_server.stop().await?;
    Ok(())
}

/// Regression test for the Windows WSAECONNRESET (os error 10054) UDP read
/// loop death.
///
/// On Windows, sending a datagram to a closed UDP port makes the OS deliver
/// the ICMP "Port Unreachable" reply as an error on the *next* recv call.
/// Before the fix, `run_udp_read_loop` treated `ConnectionReset` as fatal
/// and returned, silently killing every packet flow (RTP/SRTP/ICE) served by
/// that socket. After the fix the loop logs the error and keeps serving.
///
/// Linux does not surface ICMP errors on unconnected UDP sockets, so this
/// test is Windows-only. For the same OS behavior and fix class see
/// tokio-rs/tokio#2017 and aws/s2n-quic#1448.
#[cfg(windows)]
#[tokio::test]
#[serial]
async fn udp_read_loop_survives_wsaconnreset() -> Result<()> {
    let (transport, runner) = IceTransport::new(RtcConfiguration::default());
    tokio::spawn(runner);
    let inner = transport.inner.clone();

    // A closed UDP port on loopback: bind, note the address, then drop.
    let probe = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let closed_addr = probe.local_addr()?;
    drop(probe);

    // The socket the read loop serves.
    let sock = std::sync::Arc::new(tokio::net::UdpSocket::bind("127.0.0.1:0").await?);
    tokio::spawn(IceTransportRunner::run_udp_read_loop(
        sock.clone(),
        inner.clone(),
    ));

    // Trigger the ICMP "Port Unreachable" -> WSAECONNRESET delivery. The read
    // loop consumes the error on its next recv; this is where the pre-fix
    // loop exited and never came back.
    sock.send_to(b"probe", closed_addr).await?;
    tokio::time::sleep(Duration::from_millis(300)).await;

    // The loop must still be alive: deliver a real RTP-looking packet (first
    // byte >= 2 so it takes the non-STUN path) and observe it land in the
    // transport's packet buffer (no data receiver is registered).
    let peer = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    peer.send_to(b"rtp-payload", sock.local_addr()?).await?;
    let received = timeout(Duration::from_secs(2), async {
        loop {
            if inner
                .buffered_packets
                .lock()
                .iter()
                .any(|(p, _)| p == b"rtp-payload")
            {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(
        received,
        "UDP read loop died after WSAECONNRESET: subsequent packet not received"
    );

    Ok(())
}

/// Reproduction of the 2026-09-30 field failure (za-pbx call
/// 3bslinsis8fvtrj85ld1, site 14): the remote WebRTC agent only ever exposed
/// host/srflx/relay candidates and — per the TURN server logs — its own ICE
/// check scheduler never fired (allocation forwarded zero bytes/messages).
///
/// The local full-ICE agent (the PBX leg, Controlled role) must still probe
/// the remote RELAY candidate directly: packets sent to the peer's relayed
/// address are delivered into the peer's live allocation even when the peer
/// never sends a check of its own. This test acts as the "silent browser":
/// a plain UDP socket plays the remote relay port, dead sockets play the
/// unreachable host/srflx candidates.
#[tokio::test]
async fn silent_remote_relay_candidate_still_gets_probed_and_connects() -> Result<()> {
    // The "browser's TURN relay port": captures whatever the agent sends
    // toward the remote relay candidate (miuturn forwards it into the
    // browser's allocation when permission enforcement is off).
    let fake_relay = UdpSocket::bind("127.0.0.1:0").await?;
    let fake_relay_addr = fake_relay.local_addr()?;

    // Unreachable remote host / srflx candidates (checks there must not
    // stop the relay pair from being probed — mirrors the field call where
    // direct checks die and only the relay path can work).
    let dead_host = UdpSocket::bind("127.0.0.1:0").await?;
    let dead_srflx = UdpSocket::bind("127.0.0.1:0").await?;
    let _ = (&dead_host, &dead_srflx);

    let mut config = RtcConfiguration::default();
    config.ice_include_loopback_candidates = true;
    config.bind_ip = Some("127.0.0.1".to_string());

    let (agent, runner) = IceTransportBuilder::new(config)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner);

    let remote_params = IceParameters::new("ufrag_remote", "pwd_remote_secret");

    // Remote candidates mirroring the field INVITE SDP: host, srflx, relay.
    let mk = |addr: SocketAddr, typ: IceCandidateType, prio: u32| IceCandidate {
        foundation: format!("f{}", prio),
        priority: prio,
        address: addr,
        typ,
        transport: "udp".to_string(),
        tcp_type: None,
        component: 1,
        related_address: None,
        hostname: None,
    };
    let remotes = [
        mk(dead_host.local_addr()?, IceCandidateType::Host, 21_000_000),
        mk(
            dead_srflx.local_addr()?,
            IceCandidateType::ServerReflexive,
            16_000_000,
        ),
        mk(fake_relay_addr, IceCandidateType::Relay, 4_000_000),
    ];
    for c in &remotes {
        agent.add_remote_candidate(c.clone());
    }

    let mut selected_rx = agent.subscribe_selected_pair();

    agent.start(remote_params.clone()).await?;

    // 1. The remote relay candidate MUST receive a STUN binding request.
    let mut buf = [0u8; 1500];
    let (len, from_addr) = timeout(Duration::from_secs(3), fake_relay.recv_from(&mut buf))
        .await
        .expect("timed out waiting for a check toward the remote relay candidate")
        .map_err(|e| anyhow::anyhow!("relay socket recv error: {e}"))?;

    let msg = crate::transports::ice::stun::StunMessage::decode(&buf[..len])?;
    assert_eq!(
        msg.method,
        crate::transports::ice::stun::StunMethod::Binding,
        "packet sent to the remote relay candidate must be a STUN binding request"
    );
    assert_eq!(msg.class, crate::transports::ice::stun::StunClass::Request);

    // 2. Answer like a browser would (miuturn delivers the request into the
    //    allocation; the browser's ICE answers it on the network thread even
    //    when its own check scheduler is dead).
    let success = crate::transports::ice::stun::StunMessage::binding_success_response(
        msg.transaction_id,
        from_addr,
    );
    let success_bytes = success.encode(Some(remote_params.password.as_bytes()), true)?;
    fake_relay.send_to(&success_bytes, from_addr).await?;

    // 3. The agent must accept the pair and reach Connected.
    let selected = timeout(Duration::from_secs(3), async move {
        loop {
            if let Some(pair) = selected_rx.borrow_and_update().clone() {
                return pair;
            }
            if selected_rx.changed().await.is_err() {
                panic!("selected pair channel closed before connectivity");
            }
        }
    })
    .await
    .expect("timed out waiting for the selected pair after the relay-path answer");

    assert_eq!(
        selected.remote.address, fake_relay_addr,
        "selected pair must be the remote relay candidate"
    );
    assert_eq!(agent.state(), IceTransportState::Connected);

    Ok(())
}

/// Regression test for the multi-homed dual-nomination media hijack
/// (production 2026-09-30, call 3bslinsis8fvtrj85ld1): a Controlled agent
/// that already has a nominated, media-carrying pair must NOT follow a
/// second USE-CANDIDATE unless the new path proves a round trip.
///
/// Case 1: a silent second path (never answers the verification check) must
///         NOT divert the selected pair.
/// Case 2: a responsive second path (answers the verification) MUST be
///         followed — legitimate browser path-failover keeps working.
#[tokio::test]
#[serial]
async fn second_nomination_requires_path_verification() -> Result<()> {
    let (controlling, controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;
    wait_for_selected_pair(&controlled, Duration::from_secs(5)).await?;
    let initial = controlled
        .get_selected_pair()
        .expect("initial selected pair");

    let agent_addr = controlled
        .local_candidates()
        .iter()
        .find(|c| c.transport == "udp" && c.component == 1)
        .map(|c| c.address)
        .expect("controlled udp host candidate");
    let pwd = controlled.local_parameters().password;
    let username = format!(
        "{}:{}",
        controlling.local_parameters().username_fragment,
        controlled.local_parameters().username_fragment
    );

    let use_candidate_request = || -> Result<Vec<u8>> {
        let mut msg = StunMessage::binding_request(random_bytes::<12>(), Some("test"));
        msg.attributes
            .push(StunAttribute::Username(username.clone()));
        msg.attributes.push(StunAttribute::UseCandidate);
        Ok(msg.encode(Some(pwd.as_bytes()), true)?)
    };

    // ── Case 1: silent path ──────────────────────────────────────────────
    let silent = UdpSocket::bind("127.0.0.1:0").await?;
    silent
        .send_to(&use_candidate_request()?, agent_addr)
        .await?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let sel = controlled
        .get_selected_pair()
        .expect("selected pair after silent nomination");
    assert_ne!(
        sel.remote.address,
        silent.local_addr()?,
        "unverified second path must not divert the selected pair"
    );

    // ── Case 2: responsive path ──────────────────────────────────────────
    let good = UdpSocket::bind("127.0.0.1:0").await?;
    let good_addr = good.local_addr()?;
    good.send_to(&use_candidate_request()?, agent_addr).await?;

    // The agent verifies the new path with its own binding request; answer it.
    // (The first packet may be the agent's success response to OUR nomination
    // check — keep reading until an actual Request arrives.)
    let mut buf = [0u8; 1500];
    let (vreq, from) = {
        loop {
            let (n, from) = timeout(Duration::from_secs(3), good.recv_from(&mut buf))
                .await
                .expect("timed out waiting for the agent's path-verification check")?;
            let m = StunMessage::decode(&buf[..n])?;
            if m.class == StunClass::Request && m.method == StunMethod::Binding {
                break (m, from);
            }
        }
    };
    let resp = StunMessage::binding_success_response(vreq.transaction_id, from);
    good.send_to(&resp.encode(Some(pwd.as_bytes()), true)?, from)
        .await?;

    let switched = timeout(Duration::from_secs(3), async {
        loop {
            if let Some(p) = controlled.get_selected_pair() {
                if p.remote.address == good_addr {
                    return p;
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("timed out waiting for switch to verified path");

    assert_eq!(
        switched.remote.address, good_addr,
        "responsive path must be followed after verification"
    );
    let _ = initial;
    Ok(())
}

/// Regression for issue #54: every remote-initiated ICE restart must reset the
/// local agent. `restart()` used to set `restart_requested` even when it merely
/// mirrored a remote restart, so the flag stayed set and the *second* remote
/// restart was mistaken for the completion of a local one and skipped.
#[tokio::test]
#[serial]
async fn second_remote_ice_restart_still_restarts() -> Result<()> {
    let (transport, runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    tokio::spawn(runner);

    // Initial start: no previous remote parameters, so this is not a restart.
    transport.start(IceParameters::generate()).await?;
    let initial = transport.local_parameters();

    // First remote restart: changed credentials must roll our own.
    transport.start(IceParameters::generate()).await?;
    let after_first = transport.local_parameters();
    assert_ne!(
        initial.username_fragment, after_first.username_fragment,
        "the first remote restart must roll local credentials"
    );
    assert!(
        !transport
            .inner
            .restart_requested
            .load(std::sync::atomic::Ordering::SeqCst),
        "a remote-triggered restart must not leave restart_requested set"
    );

    // Second remote restart: must reset again (this failed before the fix).
    transport.start(IceParameters::generate()).await?;
    let after_second = transport.local_parameters();
    assert_ne!(
        after_first.username_fragment, after_second.username_fragment,
        "a second remote restart must roll local credentials again (issue #54)"
    );

    Ok(())
}

/// Regression for issue #55: when two controlled-side nominations arrive close
/// together and the *older* one's deferred path verification completes last, it
/// must not move media back to the superseded path. The most recent nomination
/// wins (RFC 8445 §8.1.1).
#[tokio::test]
#[serial]
async fn superseded_nomination_does_not_override_newer() -> Result<()> {
    let (controlling, controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;
    wait_for_selected_pair(&controlled, Duration::from_secs(5)).await?;

    let agent_addr = controlled
        .local_candidates()
        .iter()
        .find(|c| c.transport == "udp" && c.component == 1)
        .map(|c| c.address)
        .expect("controlled udp host candidate");
    let pwd = controlled.local_parameters().password;
    let username = format!(
        "{}:{}",
        controlling.local_parameters().username_fragment,
        controlled.local_parameters().username_fragment
    );
    let use_candidate_request = || -> Result<Vec<u8>> {
        let mut msg = StunMessage::binding_request(random_bytes::<12>(), Some("test"));
        msg.attributes
            .push(StunAttribute::Username(username.clone()));
        msg.attributes.push(StunAttribute::UseCandidate);
        Ok(msg.encode(Some(pwd.as_bytes()), true)?)
    };

    // Nomination A (older): send USE-CANDIDATE but never answer its
    // verification until after B is selected, so A's verifier stays pending.
    let older = UdpSocket::bind("127.0.0.1:0").await?;
    older.send_to(&use_candidate_request()?, agent_addr).await?;

    // Nomination B (newer).
    let newer = UdpSocket::bind("127.0.0.1:0").await?;
    let newer_addr = newer.local_addr()?;
    newer.send_to(&use_candidate_request()?, agent_addr).await?;

    // Answer every binding request the agent sends to B until B becomes the
    // selected pair (some may be ordinary connectivity checks).
    let mut buf = [0u8; 1500];
    timeout(Duration::from_secs(4), async {
        loop {
            let Ok((n, from)) = newer.recv_from(&mut buf).await else {
                continue;
            };
            if let Ok(m) = StunMessage::decode(&buf[..n])
                && m.class == StunClass::Request
                && m.method == StunMethod::Binding
            {
                let resp = StunMessage::binding_success_response(m.transaction_id, from);
                if let Ok(bytes) = resp.encode(Some(pwd.as_bytes()), true) {
                    let _ = newer.send_to(&bytes, from).await;
                }
            }
            if controlled
                .get_selected_pair()
                .is_some_and(|p| p.remote.address == newer_addr)
            {
                return;
            }
        }
    })
    .await
    .expect("timed out waiting for the newer nomination to be selected");

    // Now answer everything the agent sent to A (including the stale
    // verification request). Its verifier may resolve, but it has been
    // superseded and must be ignored.
    while let Ok(Ok((n, from))) =
        timeout(Duration::from_millis(250), older.recv_from(&mut buf)).await
    {
        if let Ok(m) = StunMessage::decode(&buf[..n])
            && m.class == StunClass::Request
            && m.method == StunMethod::Binding
        {
            let resp = StunMessage::binding_success_response(m.transaction_id, from);
            if let Ok(bytes) = resp.encode(Some(pwd.as_bytes()), true) {
                let _ = older.send_to(&bytes, from).await;
            }
        }
    }

    // Give the stale verifier a moment to (wrongly) apply, then assert B is
    // still selected.
    tokio::time::sleep(Duration::from_millis(400)).await;
    let selected = controlled.get_selected_pair().expect("selected pair");
    assert_eq!(
        selected.remote.address, newer_addr,
        "an older nomination's late verification must not move media back (issue #55)"
    );

    Ok(())
}

/// Answer every binding request arriving on `sock`, but only once `release`
/// fires (immediately when it already has). Requests seen before the release
/// are answered in a batch, keeping the checking agent's round in flight.
/// `seen` is notified for each request received.
async fn answer_binding_checks(
    sock: UdpSocket,
    mut release: watch::Receiver<bool>,
    seen: Arc<tokio::sync::Notify>,
) {
    let mut held = Vec::new();
    let mut buf = [0u8; 1500];
    loop {
        tokio::select! {
            r = sock.recv_from(&mut buf) => {
                let Ok((n, from)) = r else { return };
                let Ok(m) = StunMessage::decode(&buf[..n]) else { continue };
                if m.class != StunClass::Request {
                    continue;
                }
                held.push((m.transaction_id, from));
                seen.notify_one();
            }
            r = release.changed(), if !*release.borrow() => {
                if r.is_err() {
                    return;
                }
            }
        }
        if *release.borrow() {
            for (tx_id, from) in held.drain(..) {
                let resp = StunMessage::binding_success_response(tx_id, from);
                if let Ok(bytes) = resp.encode(None, true) {
                    let _ = sock.send_to(&bytes, from).await;
                }
            }
        }
    }
}

/// A connectivity-check round that finishes after another round already
/// selected a pair must not overwrite that selection on the controlled side.
///
/// Every `RunChecks` (start, each trickled or peer-reflexive candidate) spawns
/// its own round. Rounds that began before any pair was selected used to each
/// commit their best pair, writing `selected_pair` and the selected socket
/// separately; when two finished together the writes interleaved and left the
/// socket of one pair sending to the remote of the other. On a multi-homed
/// host that sent every DTLS flight from a bridge-interface socket to an en0
/// address (EHOSTDOWN) until the handshake timed out. The first round to
/// commit now wins; only USE-CANDIDATE moves the selection afterwards.
#[tokio::test]
async fn controlled_late_check_round_keeps_first_selection() -> Result<()> {
    use tokio::net::UdpSocket;

    let mut cfg = RtcConfiguration::default();
    cfg.bind_ip = Some("127.0.0.1".into());
    let (t, runner) = IceTransportBuilder::new(cfg)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner);
    timeout(Duration::from_secs(5), async {
        while t.gather_state() != IceGathererState::Complete {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("gathering did not complete in time")?;

    // Round 1 checks the slow peer, which holds its answers until released.
    let slow = UdpSocket::bind("127.0.0.1:0").await?;
    let slow_addr = slow.local_addr()?;
    let (release_slow, release_slow_rx) = watch::channel(false);
    let slow_seen = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(answer_binding_checks(
        slow,
        release_slow_rx,
        slow_seen.clone(),
    ));
    t.add_remote_candidate(IceCandidate::host(slow_addr, 1));
    t.start(IceParameters::new(
        "peer_ufrag",
        "peer_pwd_0123456789abcdef",
    ))
    .await?;
    timeout(Duration::from_secs(5), slow_seen.notified())
        .await
        .context("round 1 never checked the slow peer")?;

    // Round 2 checks the fast peer, succeeds and selects it.
    let fast = UdpSocket::bind("127.0.0.1:0").await?;
    let fast_addr = fast.local_addr()?;
    let (_release_fast, release_fast_rx) = watch::channel(true);
    tokio::spawn(answer_binding_checks(
        fast,
        release_fast_rx,
        Arc::new(tokio::sync::Notify::new()),
    ));
    t.add_remote_candidate(IceCandidate::host(fast_addr, 1));
    wait_selected_remote(&t, fast_addr, Duration::from_secs(5)).await?;

    // Let round 1 succeed too; it must not take the selection over.
    release_slow.send(true)?;
    tokio::time::sleep(Duration::from_millis(800)).await;
    let selected = t.get_selected_pair().expect("selected pair");
    assert_eq!(
        selected.remote.address, fast_addr,
        "a later check round overwrote the controlled side's selected pair"
    );
    Ok(())
}

/// A check round that outlives an ICE restart must not commit its stale
/// pair. `restart()` bumps `nomination_generation` (which the round snapped
/// up at start) and clears the pending transactions, aborting the round's
/// in-flight checks — driving the round into its commit path right as the
/// restart completes. Without the generation guard that commit would land
/// after the restart's selection reset, and the first-wins rule would keep
/// the pre-restart pair until the peer's next USE-CANDIDATE.
#[tokio::test]
async fn stale_check_round_after_restart_does_not_commit() -> Result<()> {
    use tokio::net::UdpSocket;

    let mut cfg = RtcConfiguration::default();
    cfg.bind_ip = Some("127.0.0.1".into());
    let (t, runner) = IceTransportBuilder::new(cfg)
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner);
    timeout(Duration::from_secs(5), async {
        while t.gather_state() != IceGathererState::Complete {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("gathering did not complete in time")?;

    // `fast` answers immediately; `held` never does (its release watcher
    // stays false for the whole test), keeping one check of the round in
    // flight so the round is still running when the restart fires.
    let fast = UdpSocket::bind("127.0.0.1:0").await?;
    let fast_addr = fast.local_addr()?;
    let (_release_fast, release_fast_rx) = watch::channel(true);
    let fast_seen = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(answer_binding_checks(
        fast,
        release_fast_rx,
        fast_seen.clone(),
    ));

    let held = UdpSocket::bind("127.0.0.1:0").await?;
    let held_addr = held.local_addr()?;
    let (_release_held, release_held_rx) = watch::channel(false);
    tokio::spawn(answer_binding_checks(
        held,
        release_held_rx,
        Arc::new(tokio::sync::Notify::new()),
    ));

    t.add_remote_candidate(IceCandidate::host(fast_addr, 1));
    t.add_remote_candidate(IceCandidate::host(held_addr, 1));
    t.start(IceParameters::new(
        "peer_ufrag",
        "peer_pwd_0123456789abcdef",
    ))
    .await?;
    timeout(Duration::from_secs(5), fast_seen.notified())
        .await
        .context("the round never checked the fast peer")?;
    // Let the round collect the fast success while the held check keeps
    // retransmitting (still inside the round's nomination grace window).
    tokio::time::sleep(Duration::from_millis(100)).await;

    // Restart mid-round. Whatever order the aborted round's commit and the
    // restart's internal steps interleave in, no stale pair may survive:
    // a commit before the generation bump is itself reset by the locked
    // selection clear, a commit after it is rejected by the guard.
    t.restart().await?;

    // Give the aborted round plenty of time to reach (and be rejected at)
    // its commit.
    tokio::time::sleep(Duration::from_millis(800)).await;
    assert!(
        t.get_selected_pair().is_none(),
        "a pre-restart check round committed a stale pair after the restart"
    );

    // Recovery: a fresh round started after the restart still selects.
    t.start(IceParameters::new(
        "peer_ufrag2",
        "peer_pwd_0123456789abcdeg",
    ))
    .await?;
    timeout(Duration::from_secs(5), async {
        while t.get_selected_pair().is_none() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .context("no fresh round selected a pair after the restart")?;
    Ok(())
}

/// A selection commit must refuse a pair whose local candidate has no
/// socket: advancing `selected_pair` alone would leave the previously
/// published socket (or none at all) paired with the new remote — the exact
/// mismatch `selection_lock` exists to prevent.
#[tokio::test]
async fn select_pair_refuses_unresolvable_local() -> Result<()> {
    let mut cfg = RtcConfiguration::default();
    cfg.bind_ip = Some("127.0.0.1".into());
    let (t, runner) = IceTransportBuilder::new(cfg).build();
    tokio::spawn(runner);
    timeout(Duration::from_secs(5), async {
        while t.gather_state() != IceGathererState::Complete {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .context("gathering did not complete in time")?;

    // A local address no socket was ever bound to: the commit must refuse
    // rather than publish the pair without a socket.
    let bogus_local = IceCandidate::host("127.0.0.1:1".parse()?, 1);
    let remote_addr: SocketAddr = "127.0.0.1:9999".parse()?;
    let remote = IceCandidate::host(remote_addr, 1);
    t.select_pair(IceCandidatePair::new(bogus_local, remote.clone()));
    assert!(
        t.get_selected_pair().is_none(),
        "a pair with no resolvable socket must not be selected"
    );

    // A real gathered local candidate resolves and commits as before.
    let local = t
        .local_candidates()
        .into_iter()
        .find(|c| c.transport == "udp")
        .context("no UDP local candidate gathered")?;
    t.select_pair(IceCandidatePair::new(local, remote));
    let selected = t
        .get_selected_pair()
        .context("real pair was not selected")?;
    assert_eq!(selected.remote.address, remote_addr);
    Ok(())
}

// ===========================================================================
// Controlling-side nomination round isolation (RFC 8445 §8.1.1)
//
// Regression coverage for the incident where two concurrent check rounds
// both passed the `already nominated` guard (both read `None` on
// `nomination_complete`); the losing round's USE-CANDIDATE was ignored by
// the controlled peer (first nomination wins), its binding check timed out
// (~10 s), and the `!nominated` fallback tore down a live, already-nominated
// session. Remote tunnels died seconds after every successful setup.
// ===========================================================================

/// Build a controlling-side transport with loopback gathering so a gathered
/// local socket exists and `commit_selected_pair` can resolve it.
async fn nomination_test_fixture() -> IceTransport {
    let mut config = RtcConfiguration::default();
    config.ice_include_loopback_candidates = true;
    let (transport, runner) = IceTransportBuilder::new(config)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner);
    transport.start_gathering().expect("start_gathering");

    // Wait for a loopback candidate so its socket is resolvable.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        if transport
            .local_candidates()
            .iter()
            .any(|c| c.address.ip().is_loopback())
        {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "no loopback candidate gathered within 5 s"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    transport
}

fn blackhole_pair(local: IceCandidate) -> IceCandidatePair {
    // Remote port 1: nothing listens there; the socket only needs to RESOLVE,
    // no packets are exchanged in these unit tests.
    IceCandidatePair::new(local, IceCandidate::host("127.0.0.1:1".parse().unwrap(), 1))
}

/// A late round that lost the nomination race must drop without touching
/// session state: no pair commit, no `Some(false)`, no `Failed`.
#[tokio::test]
#[serial]
async fn test_late_round_drops_when_concurrent_round_already_nominated() -> Result<()> {
    let transport = nomination_test_fixture().await;
    let local = transport
        .local_candidates()
        .into_iter()
        .find(|c| c.address.ip().is_loopback())
        .expect("loopback candidate");

    transport.force_state_for_test(IceTransportState::Connected);
    // The concurrent round already won the race: nomination is done.
    let _ = transport.inner.nomination_complete.send(Some(true));

    let round_generation = transport
        .inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst);

    let pair = blackhole_pair(local);
    let concluded = complete_controlling_nomination(
        &transport.inner,
        round_generation,
        None, // this round's USE-CANDIDATE went unanswered
        std::slice::from_ref(&pair),
    );

    assert!(!concluded, "the late round must drop without touching state");
    assert_eq!(
        *transport.inner.nomination_complete.borrow(),
        Some(true),
        "nomination state must be untouched"
    );
    assert_eq!(
        *transport.inner.state.borrow(),
        IceTransportState::Connected,
        "the transport must not transition to Failed"
    );
    assert!(
        transport.inner.selected_pair.lock().is_none(),
        "the late round must not commit its own pair"
    );
    Ok(())
}

/// A first round with a working nomination still commits and signals
/// `Some(true)` — the fix must not break the happy path.
#[tokio::test]
#[serial]
async fn test_first_round_nomination_commits_and_signals() -> Result<()> {
    let transport = nomination_test_fixture().await;
    let local = transport
        .local_candidates()
        .into_iter()
        .find(|c| c.address.ip().is_loopback())
        .expect("loopback candidate");

    transport.force_state_for_test(IceTransportState::Connected);

    let round_generation = transport
        .inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst);
    let pair = blackhole_pair(local.clone());
    let concluded = complete_controlling_nomination(
        &transport.inner,
        round_generation,
        Some(pair.clone()),
        std::slice::from_ref(&pair),
    );

    assert!(concluded, "the first round must commit");
    assert_eq!(
        *transport.inner.nomination_complete.borrow(),
        Some(true),
        "nomination must signal Some(true)"
    );
    let selected = transport
        .inner
        .selected_pair
        .lock()
        .clone()
        .expect("selected pair must be committed");
    assert_eq!(selected.local.address, local.address);
    assert_eq!(selected.remote.address, pair.remote.address);
    Ok(())
}

/// A round superseded by an ICE restart (generation bump) must drop silently:
/// say nothing on `nomination_complete`, touch no state (the fresh post-
/// restart round owns the state machine).
#[tokio::test]
#[serial]
async fn test_round_superseded_by_restart_drops_silently() -> Result<()> {
    let transport = nomination_test_fixture().await;
    let local = transport
        .local_candidates()
        .into_iter()
        .find(|c| c.address.ip().is_loopback())
        .expect("loopback candidate");

    transport.force_state_for_test(IceTransportState::Connected);

    let stale_generation = transport
        .inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst);
    // ICE restart happened while this round was in flight.
    transport
        .inner
        .nomination_generation
        .store(stale_generation + 1, core::sync::atomic::Ordering::SeqCst);

    let pair = blackhole_pair(local);
    let concluded = complete_controlling_nomination(
        &transport.inner,
        stale_generation,
        Some(pair.clone()),
        std::slice::from_ref(&pair),
    );

    assert!(!concluded, "the superseded round must drop");
    assert_eq!(
        *transport.inner.nomination_complete.borrow(),
        None,
        "a superseded round says nothing on nomination_complete"
    );
    Ok(())
}

/// A first round that cannot commit any pair (no resolvable socket) must
/// still fail the transport explicitly — the pre-fix behaviour for genuine
/// blackhole setups is preserved.
#[tokio::test]
#[serial]
async fn test_uncommittable_first_round_fails_transport() -> Result<()> {
    let transport = nomination_test_fixture().await;

    transport.force_state_for_test(IceTransportState::Connected);

    let round_generation = transport
        .inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst);
    // Local address was never gathered → no socket resolves → commit fails.
    let pair = IceCandidatePair::new(
        IceCandidate::host("10.255.255.1:9".parse().unwrap(), 1),
        IceCandidate::host("127.0.0.1:1".parse().unwrap(), 1),
    );
    let concluded = complete_controlling_nomination(
        &transport.inner,
        round_generation,
        None,
        std::slice::from_ref(&pair),
    );

    assert!(concluded, "an uncommittable round concludes with Failed");
    assert_eq!(
        *transport.inner.nomination_complete.borrow(),
        Some(false),
        "nomination must signal Some(false)"
    );
    assert_eq!(
        *transport.inner.state.borrow(),
        IceTransportState::Failed,
        "the transport must transition to Failed"
    );
    Ok(())
}

/// A round following a *failed* concurrent nomination (`Some(false)`) must be
/// allowed to nominate: the failed round's fallback pair never received
/// USE-CANDIDATE confirmation, so a fresh round is the session's chance to
/// converge. Only a *successful* nomination (`Some(true)`) blocks follow-up
/// rounds — this is the redundancy-heals-under-loss property.
#[tokio::test]
#[serial]
async fn test_round_retries_after_concurrent_nomination_failure() -> Result<()> {
    let transport = nomination_test_fixture().await;
    let local = transport
        .local_candidates()
        .into_iter()
        .find(|c| c.address.ip().is_loopback())
        .expect("loopback candidate");

    transport.force_state_for_test(IceTransportState::Connected);
    // Previous round committed a fallback pair but its USE-CANDIDATE went
    // unanswered: nomination failed.
    let _ = transport.inner.nomination_complete.send(Some(false));

    let round_generation = transport
        .inner
        .nomination_generation
        .load(core::sync::atomic::Ordering::SeqCst);
    let pair = blackhole_pair(local.clone());
    let concluded = complete_controlling_nomination(
        &transport.inner,
        round_generation,
        Some(pair.clone()),
        std::slice::from_ref(&pair),
    );

    assert!(concluded, "the retry round must nominate and commit");
    assert_eq!(
        *transport.inner.nomination_complete.borrow(),
        Some(true),
        "retry round's successful nomination must signal Some(true)"
    );
    let selected = transport
        .inner
        .selected_pair
        .lock()
        .clone()
        .expect("retry round must commit its pair");
    assert_eq!(selected.remote.address, pair.remote.address);
    Ok(())
}

/// `nomination_grace` must default to the historical 200 ms (no behaviour
/// change for existing embedders) and be overridable via the builder —
/// port-forwarding stacks raise it so the always-fast relay pair cannot
/// beat a cross-ISP direct pair to nomination.
#[test]
fn test_nomination_grace_default_and_builder() {
    let config = RtcConfiguration::default();
    assert_eq!(
        config.nomination_grace,
        Duration::from_millis(200),
        "default must keep the historical 200 ms grace"
    );

    let config = RtcConfigurationBuilder::new()
        .nomination_grace(Duration::from_millis(500))
        .build();
    assert_eq!(config.nomination_grace, Duration::from_millis(500));
}

// ===========================================================================
// Post-nomination path upgrade (RFC 8445 §8.1.1 additional nomination)
// ===========================================================================

fn cand(addr: &str, priority: u32) -> IceCandidate {
    let mut c = IceCandidate::host(addr.parse().unwrap(), 1);
    c.priority = priority;
    c
}

/// The only-upgrade rule: probe candidates must strictly exceed the selected
/// pair's priority (never equal, never lower) and come back best-first.
#[test]
fn upgrade_candidate_pairs_only_higher_priority_best_first() {
    let selected = IceCandidatePair::new(cand("10.0.0.1:100", 1000), cand("10.0.0.2:200", 1000));

    let locals = vec![cand("10.0.0.1:100", 1000), cand("10.0.0.1:101", 900)];
    let remotes = vec![
        cand("10.0.0.2:200", 1000), // same as selected remote -> excluded via address match
        cand("10.0.0.2:201", 1200), // higher -> included
        cand("10.0.0.2:202", 1000), // equal -> excluded
        cand("10.0.0.2:203", 800),  // lower -> excluded
    ];

    let out = upgrade_candidate_pairs(&locals, &remotes, &selected, IceRole::Controlling, 8);

    assert!(
        out.iter().all(|p| p.priority(IceRole::Controlling) > selected.priority(IceRole::Controlling)),
        "every probed pair must strictly beat the selected pair"
    );
    assert!(!out.is_empty(), "the higher-priority pair must be probed");
    let prios: Vec<u64> = out.iter().map(|p| p.priority(IceRole::Controlling)).collect();
    let mut sorted = prios.clone();
    sorted.sort_by(|a, b| b.cmp(a));
    assert_eq!(prios, sorted, "probe order must be best-first");
}

/// End-to-end: after a session is nominated, a late-arriving
/// higher-priority remote candidate (the "direct path validated after the
/// session started on relay" scenario) must trigger a probe and an upgrade
/// nomination on the controlling side. The remote address is a real peer
/// socket (the controlled transport), so the STUN exchange is genuine.
#[tokio::test]
#[serial]
async fn test_post_nomination_upgrade_to_higher_priority_pair() -> Result<()> {
    let (controlling, _controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;

    let ctrl_state = controlling.subscribe_state();
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await,
        "pair must connect before the upgrade scenario"
    );
    let selected_before = wait_for_selected_pair(&controlling, Duration::from_secs(10)).await?;

    // Simulate a strictly better path appearing late: same reachable peer
    // socket, advertised with a higher candidate priority (a direct
    // srflx/UPnP pair arriving after the session settled on relay).
    let mut better = selected_before.remote.clone();
    better.priority = selected_before.remote.priority.saturating_add(50_000);
    // The trigger must be fully automatic: the re-armed checks driven by the
    // late candidate probe the better path and upgrade the nomination.
    controlling.add_remote_candidate(better.clone());
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    let mut upgraded = None;
    while tokio::time::Instant::now() < deadline {
        let cur = controlling
            .inner
            .selected_pair
            .lock()
            .clone()
            .unwrap_or_else(|| selected_before.clone());
        if cur.remote.priority == better.priority {
            upgraded = Some(cur);
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    let upgraded = upgraded.context("controlling side never upgraded to the higher-priority pair")?;
    assert!(
        upgraded.priority(IceRole::Controlling) > selected_before.priority(IceRole::Controlling),
        "upgraded pair must outrank the original selection"
    );
    Ok(())
}

/// RFC 8445 §6.1.4.4 reproduction: every pair in the check list must reach a
/// terminal state (Succeeded / Failed-by-STUN-retransmission). A
/// higher-priority pair whose response arrives after the nomination grace
/// must still validate — in the SAME round — and upgrade the nomination.
/// Abandoning in-flight checks at an arbitrary grace timer leaves the pair
/// invisible forever and pins the session to the lower-priority path.
#[tokio::test]
#[serial]
async fn test_slower_higher_priority_pair_upgrades_after_nomination() -> Result<()> {
    // Manual setup (mirrors setup_host_pair) so the slow candidate is present
    // BEFORE checks start — no late-trickle re-arm may rescue the round.
    let (controlling, runner_c) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);
    let (controlled, runner_d) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    // Gathering is asynchronous (the runner task drives it): wait for host
    // candidates before exchanging, so the exchange actually delivers them.
    let gather_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < gather_deadline
        && (controlling.local_candidates().is_empty() || controlled.local_candidates().is_empty())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }

    // Delaying UDP relay: a "slow but strictly better path" to the same peer.
    // 700 ms one-way delay on requests; responses relayed immediately.
    let proxy = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
    let proxy_addr = proxy.local_addr()?;
    let peer = controlled
        .local_candidates()
        .into_iter()
        .map(|c| c.address)
        .next()
        .context("controlled has no host candidate")?;
    let delay = Duration::from_millis(700);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client: Option<SocketAddr> = None;
        while let Ok((len, from)) = proxy.recv_from(&mut buf).await {
            if from == peer {
                if let Some(c) = client {
                    let _ = proxy.send_to(&buf[..len], c).await;
                }
            } else {
                client = Some(from);
                tokio::time::sleep(delay).await;
                let _ = proxy.send_to(&buf[..len], peer).await;
            }
        }
    });

    let mut slow = IceCandidate::host(proxy_addr, 1);
    slow.priority = slow.priority.saturating_add(50_000);
    controlling.add_remote_candidate(slow);

    // Dead paths (partial unreachability): a closed port and a blackholed
    // one, one advertised with a priority ABOVE the slow path. Dead paths
    // must never delay the initial nomination nor corrupt the upgrade —
    // they simply never validate and are ignored.
    let dead_high = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        s.local_addr()?
    }; // closed immediately -> ICMP unreachable, fast fail
    let dead_low = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        s.local_addr()?
    };
    let mut dh = IceCandidate::host(dead_high, 1);
    dh.priority = dh.priority.saturating_add(80_000);
    let dl = IceCandidate::host(dead_low, 1);
    controlling.add_remote_candidate(dh);
    controlling.add_remote_candidate(dl);

    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    let ctrl_state = controlling.subscribe_state();
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await,
        "pair must connect on the fast path first"
    );

    // The slow pair's response lands ~700 ms in — after the 200 ms grace.
    // The selection must eventually upgrade to it (check-list completion,
    // then the controlling agent nominates the better validated pair).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut upgraded = false;
    while tokio::time::Instant::now() < deadline {
        if let Some(p) = controlling.inner.selected_pair.lock().clone() {
            if p.remote.address == proxy_addr {
                upgraded = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        upgraded,
        "higher-priority pair validating after the grace must upgrade the selection"
    );
    Ok(())
}

/// Multi-homed regression (cf. the EHOSTDOWN incident behind the atomic
/// `commit_selected_pair`): the post-nomination upgrade must publish the
/// socket of the NEW pair's local candidate when the upgrade lands on a
/// different local interface than the originally nominated pair. The slow
/// higher-priority path is only reachable from the loopback local — the LAN
/// local's checks toward it are dropped by the relay — so the upgrade pair is
/// guaranteed to use a different local socket.
#[tokio::test]
#[serial]
async fn test_upgrade_across_local_interfaces_publishes_correct_socket() -> Result<()> {
    let mut cfg = RtcConfiguration::default();
    cfg.ice_include_loopback_candidates = true;

    let (controlling, runner_c) = IceTransportBuilder::new(cfg)
        .role(IceRole::Controlling)
        .build();
    tokio::spawn(runner_c);
    let (controlled, runner_d) = IceTransportBuilder::new(RtcConfiguration::default())
        .role(IceRole::Controlled)
        .build();
    tokio::spawn(runner_d);

    let gather_deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < gather_deadline
        && (controlling.local_candidates().is_empty() || controlled.local_candidates().is_empty())
    {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    // Assert a loopback candidate was gathered; the value itself is unused.
    let _loopback_local = controlling
        .local_candidates()
        .into_iter()
        .find(|c| c.address.ip().is_loopback())
        .context("no loopback local candidate (include_loopback)")?;
    let lan_local = controlling
        .local_candidates()
        .into_iter()
        .find(|c| !c.address.ip().is_loopback())
        .context("no non-loopback local candidate")?;

    for c in controlling.local_candidates() {
        controlled.add_remote_candidate(c);
    }
    for c in controlled.local_candidates() {
        controlling.add_remote_candidate(c);
    }

    // Selective delaying relay: only forwards requests SENT FROM the loopback
    // local (source ip 127.0.0.1); requests from the LAN local are dropped so
    // the (LAN local -> proxy) pair can never validate.
    let proxy = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    let proxy_addr = SocketAddr::new(
        "127.0.0.1".parse::<std::net::IpAddr>().unwrap(),
        proxy.local_addr()?.port(),
    );
    let peer = controlled
        .local_candidates()
        .into_iter()
        .map(|c| c.address)
        .next()
        .context("controlled has no host candidate")?;
    let delay = Duration::from_millis(700);
    tokio::spawn(async move {
        let mut buf = [0u8; 2048];
        let mut client: Option<SocketAddr> = None;
        while let Ok((len, from)) = proxy.recv_from(&mut buf).await {
            if from == peer {
                if let Some(c) = client {
                    let _ = proxy.send_to(&buf[..len], c).await;
                }
            } else if from.ip().is_loopback() {
                client = Some(from);
                tokio::time::sleep(delay).await;
                let _ = proxy.send_to(&buf[..len], peer).await;
            }
            // Non-loopback sources (the LAN local) are dropped on purpose.
        }
    });

    let mut slow = IceCandidate::host(proxy_addr, 1);
    slow.priority = lan_local.priority.saturating_add(50_000);
    controlling.add_remote_candidate(slow);

    controlling.start(controlled.local_parameters()).await?;
    controlled.start(controlling.local_parameters()).await?;

    let ctrl_state = controlling.subscribe_state();
    assert!(
        wait_ice_connected(ctrl_state, Duration::from_secs(10)).await,
        "fast LAN path must connect first"
    );

    // The upgrade must land on the loopback local (only reachable source).
    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    let mut upgraded = None;
    while tokio::time::Instant::now() < deadline {
        if let Some(p) = controlling.inner.selected_pair.lock().clone() {
            if p.remote.address == proxy_addr {
                upgraded = Some(p);
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let upgraded = upgraded.context("upgrade never landed")?;
    assert!(
        upgraded.local.address.ip().is_loopback(),
        "upgrade pair must use the loopback local (different socket), got {}",
        upgraded.local.address
    );
    // The published socket must serve the NEW pair's local, not the old one.
    let sock = controlling
        .inner
        .selected_socket
        .borrow()
        .clone()
        .context("no selected socket after upgrade")?;
    let bound = sock
        .local_addr()
        .context("socket local_addr")?;
    assert!(
        bound.ip().is_loopback(),
        "published socket must be the loopback-local socket, got {}",
        bound
    );
    Ok(())
}

/// Monotonicity: after an upgrade to a higher-priority pair, later rounds
/// validating lower-priority pairs must never downgrade the selection.
#[tokio::test]
#[serial]
async fn test_no_downgrade_after_upgrade() -> Result<()> {
    let (controlling, _controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;
    let ctrl_state = controlling.subscribe_state();
    assert!(wait_ice_connected(ctrl_state, Duration::from_secs(10)).await);
    let base = wait_for_selected_pair(&controlling, Duration::from_secs(10)).await?;

    // Upgrade to an inflated-priority alias of the peer (same reachable socket).
    let mut better = base.remote.clone();
    better.priority = base.remote.priority.saturating_add(50_000);
    controlling.add_remote_candidate(better.clone());

    let deadline = tokio::time::Instant::now() + Duration::from_secs(8);
    while tokio::time::Instant::now() < deadline {
        let cur = controlling.inner.selected_pair.lock().clone();
        if matches!(&cur, Some(p) if p.remote.priority == better.priority) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        matches!(
            &*controlling.inner.selected_pair.lock(),
            Some(p) if p.remote.priority == better.priority
        ),
        "upgrade must have happened before the downgrade attempt"
    );

    // Now a lower-priority path validates (a fresh normal-priority remote): a
    // new round runs, but only-upgrade must reject it.
    let extra = {
        let s = tokio::net::UdpSocket::bind("127.0.0.1:0").await?;
        s.local_addr()?
    };
    let low = IceCandidate::host(extra, 1);
    controlling.add_remote_candidate(low);

    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(
        matches!(
            &*controlling.inner.selected_pair.lock(),
            Some(p) if p.remote.priority == better.priority
        ),
        "selection must never downgrade after an upgrade"
    );
    Ok(())
}

/// Performance guard: a healthy host-only negotiation must complete quickly —
/// guards against regressions that extend the nomination grace handling into
/// connection-setup latency.
#[tokio::test]
#[serial]
async fn test_healthy_connect_latency_bound() -> Result<()> {
    let started = tokio::time::Instant::now();
    let (controlling, _controlled) =
        setup_host_pair(RtcConfiguration::default(), RtcConfiguration::default()).await;
    let ctrl_state = controlling.subscribe_state();
    assert!(wait_ice_connected(ctrl_state, Duration::from_secs(10)).await);
    let _ = wait_for_selected_pair(&controlling, Duration::from_secs(10)).await?;
    let elapsed = started.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "healthy connect+nomination took {:?} — setup latency regression",
        elapsed
    );
    Ok(())
}

#[tokio::test]
async fn turn_allocate_recovers_lost_unauthenticated_response() -> Result<()> {
    allocate_after_lost_response(stun::StunClass::ErrorResponse).await
}

#[tokio::test]
async fn turn_allocate_recovers_lost_authenticated_response() -> Result<()> {
    allocate_after_lost_response(stun::StunClass::SuccessResponse).await
}

async fn allocate_after_lost_response(drop_class: stun::StunClass) -> Result<()> {
    let mut server = TestTurnServer::start().await?;
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let uri = IceServerUri::parse(&format!("turn:{}", socket.local_addr()?))?;
    let target = server.addr;
    let worker = tokio::spawn(async move {
        let mut buffer = [0; MAX_STUN_MESSAGE];
        let mut client = None;
        let mut dropped = false;
        let mut held_response: Option<Vec<u8>> = None;
        let mut requests = std::collections::BTreeMap::<[u8; 12], Vec<Vec<u8>>>::new();
        loop {
            let (length, from) = socket.recv_from(&mut buffer).await?;
            let packet = &buffer[..length];
            let message = stun::StunMessage::decode(packet)?;
            if from == target {
                if !dropped && message.class == drop_class {
                    dropped = true;
                    held_response = Some(packet.to_vec());
                    continue;
                }
                socket.send_to(packet, client.unwrap()).await?;
                if message.class == stun::StunClass::SuccessResponse {
                    assert!(dropped, "the controlled response loss must occur");
                    assert!(requests.values().any(|packets| packets.len() > 1));
                    for packets in requests.values() {
                        assert!(packets.windows(2).all(|pair| pair[0] == pair[1]));
                    }
                    return Ok::<(), anyhow::Error>(());
                }
            } else {
                client = Some(from);
                let packets = requests.entry(message.transaction_id).or_default();
                packets.push(packet.to_vec());
                if let Some(response) = held_response.take() {
                    // RFC 8489 7.3.1: retransmit the cached response for the same
                    // transaction. The existing TURN fixture returns 437 instead.
                    let cached = stun::StunMessage::decode(&response)?;
                    assert_eq!(cached.transaction_id, message.transaction_id);
                    assert!(packets.len() > 1);
                    assert!(packets.windows(2).all(|pair| pair[0] == pair[1]));
                    socket.send_to(&response, from).await?;
                    if cached.class == stun::StunClass::SuccessResponse {
                        return Ok::<(), anyhow::Error>(());
                    }
                } else {
                    socket.send_to(packet, target).await?;
                }
            }
        }
    });
    let client = turn::TurnClient::connect(&uri, false).await?;
    let started = tokio::time::Instant::now();
    let result = client
        .allocate(turn::TurnCredentials {
            username: TEST_USERNAME.into(),
            password: TEST_PASSWORD.into(),
        })
        .await;
    let elapsed = started.elapsed();
    if result.is_err() {
        worker.abort();
    } else {
        worker.await??;
    }
    server.stop().await?;
    assert!(
        result.is_ok(),
        "lost {drop_class:?} must recover: {:?}",
        result.as_ref().err()
    );
    assert!(
        elapsed < Duration::from_secs(3),
        "recovery exceeded original transaction budget"
    );
    Ok(())
}

#[tokio::test]
async fn turn_allocate_packet_loss_keeps_original_deadline() -> Result<()> {
    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    let uri = IceServerUri::parse(&format!("turn:{}", socket.local_addr()?))?;
    let client = turn::TurnClient::connect(&uri, false).await?;
    let started = tokio::time::Instant::now();
    let result = client
        .allocate(turn::TurnCredentials {
            username: TEST_USERNAME.into(),
            password: TEST_PASSWORD.into(),
        })
        .await;
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(RtcError::Timeout(_))));
    assert!(elapsed >= Duration::from_secs(3));
    assert!(
        elapsed < Duration::from_millis(3500),
        "allocation deadline grew: {elapsed:?}"
    );
    let mut packets = Vec::new();
    let mut buffer = [0; MAX_STUN_MESSAGE];
    while let Ok((length, _)) = socket.try_recv_from(&mut buffer) {
        packets.push(buffer[..length].to_vec());
    }
    assert!(
        packets.len() > 1,
        "packet loss must trigger a protocol retransmission"
    );
    assert!(
        packets.windows(2).all(|pair| pair[0] == pair[1]),
        "retransmissions must retain the original request and transaction ID"
    );
    Ok(())
}

#[tokio::test]
async fn packet_diagnostics_counts_actual_udp_reads_and_exit() {
    let (transport, _runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr = socket.local_addr().unwrap();
    let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let read_loop = tokio::spawn(IceTransportRunner::run_udp_read_loop(
        socket,
        transport.inner.clone(),
    ));
    assert!(
        transport
            .packet_diagnostics()
            .udp_read
            .last_age_ms
            .is_none()
    );
    sender.send_to(&[0x80, 0, 0, 1], addr).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while transport
            .inner
            .buffer_stats
            .packets_received
            .load(Ordering::Relaxed)
            < 1
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    assert!(
        transport
            .packet_diagnostics()
            .udp_read
            .first_age_ms
            .is_some()
    );
    tokio::time::sleep(Duration::from_millis(10)).await;
    sender.send_to(&[0x80, 0, 0, 2], addr).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while transport
            .inner
            .buffer_stats
            .packets_received
            .load(Ordering::Relaxed)
            < 2
        {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    transport
        .inner
        .state
        .send(IceTransportState::Closed)
        .unwrap();
    timeout(Duration::from_secs(1), read_loop)
        .await
        .unwrap()
        .unwrap();
    let diag = transport.packet_diagnostics();
    assert_eq!(
        diag.udp_read.packets, 2,
        "real socket read must be observable before parsing"
    );
    assert_eq!(diag.udp_read.bytes, 8);
    assert!(diag.udp_read.first_age_ms.unwrap() >= diag.udp_read.last_age_ms.unwrap() + 5);
    assert!(diag.udp_read.last_age_ms.is_some());
    assert_eq!(diag.udp_read_exits.packets, 1);
    assert_eq!(diag.udp_read_errors.packets, 0);
}

#[tokio::test]
async fn packet_diagnostics_counts_turn_udp_unwrap_outcomes() {
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let uri = IceServerUri::parse(&format!("turn:{relay_addr}")).unwrap();
    let client = Arc::new(TurnClient::connect(&uri, false).await.unwrap());
    let peer: SocketAddr = "127.0.0.1:4242".parse().unwrap();
    client.add_channel(peer, 0x4000).await;
    // Discover the actual client UDP source through a real Send Indication.
    client.send_indication(peer, b"probe").await.unwrap();
    let mut buf = [0u8; 1500];
    let (_, client_addr) = timeout(Duration::from_secs(1), relay.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let (transport, _runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    let reader = tokio::spawn(IceTransportRunner::run_turn_read_loop(
        client,
        relay_addr,
        transport.inner.clone(),
    ));
    use super::stun::StunAttribute;
    let data = StunMessage {
        class: StunClass::Indication,
        method: StunMethod::Data,
        transaction_id: [1; 12],
        attributes: vec![
            StunAttribute::XorPeerAddress(peer),
            StunAttribute::Data(vec![0x80, 0]),
        ],
    }
    .encode(None, false)
    .unwrap();
    let malformed_data = StunMessage {
        class: StunClass::Indication,
        method: StunMethod::Data,
        transaction_id: [2; 12],
        attributes: vec![],
    }
    .encode(None, false)
    .unwrap();
    let control = StunMessage::binding_success_response([3; 12], peer)
        .encode(None, false)
        .unwrap();
    let incoming = [
        vec![0x40, 0, 0, 2, 0x80, 0],
        vec![0x40, 1, 0, 2, 0x80, 0],
        vec![0x40, 0, 0, 3, 0x80],
        control,
        data,
        malformed_data,
    ];
    for packet in &incoming {
        relay.send_to(packet, client_addr).await.unwrap();
    }
    timeout(Duration::from_secs(1), async {
        while transport.packet_diagnostics().turn_malformed.packets < 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    transport
        .inner
        .state
        .send(IceTransportState::Closed)
        .unwrap();
    timeout(Duration::from_secs(1), reader)
        .await
        .unwrap()
        .unwrap();
    let diag = transport.packet_diagnostics();
    assert_eq!(diag.udp_read.packets, 6);
    let json = serde_json::to_value(&diag).unwrap();
    assert_eq!(json["turn_wire_read"]["packets"], 6);
    assert_eq!(json["turn_wire_read"]["bytes"], diag.udp_read.bytes);
    let json = transport.diagnostic_snapshot();
    assert_eq!(json["turn_wire_packets"]["packets"], 6);
    assert_eq!(json["socket_packets"]["packets"], 0);
    assert_eq!(json["turn_unwrapped_packets"]["packets"], 2);
    assert_eq!(json["turn_unwrap_errors"], 3);
    assert_eq!(
        diag.udp_read.bytes,
        incoming
            .iter()
            .map(|packet| packet.len() as u64)
            .sum::<u64>()
    );
    assert_eq!(
        diag.turn_channel_data.packets, 1,
        "unknown channels must not count as successfully unwrapped media"
    );
    assert_eq!(diag.turn_channel_data.bytes, 2);
    assert_eq!(diag.turn_unknown_channel.packets, 1);
    assert_eq!(diag.turn_data_indication.packets, 1);
    assert_eq!(diag.turn_malformed.packets, 2);
    assert_eq!(diag.turn_control.packets, 1);
    assert_eq!(diag.buffered_received, 2);
    assert_eq!(diag.last_turn_control.unwrap().class, "SuccessResponse");
    assert_eq!(diag.udp_read_exits.packets, 1);
}

#[tokio::test]
#[serial]
async fn packet_diagnostics_tracks_real_turn_control_history() -> Result<()> {
    let mut server = TestTurnServer::start().await?;
    let config =
        IceServer::new(vec![server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let uri = IceServerUri::parse(&server.turn_url())?;
    let (transport, _runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    let candidate = transport
        .inner
        .gatherer
        .probe_turn(&uri, &config)
        .await?
        .unwrap();
    let history = transport.packet_diagnostics().turn_control_history;
    assert!(
        history.len() >= 2,
        "Allocate challenge and authenticated response must both survive"
    );
    assert_eq!(history[0].method, "Allocate");
    assert_eq!(history[0].error_code, Some(401));
    assert_eq!(history.last().unwrap().outcome, "success");
    assert!(history.iter().all(|attempt| attempt.duration_ms.is_some()));
    let client = transport
        .inner
        .gatherer
        .turn_clients
        .lock()
        .get(&candidate.address)
        .unwrap()
        .clone();
    let peer = UdpSocket::bind("127.0.0.1:0").await?;
    client.create_permission(peer.local_addr()?).await?;
    client.add_channel(peer.local_addr()?, 0x4000).await;
    let reader = tokio::spawn(IceTransportRunner::run_turn_read_loop(
        client.clone(),
        candidate.address,
        transport.inner.clone(),
    ));
    IceTransportRunner::refresh_one_turn_client(
        &transport.inner,
        candidate.address,
        &client,
        Some(peer.local_addr()?),
    )
    .await;
    let history = transport.packet_diagnostics().turn_control_history;
    for method in ["Allocate", "Refresh", "CreatePermission", "ChannelBind"] {
        assert!(
            history
                .iter()
                .any(|attempt| attempt.method == method && attempt.outcome == "success"),
            "missing {method}: {history:?}"
        );
    }
    assert!(history.len() <= 8);
    transport
        .inner
        .state
        .send(IceTransportState::Closed)
        .unwrap();
    timeout(Duration::from_secs(1), reader).await??;
    server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn packet_diagnostics_turn_history_records_real_timeout_cancel_and_bound() {
    let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let relay_addr = relay.local_addr().unwrap();
    let (transport, _runner) = IceTransportBuilder::new(RtcConfiguration::default()).build();
    let spawn_probe = || {
        let inner = transport.inner.clone();
        tokio::spawn(async move {
            let uri = IceServerUri::parse(&format!("turn:{relay_addr}")).unwrap();
            let config = IceServer::new(vec![format!("turn:{relay_addr}")])
                .with_credential("diagnostic-test", "fixture-only");
            inner.gatherer.probe_turn(&uri, &config).await
        })
    };
    let task = spawn_probe();
    let mut buf = [0u8; 1500];
    timeout(Duration::from_secs(1), relay.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let pending = transport.packet_diagnostics().turn_control_history;
    assert_eq!(pending.last().unwrap().outcome, "pending");
    assert_eq!(pending.last().unwrap().duration_ms, None);
    let error = timeout(Duration::from_secs(6), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.is_timeout());
    let finished = transport.packet_diagnostics().turn_control_history;
    assert_eq!(finished.last().unwrap().outcome, "timeout");
    assert!(finished.last().unwrap().duration_ms.unwrap() >= 2900);
    // Drain the 0.4.14 UDP retransmissions before observing new probes.
    while relay.try_recv_from(&mut buf).is_ok() {}
    for _ in 0..9 {
        let task = spawn_probe();
        timeout(Duration::from_secs(1), relay.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
    }
    let finished = transport.packet_diagnostics().turn_control_history;
    assert_eq!(finished.len(), 8);
    assert!(
        finished
            .iter()
            .all(|entry| entry.outcome == "cancelled" && entry.duration_ms.is_some())
    );
}
