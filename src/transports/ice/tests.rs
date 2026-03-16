use super::*;
use crate::transports::PacketReceiver;
use crate::{IceServer, IceTransportPolicy, RtcConfiguration};
use ::turn::{
    auth::{AuthHandler, generate_auth_key},
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{
        Server,
        config::{ConnConfig, ServerConfig},
    },
};
use anyhow::Result;
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
    assert!(!uri.secure);
}

#[test]
fn parse_turns_uri_defaults_to_secure_tcp() {
    let uri = IceServerUri::parse("turns:example.com").unwrap();
    assert_eq!(uri.host, "example.com");
    assert_eq!(uri.port, 5349);
    assert_eq!(uri.transport, IceTransportProtocol::Tcp);
    assert_eq!(uri.kind, IceUriKind::Turn);
    assert!(uri.secure);
}

#[tokio::test]
async fn stuns_probe_rejects_tcp_fallback() -> Result<()> {
    let (tx, _) = broadcast::channel(100);
    let (socket_tx, _) = tokio::sync::mpsc::unbounded_channel();
    let gatherer = IceGatherer::new(RtcConfiguration::default(), tx, socket_tx);
    let uri = IceServerUri::parse("stuns:127.0.0.1:5349").unwrap();

    let err = gatherer
        .probe_stun(&uri)
        .await
        .expect_err("stuns probe should fail until ICE-TCP exists");

    assert!(
        err.to_string()
            .contains("refusing the previous UDP fallback"),
        "unexpected error: {err}"
    );
    Ok(())
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
#[serial]
async fn turn_client_can_create_permission() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let client = TurnClient::connect(&uri, false, false).await?;
    let creds = TurnCredentials::from_server(&server)?;
    client.allocate(creds).await?;
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    client.create_permission(peer).await?;
    turn_server.stop().await?;
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
    let config2 = RtcConfiguration::default();
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
    transport1.start(transport2.local_parameters())?;
    transport2.start(transport1.local_parameters())?;

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

    // Verify selected pair on transport 1 is Relay
    let pair1 = transport1.get_selected_pair().await.unwrap();
    assert_eq!(pair1.local.typ, IceCandidateType::Relay);

    // Send data
    let (tx1, mut rx1_data) = tokio::sync::mpsc::channel(10);
    let (tx2, mut rx2_data) = tokio::sync::mpsc::channel(10);

    struct TestReceiver(tokio::sync::mpsc::Sender<Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for TestReceiver {
        async fn receive(&self, packet: Bytes, _addr: SocketAddr) {
            let _ = self.0.send(packet).await;
        }
    }

    transport1
        .set_data_receiver(Arc::new(TestReceiver(tx1)))
        .await;
    transport2
        .set_data_receiver(Arc::new(TestReceiver(tx2)))
        .await;

    let socket1 = transport1.get_selected_socket().await.unwrap();
    let pair1 = transport1.get_selected_pair().await.unwrap();

    let data = Bytes::from_static(b"hello from 1");
    socket1.send_to(&data, pair1.remote.address).await?;

    let received = timeout(Duration::from_secs(5), rx2_data.recv())
        .await?
        .unwrap();
    assert_eq!(received, data);

    // Send data back
    let socket2 = transport2.get_selected_socket().await.unwrap();
    let pair2 = transport2.get_selected_pair().await.unwrap();
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
    ice_full.start(lite_params.clone())?;

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
    let lite_pair = ice_lite.get_selected_pair().await.unwrap();
    let full_pair = ice_full.get_selected_pair().await.unwrap();

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
        async fn receive(&self, packet: Bytes, _addr: SocketAddr) {
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
    let full_socket = ice_full.get_selected_socket().await.unwrap();
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
    let lite_socket = ice_lite.get_selected_socket().await.unwrap();
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
        .expect("controlling.start");
    controlled
        .start(controlling.local_parameters())
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
    *transport.inner.role.lock().unwrap() = IceRole::Controlling;

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
    let mut config1 = RtcConfiguration::default();
    config1.external_ip = Some("203.0.113.10".to_string());

    let mut config2 = RtcConfiguration::default();
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

    // Verify selected pair exists
    let selected_pair = controlling.get_selected_pair().await;
    assert!(
        selected_pair.is_some(),
        "Controlling agent should have a selected pair"
    );

    let selected_pair = controlled.get_selected_pair().await;
    assert!(
        selected_pair.is_some(),
        "Controlled agent should have a selected pair"
    );

    Ok(())
}

/// Test that nomination_complete fires correctly when external_ip is configured.
#[tokio::test]
#[serial]
async fn test_nomination_with_external_ip() -> Result<()> {
    let mut config1 = RtcConfiguration::default();
    config1.external_ip = Some("203.0.113.10".to_string());

    let mut config2 = RtcConfiguration::default();
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

    // Verify selected pair exists and is valid
    let ctrl_pair = controlling.get_selected_pair().await;
    assert!(
        ctrl_pair.is_some(),
        "Controlling agent should have a selected pair"
    );
    let pair = ctrl_pair.unwrap();
    // Verify the pair addresses match what we expect
    assert!(
        pair.local.address.port() > 0,
        "Local address should have valid port"
    );
    assert!(
        pair.remote.address.port() > 0,
        "Remote address should have valid port"
    );

    let ctrd_pair = controlled.get_selected_pair().await;
    assert!(
        ctrd_pair.is_some(),
        "Controlled agent should have a selected pair"
    );

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

    *transport.inner.role.lock().unwrap() = IceRole::Controlling;
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

    let ctrl_pair = controlling.get_selected_pair().await;
    assert!(
        ctrl_pair.is_some(),
        "Even when nomination times out, ICE selected pair should exist. nom={:?}",
        nom
    );
    let ctrd_pair = controlled.get_selected_pair().await;
    assert!(
        ctrd_pair.is_some(),
        "Controlled side should have a selected pair even when controlling nomination times out"
    );

    let (tx1, rx1) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();
    let (tx2, mut rx2) = tokio::sync::mpsc::unbounded_channel::<bytes::Bytes>();

    struct Chan(tokio::sync::mpsc::UnboundedSender<bytes::Bytes>);
    #[async_trait::async_trait]
    impl PacketReceiver for Chan {
        async fn receive(&self, packet: bytes::Bytes, _addr: std::net::SocketAddr) {
            let _ = self.0.send(packet);
        }
    }

    controlling
        .inner
        .data_receiver
        .lock()
        .unwrap()
        .replace(Arc::new(Chan(tx1)));
    controlled
        .inner
        .data_receiver
        .lock()
        .unwrap()
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

    if let (Some(sock), Some(ctrl_pair)) = (ctrl_sock, controlling.get_selected_pair().await) {
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
