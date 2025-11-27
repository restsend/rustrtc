use super::*;
use crate::{IceServer, RtcConfiguration};
use anyhow::Result;
use turn::{
    Error as TurnError,
    auth::{AuthHandler, generate_auth_key},
    relay::relay_static::RelayAddressGeneratorStatic,
    server::{Server, config::ConnConfig, config::ServerConfig},
};
// use webrtc_util::vnet::net::Net;
type TurnResult<T> = std::result::Result<T, TurnError>;

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
    let transport = IceTransportBuilder::new(RtcConfiguration::default()).build();
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert!(matches!(
        transport.gather_state().await,
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
    let gatherer = IceGatherer::new(config);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates().await;
    assert!(
        candidates
            .iter()
            .any(|c| matches!(c.typ, IceCandidateType::ServerReflexive))
    );
    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn turn_probe_yields_relay_candidate() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let mut config = RtcConfiguration::default();
    config.ice_servers.push(
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD),
    );
    let gatherer = IceGatherer::new(config);
    gatherer.gather().await?;
    let candidates = gatherer.local_candidates().await;
    assert!(
        candidates
            .iter()
            .any(|c| matches!(c.typ, IceCandidateType::Relay))
    );
    turn_server.stop().await?;
    Ok(())
}

#[tokio::test]
async fn turn_client_can_create_permission() -> Result<()> {
    let mut turn_server = TestTurnServer::start().await?;
    let uri = IceServerUri::parse(&turn_server.turn_url())?;
    let server =
        IceServer::new(vec![turn_server.turn_url()]).with_credential(TEST_USERNAME, TEST_PASSWORD);
    let client = TurnClient::connect(&uri, false).await?;
    let creds = TurnCredentials::from_server(&server)?;
    client.allocate(creds).await?;
    let peer: SocketAddr = "127.0.0.1:5000".parse().unwrap();
    client.create_permission(peer).await?;
    turn_server.stop().await?;
    Ok(())
}

const TEST_USERNAME: &str = "test";
const TEST_PASSWORD: &str = "test";
const TEST_REALM: &str = "rport.turn";

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
            return Err(TurnError::ErrNoSuchUser);
        }
        Ok(generate_auth_key(username, realm, &self.password))
    }
}
