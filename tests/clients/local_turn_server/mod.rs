use anyhow::{Result, anyhow};
use rcgen::generate_simple_self_signed;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustrtc::transports::ice::stun::{
    StunAttribute, StunClass, StunDecoded, StunMessage, StunMethod, random_bytes,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;
use tokio_rustls::TlsAcceptor;

const TEST_TURN_REALM: &str = "rustrtc.test.turn";
const TEST_TURN_NONCE: &str = "rustrtc-test-nonce";
const TEST_TURN_LIFETIME: u32 = 600;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ControlProtocol {
    Udp,
    Tcp,
    Tls,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum ControlId {
    Udp(SocketAddr),
    Stream {
        peer: SocketAddr,
        protocol: ControlProtocol,
    },
}

#[derive(Clone)]
enum ControlPath {
    Udp {
        socket: Arc<UdpSocket>,
        peer: SocketAddr,
    },
    Stream {
        tx: mpsc::UnboundedSender<Vec<u8>>,
        peer: SocketAddr,
        protocol: ControlProtocol,
    },
}

impl ControlPath {
    fn id(&self) -> ControlId {
        match self {
            Self::Udp { peer, .. } => ControlId::Udp(*peer),
            Self::Stream { peer, protocol, .. } => ControlId::Stream {
                peer: *peer,
                protocol: *protocol,
            },
        }
    }

    fn peer_addr(&self) -> SocketAddr {
        match self {
            Self::Udp { peer, .. } | Self::Stream { peer, .. } => *peer,
        }
    }

    async fn send_payload(&self, payload: &[u8]) -> Result<()> {
        match self {
            Self::Udp { socket, peer } => {
                socket.send_to(payload, *peer).await?;
            }
            Self::Stream { tx, .. } => {
                tx.send(payload.to_vec())
                    .map_err(|_| anyhow!("TURN control stream closed"))?;
            }
        }
        Ok(())
    }
}

struct Allocation {
    control: ControlPath,
    relay_socket: Arc<UdpSocket>,
    permissions: Mutex<HashSet<SocketAddr>>,
    channels_by_peer: Mutex<HashMap<SocketAddr, u16>>,
    peers_by_channel: Mutex<HashMap<u16, SocketAddr>>,
}

impl Allocation {
    async fn allow_peer(&self, peer: SocketAddr) {
        self.permissions.lock().await.insert(peer);
    }

    async fn bind_channel(&self, channel: u16, peer: SocketAddr) {
        self.channels_by_peer.lock().await.insert(peer, channel);
        self.peers_by_channel.lock().await.insert(channel, peer);
    }

    async fn peer_for_channel(&self, channel: u16) -> Option<SocketAddr> {
        self.peers_by_channel.lock().await.get(&channel).copied()
    }

    async fn channel_for_peer(&self, peer: SocketAddr) -> Option<u16> {
        self.channels_by_peer.lock().await.get(&peer).copied()
    }
}

struct SharedState {
    allocations: Mutex<HashMap<ControlId, Arc<Allocation>>>,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl SharedState {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            allocations: Mutex::new(HashMap::new()),
            tasks: Mutex::new(Vec::new()),
        })
    }

    async fn add_task(self: &Arc<Self>, handle: JoinHandle<()>) {
        self.tasks.lock().await.push(handle);
    }

    async fn allocation(&self, control: &ControlPath) -> Option<Arc<Allocation>> {
        self.allocations.lock().await.get(&control.id()).cloned()
    }

    async fn insert_allocation(&self, control: &ControlPath, allocation: Arc<Allocation>) {
        self.allocations
            .lock()
            .await
            .insert(control.id(), allocation);
    }
}

#[allow(dead_code)]
pub struct LocalTurnServer {
    shared: Arc<SharedState>,
    udp_addr: SocketAddr,
    tcp_addr: SocketAddr,
    tls_addr: SocketAddr,
}

impl LocalTurnServer {
    #[allow(dead_code)]
    pub async fn start() -> Result<Self> {
        rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::aws_lc_rs::default_provider(),
        )
        .ok();

        let shared = SharedState::new();

        let udp_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let udp_addr = udp_socket.local_addr()?;
        shared
            .add_task(tokio::spawn(run_udp_listener(
                udp_socket.clone(),
                shared.clone(),
            )))
            .await;

        let tcp_listener = TcpListener::bind("127.0.0.1:0").await?;
        let tcp_addr = tcp_listener.local_addr()?;
        shared
            .add_task(tokio::spawn(run_tcp_listener(
                tcp_listener,
                ControlProtocol::Tcp,
                shared.clone(),
            )))
            .await;

        let tls_listener = TcpListener::bind("127.0.0.1:0").await?;
        let tls_addr = tls_listener.local_addr()?;
        let acceptor = TlsAcceptor::from(Arc::new(build_tls_server_config()?));
        shared
            .add_task(tokio::spawn(run_tls_listener(
                tls_listener,
                acceptor,
                shared.clone(),
            )))
            .await;

        Ok(Self {
            shared,
            udp_addr,
            tcp_addr,
            tls_addr,
        })
    }

    #[allow(dead_code)]
    pub fn turn_url(&self) -> String {
        format!("turn:{}", self.udp_addr)
    }

    #[allow(dead_code)]
    pub fn turn_tcp_url(&self) -> String {
        format!("turn:{}?transport=tcp", self.tcp_addr)
    }

    #[allow(dead_code)]
    pub fn turns_url(&self) -> String {
        format!("turns:{}", self.tls_addr)
    }

    #[allow(dead_code)]
    pub async fn stop(self) {
        let mut tasks = self.shared.tasks.lock().await;
        for handle in tasks.drain(..) {
            handle.abort();
        }
    }
}

async fn run_udp_listener(socket: Arc<UdpSocket>, shared: Arc<SharedState>) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, peer) = match socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(_) => break,
        };
        let payload = buf[..len].to_vec();
        let control = ControlPath::Udp {
            socket: socket.clone(),
            peer,
        };
        if let Err(err) = handle_control_packet(payload, control, shared.clone()).await {
            eprintln!("local TURN UDP handler error: {err}");
        }
    }
}

async fn run_tcp_listener(
    listener: TcpListener,
    protocol: ControlProtocol,
    shared: Arc<SharedState>,
) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(_) => break,
        };
        let shared_clone = shared.clone();
        let handle = tokio::spawn(async move {
            if let Err(err) = run_stream_session(stream, peer_addr, protocol, shared_clone).await {
                eprintln!("local TURN stream handler error: {err}");
            }
        });
        shared.add_task(handle).await;
    }
}

async fn run_tls_listener(listener: TcpListener, acceptor: TlsAcceptor, shared: Arc<SharedState>) {
    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(value) => value,
            Err(_) => break,
        };
        let acceptor = acceptor.clone();
        let shared_clone = shared.clone();
        let handle = tokio::spawn(async move {
            match acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(err) = run_stream_session(
                        tls_stream,
                        peer_addr,
                        ControlProtocol::Tls,
                        shared_clone,
                    )
                    .await
                    {
                        eprintln!("local TURN TLS handler error: {err}");
                    }
                }
                Err(err) => {
                    eprintln!("local TURN TLS accept error: {err}");
                }
            }
        });
        shared.add_task(handle).await;
    }
}

async fn run_stream_session<S>(
    stream: S,
    peer_addr: SocketAddr,
    protocol: ControlProtocol,
    shared: Arc<SharedState>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut read, mut write) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::unbounded_channel::<Vec<u8>>();
    let writer = tokio::spawn(async move {
        while let Some(payload) = rx.recv().await {
            let len = (payload.len() as u16).to_be_bytes();
            if write.write_all(&len).await.is_err() {
                break;
            }
            if write.write_all(&payload).await.is_err() {
                break;
            }
        }
    });
    shared.add_task(writer).await;

    let control = ControlPath::Stream {
        tx,
        peer: peer_addr,
        protocol,
    };
    let mut header = [0u8; 2];
    loop {
        read.read_exact(&mut header).await?;
        let len = u16::from_be_bytes(header) as usize;
        let mut payload = vec![0u8; len];
        read.read_exact(&mut payload).await?;
        handle_control_packet(payload, control.clone(), shared.clone()).await?;
    }
}

async fn handle_control_packet(
    payload: Vec<u8>,
    control: ControlPath,
    shared: Arc<SharedState>,
) -> Result<()> {
    if let Some((channel, data)) = decode_channel_data(&payload) {
        if let Some(allocation) = shared.allocation(&control).await
            && let Some(peer) = allocation.peer_for_channel(channel).await
        {
            allocation.relay_socket.send_to(&data, peer).await?;
        }
        return Ok(());
    }

    let message = StunMessage::decode(&payload)?;
    match (message.class, message.method) {
        (StunClass::Request, StunMethod::Binding) => {
            send_stun_message(
                &control,
                StunMessage::binding_success_response(message.transaction_id, control.peer_addr()),
            )
            .await?;
        }
        (StunClass::Request, StunMethod::Allocate) => {
            handle_allocate(message, control, shared).await?;
        }
        (StunClass::Request, StunMethod::CreatePermission) => {
            handle_create_permission(message, control, shared).await?;
        }
        (StunClass::Request, StunMethod::ChannelBind) => {
            handle_channel_bind(message, control, shared).await?;
        }
        (StunClass::Request, StunMethod::Refresh) => {
            handle_refresh(message, control).await?;
        }
        (StunClass::Indication, StunMethod::Send) => {
            handle_send_indication(message, control, shared).await?;
        }
        _ => {}
    }
    Ok(())
}

async fn handle_allocate(
    message: StunDecoded,
    control: ControlPath,
    shared: Arc<SharedState>,
) -> Result<()> {
    if !is_authorized(&message) {
        send_stun_message(
            &control,
            error_response(StunMethod::Allocate, message.transaction_id, 401),
        )
        .await?;
        return Ok(());
    }

    let allocation = if let Some(existing) = shared.allocation(&control).await {
        existing
    } else {
        let relay_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let allocation = Arc::new(Allocation {
            control: control.clone(),
            relay_socket: relay_socket.clone(),
            permissions: Mutex::new(HashSet::new()),
            channels_by_peer: Mutex::new(HashMap::new()),
            peers_by_channel: Mutex::new(HashMap::new()),
        });
        let relay_task = tokio::spawn(run_relay_listener(allocation.clone()));
        shared.add_task(relay_task).await;
        shared.insert_allocation(&control, allocation.clone()).await;
        allocation
    };

    let relayed_addr = allocation.relay_socket.local_addr()?;
    send_stun_message(
        &control,
        StunMessage {
            class: StunClass::SuccessResponse,
            method: StunMethod::Allocate,
            transaction_id: message.transaction_id,
            attributes: vec![
                StunAttribute::XorRelayedAddress(relayed_addr),
                StunAttribute::XorMappedAddress(control.peer_addr()),
                StunAttribute::Lifetime(TEST_TURN_LIFETIME),
            ],
        },
    )
    .await?;
    Ok(())
}

async fn handle_create_permission(
    message: StunDecoded,
    control: ControlPath,
    shared: Arc<SharedState>,
) -> Result<()> {
    if !is_authorized(&message) {
        send_stun_message(
            &control,
            error_response(StunMethod::CreatePermission, message.transaction_id, 401),
        )
        .await?;
        return Ok(());
    }

    if let Some(allocation) = shared.allocation(&control).await
        && let Some(peer) = message.xor_peer_address
    {
        allocation.allow_peer(peer).await;
    }

    send_stun_message(
        &control,
        success_response(StunMethod::CreatePermission, message.transaction_id),
    )
    .await
}

async fn handle_channel_bind(
    message: StunDecoded,
    control: ControlPath,
    shared: Arc<SharedState>,
) -> Result<()> {
    if !is_authorized(&message) {
        send_stun_message(
            &control,
            error_response(StunMethod::ChannelBind, message.transaction_id, 401),
        )
        .await?;
        return Ok(());
    }

    if let Some(allocation) = shared.allocation(&control).await
        && let (Some(peer), Some(channel)) = (message.xor_peer_address, message.channel_number)
    {
        allocation.bind_channel(channel, peer).await;
    }

    send_stun_message(
        &control,
        success_response(StunMethod::ChannelBind, message.transaction_id),
    )
    .await
}

async fn handle_refresh(message: StunDecoded, control: ControlPath) -> Result<()> {
    if !is_authorized(&message) {
        send_stun_message(
            &control,
            error_response(StunMethod::Refresh, message.transaction_id, 401),
        )
        .await?;
        return Ok(());
    }

    send_stun_message(
        &control,
        StunMessage {
            class: StunClass::SuccessResponse,
            method: StunMethod::Refresh,
            transaction_id: message.transaction_id,
            attributes: vec![StunAttribute::Lifetime(TEST_TURN_LIFETIME)],
        },
    )
    .await
}

async fn handle_send_indication(
    message: StunDecoded,
    control: ControlPath,
    shared: Arc<SharedState>,
) -> Result<()> {
    let Some(allocation) = shared.allocation(&control).await else {
        return Ok(());
    };
    let Some(peer) = message.xor_peer_address else {
        return Ok(());
    };
    let Some(data) = message.data else {
        return Ok(());
    };

    allocation.relay_socket.send_to(&data, peer).await?;
    Ok(())
}

async fn run_relay_listener(allocation: Arc<Allocation>) {
    let mut buf = [0u8; 2048];
    loop {
        let (len, peer) = match allocation.relay_socket.recv_from(&mut buf).await {
            Ok(value) => value,
            Err(_) => break,
        };
        let payload = &buf[..len];
        let outbound = if let Some(channel) = allocation.channel_for_peer(peer).await {
            encode_channel_data(channel, payload)
        } else {
            StunMessage {
                class: StunClass::Indication,
                method: StunMethod::Data,
                transaction_id: random_bytes::<12>(),
                attributes: vec![
                    StunAttribute::XorPeerAddress(peer),
                    StunAttribute::Data(payload.to_vec()),
                ],
            }
            .encode(None, true)
            .expect("encode data indication")
        };

        if allocation.control.send_payload(&outbound).await.is_err() {
            break;
        }
    }
}

fn is_authorized(message: &StunDecoded) -> bool {
    message.realm.as_deref() == Some(TEST_TURN_REALM)
        && message.nonce.as_deref() == Some(TEST_TURN_NONCE)
}

fn success_response(method: StunMethod, transaction_id: [u8; 12]) -> StunMessage {
    StunMessage {
        class: StunClass::SuccessResponse,
        method,
        transaction_id,
        attributes: Vec::new(),
    }
}

fn error_response(method: StunMethod, transaction_id: [u8; 12], code: u16) -> StunMessage {
    StunMessage {
        class: StunClass::ErrorResponse,
        method,
        transaction_id,
        attributes: vec![
            StunAttribute::ErrorCode(code),
            StunAttribute::Realm(TEST_TURN_REALM.to_string()),
            StunAttribute::Nonce(TEST_TURN_NONCE.to_string()),
        ],
    }
}

async fn send_stun_message(control: &ControlPath, message: StunMessage) -> Result<()> {
    let bytes = message.encode(None, true)?;
    control.send_payload(&bytes).await
}

fn decode_channel_data(payload: &[u8]) -> Option<(u16, Vec<u8>)> {
    if payload.len() < 4 {
        return None;
    }
    let channel = u16::from_be_bytes([payload[0], payload[1]]);
    if !(0x4000..=0x7FFF).contains(&channel) {
        return None;
    }
    let len = u16::from_be_bytes([payload[2], payload[3]]) as usize;
    if payload.len() < 4 + len {
        return None;
    }
    Some((channel, payload[4..4 + len].to_vec()))
}

fn encode_channel_data(channel: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + payload.len());
    packet.extend_from_slice(&channel.to_be_bytes());
    packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

fn build_tls_server_config() -> Result<ServerConfig> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string(), "127.0.0.1".to_string()])?;
    let certs: Vec<CertificateDer<'static>> = vec![cert.cert.der().clone()];
    let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der()));
    Ok(ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?)
}
