use anyhow::{Result, anyhow, bail};
use md5::{Digest as Md5Digest, Md5};
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;
use tokio::time::timeout;
use tokio_rustls::TlsConnector;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, RootCertStore, SignatureScheme,
};

use super::stun::{StunAttribute, StunClass, StunMessage, StunMethod, random_bytes};
use super::{IceServerUri, IceTransportProtocol, MAX_STUN_MESSAGE};
use crate::{IceCredentialType, IceServer};

pub const DEFAULT_TURN_LIFETIME: u32 = 600;
pub const DEFAULT_STUN_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);

#[derive(Debug, Clone)]
pub(crate) struct TurnCredentials {
    pub username: String,
    pub password: String,
}

impl TurnCredentials {
    pub fn from_server(server: &IceServer) -> Result<Self> {
        if server.credential_type != IceCredentialType::Password {
            bail!("only password credentials supported for TURN");
        }
        let username = server
            .username
            .clone()
            .ok_or_else(|| anyhow!("TURN server missing username"))?;
        let password = server
            .credential
            .clone()
            .ok_or_else(|| anyhow!("TURN server missing credential"))?;
        Ok(Self { username, password })
    }
}

pub struct TurnClient {
    transport: TurnTransport,
    auth: Mutex<Option<TurnAuthState>>,
    channels: Mutex<HashMap<SocketAddr, u16>>,
    channel_map: Mutex<HashMap<u16, SocketAddr>>,
    next_channel: Mutex<u16>,
}

impl std::fmt::Debug for TurnClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TurnClient")
            .field("protocol", &self.transport.protocol())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
#[cfg_attr(not(test), allow(dead_code))]
struct TurnAuthState {
    username: String,
    password: String,
    realm: String,
    nonce: String,
    key: Vec<u8>,
}

#[cfg_attr(not(test), allow(dead_code))]
impl TurnAuthState {
    fn with_key(
        username: String,
        password: String,
        realm: String,
        nonce: String,
        key: Vec<u8>,
    ) -> Self {
        Self {
            username,
            password,
            realm,
            nonce,
            key,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    fn update_nonce(&mut self, realm: String, nonce: String) {
        self.realm = realm;
        self.nonce = nonce;
        self.key = long_term_key(&self.username, &self.realm, &self.password);
    }
}

impl TurnClient {
    pub(crate) async fn connect(
        uri: &IceServerUri,
        disable_ipv6: bool,
        allow_insecure_tls: bool,
    ) -> Result<Self> {
        let addr = uri.resolve(disable_ipv6).await?;
        let transport = match uri.transport {
            IceTransportProtocol::Udp => {
                let socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
                TurnTransport::Udp {
                    socket,
                    server: addr,
                }
            }
            IceTransportProtocol::Tcp => {
                let stream = TcpStream::connect(addr).await?;
                let (read, write) = if uri.secure {
                    split_tls_stream(stream, &uri.host, allow_insecure_tls).await?
                } else {
                    split_stream(stream)
                };
                TurnTransport::Stream {
                    protocol: IceTransportProtocol::Tcp,
                    read: Arc::new(Mutex::new(read)),
                    write: Arc::new(Mutex::new(write)),
                }
            }
        };
        Ok(Self {
            transport,
            auth: Mutex::new(None),
            channels: Mutex::new(HashMap::new()),
            channel_map: Mutex::new(HashMap::new()),
            next_channel: Mutex::new(0x4000),
        })
    }

    pub(crate) async fn allocate(&self, creds: TurnCredentials) -> Result<TurnAllocation> {
        *self.auth.lock().await = None;
        let mut nonce_info: Option<TurnNonce> = None;
        let mut attempt = 0;
        loop {
            attempt += 1;
            if attempt > 3 {
                bail!("TURN allocation failed after retries");
            }
            let tx_id = random_bytes::<12>();
            let attrs = vec![
                StunAttribute::RequestedTransport(17),
                StunAttribute::Lifetime(DEFAULT_TURN_LIFETIME),
            ];
            let (message, key_option) = if let Some(info) = &nonce_info {
                let key = long_term_key(&creds.username, &info.realm, &creds.password);
                let mut extended = attrs.clone();
                extended.push(StunAttribute::Username(creds.username.clone()));
                extended.push(StunAttribute::Realm(info.realm.clone()));
                extended.push(StunAttribute::Nonce(info.nonce.clone()));
                let msg = StunMessage::allocate_request(tx_id, extended);
                (msg, Some(key))
            } else {
                (StunMessage::allocate_request(tx_id, attrs.clone()), None)
            };
            let used_key = key_option.clone();
            let bytes = message.encode(key_option.as_deref(), true)?;
            self.send(&bytes).await?;
            let mut buf = [0u8; MAX_STUN_MESSAGE];
            let len = self.recv(&mut buf).await?;
            let parsed = StunMessage::decode(&buf[..len])?;
            if parsed.transaction_id != tx_id {
                continue;
            }
            if parsed.method != StunMethod::Allocate {
                bail!("unexpected STUN method in allocate response");
            }
            match parsed.class {
                StunClass::SuccessResponse => {
                    if let Some(relayed) = parsed.xor_relayed_address {
                        if let (Some(info), Some(key)) = (nonce_info.clone(), used_key) {
                            *self.auth.lock().await = Some(TurnAuthState::with_key(
                                creds.username.clone(),
                                creds.password.clone(),
                                info.realm,
                                info.nonce,
                                key,
                            ));
                        }
                        return Ok(TurnAllocation {
                            relayed_address: relayed,
                        });
                    }
                    bail!("TURN success without relayed address");
                }
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed
                            .realm
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing realm"))?;
                        let nonce = parsed
                            .nonce
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing nonce"))?;
                        nonce_info = Some(TurnNonce { realm, nonce });
                        continue;
                    }
                    bail!("TURN allocate error {}", parsed.error_code.unwrap_or(0));
                }
                _ => bail!("unexpected TURN response class"),
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn create_permission(&self, peer: SocketAddr) -> Result<()> {
        const MAX_ATTEMPTS: usize = 3;
        for _ in 0..MAX_ATTEMPTS {
            let tx_id = random_bytes::<12>();
            let bytes = {
                let auth_guard = self.auth.lock().await;
                let auth = auth_guard
                    .as_ref()
                    .ok_or_else(|| anyhow!("TURN allocation missing auth context"))?;
                let mut attributes = vec![StunAttribute::Username(auth.username.clone())];
                attributes.push(StunAttribute::Realm(auth.realm.clone()));
                attributes.push(StunAttribute::Nonce(auth.nonce.clone()));
                attributes.push(StunAttribute::XorPeerAddress(peer));
                let msg = StunMessage {
                    class: StunClass::Request,
                    method: StunMethod::CreatePermission,
                    transaction_id: tx_id,
                    attributes,
                };
                msg.encode(Some(&auth.key), true)?
            };
            self.send(&bytes).await?;
            let mut buf = [0u8; MAX_STUN_MESSAGE];
            let len = self.recv(&mut buf).await?;
            let parsed = StunMessage::decode(&buf[..len])?;
            if parsed.transaction_id != tx_id {
                continue;
            }
            if parsed.method != StunMethod::CreatePermission {
                bail!("unexpected STUN method in create-permission response");
            }
            match parsed.class {
                StunClass::SuccessResponse => return Ok(()),
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed
                            .realm
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing realm"))?;
                        let nonce = parsed
                            .nonce
                            .clone()
                            .ok_or_else(|| anyhow!("TURN error missing nonce"))?;
                        if let Some(state) = self.auth.lock().await.as_mut() {
                            state.update_nonce(realm, nonce);
                        }
                        continue;
                    }
                    bail!(
                        "TURN create-permission error {}",
                        parsed.error_code.unwrap_or(0)
                    );
                }
                _ => bail!("unexpected TURN response class"),
            }
        }
        bail!("TURN create-permission failed after retries");
    }

    pub(crate) async fn create_refresh_packet(&self) -> Result<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock().await;
        let auth = auth_guard
            .as_ref()
            .ok_or_else(|| anyhow!("TURN refresh: no auth context"))?;

        let attributes = vec![
            StunAttribute::Lifetime(DEFAULT_TURN_LIFETIME),
            StunAttribute::Username(auth.username.clone()),
            StunAttribute::Realm(auth.realm.clone()),
            StunAttribute::Nonce(auth.nonce.clone()),
        ];

        let msg = StunMessage {
            class: StunClass::Request,
            method: StunMethod::Refresh,
            transaction_id: tx_id,
            attributes,
        };
        let bytes = msg.encode(Some(&auth.key), true)?;
        Ok((bytes, tx_id))
    }

    pub(crate) async fn bound_peers(&self) -> Vec<SocketAddr> {
        self.channels.lock().await.keys().cloned().collect()
    }

    pub(crate) async fn send(&self, data: &[u8]) -> Result<()> {
        match &self.transport {
            TurnTransport::Udp { socket, server } => {
                socket.send_to(data, *server).await?;
            }
            TurnTransport::Stream { write, .. } => {
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(data);
                write.lock().await.write_all(&frame).await?;
            }
        }
        Ok(())
    }

    pub(crate) async fn recv(&self, buf: &mut [u8]) -> Result<usize> {
        match &self.transport {
            TurnTransport::Udp { socket, .. } => {
                let (len, _) = timeout(DEFAULT_STUN_TIMEOUT, socket.recv_from(buf)).await??;
                Ok(len)
            }
            TurnTransport::Stream { read, .. } => {
                timeout(DEFAULT_STUN_TIMEOUT, async {
                    let mut header = [0u8; 2];
                    let mut stream = read.lock().await;
                    stream.read_exact(&mut header).await?;
                    let len = u16::from_be_bytes(header) as usize;
                    let mut offset = 0;
                    while offset < len {
                        let read = stream.read(&mut buf[offset..len]).await?;
                        if read == 0 {
                            bail!("TURN TCP stream closed");
                        }
                        offset += read;
                    }
                    Ok(len)
                })
                .await?
            }
        }
    }

    pub(crate) async fn send_indication(&self, peer: SocketAddr, data: &[u8]) -> Result<()> {
        let tx_id = random_bytes::<12>();
        let mut attributes = vec![StunAttribute::XorPeerAddress(peer)];
        attributes.push(StunAttribute::Data(data.to_vec()));

        let msg = StunMessage {
            class: StunClass::Indication,
            method: StunMethod::Send,
            transaction_id: tx_id,
            attributes,
        };

        let bytes = {
            let auth_guard = self.auth.lock().await;
            if let Some(auth) = auth_guard.as_ref() {
                let mut authenticated_msg = msg.clone();
                authenticated_msg
                    .attributes
                    .insert(0, StunAttribute::Username(auth.username.clone()));
                authenticated_msg
                    .attributes
                    .insert(1, StunAttribute::Realm(auth.realm.clone()));
                authenticated_msg
                    .attributes
                    .insert(2, StunAttribute::Nonce(auth.nonce.clone()));
                authenticated_msg.encode(Some(&auth.key), true)?
            } else {
                msg.encode(None, false)?
            }
        };

        self.send(&bytes).await
    }

    pub(crate) async fn create_permission_packet(
        &self,
        peer: SocketAddr,
    ) -> Result<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock().await;
        let auth = auth_guard.as_ref().ok_or_else(|| anyhow!("no auth"))?;

        let mut attributes = vec![StunAttribute::Username(auth.username.clone())];
        attributes.push(StunAttribute::Realm(auth.realm.clone()));
        attributes.push(StunAttribute::Nonce(auth.nonce.clone()));
        attributes.push(StunAttribute::XorPeerAddress(peer));

        let msg = StunMessage {
            class: StunClass::Request,
            method: StunMethod::CreatePermission,
            transaction_id: tx_id,
            attributes,
        };
        let bytes = msg.encode(Some(&auth.key), true)?;
        Ok((bytes, tx_id))
    }

    pub(crate) async fn create_channel_bind_packet(
        &self,
        peer: SocketAddr,
    ) -> Result<(Vec<u8>, [u8; 12], u16)> {
        // Allocate new channel number
        let channel_number = {
            let mut next = self.next_channel.lock().await;
            let n = *next;
            if n >= 0x7FFF {
                *next = 0x4000;
            } else {
                *next += 1;
            }
            n
        };

        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock().await;
        let auth = auth_guard.as_ref().ok_or_else(|| anyhow!("no auth"))?;

        let attributes = vec![
            StunAttribute::ChannelNumber(channel_number),
            StunAttribute::XorPeerAddress(peer),
            StunAttribute::Username(auth.username.clone()),
            StunAttribute::Realm(auth.realm.clone()),
            StunAttribute::Nonce(auth.nonce.clone()),
        ];

        let msg = StunMessage {
            class: StunClass::Request,
            method: StunMethod::ChannelBind,
            transaction_id: tx_id,
            attributes,
        };
        let bytes = msg.encode(Some(&auth.key), true)?;
        Ok((bytes, tx_id, channel_number))
    }

    pub(crate) async fn create_channel_rebind_packet(
        &self,
        peer: SocketAddr,
        channel_number: u16,
    ) -> Result<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock().await;
        let auth = auth_guard.as_ref().ok_or_else(|| anyhow!("no auth"))?;

        let attributes = vec![
            StunAttribute::ChannelNumber(channel_number),
            StunAttribute::XorPeerAddress(peer),
            StunAttribute::Username(auth.username.clone()),
            StunAttribute::Realm(auth.realm.clone()),
            StunAttribute::Nonce(auth.nonce.clone()),
        ];

        let msg = StunMessage {
            class: StunClass::Request,
            method: StunMethod::ChannelBind,
            transaction_id: tx_id,
            attributes,
        };
        let bytes = msg.encode(Some(&auth.key), true)?;
        Ok((bytes, tx_id))
    }

    pub(crate) async fn add_channel(&self, peer: SocketAddr, channel: u16) {
        let mut channels = self.channels.lock().await;
        let mut channel_map = self.channel_map.lock().await;
        channels.insert(peer, channel);
        channel_map.insert(channel, peer);
    }

    pub(crate) async fn get_channel(&self, peer: SocketAddr) -> Option<u16> {
        let channels = self.channels.lock().await;
        channels.get(&peer).copied()
    }

    pub(crate) async fn get_peer(&self, channel: u16) -> Option<SocketAddr> {
        let channel_map = self.channel_map.lock().await;
        channel_map.get(&channel).copied()
    }

    pub(crate) async fn send_channel_data(&self, channel: u16, data: &[u8]) -> Result<()> {
        // ChannelData:
        // 0-1: Channel Number
        // 2-3: Length
        // 4-N: Data
        // Padding to 4 bytes (UDP only? RFC says "The ChannelData message is not padded to a 4-byte boundary")
        // Wait, RFC 5766 Section 11.5: "The ChannelData message is not padded to a 4-byte boundary"
        // BUT, if using TCP, we need framing.

        let mut packet = Vec::with_capacity(4 + data.len());
        packet.extend_from_slice(&channel.to_be_bytes());
        packet.extend_from_slice(&(data.len() as u16).to_be_bytes());
        packet.extend_from_slice(data);

        self.send(&packet).await
    }
}

#[derive(Clone)]
struct TurnNonce {
    realm: String,
    nonce: String,
}

#[derive(Clone)]
pub(crate) struct TurnAllocation {
    pub relayed_address: SocketAddr,
}

impl TurnTransport {
    fn protocol(&self) -> IceTransportProtocol {
        match self {
            TurnTransport::Udp { .. } => IceTransportProtocol::Udp,
            TurnTransport::Stream { protocol, .. } => *protocol,
        }
    }
}

#[derive(Clone)]
enum TurnTransport {
    Udp {
        socket: Arc<UdpSocket>,
        server: SocketAddr,
    },
    Stream {
        protocol: IceTransportProtocol,
        read: Arc<Mutex<BoxedReader>>,
        write: Arc<Mutex<BoxedWriter>>,
    },
}

type BoxedReader = Box<dyn AsyncRead + Send + Unpin>;
type BoxedWriter = Box<dyn AsyncWrite + Send + Unpin>;

fn split_stream<S>(stream: S) -> (BoxedReader, BoxedWriter)
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (read, write) = tokio::io::split(stream);
    (Box::new(read), Box::new(write))
}

async fn split_tls_stream(
    stream: TcpStream,
    host: &str,
    allow_insecure_tls: bool,
) -> Result<(BoxedReader, BoxedWriter)> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider())
        .ok();

    let mut root_store = RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let mut config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    if allow_insecure_tls {
        // This is intentionally opt-in and only used by local regression tests
        // that spin up a self-signed TURN/TLS server inside the test process.
        config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoCertificateVerification));
    }

    let server_name = server_name_from_host(host)?;
    let tls_stream = TlsConnector::from(Arc::new(config))
        .connect(server_name, stream)
        .await?;
    Ok(split_stream(tls_stream))
}

fn server_name_from_host(host: &str) -> Result<ServerName<'static>> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ServerName::IpAddress(ip.into()));
    }

    ServerName::try_from(host.to_string())
        .map_err(|_| anyhow!("invalid TURN TLS server name {}", host))
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, RustlsError> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, RustlsError> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA1,
            SignatureScheme::ECDSA_SHA1_Legacy,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP521_SHA512,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::ED25519,
            SignatureScheme::ED448,
        ]
    }
}

fn long_term_key(username: &str, realm: &str, password: &str) -> Vec<u8> {
    let input = format!("{}:{}:{}", username, realm, password);
    md5_digest(input.as_bytes()).to_vec()
}

fn md5_digest(input: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, input);
    let result = Md5Digest::finalize(hasher);
    let mut out = [0u8; 16];
    out.copy_from_slice(&result);
    out
}
