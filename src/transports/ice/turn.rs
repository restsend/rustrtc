use crate::errors::{RtcError, RtcResult};
use crate::platform::sync::AsyncMutex as Mutex;
use crate::platform::sync::Mutex as SyncMutex;
use crate::platform::time::with_timeout as timeout;
use crate::prelude::*;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use core::net::SocketAddr;
use md5::{Digest as Md5Digest, Md5};
#[cfg(feature = "std")] // TURN-TCP mode is excluded from the embedded target
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(feature = "std")]
use tokio::net::TcpStream;
#[cfg(feature = "std")]
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};

use super::stun::{StunAttribute, StunClass, StunMessage, StunMethod, random_bytes};
use super::{IceServerUri, IceTransportProtocol, MAX_STUN_MESSAGE};
use crate::{IceCredentialType, IceServer};

pub const DEFAULT_TURN_LIFETIME: u32 = 600;
pub const DEFAULT_STUN_TIMEOUT: core::time::Duration = core::time::Duration::from_secs(3);

#[derive(Debug, Clone)]
pub(crate) struct TurnCredentials {
    pub username: String,
    pub password: String,
}

impl TurnCredentials {
    pub fn from_server(server: &IceServer) -> RtcResult<Self> {
        if server.credential_type != IceCredentialType::Password {
            return Err(RtcError::Internal(format!(
                "only password credentials supported for TURN"
            )));
        }
        let username = server
            .username
            .clone()
            .ok_or_else(|| RtcError::Internal(format!("TURN server missing username")))?;
        let password = server
            .credential
            .clone()
            .ok_or_else(|| RtcError::Internal(format!("TURN server missing credential")))?;
        Ok(Self { username, password })
    }
}

#[derive(Debug)]
pub struct TurnClient {
    transport: TurnTransport,
    auth: SyncMutex<Option<TurnAuthState>>,
    channels: Mutex<BTreeMap<SocketAddr, u16>>,
    channel_map: Mutex<BTreeMap<u16, SocketAddr>>,
    next_channel: Mutex<u16>,
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
    pub(crate) async fn connect(uri: &IceServerUri, disable_ipv6: bool) -> RtcResult<Self> {
        let addr = timeout(DEFAULT_STUN_TIMEOUT, uri.resolve(disable_ipv6))
            .await
            .map_err(|_| RtcError::Internal(format!("TURN server DNS resolution timed out")))??;
        let transport = match uri.transport {
            IceTransportProtocol::Udp => {
                #[cfg(feature = "std")]
                let socket: Arc<dyn crate::platform::net::UdpSocket> = {
                    let sock = tokio::net::UdpSocket::bind("0.0.0.0:0")
                        .await
                        .map_err(|e| RtcError::Internal(format!("turn bind: {e}")))?;
                    Arc::new(crate::platform::net::tokio_impl::TokioUdpSocket::new(sock))
                };
                #[cfg(not(feature = "std"))]
                let socket: Arc<dyn crate::platform::net::UdpSocket> =
                    unimplemented!("no_std TURN socket injection (WP3)");
                TurnTransport::Udp {
                    socket,
                    server: addr,
                }
            }
            #[cfg(feature = "std")]
            IceTransportProtocol::Tcp => {
                let stream = timeout(DEFAULT_STUN_TIMEOUT, TcpStream::connect(addr))
                    .await
                    .map_err(|_| {
                        RtcError::Internal(format!("TURN TCP connect to {} timed out", addr))
                    })??;
                let (read, write) = stream.into_split();
                TurnTransport::Tcp {
                    read: Arc::new(Mutex::new(read)),
                    write: Arc::new(Mutex::new(write)),
                }
            }
            #[cfg(not(feature = "std"))]
            IceTransportProtocol::Tcp => {
                unimplemented!("TURN-TCP is excluded from the embedded target")
            }
        };
        Ok(Self {
            transport,
            auth: SyncMutex::new(None),
            channels: Mutex::new(BTreeMap::new()),
            channel_map: Mutex::new(BTreeMap::new()),
            next_channel: Mutex::new(0x4000),
        })
    }

    pub(crate) async fn allocate(&self, creds: TurnCredentials) -> RtcResult<TurnAllocation> {
        *self.auth.lock() = None;
        let mut nonce_info: Option<TurnNonce> = None;
        let mut attempt = 0;
        loop {
            attempt += 1;
            if attempt > 3 {
                return Err(RtcError::Internal(format!(
                    "TURN allocation failed after retries"
                )));
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
                return Err(RtcError::Internal(format!(
                    "unexpected STUN method in allocate response"
                )));
            }
            match parsed.class {
                StunClass::SuccessResponse => {
                    if let Some(relayed) = parsed.xor_relayed_address {
                        if let (Some(info), Some(key)) = (nonce_info.clone(), used_key) {
                            *self.auth.lock() = Some(TurnAuthState::with_key(
                                creds.username.clone(),
                                creds.password.clone(),
                                info.realm,
                                info.nonce,
                                key,
                            ));
                        }
                        let granted_lifetime = parsed
                            .lifetime
                            .filter(|&l| l > 0)
                            .unwrap_or(DEFAULT_TURN_LIFETIME);
                        return Ok(TurnAllocation {
                            relayed_address: relayed,
                            transport: self.transport.protocol(),
                            lifetime_secs: granted_lifetime,
                        });
                    }
                    return Err(RtcError::Internal(format!(
                        "TURN success without relayed address"
                    )));
                }
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed.realm.clone().ok_or_else(|| {
                            RtcError::Internal(format!("TURN error missing realm"))
                        })?;
                        let nonce = parsed.nonce.clone().ok_or_else(|| {
                            RtcError::Internal(format!("TURN error missing nonce"))
                        })?;
                        nonce_info = Some(TurnNonce { realm, nonce });
                        continue;
                    }
                    return Err(RtcError::Internal(format!(
                        "TURN allocate error {}",
                        parsed.error_code.unwrap_or(0)
                    )));
                }
                _ => {
                    return Err(RtcError::Internal(format!(
                        "unexpected TURN response class"
                    )));
                }
            }
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub(crate) async fn create_permission(&self, peer: SocketAddr) -> RtcResult<()> {
        const MAX_ATTEMPTS: usize = 3;
        for _ in 0..MAX_ATTEMPTS {
            let tx_id = random_bytes::<12>();
            let bytes = {
                let auth_guard = self.auth.lock();
                let auth = auth_guard.as_ref().ok_or_else(|| {
                    RtcError::Internal(format!("TURN allocation missing auth context"))
                })?;
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
                return Err(RtcError::Internal(format!(
                    "unexpected STUN method in create-permission response"
                )));
            }
            match parsed.class {
                StunClass::SuccessResponse => return Ok(()),
                StunClass::ErrorResponse => {
                    if parsed.error_code == Some(401) || parsed.error_code == Some(438) {
                        let realm = parsed.realm.clone().ok_or_else(|| {
                            RtcError::Internal(format!("TURN error missing realm"))
                        })?;
                        let nonce = parsed.nonce.clone().ok_or_else(|| {
                            RtcError::Internal(format!("TURN error missing nonce"))
                        })?;
                        if let Some(state) = self.auth.lock().as_mut() {
                            state.update_nonce(realm, nonce);
                        }
                        continue;
                    }
                    return Err(RtcError::Internal(format!(
                        "TURN create-permission error {}",
                        parsed.error_code.unwrap_or(0)
                    )));
                }
                _ => {
                    return Err(RtcError::Internal(format!(
                        "unexpected TURN response class"
                    )));
                }
            }
        }
        return Err(RtcError::Internal(format!(
            "TURN create-permission failed after retries"
        )));
    }

    pub(crate) async fn create_refresh_packet(&self) -> RtcResult<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock();
        let auth = auth_guard
            .as_ref()
            .ok_or_else(|| RtcError::Internal(format!("TURN refresh: no auth context")))?;

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

    /// Build a Refresh request with LIFETIME=0 to explicitly destroy the
    /// allocation (RFC 5766 §7.4 "Destroying an Allocation"). The server
    /// releases the allocation upon receipt of the request; the success
    /// response (which carries LIFETIME=0) is purely informational.
    pub(crate) fn create_destroy_packet_sync(&self) -> RtcResult<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let guard = self
            .auth
            .try_lock()
            .ok_or_else(|| RtcError::Internal(format!("TURN destroy: auth mutex busy")))?;
        let auth = guard
            .as_ref()
            .ok_or_else(|| RtcError::Internal(format!("TURN destroy: no auth context")))?;

        let attributes = vec![
            StunAttribute::Lifetime(0),
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

    /// Update the stored nonce (and realm) after receiving a 401/438 from the TURN server.
    /// Must be called before retrying the request that triggered the stale-nonce error.
    pub(crate) async fn update_nonce(&self, realm: String, nonce: String) {
        if let Some(state) = self.auth.lock().as_mut() {
            state.update_nonce(realm, nonce);
        }
    }

    pub(crate) async fn bound_peers(&self) -> Vec<SocketAddr> {
        self.channels.lock().await.keys().cloned().collect()
    }

    pub(crate) async fn send(&self, data: &[u8]) -> RtcResult<()> {
        match &self.transport {
            TurnTransport::Udp { socket, server } => {
                socket.send_to(data, *server).await?;
            }
            #[cfg(feature = "std")]
            TurnTransport::Tcp { write, .. } => {
                let mut frame = Vec::with_capacity(2 + data.len());
                frame.extend_from_slice(&(data.len() as u16).to_be_bytes());
                frame.extend_from_slice(data);
                write.lock().await.write_all(&frame).await?;
            }
        }
        Ok(())
    }

    /// Synchronous best-effort send for the close path. UDP uses
    /// `try_send_to` (non-blocking); TCP is skipped (needs async write).
    /// Returns true if a best-effort attempt was made.
    pub(crate) fn try_send_sync(&self, data: &[u8]) -> bool {
        match &self.transport {
            TurnTransport::Udp { socket, server } => {
                let _ = socket.try_send_to(data, *server);
                true
            }
            #[cfg(feature = "std")]
            TurnTransport::Tcp { .. } => false,
            #[cfg(not(feature = "std"))]
            _ => false,
        }
    }

    pub(crate) async fn recv(&self, buf: &mut [u8]) -> RtcResult<usize> {
        match &self.transport {
            TurnTransport::Udp { socket, .. } => {
                let (len, _) = timeout(DEFAULT_STUN_TIMEOUT, socket.recv_from(buf))
                    .await
                    .map_err(|_| RtcError::Internal("timeout".into()))?
                    .map_err(RtcError::from)?;
                Ok(len)
            }
            #[cfg(feature = "std")]
            TurnTransport::Tcp { read, .. } => {
                let mut header = [0u8; 2];
                let mut stream = read.lock().await;
                stream.read_exact(&mut header).await?;
                let len = u16::from_be_bytes(header) as usize;
                let mut offset = 0;
                while offset < len {
                    let read = stream.read(&mut buf[offset..len]).await?;
                    if read == 0 {
                        return Err(RtcError::Internal(format!("TURN TCP stream closed")));
                    }
                    offset += read;
                }
                Ok(len)
            }
        }
    }

    pub(crate) async fn send_indication(&self, peer: SocketAddr, data: &[u8]) -> RtcResult<()> {
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
            let auth_guard = self.auth.lock();
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
    ) -> RtcResult<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock();
        let auth = auth_guard
            .as_ref()
            .ok_or_else(|| RtcError::Internal(format!("no auth")))?;

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
    ) -> RtcResult<(Vec<u8>, [u8; 12], u16)> {
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
        let auth_guard = self.auth.lock();
        let auth = auth_guard
            .as_ref()
            .ok_or_else(|| RtcError::Internal(format!("no auth")))?;

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
    ) -> RtcResult<(Vec<u8>, [u8; 12])> {
        let tx_id = random_bytes::<12>();
        let auth_guard = self.auth.lock();
        let auth = auth_guard
            .as_ref()
            .ok_or_else(|| RtcError::Internal(format!("no auth")))?;

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

    pub(crate) async fn send_channel_data(&self, channel: u16, data: &[u8]) -> RtcResult<()> {
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
    pub transport: IceTransportProtocol,
    /// Lifetime (seconds) the server actually granted. May be smaller than the
    /// requested `DEFAULT_TURN_LIFETIME`; clients must refresh before it elapses
    /// (RFC 5766 §2.2/§7).
    pub lifetime_secs: u32,
}

impl TurnTransport {
    fn protocol(&self) -> IceTransportProtocol {
        match self {
            TurnTransport::Udp { .. } => IceTransportProtocol::Udp,
            #[cfg(feature = "std")]
            TurnTransport::Tcp { .. } => IceTransportProtocol::Tcp,
            #[cfg(not(feature = "std"))]
            _ => IceTransportProtocol::Udp,
        }
    }
}

enum TurnTransport {
    Udp {
        socket: Arc<dyn crate::platform::net::UdpSocket>,
        server: SocketAddr,
    },
    #[cfg(feature = "std")]
    Tcp {
        read: Arc<Mutex<OwnedReadHalf>>,
        write: Arc<Mutex<OwnedWriteHalf>>,
    },
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

impl core::fmt::Debug for TurnTransport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TurnTransport::Udp { server, .. } => f
                .debug_struct("TurnTransport::Udp")
                .field("server", server)
                .finish(),
            #[cfg(feature = "std")]
            TurnTransport::Tcp { .. } => f.write_str("TurnTransport::Tcp"),
        }
    }
}

impl Clone for TurnTransport {
    fn clone(&self) -> Self {
        match self {
            TurnTransport::Udp { socket, server } => TurnTransport::Udp {
                socket: socket.clone(),
                server: server.clone(),
            },
            #[cfg(feature = "std")]
            TurnTransport::Tcp { read, write } => TurnTransport::Tcp {
                read: read.clone(),
                write: write.clone(),
            },
        }
    }
}
