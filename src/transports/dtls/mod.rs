pub mod handshake;
#[cfg(test)]
mod interop_tests;
pub mod record;
#[cfg(test)]
mod tests;

use aes_gcm::{
    Aes128Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use anyhow::Result;
use bytes::{Buf, Bytes, BytesMut};
use core::fmt;
use hmac::{Hmac, Mac};
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{SigningKey, signature::RandomizedSigner};
use p256::pkcs8::DecodePrivateKey;
use p256::{PublicKey, ecdh::EphemeralSecret, elliptic_curve::sec1::ToEncodedPoint};
use rand_core::OsRng;
use rcgen::generate_simple_self_signed;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};

use self::handshake::{
    CertificateMessage, ClientHello, ClientKeyExchange, Finished, HandshakeMessage, HandshakeType,
    HelloVerifyRequest, Random, ServerHello, ServerHelloDone, ServerKeyExchange,
};
use self::record::{ContentType, DtlsRecord, ProtocolVersion};
use crate::transports::ice::conn::IceConn;
use tracing::{debug, trace, warn};

pub fn generate_certificate() -> Result<Certificate> {
    let cert = generate_simple_self_signed(vec!["localhost".to_string()])?;
    Ok(Certificate {
        certificate: vec![cert.cert.der().to_vec()],
        private_key: cert.signing_key.serialize_pem(),
    })
}

pub fn fingerprint(cert: &Certificate) -> String {
    let mut hasher = Sha256::new();
    hasher.update(&cert.certificate[0]);
    let result = hasher.finalize();
    result
        .iter()
        .map(|b| format!("{:02X}", b))
        .collect::<Vec<String>>()
        .join(":")
}

#[derive(Clone)]
pub struct Certificate {
    pub certificate: Vec<Vec<u8>>,
    pub private_key: String, // PEM encoded key
}

#[derive(Clone, PartialEq)]
pub struct SessionKeys {
    pub client_write_key: Vec<u8>,
    pub server_write_key: Vec<u8>,
    pub client_write_iv: Vec<u8>,
    pub server_write_iv: Vec<u8>,
    pub master_secret: Vec<u8>,
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
}

struct DtlsInner {
    conn: Arc<IceConn>,
    state: Arc<Mutex<DtlsState>>,
    state_tx: tokio::sync::watch::Sender<DtlsState>,
    state_rx: tokio::sync::watch::Receiver<DtlsState>,
    incoming_data_rx: Arc<Mutex<mpsc::Receiver<Vec<u8>>>>,
    outgoing_data_tx: mpsc::Sender<Vec<u8>>,
    handshake_rx_feeder: mpsc::Sender<Vec<u8>>,
}

pub struct DtlsTransport {
    inner: Arc<DtlsInner>,
    close_tx: Arc<tokio::sync::Notify>,
}

#[derive(Clone, PartialEq)]
pub enum DtlsState {
    New,
    Handshaking,
    Connected(SessionKeys, Option<u16>),
    Failed,
    Closed,
}

impl fmt::Display for DtlsState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DtlsState::New => write!(f, "New"),
            DtlsState::Handshaking => write!(f, "Handshaking"),
            DtlsState::Connected(_, profile) => write!(f, "Connected (SRTP: {:?})", profile),
            DtlsState::Failed => write!(f, "Failed"),
            DtlsState::Closed => write!(f, "Closed"),
        }
    }
}

impl DtlsTransport {
    pub async fn get_state(&self) -> DtlsState {
        self.inner.state.lock().await.clone()
    }

    pub async fn new(
        conn: Arc<IceConn>,
        certificate: Certificate,
        is_client: bool,
    ) -> Result<(Arc<Self>, impl std::future::Future<Output = ()> + Send)> {
        let (incoming_data_tx, incoming_data_rx) = mpsc::channel(100);
        let (outgoing_data_tx, outgoing_data_rx) = mpsc::channel(100);
        let (handshake_rx_feeder, handshake_rx) = mpsc::channel(100);
        let (state_tx, state_rx) = tokio::sync::watch::channel(DtlsState::New);

        let inner = Arc::new(DtlsInner {
            conn: conn.clone(),
            state: Arc::new(Mutex::new(DtlsState::New)),
            state_tx,
            state_rx,
            incoming_data_rx: Arc::new(Mutex::new(incoming_data_rx)),
            outgoing_data_tx,
            handshake_rx_feeder,
        });

        let close_tx = Arc::new(tokio::sync::Notify::new());
        let close_rx = close_tx.clone();

        let transport = Arc::new(Self {
            inner: inner.clone(),
            close_tx,
        });

        // Register with IceConn
        conn.set_dtls_receiver(transport.clone()).await;

        let inner_clone = inner.clone();
        let runner = async move {
            if let Err(e) = inner_clone
                .handshake(
                    certificate,
                    is_client,
                    incoming_data_tx,
                    outgoing_data_rx,
                    handshake_rx,
                    close_rx,
                )
                .await
            {
                warn!("DTLS handshake failed: {}", e);
                *inner_clone.state.lock().await = DtlsState::Failed;
                let _ = inner_clone.state_tx.send(DtlsState::Failed);
            }
            // Connected state is set inside handshake now
        };

        Ok((transport, runner))
    }

    pub fn subscribe_state(&self) -> tokio::sync::watch::Receiver<DtlsState> {
        self.inner.state_rx.clone()
    }

    pub fn close(&self) {
        self.close_tx.notify_waiters();
    }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
        self.inner
            .outgoing_data_tx
            .send(data.to_vec())
            .await
            .map_err(|_| anyhow::anyhow!("Send failed"))
    }

    pub async fn recv(&self) -> Result<Vec<u8>> {
        let mut rx = self.inner.incoming_data_rx.lock().await;
        rx.recv().await.ok_or(anyhow::anyhow!("Channel closed"))
    }

    pub async fn export_keying_material(&self, label: &str, len: usize) -> Result<Vec<u8>> {
        let state = self.inner.state.lock().await;
        if let DtlsState::Connected(keys, _) = &*state {
            let seed = [keys.client_random.as_slice(), keys.server_random.as_slice()].concat();
            prf_sha256(&keys.master_secret, label.as_bytes(), &seed, len)
        } else {
            Err(anyhow::anyhow!("DTLS not connected"))
        }
    }
}

impl Drop for DtlsTransport {
    fn drop(&mut self) {
        self.close_tx.notify_waiters();
    }
}

impl DtlsInner {
    async fn handle_retransmit(&self, ctx: &HandshakeContext, is_client: bool) {
        if let Some(buf) = &ctx.last_flight_buffer
            && is_client
            && ctx.message_seq == 1
            && let Err(e) = self.conn.send(buf).await
        {
            warn!("Retransmission failed: {}", e);
        }
    }

    async fn handle_incoming_packet(
        &self,
        packet: Vec<u8>,
        ctx: &mut HandshakeContext,
        incoming_data_tx: &mpsc::Sender<Vec<u8>>,
        certificate: &Certificate,
        is_client: bool,
    ) -> Result<()> {
        let mut data = Bytes::from(packet);

        while !data.is_empty() {
            match DtlsRecord::decode(&mut data) {
                Ok(None) => break,
                Ok(Some(record)) => {
                    let payload = match self.try_decrypt_record(&record, ctx, is_client) {
                        Ok(p) => p,
                        Err(e) => {
                            warn!("{}", e);
                            break;
                        }
                    };

                    self.handle_decrypted_record(
                        record.content_type,
                        payload,
                        ctx,
                        incoming_data_tx,
                        certificate,
                        is_client,
                    )
                    .await?;
                }
                Err(e) => {
                    warn!("Failed to decode DTLS record: {}", e);
                    data = Bytes::new();
                }
            }
        }
        Ok(())
    }

    fn try_decrypt_record(
        &self,
        record: &DtlsRecord,
        ctx: &HandshakeContext,
        is_client: bool,
    ) -> Result<Bytes> {
        if record.epoch == 0 {
            return Ok(record.payload.clone());
        }

        if let Some(keys) = &ctx.session_keys {
            let (key, iv) = if is_client {
                (&keys.server_write_key, &keys.server_write_iv)
            } else {
                (&keys.client_write_key, &keys.client_write_iv)
            };

            // Sequence number for AAD is epoch (16) + seq (48)
            let full_seq = ((record.epoch as u64) << 48) | record.sequence_number;

            match decrypt_record(
                record.content_type,
                record.version,
                full_seq,
                &record.payload,
                key,
                iv,
            ) {
                Ok(p) => Ok(Bytes::from(p)),
                Err(e) => {
                    debug!(
                        "Decryption failed details: seq={} epoch={} type={:?} ver={:?} len={}",
                        record.sequence_number,
                        record.epoch,
                        record.content_type,
                        record.version,
                        record.payload.len()
                    );
                    Err(anyhow::anyhow!("Decryption failed: {}", e))
                }
            }
        } else {
            Err(anyhow::anyhow!(
                "Received encrypted record but no keys available"
            ))
        }
    }

    async fn handle_decrypted_record(
        &self,
        content_type: ContentType,
        payload: Bytes,
        ctx: &mut HandshakeContext,
        incoming_data_tx: &mpsc::Sender<Vec<u8>>,
        certificate: &Certificate,
        is_client: bool,
    ) -> Result<()> {
        match content_type {
            ContentType::ChangeCipherSpec => {
                trace!("Received ChangeCipherSpec");
                // TODO: Switch to encrypted mode
            }
            ContentType::ApplicationData => {
                if let Err(e) = incoming_data_tx.send(payload.to_vec()).await {
                    warn!("Failed to send incoming data to channel: {}", e);
                }
            }
            ContentType::Handshake => {
                self.process_handshake_payload(payload, ctx, certificate, is_client)
                    .await?;
            }
            ContentType::Alert => {
                trace!("Received Alert: {:?}", payload);
                if payload.len() >= 2 {
                    let description = payload[1];
                    if description == 0 {
                        // CloseNotify
                        *self.state.lock().await = DtlsState::Closed;
                        let _ = self.state_tx.send(DtlsState::Closed);
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }

    async fn process_handshake_payload(
        &self,
        mut body: Bytes,
        ctx: &mut HandshakeContext,
        certificate: &Certificate,
        is_client: bool,
    ) -> Result<()> {
        while !body.is_empty() {
            let msg_buf = body.clone();
            match HandshakeMessage::decode(&mut body) {
                Ok(None) => break,
                Ok(Some(msg)) => {
                    let consumed = msg_buf.len() - body.len();
                    let raw_msg = msg_buf.slice(0..consumed);

                    if msg.message_seq < ctx.recv_message_seq {
                        // Duplicate
                        // Special case: ClientHello on Server (to trigger retransmit)
                        if msg.msg_type == HandshakeType::ClientHello && !is_client {
                            self.handle_handshake_message(
                                msg,
                                &raw_msg,
                                ctx,
                                certificate,
                                is_client,
                            )
                            .await?;
                        }
                        continue;
                    }

                    if msg.message_seq > ctx.recv_message_seq {
                        warn!(
                            "Received out-of-order handshake message: got {}, expected {}",
                            msg.message_seq, ctx.recv_message_seq
                        );
                        // Ignore out-of-order for now
                        continue;
                    }

                    // Expected message
                    ctx.recv_message_seq += 1;

                    if msg.msg_type != HandshakeType::Finished
                        && msg.msg_type != HandshakeType::HelloRequest
                        && msg.msg_type != HandshakeType::HelloVerifyRequest
                    {
                        ctx.handshake_messages.extend_from_slice(&raw_msg[..]);
                    }

                    self.handle_handshake_message(msg, &raw_msg, ctx, certificate, is_client)
                        .await?;
                }
                Err(e) => {
                    warn!("Failed to decode handshake message: {}", e);
                    // If decoding fails, we probably can't continue parsing this record
                    return Ok(());
                }
            }
        }
        Ok(())
    }

    async fn handle_handshake_message(
        &self,
        msg: HandshakeMessage,
        raw_msg: &[u8],
        ctx: &mut HandshakeContext,
        certificate: &Certificate,
        is_client: bool,
    ) -> Result<()> {
        match msg.msg_type {
            HandshakeType::ClientHello => {
                self.handle_client_hello(msg, ctx, certificate, is_client)
                    .await?;
            }
            HandshakeType::ClientKeyExchange => {
                self.handle_client_key_exchange(msg, ctx, is_client)?;
            }
            HandshakeType::Finished => {
                self.handle_finished(msg, raw_msg, ctx, is_client).await?;
            }
            HandshakeType::HelloVerifyRequest => {
                self.handle_hello_verify_request(msg, ctx, is_client)
                    .await?;
            }
            HandshakeType::ServerHello => {
                self.handle_server_hello(msg, ctx, is_client)?;
            }
            HandshakeType::Certificate => {}
            HandshakeType::ServerKeyExchange => {
                self.handle_server_key_exchange(msg, ctx, is_client)?;
            }
            HandshakeType::ServerHelloDone => {
                self.handle_server_hello_done(ctx, is_client).await?;
            }
            _ => {}
        }
        Ok(())
    }

    async fn handle_client_hello(
        &self,
        msg: HandshakeMessage,
        ctx: &mut HandshakeContext,
        certificate: &Certificate,
        is_client: bool,
    ) -> Result<()> {
        if is_client {
            return Ok(());
        }

        if ctx.server_random.is_some() {
            if let Some(flight) = &ctx.last_flight_buffer {
                if let Err(e) = self.conn.send(flight).await {
                    warn!("Failed to retransmit flight: {}", e);
                }
            }
            return Ok(());
        }

        let mut body = msg.body.clone();
        let client_hello = match ClientHello::decode(&mut body) {
            Ok(ch) => ch,
            Err(e) => {
                warn!("Failed to decode ClientHello: {}", e);
                return Ok(());
            }
        };

        trace!(
            "ClientHello Version: {:?} ({}, {})",
            client_hello.version, client_hello.version.major, client_hello.version.minor
        );
        ctx.client_random = Some(client_hello.random.to_bytes());
        // Parse ClientHello extensions to trace
        let mut srtp_profiles = Vec::new();
        let mut ext_buf = Bytes::from(client_hello.extensions.clone());
        while ext_buf.len() >= 4 {
            let ext_type = ext_buf.get_u16();
            let ext_len = ext_buf.get_u16() as usize;
            if ext_buf.len() < ext_len {
                break;
            }
            let _ext_data = ext_buf.split_to(ext_len);
            if ext_type == 13 {
                // signature_algorithms
            } else if ext_type == 10 {
                // supported_groups
            } else if ext_type == 14 {
                // use_srtp
                if _ext_data.len() >= 2 {
                    let len = u16::from_be_bytes([_ext_data[0], _ext_data[1]]) as usize;
                    let mut idx = 2;
                    while idx < 2 + len && idx + 1 < _ext_data.len() {
                        let profile = u16::from_be_bytes([_ext_data[idx], _ext_data[idx + 1]]);
                        srtp_profiles.push(profile);
                        idx += 2;
                    }
                }
            } else if ext_type == 23 {
                // extended_master_secret
                ctx.ems_negotiated = true;
            }
        }
        let random = Random::new();
        ctx.server_random = Some(random.to_bytes());

        let mut extensions = Vec::new();
        // Supported Point Formats (uncompressed)
        extensions.extend_from_slice(&[0x00, 0x0b]); // Type
        extensions.extend_from_slice(&[0x00, 0x02]); // Length
        extensions.extend_from_slice(&[0x01]); // List Length
        extensions.extend_from_slice(&[0x00]); // uncompressed

        // Renegotiation Info (empty)
        extensions.extend_from_slice(&[0xff, 0x01]); // Type
        extensions.extend_from_slice(&[0x00, 0x01]); // Length
        extensions.extend_from_slice(&[0x00]); // Body (len 0)

        // Extended Master Secret
        if ctx.ems_negotiated {
            extensions.extend_from_slice(&[0x00, 0x17]); // Type 23
            extensions.extend_from_slice(&[0x00, 0x00]); // Length 0
        }

        // Use SRTP
        if !srtp_profiles.is_empty() {
            let selected_profile = srtp_profiles[0];
            ctx.srtp_profile = Some(selected_profile);
            extensions.extend_from_slice(&[0x00, 0x0e]); // Type 14
            extensions.extend_from_slice(&[0x00, 0x05]); // Length
            extensions.extend_from_slice(&[0x00, 0x02]); // List Length
            extensions.extend_from_slice(&selected_profile.to_be_bytes());
            extensions.extend_from_slice(&[0x00]); // MKI Length
        }

        // Generate new Session ID to force full handshake
        let mut session_id = vec![0u8; 32];
        use rand_core::RngCore;
        OsRng.fill_bytes(&mut session_id);

        let server_hello = ServerHello {
            version: ProtocolVersion::DTLS_1_2,
            random,
            session_id,           // Always new session ID
            cipher_suite: 0xC02B, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            compression_method: 0,
            extensions,
        };
        let mut body = BytesMut::new();
        server_hello.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::ServerHello,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        let mut flight_buffer = Vec::new();

        let buf = self
            .send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                None,
                is_client,
            )
            .await?;
        flight_buffer.extend_from_slice(&buf);
        ctx.message_seq += 1;

        // Send Certificate
        let cert_msg = CertificateMessage {
            certificates: certificate.certificate.clone(),
        };

        let mut body = BytesMut::new();
        cert_msg.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::Certificate,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        let buf = self
            .send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                None,
                is_client,
            )
            .await?;
        flight_buffer.extend_from_slice(&buf);
        ctx.message_seq += 1;

        // Send ServerKeyExchange
        let mut params = Vec::new();
        if let (Some(cr), Some(sr)) = (&ctx.client_random, &ctx.server_random) {
            params.extend_from_slice(cr);
            params.extend_from_slice(sr);
        }
        params.push(3); // curve_type: named_curve
        params.extend_from_slice(&23u16.to_be_bytes()); // named_curve: secp256r1
        params.push(ctx.local_public_key_bytes.len() as u8);
        params.extend_from_slice(&ctx.local_public_key_bytes);

        let signing_key = SigningKey::from_pkcs8_pem(&certificate.private_key)
            .map_err(|e| anyhow::anyhow!("Failed to parse private key: {}", e))?;
        let signature: p256::ecdsa::Signature = signing_key.sign_with_rng(&mut OsRng, &params);
        let signature_bytes = signature.to_der().as_bytes().to_vec();
        // Self-verification
        let verifying_key = signing_key.verifying_key();
        if let Err(e) = verifying_key.verify(&params, &signature) {
            warn!("SELF-VERIFICATION FAILED: {}", e);
        }

        let server_key_exchange = ServerKeyExchange {
            curve_type: 3,   // named_curve
            named_curve: 23, // secp256r1
            public_key: ctx.local_public_key_bytes.clone(),
            signature: signature_bytes,
        };

        let mut body = BytesMut::new();
        server_key_exchange.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::ServerKeyExchange,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        let buf = self
            .send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                None,
                is_client,
            )
            .await?;
        flight_buffer.extend_from_slice(&buf);
        ctx.message_seq += 1;

        // Send ServerHelloDone
        let done_msg = ServerHelloDone {};
        let mut body = BytesMut::new();
        done_msg.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::ServerHelloDone,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        let buf = self
            .send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                None,
                is_client,
            )
            .await?;
        flight_buffer.extend_from_slice(&buf);
        ctx.message_seq += 1;

        ctx.last_flight_buffer = Some(flight_buffer);

        Ok(())
    }

    fn handle_client_key_exchange(
        &self,
        msg: HandshakeMessage,
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        if is_client {
            return Ok(());
        }

        if ctx.session_keys.is_some() {
            trace!("Session keys already derived, skipping ClientKeyExchange processing");
            return Ok(());
        }

        trace!("Received ClientKeyExchange");
        let mut body = msg.body.clone();
        let client_key_exchange = match ClientKeyExchange::decode(&mut body) {
            Ok(cke) => cke,
            Err(_) => {
                warn!("Failed to decode ClientKeyExchange");
                return Ok(());
            }
        };

        ctx.peer_public_key = Some(client_key_exchange.public_key);

        // Compute shared secret
        let peer_key = if let Some(pk) = &ctx.peer_public_key {
            pk
        } else {
            return Ok(());
        };

        let secret = if let Some(s) = ctx.local_secret.as_ref() {
            s
        } else {
            warn!("Local secret not available (already consumed?)");
            return Ok(());
        };

        let pk = match PublicKey::from_sec1_bytes(peer_key) {
            Ok(pk) => pk,
            Err(_) => {
                warn!("Failed to parse peer public key");
                return Ok(());
            }
        };

        let shared_secret = secret.diffie_hellman(&pk);
        trace!("Shared secret computed (Server)");

        let (cr, sr) = match (&ctx.client_random, &ctx.server_random) {
            (Some(cr), Some(sr)) => (cr, sr),
            _ => return Ok(()),
        };

        let pre_master_secret = shared_secret.raw_secret_bytes();
        let mut seed = Vec::new();
        seed.extend_from_slice(cr);
        seed.extend_from_slice(sr);

        let master_secret_res = if ctx.ems_negotiated {
            let mut hasher = Sha256::new();
            hasher.update(&ctx.handshake_messages);
            let session_hash = hasher.finalize();
            trace!("EMS Session Hash: {:?}", session_hash);
            prf_sha256(
                pre_master_secret,
                b"extended master secret",
                &session_hash,
                48,
            )
        } else {
            prf_sha256(pre_master_secret, b"master secret", &seed, 48)
        };

        let master_secret = match master_secret_res {
            Ok(ms) => ms,
            Err(_) => return Ok(()),
        };

        trace!("Master secret derived: {:?}", master_secret);

        let keys = match expand_keys(&master_secret, cr, sr) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };

        trace!("Session keys derived (Server)");
        ctx.session_keys = Some(keys);

        Ok(())
    }

    async fn handle_finished(
        &self,
        msg: HandshakeMessage,
        raw_msg: &[u8],
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        let mut body = msg.body.clone();
        let finished = match Finished::decode(&mut body) {
            Ok(f) => f,
            Err(e) => {
                warn!("Failed to decode Finished message: {}", e);
                return Ok(());
            }
        };

        if !is_client {
            // Verify Client's Finished
            if let Some(keys) = &ctx.session_keys {
                let expected_verify_data = calculate_verify_data(
                    &keys.master_secret,
                    b"client finished",
                    &ctx.handshake_messages,
                )?;

                if finished.verify_data != expected_verify_data {
                    warn!(
                        "Finished verification failed. Expected {:?}, got {:?}",
                        expected_verify_data, finished.verify_data
                    );
                    *self.state.lock().await = DtlsState::Failed;
                    return Err(anyhow::anyhow!("Finished verification failed"));
                } else {
                    trace!("Client Finished verified");
                }
            }

            // Add Client's Finished to transcript
            ctx.handshake_messages.extend_from_slice(raw_msg);

            // Send ChangeCipherSpec
            let record = DtlsRecord {
                content_type: ContentType::ChangeCipherSpec,
                version: ProtocolVersion::DTLS_1_2,
                epoch: ctx.epoch,
                sequence_number: ctx.sequence_number,
                payload: Bytes::from_static(&[1]),
            };
            // sequence_number increment is not needed as we reset it below

            let mut buf = BytesMut::new();
            record.encode(&mut buf);
            self.conn.send(&buf).await?;

            ctx.epoch += 1;
            ctx.sequence_number = 0;

            // Send Finished
            let verify_data = if let Some(keys) = &ctx.session_keys {
                calculate_verify_data(
                    &keys.master_secret,
                    b"server finished",
                    &ctx.handshake_messages,
                )?
            } else {
                vec![0u8; 12]
            };

            let finished = Finished { verify_data };

            let mut body = BytesMut::new();
            finished.encode(&mut body);

            let handshake_msg = HandshakeMessage {
                msg_type: HandshakeType::Finished,
                message_seq: ctx.message_seq,
                fragment_offset: 0,
                fragment_length: body.len() as u32,
                body: body.freeze(),
            };

            let mut buf = BytesMut::new();
            handshake_msg.encode(&mut buf);
            ctx.handshake_messages.extend_from_slice(&buf);

            self.send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                ctx.session_keys.as_ref(),
                is_client,
            )
            .await?;
            // message_seq += 1; // End of handshake

            if let Some(keys) = &ctx.session_keys {
                let state = DtlsState::Connected(keys.clone(), ctx.srtp_profile);
                *self.state.lock().await = state.clone();
                let _ = self.state_tx.send(state);
                // Clear ephemeral secret as handshake is complete
                ctx.local_secret = None;
            } else {
                *self.state.lock().await = DtlsState::Failed;
                let _ = self.state_tx.send(DtlsState::Failed);
                return Err(anyhow::anyhow!("Session keys not derived"));
            }
        } else {
            // Client logic: Verify Finished
            if let Some(keys) = &ctx.session_keys {
                let expected_verify_data = calculate_verify_data(
                    &keys.master_secret,
                    b"server finished",
                    &ctx.handshake_messages,
                )?;

                if finished.verify_data != expected_verify_data {
                    warn!(
                        "Finished verification failed. Expected {:?}, got {:?}",
                        expected_verify_data, finished.verify_data
                    );
                    *self.state.lock().await = DtlsState::Failed;
                    return Err(anyhow::anyhow!("Finished verification failed"));
                } else {
                    debug!("Finished verified");
                    if let Some(keys) = &ctx.session_keys {
                        let state = DtlsState::Connected(keys.clone(), ctx.srtp_profile);
                        *self.state.lock().await = state.clone();
                        let _ = self.state_tx.send(state);
                        ctx.local_secret = None;
                    }
                }
            }
        }
        Ok(())
    }

    async fn handle_hello_verify_request(
        &self,
        msg: HandshakeMessage,
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        trace!("Received HelloVerifyRequest");
        let mut body = msg.body.clone();
        if let Ok(verify_req) = HelloVerifyRequest::decode(&mut body) {
            trace!("Resending ClientHello with cookie");

            // Reset handshake messages
            ctx.handshake_messages.clear();

            // Reuse previous random
            let random = if let Some(bytes) = &ctx.client_random {
                let gmt = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
                let mut rb = [0u8; 28];
                rb.copy_from_slice(&bytes[4..32]);
                Random {
                    gmt_unix_time: gmt,
                    random_bytes: rb,
                }
            } else {
                Random::new()
            };
            // client_random is already set, no need to update

            let mut extensions = Vec::new();
            // Supported Elliptic Curves (secp256r1)
            extensions.extend_from_slice(&[0x00, 0x0a, 0x00, 0x04, 0x00, 0x02, 0x00, 0x17]);
            // Supported Point Formats (uncompressed)
            extensions.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);

            let client_hello = ClientHello {
                version: ProtocolVersion::DTLS_1_2,
                random,
                session_id: vec![],
                cookie: verify_req.cookie,
                cipher_suites: vec![0xC02B],
                compression_methods: vec![0],
                extensions,
            };

            let mut body = BytesMut::new();
            client_hello.encode(&mut body);

            let handshake_msg = HandshakeMessage {
                msg_type: HandshakeType::ClientHello,
                message_seq: ctx.message_seq,
                fragment_offset: 0,
                fragment_length: body.len() as u32,
                body: body.freeze(),
            };

            let mut buf = BytesMut::new();
            handshake_msg.encode(&mut buf);
            ctx.handshake_messages.extend_from_slice(&buf);

            self.send_handshake_message(
                handshake_msg,
                ctx.epoch,
                &mut ctx.sequence_number,
                None,
                is_client,
            )
            .await?;
            ctx.message_seq += 1;
        }
        Ok(())
    }

    fn handle_server_hello(
        &self,
        msg: HandshakeMessage,
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        if !is_client {
            return Ok(());
        }

        trace!("Received ServerHello");
        let mut body = msg.body.clone();
        let server_hello = match ServerHello::decode(&mut body) {
            Ok(h) => h,
            Err(_) => return Ok(()),
        };

        ctx.server_random = Some(server_hello.random.to_bytes());
        trace!("Server extensions len: {}", server_hello.extensions.len());

        if server_hello.extensions.is_empty() {
            return Ok(());
        }

        trace!("Server extensions: {:?}", server_hello.extensions);
        let mut ext_buf = Bytes::from(server_hello.extensions.clone());
        while ext_buf.len() >= 4 {
            let ext_type = ext_buf.get_u16();
            let ext_len = ext_buf.get_u16() as usize;
            if ext_buf.len() < ext_len {
                break;
            }
            let ext_data = ext_buf.split_to(ext_len);
            if ext_type == 23 {
                ctx.ems_negotiated = true;
            } else if ext_type == 14 {
                // use_srtp
                if ext_data.len() >= 5 {
                    // Length of list (2 bytes)
                    // Profile (2 bytes)
                    // MKI (1 byte)
                    let profile = u16::from_be_bytes([ext_data[2], ext_data[3]]);
                    ctx.srtp_profile = Some(profile);
                }
            }
        }
        Ok(())
    }

    fn handle_server_key_exchange(
        &self,
        msg: HandshakeMessage,
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        if is_client {
            let mut body = msg.body.clone();
            if let Ok(server_key_exchange) = ServerKeyExchange::decode(&mut body) {
                ctx.peer_public_key = Some(server_key_exchange.public_key);
            }
        }
        Ok(())
    }

    async fn handle_server_hello_done(
        &self,
        ctx: &mut HandshakeContext,
        is_client: bool,
    ) -> Result<()> {
        if ctx.session_keys.is_some() {
            return Ok(());
        }

        // Send ClientKeyExchange
        let client_key_exchange = ClientKeyExchange {
            identity_hint: vec![],
            public_key: ctx.local_public_key_bytes.clone(),
        };

        let mut body = BytesMut::new();
        client_key_exchange.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::ClientKeyExchange,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        self.send_handshake_message(
            handshake_msg,
            ctx.epoch,
            &mut ctx.sequence_number,
            None,
            is_client,
        )
        .await?;
        ctx.message_seq += 1;

        // Compute shared secret
        let peer_key = if let Some(pk) = &ctx.peer_public_key {
            pk
        } else {
            return Ok(());
        };

        let secret = if let Some(s) = ctx.local_secret.as_ref() {
            s
        } else {
            warn!("Local secret not available (already consumed?)");
            return Ok(());
        };

        let pk = match PublicKey::from_sec1_bytes(peer_key) {
            Ok(pk) => pk,
            Err(_) => {
                warn!("Failed to parse peer public key");
                return Ok(());
            }
        };

        let shared_secret = secret.diffie_hellman(&pk);

        let (cr, sr) = match (&ctx.client_random, &ctx.server_random) {
            (Some(cr), Some(sr)) => (cr, sr),
            _ => return Ok(()),
        };

        let pre_master_secret = shared_secret.raw_secret_bytes();
        let mut seed = Vec::new();
        seed.extend_from_slice(cr);
        seed.extend_from_slice(sr);

        let master_secret_res = if ctx.ems_negotiated {
            let mut hasher = Sha256::new();
            hasher.update(&ctx.handshake_messages);
            let session_hash = hasher.finalize();
            prf_sha256(
                pre_master_secret,
                b"extended master secret",
                &session_hash,
                48,
            )
        } else {
            prf_sha256(pre_master_secret, b"master secret", &seed, 48)
        };

        let master_secret = match master_secret_res {
            Ok(ms) => ms,
            Err(_) => return Ok(()),
        };

        let keys = match expand_keys(&master_secret, cr, sr) {
            Ok(k) => k,
            Err(_) => return Ok(()),
        };
        ctx.session_keys = Some(keys);

        // Send ChangeCipherSpec
        let record = DtlsRecord {
            content_type: ContentType::ChangeCipherSpec,
            version: ProtocolVersion::DTLS_1_2,
            epoch: ctx.epoch,
            sequence_number: ctx.sequence_number,
            payload: Bytes::from_static(&[1]),
        };

        let mut buf = BytesMut::new();
        record.encode(&mut buf);
        self.conn.send(&buf).await?;

        ctx.epoch += 1;
        ctx.sequence_number = 0;

        // Send Finished
        let verify_data =
            calculate_verify_data(&master_secret, b"client finished", &ctx.handshake_messages)?;

        let finished = Finished { verify_data };

        let mut body = BytesMut::new();
        finished.encode(&mut body);

        let handshake_msg = HandshakeMessage {
            msg_type: HandshakeType::Finished,
            message_seq: ctx.message_seq,
            fragment_offset: 0,
            fragment_length: body.len() as u32,
            body: body.freeze(),
        };

        let mut buf = BytesMut::new();
        handshake_msg.encode(&mut buf);
        ctx.handshake_messages.extend_from_slice(&buf);

        self.send_handshake_message(
            handshake_msg,
            ctx.epoch,
            &mut ctx.sequence_number,
            ctx.session_keys.as_ref(),
            is_client,
        )
        .await?;
        ctx.message_seq += 1;

        Ok(())
    }
    async fn handshake(
        &self,
        certificate: Certificate,
        is_client: bool,
        incoming_data_tx: mpsc::Sender<Vec<u8>>,
        mut outgoing_data_rx: mpsc::Receiver<Vec<u8>>,
        mut handshake_rx: mpsc::Receiver<Vec<u8>>,
        close_rx: Arc<tokio::sync::Notify>,
    ) -> Result<()> {
        *self.state.lock().await = DtlsState::Handshaking;
        let _ = self.state_tx.send(DtlsState::Handshaking);

        let mut ctx = HandshakeContext::new();

        // Retransmission state
        let mut retransmit_interval = tokio::time::interval(std::time::Duration::from_secs(1));
        retransmit_interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        if is_client {
            // Send ClientHello
            let random = Random::new();
            ctx.client_random = Some(random.to_bytes());

            let mut extensions = Vec::new();

            // Extended Master Secret
            extensions.extend_from_slice(&[0x00, 17]); // Type 23
            extensions.extend_from_slice(&[0x00, 0x00]); // Length 0

            // Supported Elliptic Curves (secp256r1)
            extensions.extend_from_slice(&[0x00, 0x0a]); // Type
            extensions.extend_from_slice(&[0x00, 0x04]); // Length
            extensions.extend_from_slice(&[0x00, 0x02]); // List Length
            extensions.extend_from_slice(&[0x00, 0x17]); // secp256r1

            // Supported Point Formats (uncompressed)
            extensions.extend_from_slice(&[0x00, 0x0b]); // Type
            extensions.extend_from_slice(&[0x00, 0x02]); // Length
            extensions.extend_from_slice(&[0x01]); // List Length
            extensions.extend_from_slice(&[0x00]); // uncompressed

            let client_hello = ClientHello {
                version: ProtocolVersion::DTLS_1_2,
                random,
                session_id: vec![],
                cookie: vec![],
                cipher_suites: vec![0xC02B], // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
                compression_methods: vec![0], // Null
                extensions,
            };

            let mut body = BytesMut::new();
            client_hello.encode(&mut body);

            let handshake_msg = HandshakeMessage {
                msg_type: HandshakeType::ClientHello,
                message_seq: ctx.message_seq,
                fragment_offset: 0,
                fragment_length: body.len() as u32,
                body: body.freeze(),
            };

            let mut buf = BytesMut::new();
            handshake_msg.encode(&mut buf);
            ctx.handshake_messages.extend_from_slice(&buf);

            let buf = self
                .send_handshake_message(
                    handshake_msg,
                    ctx.epoch,
                    &mut ctx.sequence_number,
                    None,
                    is_client,
                )
                .await?;
            ctx.last_flight_buffer = Some(buf);
            ctx.message_seq += 1;
        }

        loop {
            tokio::select! {
                _ = close_rx.notified() => {
                    // Send CloseNotify
                    if let Some(keys) = &ctx.session_keys {
                        let alert = vec![1, 0]; // Level: Warning (1), Description: CloseNotify (0)
                        let (key, iv) = if is_client {
                            (&keys.client_write_key, &keys.client_write_iv)
                        } else {
                            (&keys.server_write_key, &keys.server_write_iv)
                        };
                        let full_seq = ((ctx.epoch as u64) << 48) | ctx.sequence_number;
                        if let Ok(encrypted) = encrypt_record(
                            ContentType::Alert,
                            ProtocolVersion::DTLS_1_2,
                            full_seq,
                            &alert,
                            key,
                            iv
                        ) {
                            let record = DtlsRecord {
                                content_type: ContentType::Alert,
                                version: ProtocolVersion::DTLS_1_2,
                                epoch: ctx.epoch,
                                sequence_number: ctx.sequence_number,
                                payload: Bytes::from(encrypted),
                            };
                            let mut buf = BytesMut::new();
                            record.encode(&mut buf);
                            let _ = self.conn.send(&buf).await;
                        }
                    }
                    return Ok(());
                }
                _ = retransmit_interval.tick() => {
                    self.handle_retransmit(&ctx, is_client).await;
                }
                Some(packet) = handshake_rx.recv() => {
                    self.handle_incoming_packet(packet, &mut ctx, &incoming_data_tx, &certificate, is_client).await?;
                }
                Some(data) = outgoing_data_rx.recv() => {
                    if let Some(keys) = &ctx.session_keys {
                        let (key, iv) = if is_client {
                            (&keys.client_write_key, &keys.client_write_iv)
                        } else {
                            (&keys.server_write_key, &keys.server_write_iv)
                        };

                        let full_seq = ((ctx.epoch as u64) << 48) | ctx.sequence_number;

                        match encrypt_record(
                            ContentType::ApplicationData,
                            ProtocolVersion::DTLS_1_2,
                            full_seq,
                            &data,
                            key,
                            iv
                        ) {
                            Ok(encrypted) => {
                                let record = DtlsRecord {
                                    content_type: ContentType::ApplicationData,
                                    version: ProtocolVersion::DTLS_1_2,
                                    epoch: ctx.epoch,
                                    sequence_number: ctx.sequence_number,
                                    payload: Bytes::from(encrypted),
                                };
                                ctx.sequence_number += 1;

                                let mut buf = BytesMut::new();
                                record.encode(&mut buf);
                                if let Err(e) = self.conn.send(&buf).await {
                                     warn!("Failed to send application data: {}", e);
                                }
                            },
                            Err(e) => warn!("Failed to encrypt application data: {}", e),
                        }
                    } else {
                        warn!("Cannot send application data: handshake not completed");
                    }
                }
            }
        }
    }

    async fn send_handshake_message(
        &self,
        msg: HandshakeMessage,
        epoch: u16,
        sequence_number: &mut u64,
        session_keys: Option<&SessionKeys>,
        is_client: bool,
    ) -> Result<Vec<u8>> {
        let mut buf = BytesMut::new();
        msg.encode(&mut buf);
        let payload = buf.freeze();
        let mut record_payload = payload;

        if epoch > 0
            && let Some(keys) = session_keys
        {
            let (key, iv) = if is_client {
                (&keys.client_write_key, &keys.client_write_iv)
            } else {
                (&keys.server_write_key, &keys.server_write_iv)
            };

            let full_seq = ((epoch as u64) << 48) | *sequence_number;

            record_payload = Bytes::from(encrypt_record(
                ContentType::Handshake,
                ProtocolVersion::DTLS_1_2,
                full_seq,
                &record_payload,
                key,
                iv,
            )?);
        }

        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::DTLS_1_2,
            epoch,
            sequence_number: *sequence_number,
            payload: record_payload,
        };
        *sequence_number += 1;

        let mut buf = BytesMut::new();
        record.encode(&mut buf);
        if let Err(e) = self.conn.send(&buf).await {
            warn!("Failed to send DTLS record: {}", e);
            return Err(e);
        }

        Ok(buf.to_vec())
    }
}

impl Clone for DtlsTransport {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            close_tx: self.close_tx.clone(),
        }
    }
}

use crate::transports::PacketReceiver;
use std::net::SocketAddr;

#[async_trait::async_trait]
impl PacketReceiver for DtlsTransport {
    async fn receive(&self, packet: Bytes, _addr: SocketAddr) {
        // Push to the internal handshake loop
        // We ignore errors here (e.g. if the loop is closed)
        let _ = self.inner.handshake_rx_feeder.send(packet.to_vec()).await;
    }
}

fn prf_sha256(secret: &[u8], label: &[u8], seed: &[u8], output_length: usize) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut real_seed = Vec::new();
    real_seed.extend_from_slice(label);
    real_seed.extend_from_slice(seed);

    let mut a = real_seed.clone();

    while output.len() < output_length {
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        mac.update(&a);
        a = mac.finalize().into_bytes().to_vec();

        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        mac.update(&a);
        mac.update(&real_seed);
        let block = mac.finalize().into_bytes();

        let len = std::cmp::min(block.len(), output_length - output.len());
        output.extend_from_slice(&block[..len]);
    }

    Ok(output)
}

fn expand_keys(
    master_secret: &[u8],
    client_random: &[u8],
    server_random: &[u8],
) -> Result<SessionKeys> {
    let mut keys = SessionKeys {
        client_write_key: vec![0u8; 16],
        server_write_key: vec![0u8; 16],
        client_write_iv: vec![0u8; 4],
        server_write_iv: vec![0u8; 4],
        master_secret: master_secret.to_vec(),
        client_random: client_random.to_vec(),
        server_random: server_random.to_vec(),
    };

    let key_block = prf_sha256(
        master_secret,
        b"key expansion",
        [server_random, client_random].concat().as_slice(),
        40,
    )?;

    keys.client_write_key.copy_from_slice(&key_block[0..16]);
    keys.server_write_key.copy_from_slice(&key_block[16..32]);
    keys.client_write_iv.copy_from_slice(&key_block[32..36]);
    keys.server_write_iv.copy_from_slice(&key_block[36..40]);

    Ok(keys)
}

fn calculate_verify_data(
    master_secret: &[u8],
    label: &[u8],
    handshake_messages: &[u8],
) -> Result<Vec<u8>> {
    let mut hasher = Sha256::new();
    hasher.update(handshake_messages);
    let hash = hasher.finalize();
    let verify_data = prf_sha256(master_secret, label, &hash, 12)?;
    Ok(verify_data)
}

fn make_aad(
    seq: u64,
    content_type: ContentType,
    version: ProtocolVersion,
    length: usize,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(13);
    aad.extend_from_slice(&seq.to_be_bytes());
    aad.push(content_type as u8);
    aad.push(version.major);
    aad.push(version.minor);
    aad.extend_from_slice(&(length as u16).to_be_bytes());
    aad
}

fn decrypt_record(
    content_type: ContentType,
    version: ProtocolVersion,
    seq: u64,
    payload: &Bytes,
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>> {
    if payload.len() < 8 {
        return Err(anyhow::anyhow!("Record too short for explicit nonce"));
    }

    let explicit_nonce = &payload[0..8];
    let ciphertext = &payload[8..];

    if ciphertext.len() < 16 {
        return Err(anyhow::anyhow!("Ciphertext too short for tag"));
    }

    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..4].copy_from_slice(iv);
    nonce_bytes[4..12].copy_from_slice(explicit_nonce);

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    let plaintext_len = ciphertext.len() - 16;
    let aad = make_aad(seq, content_type, version, plaintext_len);

    let decrypted_payload = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("Decryption failed: {}", e))?;

    Ok(decrypted_payload)
}

fn encrypt_record(
    content_type: ContentType,
    version: ProtocolVersion,
    seq: u64,
    payload: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>> {
    let mut nonce_bytes = [0u8; 12];
    nonce_bytes[0..4].copy_from_slice(iv);
    nonce_bytes[4..12].copy_from_slice(&seq.to_be_bytes());

    let nonce = Nonce::from_slice(&nonce_bytes);
    let cipher =
        Aes128Gcm::new_from_slice(key).map_err(|_| anyhow::anyhow!("Invalid key length"))?;

    let aad = make_aad(seq, content_type, version, payload.len());

    let encrypted_payload = cipher
        .encrypt(
            nonce,
            Payload {
                msg: payload,
                aad: &aad,
            },
        )
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut result = Vec::new();
    result.extend_from_slice(&nonce_bytes[4..12]);
    result.extend_from_slice(&encrypted_payload);

    Ok(result)
}

struct HandshakeContext {
    sequence_number: u64,
    epoch: u16,
    message_seq: u16,
    recv_message_seq: u16,
    last_flight_buffer: Option<Vec<u8>>,
    local_secret: Option<EphemeralSecret>,
    local_public_key_bytes: Vec<u8>,
    peer_public_key: Option<Vec<u8>>,
    client_random: Option<Vec<u8>>,
    server_random: Option<Vec<u8>>,
    session_keys: Option<SessionKeys>,
    handshake_messages: Vec<u8>,
    ems_negotiated: bool,
    srtp_profile: Option<u16>,
}

impl HandshakeContext {
    fn new() -> Self {
        // Generate ephemeral key for ECDHE
        let local_secret = EphemeralSecret::random(&mut OsRng);
        let local_public = local_secret.public_key();
        let local_public_key_bytes = local_public.to_encoded_point(false).as_bytes().to_vec();

        Self {
            sequence_number: 0,
            epoch: 0,
            message_seq: 0,
            recv_message_seq: 0,
            last_flight_buffer: None,
            local_secret: Some(local_secret),
            local_public_key_bytes,
            peer_public_key: None,
            client_random: None,
            server_random: None,
            session_keys: None,
            handshake_messages: Vec::new(),
            ems_negotiated: false,
            srtp_profile: None,
        }
    }
}
