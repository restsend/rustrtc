use super::*;
use crate::transports::PacketReceiver;
use crate::transports::ice::IceSocketWrapper;
use bytes::Bytes;
use serial_test::serial;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

fn spawn_socket_pump(socket: Arc<UdpSocket>, conn: Arc<IceConn>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                conn.receive(packet, addr).await;
            }
        }
    });
}

async fn wait_for_terminal_state(dtls: &Arc<DtlsTransport>) -> Result<DtlsState> {
    let mut state_rx = dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    loop {
        let state = state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            return Ok(state);
        }

        let now = tokio::time::Instant::now();
        if now >= deadline {
            return Err(anyhow::anyhow!("timed out waiting for DTLS terminal state"));
        }

        tokio::time::timeout(deadline - now, state_rx.changed()).await??;
    }
}

#[tokio::test]
async fn test_dtls_handshake_client_hello() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr);

    let cert = generate_certificate()?;

    // Start client
    let (_client_dtls, _rx, runner) =
        DtlsTransport::new(client_conn, cert.clone(), true, 1500, None).await?;
    tokio::spawn(runner);

    // Read from server socket to verify ClientHello
    let mut buf = vec![0u8; 2048];
    let (len, addr) = server_socket.recv_from(&mut buf).await?;
    assert_eq!(addr, client_addr);

    let mut data = Bytes::copy_from_slice(&buf[..len]);
    let record = DtlsRecord::decode(&mut data)?.unwrap();

    assert_eq!(record.content_type, ContentType::Handshake);

    let mut body = record.payload;
    let msg = HandshakeMessage::decode(&mut body)?.unwrap();

    assert_eq!(msg.msg_type, HandshakeType::ClientHello);

    Ok(())
}

#[tokio::test]
#[serial]
async fn test_dtls_handshake_server_hello() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr);

    let cert = generate_certificate()?;

    // Start server
    let (_server_dtls, _rx, runner) =
        DtlsTransport::new(server_conn.clone(), cert.clone(), false, 1500, None).await?;
    tokio::spawn(runner);

    // Start a loop to feed server_dtls
    let server_socket_clone = server_socket.clone();
    let server_conn_clone = server_conn.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            if let Ok((len, addr)) = server_socket_clone.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                server_conn_clone.receive(packet, addr).await;
            }
        }
    });

    // Send ClientHello from client socket
    let client_hello = ClientHello {
        version: ProtocolVersion::DTLS_1_2,
        random: Random::new(),
        session_id: vec![],
        cookie: vec![],
        cipher_suites: vec![0xC02B],
        compression_methods: vec![0],
        extensions: vec![],
    };

    let mut body = BytesMut::new();
    client_hello.encode(&mut body);

    let handshake_msg = HandshakeMessage {
        msg_type: HandshakeType::ClientHello,
        total_length: body.len() as u32,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
        body: body.freeze(),
    };

    let mut msg_body = BytesMut::new();
    handshake_msg.encode(&mut msg_body);

    let record = DtlsRecord {
        content_type: ContentType::Handshake,
        version: ProtocolVersion::DTLS_1_2,
        epoch: 0,
        sequence_number: 0,
        payload: msg_body.freeze(),
    };

    let mut buf = BytesMut::new();
    record.encode(&mut buf);

    client_socket.send_to(&buf, server_addr).await?;

    // Collect all handshake messages from server
    let mut received_hello = false;
    let mut received_certificate = false;
    let mut received_server_key_exchange = false;
    let mut received_server_hello_done = false;

    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);

    while tokio::time::Instant::now() < deadline {
        let mut recv_buf = vec![0u8; 8192];
        let result = tokio::time::timeout(
            std::time::Duration::from_millis(500),
            client_socket.recv_from(&mut recv_buf),
        )
        .await;

        match result {
            Ok(Ok((len, _addr))) => {
                let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
                while !data.is_empty() {
                    if let Ok(Some(record)) = DtlsRecord::decode(&mut data) {
                        if record.content_type == ContentType::Handshake {
                            let mut payload = record.payload;
                            while !payload.is_empty() {
                                if let Ok(Some(msg)) = HandshakeMessage::decode(&mut payload) {
                                    match msg.msg_type {
                                        HandshakeType::ServerHello => received_hello = true,
                                        HandshakeType::Certificate => received_certificate = true,
                                        HandshakeType::ServerKeyExchange => {
                                            received_server_key_exchange = true
                                        }
                                        HandshakeType::ServerHelloDone => {
                                            received_server_hello_done = true
                                        }
                                        _ => {}
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
            _ => {
                // Timeout or error - check if we have all messages
                if received_hello
                    && received_certificate
                    && received_server_key_exchange
                    && received_server_hello_done
                {
                    break;
                }
            }
        }

        if received_hello
            && received_certificate
            && received_server_key_exchange
            && received_server_hello_done
        {
            break;
        }
    }

    assert!(received_hello, "Should receive ServerHello");
    assert!(received_certificate, "Should receive Certificate");
    assert!(
        received_server_key_exchange,
        "Should receive ServerKeyExchange"
    );
    assert!(received_server_hello_done, "Should receive ServerHelloDone");

    Ok(())
}

#[tokio::test]
async fn test_dtls_handshake_full_flow() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr);

    let client_cert = generate_certificate()?;
    let server_cert = generate_certificate()?;

    // Start client
    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(fingerprint(&server_cert)),
    )
    .await?;
    tokio::spawn(client_runner);
    let (server_dtls, _server_rx, server_runner) =
        DtlsTransport::new(server_conn.clone(), server_cert, false, 1500, None).await?;
    tokio::spawn(server_runner);

    spawn_socket_pump(client_socket, client_conn);
    spawn_socket_pump(server_socket, server_conn);

    assert!(matches!(
        wait_for_terminal_state(&client_dtls).await?,
        DtlsState::Connected(..)
    ));
    assert!(matches!(
        wait_for_terminal_state(&server_dtls).await?,
        DtlsState::Connected(..)
    ));

    Ok(())
}

#[tokio::test]
async fn test_dtls_handshake_fails_on_fingerprint_mismatch() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr);

    let client_cert = generate_certificate()?;
    let server_cert = generate_certificate()?;
    let wrong_cert = generate_certificate()?;

    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(fingerprint(&wrong_cert)),
    )
    .await?;
    tokio::spawn(client_runner);
    let (_server_dtls, _server_rx, server_runner) =
        DtlsTransport::new(server_conn.clone(), server_cert, false, 1500, None).await?;
    tokio::spawn(server_runner);

    spawn_socket_pump(client_socket, client_conn);
    spawn_socket_pump(server_socket, server_conn);

    assert!(matches!(
        wait_for_terminal_state(&client_dtls).await?,
        DtlsState::Failed
    ));
    Ok(())
}

#[test]
fn test_verify_server_key_exchange_signature_rejects_tampering() -> Result<()> {
    let certificate = generate_certificate()?;
    let signing_key = certificate.dtls_signing_key.as_ref().unwrap().clone();
    let secret = EphemeralSecret::random(&mut OsRng);
    let public_key = secret
        .public_key()
        .to_encoded_point(false)
        .as_bytes()
        .to_vec();
    let client_random = Random::new().to_bytes();
    let server_random = Random::new().to_bytes();

    let mut signed_params = Vec::new();
    signed_params.extend_from_slice(&client_random);
    signed_params.extend_from_slice(&server_random);
    signed_params.push(3);
    signed_params.extend_from_slice(&23u16.to_be_bytes());
    signed_params.push(public_key.len() as u8);
    signed_params.extend_from_slice(&public_key);

    let signature: p256::ecdsa::Signature = signing_key.sign_with_rng(&mut OsRng, &signed_params);
    let server_key_exchange = ServerKeyExchange {
        curve_type: 3,
        named_curve: 23,
        public_key: public_key.clone(),
        signature: signature.to_der().as_bytes().to_vec(),
    };

    verify_server_key_exchange_signature(
        &certificate.certificate[0],
        &client_random,
        &server_random,
        &server_key_exchange,
    )?;

    let mut tampered = server_key_exchange.clone();
    tampered.public_key[0] ^= 0x01;

    let err = verify_server_key_exchange_signature(
        &certificate.certificate[0],
        &client_random,
        &server_random,
        &tampered,
    )
    .unwrap_err();

    assert!(err.to_string().contains("signature verification failed"));

    Ok(())
}
