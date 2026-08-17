use super::*;
use crate::transports::PacketReceiver;
use crate::transports::ice::IceSocketWrapper;
use bytes::Bytes;
use serial_test::serial;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

fn spawn_socket_pump(socket: Arc<UdpSocket>, conn: Arc<IceConn>) {
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut marshal_buf = Vec::new();
        loop {
            if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                conn.receive(packet, addr, &mut marshal_buf).await;
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
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);
    let cert = generate_certificate()?;

    // Start client
    let (_client_dtls, _rx, runner) =
        DtlsTransport::new(client_conn, cert, true, 1500, None).await?;
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
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);
    let cert = generate_certificate()?;
    let (_server_dtls, _, runner) =
        DtlsTransport::new(server_conn.clone(), cert, false, 1500, None).await?;
    tokio::spawn(runner);

    // Start a loop to feed server_dtls
    let server_socket_clone = server_socket.clone();
    let server_conn_clone = server_conn.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        let mut marshal_buf = Vec::new();
        loop {
            if let Ok((len, addr)) = server_socket_clone.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                server_conn_clone
                    .receive(packet, addr, &mut marshal_buf)
                    .await;
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
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

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
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

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

#[test]
fn test_verify_server_key_exchange_signature_rejects_oversized_public_key() -> Result<()> {
    let certificate = generate_certificate()?;
    let client_random = Random::new().to_bytes();
    let server_random = Random::new().to_bytes();

    // Build a ServerKeyExchange with a public key that exceeds 255 bytes.
    let oversized_key = vec![0x04u8; 256];
    let server_key_exchange = ServerKeyExchange {
        curve_type: 3,
        named_curve: 23,
        public_key: oversized_key,
        signature: vec![],
    };

    let err = verify_server_key_exchange_signature(
        &certificate.certificate[0],
        &client_random,
        &server_random,
        &server_key_exchange,
    )
    .unwrap_err();

    assert!(
        err.to_string().contains("too long"),
        "expected 'too long' error, got: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_dtls_handshake_no_fingerprint_skips_check() -> Result<()> {
    // When expected_remote_fingerprint is None the handshake should succeed
    // regardless of the server certificate (fingerprint check is opt-in).
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

    let client_cert = generate_certificate()?;
    let server_cert = generate_certificate()?;

    // Client passes None — no fingerprint binding expected
    let (client_dtls, _client_rx, client_runner) =
        DtlsTransport::new(client_conn.clone(), client_cert, true, 1500, None).await?;
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

// ---------------------------------------------------------------------------
// Regression tests for the DTLS retransmit / memory-leak fix.
//
// Before the fix, the DTLS handshake task would spin forever once the ICE
// socket disappeared, logging "no selected socket" warnings every second and
// holding its `Arc<DtlsInner>` / `Arc<IceConn>` alive indefinitely (a memory
// leak + log spam).
//
// These tests verify that the task now exits promptly when:
//   1. The ICE socket watch channel transitions to `None`.
//   2. No peer ever responds to the ClientHello (handshake timeout).
//   3. The socket is cleared AFTER a successful handshake.
//   4. close() is called during handshake.
// ---------------------------------------------------------------------------

/// When the ICE socket is cleared (simulating `IceTransport::stop()`), the
/// DTLS handshake task must exit within a couple of retransmit intervals
/// and transition to `Failed`.
#[tokio::test]
async fn test_dtls_exits_when_ice_socket_cleared() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_addr: SocketAddr = "127.0.0.1:9".parse()?; // discard port — nobody listens

    let (socket_tx, _rx) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let conn = IceConn::new(socket_tx.subscribe(), server_addr, None);
    let cert = generate_certificate()?;

    let (dtls, _rx, runner) = DtlsTransport::new(conn, cert, true, 1500, None).await?;
    let task = tokio::spawn(runner);

    // Give the client time to send its ClientHello and enter the retransmit
    // loop.  500 ms is well within the first 1-second retransmit window.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    // Simulate ICE stopping — the selected socket goes to None.
    socket_tx.send(None)?;

    // The task must exit (not spin forever).  If the fix is missing it will
    // hang indefinitely and the timeout below will fire.
    let deadline = std::time::Duration::from_secs(5);
    let result = tokio::time::timeout(deadline, task).await;

    assert!(
        result.is_ok(),
        "DTLS handshake task did NOT exit within {deadline:?} after ICE socket was cleared — \
         this is the memory-leak / log-spam regression"
    );

    // The state must be `Failed` (we were still handshaking).
    assert!(
        matches!(dtls.get_state(), DtlsState::Failed),
        "expected DtlsState::Failed after ICE socket cleared, got {}",
        dtls.get_state()
    );

    Ok(())
}

/// When no peer ever responds, the handshake must time out and the task must
/// exit instead of retransmitting forever.
#[tokio::test]
async fn test_dtls_handshake_timeout_on_no_response() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    // Port 9 (discard) — packets are sent but nobody answers.
    let server_addr: SocketAddr = "127.0.0.1:9".parse()?;

    let (socket_tx, _rx) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let conn = IceConn::new(socket_tx.subscribe(), server_addr, None);
    let cert = generate_certificate()?;

    let (dtls, _rx, runner) = DtlsTransport::new(conn, cert, true, 1500, None).await?;
    let task = tokio::spawn(runner);

    // In test mode the timeout is 5 s; allow generous margin.
    let deadline = std::time::Duration::from_secs(10);
    let result = tokio::time::timeout(deadline, task).await;

    assert!(
        result.is_ok(),
        "DTLS handshake task did NOT time out within {deadline:?} — \
         the handshake-timeout fix is missing"
    );

    assert!(
        matches!(dtls.get_state(), DtlsState::Failed),
        "expected DtlsState::Failed after handshake timeout, got {}",
        dtls.get_state()
    );

    Ok(())
}

/// After a successful handshake, clearing the ICE socket (peer disconnected)
/// must transition the transport to `Closed` and the task must exit — not
/// continue running in the background forever.
#[tokio::test]
async fn test_dtls_exits_after_connected_when_ice_socket_cleared() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

    let client_cert = generate_certificate()?;
    let server_cert = generate_certificate()?;

    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(fingerprint(&server_cert)),
    )
    .await?;
    let client_task = tokio::spawn(client_runner);
    let (server_dtls, _server_rx, server_runner) =
        DtlsTransport::new(server_conn.clone(), server_cert, false, 1500, None).await?;
    tokio::spawn(server_runner);

    spawn_socket_pump(client_socket, client_conn);
    spawn_socket_pump(server_socket, server_conn);

    // Wait for both sides to reach Connected.
    assert!(matches!(
        wait_for_terminal_state(&client_dtls).await?,
        DtlsState::Connected(..)
    ));
    assert!(matches!(
        wait_for_terminal_state(&server_dtls).await?,
        DtlsState::Connected(..)
    ));

    // Simulate ICE stopping on the client side.
    client_socket_tx.send(None)?;

    // The client DTLS task must transition to Closed and exit.
    let result = tokio::time::timeout(std::time::Duration::from_secs(5), client_task).await;
    assert!(
        result.is_ok(),
        "Client DTLS task did NOT exit after ICE socket was cleared post-Connected"
    );
    assert!(
        matches!(client_dtls.get_state(), DtlsState::Closed),
        "expected DtlsState::Closed, got {}",
        client_dtls.get_state()
    );

    // Cleanup server side.
    server_dtls.close();
    Ok(())
}

/// `DtlsTransport::close()` must reliably stop the handshake task, even when
/// called during the `Handshaking` phase.  This guards against the
/// `notify_waiters` → `notify_one` race fix.
#[tokio::test]
async fn test_dtls_close_during_handshake_exits_task() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_addr: SocketAddr = "127.0.0.1:9".parse()?;

    let (socket_tx, _rx) = watch::channel(Some(IceSocketWrapper::Udp(client_socket)));
    let conn = IceConn::new(socket_tx.subscribe(), server_addr, None);
    let cert = generate_certificate()?;

    let (dtls, _rx, runner) = DtlsTransport::new(conn, cert, true, 1500, None).await?;
    let task = tokio::spawn(runner);

    // Let the ClientHello be sent.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    dtls.close();

    let result = tokio::time::timeout(std::time::Duration::from_secs(3), task).await;
    assert!(
        result.is_ok(),
        "DTLS task did NOT exit within 3s after close() — notify_one race?"
    );

    Ok(())
}

//=== Application-data fragmentation (large messages must not be IP-fragmented) ===

/// Spin up a connected client/server DTLS pair over loopback.
async fn spawn_connected_dtls_pair(
) -> Result<(Arc<DtlsTransport>, Arc<DtlsTransport>, mpsc::UnboundedReceiver<Bytes>)> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

    let client_cert = generate_certificate()?;
    let server_cert = generate_certificate()?;

    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(fingerprint(&server_cert)),
    )
    .await?;
    tokio::spawn(client_runner);
    let (server_dtls, server_rx, server_runner) =
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

    Ok((client_dtls, server_dtls, server_rx))
}

/// Send `payload` from client to server and return `(record_count, reassembled)`.
/// Each received `Bytes` is one DTLS ApplicationData record; a record larger
/// than `MAX_APP_DATA_RECORD_SIZE` would prove an MTU violation.
async fn send_and_collect_records(
    client_dtls: &Arc<DtlsTransport>,
    server_rx: &mut mpsc::UnboundedReceiver<Bytes>,
    payload: &[u8],
) -> Result<(usize, Vec<u8>)> {
    client_dtls.send(Bytes::copy_from_slice(payload)).await?;

    let mut received = Vec::new();
    let mut record_count = 0usize;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    while received.len() < payload.len() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out reassembling fragmented payload (got {} of {} bytes)",
            received.len(),
            payload.len()
        );
        let record = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            server_rx.recv(),
        )
        .await
        .map_err(|_| anyhow::anyhow!("record recv timeout"))?
        .ok_or_else(|| anyhow::anyhow!("DTLS channel closed"))?;
        record_count += 1;
        assert!(
            record.len() <= MAX_APP_DATA_RECORD_SIZE,
            "record {} exceeds the MTU-safe ceiling: {} bytes",
            record_count,
            record.len()
        );
        received.extend_from_slice(&record);
    }
    Ok((record_count, received))
}

#[tokio::test]
async fn test_dtls_application_data_fragmentation_roundtrip() -> Result<()> {
    let (client_dtls, _server_dtls, mut server_rx) = spawn_connected_dtls_pair().await?;

    // Deterministic 5000-byte payload — far larger than one MTU-sized record.
    let payload: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();

    let (record_count, received) =
        send_and_collect_records(&client_dtls, &mut server_rx, &payload).await?;

    assert!(
        record_count > 1,
        "payload was not fragmented: expected >1 records, got {}",
        record_count
    );
    assert_eq!(
        received, payload,
        "reassembled payload must match the original"
    );

    Ok(())
}

#[tokio::test]
async fn test_dtls_application_data_fragmentation_boundary() -> Result<()> {
    // Exactly one record at the ceiling; two records just past it.
    let (client_dtls, _server_dtls, mut server_rx) = spawn_connected_dtls_pair().await?;

    let (count, received) = send_and_collect_records(
        &client_dtls,
        &mut server_rx,
        &vec![7u8; MAX_APP_DATA_RECORD_SIZE],
    )
    .await?;
    assert_eq!(count, 1, "payload == record ceiling must be a single record");
    assert_eq!(received.len(), MAX_APP_DATA_RECORD_SIZE);

    let (count2, received2) = send_and_collect_records(
        &client_dtls,
        &mut server_rx,
        &vec![9u8; MAX_APP_DATA_RECORD_SIZE + 1],
    )
    .await?;
    assert_eq!(
        count2, 2,
        "payload == ceiling+1 must span exactly two records"
    );
    assert_eq!(received2.len(), MAX_APP_DATA_RECORD_SIZE + 1);

    Ok(())
}
