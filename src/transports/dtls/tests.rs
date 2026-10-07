use super::*;
use super::{bail, dtls_err};
use crate::platform::crypto;
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
            return Err(dtls_err!("timed out waiting for DTLS terminal state"));
        }

        tokio::time::timeout(deadline - now, state_rx.changed())
            .await
            .map_err(|e| dtls_err!("timed out waiting for DTLS terminal state: {e}"))?
            .map_err(|e| dtls_err!("DTLS state watch closed: {e}"))?;
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
    let signing_key =
        crypto::crypto().signing_key_from_pkcs8_der(&certificate.private_key_pkcs8)?;
    let (public_key, _secret) = crypto::crypto().ecdh_generate()?;
    let client_random = Random::new().to_bytes();
    let server_random = Random::new().to_bytes();

    let mut signed_params = Vec::new();
    signed_params.extend_from_slice(&client_random);
    signed_params.extend_from_slice(&server_random);
    signed_params.push(3);
    signed_params.extend_from_slice(&23u16.to_be_bytes());
    signed_params.push(public_key.len() as u8);
    signed_params.extend_from_slice(&public_key);

    let signature_bytes = signing_key.sign(&signed_params)?;
    let server_key_exchange = ServerKeyExchange {
        curve_type: 3,
        named_curve: 23,
        public_key: public_key.clone(),
        signature: signature_bytes,
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
    socket_tx
        .send(None)
        .map_err(|e| dtls_err!("socket watch send failed: {e}"))?;

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
    client_socket_tx
        .send(None)
        .map_err(|e| dtls_err!("socket watch send failed: {e}"))?;

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
async fn spawn_connected_dtls_pair() -> Result<(
    Arc<DtlsTransport>,
    Arc<DtlsTransport>,
    mpsc::UnboundedReceiver<Bytes>,
)> {
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
        let record = tokio::time::timeout(std::time::Duration::from_secs(5), server_rx.recv())
            .await
            .map_err(|_| dtls_err!("record recv timeout"))?
            .ok_or_else(|| dtls_err!("DTLS channel closed"))?;
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
    assert_eq!(
        count, 1,
        "payload == record ceiling must be a single record"
    );
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

// ==================== HandshakeReassembly (fragment reordering) ====================

struct Fragments {
    f1: HandshakeMessage,
    f2: HandshakeMessage,
    full: Vec<u8>,
}

fn fragmented_message(seq: u16, total_len: usize, split_at: usize) -> Fragments {
    let body: Vec<u8> = (0..total_len).map(|i| (i % 251) as u8).collect();

    let mk = |offset: usize, part: &[u8]| HandshakeMessage {
        msg_type: HandshakeType::Certificate,
        message_seq: seq,
        fragment_offset: offset as u32,
        fragment_length: part.len() as u32,
        total_length: total_len as u32,
        body: Bytes::copy_from_slice(part),
    };

    Fragments {
        f1: mk(0, &body[..split_at]),
        f2: mk(split_at, &body[split_at..]),
        full: body,
    }
}

#[test]
fn reassembly_completes_in_order() {
    let Fragments { f1, f2, full } = fragmented_message(0, 100, 40);
    let mut r = HandshakeReassembly::default();

    assert!(
        r.push(0, 100, f1.fragment_offset, &f1.body)
            .unwrap()
            .is_none()
    );
    let done = r
        .push(0, 100, f2.fragment_offset, &f2.body)
        .unwrap()
        .expect("complete");
    assert_eq!(done.len(), 100);
    assert_eq!(done, full);
}

#[test]
fn reassembly_completes_out_of_order() {
    // Regression: the old implementation reset its buffer when the first
    // fragment (offset == 0) arrived after later ones, discarding buffered
    // bytes and wedging the handshake on persistently reordering paths.
    let Fragments { f1, f2, full } = fragmented_message(0, 100, 40);
    let mut r = HandshakeReassembly::default();

    // Second fragment arrives first — must be buffered, not dropped.
    assert!(
        r.push(0, 100, f2.fragment_offset, &f2.body)
            .unwrap()
            .is_none()
    );
    let done = r
        .push(0, 100, f1.fragment_offset, &f1.body)
        .unwrap()
        .expect("complete");
    assert_eq!(done.len(), 100);
    assert_eq!(done, full);
}

#[test]
fn reassembly_ignores_duplicate_fragments() {
    let Fragments { f1, f2, .. } = fragmented_message(0, 100, 40);
    let mut r = HandshakeReassembly::default();

    assert!(
        r.push(0, 100, f1.fragment_offset, &f1.body)
            .unwrap()
            .is_none()
    );
    // Same fragment again: idempotent, no accounting drift.
    assert!(
        r.push(0, 100, f1.fragment_offset, &f1.body)
            .unwrap()
            .is_none()
    );
    let done = r
        .push(0, 100, f2.fragment_offset, &f2.body)
        .unwrap()
        .expect("complete");
    assert_eq!(done.len(), 100);
}

#[test]
fn reassembly_resets_on_new_message_seq() {
    let Fragments { f1, .. } = fragmented_message(0, 100, 40);
    let Fragments {
        f1: g1,
        f2: g2,
        full,
    } = fragmented_message(1, 60, 30);
    let mut r = HandshakeReassembly::default();

    assert!(
        r.push(0, 100, f1.fragment_offset, &f1.body)
            .unwrap()
            .is_none()
    );
    // A different message seq starts a fresh reassembly.
    assert!(
        r.push(1, 60, g1.fragment_offset, &g1.body)
            .unwrap()
            .is_none()
    );
    let done = r
        .push(1, 60, g2.fragment_offset, &g2.body)
        .unwrap()
        .expect("complete");
    assert_eq!(done.len(), 60);
    assert_eq!(done, full);
}

#[test]
fn reassembly_rejects_oversized_and_overrun() {
    let mut r = HandshakeReassembly::default();
    assert!(
        r.push(0, MAX_HANDSHAKE_MESSAGE_LEN + 1, 0, &[0u8; 8])
            .is_err()
    );
    assert!(
        r.push(0, 10, 8, &[0u8; 8]).is_err(),
        "offset+len exceeds total"
    );
}

// ==================== Cipher suite negotiation ====================

#[test]
fn negotiate_cipher_suite_accepts_only_supported_suite() {
    assert_eq!(negotiate_cipher_suite(&[0xC02B]), Some(0xC02B));
    assert_eq!(
        negotiate_cipher_suite(&[0xC02F, 0xC02B, 0x009C]),
        Some(0xC02B),
        "supported suite anywhere in the offer wins"
    );
    assert_eq!(negotiate_cipher_suite(&[0xC02F, 0x009C]), None);
    assert_eq!(negotiate_cipher_suite(&[]), None);
}

/// Drive the server role directly with a crafted ClientHello.
async fn server_handle_client_hello(
    server_dtls: &Arc<DtlsTransport>,
    cipher_suites: Vec<u16>,
) -> Result<()> {
    let client_hello = ClientHello {
        version: ProtocolVersion::DTLS_1_2,
        random: Random::new(),
        session_id: vec![],
        cookie: vec![],
        cipher_suites,
        compression_methods: vec![0],
        extensions: vec![],
    };
    let mut body = BytesMut::new();
    client_hello.encode(&mut body);
    let msg = HandshakeMessage {
        msg_type: HandshakeType::ClientHello,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
        total_length: body.len() as u32,
        body: body.freeze(),
    };

    let mut ctx = HandshakeContext::new(None).unwrap();
    let certificate = generate_certificate()?;
    server_dtls
        .inner
        .handle_client_hello(msg, &mut ctx, &certificate, false)
        .await
}

#[tokio::test]
async fn test_server_accepts_client_hello_offering_supported_suite() -> Result<()> {
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_addr = server_socket.local_addr()?;
    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), server_addr, None);
    let (server_dtls, _rx, _runner) = DtlsTransport::new(
        server_conn.clone(),
        generate_certificate()?,
        false,
        1500,
        None,
    )
    .await?;

    // Supported suite anywhere in the offer is enough — extra suites must not
    // break negotiation.
    server_handle_client_hello(&server_dtls, vec![0x1301, 0xC02F, 0xC02B])
        .await
        .expect("ServerHello flight built for an offering client");
    Ok(())
}

#[tokio::test]
async fn test_server_rejects_client_hello_without_supported_suite() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr = client_socket.local_addr()?;
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);
    let (server_dtls, _rx, _runner) = DtlsTransport::new(
        server_conn.clone(),
        generate_certificate()?,
        false,
        1500,
        None,
    )
    .await?;

    // The failure alert is a plaintext record — capture it on the client socket.
    spawn_socket_pump(server_socket, server_conn);

    let result = server_handle_client_hello(&server_dtls, vec![0x1301, 0x009C]).await;
    assert!(
        result.is_err(),
        "handshake must fail loudly when no suite is shared"
    );
    assert!(
        matches!(
            server_dtls.subscribe_state().borrow().clone(),
            DtlsState::Failed
        ),
        "transport must transition to Failed"
    );

    // A fatal handshake_failure alert (content type 21) must reach the peer.
    let mut buf = vec![0u8; 64];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_socket.recv_from(&mut buf),
    )
    .await
    .expect("alert within 2s")
    .expect("recv ok");
    assert_eq!(buf[0], 21, "expected a DTLS alert record, got {}", buf[0]);
    assert_eq!(&buf[len - 2..len], &[2, 40], "fatal handshake_failure");
    Ok(())
}

// ==================== Mainstream stack cipher-suite offers ====================

/// Default DTLS cipher-suite offers of the mainstream WebRTC stacks, taken
/// from their sources: every list contains TLS_ECDHE_ECDSA_WITH_AES_128_GCM_
/// SHA256 (0xC02B) — the only suite this server implements — so negotiation
/// must succeed for all of them.
#[tokio::test]
async fn test_server_accepts_mainstream_client_hello_suite_offers() -> Result<()> {
    // pion/dtls v2.2.12 defaultCipherSuites() (also pion/webrtc's offer).
    let pion: Vec<u16> = vec![0xC02B, 0xC02F, 0xC024, 0xC028, 0xC02C, 0xC030];
    // webrtc-rs dtls 0.17.1 default_cipher_suites() (pion port):
    // ECDHE_ECDSA_AES128_GCM, ECDHE_ECDSA_AES256_CBC, ECDHE_RSA_AES128_GCM,
    // ECDHE_RSA_AES256_CBC, ECDHE_ECDSA_CHACHA20.
    let webrtcrs: Vec<u16> = vec![0xC02B, 0xC00A, 0xC02F, 0xC014, 0xCCA9];
    // Chromium/libwebrtc DTLS profile: ECDSA AES-GCM + ChaCha20 only.
    let chrome: Vec<u16> = vec![0xC02B, 0xCCA9];
    // Firefox: adds the AES-256-GCM ECDSA variant.
    let firefox: Vec<u16> = vec![0xC02B, 0xCCA9, 0xC02C];

    for (name, suites) in [
        ("pion", pion),
        ("webrtc-rs", webrtcrs),
        ("chrome", chrome),
        ("firefox", firefox),
    ] {
        let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let server_addr = server_socket.local_addr()?;
        let (server_socket_tx, _) =
            watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
        let server_conn = IceConn::new(server_socket_tx.subscribe(), server_addr, None);
        let (server_dtls, _rx, _runner) =
            DtlsTransport::new(server_conn, generate_certificate()?, false, 1500, None).await?;
        server_handle_client_hello(&server_dtls, suites)
            .await
            .unwrap_or_else(|e| panic!("{name} suite offer must negotiate, got: {e}"));
    }
    Ok(())
}

// ==================== Fragmented + reordered ClientHello (wire level) ====================

/// Chrome's post-quantum ClientHello (~1.8 KB) exceeds the MTU and arrives
/// as two DTLS handshake fragments — which UDP may deliver out of order.
/// Drive the full server receive path (record decode → reassembly →
/// handle_client_hello) with the SECOND fragment's record sent first and
/// assert the server still answers its ServerHello flight.
#[tokio::test]
async fn test_server_processes_fragmented_out_of_order_client_hello() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("debug"))
        .try_init();
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let client_addr = client_socket.local_addr()?;
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_addr = server_socket.local_addr()?;
    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);
    let (server_dtls, _rx, runner) = DtlsTransport::new(
        server_conn.clone(),
        generate_certificate()?,
        false,
        1500,
        None,
    )
    .await?;
    tokio::spawn(runner);
    spawn_socket_pump(server_socket, server_conn);

    // Build a ClientHello and split its body into two handshake fragments.
    let client_hello = ClientHello {
        version: ProtocolVersion::DTLS_1_2,
        random: Random::new(),
        session_id: vec![],
        cookie: vec![],
        cipher_suites: vec![0xC02B, 0xCCA9],
        compression_methods: vec![0],
        extensions: vec![],
    };
    let mut body = BytesMut::new();
    client_hello.encode(&mut body);
    let body = body.freeze();
    let split = body.len() / 2;

    let fragment_record = |offset: u32, part: &[u8], record_seq: u64| -> Vec<u8> {
        let msg = HandshakeMessage {
            msg_type: HandshakeType::ClientHello,
            message_seq: 0,
            fragment_offset: offset,
            fragment_length: part.len() as u32,
            total_length: body.len() as u32,
            body: Bytes::copy_from_slice(part),
        };
        let mut handshake_buf = BytesMut::new();
        msg.encode(&mut handshake_buf);
        let record = DtlsRecord {
            content_type: ContentType::Handshake,
            version: ProtocolVersion::DTLS_1_2,
            epoch: 0,
            sequence_number: record_seq,
            payload: handshake_buf.freeze(),
        };
        let mut buf = BytesMut::new();
        record.encode(&mut buf);
        buf.to_vec()
    };

    let second = fragment_record(split as u32, &body[split..], 1);
    let first = fragment_record(0, &body[..split], 0);

    // Deliver the second fragment's record BEFORE the first one.
    client_socket.send_to(&second, server_addr).await?;
    client_socket.send_to(&first, server_addr).await?;

    // The server must answer its flight (a Handshake record, content type 22).
    let mut buf = vec![0u8; 2048];
    let (len, _) = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        client_socket.recv_from(&mut buf),
    )
    .await
    .expect("server flight within 5s")?;
    assert_eq!(buf[0], 22, "expected a Handshake record, got {}", buf[0]);
    assert!(len > 12, "flight must carry a ServerHello");
    assert!(
        !matches!(
            server_dtls.subscribe_state().borrow().clone(),
            DtlsState::Failed | DtlsState::Closed
        ),
        "server must not fail on reordered fragments"
    );
    Ok(())
}

/// RFC 6347 §4.2.2: the handshake header length field carries the TOTAL
/// message length; fragment_offset/fragment_length describe the fragment.
/// A fragmented message must encode the total (not the fragment) length so
/// the peer can reassemble.
#[test]
fn handshake_header_length_field_is_total_length_for_fragments() {
    let frag = HandshakeMessage {
        msg_type: HandshakeType::ClientHello,
        message_seq: 0,
        fragment_offset: 40,
        fragment_length: 60,
        total_length: 100,
        body: Bytes::from(vec![0u8; 60]),
    };
    let mut buf = BytesMut::new();
    frag.encode(&mut buf);

    // Decode back and verify the header semantics survived the round trip.
    let mut reader = Bytes::copy_from_slice(&buf);
    let decoded = HandshakeMessage::decode(&mut reader)
        .unwrap()
        .expect("some msg");
    assert_eq!(decoded.total_length, 100, "total length preserved");
    assert_eq!(decoded.fragment_offset, 40);
    assert_eq!(decoded.fragment_length, 60);

    // And the on-wire 24-bit length field itself (bytes 1..4) must be the
    // total length, not the fragment length.
    let wire_len = ((buf[1] as u32) << 16) | ((buf[2] as u32) << 8) | buf[3] as u32;
    assert_eq!(
        wire_len, 100,
        "wire length field must carry the message total"
    );
}

// ==================== Hardening regressions ====================

#[test]
fn reassembly_rejects_total_length_change_for_same_seq() {
    // The header length field is fixed per handshake message; a peer that
    // flips total_length mid-reassembly is garbage (or allocation-churn
    // bait) and must be rejected, not silently reallocated.
    let Fragments { f1, .. } = fragmented_message(0, 100, 40);
    let mut r = HandshakeReassembly::default();
    assert!(
        r.push(0, 100, f1.fragment_offset, &f1.body)
            .unwrap()
            .is_none()
    );
    // A fragment that fits both the old (100) and tampered (90) totals, so
    // the rejection can only come from the consistency check.
    let err = r
        .push(0, 90, 40, &[7u8; 30])
        .expect_err("total_length change must be rejected");
    assert!(err.to_string().contains("changed total_length"), "{err}");
}

/// Craft a ServerHello handshake message with the given cipher suite.
fn server_hello_message(cipher_suite: u16) -> HandshakeMessage {
    let server_hello = ServerHello {
        version: ProtocolVersion::DTLS_1_2,
        random: Random::new(),
        session_id: vec![],
        cipher_suite,
        compression_method: 0,
        extensions: vec![],
    };
    let mut body = BytesMut::new();
    server_hello.encode(&mut body);
    HandshakeMessage {
        msg_type: HandshakeType::ServerHello,
        message_seq: 0,
        fragment_offset: 0,
        fragment_length: body.len() as u32,
        total_length: body.len() as u32,
        body: body.freeze(),
    }
}

async fn client_transport_for_handling() -> Result<Arc<DtlsTransport>> {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let addr: std::net::SocketAddr = "127.0.0.1:1".parse().unwrap();
    let (socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(socket)));
    let conn = IceConn::new(socket_tx.subscribe(), addr, None);
    let (dtls, _rx, _runner) =
        DtlsTransport::new(conn, generate_certificate()?, true, 1500, None).await?;
    Ok(dtls)
}

#[tokio::test]
async fn client_rejects_server_hello_with_unsupported_suite() -> Result<()> {
    let dtls = client_transport_for_handling().await?;
    let mut ctx = HandshakeContext::new(None).unwrap();
    let res = dtls
        .inner
        .handle_server_hello(server_hello_message(0xC02F), &mut ctx, true);
    assert!(res.is_err(), "unsupported suite must abort the handshake");
    assert!(
        matches!(dtls.subscribe_state().borrow().clone(), DtlsState::Failed),
        "client transport must transition to Failed"
    );
    assert!(
        ctx.server_random.is_none(),
        "no state may leak on rejection"
    );
    Ok(())
}

#[tokio::test]
async fn client_accepts_server_hello_with_supported_suite() -> Result<()> {
    let dtls = client_transport_for_handling().await?;
    let mut ctx = HandshakeContext::new(None).unwrap();
    dtls.inner
        .handle_server_hello(server_hello_message(0xC02B), &mut ctx, true)?;
    assert!(ctx.server_random.is_some(), "ServerHello state recorded");
    Ok(())
}

/// A reordered server flight (Certificate arriving before ServerHello) must
/// be buffered and drained in order instead of stalling the handshake until
/// retransmission (RFC 6347 §4.2.4).
#[tokio::test]
async fn client_processes_reordered_server_flight() -> Result<()> {
    let dtls = client_transport_for_handling().await?;
    let own_cert = generate_certificate()?;

    let server_hello = server_hello_message(0xC02B);
    let mut cert_body = BytesMut::new();
    CertificateMessage {
        certificates: own_cert.certificate.clone(),
    }
    .encode(&mut cert_body);
    let certificate = HandshakeMessage {
        msg_type: HandshakeType::Certificate,
        message_seq: 1,
        fragment_offset: 0,
        fragment_length: cert_body.len() as u32,
        total_length: cert_body.len() as u32,
        body: cert_body.freeze(),
    };

    // Deliver Certificate (seq 1) BEFORE ServerHello (seq 0) in one payload.
    let mut payload = BytesMut::new();
    certificate.encode(&mut payload);
    server_hello.encode(&mut payload);

    let mut ctx = HandshakeContext::new(None).unwrap();
    dtls.inner
        .process_handshake_payload(payload.freeze(), &mut ctx, &own_cert, true)
        .await?;

    assert!(ctx.server_random.is_some(), "ServerHello processed");
    assert!(
        ctx.peer_certificate.is_some(),
        "buffered Certificate drained after the gap closed"
    );
    assert_eq!(ctx.recv_message_seq, 2);
    Ok(())
}
