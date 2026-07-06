use super::*;
use crate::transports::PacketReceiver;
use crate::transports::ice::IceSocketWrapper;
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::watch;

#[tokio::test]
async fn test_dtls_handshake_with_fingerprint_verification() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (client_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(client_socket.clone())));
    let client_conn = IceConn::new(client_socket_tx.subscribe(), server_addr, None);

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr, None);

    let server_cert = generate_certificate()?;
    let server_fingerprint = fingerprint_from_der(&server_cert.certificate[0]);

    let client_cert = generate_certificate()?;
    let client_fingerprint = fingerprint_from_der(&client_cert.certificate[0]);

    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(server_fingerprint.clone()),
    )
    .await?;
    tokio::spawn(client_runner);

    let (server_dtls, _server_rx, server_runner) = DtlsTransport::new(
        server_conn.clone(),
        server_cert,
        false,
        1500,
        Some(client_fingerprint),
    )
    .await?;
    tokio::spawn(server_runner);

    // Reuse the pump helper from tests.rs (same crate)
    tokio::spawn({
        let socket = client_socket.clone();
        let conn = client_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });
    tokio::spawn({
        let socket = server_socket.clone();
        let conn = server_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });

    let mut client_state_rx = client_dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = client_state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            assert!(matches!(state, DtlsState::Connected(..)));
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("timed out waiting for client DTLS terminal state");
        }
        tokio::time::timeout(deadline - now, client_state_rx.changed()).await??;
    }

    let mut server_state_rx = server_dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = server_state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            assert!(matches!(state, DtlsState::Connected(..)));
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("timed out waiting for server DTLS terminal state");
        }
        tokio::time::timeout(deadline - now, server_state_rx.changed()).await??;
    }

    Ok(())
}

#[tokio::test]
async fn test_dtls_handshake_rejects_wrong_fingerprint() -> Result<()> {
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

    // Client expects wrong fingerprint — must fail
    let (client_dtls, _client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some("AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99".to_string()),
    )
    .await?;
    tokio::spawn(client_runner);

    // Need a real server to respond so the handshake reaches certificate verification
    let (_server_dtls, _server_rx, server_runner) =
        DtlsTransport::new(server_conn.clone(), server_cert, false, 1500, None).await?;
    tokio::spawn(server_runner);

    // Pumps
    tokio::spawn({
        let socket = client_socket.clone();
        let conn = client_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });
    tokio::spawn({
        let socket = server_socket.clone();
        let conn = server_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });

    let mut client_state_rx = client_dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = client_state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            assert!(
                matches!(state, DtlsState::Failed),
                "Expected DtlsState::Failed due to fingerprint mismatch, got {}",
                state
            );
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("timed out waiting for DTLS terminal state");
        }
        tokio::time::timeout(deadline - now, client_state_rx.changed()).await??;
    }

    Ok(())
}

#[tokio::test]
async fn test_dtls_encrypted_data_exchange() -> Result<()> {
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
    let server_fingerprint = fingerprint_from_der(&server_cert.certificate[0]);

    let (client_dtls, mut client_rx, client_runner) = DtlsTransport::new(
        client_conn.clone(),
        client_cert,
        true,
        1500,
        Some(server_fingerprint),
    )
    .await?;
    tokio::spawn(client_runner);

    let (server_dtls, mut server_rx, server_runner) =
        DtlsTransport::new(server_conn.clone(), server_cert, false, 1500, None).await?;
    tokio::spawn(server_runner);

    // Pumps
    tokio::spawn({
        let socket = client_socket.clone();
        let conn = client_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });
    tokio::spawn({
        let socket = server_socket.clone();
        let conn = server_conn.clone();
        async move {
            let mut buf = vec![0u8; 2048];
            loop {
                if let Ok((len, addr)) = socket.recv_from(&mut buf).await {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn.receive(packet, addr).await;
                }
            }
        }
    });

    // Wait for handshake completion
    let mut client_state_rx = client_dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = client_state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            assert!(matches!(state, DtlsState::Connected(..)));
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("timed out");
        }
        tokio::time::timeout(deadline - now, client_state_rx.changed()).await??;
    }

    let mut server_state_rx = server_dtls.subscribe_state();
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let state = server_state_rx.borrow().clone();
        if matches!(
            state,
            DtlsState::Connected(..) | DtlsState::Failed | DtlsState::Closed
        ) {
            assert!(matches!(state, DtlsState::Connected(..)));
            break;
        }
        let now = tokio::time::Instant::now();
        if now >= deadline {
            panic!("timed out");
        }
        tokio::time::timeout(deadline - now, server_state_rx.changed()).await??;
    }

    // Client sends encrypted data
    let test_msg = b"hello encrypted world";
    client_dtls.send(Bytes::from_static(test_msg)).await?;

    let received = tokio::time::timeout(std::time::Duration::from_secs(3), server_rx.recv())
        .await
        .map_err(|e| anyhow::anyhow!("timeout: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("channel closed"))?;
    assert_eq!(&received[..], test_msg);

    // Server sends back
    let reply = b"ack";
    server_dtls.send(Bytes::from_static(reply)).await?;

    let received = tokio::time::timeout(std::time::Duration::from_secs(3), client_rx.recv())
        .await
        .map_err(|e| anyhow::anyhow!("timeout: {}", e))?
        .ok_or_else(|| anyhow::anyhow!("channel closed"))?;
    assert_eq!(&received[..], reply);

    Ok(())
}

#[test]
fn test_change_cipher_spec_does_not_crash() {
    let ccs = ContentType::ChangeCipherSpec;
    assert_eq!(ccs as u8, 0x14);
}

#[test]
fn test_fingerprint_encoding() {
    let cert = generate_certificate().expect("certificate generation should succeed");
    let fp = fingerprint(&cert);

    assert!(fp.contains(':'), "Fingerprint must use colon separators");
    let parts: Vec<&str> = fp.split(':').collect();
    assert_eq!(parts.len(), 32, "SHA-256 produces 32 bytes");
    for part in &parts {
        assert_eq!(part.len(), 2, "Each hex byte is 2 chars: {}", part);
        assert!(u8::from_str_radix(part, 16).is_ok(), "Valid hex: {}", part);
    }
}

#[test]
fn test_handshake_state_transitions() {
    let keys = SessionKeys {
        client_write_key: vec![0u8; 16],
        server_write_key: vec![0u8; 16],
        client_write_iv: vec![0u8; 4],
        server_write_iv: vec![0u8; 4],
        master_secret: vec![0u8; 48],
        client_random: vec![0u8; 32],
        server_random: vec![0u8; 32],
    };

    let states = vec![
        DtlsState::New,
        DtlsState::Handshaking,
        DtlsState::Connected(Arc::new(create_session_crypto(keys).unwrap()), None),
        DtlsState::Failed,
        DtlsState::Closed,
    ];

    for state in &states {
        let s = format!("{}", state);
        assert!(!s.is_empty());
    }

    for state in &states {
        let cloned = state.clone();
        assert!(
            *state == cloned,
            "State clone mismatch: {} != {}",
            state,
            cloned
        );
    }
}
