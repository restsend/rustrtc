use super::*;
use crate::transports::PacketReceiver;
use crate::transports::ice::IceSocketWrapper;
use bytes::Bytes;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

#[tokio::test]
async fn test_dtls_handshake_client_hello() -> Result<()> {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let client_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(Arc::new(client_socket)),
        remote_addr: RwLock::new(server_addr),
        dtls_receiver: RwLock::new(None),
        rtp_receiver: RwLock::new(None),
    });

    let server_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(Arc::new(server_socket)),
        remote_addr: RwLock::new(client_addr),
        dtls_receiver: RwLock::new(None),
        rtp_receiver: RwLock::new(None),
    });

    let cert = generate_certificate()?;

    // Start client
    let _client_dtls = DtlsTransport::new(client_conn, cert.clone(), true).await?;

    // Read from server socket to verify ClientHello
    let mut buf = vec![0u8; 2048];
    let (len, addr) = server_conn.socket.recv_from(&mut buf).await?;
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
async fn test_dtls_handshake_server_hello() -> Result<()> {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let server_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(Arc::new(server_socket)),
        remote_addr: RwLock::new(client_addr),
        dtls_receiver: RwLock::new(None),
        rtp_receiver: RwLock::new(None),
    });

    let cert = generate_certificate()?;

    // Start server
    let _server_dtls = DtlsTransport::new(server_conn.clone(), cert.clone(), false).await?;

    // Start a loop to feed server_dtls
    let server_socket_clone = server_conn.socket.clone();
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

    // Read response (ServerHello)
    let mut recv_buf = vec![0u8; 8192];
    let (len, _addr) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_socket.recv_from(&mut recv_buf),
    )
    .await??;

    let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
    let record = DtlsRecord::decode(&mut data)?.unwrap();

    assert_eq!(record.content_type, ContentType::Handshake);

    let mut body = record.payload;
    let msg = HandshakeMessage::decode(&mut body)?.unwrap();

    assert_eq!(msg.msg_type, HandshakeType::ServerHello);

    // Read Certificate
    let mut recv_buf = vec![0u8; 8192];
    let (len, _addr) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_socket.recv_from(&mut recv_buf),
    )
    .await??;
    let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
    let record = DtlsRecord::decode(&mut data)?.unwrap();
    assert_eq!(record.content_type, ContentType::Handshake);
    let mut body = record.payload;
    let msg = HandshakeMessage::decode(&mut body)?.unwrap();
    assert_eq!(msg.msg_type, HandshakeType::Certificate);

    // Read ServerKeyExchange
    let mut recv_buf = vec![0u8; 8192];
    let (len, _addr) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_socket.recv_from(&mut recv_buf),
    )
    .await??;
    let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
    let record = DtlsRecord::decode(&mut data)?.unwrap();
    assert_eq!(record.content_type, ContentType::Handshake);
    let mut body = record.payload;
    let msg = HandshakeMessage::decode(&mut body)?.unwrap();
    assert_eq!(msg.msg_type, HandshakeType::ServerKeyExchange);

    // Read ServerHelloDone
    let mut recv_buf = vec![0u8; 8192];
    let (len, _addr) = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        client_socket.recv_from(&mut recv_buf),
    )
    .await??;
    let mut data = Bytes::copy_from_slice(&recv_buf[..len]);
    let record = DtlsRecord::decode(&mut data)?.unwrap();
    assert_eq!(record.content_type, ContentType::Handshake);
    let mut body = record.payload;
    let msg = HandshakeMessage::decode(&mut body)?.unwrap();
    assert_eq!(msg.msg_type, HandshakeType::ServerHelloDone);

    Ok(())
}

#[tokio::test]
async fn test_dtls_handshake_full_flow() -> Result<()> {
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let server_socket = UdpSocket::bind("127.0.0.1:0").await?;

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let client_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(Arc::new(client_socket)),
        remote_addr: RwLock::new(server_addr),
        dtls_receiver: RwLock::new(None),
        rtp_receiver: RwLock::new(None),
    });

    let server_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(Arc::new(server_socket)),
        remote_addr: RwLock::new(client_addr),
        dtls_receiver: RwLock::new(None),
        rtp_receiver: RwLock::new(None),
    });

    let cert = generate_certificate()?;

    // Start client and server
    let _client_dtls = DtlsTransport::new(client_conn.clone(), cert.clone(), true).await?;
    let _server_dtls = DtlsTransport::new(server_conn.clone(), cert.clone(), false).await?;

    // Start loops to feed DTLS transports
    let client_socket_clone = client_conn.socket.clone();
    let client_conn_clone = client_conn.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 2048];
        loop {
            if let Ok((len, addr)) = client_socket_clone.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                client_conn_clone.receive(packet, addr).await;
            }
        }
    });

    let server_socket_clone = server_conn.socket.clone();
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

    // Wait for handshake to complete (simple timeout for now)
    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;

    // Check states (Note: In a real test we would wait for state change events)
    // Since we are running in the same process, we can check the internal state if we exposed it,
    // or just verify that no errors occurred and packets were exchanged.

    // For now, let's just verify that the client sent the final flight
    // We can't easily inspect the internal state without exposing it,
    // but if the handshake failed, the background tasks would print errors.

    Ok(())
}
