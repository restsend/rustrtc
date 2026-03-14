use anyhow::{Result, anyhow};
use bytes::{Bytes, BytesMut};
use rustrtc::transports::PacketReceiver;
use rustrtc::transports::dtls::handshake::{HandshakeMessage, HandshakeType};
use rustrtc::transports::dtls::record::{ContentType, DtlsRecord, ProtocolVersion};
use rustrtc::transports::dtls::{DtlsState, DtlsTransport, generate_certificate};
use rustrtc::transports::ice::IceSocketWrapper;
use rustrtc::transports::ice::conn::IceConn;
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
            return Err(anyhow!("timed out waiting for DTLS terminal state"));
        }

        tokio::time::timeout(deadline - now, state_rx.changed()).await??;
    }
}

#[tokio::test]
async fn malformed_dtls_fragment_range_fails_handshake() -> Result<()> {
    let client_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
    let server_socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);

    let client_addr = client_socket.local_addr()?;
    let server_addr = server_socket.local_addr()?;

    let (server_socket_tx, _) = watch::channel(Some(IceSocketWrapper::Udp(server_socket.clone())));
    let server_conn = IceConn::new(server_socket_tx.subscribe(), client_addr);

    let cert = generate_certificate()?;
    let (server_dtls, _server_rx, runner) =
        DtlsTransport::new(server_conn.clone(), cert, false, 128, None).await?;
    tokio::spawn(runner);
    spawn_socket_pump(server_socket, server_conn);

    let handshake_msg = HandshakeMessage {
        msg_type: HandshakeType::ClientHello,
        total_length: 32,
        message_seq: 0,
        fragment_offset: 16,
        fragment_length: 32,
        body: Bytes::from(vec![0u8; 32]),
    };

    let mut handshake_buf = BytesMut::new();
    handshake_msg.encode(&mut handshake_buf);
    let record = DtlsRecord {
        content_type: ContentType::Handshake,
        version: ProtocolVersion::DTLS_1_2,
        epoch: 0,
        sequence_number: 0,
        payload: handshake_buf.freeze(),
    };

    let mut record_buf = BytesMut::new();
    record.encode(&mut record_buf);
    client_socket.send_to(&record_buf, server_addr).await?;

    assert!(matches!(
        wait_for_terminal_state(&server_dtls).await?,
        DtlsState::Failed
    ));
    Ok(())
}
