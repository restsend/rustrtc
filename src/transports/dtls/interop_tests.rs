use super::*;
use crate::transports::ice::IceSocketWrapper;
use anyhow::Result;
use dtls::cipher_suite::CipherSuiteId;
use dtls::config::Config;
use dtls::crypto::Certificate as DtlsCertificate;
use dtls::listener::listen;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{error, info};
use webrtc_util::conn::Listener;

#[tokio::test]
async fn test_interop_rustrtc_client_webrtc_server() -> Result<()> {
    // 1. Setup webrtc-dtls server
    // Generate certificate for webrtc-dtls
    let cert = DtlsCertificate::generate_self_signed(vec!["localhost".to_string()])?;

    let config = Config {
        certificates: vec![cert],
        cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
        ..Default::default()
    };

    let listener = listen("127.0.0.1:0", config).await?;
    let server_addr = listener.addr().await?;

    info!("webrtc-dtls server listening on {}", server_addr);

    tokio::spawn(async move {
        while let Ok((conn, _)) = listener.accept().await {
            info!("webrtc-dtls server accepted connection");
            tokio::spawn(async move {
                let mut buf = vec![0u8; 1024];
                while let Ok(n) = conn.recv(&mut buf).await {
                    info!(
                        "webrtc-dtls server received: {}",
                        String::from_utf8_lossy(&buf[..n])
                    );
                    if let Err(e) = conn.send(&buf[..n]).await {
                        error!("webrtc-dtls server send error: {}", e);
                        break;
                    }
                }
            });
        }
    });

    // 2. Setup rustrtc client
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    // Clone socket for the read loop
    let socket_reader = Arc::new(client_socket);
    let socket_writer = socket_reader.clone();

    let client_conn = Arc::new(IceConn {
        socket: IceSocketWrapper::Udp(socket_writer),
        remote_addr: tokio::sync::RwLock::new(server_addr),
        dtls_receiver: tokio::sync::RwLock::new(None),
        rtp_receiver: tokio::sync::RwLock::new(None),
    });

    // Start read loop
    let conn_clone = client_conn.clone();
    let reader_clone = socket_reader.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 1500];
        loop {
            match reader_clone.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let packet = Bytes::copy_from_slice(&buf[..len]);
                    conn_clone.receive(packet, addr).await;
                }
                Err(e) => {
                    error!("Client socket read error: {}", e);
                    break;
                }
            }
        }
    });

    let cert = generate_certificate()?;
    let client_dtls = DtlsTransport::new(client_conn, cert, true).await?;

    // Wait for handshake
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check state
    {
        let state = client_dtls.state.lock().await;
        match *state {
            DtlsState::Connected(..) => info!("rustrtc client connected!"),
            _ => panic!("rustrtc client failed to connect, state: {}", *state),
        }
    }

    // Send data
    let msg = b"hello world";
    info!("rustrtc client sending: {:?}", String::from_utf8_lossy(msg));
    client_dtls.send(msg).await?;

    // Receive echo
    info!("rustrtc client waiting for echo...");
    let echo = client_dtls.recv().await?;
    info!(
        "rustrtc client received: {:?}",
        String::from_utf8_lossy(&echo)
    );

    assert_eq!(echo, msg);
    info!("Echo verified!");

    Ok(())
}
