use super::*;
use crate::transports::ice::IceSocketWrapper;
use anyhow::Result;
use dtls::cipher_suite::CipherSuiteId;
use dtls::config::Config;
use dtls::crypto::Certificate as DtlsCertificate;
use dtls::extension::extension_use_srtp::SrtpProtectionProfile;
use dtls::listener::listen;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{error, info};
use webrtc_util::conn::Listener;

#[tokio::test]
async fn test_interop_rustrtc_client_webrtc_server() -> Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init();

    // 1. Setup webrtc-dtls server
    // Generate certificate for webrtc-dtls
    let cert = DtlsCertificate::generate_self_signed(vec!["localhost".to_string()])?;

    let config = Config {
        certificates: vec![cert],
        cipher_suites: vec![CipherSuiteId::Tls_Ecdhe_Ecdsa_With_Aes_128_Gcm_Sha256],
        srtp_protection_profiles: vec![SrtpProtectionProfile::Srtp_Aead_Aes_128_Gcm],
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

    let (socket_tx, _) = tokio::sync::watch::channel(Some(IceSocketWrapper::Udp(socket_writer)));
    let client_conn = IceConn::new(socket_tx.subscribe(), server_addr);

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
    let (client_dtls, mut incoming_rx, runner) =
        DtlsTransport::new(client_conn, cert, true, 1500).await?;
    tokio::spawn(runner);

    // Wait for handshake
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Check state
    {
        let state = client_dtls.get_state();
        match state {
            DtlsState::Connected(..) => info!("rustrtc client connected!"),
            _ => panic!("rustrtc client failed to connect, state: {}", state),
        }
    }

    // Send data
    let msg = b"hello world";
    info!("rustrtc client sending: {:?}", String::from_utf8_lossy(msg));
    client_dtls.send(Bytes::from_static(msg)).await?;

    // Receive echo
    info!("rustrtc client waiting for echo...");
    let echo = incoming_rx
        .recv()
        .await
        .ok_or(anyhow::anyhow!("Channel closed"))?;
    info!(
        "rustrtc client received: {:?}",
        String::from_utf8_lossy(&echo)
    );

    assert_eq!(&echo[..], msg);
    info!("Echo verified!");

    Ok(())
}

#[tokio::test]
async fn test_interop_rustrtc_client_openssl_server() -> Result<()> {
    use std::process::{Command, Stdio};

    // Check if openssl is available
    if Command::new("openssl").arg("version").output().is_err() {
        println!("openssl command not found, skipping test");
        return Ok(());
    }

    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join("key.pem");
    let cert_path = temp_dir.join("cert.pem");

    let status = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            key_path.to_str().unwrap(),
            "-out",
            cert_path.to_str().unwrap(),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
        ])
        .status()?;
    assert!(status.success());

    let port = 44444;
    let mut server_child = Command::new("openssl")
        .args([
            "s_server",
            "-dtls1_2",
            "-accept",
            &port.to_string(),
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-use_srtp",
            "SRTP_AES128_CM_SHA1_80",
            "-msg",
            "-debug",
        ])
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()?;

    info!("Waiting for OpenSSL s_server to start on port {}...", port);
    tokio::time::sleep(Duration::from_secs(1)).await;

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    let socket_reader = Arc::new(client_socket);
    let socket_writer = socket_reader.clone();

    let (socket_tx, _) = tokio::sync::watch::channel(Some(IceSocketWrapper::Udp(socket_writer)));
    let client_conn = IceConn::new(socket_tx.subscribe(), server_addr);

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
                Err(_) => break,
            }
        }
    });

    let cert = generate_certificate()?;
    let (client_dtls, _incoming_rx, runner) =
        DtlsTransport::new(client_conn, cert, true, 1500).await?;
    tokio::spawn(runner);

    let mut success = false;
    let timeout = tokio::time::sleep(Duration::from_secs(5));
    tokio::pin!(timeout);

    loop {
        tokio::select! {
            _ = &mut timeout => {
                let state = client_dtls.get_state();
                if let DtlsState::Connected(..) = state {
                    info!("rustrtc client connected!");
                    success = true;
                } else {
                    error!("Timeout waiting for OpenSSL handshake, state: {}", state);
                }
                break;
            }
        }
    }

    let _ = server_child.kill();
    let _ = std::fs::remove_file(key_path);
    let _ = std::fs::remove_file(cert_path);

    assert!(success, "DTLS Handshake with OpenSSL failed");

    Ok(())
}
