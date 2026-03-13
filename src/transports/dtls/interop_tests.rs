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

/// Requires webrtc-dtls server - environment dependent
#[tokio::test]
#[ignore]
async fn test_interop_rustrtc_client_webrtc_server() -> Result<()> {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();

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
        DtlsTransport::new(client_conn, cert, true, 1500, None).await?;
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

/// OpenSSL interop test - fails with LibreSSL due to compatibility issues
#[tokio::test]
#[ignore]
async fn test_interop_rustrtc_client_openssl_server() -> Result<()> {
    use std::process::{Command, Stdio};

    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("debug")),
        )
        .try_init();

    // Check if openssl is available and supports DTLS
    let openssl_version = match Command::new("openssl").arg("version").output() {
        Ok(output) => String::from_utf8_lossy(&output.stdout).to_string(),
        Err(_) => {
            info!("openssl command not found, skipping test");
            return Ok(());
        }
    };
    info!("OpenSSL version: {}", openssl_version.trim());

    // Check if s_server supports -dtls1_2
    let help_output = Command::new("openssl").args(["s_server", "-help"]).output();
    if let Ok(output) = help_output {
        let help_text = String::from_utf8_lossy(&output.stderr);
        if !help_text.contains("dtls1_2") {
            info!("openssl s_server does not support -dtls1_2, skipping test");
            return Ok(());
        }
    }

    let temp_dir = std::env::temp_dir();
    let key_path = temp_dir.join("rustrtc_test_key.pem");
    let cert_path = temp_dir.join("rustrtc_test_cert.pem");

    // Generate RSA certificate for the server
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
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    assert!(status.success(), "Failed to generate test certificate");

    // Find a free port by binding a temporary UDP socket
    let tmp_socket = std::net::UdpSocket::bind("127.0.0.1:0")?;
    let port = tmp_socket.local_addr()?.port();
    drop(tmp_socket);

    let port_str = port.to_string();
    let mut server_child = Command::new("openssl")
        .args([
            "s_server",
            "-dtls1_2",
            "-accept",
            &port_str,
            "-cert",
            cert_path.to_str().unwrap(),
            "-key",
            key_path.to_str().unwrap(),
            "-use_srtp",
            "SRTP_AES128_CM_SHA1_80",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()?;

    info!("OpenSSL s_server starting on port {}...", port);

    // Wait for the server to start listening
    tokio::time::sleep(Duration::from_millis(500)).await;

    let server_addr: std::net::SocketAddr = format!("127.0.0.1:{}", port).parse()?;
    let client_socket = UdpSocket::bind("127.0.0.1:0").await?;
    info!("Client socket bound to: {}", client_socket.local_addr()?);

    let socket_reader = Arc::new(client_socket);
    let socket_writer = socket_reader.clone();

    let (socket_tx, _) = tokio::sync::watch::channel(Some(IceSocketWrapper::Udp(socket_writer)));
    let client_conn = IceConn::new(socket_tx.subscribe(), server_addr);

    // Start read loop - forwards incoming UDP packets to IceConn
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
    let (client_dtls, _incoming_rx, runner) =
        DtlsTransport::new(client_conn, cert, true, 1500, None).await?;
    tokio::spawn(runner);

    // Poll for handshake completion
    let mut success = false;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let state = client_dtls.get_state();
        if let DtlsState::Connected(..) = state {
            info!("rustrtc DTLS handshake with OpenSSL succeeded!");
            success = true;
            break;
        }
        if tokio::time::Instant::now() >= deadline {
            error!("Timeout waiting for OpenSSL handshake, state: {}", state);
            break;
        }
    }

    let _ = server_child.kill();
    let _ = server_child.wait();
    let _ = std::fs::remove_file(&key_path);
    let _ = std::fs::remove_file(&cert_path);

    assert!(success, "DTLS Handshake with OpenSSL failed");

    Ok(())
}
