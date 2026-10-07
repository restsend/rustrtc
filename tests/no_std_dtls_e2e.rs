#![cfg(not(feature = "std"))]

//! G1: DTLS handshake (self-implemented DTLS 1.2, ECDSA-P256 + ECDH-P256)
//! running over the loopback seams with the pure-Rust crypto backend —
//! the same seam shape rtcembed uses on the target (`platform::crypto`
//! reference backend + TRNG-backed platform RNG + embassy-shaped timers).
//!
//! Bypasses full ICE on purpose: two `IceConn`s over a loopback socket
//! pair isolate the DTLS layer. Assertions: handshake completes both ways,
//! fingerprints verified, SRTP keying material matches, app data round-trips.

mod common;

use std::sync::{Arc, Mutex};

use common::{block_on, drive_until, install_mock_platform};
use rustrtc::platform::net::UdpSocket;
use rustrtc::transports::dtls::{Certificate, DtlsState, DtlsTransport, fingerprint};
use rustrtc::transports::ice::conn::IceConn;
use rustrtc::transports::PacketReceiver;
use rustrtc::transports::ice::IceSocketWrapper;
use common::bind_loop;

const CERT_DER: &[u8] = include_bytes!("fixtures/dtls_cert.der");
const KEY_DER: &[u8] = include_bytes!("fixtures/dtls_key.der");

/// Forwards every inbound datagram into the DTLS transport (the demux role
/// the ICE read loop plays in a full stack).
async fn pump(sock: Arc<dyn UdpSocket>, transport: Arc<DtlsTransport>) {
    let mut buf = vec![0u8; 1500];
    let mut marshal = Vec::with_capacity(1500);
    loop {
        let Ok((len, from)) = sock.recv_from(&mut buf).await else {
            break;
        };
        let packet = bytes::Bytes::copy_from_slice(&buf[..len]);
        transport.receive(packet, from, &mut marshal).await;
    }
}

fn make_conn(sock: Arc<dyn UdpSocket>, peer: std::net::SocketAddr) -> Arc<IceConn> {
    let (tx, rx) = rustrtc::platform::sync::watch::channel(Some(IceSocketWrapper::Platform(
        sock,
    )));
    let _ = tx;
    IceConn::new(rx, peer, None)
}

#[test]
fn dtls_handshake_completes_over_the_loopback_seams() {
    install_mock_platform();
    // Explicit (the crypto-p256 feature also provides this as a fallback).
    rustrtc::platform::crypto::set_crypto(Arc::new(
        rustrtc::platform::crypto_p256::P256Crypto,
    ));

    let sock_c = bind_loop("127.0.0.1:40100".parse().unwrap()).unwrap();
    let sock_s = bind_loop("127.0.0.1:40102".parse().unwrap()).unwrap();
    let addr_c = sock_c.local_addr().unwrap();
    let addr_s = sock_s.local_addr().unwrap();

    // Same self-signed fixture on both sides (factory-provisioned cert
    // shape: pre-provisioned DER, no runtime certificate generation).
    let cert_c = Certificate::from_pkcs8_der(CERT_DER.to_vec(), KEY_DER.to_vec())
        .expect("client cert");
    let fp = fingerprint(&cert_c);
    assert!(!fp.is_empty());
    let cert_s = Certificate::from_pkcs8_der(CERT_DER.to_vec(), KEY_DER.to_vec())
        .expect("server cert");

    let conn_c = make_conn(sock_c.clone(), addr_s);
    let conn_s = make_conn(sock_s.clone(), addr_c);

    let (dtls_c, mut in_c, run_c) = block_on(DtlsTransport::new(
        conn_c,
        cert_c,
        true,
        1500,
        Some(fp.clone()),
    ))
    .expect("client DTLS transport");
    let (dtls_s, mut in_s, run_s) = block_on(DtlsTransport::new(
        conn_s,
        cert_s,
        false,
        1500,
        Some(fp),
    ))
    .expect("server DTLS transport");
    common::keep_task(Box::new(run_c));
    common::keep_task(Box::new(run_s));

    // Demux pumps (the ICE read loop's DTLS slice).
    common::keep_task(Box::new(pump(sock_c.clone(), dtls_c.clone())));
    common::keep_task(Box::new(pump(sock_s.clone(), dtls_s.clone())));

    // Collectors: park each inbound stream into a shared buffer the test
    // can inspect from the driver thread.
    async fn collector(
        mut rx: rustrtc::platform::sync::mpsc::UnboundedReceiver<bytes::Bytes>,
        seen: Arc<Mutex<Vec<Vec<u8>>>>,
    ) {
        while let Some(data) = rx.recv().await {
            seen.lock().unwrap().push(data.to_vec());
        }
    }

    let seen_c: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    let seen_s: Arc<Mutex<Vec<Vec<u8>>>> = Arc::new(Mutex::new(Vec::new()));
    common::keep_task(Box::new(collector(in_c, seen_c.clone())));
    common::keep_task(Box::new(collector(in_s, seen_s.clone())));

    let is_connected = |t: &Arc<DtlsTransport>| {
        matches!(
            *t.subscribe_state().borrow(),
            DtlsState::Connected(..)
        )
    };

    let ok = drive_until(
        || is_connected(&dtls_c) && is_connected(&dtls_s),
        60_000,
    );
    assert!(ok, "DTLS handshake must complete over the seams");

    // SRTP keying material must match on both sides (same extraction).
    let km_c = dtls_c
        .export_keying_material("EXTRACTOR-dtls_srtp", 60)
        .expect("client keying material");
    let km_s = dtls_s
        .export_keying_material("EXTRACTOR-dtls_srtp", 60)
        .expect("server keying material");
    assert_eq!(km_c.len(), 60);
    assert_eq!(km_c, km_s, "both sides must derive identical keys");

    // Application data round-trip through the protected channel.
    let sent_c = dtls_c.clone();
    common::keep_task(Box::new(async move {
        use rustrtc::platform::task::sleep;
        sleep(std::time::Duration::from_millis(50)).await;
        let _ = sent_c.send(bytes::Bytes::from_static(b"ping")).await;
    }));
    let got = drive_until(
        || seen_s.lock().unwrap().iter().any(|d| d == b"ping"),
        5_000,
    );
    assert!(got, "server must receive the client's app data");

    let sent_s = dtls_s.clone();
    common::keep_task(Box::new(async move {
        use rustrtc::platform::task::sleep;
        sleep(std::time::Duration::from_millis(50)).await;
        let _ = sent_s.send(bytes::Bytes::from_static(b"pong")).await;
    }));
    let got = drive_until(
        || seen_c.lock().unwrap().iter().any(|d| d == b"pong"),
        5_000,
    );
    assert!(got, "client must receive the server's app data");
}
