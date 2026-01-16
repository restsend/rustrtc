use bytes::Bytes;
use rustrtc::rtp::{RtpHeader, RtpPacket};
use rustrtc::srtp::{SrtpContext, SrtpDirection, SrtpKeyingMaterial, SrtpProfile};
use rustrtc::transports::PacketReceiver;
use rustrtc::transports::dtls::{DtlsState, DtlsTransport};
use rustrtc::transports::ice::IceSocketWrapper;
use rustrtc::transports::ice::conn::IceConn;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::UdpSocket;
use tokio::sync::watch;

#[tokio::main]
async fn main() {
    rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider()).ok();
    let args: Vec<String> = std::env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("all");

    if mode == "srtp" || mode == "all" {
        println!("Running SRTP Benchmark...");
        bench_srtp(SrtpProfile::Aes128Sha1_80, "AES128_SHA1_80");
        bench_srtp(SrtpProfile::AeadAes128Gcm, "AEAD_AES128_GCM");
    }

    if mode == "dtls" || mode == "all" {
        println!("\nRunning DTLS Benchmark...");
        bench_dtls().await;
    }
}

fn bench_srtp(profile: SrtpProfile, name: &str) {
    let keying = SrtpKeyingMaterial::new(vec![0u8; 16], vec![0u8; 14]);
    let mut sender =
        SrtpContext::new(1234, profile, keying.clone(), SrtpDirection::Sender).unwrap();
    let mut receiver = SrtpContext::new(1234, profile, keying, SrtpDirection::Receiver).unwrap();

    let payload_size = 1200;
    let iterations = 100_000;
    let mut packet = RtpPacket::new(RtpHeader::new(96, 0, 0, 1234), vec![0u8; payload_size]);

    println!(
        "Benchmarking {} ({} iterations, {} bytes payload)",
        name, iterations, payload_size
    );

    let start = Instant::now();
    for i in 0..iterations {
        packet.header.sequence_number = (i % 65535) as u16;
        // Reset payload size (protect adds tag)
        packet.payload.truncate(payload_size);

        sender.protect(&mut packet).unwrap();
        receiver.unprotect(&mut packet).unwrap();
    }
    let duration = start.elapsed();

    let total_bytes = (payload_size * iterations) as u64;
    let mb = total_bytes as f64 / 1024.0 / 1024.0;
    let secs = duration.as_secs_f64();

    println!("  Duration: {:.2?}", duration);
    println!("  Throughput: {:.2} MB/s", mb / secs);
    println!("  Ops: {:.2} ops/s", iterations as f64 / secs);
}

async fn bench_dtls() {
    let iterations = 100_000;
    let payload_size = 1024;

    println!("Setting up DTLS connection...");

    // Setup connection
    let s1 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let s2 = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let addr1 = s1.local_addr().unwrap();
    let addr2 = s2.local_addr().unwrap();

    let (_tx1, rx1) = watch::channel(Some(IceSocketWrapper::Udp(s1.clone())));
    let conn1 = IceConn::new(rx1, addr2);

    let (_tx2, rx2) = watch::channel(Some(IceSocketWrapper::Udp(s2.clone())));
    let conn2 = IceConn::new(rx2, addr1);

    // Spawn read loops
    let s1_clone = s1.clone();
    let conn1_clone = conn1.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2000];
        loop {
            if let Ok((len, addr)) = s1_clone.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                conn1_clone.receive(packet, addr).await;
            }
        }
    });

    let s2_clone = s2.clone();
    let conn2_clone = conn2.clone();
    tokio::spawn(async move {
        let mut buf = [0u8; 2000];
        loop {
            if let Ok((len, addr)) = s2_clone.recv_from(&mut buf).await {
                let packet = Bytes::copy_from_slice(&buf[..len]);
                conn2_clone.receive(packet, addr).await;
            }
        }
    });

    let cert1 = rustrtc::transports::dtls::generate_certificate().unwrap();
    let cert2 = rustrtc::transports::dtls::generate_certificate().unwrap();

    let (dtls1, _rx_data1, runner1) = DtlsTransport::new(conn1, cert1, true, 2000).await.unwrap();
    let (dtls2, mut rx_data2, runner2) =
        DtlsTransport::new(conn2, cert2, false, 2000).await.unwrap();

    tokio::spawn(runner1);
    tokio::spawn(runner2);

    // Wait for connection
    let mut state_rx = dtls1.subscribe_state();
    loop {
        if let DtlsState::Connected(_, _) = *state_rx.borrow() {
            break;
        }
        if state_rx.changed().await.is_err() {
            panic!("DTLS failed to connect");
        }
    }
    println!(
        "DTLS Connected. Starting benchmark ({} iterations, {} bytes payload)...",
        iterations, payload_size
    );

    let data = Bytes::from(vec![0u8; payload_size]);
    let start = Instant::now();

    let dtls1_clone = dtls1.clone();
    let data_clone = data.clone();

    let sender_handle = tokio::spawn(async move {
        for _ in 0..iterations {
            dtls1_clone.send(data_clone.clone()).await.unwrap();
        }
    });

    let mut received_count = 0;
    while received_count < iterations {
        if let Some(_) = rx_data2.recv().await {
            received_count += 1;
        } else {
            break;
        }
    }

    sender_handle.await.unwrap();
    let duration = start.elapsed();

    let total_bytes = (payload_size * iterations) as u64;
    let mb = total_bytes as f64 / 1024.0 / 1024.0;
    let secs = duration.as_secs_f64();

    println!("  Duration: {:.2?}", duration);
    println!("  Throughput: {:.2} MB/s", mb / secs);
    println!("  Ops: {:.2} ops/s", iterations as f64 / secs);

    dtls1.close();
    dtls2.close();
}
