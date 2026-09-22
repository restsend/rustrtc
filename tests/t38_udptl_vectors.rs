#![cfg(feature = "t38")]

use bytes::Bytes;
use rustrtc::transports::udptl::{UdtlConfig, UdtlReceiveBuffer, UdtlTransport};
use std::sync::Arc;
use tokio::net::UdpSocket;

#[tokio::test]
async fn udptl_tx_framing_matches_t38_spec() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b.local_addr().unwrap();
    let config = UdtlConfig {
        redundancy_depth: 2,
        ..UdtlConfig::default()
    };
    let t = UdtlTransport::with_config(Arc::new(a), b_addr, config);

    t.send(&[0xC0, 0x01, 0x20]).await.unwrap();
    t.send(&[0x02]).await.unwrap();
    t.send(&[0x06]).await.unwrap();

    let mut buf = [0u8; 256];
    let (n, _) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], &[0x00, 0x01, 0x03, 0xC0, 0x01, 0x20]);

    let (n, _) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(
        &buf[..n],
        &[0x00, 0x02, 0x01, 0x02, 0x00, 0x01, 0x03, 0xC0, 0x01, 0x20]
    );

    let (n, _) = b.recv_from(&mut buf).await.unwrap();
    assert_eq!(
        &buf[..n],
        &[
            0x00, 0x03, 0x01, 0x06, 0x00, 0x02, 0x03, 0xC0, 0x01, 0x20, 0x01, 0x02
        ]
    );
}

#[tokio::test]
async fn udptl_rx_parses_t38_spec_vectors() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let a_addr = a.local_addr().unwrap();
    let t = UdtlTransport::new(Arc::new(b), a_addr);
    let mut rb = UdtlReceiveBuffer::new();

    a.send_to(
        &[0x00, 0x05, 0x03, 0xC0, 0x01, 0x20],
        t.socket().local_addr().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), t.recv(&mut rb))
            .await
            .unwrap()
            .unwrap(),
        Some(Bytes::from_static(&[0xC0, 0x01, 0x20]))
    );

    a.send_to(
        &[
            0x00, 0x06, 0x01, 0x02, 0x00, 0x02, 0x03, 0xAA, 0xBB, 0xCC, 0x01, 0xDD,
        ],
        t.socket().local_addr().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), t.recv(&mut rb))
            .await
            .unwrap()
            .unwrap(),
        Some(Bytes::from_static(&[0x02]))
    );

    a.send_to(
        &[
            0x00, 0x07, 0x01, 0x06, 0x80, 0x00, 0x06, 0x01, 0x05, 0xDE, 0xAD,
        ],
        t.socket().local_addr().unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(
        tokio::time::timeout(std::time::Duration::from_secs(1), t.recv(&mut rb))
            .await
            .unwrap()
            .unwrap(),
        Some(Bytes::from_static(&[0x06]))
    );
}

#[test]
fn udptl_redundancy_recovers_lost_primary() {
    let mut rb = UdtlReceiveBuffer::new();

    assert_eq!(
        rb.try_deliver(3, Bytes::from_static(&[0x33]), vec![])
            .unwrap(),
        Some(Bytes::from_static(&[0x33]))
    );

    let got = rb
        .try_deliver(
            5,
            Bytes::from_static(&[0x35]),
            vec![(4, Bytes::from_static(&[0x34]))],
        )
        .unwrap();
    assert_eq!(got, Some(Bytes::from_static(&[0x34])));
    assert_eq!(rb.take_ready(), Some(Bytes::from_static(&[0x35])));
    assert_eq!(rb.take_ready(), None);
    assert_eq!(rb.packets_recovered, 1);
    assert_eq!(rb.last_delivered_seq, Some(5));
}

#[test]
fn udptl_first_packet_accepts_any_seq() {
    let mut rb = UdtlReceiveBuffer::new();
    assert_eq!(
        rb.try_deliver(0x8000, Bytes::from_static(&[0x01]), vec![])
            .unwrap(),
        Some(Bytes::from_static(&[0x01]))
    );
    assert_eq!(
        rb.try_deliver(0x8001, Bytes::from_static(&[0x02]), vec![])
            .unwrap(),
        Some(Bytes::from_static(&[0x02]))
    );
    assert_eq!(
        rb.try_deliver(0x8000, Bytes::from_static(&[0x01]), vec![])
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn udptl_rejects_oversized_ifp() {
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let t = UdtlTransport::new(Arc::new(a), b.local_addr().unwrap());
    let big = vec![0u8; 256];
    assert!(t.send(&big).await.is_err());
}
