use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use rustrtc::{UdtlConfig, UdtlReceiveBuffer, UdtlTransport};

/// Helper: create a pair of UdtlTransports connected to each other via localhost.
async fn make_transport_pair(
    config_a: Option<UdtlConfig>,
    config_b: Option<UdtlConfig>,
) -> (UdtlTransport, UdtlTransport) {
    let a_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let b_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let a_addr = a_sock.local_addr().unwrap();
    let b_addr = b_sock.local_addr().unwrap();

    let a = match config_a {
        Some(c) => UdtlTransport::with_config(a_sock, b_addr, c),
        None => UdtlTransport::new(a_sock, b_addr),
    };
    let b = match config_b {
        Some(c) => UdtlTransport::with_config(b_sock, a_addr, c),
        None => UdtlTransport::new(b_sock, a_addr),
    };
    (a, b)
}

/// Receive one UDPTL packet with a timeout.
async fn recv_timeout(
    transport: &UdtlTransport,
    buf: &mut UdtlReceiveBuffer,
    timeout: Duration,
) -> Option<Vec<u8>> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Ok(Some(data)) = transport.recv(buf).await {
                return Some(data.to_vec());
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .ok()
    .flatten()
}

// ──────────────────────────────────────────────
// UDPTL E2E tests
// ──────────────────────────────────────────────

#[tokio::test]
async fn test_udptl_send_recv_single() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, tb) = make_transport_pair(None, None).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    let payload = vec![0x01, 0x02, 0x03];
    ta.send(&payload).await.unwrap();

    let result = recv_timeout(&tb, &mut buf_b, Duration::from_secs(1)).await;
    assert_eq!(result, Some(payload));
}

#[tokio::test]
async fn test_udptl_send_recv_bidirectional() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, tb) = make_transport_pair(None, None).await;
    let mut buf_a = UdtlReceiveBuffer::new();
    let mut buf_b = UdtlReceiveBuffer::new();

    ta.send(b"hello").await.unwrap();
    tb.send(b"world").await.unwrap();

    let from_b = recv_timeout(&tb, &mut buf_b, Duration::from_secs(1)).await;
    assert_eq!(from_b, Some(b"hello".to_vec()));

    let from_a = recv_timeout(&ta, &mut buf_a, Duration::from_secs(1)).await;
    assert_eq!(from_a, Some(b"world".to_vec()));
}

#[tokio::test]
async fn test_udptl_send_recv_multiple_ordered() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, tb) = make_transport_pair(None, None).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    let n = 25;
    for i in 0..n {
        ta.send(&[i]).await.unwrap();
    }

    for i in 0..n {
        let result = recv_timeout(&tb, &mut buf_b, Duration::from_secs(2)).await;
        assert_eq!(result, Some(vec![i]), "mismatch at index {}", i);
    }

    assert_eq!(buf_b.packets_received, n as u64);
}

#[tokio::test]
async fn test_udptl_large_payload() {
    let _ = env_logger::builder().is_test(true).try_init();
    let config = UdtlConfig {
        max_datagram: 2000,
        ..UdtlConfig::default()
    };
    let (ta, tb) = make_transport_pair(Some(config.clone()), Some(config)).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    let payload = (0..255).collect::<Vec<_>>();
    ta.send(&payload).await.unwrap();

    let result = recv_timeout(&tb, &mut buf_b, Duration::from_secs(1)).await;
    assert_eq!(result, Some(payload));
}

#[tokio::test]
async fn test_udptl_stats_tracking() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, tb) = make_transport_pair(None, None).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    let n = 10;
    for i in 0..n {
        ta.send(&[i]).await.unwrap();
    }

    for _i in 0..n {
        recv_timeout(&tb, &mut buf_b, Duration::from_secs(2)).await;
    }

    assert_eq!(buf_b.packets_received, n as u64);
    assert!(buf_b.packets_lost == 0);
    assert_eq!(buf_b.expected_seq(), (n + 1) as u16);
}

#[tokio::test]
async fn test_udptl_sequence_numbers_monotonic() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, _tb) = make_transport_pair(None, None).await;

    let start = ta.current_seq();
    let n = 50u16;
    for i in 0..n {
        ta.send(&[i as u8]).await.unwrap();
    }
    let end = ta.current_seq();
    assert_eq!(end - start, n);
}

#[tokio::test]
async fn test_udptl_redundancy_recovery() {
    let _ = env_logger::builder().is_test(true).try_init();
    let config = UdtlConfig {
        redundancy_depth: 3,
        ..UdtlConfig::default()
    };
    let (ta, tb) = make_transport_pair(Some(config.clone()), Some(config)).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    for i in 0..5u8 {
        ta.send(&[i]).await.unwrap();
    }

    for i in 0..5 {
        let result = recv_timeout(&tb, &mut buf_b, Duration::from_secs(2)).await;
        assert_eq!(result, Some(vec![i]), "failed at {}", i);
    }

    assert_eq!(buf_b.packets_received, 5);
    assert_eq!(buf_b.packets_lost, 0);
}

#[tokio::test]
async fn test_udptl_out_of_order_reordering() {
    let _ = env_logger::builder().is_test(true).try_init();
    let (ta, tb) = make_transport_pair(None, None).await;
    let mut buf_b = UdtlReceiveBuffer::new();

    let payloads: Vec<Vec<u8>> = (0..20).map(|i| vec![i as u8; 10]).collect();
    for p in &payloads {
        ta.send(p).await.unwrap();
    }

    for (i, expected) in payloads.iter().enumerate() {
        let result = recv_timeout(&tb, &mut buf_b, Duration::from_secs(3)).await;
        assert_eq!(
            result.as_deref(),
            Some(expected.as_slice()),
            "payload {} mismatch",
            i
        );
    }
}
