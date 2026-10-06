#![cfg(feature = "std")]

//! WP2: e2e verification of the IceSocketWrapper::Platform variant.
//! tokio UdpSocket → TokioUdpSocket (trait impl) → IceSocketWrapper::Platform
//! send_to/recv_from round-tripping proves the seam works.

use std::sync::Arc;

use core::net::SocketAddr;
use rustrtc::platform::net::TokioUdpSocket;
use rustrtc::platform::net::{NetError, UdpSocket};
use rustrtc::transports::ice::IceSocketWrapper;

struct Wrapped(Arc<tokio::net::UdpSocket>);

#[async_trait::async_trait]
impl UdpSocket for Wrapped {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        self.0.recv_from(buf).await.map_err(|_| NetError::Other)
    }
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
        self.0.send_to(buf, addr).await.map_err(|_| NetError::Other)
    }
    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        self.0.local_addr().map_err(|_| NetError::Other)
    }
}

#[tokio::test]
async fn platform_variant_send_recv() {
    let a = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b_addr = b.local_addr().unwrap();

    // wrap side b with the Platform variant
    let wrapper = IceSocketWrapper::Platform(Arc::new(Wrapped(Arc::new(b))));

    // side a sends
    a.send_to(b"hello-platform", b_addr).await.unwrap();

    // receive through the Platform variant
    let mut buf = vec![0u8; 64];
    let (n, from) = wrapper.recv_from(&mut buf).await.unwrap();
    assert_eq!(&buf[..n], b"hello-platform");
    assert_eq!(from, a.local_addr().unwrap());

    // echo back through the Platform variant
    wrapper.send_to(b"world", from).await.unwrap();
    let mut rbuf = vec![0u8; 64];
    let (n, _) = a.recv_from(&mut rbuf).await.unwrap();
    assert_eq!(&rbuf[..n], b"world");
}
