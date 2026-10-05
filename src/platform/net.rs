//! Platform network seams (WP2).
//!
//! [`UdpSocket`] is the socket seam for ICE/STUN/TURN: the
//! `platform-tokio` backend implements it over tokio; the embassy-net
//! implementation lands in WP3. ICE logic (decision D2: stays inside
//! rustrtc) only depends on this trait and never sees the network stack.

use crate::prelude::*;
#[cfg_attr(feature = "std", allow(unused_imports))]
use alloc::string::String;
use core::net::SocketAddr;

/// Single-reader UDP socket seam (matches the rsipstack::platform::net
/// decision — concurrent ICE/STUN/RTP reads of one socket are unified by
/// the upper demux layer, so only `&self` + internal synchronisation is
/// required; the tokio backend satisfies this natively).
///
/// embassy backend (WP3): rtcembed's demux provides the single-reader
/// + dispatch implementation.
#[async_trait::async_trait]
pub trait UdpSocket: Send + Sync {
    /// Receives one datagram, returning `(len, remote address)`.
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError>;

    /// Sends one datagram; for UDP this always equals `buf.len()`.
    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError>;

    fn local_addr(&self) -> Result<SocketAddr, NetError>;

    /// Synchronous best-effort send for RTP fast paths. Default:
    /// unsupported.
    fn try_send_to(&self, _buf: &[u8], _addr: SocketAddr) -> Result<usize, NetError> {
        Err(NetError::Other)
    }
}

/// Socket error (WP3 will switch to a type carrying backend error detail).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetError {
    Closed,
    BufferTooSmall,
    Other,
}

impl core::fmt::Display for NetError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NetError::Closed => f.write_str("socket closed"),
            NetError::BufferTooSmall => f.write_str("buffer too small"),
            NetError::Other => f.write_str("io error"),
        }
    }
}

impl core::error::Error for NetError {}

// ── tokio backend implementation (platform-tokio) ──
#[cfg(feature = "std")]
pub mod tokio_impl {
    use super::{NetError, UdpSocket};
    use alloc::sync::Arc;
    use core::net::SocketAddr;

    /// Wrapper over a tokio UdpSocket (internally Arc-shared; ICE/STUN/RTP
    /// concurrent reads/writes are safe via tokio's socket-level
    /// synchronisation).
    #[derive(Clone)]
    pub struct TokioUdpSocket(pub Arc<tokio::net::UdpSocket>);

    impl TokioUdpSocket {
        pub fn new(sock: tokio::net::UdpSocket) -> Self {
            Self(Arc::new(sock))
        }
    }

    #[async_trait::async_trait]
    impl UdpSocket for TokioUdpSocket {
        async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
            self.0
                .recv_from(buf)
                .await
                .map_err(|_| NetError::Other)
        }

        async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
            self.0.send_to(buf, addr).await.map_err(|_| NetError::Other)
        }

        fn local_addr(&self) -> Result<SocketAddr, NetError> {
            self.0.local_addr().map_err(|_| NetError::Other)
        }

        fn try_send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
            // tokio readiness model: a socket never polled for writability
            // reports WouldBlock even when the OS buffer is free. Drive one
            // non-blocking readiness poll first (a fresh UDP socket is
            // writable, so this completes immediately).
            {
                use core::future::Future;
                use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
                unsafe fn clone_raw(_: *const ()) -> RawWaker {
                    RawWaker::new(core::ptr::null(), &VTABLE)
                }
                unsafe fn noop_raw(_: *const ()) {}
                static VTABLE: RawWakerVTable =
                    RawWakerVTable::new(clone_raw, noop_raw, noop_raw, noop_raw);
                let waker = unsafe { Waker::from_raw(RawWaker::new(core::ptr::null(), &VTABLE)) };
                let mut cx = Context::from_waker(&waker);
                let mut fut = self.0.writable();
                let _ = core::pin::pin!(fut).poll(&mut cx);
            }
            self.0
                .try_send_to(buf, addr)
                .map_err(|_| NetError::Other)
        }
    }
}

#[cfg(feature = "std")]
pub use tokio_impl::TokioUdpSocket;
