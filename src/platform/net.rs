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

impl core::fmt::Debug for dyn UdpSocket {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let addr = self
            .local_addr()
            .map(|a| a.to_string())
            .unwrap_or_else(|_| "?".into());
        write!(f, "UdpSocket({addr})")
    }
}

/// UDP bind factory seam: creates the sockets behind ICE host candidates and
/// the direct-RTP path. std default: tokio sockets. Embedded: the embedder
/// (rtcembed) installs a factory over embassy-net — usually its demux socket
/// (single reader + dispatch), so `recv_from` here is served from an inbox
/// and `send_to`/`try_send_to` enqueue to the shared TX path.
pub type UdpBindFn =
    fn(core::net::SocketAddr) -> crate::errors::RtcResult<alloc::sync::Arc<dyn UdpSocket>>;

static UDP_BIND_FN: crate::platform::sync::Mutex<Option<UdpBindFn>> =
    crate::platform::sync::Mutex::new(None);

/// Installs the UDP bind factory (embedded targets; overrides the tokio
/// backend on std too, which host tests use for deterministic loopbacks).
pub fn set_udp_bind_fn(f: UdpBindFn) {
    *UDP_BIND_FN.lock() = Some(f);
}

/// Clears the UDP bind factory (test isolation).
pub fn clear_udp_bind_fn() {
    *UDP_BIND_FN.lock() = None;
}

/// Runs a bind through the installed factory; `None` when no factory is set
/// (callers fall back to the tokio backend, or fail on embedded).
pub(crate) fn udp_bind_via_factory(
    addr: core::net::SocketAddr,
) -> Option<crate::errors::RtcResult<alloc::sync::Arc<dyn UdpSocket>>> {
    let f = *UDP_BIND_FN.lock();
    f.map(|f| f(addr))
}

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
            self.0.recv_from(buf).await.map_err(|_| NetError::Other)
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
            self.0.try_send_to(buf, addr).map_err(|_| NetError::Other)
        }
    }
}

#[cfg(feature = "std")]
pub use tokio_impl::TokioUdpSocket;
