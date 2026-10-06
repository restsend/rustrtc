//! Platform seams for the no_std build (WP2, growing slice by slice).
//!
//! - [`time`]: monotonic-ish instant for inactivity/expiry accounting.
//! - [`net`]: UDP socket abstraction (data-plane send/recv).
//! - [`task`] / [`sync`] / [`select`]: spawn + timers + channel seams used
//!   by the ICE transport.
//!
//! std build: the seams alias tokio types, so existing call sites keep
//! working unchanged. no_std build: spin-lock channels and an injected
//! task spawner (`task::set_spawn_fn`) — the WP3 embassy pass replaces
//! the placeholders with embassy-time primitives.

pub mod net;

/// 64-bit atomic counters that degrade gracefully on targets without 64-bit
/// atomics (ESP32-S3 etc.): backed by `AtomicU32`, values wrap at 2^32.
pub mod atomic64 {
    #[cfg(target_has_atomic = "64")]
    pub use core::sync::atomic::AtomicU64;

    #[cfg(not(target_has_atomic = "64"))]
    #[derive(Debug, Default)]
    pub struct AtomicU64(core::sync::atomic::AtomicU32);

    #[cfg(not(target_has_atomic = "64"))]
    impl AtomicU64 {
        pub const fn new(v: u64) -> Self {
            Self(core::sync::atomic::AtomicU32::new(v as u32))
        }
        pub fn load(&self, o: core::sync::atomic::Ordering) -> u64 {
            self.0.load(o) as u64
        }
        pub fn store(&self, v: u64, o: core::sync::atomic::Ordering) {
            self.0.store(v as u32, o)
        }
        pub fn fetch_add(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
            self.0.fetch_add(v as u32, o) as u64
        }
        pub fn fetch_sub(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
            self.0.fetch_sub(v as u32, o) as u64
        }
        pub fn swap(&self, v: u64, o: core::sync::atomic::Ordering) -> u64 {
            self.0.swap(v as u32, o) as u64
        }
    }
}

/// DNS resolver seam. std: tokio's `lookup_host`. no_std (WP3): the
/// embedder injects an embassy-net DNS resolver (or a static map).
pub mod dns {
    use crate::errors::RtcResult;
    use alloc::vec::Vec;
    use core::net::SocketAddr;

    /// Resolves `host:port` to a list of socket addresses.
    #[cfg(feature = "std")]
    pub async fn lookup_host(host: &str) -> RtcResult<Vec<SocketAddr>> {
        let addrs = tokio::net::lookup_host(host)
            .await
            .map_err(|e| crate::errors::RtcError::Internal(alloc::format!("dns: {e}")))?;
        Ok(addrs.collect())
    }

    /// no_std placeholder (WP3 wires the embedder's resolver).
    #[cfg(not(feature = "std"))]
    pub async fn lookup_host(_host: &str) -> RtcResult<Vec<SocketAddr>> {
        Err(crate::errors::RtcError::Internal(
            alloc::string::String::from("dns: no resolver wired (WP3)"),
        ))
    }
}

#[cfg(not(feature = "std"))]
pub mod sync_embedded;

/// 64-bit atomic counters that degrade gracefully on targets without 64-bit
/// atomics (ESP32-S3 etc.): backed by `AtomicU32`, values wrap at 2^32 —
/// fine for diagnostics counters and a 2^32 ms logical clock.

/// Backend-agnostic racing combinators (replace `tokio::select!` at the
/// drive-loop sites). Poll-based and unbiased: all arms polled on every
/// wake; first completion wins. Futures must be `Unpin` (callers pass
/// `core::pin::pin!(..)` bindings for `!Unpin` futures).
pub mod select {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// `FutureExt::poll_unpin` without the dependency: `Unpin` futures can
    /// be polled through `Pin::new`.
    #[inline]
    fn poll_unpin<F: Future + Unpin>(fut: &mut F, cx: &mut Context<'_>) -> Poll<F::Output> {
        Pin::new(fut).poll(cx)
    }

    /// Two-arm race output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Either<A, B> {
        A(A),
        B(B),
    }

    /// Three-arm race output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Which3<A, B, C> {
        A(A),
        B(B),
        C(C),
    }

    /// Four-arm race output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Which4<A, B, C, D> {
        A(A),
        B(B),
        C(C),
        D(D),
    }

    /// Races two futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Select2<A: Future, B: Future> {
        a: A,
        b: B,
    }

    /// Races two futures.
    pub fn select2<A: Future, B: Future>(a: A, b: B) -> Select2<A, B> {
        Select2 { a, b }
    }

    impl<A: Future + Unpin, B: Future + Unpin> Future for Select2<A, B> {
        type Output = Either<A::Output, B::Output>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            if let Poll::Ready(v) = poll_unpin(&mut this.a, cx) {
                return Poll::Ready(Either::A(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.b, cx) {
                return Poll::Ready(Either::B(v));
            }
            Poll::Pending
        }
    }

    /// Races three futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Select3<A: Future, B: Future, C: Future> {
        a: A,
        b: B,
        c: C,
    }

    /// Races three futures.
    pub fn select3<A: Future, B: Future, C: Future>(a: A, b: B, c: C) -> Select3<A, B, C> {
        Select3 { a, b, c }
    }

    impl<A: Future + Unpin, B: Future + Unpin, C: Future + Unpin> Future for Select3<A, B, C> {
        type Output = Which3<A::Output, B::Output, C::Output>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            if let Poll::Ready(v) = poll_unpin(&mut this.a, cx) {
                return Poll::Ready(Which3::A(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.b, cx) {
                return Poll::Ready(Which3::B(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.c, cx) {
                return Poll::Ready(Which3::C(v));
            }
            Poll::Pending
        }
    }

    /// Races four futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Select4<A: Future, B: Future, C: Future, D: Future> {
        a: A,
        b: B,
        c: C,
        d: D,
    }

    /// Races four futures.
    pub fn select4<A: Future, B: Future, C: Future, D: Future>(
        a: A,
        b: B,
        c: C,
        d: D,
    ) -> Select4<A, B, C, D> {
        Select4 { a, b, c, d }
    }

    impl<A: Future + Unpin, B: Future + Unpin, C: Future + Unpin, D: Future + Unpin> Future
        for Select4<A, B, C, D>
    {
        type Output = Which4<A::Output, B::Output, C::Output, D::Output>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            if let Poll::Ready(v) = poll_unpin(&mut this.a, cx) {
                return Poll::Ready(Which4::A(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.b, cx) {
                return Poll::Ready(Which4::B(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.c, cx) {
                return Poll::Ready(Which4::C(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.d, cx) {
                return Poll::Ready(Which4::D(v));
            }
            Poll::Pending
        }
    }
}

pub mod time {
    use crate::platform::atomic64::AtomicU64;
    #[cfg_attr(feature = "std", allow(unused_imports))]
    use core::sync::atomic::Ordering;

    /// Minimal instant used for inactivity/expiry accounting.
    ///
    /// - std: wall-clock milliseconds.
    /// - no_std: logical milliseconds from a global counter. The embedder
    ///   advances it via [`advance_ms`].
    #[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
    pub struct Instant {
        ms: u64,
    }

    impl Instant {
        pub fn now() -> Self {
            #[cfg(feature = "std")]
            {
                let ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                Self { ms }
            }
            #[cfg(not(feature = "std"))]
            {
                Self {
                    ms: NOW_MS.load(Ordering::Relaxed),
                }
            }
        }

        /// Duration elapsed since this instant.
        /// std: real wall-clock delta. no_std: zero for the logical clock
        /// until WP3 wires a real timer.
        pub fn elapsed(&self) -> core::time::Duration {
            #[cfg(feature = "std")]
            {
                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_millis() as u64)
                    .unwrap_or(0);
                core::time::Duration::from_millis(now_ms.saturating_sub(self.ms))
            }
            #[cfg(not(feature = "std"))]
            {
                core::time::Duration::ZERO
            }
        }

        /// Duration elapsed since `earlier` (saturating at zero).
        pub fn duration_since(&self, earlier: Self) -> core::time::Duration {
            core::time::Duration::from_millis(self.ms.saturating_sub(earlier.ms))
        }
    }

    #[cfg(not(feature = "std"))]
    static NOW_MS: AtomicU64 = AtomicU64::new(0);

    /// no_std only: advances the logical clock. The platform task calls this
    /// periodically (WP3 wires embassy-time here).
    #[cfg(not(feature = "std"))]
    pub fn advance_ms(ms: u64) {
        NOW_MS.fetch_add(ms.max(1), Ordering::Relaxed);
    }

    /// no_std only: sets the logical clock outright.
    #[cfg(not(feature = "std"))]
    pub fn set_now_ms(ms: u64) {
        NOW_MS.store(ms, Ordering::Relaxed);
    }

    /// no_std placeholder: runs a future without a real timeout. WP3 swaps
    /// in `embassy_time::with_timeout`.
    #[cfg(not(feature = "std"))]
    pub async fn with_timeout<F: core::future::Future>(
        dur: core::time::Duration,
        fut: F,
    ) -> core::result::Result<F::Output, ()> {
        let _ = dur;
        Ok(fut.await)
    }

    /// std: tokio-backed timeout.
    #[cfg(feature = "std")]
    pub async fn with_timeout<F: core::future::Future>(
        dur: core::time::Duration,
        fut: F,
    ) -> core::result::Result<F::Output, tokio::time::error::Elapsed> {
        tokio::time::timeout(dur, fut).await
    }
}

/// Task seams: spawn (std: tokio runtime; no_std: injected spawner via
/// [`task::set_spawn_fn`]) and timers (std: tokio time; no_std WP3:
/// embassy-time).
#[cfg(feature = "std")]
pub mod task {
    use core::future::Future;

    /// Spawns a detached task.
    pub fn spawn<F>(fut: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        tokio::spawn(fut)
    }

    /// Sleeps for `dur`.
    pub async fn sleep(dur: core::time::Duration) {
        tokio::time::sleep(dur).await;
    }

    /// Periodic ticker firing every `period`, first tick after `delay`.
    /// std: tokio `Interval`. no_std (WP3): embassy Ticker-based equivalent.
    pub struct Interval(tokio::time::Interval);

    impl Interval {
        pub async fn tick(&mut self) {
            self.0.tick().await;
        }
    }

    /// Creates a ticker that fires `period` apart, first after `delay`.
    pub fn interval_after(delay: core::time::Duration, period: core::time::Duration) -> Interval {
        Interval(tokio::time::interval_at(
            tokio::time::Instant::now() + delay,
            period,
        ))
    }
}

#[cfg(not(feature = "std"))]
pub mod task {
    use alloc::boxed::Box;
    use core::future::Future;

    /// Injected task spawner (the embedder's embassy executor). Set once at
    /// boot via [`set_spawn_fn`].
    type SpawnFn = fn(Box<dyn Future<Output = ()> + Send>);

    static SPAWN_FN: crate::platform::sync::Mutex<Option<SpawnFn>> =
        crate::platform::sync::Mutex::new(None);

    /// Installs the task spawner. Must be called before any task spawn.
    pub fn set_spawn_fn(f: SpawnFn) {
        *SPAWN_FN.lock() = Some(f);
    }

    /// Spawns a detached task through the injected spawner. Panics if the
    /// embedder never installed one.
    pub fn spawn<F>(fut: F)
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let f = SPAWN_FN
            .lock()
            .expect("platform::task::set_spawn_fn not called");
        f(Box::new(fut));
    }

    /// no_std placeholder sleep: pends forever. WP3 replaces this with
    /// `embassy_time::Timer::after`.
    pub async fn sleep(_dur: core::time::Duration) {
        core::future::pending::<()>().await;
    }

    /// no_std placeholder ticker (WP3: embassy Ticker).
    pub struct Interval;

    impl Interval {
        pub async fn tick(&mut self) {
            core::future::pending::<()>().await;
        }
    }

    pub fn interval_after(_delay: core::time::Duration, _period: core::time::Duration) -> Interval {
        Interval
    }
}

/// Channel seams for the ICE transport. std aliases tokio so existing call
/// sites typecheck unchanged; the no_std backend lives in
/// [`sync_embedded`] (spin-lock based).
#[cfg(feature = "std")]
pub mod sync {
    pub mod watch {
        pub use tokio::sync::watch::{Receiver, Sender, channel, error::RecvError};
    }
    pub mod mpsc {
        pub use tokio::sync::mpsc::error::TrySendError;
        pub use tokio::sync::mpsc::{
            Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
        };
    }
    pub mod oneshot {
        pub use tokio::sync::oneshot::{Receiver, Sender, channel};
    }
    pub mod broadcast {
        pub use tokio::sync::broadcast::{Receiver, Sender, channel, error::RecvError};
    }
    /// Lock primitives. std: parking_lot (non-poisoning, matches the
    /// guard API used across the codebase). no_std (WP3): critical-section
    /// mutex + embassy RwLock.
    pub use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
    pub use std::sync::OnceLock;
    /// Async mutex (held across `.await`). std: tokio. no_std (WP3): embassy.
    pub use tokio::sync::Mutex as AsyncMutex;
}

#[cfg(not(feature = "std"))]
pub mod sync {
    pub use crate::platform::sync_embedded::OnceLock;
    pub use crate::platform::sync_embedded::broadcast;
    pub use crate::platform::sync_embedded::mpsc;
    pub use crate::platform::sync_embedded::oneshot;
    pub use crate::platform::sync_embedded::watch;
    pub use crate::platform::sync_embedded::{AsyncMutex, Mutex, MutexGuard};
    pub use crate::platform::sync_embedded::{RwLock, RwLockReadGuard, RwLockWriteGuard};
}
