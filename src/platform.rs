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

/// Randomness seam. std: OS RNG (`rand`). no_std: the embedder MUST
/// inject a fill function (e.g. the esp-hal hardware RNG) via
/// [`rng::set_fill_fn`] before any key material is generated; until then
/// [`rng::fill`] panics — deliberately never returning zeros, since SDES
/// keys or STUN transaction ids derived from a constant would be a
/// critical vulnerability.
pub mod rng {
    use crate::platform::sync::Mutex;

    type FillFn = fn(&mut [u8]);

    static FILL_FN: Mutex<Option<FillFn>> = Mutex::new(None);

    /// Installs the embedder's CSPRNG (no_std only; std uses the OS RNG).
    /// Must be called before any SRTP/SDES key generation.
    pub fn set_fill_fn(f: FillFn) {
        *FILL_FN.lock() = Some(f);
    }

    /// Fills `buf` with cryptographically secure random bytes.
    pub fn fill(buf: &mut [u8]) {
        #[cfg(feature = "std")]
        {
            use rand::Rng;
            rand::rng().fill_bytes(buf);
        }
        #[cfg(not(feature = "std"))]
        {
            let fill =
                (*FILL_FN.lock()).expect("platform::rng: set_fill_fn not called before fill");
            fill(buf);
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
///
/// Backend-agnostic racing combinators (replace `tokio::select!` at the
/// drive-loop sites). Poll-based and unbiased: all arms polled on every
/// wake; first completion wins. Futures must be `Unpin` (callers pass
/// `core::pin::pin!(..)` bindings for `!Unpin` futures).
pub mod select {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// Turns [`Either`] into a future: polls the live branch. This is the
    /// building block for conditional `select!` arms (`expr, if cond`):
    /// `Either::A(real_future)` / `Either::B(pending())` disables the arm.
    impl<A, B> Future for Either<A, B>
    where
        A: Future + Unpin,
        B: Future<Output = A::Output> + Unpin,
    {
        type Output = A::Output;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            match self.get_mut() {
                Either::A(a) => Pin::new(a).poll(cx),
                Either::B(b) => Pin::new(b).poll(cx),
            }
        }
    }

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

    /// Five-arm race output.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Which5<A, B, C, D, E> {
        A(A),
        B(B),
        C(C),
        D(D),
        E(E),
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

    /// Races five futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Select5<A: Future, B: Future, C: Future, D: Future, E: Future> {
        a: A,
        b: B,
        c: C,
        d: D,
        e: E,
    }

    /// Races five futures.
    pub fn select5<A: Future, B: Future, C: Future, D: Future, E: Future>(
        a: A,
        b: B,
        c: C,
        d: D,
        e: E,
    ) -> Select5<A, B, C, D, E> {
        Select5 { a, b, c, d, e }
    }

    impl<
        A: Future + Unpin,
        B: Future + Unpin,
        C: Future + Unpin,
        D: Future + Unpin,
        E: Future + Unpin,
    > Future for Select5<A, B, C, D, E>
    {
        type Output = Which5<A::Output, B::Output, C::Output, D::Output, E::Output>;
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let this = self.get_mut();
            if let Poll::Ready(v) = poll_unpin(&mut this.a, cx) {
                return Poll::Ready(Which5::A(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.b, cx) {
                return Poll::Ready(Which5::B(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.c, cx) {
                return Poll::Ready(Which5::C(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.d, cx) {
                return Poll::Ready(Which5::D(v));
            }
            if let Poll::Ready(v) = poll_unpin(&mut this.e, cx) {
                return Poll::Ready(Which5::E(v));
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
    #[cfg(not(feature = "std"))]
    use crate::platform::atomic64::AtomicU64;
    #[cfg(not(feature = "std"))]
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

    impl core::ops::Add<core::time::Duration> for Instant {
        type Output = Instant;
        fn add(self, rhs: core::time::Duration) -> Instant {
            Instant {
                ms: self.ms.saturating_add(rhs.as_millis() as u64),
            }
        }
    }

    impl core::ops::Sub<core::time::Duration> for Instant {
        type Output = Instant;
        fn sub(self, rhs: core::time::Duration) -> Instant {
            Instant {
                ms: self.ms.saturating_sub(rhs.as_millis() as u64),
            }
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

    /// Unix epoch milliseconds when a wall clock exists. std: real clock.
    /// no_std: `None` (targets without an RTC battery report no wall time;
    /// callers fall back to monotonic counters or omit wall-clock fields).
    #[cfg(feature = "std")]
    pub fn unix_ms() -> Option<u64> {
        Some(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
                .unwrap_or(0),
        )
    }

    /// no_std counterpart: no wall clock is assumed.
    #[cfg(not(feature = "std"))]
    pub fn unix_ms() -> Option<u64> {
        None
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

    /// Yields the current task once (tokio parity).
    pub async fn yield_now() {
        tokio::task::yield_now().await;
    }

    /// Periodic ticker firing every `period`, first tick after `delay`.
    /// std: tokio `Interval`. no_std (WP3): embassy Ticker-based equivalent.
    pub struct Interval(tokio::time::Interval);

    impl Interval {
        pub async fn tick(&mut self) {
            self.0.tick().await;
        }

        /// Tokio parity passthrough (no_std: ticks never bunch up, so the
        /// behavior setting is a no-op).
        pub fn set_missed_tick_behavior(&mut self, behavior: MissedTickBehavior) {
            self.0.set_missed_tick_behavior(match behavior {
                MissedTickBehavior::Burst => tokio::time::MissedTickBehavior::Burst,
                MissedTickBehavior::Delay => tokio::time::MissedTickBehavior::Delay,
                MissedTickBehavior::Skip => tokio::time::MissedTickBehavior::Skip,
            });
        }
    }

    /// Missed-tick policy (tokio parity enum).
    #[derive(Debug, Clone, Copy)]
    pub enum MissedTickBehavior {
        Burst,
        Delay,
        Skip,
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
    use core::pin::Pin;
    use core::task::{Context, Poll};

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

    /// Yields once: pends a single poll with a self-wake so the executor
    /// can run other tasks before resuming this one (tokio parity).
    pub async fn yield_now() {
        struct YieldNow(bool);
        impl Future for YieldNow {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
                if self.0 {
                    Poll::Ready(())
                } else {
                    self.0 = true;
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }
        }
        YieldNow(false).await;
    }

    /// no_std placeholder ticker (WP3: embassy Ticker).
    pub struct Interval;

    impl Interval {
        pub async fn tick(&mut self) {
            core::future::pending::<()>().await;
        }

        /// no-op on the placeholder ticker (WP3 wires the embassy policy).
        pub fn set_missed_tick_behavior(&mut self, _behavior: MissedTickBehavior) {}
    }

    /// Missed-tick policy (tokio parity enum; placeholder accepts it).
    #[derive(Debug, Clone, Copy)]
    pub enum MissedTickBehavior {
        Burst,
        Delay,
        Skip,
    }

    pub fn interval_after(_delay: core::time::Duration, _period: core::time::Duration) -> Interval {
        Interval
    }
}

/// Backend-agnostic `tokio::join!` replacements (fixed arities): wait for
/// ALL futures, polling each on every wake. Unbiased; futures must be
/// `Unpin` (callers `core::pin::pin!` `!Unpin` futures).
pub mod join {
    use core::future::Future;
    use core::pin::Pin;
    use core::task::{Context, Poll};

    /// Joins two futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Join2<A: Future, B: Future> {
        a: Option<A>,
        b: Option<B>,
        a_out: Option<A::Output>,
        b_out: Option<B::Output>,
    }

    /// Joins two futures.
    pub fn join2<A: Future, B: Future>(a: A, b: B) -> Join2<A, B> {
        Join2 {
            a: Some(a),
            b: Some(b),
            a_out: None,
            b_out: None,
        }
    }

    impl<A: Future + Unpin, B: Future + Unpin> Future for Join2<A, B> {
        type Output = (A::Output, B::Output);
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // SAFETY: no structural pinning — `a`/`b` are polled through
            // `Pin::new` (they are `Unpin`); the buffered outputs are only
            // moved out on completion.
            let this = unsafe { self.get_unchecked_mut() };
            if this.a_out.is_none()
                && let Some(a) = this.a.as_mut()
                && let Poll::Ready(v) = Pin::new(a).poll(cx)
            {
                this.a_out = Some(v);
                this.a = None;
            }
            if this.b_out.is_none()
                && let Some(b) = this.b.as_mut()
                && let Poll::Ready(v) = Pin::new(b).poll(cx)
            {
                this.b_out = Some(v);
                this.b = None;
            }
            match (this.a_out.take(), this.b_out.take()) {
                (Some(a), Some(b)) => Poll::Ready((a, b)),
                (a, b) => {
                    this.a_out = a;
                    this.b_out = b;
                    Poll::Pending
                }
            }
        }
    }

    /// Joins three futures.
    #[must_use = "futures do nothing unless you `.await` or poll them"]
    pub struct Join3<A: Future, B: Future, C: Future> {
        a: Option<A>,
        b: Option<B>,
        c: Option<C>,
        a_out: Option<A::Output>,
        b_out: Option<B::Output>,
        c_out: Option<C::Output>,
    }

    /// Joins three futures.
    pub fn join3<A: Future, B: Future, C: Future>(a: A, b: B, c: C) -> Join3<A, B, C> {
        Join3 {
            a: Some(a),
            b: Some(b),
            c: Some(c),
            a_out: None,
            b_out: None,
            c_out: None,
        }
    }

    impl<A: Future + Unpin, B: Future + Unpin, C: Future + Unpin> Future for Join3<A, B, C> {
        type Output = (A::Output, B::Output, C::Output);
        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            // SAFETY: see [`Join2::poll`].
            let this = unsafe { self.get_unchecked_mut() };
            if this.a_out.is_none()
                && let Some(a) = this.a.as_mut()
                && let Poll::Ready(v) = Pin::new(a).poll(cx)
            {
                this.a_out = Some(v);
                this.a = None;
            }
            if this.b_out.is_none()
                && let Some(b) = this.b.as_mut()
                && let Poll::Ready(v) = Pin::new(b).poll(cx)
            {
                this.b_out = Some(v);
                this.b = None;
            }
            if this.c_out.is_none()
                && let Some(c) = this.c.as_mut()
                && let Poll::Ready(v) = Pin::new(c).poll(cx)
            {
                this.c_out = Some(v);
                this.c = None;
            }
            match (this.a_out.take(), this.b_out.take(), this.c_out.take()) {
                (Some(a), Some(b), Some(c)) => Poll::Ready((a, b, c)),
                (a, b, c) => {
                    this.a_out = a;
                    this.b_out = b;
                    this.c_out = c;
                    Poll::Pending
                }
            }
        }
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
        pub use tokio::sync::mpsc::error::{SendError, TrySendError};
        pub use tokio::sync::mpsc::{
            Receiver, Sender, UnboundedReceiver, UnboundedSender, channel, unbounded_channel,
        };
    }
    pub mod oneshot {
        pub use tokio::sync::oneshot::{Receiver, Sender, channel};
    }
    pub mod broadcast {
        pub use tokio::sync::broadcast::error::TryRecvError;
        pub use tokio::sync::broadcast::{Receiver, Sender, channel, error::RecvError};
    }
    /// Lock primitives. std: parking_lot (non-poisoning, matches the
    /// guard API used across the codebase). no_std (WP3): critical-section
    /// mutex + embassy RwLock.
    pub use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
    pub use std::sync::OnceLock;
    /// Async mutex (held across `.await`). std: tokio. no_std (WP3): embassy.
    pub use tokio::sync::Mutex as AsyncMutex;
    /// Async notification (permit semantics). std: tokio. no_std: see
    /// `sync_embedded::Notify`.
    pub use tokio::sync::Notify;
}

#[cfg(not(feature = "std"))]
pub mod sync {
    pub use crate::platform::sync_embedded::Notify;
    pub use crate::platform::sync_embedded::OnceLock;
    pub use crate::platform::sync_embedded::broadcast;
    pub use crate::platform::sync_embedded::mpsc;
    pub use crate::platform::sync_embedded::oneshot;
    pub use crate::platform::sync_embedded::watch;
    pub use crate::platform::sync_embedded::{AsyncMutex, Mutex, MutexGuard};
    pub use crate::platform::sync_embedded::{RwLock, RwLockReadGuard, RwLockWriteGuard};
}
