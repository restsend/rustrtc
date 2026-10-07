#![allow(non_camel_case_types)]
//! no_std backend for [`crate::platform::sync`] (WP3 preview).
//!
//! Mirrors the tokio API surface the ICE transport uses: `watch`,
//! unbounded `mpsc`, `oneshot`, `broadcast`, parking_lot-style sync
//! `Mutex`/`RwLock`, and an async `AsyncMutex`.
//!
//! Concurrency model:
//! - sync `Mutex`/`RwLock` spin on atomics — safe because the crate
//!   convention is "guards never span `.await`", so hold times are bounded
//!   by short critical sections;
//! - channel state lives behind the same spin `Mutex`; waits register a
//!   `Waker` into the state and are woken by the sending side;
//! - `broadcast` keeps a bounded history; receivers that fall further
//!   behind than the history get `Lagged`.

use crate::prelude::*;

use crate::platform::atomic64::AtomicU64;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use core::task::{Context, Poll, Waker};

// ── spin primitives ──────────────────────────────────────────────────────

#[derive(Default)]
struct SpinFlag(AtomicBool);

impl SpinFlag {
    const fn new() -> Self {
        Self(AtomicBool::new(false))
    }
    fn acquire(&self) {
        while self.0.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }
    fn release(&self) {
        self.0.store(false, Ordering::Release);
    }
}

// ── sync Mutex / RwLock (parking_lot-style guard API) ────────────────────

pub struct Mutex<T> {
    locked: SpinFlag,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for Mutex<T> {}
unsafe impl<T: Send> Send for Mutex<T> {}

pub struct MutexGuard<'a, T> {
    mutex: &'a Mutex<T>,
}

impl<T> Drop for MutexGuard<'_, T> {
    fn drop(&mut self) {
        self.mutex.locked.release();
    }
}

impl<T> core::ops::Deref for MutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.mutex.value.get() }
    }
}

impl<T> core::ops::DerefMut for MutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.mutex.value.get() }
    }
}

impl<T: Default> Default for Mutex<T> {
    fn default() -> Self {
        Mutex::new(T::default())
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for Mutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let guard = self.lock();
        f.debug_struct("Mutex").field("value", &*guard).finish()
    }
}

impl<T> Mutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            locked: SpinFlag::new(),
            value: UnsafeCell::new(value),
        }
    }

    /// Blocks until free. Convention: guards never span `.await`.
    pub fn lock(&self) -> MutexGuard<'_, T> {
        self.locked.acquire();
        MutexGuard { mutex: self }
    }

    /// Non-blocking acquisition.
    pub fn try_lock(&self) -> Option<MutexGuard<'_, T>> {
        if self
            .locked
            .0
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Acquire)
            .is_ok()
        {
            Some(MutexGuard { mutex: self })
        } else {
            None
        }
    }
}

pub struct RwLock<T> {
    state: AtomicUsize, // 0 = free, usize::MAX = writer, n>0 = n readers
    value: UnsafeCell<T>,
}

unsafe impl<T: Send + Sync> Sync for RwLock<T> {}
unsafe impl<T: Send> Send for RwLock<T> {}

const WRITER_BIT: usize = usize::MAX;

pub struct RwLockReadGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Drop for RwLockReadGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.fetch_sub(1, Ordering::AcqRel);
    }
}

impl<T> core::ops::Deref for RwLockReadGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}

pub struct RwLockWriteGuard<'a, T> {
    lock: &'a RwLock<T>,
}

impl<T> Drop for RwLockWriteGuard<'_, T> {
    fn drop(&mut self) {
        self.lock.state.store(0, Ordering::Release);
    }
}

impl<T> core::ops::Deref for RwLockWriteGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.lock.value.get() }
    }
}

impl<T> core::ops::DerefMut for RwLockWriteGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.lock.value.get() }
    }
}

impl<T> RwLock<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AtomicUsize::new(0),
            value: UnsafeCell::new(value),
        }
    }

    pub fn read(&self) -> RwLockReadGuard<'_, T> {
        loop {
            let cur = self.state.load(Ordering::Acquire);
            if cur != WRITER_BIT
                && self
                    .state
                    .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return RwLockReadGuard { lock: self };
            }
            core::hint::spin_loop();
        }
    }

    pub fn write(&self) -> RwLockWriteGuard<'_, T> {
        loop {
            let cur = self.state.load(Ordering::Acquire);
            if cur == 0
                && self
                    .state
                    .compare_exchange(0, WRITER_BIT, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                return RwLockWriteGuard { lock: self };
            }
            core::hint::spin_loop();
        }
    }
}

// ── AsyncMutex ───────────────────────────────────────────────────────────

/// Shared state for one async lock: flag + waiters.
struct AsyncLockState {
    locked: AtomicBool,
    waiters: Mutex<Vec<Waker>>,
}

impl AsyncLockState {
    const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
            waiters: Mutex::new(Vec::new()),
        }
    }
    fn wake_all(&self) {
        let drained = core::mem::take(&mut *self.waiters.lock());
        for w in drained {
            w.wake();
        }
    }
}

pub struct AsyncMutex<T> {
    state: AsyncLockState,
    value: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for AsyncMutex<T> {}
unsafe impl<T: Send> Send for AsyncMutex<T> {}

pub struct AsyncMutexGuard<'a, T> {
    state: &'a AsyncLockState,
    value: &'a AsyncMutex<T>,
}

impl<T> Drop for AsyncMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.state.locked.store(false, Ordering::Release);
        self.state.wake_all();
    }
}

impl<T> core::ops::Deref for AsyncMutexGuard<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        unsafe { &*self.value.value.get() }
    }
}

impl<T> core::ops::DerefMut for AsyncMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        unsafe { &mut *self.value.value.get() }
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for AsyncMutex<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("AsyncMutex").finish_non_exhaustive()
    }
}

pub struct AsyncLockFuture<'a, T> {
    mutex: &'a AsyncMutex<T>,
}

impl<'a, T> Future for AsyncLockFuture<'a, T> {
    type Output = AsyncMutexGuard<'a, T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if self
            .mutex
            .state
            .locked
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Poll::Ready(AsyncMutexGuard {
                state: &self.mutex.state,
                value: self.mutex,
            });
        }
        self.mutex.state.waiters.lock().push(cx.waker().clone());
        Poll::Pending
    }
}

impl<T> AsyncMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            state: AsyncLockState::new(),
            value: UnsafeCell::new(value),
        }
    }

    pub fn lock(&self) -> AsyncLockFuture<'_, T> {
        AsyncLockFuture { mutex: self }
    }
}

// ── Notify ───────────────────────────────────────────────────────────────

/// Tokio-style async notification primitive.
///
/// Semantics mirror `tokio::sync::Notify` for the surface the crate uses:
/// - [`notify_one`](Notify::notify_one) wakes one registered waiter, or
///   stores a **permit** (at most one) so the wake is never lost across
///   await points — the permit is consumed by the next `notified()` poll;
/// - [`notify_waiters`](Notify::notify_waiters) wakes every currently
///   registered waiter and stores **no** permit (`notified()` futures that
///   have not been polled yet do not observe it);
/// - [`notified`](Notify::notified) resolves immediately when a permit is
///   pending, otherwise registers the waker and pends.
///
/// WP3 note: the embassy backend can build the same semantics on
/// `embassy_sync::signal` + a permit flag.
pub struct Notify {
    state: Mutex<NotifyState>,
}

struct NotifyState {
    permit: bool,
    /// Registered waiters with their notification flag: `notify_one` marks
    /// ONE entry notified (tokio parity) instead of relying on the waker —
    /// a woken-but-not-yet-repolled future must still observe the
    /// notification on its next poll.
    waiters: Vec<NotifyWaiter>,
}

struct NotifyWaiter {
    waker: Waker,
    notified: bool,
}

impl Notify {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(NotifyState {
                permit: false,
                waiters: Vec::new(),
            }),
        }
    }

    /// Wakes one registered waiter; with no waiter pending, stores a single
    /// permit for the next `notified()`.
    pub fn notify_one(&self) {
        let woken;
        {
            let mut state = self.state.lock();
            if state.waiters.is_empty() {
                state.permit = true;
                return;
            }
            // Mark the first waiter not yet notified (fairness); several
            // entries may already carry the flag after notify_waiters.
            let idx = state
                .waiters
                .iter()
                .position(|w| !w.notified)
                .unwrap_or(0);
            state.waiters[idx].notified = true;
            woken = Some(state.waiters[idx].waker.clone());
        }
        woken.unwrap().wake();
    }

    /// Wakes every currently registered waiter. Stores no permit.
    pub fn notify_waiters(&self) {
        let mut state = self.state.lock();
        for w in state.waiters.iter_mut() {
            w.notified = true;
        }
        let woken: Vec<Waker> = state.waiters.iter().map(|w| w.waker.clone()).collect();
        drop(state);
        for w in woken {
            w.wake();
        }
    }

    /// Future resolving on the next wake (or immediately with a stored
    /// permit). Registration happens on first poll, matching tokio.
    pub fn notified(&self) -> NotifyNotified<'_> {
        NotifyNotified { notify: self }
    }
}

impl Default for Notify {
    fn default() -> Self {
        Self::new()
    }
}

/// Future returned by [`Notify::notified`].
pub struct NotifyNotified<'a> {
    notify: &'a Notify,
}

impl Future for NotifyNotified<'_> {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.notify.state.lock();
        if state.permit {
            state.permit = false;
            drop(state);
            return Poll::Ready(());
        }
        // Re-poll replaces the stored waker (same task, same future) so a
        // long-lived loop does not accumulate stale entries; a different
        // waker means a genuinely distinct waiter and is appended.
        match state
            .waiters
            .iter_mut()
            .find(|w| w.waker.will_wake(cx.waker()))
        {
            Some(slot) => {
                if slot.notified {
                    // This waiter was woken while the task was busy: the
                    // notification is consumed here, not lost.
                    slot.notified = false;
                    drop(state);
                    return Poll::Ready(());
                }
                slot.waker = cx.waker().clone();
            }
            None => state.waiters.push(NotifyWaiter {
                waker: cx.waker().clone(),
                notified: false,
            }),
        }
        drop(state);
        Poll::Pending
    }
}

// ── watch ────────────────────────────────────────────────────────────────

struct WatchState<T> {
    value: T,
    wakers: Vec<Waker>,
    sender_gone: bool,
}

struct WatchInner<T> {
    state: Mutex<WatchState<T>>,
    version: AtomicU64,
    seen: AtomicU64,
}

pub struct watch_Sender<T> {
    inner: Arc<WatchInner<T>>,
    /// Live-sender count: the channel reports `Closed` only when the LAST
    /// clone drops (tokio parity — `watch::Sender` is `Clone` here).
    senders: Arc<AtomicUsize>,
}

impl<T> Clone for watch_Sender<T> {
    fn clone(&self) -> Self {
        self.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
            senders: self.senders.clone(),
        }
    }
}

pub struct watch_Receiver<T> {
    inner: Arc<WatchInner<T>>,
}

impl<T> Clone for watch_Receiver<T> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

/// Guard returned by `Receiver::borrow*` — holds the state spin lock.
pub struct watch_Ref<'a, T> {
    guard: MutexGuard<'a, WatchState<T>>,
}

impl<T> core::ops::Deref for watch_Ref<'_, T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.guard.value
    }
}

pub mod watch {
    use crate::prelude::*;
    use alloc::sync::Arc;

    pub use super::{watch_Receiver as Receiver, watch_Ref as Ref, watch_Sender as Sender};

    /// Error returned when every sender has been dropped.
    #[derive(Debug, PartialEq, Eq)]
    pub enum RecvError {
        Closed,
    }

    pub fn channel<T>(init: T) -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(super::WatchInner {
            state: super::Mutex::new(super::WatchState {
                value: init,
                wakers: Vec::new(),
                sender_gone: false,
            }),
            version: crate::platform::atomic64::AtomicU64::new(0),
            seen: crate::platform::atomic64::AtomicU64::new(0),
        });
        (
            Sender {
                inner: inner.clone(),
                senders: Arc::new(core::sync::atomic::AtomicUsize::new(1)),
            },
            Receiver { inner },
        )
    }
}

impl<T: core::fmt::Debug> core::fmt::Debug for watch_Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("watch::Sender").finish_non_exhaustive()
    }
}

impl<T> watch_Sender<T> {
    /// Stores `value` and wakes all receivers.
    pub fn send(&self, value: T) -> Result<(), T> {
        let mut state = self.inner.state.lock();
        state.value = value;
        self.inner.version.fetch_add(1, Ordering::AcqRel);
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
        Ok(())
    }

    /// New receiver observing the same channel.
    pub fn subscribe(&self) -> watch_Receiver<T> {
        watch_Receiver {
            inner: self.inner.clone(),
        }
    }

    /// Borrows the current value from the sender side.
    pub fn borrow(&self) -> watch_Ref<'_, T> {
        watch_Ref {
            guard: self.inner.state.lock(),
        }
    }

    /// Stores `f(value)` when the mutation reports a change; wakes all
    /// receivers only then (tokio parity).
    pub fn send_if_modified(&self, f: impl FnOnce(&mut T) -> bool) {
        let woken;
        {
            let mut state = self.inner.state.lock();
            if !f(&mut state.value) {
                return;
            }
            self.inner.version.fetch_add(1, Ordering::AcqRel);
            woken = core::mem::take(&mut state.wakers);
        }
        for w in woken {
            w.wake();
        }
    }
}

impl<T> watch_Receiver<T> {
    /// Borrows the current value (holds the state spin lock until dropped).
    pub fn borrow(&self) -> watch_Ref<'_, T> {
        watch_Ref {
            guard: self.inner.state.lock(),
        }
    }

    /// Same as [`borrow`](Self::borrow); also marks the current version as
    /// seen so a subsequent `changed()` waits for the next write.
    pub fn borrow_and_update(&self) -> watch_Ref<'_, T> {
        let r = self.borrow();
        let v = self.inner.version.load(Ordering::Acquire);
        self.inner.seen.store(v, Ordering::Release);
        r
    }

    /// Resolves when the value changes or every sender is dropped.
    pub fn changed(&self) -> watch_Changed<'_, T> {
        watch_Changed { rx: self }
    }

    /// Additional receiver over the same channel.
    pub fn subscribe(&self) -> watch_Receiver<T> {
        self.clone()
    }
}

pub struct watch_Changed<'a, T> {
    rx: &'a watch_Receiver<T>,
}

impl<'a, T> Future for watch_Changed<'a, T> {
    type Output = Result<(), watch::RecvError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let i = &self.rx.inner;
        let mut state = i.state.lock();
        let version = i.version.load(Ordering::Acquire);
        let seen = i.seen.load(Ordering::Acquire);
        if version != seen {
            i.seen.store(version, Ordering::Release);
            drop(state);
            return Poll::Ready(Ok(()));
        }
        if state.sender_gone {
            drop(state);
            return Poll::Ready(Err(watch::RecvError::Closed));
        }
        state.wakers.push(cx.waker().clone());
        drop(state);
        Poll::Pending
    }
}

impl<T> Drop for watch_Sender<T> {
    fn drop(&mut self) {
        // Only the LAST live clone closes the channel.
        if self.senders.fetch_sub(1, Ordering::AcqRel) > 1 {
            return;
        }
        let mut state = self.inner.state.lock();
        state.sender_gone = true;
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
    }
}

// ── oneshot ──────────────────────────────────────────────────────────────

struct OneshotState<T> {
    value: Option<T>,
    wakers: Vec<Waker>,
    sender_gone: bool,
}

pub struct oneshot_Sender<T> {
    inner: Arc<Mutex<OneshotState<T>>>,
}

pub struct oneshot_Receiver<T> {
    inner: Arc<Mutex<OneshotState<T>>>,
}

/// Awaiting the receiver after the sender was dropped without sending.
#[derive(Debug, PartialEq, Eq)]
pub struct oneshot_Canceled;

pub mod oneshot {
    pub use super::{
        oneshot_Canceled as Canceled, oneshot_Receiver as Receiver, oneshot_Sender as Sender,
    };
    use crate::prelude::*;
    use alloc::sync::Arc;

    pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(super::Mutex::new(super::OneshotState {
            value: None,
            wakers: Vec::new(),
            sender_gone: false,
        }));
        (
            Sender {
                inner: inner.clone(),
            },
            Receiver { inner },
        )
    }
}

impl<T> oneshot_Sender<T> {
    /// Delivers `value`; `Err(value)` if the receiver is gone.
    pub fn send(self, value: T) -> Result<(), T> {
        let woken;
        {
            let mut state = self.inner.lock();
            if state.sender_gone {
                return Err(value);
            }
            state.value = Some(value);
            woken = core::mem::take(&mut state.wakers);
        }
        for w in woken {
            w.wake();
        }
        Ok(())
    }
}

impl<T> oneshot_Receiver<T> {
    fn try_take(&self) -> Poll<Result<T, oneshot_Canceled>> {
        let mut state = self.inner.lock();
        if let Some(v) = state.value.take() {
            return Poll::Ready(Ok(v));
        }
        if state.sender_gone {
            return Poll::Ready(Err(oneshot_Canceled));
        }
        Poll::Pending
    }
}

impl<T> Future for oneshot_Receiver<T> {
    type Output = Result<T, oneshot_Canceled>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match self.try_take() {
            Poll::Ready(v) => Poll::Ready(v),
            Poll::Pending => {
                let mut state = self.inner.lock();
                if state.value.is_none() && !state.sender_gone {
                    state.wakers.push(cx.waker().clone());
                }
                drop(state);
                Poll::Pending
            }
        }
    }
}

impl<T> Drop for oneshot_Sender<T> {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        state.sender_gone = true;
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
    }
}

// ── unbounded mpsc ───────────────────────────────────────────────────────

struct MpscState<T> {
    queue: VecDeque<T>,
    wakers: Vec<Waker>,
    sender_gone: bool,
}

pub struct mpsc_UnboundedSender<T> {
    inner: Arc<Mutex<MpscState<T>>>,
    /// Live-sender count: the channel closes when the LAST clone drops.
    senders: Arc<AtomicUsize>,
}

pub struct mpsc_UnboundedReceiver<T> {
    inner: Arc<Mutex<MpscState<T>>>,
}

impl<T> Clone for mpsc_UnboundedSender<T> {
    fn clone(&self) -> Self {
        self.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
            senders: self.senders.clone(),
        }
    }
}

/// Carries the rejected value, matching tokio's `mpsc::SendError<T>`.
pub struct mpsc_SendError<T>(pub T);

pub mod mpsc {
    use crate::prelude::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;

    pub use super::mpsc_bounded::channel;
    pub use super::mpsc_bounded::{Receiver, Sender, TrySendError};
    pub use super::{
        mpsc_SendError as SendError, mpsc_UnboundedReceiver as UnboundedReceiver,
        mpsc_UnboundedSender as UnboundedSender,
    };

    pub fn unbounded_channel<T>() -> (UnboundedSender<T>, UnboundedReceiver<T>) {
        let inner = Arc::new(super::Mutex::new(super::MpscState {
            queue: VecDeque::new(),
            wakers: Vec::new(),
            sender_gone: false,
        }));
        (
            UnboundedSender {
                inner: inner.clone(),
                senders: Arc::new(core::sync::atomic::AtomicUsize::new(1)),
            },
            UnboundedReceiver { inner },
        )
    }
}

impl<T> mpsc_UnboundedSender<T> {
    /// Queues `value`; wakes the receiver. `Err(SendError(value))` if the
    /// receiver is gone.
    pub fn send(&self, value: T) -> Result<(), mpsc_SendError<T>> {
        let woken;
        {
            let mut state = self.inner.lock();
            if state.sender_gone {
                return Err(mpsc_SendError(value));
            }
            state.queue.push_back(value);
            woken = core::mem::take(&mut state.wakers);
        }
        for w in woken {
            w.wake();
        }
        Ok(())
    }
}

impl<T> Drop for mpsc_UnboundedSender<T> {
    fn drop(&mut self) {
        // Only the LAST live clone closes the channel.
        if self.senders.fetch_sub(1, Ordering::AcqRel) > 1 {
            return;
        }
        let mut state = self.inner.lock();
        state.sender_gone = true;
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
    }
}

impl<T> mpsc_UnboundedReceiver<T> {
    /// Async receive: `None` once the channel closes.
    pub fn recv(&mut self) -> MpscRecvFuture<'_, T> {
        MpscRecvFuture { rx: self }
    }

    /// Non-blocking receive: `Ok(None)` = empty (channel still open).
    pub fn try_recv(&mut self) -> Result<Option<T>, mpsc_SendError<T>> {
        let _ = self; // shape parity
        unimplemented!("try_recv is only used by std-side tests")
    }
}

pub struct MpscRecvFuture<'a, T> {
    rx: &'a mut mpsc_UnboundedReceiver<T>,
}

impl<'a, T> Future for MpscRecvFuture<'a, T> {
    type Output = Option<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.rx.inner.lock();
        if let Some(v) = state.queue.pop_front() {
            drop(state);
            return Poll::Ready(Some(v));
        }
        if state.sender_gone {
            drop(state);
            return Poll::Ready(None);
        }
        state.wakers.push(cx.waker().clone());
        drop(state);
        Poll::Pending
    }
}

// ── broadcast ────────────────────────────────────────────────────────────

const BROADCAST_HISTORY: usize = 16;

struct BroadcastState<T> {
    history: VecDeque<(u64, T)>,
    next_seq: u64,
    wakers: Vec<Waker>,
    sender_gone: bool,
}

pub struct broadcast_Sender<T> {
    inner: Arc<Mutex<BroadcastState<T>>>,
    /// Live-sender count: the channel reports `Closed` once the LAST
    /// sender clone drops (tokio parity).
    senders: Arc<AtomicUsize>,
    /// Live receiver count (tokio `receiver_count` parity). Senders share
    /// the counter; only receiver creation/drop changes it.
    receivers: Arc<AtomicUsize>,
}

pub struct broadcast_Receiver<T> {
    inner: Arc<Mutex<BroadcastState<T>>>,
    next_seq: AtomicU64,
    receivers: Arc<AtomicUsize>,
}

impl<T> Clone for broadcast_Receiver<T> {
    fn clone(&self) -> Self {
        self.receivers.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
            next_seq: AtomicU64::new(self.next_seq.load(Ordering::Acquire)),
            receivers: self.receivers.clone(),
        }
    }
}

impl<T> Drop for broadcast_Receiver<T> {
    fn drop(&mut self) {
        self.receivers.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum broadcast_RecvError {
    Closed,
    Lagged(u64),
}

/// Non-blocking receive outcome (tokio `broadcast::error::TryRecvError`
/// parity).
#[derive(Debug, PartialEq, Eq)]
pub enum broadcast_TryRecvError {
    Empty,
    Lagged(u64),
    Closed,
}

#[derive(Debug, PartialEq, Eq)]
pub struct broadcast_SendError;

pub mod broadcast {
    use crate::platform::atomic64::AtomicU64;
    use crate::prelude::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;
    use core::sync::atomic::AtomicUsize;

    pub use super::{
        broadcast_Receiver as Receiver, broadcast_RecvError as RecvError,
        broadcast_SendError as SendError, broadcast_Sender as Sender,
        broadcast_TryRecvError as TryRecvError,
    };

    /// `capacity` is accepted for API parity; history is fixed at
    /// [`BROADCAST_HISTORY`].
    pub fn channel<T>(_: usize) -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(super::Mutex::new(super::BroadcastState {
            history: VecDeque::new(),
            next_seq: 0,
            wakers: Vec::new(),
            sender_gone: false,
        }));
        let senders = Arc::new(AtomicUsize::new(1));
        let receivers = Arc::new(AtomicUsize::new(1));
        (
            Sender {
                inner: inner.clone(),
                senders: senders.clone(),
                receivers: receivers.clone(),
            },
            Receiver {
                inner,
                next_seq: AtomicU64::new(0),
                receivers,
            },
        )
    }
}

impl<T> Clone for broadcast_Sender<T> {
    fn clone(&self) -> Self {
        self.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
            senders: self.senders.clone(),
            receivers: self.receivers.clone(),
        }
    }
}

impl<T: Clone> broadcast_Sender<T> {
    /// Delivers to every live receiver; history keeps the newest
    /// [`BROADCAST_HISTORY`] entries.
    pub fn send(&self, value: T) -> Result<usize, broadcast_SendError> {
        let woken;
        {
            let mut state = self.inner.lock();
            if state.sender_gone {
                return Err(broadcast_SendError);
            }
            let seq = state.next_seq;
            state.next_seq += 1;
            state.history.push_back((seq, value));
            while state.history.len() > BROADCAST_HISTORY {
                state.history.pop_front();
            }
            woken = core::mem::take(&mut state.wakers);
        }
        for w in woken {
            w.wake();
        }
        Ok(1)
    }

    /// New receiver (sees only values sent after this point).
    pub fn subscribe(&self) -> broadcast_Receiver<T> {
        let next = self.inner.lock().next_seq;
        self.receivers.fetch_add(1, Ordering::AcqRel);
        broadcast_Receiver {
            inner: self.inner.clone(),
            next_seq: AtomicU64::new(next),
            receivers: self.receivers.clone(),
        }
    }

    /// Number of live receivers (tokio parity).
    pub fn receiver_count(&self) -> usize {
        self.receivers.load(Ordering::Acquire)
    }
}

impl<T: Clone> broadcast_Receiver<T> {
    /// Async receive of the next undelivered value.
    pub fn recv(&mut self) -> BroadcastRecvFuture<'_, T> {
        BroadcastRecvFuture { rx: self }
    }

    /// Non-blocking receive (tokio parity): the next undelivered value,
    /// `Empty` when nothing new, `Lagged` (with the skipped count) when the
    /// receiver fell behind the history, `Closed` once the sender is gone
    /// and the history is drained. Advances `next_seq` on `Ok`/`Lagged`,
    /// matching tokio.
    pub fn try_recv(&self) -> Result<T, broadcast_TryRecvError> {
        let mut state = self.inner.lock();
        let want = self.next_seq.load(Ordering::Acquire);
        if let Some(&(oldest, _)) = state.history.front()
            && want < oldest
        {
            self.next_seq.store(oldest, Ordering::Release);
            return Err(broadcast_TryRecvError::Lagged(oldest - want));
        }
        if let Some(pos) = state.history.iter().position(|(s, _)| *s == want) {
            let v = state.history[pos].1.clone();
            self.next_seq.store(want + 1, Ordering::Release);
            return Ok(v);
        }
        if state.sender_gone {
            return Err(broadcast_TryRecvError::Closed);
        }
        Err(broadcast_TryRecvError::Empty)
    }
}

pub struct BroadcastRecvFuture<'a, T> {
    rx: &'a mut broadcast_Receiver<T>,
}

impl<'a, T: Clone> Future for BroadcastRecvFuture<'a, T> {
    type Output = Result<T, broadcast_RecvError>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.rx.inner.lock();
        let want = self.rx.next_seq.load(Ordering::Acquire);
        if let Some(&(oldest, _)) = state.history.front() {
            if want < oldest {
                self.rx.next_seq.store(oldest, Ordering::Release);
                let lag = oldest - want;
                drop(state);
                return Poll::Ready(Err(broadcast_RecvError::Lagged(lag)));
            }
        }
        if let Some(pos) = state.history.iter().position(|(s, _)| *s == want) {
            let v = state.history[pos].1.clone();
            self.rx.next_seq.store(want + 1, Ordering::Release);
            drop(state);
            return Poll::Ready(Ok(v));
        }
        if state.sender_gone {
            drop(state);
            return Poll::Ready(Err(broadcast_RecvError::Closed));
        }
        state.wakers.push(cx.waker().clone());
        drop(state);
        Poll::Pending
    }
}

impl<T> Drop for broadcast_Sender<T> {
    fn drop(&mut self) {
        // Only the LAST live clone closes the channel.
        if self.senders.fetch_sub(1, Ordering::AcqRel) > 1 {
            return;
        }
        let mut state = self.inner.lock();
        state.sender_gone = true;
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
    }
}

// ── OnceLock ─────────────────────────────────────────────────────────────

/// Single-initialisation cell (spin-based `std::sync::OnceLock` analogue).
pub struct OnceLock<T> {
    state: Mutex<OnceState<T>>,
}

struct OnceState<T> {
    value: Option<T>,
}

impl<T> OnceLock<T> {
    pub const fn new() -> Self {
        Self {
            state: Mutex::new(OnceState { value: None }),
        }
    }

    pub fn get(&self) -> Option<&T> {
        let guard = self.state.lock();
        // SAFETY: once `Some`, the value is never mutated or moved (OnceLock
        // semantics), so the reference outlives the dropped guard and
        // borrows `self`.
        unsafe { core::mem::transmute::<Option<&T>, Option<&T>>(guard.value.as_ref()) }
    }

    /// Initialises with `f` if empty; returns the stored value.
    pub fn get_or_init(&self, f: impl FnOnce() -> T) -> &T {
        if let Some(v) = self.get() {
            // SAFETY: see `get` — initialised cells never change.
            return unsafe { core::mem::transmute::<&T, &T>(v) };
        }
        let value = f();
        {
            let mut state = self.state.lock();
            if state.value.is_none() {
                state.value = Some(value);
            }
            // SAFETY: see `get`.
            unsafe { core::mem::transmute::<Option<&T>, Option<&T>>(state.value.as_ref()) }.unwrap()
        }
    }
}

impl<T> Default for OnceLock<T> {
    fn default() -> Self {
        Self::new()
    }
}

// ── bounded mpsc ─────────────────────────────────────────────────────────

struct BoundedState<T> {
    queue: VecDeque<T>,
    capacity: usize,
    wakers: Vec<Waker>,
    receiver_gone: bool,
    /// Set when the LAST sender clone drops: `recv` then returns `None`.
    sender_gone: bool,
}

pub struct mpsc_BoundedSender<T> {
    inner: Arc<Mutex<BoundedState<T>>>,
    /// Live-sender count: the channel closes when the LAST clone drops.
    senders: Arc<AtomicUsize>,
}

impl<T> Clone for mpsc_BoundedSender<T> {
    fn clone(&self) -> Self {
        self.senders.fetch_add(1, Ordering::AcqRel);
        Self {
            inner: self.inner.clone(),
            senders: self.senders.clone(),
        }
    }
}

pub struct mpsc_BoundedReceiver<T> {
    inner: Arc<Mutex<BoundedState<T>>>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum mpsc_TrySendError<T> {
    Full(T),
    Closed(T),
}

pub mod mpsc_bounded {
    use crate::prelude::*;
    use alloc::collections::VecDeque;
    use alloc::sync::Arc;

    pub use super::{
        mpsc_BoundedReceiver as Receiver, mpsc_BoundedSender as Sender,
        mpsc_TrySendError as TrySendError,
    };

    pub fn channel<T>(capacity: usize) -> (Sender<T>, Receiver<T>) {
        let inner = Arc::new(super::Mutex::new(super::BoundedState {
            queue: VecDeque::new(),
            capacity,
            wakers: Vec::new(),
            receiver_gone: false,
            sender_gone: false,
        }));
        (
            Sender {
                inner: inner.clone(),
                senders: Arc::new(core::sync::atomic::AtomicUsize::new(1)),
            },
            Receiver { inner },
        )
    }
}

impl<T> mpsc_BoundedSender<T> {
    /// Non-blocking enqueue: `Full` when the ring is at capacity (the mux
    /// path drops instead of blocking the packet loop).
    pub fn try_send(&self, value: T) -> Result<(), mpsc_TrySendError<T>> {
        let woken;
        {
            let mut state = self.inner.lock();
            if state.receiver_gone {
                return Err(mpsc_TrySendError::Closed(value));
            }
            if state.queue.len() >= state.capacity {
                return Err(mpsc_TrySendError::Full(value));
            }
            state.queue.push_back(value);
            woken = core::mem::take(&mut state.wakers);
        }
        for w in woken {
            w.wake();
        }
        Ok(())
    }

    /// `true` once the receiver half has been dropped.
    pub fn is_closed(&self) -> bool {
        self.inner.lock().receiver_gone
    }

    /// `true` when both handles point at the same channel.
    pub fn same_channel(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Async send: waits for room. Fails with `SendError` once the
    /// receiver is gone (tokio `Sender::send` parity).
    pub fn send(&self, value: T) -> BoundedSendFuture<'_, T> {
        BoundedSendFuture {
            sender: self,
            value: Some(value),
        }
    }
}

pub struct BoundedSendFuture<'a, T> {
    sender: &'a mpsc_BoundedSender<T>,
    value: Option<T>,
}

impl<'a, T> Future for BoundedSendFuture<'a, T> {
    type Output = Result<(), mpsc_SendError<T>>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Projection is safe: no structural pinning (value moved out via
        // Option::take, sender reference is fixed).
        let this = unsafe { self.get_unchecked_mut() };
        let mut state = this.sender.inner.lock();
        if state.receiver_gone {
            let v = this.value.take().unwrap();
            return Poll::Ready(Err(mpsc_SendError(v)));
        }
        if state.queue.len() >= state.capacity {
            state.wakers.push(cx.waker().clone());
            drop(state);
            return Poll::Pending;
        }
        let v = this.value.take().unwrap();
        state.queue.push_back(v);
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
        Poll::Ready(Ok(()))
    }
}

impl<T> Drop for mpsc_BoundedReceiver<T> {
    fn drop(&mut self) {
        let mut state = self.inner.lock();
        state.receiver_gone = true;
        let woken = core::mem::take(&mut state.wakers);
        drop(state);
        for w in woken {
            w.wake();
        }
    }
}

impl<T> mpsc_BoundedReceiver<T> {
    /// Async receive: `None` once the sender side is gone and drained.
    pub fn recv(&mut self) -> BoundedRecvFuture<'_, T> {
        BoundedRecvFuture { rx: self }
    }
}

pub struct BoundedRecvFuture<'a, T> {
    rx: &'a mut mpsc_BoundedReceiver<T>,
}

impl<'a, T> Future for BoundedRecvFuture<'a, T> {
    type Output = Option<T>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let mut state = self.rx.inner.lock();
        if let Some(v) = state.queue.pop_front() {
            // a sender may be waiting for room
            let woken = core::mem::take(&mut state.wakers);
            drop(state);
            for w in woken {
                w.wake();
            }
            return Poll::Ready(Some(v));
        }
        if state.sender_gone {
            drop(state);
            return Poll::Ready(None);
        }
        state.wakers.push(cx.waker().clone());
        drop(state);
        Poll::Pending
    }
}

impl<T> core::fmt::Debug for oneshot_Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("oneshot_Sender").finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for broadcast_Sender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("broadcast_Sender").finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for mpsc_UnboundedSender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("mpsc_UnboundedSender")
            .finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for mpsc_BoundedSender<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("mpsc_BoundedSender").finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for watch_Receiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("watch_Receiver").finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for broadcast_Receiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("broadcast_Receiver").finish_non_exhaustive()
    }
}

impl<T> core::fmt::Debug for oneshot_Receiver<T> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("oneshot_Receiver").finish_non_exhaustive()
    }
}
