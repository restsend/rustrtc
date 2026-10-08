//! Shared mock runtime for the no_std e2e suites (G1).
//!
//! Everything an embedded integration (rtcembed) must provide behind the
//! rustrtc platform seams, in test form:
//! - [`LoopNet`] — UDP bind factory over per-port inboxes with waker-aware
//!   recv (the embassy-net demux shape)
//! - [`install_mock_platform`] — sleep factory on the crate's logical clock
//!   (test-side timer wheel), task queue, counter RNG
//! - [`drive_until`] — the executor: polls every registered task after each
//!   clock step until `pred` holds or the simulated budget runs out
//!
//! Nothing here is linked into the library; rustrtc itself stays
//! backend-free (zero embassy/std content under `--no-default-features`).

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustrtc::platform::net::{NetError, UdpSocket};
use rustrtc::platform::task::BoxedTask;
use rustrtc::platform::time::advance_ms;

// ── logical clock ────────────────────────────────────────────────────────

/// Reads the crate's logical clock through public API (`elapsed` from a
/// boot anchor). The driver advances it with `advance_ms`, so scheduling
/// and the library share one clock.
pub fn clock() -> u64 {
    static ANCHOR: OnceLock<rustrtc::platform::time::Instant> = OnceLock::new();
    ANCHOR
        .get_or_init(rustrtc::platform::time::Instant::now)
        .elapsed()
        .as_millis() as u64
}

// ── sleep factory (test-side timer wheel) ────────────────────────────────

static TIMERS: Mutex<Vec<(u64, std::task::Waker)>> = Mutex::new(Vec::new());

struct Sleep {
    deadline: u64,
}

impl std::future::Future for Sleep {
    type Output = ();
    fn poll(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<()> {
        if clock() >= self.deadline {
            std::task::Poll::Ready(())
        } else {
            let mut timers = TIMERS.lock().unwrap();
            if !timers.iter().any(|(_, w)| w.will_wake(cx.waker())) {
                timers.push((self.deadline, cx.waker().clone()));
            }
            std::task::Poll::Pending
        }
    }
}

/// rtcembed's embassy-time factory shape: a non-capturing `fn` handing
/// back a boxed timer (stands in for `embassy_time::Timer::after`).
pub fn sleep_factory(
    dur: Duration,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(Sleep {
        deadline: clock() + dur.as_millis() as u64,
    })
}

fn wake_due_timers() {
    let now = clock();
    let due: Vec<_> = {
        let mut timers = TIMERS.lock().unwrap();
        let mut due = Vec::new();
        let mut i = 0;
        while i < timers.len() {
            if timers[i].0 <= now {
                due.push(timers.swap_remove(i));
            } else {
                i += 1;
            }
        }
        due
    };
    for (_, w) in due {
        w.wake();
    }
}

// ── task queue (per-task real wakers — true executor semantics) ─────────

struct TaskWoken(std::sync::atomic::AtomicBool);

impl TaskWoken {
    fn new() -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicBool::new(true)))
    }
    fn wake_by_ref(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
    fn take(&self) -> bool {
        self.0.swap(false, std::sync::atomic::Ordering::SeqCst)
    }
}

pub struct Task {
    label: &'static str,
    woken: Arc<TaskWoken>,
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

/// A waker bound to one task: waking marks that task runnable (the driver
/// re-polls exactly the runnable set — same contract as a real executor).
#[derive(Clone)]
struct TaskHandle(Arc<TaskWoken>);

impl TaskHandle {
    fn waker(&self) -> std::task::Waker {
        use std::task::{RawWaker, RawWakerVTable, Waker};
        unsafe fn clone_raw(p: *const ()) -> RawWaker {
            let arc = Arc::from_raw(p as *const TaskWoken);
            let c = arc.clone();
            Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(c) as *const (), &VTABLE)
        }
        unsafe fn wake_raw(p: *const ()) {
            let arc = Arc::from_raw(p as *const TaskWoken);
            arc.wake_by_ref();
            Arc::into_raw(arc);
        }
        unsafe fn wake_by_ref_raw(p: *const ()) {
            let arc = Arc::from_raw(p as *const TaskWoken);
            arc.wake_by_ref();
            Arc::into_raw(arc);
        }
        unsafe fn drop_raw(p: *const ()) {
            drop(Arc::from_raw(p as *const TaskWoken));
        }
        static VTABLE: RawWakerVTable =
            RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);
        unsafe {
            Waker::from_raw(RawWaker::new(
                Arc::into_raw(self.0.clone()) as *const (),
                &VTABLE,
            ))
        }
    }
}

static TASKS: Mutex<Vec<Task>> = Mutex::new(Vec::new());

/// Parks a spawned future in the queue the driver polls.
pub fn keep_task_labeled(label: &'static str, fut: BoxedTask) {
    let woken = TaskWoken::new();
    let handle = TaskHandle(woken.clone());
    let _waker = handle.waker();
    TASKS.lock().unwrap().push(Task {
        label,
        woken,
        fut: Box::into_pin(fut),
    });
}

pub fn keep_task(fut: BoxedTask) {
    keep_task_labeled("task", fut);
}

pub fn task_count() -> usize {
    TASKS.lock().unwrap().len()
}

// ── platform installation ────────────────────────────────────────────────

/// Installs the four platform seams rtcembed wires at boot. Idempotent.
pub fn install_mock_platform() {
    fn counter_fill(buf: &mut [u8]) {
        static COUNTER: std::sync::atomic::AtomicU32 = std::sync::atomic::AtomicU32::new(7);
        for slot in buf.iter_mut() {
            *slot = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u8;
        }
    }
    rustrtc::platform::rng::set_fill_fn(counter_fill);
    rustrtc::platform::task::set_sleep_fn(sleep_factory);
    rustrtc::platform::task::set_spawn_fn(keep_task);
    rustrtc::platform::net::set_udp_bind_fn(bind_loop);
}

/// Test-side debug print (works under the no_std lib's tracing-less build).
pub fn dbg(msg: &str) {
    eprintln!("[mock] {msg}");
}

// ── loopback network ─────────────────────────────────────────────────────

struct Inbox {
    queue: VecDeque<(SocketAddr, Vec<u8>)>,
    wakers: Vec<std::task::Waker>,
}

fn inboxes() -> &'static Mutex<HashMap<u16, Inbox>> {
    static INBOXES: OnceLock<Mutex<HashMap<u16, Inbox>>> = OnceLock::new();
    INBOXES.get_or_init(|| Mutex::new(HashMap::new()))
}

static EPHEMERAL: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40_000);

pub struct LoopSocket {
    local: SocketAddr,
}

impl LoopSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// UDP bind factory (the `set_udp_bind_fn` implementation shape).
pub fn bind_loop(addr: SocketAddr) -> Result<Arc<dyn UdpSocket>, rustrtc::errors::RtcError> {
    let port = if addr.port() == 0 {
        EPHEMERAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    } else {
        addr.port()
    };
    let mut inboxes = inboxes().lock().unwrap();
    if inboxes.contains_key(&port) {
        return Err(rustrtc::errors::RtcError::AddrInUse);
    }
    inboxes.insert(
        port,
        Inbox {
            queue: VecDeque::new(),
            wakers: Vec::new(),
        },
    );
    Ok(Arc::new(LoopSocket {
        local: SocketAddr::new(addr.ip(), port),
    }) as Arc<dyn UdpSocket>)
}

#[async_trait::async_trait]
impl UdpSocket for LoopSocket {
    async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr), NetError> {
        std::future::poll_fn(|cx| {
            let mut inboxes = inboxes().lock().unwrap();
            let Some(inbox) = inboxes.get_mut(&self.local.port()) else {
                return std::task::Poll::Ready(Err(NetError::Closed));
            };
            if let Some((from, data)) = inbox.queue.pop_front() {
                let len = data.len().min(buf.len());
                buf[..len].copy_from_slice(&data[..len]);
                return std::task::Poll::Ready(Ok((len, from)));
            }
            if !inbox.wakers.iter().any(|w| w.will_wake(cx.waker())) {
                inbox.wakers.push(cx.waker().clone());
            }
            std::task::Poll::Pending
        })
        .await
    }

    async fn send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
        self.try_send_to(buf, addr)
    }

    fn local_addr(&self) -> Result<SocketAddr, NetError> {
        Ok(self.local)
    }

    fn try_send_to(&self, buf: &[u8], addr: SocketAddr) -> Result<usize, NetError> {
        let mut inboxes = inboxes().lock().unwrap();
        let Some(inbox) = inboxes.get_mut(&addr.port()) else {
            return Ok(buf.len());
        };
        inbox.queue.push_back((self.local, buf.to_vec()));
        for w in inbox.wakers.drain(..) {
            w.wake();
        }
        Ok(buf.len())
    }
}

// ── driver (per-task-waker executor: only woken tasks are polled) ───────

/// Polls runnable tasks after each clock step until `pred` holds or the
/// simulated budget runs out. Only tasks whose own waker fired are polled —
/// true executor semantics.
pub fn drive_until_raw(mut pred: impl FnMut() -> bool, budget_ms: u64) -> bool {
    let deadline = clock() + budget_ms;
    loop {
        let tasks: Vec<_> = std::mem::take(&mut *TASKS.lock().unwrap());
        let mut pending = Vec::with_capacity(tasks.len());
        for mut task in tasks {
            if task.woken.take() {
                let handle = TaskHandle(task.woken.clone());
                let waker = handle.waker();
                let mut cx = std::task::Context::from_waker(&waker);
                if task.fut.as_mut().poll(&mut cx).is_pending() {
                    // Re-arm: the task stays parked until its own waker
                    // fires again.
                    task.woken.0.store(true, Ordering::SeqCst);
                    pending.push(task);
                }
            } else {
                pending.push(task);
            }
        }
        TASKS.lock().unwrap().extend(pending);

        if pred() {
            return true;
        }
        if clock() >= deadline {
            return pred();
        }
        let now = clock();
        let next_due = TIMERS.lock().unwrap().iter().map(|(d, _)| *d).min();
        let step = next_due
            .filter(|d| *d > now)
            .map(|d| d - now)
            .unwrap_or(10)
            .min(50);
        advance_ms(step.max(1));
        wake_due_timers();
    }
}

pub fn drive_until(pred: impl Fn() -> bool, budget_ms: u64) -> bool {
    drive_until_raw(pred, budget_ms)
}

/// Drives one (borrowed-ok) future to completion against the shared
/// runtime: polls the local future and every runnable task each round,
/// advancing the logical clock between rounds.
pub fn drive<F: std::future::Future>(fut: F, budget_ms: u64) -> Option<F::Output> {
    let local_woken = Arc::new(TaskWoken(std::sync::atomic::AtomicBool::new(true)));
    let local_waker = TaskHandle(local_woken.clone()).waker();
    let mut fut = Box::pin(fut);
    let mut cx = std::task::Context::from_waker(&local_waker);
    let deadline = clock() + budget_ms;
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        // Keep the rest of the runtime alive while this future waits.
        let tasks: Vec<_> = std::mem::take(&mut *TASKS.lock().unwrap());
        let mut pending = Vec::with_capacity(tasks.len());
        for mut task in tasks {
            if task.woken.take() {
                let handle = TaskHandle(task.woken.clone());
                let w = handle.waker();
                let mut tcx = std::task::Context::from_waker(&w);
                if task.fut.as_mut().poll(&mut tcx).is_pending() {
                    task.woken.wake_by_ref();
                    pending.push(task);
                }
            } else {
                pending.push(task);
            }
        }
        TASKS.lock().unwrap().extend(pending);

        if clock() >= deadline {
            return None;
        }
        let now = clock();
        let next_due = TIMERS.lock().unwrap().iter().map(|(d, _)| *d).min();
        let step = next_due
            .filter(|d| *d > now)
            .map(|d| d - now)
            .unwrap_or(10)
            .min(50);
        advance_ms(step.max(1));
        wake_due_timers();
    }
}


pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}

pub fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn clone_raw(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop_raw(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_raw, noop_raw, noop_raw, noop_raw);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}
