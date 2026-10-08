//! Mock embedded runtime for the no_std e2e suites (G1).
//!
//! Everything an embedded integration must provide behind the rustrtc
//! platform seams, in test form:
//! - loopback UDP bind factory (`platform::net::set_udp_bind_fn`)
//! - sleep factory on the crate's logical clock (`task::set_sleep_fn`)
//! - task queue (`task::set_spawn_fn`) driven by a per-task-waker executor
//! - counter RNG (`rng::set_fill_fn`)
//!
//! The driver polls only tasks whose own waker fired — true executor
//! semantics. Nothing here is linked into the library.

#![allow(dead_code)]

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use rustrtc::platform::net::{NetError, UdpSocket, set_udp_bind_fn};
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
            if !timers
                .iter()
                .any(|(_, w)| w.will_wake(cx.waker()) && same_task(w, cx))
            {
                timers.push((self.deadline, cx.waker().clone()));
            }
            std::task::Poll::Pending
        }
    }
}

/// Identity helper: this mock executor has one driver thread, so any waker
/// is "the same task" for de-duplication purposes is too coarse — keep the
/// exact-waker comparison (each task polls with its own task waker).
fn same_task(_a: &std::task::Waker, _cx: &std::task::Context<'_>) -> bool {
    false
}

/// rtcembed's embassy-time factory shape: a non-capturing `fn` handing back
/// a boxed timer (stands in for `embassy_time::Timer::after`).
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

struct TaskWoken(AtomicBool);

impl TaskWoken {
    fn new() -> Arc<Self> {
        Arc::new(Self(AtomicBool::new(true))) // runnable on first poll
    }
    fn wake_by_ref(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    fn take(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

pub struct Task {
    label: &'static str,
    woken: Arc<TaskWoken>,
    /// Created once at spawn: a STABLE waker is required so `Waker::will_wake`
    /// comparisons inside the library (Notify/watch de-duplication) keep
    /// working across polls — fresh waker allocations defeat them.
    waker: std::task::Waker,
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
            unsafe {
                let arc = Arc::from_raw(p as *const TaskWoken);
                let c = arc.clone();
                Arc::into_raw(arc);
                RawWaker::new(Arc::into_raw(c) as *const (), &TASK_WAKER_VTABLE)
            }
        }
        unsafe fn wake_raw(p: *const ()) {
            unsafe {
                let arc = Arc::from_raw(p as *const TaskWoken);
                arc.wake_by_ref();
                Arc::into_raw(arc);
            }
        }
        unsafe fn wake_by_ref_raw(p: *const ()) {
            unsafe {
                let arc = Arc::from_raw(p as *const TaskWoken);
                arc.wake_by_ref();
                Arc::into_raw(arc);
            }
        }
        unsafe fn drop_raw(p: *const ()) {
            unsafe {
                drop(Arc::from_raw(p as *const TaskWoken));
            }
        }
        unsafe {
            Waker::from_raw(RawWaker::new(
                Arc::into_raw(self.0.clone()) as *const (),
                &TASK_WAKER_VTABLE,
            ))
        }
    }
}


// Shared waker vtable for the mock task wakers (all point at TaskWoken).
static TASK_WAKER_VTABLE: std::task::RawWakerVTable = build_task_vtable();

const fn build_task_vtable() -> std::task::RawWakerVTable {
    use std::task::{RawWaker, RawWakerVTable};
    unsafe fn clone_raw(p: *const ()) -> RawWaker {
        unsafe {
            let arc = Arc::from_raw(p as *const TaskWoken);
            let c = arc.clone();
            Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(c) as *const (), &VTABLE)
        }
    }
    unsafe fn wake_raw(p: *const ()) {
        unsafe {
            let arc = Arc::from_raw(p as *const TaskWoken);
            arc.wake_by_ref();
            Arc::into_raw(arc);
        }
    }
    unsafe fn wake_by_ref_raw(p: *const ()) {
        unsafe {
            let arc = Arc::from_raw(p as *const TaskWoken);
            arc.wake_by_ref();
            Arc::into_raw(arc);
        }
    }
    unsafe fn drop_raw(p: *const ()) {
        unsafe {
            drop(Arc::from_raw(p as *const TaskWoken));
        }
    }
    static VTABLE: RawWakerVTable =
        RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw);
    RawWakerVTable::new(clone_raw, wake_raw, wake_by_ref_raw, drop_raw)
}
static TASKS: Mutex<Vec<Task>> = Mutex::new(Vec::new());

/// Parks a spawned future in the queue the driver polls.
pub fn keep_task_labeled(label: &'static str, fut: BoxedTask) {
    let woken = TaskWoken::new();
    let waker = TaskHandle(woken.clone()).waker();
    TASKS.lock().unwrap().push(Task {
        label,
        woken,
        waker,
        fut: Box::into_pin(fut),
    });
}

pub fn keep_task(fut: BoxedTask) {
    keep_task_labeled("task", fut);
}

pub fn task_count() -> usize {
    TASKS.lock().unwrap().len()
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

static EPHEMERAL: AtomicU16 = AtomicU16::new(40_000);

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
        EPHEMERAL.fetch_add(1, Ordering::Relaxed)
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
        if std::env::var("LOOPNET_TRACE").is_ok() {
            eprintln!("[net] {} -> {} len={} first={:?}", self.local, addr, buf.len(), buf.first());
        }
        let mut inboxes = inboxes().lock().unwrap();
        let Some(inbox) = inboxes.get_mut(&addr.port()) else {
            // UDP semantics: no listener → datagram dropped.
            return Ok(buf.len());
        };
        inbox.queue.push_back((self.local, buf.to_vec()));
        for w in inbox.wakers.drain(..) {
            w.wake();
        }
        Ok(buf.len())
    }
}

// ── platform installation ────────────────────────────────────────────────

/// Installs the four platform seams an embedded integration wires at boot.
/// Idempotent.
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

pub fn dbg(msg: &str) {
    eprintln!("[mock] {msg}");
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
                let waker = task.waker.clone();
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
    let local_waker = TaskHandle(Arc::new(TaskWoken(std::sync::atomic::AtomicBool::new(true)))).waker();
    let mut fut = Box::pin(fut);
    let mut cx = std::task::Context::from_waker(&local_waker);
    let deadline = clock() + budget_ms;
    loop {
        // Always poll the driven future.
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        // Keep the rest of the runtime alive while this future waits.
        let tasks: Vec<_> = std::mem::take(&mut *TASKS.lock().unwrap());
        let mut pending = Vec::with_capacity(tasks.len());
        for mut task in tasks {
            if task.woken.take() {
                let waker = task_waker_for(&task.woken);
                let mut tcx = std::task::Context::from_waker(&waker);
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

fn task_waker_for(woken: &Arc<TaskWoken>) -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    let ptr = Arc::into_raw(woken.clone()) as *const ();
    unsafe fn clone_raw(p: *const ()) -> RawWaker {
        unsafe {
            let arc = Arc::from_raw(p as *const AtomicBool);
            let c = arc.clone();
            Arc::into_raw(arc);
            RawWaker::new(Arc::into_raw(c) as *const (), &TASK_WAKER_VTABLE)
        }
    }
    unsafe fn wake_raw(p: *const ()) {
        unsafe {
            let arc = Arc::from_raw(p as *const AtomicBool);
            arc.store(true, Ordering::SeqCst);
            Arc::into_raw(arc);
        }
    }
    unsafe fn wake_by_ref_raw(p: *const ()) {
        unsafe {
            let arc = Arc::from_raw(p as *const AtomicBool);
            arc.store(true, Ordering::SeqCst);
            Arc::into_raw(arc);
        }
    }
    unsafe fn drop_raw(p: *const ()) {
        unsafe {
            drop(Arc::from_raw(p as *const AtomicBool));
        }
    }
    unsafe { Waker::from_raw(RawWaker::new(ptr, &TASK_WAKER_VTABLE)) }
}


/// Spin-poll one future to completion without advancing the clock or
/// polling tasks (for short futures that only need a few polls).
pub fn block_on<F: std::future::Future>(fut: F) -> F::Output {
    let mut fut = Box::pin(fut);
    let waker = std::task::Waker::noop();
    let mut cx = std::task::Context::from_waker(&waker);
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return v;
        }
        std::thread::yield_now();
    }
}
