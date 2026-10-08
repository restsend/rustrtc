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

// ── task queue ───────────────────────────────────────────────────────────

static TASKS: Mutex<Vec<Task>> = Mutex::new(Vec::new());

struct Task {
    label: &'static str,
    fut: std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>,
}

/// rtcembed's `keep`-style spawner target: parks spawned futures in the
/// queue the driver polls.
pub fn keep_task_labeled(label: &'static str, fut: BoxedTask) {
    TASKS.lock().unwrap().push(Task {
        label,
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

static EPHEMERAL: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(40_000);

pub struct LoopSocket {
    local: SocketAddr,
}

impl LoopSocket {
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }
}

/// UDP bind factory ( rtcembed's `set_udp_bind_fn` implementation shape).
pub fn bind_loop(addr: SocketAddr) -> Result<Arc<dyn UdpSocket>, rustrtc::errors::RtcError> {
    let port = if addr.port() == 0 {
        EPHEMERAL.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    } else {
        addr.port()
    };
    let mut inboxes = inboxes().lock().unwrap();
    if inboxes.contains_key(&port) {
        // Matches io::ErrorKind::AddrInUse on std: bind_one retries the
        // next port in the configured range.
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
            eprintln!(
                "[net] {} -> {} len={} first={:?}",
                self.local,
                addr,
                buf.len(),
                buf.first().copied()
            );
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

// ── driver ───────────────────────────────────────────────────────────────

/// Polls every registered task after each clock step until `pred` holds or
/// the simulated budget (ms of logical time) runs out. Returns the final
/// predicate value.
pub fn drive_until_raw(pred: impl FnMut() -> bool, budget_ms: u64) -> bool {
    drive_until_raw_inner(pred, budget_ms)
}

pub fn drive_until(pred: impl Fn() -> bool, budget_ms: u64) -> bool {
    drive_until_raw_inner(pred, budget_ms)
}

fn drive_until_raw_inner(mut pred: impl FnMut() -> bool, budget_ms: u64) -> bool {
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let deadline = clock() + budget_ms;
    let mut round = 0u32;
    loop {
        round += 1;
        let trace = std::env::var("TASK_TRACE").is_ok() && round <= 8;
        let tasks: Vec<_> = std::mem::take(&mut *TASKS.lock().unwrap());
        let mut pending = Vec::with_capacity(tasks.len());
        let mut addrs = Vec::new();
        for mut task in tasks {
            let label = task.label;
            let completed = task.fut.as_mut().poll(&mut cx).is_ready();
            if trace {
                if completed {
                    eprintln!("[task-trace r{round}] {label} COMPLETED");
                } else {
                    addrs.push(label);
                }
            }
            if !completed {
                pending.push(task);
            }
        }
        let alive = pending.len();
        TASKS.lock().unwrap().extend(pending);
        if trace {
            eprintln!("[task-trace r{round}] alive={alive}");
            for a in &addrs {
                eprintln!("[task-trace r{round}]   alive {a}");
            }
        }

        if pred() {
            return true;
        }
        if clock() >= deadline {
            return pred();
        }
        // Step the clock to the next interesting moment (timer due, else a
        // fixed 10ms tick) and wake whoever is waiting on it.
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

/// Drives one (borrowed-ok) future to completion against the shared
/// runtime: polls the future AND the registered tasks each round, advancing
/// the logical clock between rounds. Returns `None` if it never completes
/// within the budget.
pub fn drive<F: std::future::Future>(fut: F, budget_ms: u64) -> Option<F::Output> {
    let mut fut = Box::pin(fut);
    let waker = noop_waker();
    let mut cx = std::task::Context::from_waker(&waker);
    let deadline = clock() + budget_ms;
    loop {
        if let std::task::Poll::Ready(v) = fut.as_mut().poll(&mut cx) {
            return Some(v);
        }
        // Keep the rest of the runtime alive while this future waits.
        let tasks: Vec<_> = std::mem::take(&mut *TASKS.lock().unwrap());
        let mut pending = Vec::with_capacity(tasks.len());
        for mut task in tasks {
            if task.fut.as_mut().poll(&mut cx).is_pending() {
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

/// Spin-poll one future to completion without advancing the clock or
/// polling tasks (for short futures that only need a few polls).
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
