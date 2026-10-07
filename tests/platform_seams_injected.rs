#![cfg(not(feature = "std"))]

//! G1: platform seams under the no_std build — injected backends, using the
//! exact call shapes rtcembed's adapters use:
//! - `task::set_spawn_fn(keep)` with rtcembed's leaked-task `keep` fn
//! - `task::set_sleep_fn(|dur| Box::pin(...))` with rtcembed's
//!   embassy-time factory shape (non-capturing closure → fn pointer)
//! - `task::set_spawner(&'static dyn Fn)` for executor adapters that
//!   capture their handle in a static
//! - `rng::set_fill_fn` before any key material (panic-if-unset contract)
//! - `task::interval_after` / `time::with_timeout` driven by the injected
//!   sleep

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use rustrtc::platform::task::{
    BoxedTask, interval_after, set_sleep_fn, set_spawn_fn, set_spawner, sleep, spawn,
};

/// rtcembed's `keep` (bin/ua.rs): spawned tasks are stored, never polled.
fn keep(fut: BoxedTask) {
    std::mem::forget(fut);
}

#[test]
fn spawn_via_set_spawn_fn_stores_tasks() {
    set_spawn_fn(keep);
    spawn(async {
        // never polled — just must not panic
    });
}

#[test]
fn spawn_via_set_spawner_dyn_counts_tasks() {
    static COUNT: AtomicU32 = AtomicU32::new(0);
    // Closure capturing only a static → &'static coercion works, which is
    // what an embassy-executor adapter needs.
    set_spawner(&|fut: BoxedTask| {
        COUNT.fetch_add(1, Ordering::SeqCst);
        std::mem::forget(fut);
    });
    spawn(async {});
    spawn(async {});
    assert!(COUNT.load(Ordering::SeqCst) >= 2);
}

/// rtcembed's embassy-time factory (src/platform/embassy_time.rs): a
/// non-capturing closure handing back a boxed embassy timer. Here it also
/// records the requested duration so the test can assert on it.
fn embassy_style_sleep(
    dur: Duration,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    LAST_SLEEP_MS.with(|c| c.set(dur.as_millis() as u32));
    Box::pin(std::future::ready(()))
}

thread_local! {
    static LAST_SLEEP_MS: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

#[test]
fn injected_sleep_backend_contract() {
    // One test because set_sleep_fn mutates process-global state; sibling
    // tests run in parallel in the same binary.
    set_sleep_fn(embassy_style_sleep);

    block_on(async {
        sleep(Duration::from_millis(250)).await; // must not hang
    });
    assert_eq!(LAST_SLEEP_MS.with(|c| c.get()), 250, "factory saw the duration");

    // Interval is driven by the injected sleep (ticks complete instantly).
    block_on(async {
        let mut tick = interval_after(Duration::from_millis(20), Duration::from_millis(20));
        for _ in 0..3 {
            tick.tick().await;
        }
    });
    assert_eq!(LAST_SLEEP_MS.with(|c| c.get()), 20, "ticker used the factory");

    // with_timeout races the injected sleep: instant-completion factory →
    // a never-ready inner must report Err immediately.
    let result = block_on(rustrtc::platform::time::with_timeout(
        Duration::from_millis(5),
        std::future::pending::<()>(),
    ));
    assert_eq!(result, Err(()));
}

// ── ICE wiring sanity through public types ───────────────────────────────

fn install_rng_counter() {
    static COUNTER: AtomicU32 = AtomicU32::new(1);
    fn fill(buf: &mut [u8]) {
        for slot in buf.iter_mut() {
            *slot = COUNTER.fetch_add(1, Ordering::Relaxed) as u8;
        }
    }
    rustrtc::platform::rng::set_fill_fn(fill);
}

#[test]
fn ice_transport_constructs_without_std() {
    install_rng_counter();
    // rtcembed's bin/ua.rs shape: new() must work under no_std and hand
    // back the runner future.
    let cfg = rustrtc::config::RtcConfiguration::default();
    let (transport, _runner) = rustrtc::transports::ice::IceTransport::new(cfg);
    assert_eq!(
        transport.state(),
        rustrtc::transports::ice::IceTransportState::New
    );
}

#[test]
fn ice_credentials_are_random_under_no_std() {
    install_rng_counter();
    // Regression guard for the old all-zero placeholder: ufrag/pwd and
    // tie-breaker must come from the injected source, not zeros.
    let cfg = rustrtc::config::RtcConfiguration::default();
    let (transport, _runner) = rustrtc::transports::ice::IceTransport::new(cfg);
    let params = transport.local_parameters();
    assert_ne!(params.username_fragment, "");
    assert_ne!(params.password, "");
    assert_ne!(params.username_fragment, "00000000");
    assert_ne!(params.tie_breaker, 0);
}

// ── helpers ──────────────────────────────────────────────────────────────

fn block_on<F: std::future::Future>(fut: F) -> F::Output {
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

fn noop_waker() -> std::task::Waker {
    use std::task::{RawWaker, RawWakerVTable, Waker};
    unsafe fn clone_raw(_: *const ()) -> RawWaker {
        RawWaker::new(std::ptr::null(), &VTABLE)
    }
    unsafe fn noop_raw(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone_raw, noop_raw, noop_raw, noop_raw);
    unsafe { Waker::from_raw(RawWaker::new(std::ptr::null(), &VTABLE)) }
}

// Silence unused import when variants are cfg'd out on some backends.
#[allow(dead_code)]
fn _unused(_: SocketAddr) {}
