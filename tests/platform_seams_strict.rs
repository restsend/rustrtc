#![cfg(not(feature = "std"))]

//! G1: strictness contract of the no_std seams, pinned in an isolated
//! binary (the injected factories are process-global, so these tests must
//! not share a binary with the ones that install them):
//! - `platform::rng::fill` panics before `set_fill_fn`
//! - `platform::task::sleep` panics before `set_sleep_fn`
//!
//! Both are deliberate: silent zeros (RNG) or a hung timer (sleep) would
//! be far worse failure modes on a target than a loud boot-time panic.

#[test]
#[should_panic(expected = "platform::rng: set_fill_fn not called")]
fn rng_fill_panics_without_an_injected_source() {
    let mut buf = [0u8; 16];
    rustrtc::platform::rng::fill(&mut buf);
}

#[test]
#[should_panic(expected = "platform::task::set_sleep_fn not called")]
fn task_sleep_panics_without_an_injected_factory() {
    block_on(async {
        rustrtc::platform::task::sleep(std::time::Duration::from_millis(1)).await;
    });
}

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
