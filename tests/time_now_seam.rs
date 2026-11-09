#![cfg(not(feature = "std"))]

//! no_std clock seam: an injected hardware monotonic source drives
//! `Instant::now()`/`elapsed()` instead of the logical counter.

use std::sync::atomic::{AtomicU64, Ordering};

use rustrtc::platform::time::Instant;

static TICK_MS: AtomicU64 = AtomicU64::new(1_000);

fn injected_now_ms() -> u64 {
    TICK_MS.load(Ordering::Relaxed)
}

#[test]
fn injected_now_fn_drives_instant_deltas() {
    rustrtc::platform::time::set_now_fn(injected_now_ms);

    let start = Instant::now();
    TICK_MS.fetch_add(250, Ordering::Relaxed);
    assert_eq!(start.elapsed().as_millis(), 250);

    let mid = Instant::now();
    TICK_MS.fetch_add(1_000, Ordering::Relaxed);
    assert_eq!(Instant::now().duration_since(mid).as_millis(), 1_000);
}
