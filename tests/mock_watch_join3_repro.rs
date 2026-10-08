#![cfg(not(feature = "std"))]

//! Minimal reproduction: does a watch transition inside a join3 wake the
//! sibling loop under the mock driver? (The WebRtc e2e answerer's dtls loop
//! stops observing ICE state transitions after its first wake.)

mod common;

use std::sync::Arc;

use rustrtc::platform::sync::watch;
use rustrtc::platform::task::BoxedTask;

#[test]
fn watch_transition_wakes_join3_sibling() {
    common::install_mock_platform();

    let (state_tx, state_rx) = watch::channel("New".to_string());
    let state_tx = Arc::new(state_tx);


    // "monitor": join3(gather, dtls, runner) shape — dtls loop reacts to
    // state transitions; gather loop returns after one complete round.
    let gather = {
        let state_tx = state_tx.clone();
        async move {
            // Simulates run_gathering_loop: completes on first poll.
            let _ = state_tx.send("Gathering".to_string());
        }
    };
    let dtls = {
        let mut rx = state_rx;
        async move {
        loop {
            let state = rx.borrow_and_update().clone();
            common::dbg(&format!("[repro] dtls wake: {state}"));
            if state == "Connected" {
                SEEN_CONNECTED.store(true, Ordering::SeqCst);
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
    };
    let runner = async {
        // Simulates the ICE read loop: parks forever.
        std::future::pending::<()>().await;
    };

    common::keep_task_labeled("monitor", Box::new(async move {
        let a = core::pin::pin!(gather);
        let b = core::pin::pin!(dtls);
        let c = core::pin::pin!(runner);
        rustrtc::platform::join::join3(a, b, c).await;
    }));
    // drive the transition from outside, like the test harness does
    common::keep_task_labeled("mover", {
        let state_tx = state_tx.clone();
        Box::new(async move {
            rustrtc::platform::task::sleep(std::time::Duration::from_millis(50)).await;
            let _ = state_tx.send("Checking".to_string());
            rustrtc::platform::task::sleep(std::time::Duration::from_millis(50)).await;
            let _ = state_tx.send("Connected".to_string());
        })
    });

    use std::sync::atomic::{AtomicBool, Ordering};
    static SEEN_CONNECTED: AtomicBool = AtomicBool::new(false);
    let got = common::drive_until(
        || SEEN_CONNECTED.load(Ordering::SeqCst),
        5_000,
    );
    assert!(got, "dtls loop must observe the Connected transition");
}
