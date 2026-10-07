#![cfg(feature = "std")]

// Interop test: TWCC feedback + GCC bandwidth estimation between rustrtc
// (client/offerer, sending video) and pion v3 (Go, server/answerer with
// TWCC interceptors). The pion side generates TWCC feedback for the inbound
// rustrtc stream; rustrtc's GCC estimator must consume it and move
// `target_bitrate` off its start value (server logs GCC-TWCC-OK).
#![allow(clippy::zombie_processes)]
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn test_pion_interop_gcc_twcc() {
    let status = Command::new("cargo")
        .args([
            "build",
            "--example",
            "interop_pion",
            "--target-dir",
            "target/e2e",
        ])
        .status()
        .expect("Failed to build Rust example");
    assert!(status.success());

    let status = Command::new("go")
        .args(["build", "-o", "interop_pion_go_gcc", "."])
        .current_dir("examples/interop_pion_go")
        .status()
        .expect("Failed to run go build (is Go installed?)");
    assert!(status.success(), "go build failed");

    // pion answerer with TWCC interceptors.
    let mut server = Command::new("./examples/interop_pion_go/interop_pion_go_gcc")
        .args(["-mode", "server", "-addr", "127.0.0.1:39145"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Go server");
    thread::sleep(Duration::from_secs(3));

    // rustrtc offerer sending video (its client mode logs GCC-TWCC-OK).
    let mut client = Command::new("./target/e2e/debug/examples/interop_pion")
        .args(["client", "127.0.0.1:39145"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Rust client");

    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    let mut finished = false;
    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        match client.try_wait().expect("wait client") {
            Some(_status) => {
                finished = true;
                break;
            }
            None => thread::sleep(Duration::from_millis(500)),
        }
    }
    if !finished {
        let _ = client.kill();
    }
    let out = client.wait_with_output().expect("client output");
    let client_log = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(
        client_log.contains("GCC-TWCC-OK"),
        "rustrtc GCC estimator never observed TWCC feedback from pion.\n--- client log ---\n{client_log}"
    );
    let _ = server.kill();
    let _ = server.wait();
}
