#![cfg(feature = "std")]
// Interop test: ICE restart between rustrtc (server/answerer) and pion v3
// (Go, client). The pion client connects normally, then the rustrtc side
// rolls fresh ICE credentials (restart_ice + new offer). pion detects the
// remote restart, answers with its own fresh credentials, and the DataChannel
// must keep flowing afterwards (server prints RESTART-OK after two
// post-restart echoes).
#![allow(clippy::zombie_processes)]
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::Duration;

/// Kills the child on drop so a failing assert never leaks a process holding
/// the test's server port (which would make every subsequent run fail, too).
struct KillOnDrop(Option<Child>);

impl Drop for KillOnDrop {
    fn drop(&mut self) {
        if let Some(child) = &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Grab a free ephemeral port instead of a fixed one: fixed ports collide with
/// stale processes and between concurrent/failed runs.
fn pick_free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("bind ephemeral port")
        .local_addr()
        .expect("local addr")
        .port()
}

#[test]
fn test_pion_interop_ice_restart() {
    // 0. Build Rust example (separate target dir to avoid lock contention)
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

    // 1. Build Go pion client
    let status = Command::new("go")
        .args(["build", "-o", "interop_pion_go_restart", "."])
        .current_dir("examples/interop_pion_go")
        .status()
        .expect("Failed to run go build (is Go installed?)");
    assert!(status.success(), "go build failed");

    let addr = format!("127.0.0.1:{}", pick_free_port());

    // 2. Start Rust server
    let server = Command::new("./target/e2e/debug/examples/interop_pion")
        .args(["server", &addr])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Rust server");
    let mut server = KillOnDrop(Some(server));
    thread::sleep(Duration::from_secs(3));

    // 3. Start pion client with restart flow (12 ticks ≈ 12 s + setup)
    let client = Command::new("./examples/interop_pion_go/interop_pion_go_restart")
        .args(["-mode", "client", "-addr", &addr, "-restart"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Go client");
    let mut client = KillOnDrop(Some(client));

    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    let mut client_ok = false;
    loop {
        if std::time::Instant::now() > deadline {
            break;
        }
        match client
            .0
            .as_mut()
            .expect("client alive")
            .try_wait()
            .expect("wait client")
        {
            Some(status) => {
                client_ok = status.success();
                break;
            }
            None => thread::sleep(Duration::from_millis(500)),
        }
    }
    assert!(client_ok, "pion client did not finish successfully");

    // 4. Give the server a moment to log the post-restart echoes.
    thread::sleep(Duration::from_secs(2));
    let _ = server.0.as_mut().expect("server alive").kill();
    let server = server.0.take().expect("server alive");
    let output = server.wait_with_output().expect("server output");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let all = format!("{stdout}{stderr}");

    assert!(
        all.contains("RESTART-OK"),
        "server did not observe post-restart media.\n--- server log ---\n{all}"
    );
    assert!(
        all.contains("ice-ufrag"),
        "restart offer ufrag rotation was not logged.\n--- server log ---\n{all}"
    );
    assert!(
        !all.contains("restart_ice failed") && !all.contains("ICE error"),
        "server hit an ICE error during restart.\n--- server log ---\n{all}"
    );
}
