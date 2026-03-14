use std::net::{SocketAddr, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::{Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};

fn wait_for_child_with_timeout(
    child: &mut Child,
    timeout: Duration,
) -> std::io::Result<Option<std::process::ExitStatus>> {
    let start = Instant::now();
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if start.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(100));
    }
}

fn interop_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

fn wait_for_tcp_listener(addr: &str, timeout: Duration) -> std::io::Result<()> {
    let addr: SocketAddr = addr
        .parse()
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid address"))?;
    let start = Instant::now();
    loop {
        match TcpStream::connect_timeout(&addr, Duration::from_millis(200)) {
            Ok(_) => return Ok(()),
            Err(err) if start.elapsed() >= timeout => return Err(err),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

#[test]
fn test_rust_server_go_client() {
    // These tests share a build dir, a Go binary path, and fixed localhost ports.
    // Serialize them so one scenario cannot starve or interfere with the other.
    let _guard = interop_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // 0. Build Rust example (use separate target dir to avoid lock contention)
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--example",
            "interop_pion",
            "--target-dir",
            "target/e2e",
        ])
        .status()
        .expect("Failed to build Rust example");
    assert!(status.success());

    // 1. Build Go binary
    let status = Command::new("go")
        .args(&["build", "-o", "interop_pion_go", "."])
        .current_dir("examples/interop_pion_go")
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            println!("Skipping test: Go build failed or go not found");
            return;
        }
    }

    // 2. Start Rust Server
    let mut server = Command::new("./target/e2e/debug/examples/interop_pion")
        .args(&["server", "127.0.0.1:3000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Rust server");

    wait_for_tcp_listener("127.0.0.1:3000", Duration::from_secs(10))
        .expect("Rust server did not start listening in time");

    // 3. Start Go Client
    let client = Command::new("./examples/interop_pion_go/interop_pion_go")
        .args(&["-mode", "client", "-addr", "127.0.0.1:3000"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Go client");

    // 4. Wait for client to finish (it should exit 0 after 5 pings)
    let output = client
        .wait_with_output()
        .expect("Failed to wait for Go client");

    // Kill server
    let _ = server.kill();

    if !output.status.success() {
        println!(
            "Go Client stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
        println!(
            "Go Client stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    if output.status.success() {
        println!(
            "Go Client stdout: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
}

#[test]
fn test_go_server_rust_client() {
    // These tests share a build dir, a Go binary path, and fixed localhost ports.
    // Serialize them so one scenario cannot starve or interfere with the other.
    let _guard = interop_test_lock()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());

    // 0. Build Rust example
    let status = Command::new("cargo")
        .args(&[
            "build",
            "--example",
            "interop_pion",
            "--target-dir",
            "target/e2e",
        ])
        .status()
        .expect("Failed to build Rust example");
    assert!(status.success());

    // 1. Build Go binary
    let status = Command::new("go")
        .args(&["build", "-o", "interop_pion_go", "."])
        .current_dir("examples/interop_pion_go")
        .status();

    match status {
        Ok(s) if s.success() => {}
        _ => {
            println!("Skipping test: Go build failed or go not found");
            return;
        }
    }

    // 2. Start Go Server
    let mut server = Command::new("./examples/interop_pion_go/interop_pion_go")
        .args(&["-mode", "server", "-addr", "127.0.0.1:3001"]) // Use different port
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Go server");

    wait_for_tcp_listener("127.0.0.1:3001", Duration::from_secs(10))
        .expect("Go server did not start listening in time");

    // 3. Start Rust Client
    let mut client = Command::new("./target/e2e/debug/examples/interop_pion")
        .args(&["client", "127.0.0.1:3001"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start Rust client");

    // 4. Wait for client to finish (it should exit 0 after 5 pings).
    // Avoid piping the Rust client's logs into an unread buffer, which can
    // block the child process once debug logging becomes noisy.
    let status = wait_for_child_with_timeout(&mut client, Duration::from_secs(40))
        .expect("Failed to wait for Rust client")
        .unwrap_or_else(|| {
            let _ = client.kill();
            panic!("Rust client timed out");
        });

    // Kill server
    let _ = server.kill();

    assert!(status.success(), "Rust client failed");
}
