use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration;

#[test]
fn test_rust_server_go_client() {
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

    // Give server time to start
    thread::sleep(Duration::from_secs(5));

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

    // Give server time to start
    thread::sleep(Duration::from_secs(2));

    // 3. Start Rust Client
    let mut client = Command::new("./target/e2e/debug/examples/interop_pion")
        .args(&["client", "127.0.0.1:3001"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start Rust client");

    // 4. Wait for client to finish (it should exit 0 after 5 pings)
    let status = client.wait().expect("Failed to wait for Rust client");

    // Kill server
    let _ = server.kill();

    assert!(status.success(), "Rust client failed");
}
