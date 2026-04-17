//! Integration tests for `strait-host`.
//!
//! These tests exercise the published binary: they spawn `strait-host serve`
//! with override paths, connect to both listeners, and verify that SIGTERM
//! exits the process within the budget documented in the work item.

#![cfg(unix)]

use std::process::Stdio;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};
use tokio::process::Command;
use tokio::time::timeout;

/// Path to the built `strait-host` binary, injected by cargo at compile time.
const BIN: &str = env!("CARGO_BIN_EXE_strait-host");

/// Pick a free TCP port on loopback by binding and dropping a throwaway listener.
fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Wait for a predicate up to `budget`. Poll every 20ms.
async fn wait_until<F: Fn() -> bool>(budget: Duration, predicate: F) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    predicate()
}

#[tokio::test]
async fn both_listeners_accept_stubbed_heartbeat() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let tcp_addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--unix-socket")
        .arg(&sock)
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--log-format")
        .arg("text")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn strait-host");

    // Wait for the Unix socket file to appear and TCP to accept.
    let sock_clone = sock.clone();
    let unix_ready = wait_until(Duration::from_secs(5), move || sock_clone.exists()).await;
    assert!(unix_ready, "unix socket never appeared");

    let tcp_ready = wait_until(Duration::from_secs(5), || {
        std::net::TcpStream::connect_timeout(&tcp_addr.parse().unwrap(), Duration::from_millis(200))
            .is_ok()
    })
    .await;
    assert!(tcp_ready, "tcp listener did not start");

    // Unix: send a stub heartbeat and read the OK response.
    {
        let mut u = UnixStream::connect(&sock).await.expect("unix connect");
        u.write_all(b"HEARTBEAT\n").await.unwrap();
        u.shutdown().await.unwrap();
        let mut resp = Vec::new();
        u.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"OK\n", "unix heartbeat: {resp:?}");
    }

    // TCP: same handshake.
    {
        let mut t = TcpStream::connect(&tcp_addr).await.expect("tcp connect");
        t.write_all(b"HEARTBEAT\n").await.unwrap();
        t.shutdown().await.unwrap();
        let mut resp = Vec::new();
        t.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"OK\n", "tcp heartbeat: {resp:?}");
    }

    // Clean up.
    let pid = child.id().expect("child has no pid");
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
}

#[tokio::test]
async fn sigterm_exits_within_two_seconds() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let tcp_addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--unix-socket")
        .arg(&sock)
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--log-format")
        .arg("text")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn strait-host");

    let sock_clone = sock.clone();
    let ready = wait_until(Duration::from_secs(5), move || sock_clone.exists()).await;
    assert!(ready, "unix socket never appeared");

    let pid = child.id().expect("child has no pid");
    let t0 = Instant::now();
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let status = timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("process did not exit within 2s after SIGTERM")
        .expect("wait failed");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "SIGTERM shutdown took {elapsed:?}",
    );
    assert!(status.success(), "exit status: {status:?}");
}

#[tokio::test]
async fn help_documents_defaults() {
    let output = std::process::Command::new(BIN)
        .arg("serve")
        .arg("--help")
        .output()
        .expect("run strait-host serve --help");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("/var/run/strait/host.sock"),
        "--help missing default unix socket path:\n{text}",
    );
    assert!(
        text.contains("127.0.0.1:3129"),
        "--help missing default tcp listener:\n{text}",
    );

    let top = std::process::Command::new(BIN)
        .arg("--help")
        .output()
        .expect("run strait-host --help");
    let text = String::from_utf8_lossy(&top.stdout);
    assert!(
        text.contains("host.toml"),
        "top-level --help missing config path mention:\n{text}",
    );
}
