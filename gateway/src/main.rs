//! strait-gateway: in-container TCP-to-Unix-socket forwarder.
//!
//! Runs inside the container, listens on 127.0.0.1:3128 (or a configured
//! address), and forwards every accepted TCP connection to the host proxy
//! over a Unix socket. Spawns a child command, forwards signals to it,
//! and exits with the child's exit code.

use std::process::ExitCode;

use tokio::io::{self, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::process::Command;
use tokio::sync::watch;

// ── CLI arg parsing (no dep on clap -- keep the binary small) ────────

struct Args {
    listen: String,
    socket: String,
    command: Vec<String>,
}

fn parse_args() -> Result<Args, String> {
    let mut args = std::env::args().skip(1);
    let mut listen = String::from("127.0.0.1:3128");
    let mut socket: Option<String> = None;
    let mut command: Vec<String> = Vec::new();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--" => {
                command.extend(args);
                break;
            }
            "--listen" => {
                listen = args
                    .next()
                    .ok_or_else(|| "--listen requires a value".to_string())?;
            }
            "--socket" => {
                socket = Some(
                    args.next()
                        .ok_or_else(|| "--socket requires a value".to_string())?,
                );
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
    }

    let socket = socket.ok_or_else(|| "--socket <path> is required".to_string())?;

    if command.is_empty() {
        return Err("a command is required after --".to_string());
    }

    Ok(Args {
        listen,
        socket,
        command,
    })
}

// ── Forwarding ───────────────────────────────────────────────────────

/// Forward a single TCP connection to the Unix socket at `socket_path`.
///
/// Copies data bidirectionally with proper half-close: when one direction
/// finishes (EOF), the write side of the other stream is shut down so the
/// peer learns that no more data is coming. Both directions run to
/// completion before the function returns.
async fn forward(tcp: TcpStream, socket_path: &str) -> io::Result<()> {
    let unix = UnixStream::connect(socket_path).await?;
    let (mut tcp_r, mut tcp_w) = tcp.into_split();
    let (mut unix_r, mut unix_w) = unix.into_split();

    let client_to_proxy = async {
        let r = io::copy(&mut tcp_r, &mut unix_w).await;
        // Client finished sending; tell the proxy via shutdown.
        let _ = unix_w.shutdown().await;
        r
    };
    let proxy_to_client = async {
        let r = io::copy(&mut unix_r, &mut tcp_w).await;
        let _ = tcp_w.shutdown().await;
        r
    };

    let (a, b) = tokio::join!(client_to_proxy, proxy_to_client);
    a.and(b).map(|_| ())
}

// ── Signal forwarding ────────────────────────────────────────────────

/// Send a signal to a process. No-op on non-Unix platforms.
#[cfg(unix)]
fn send_signal(pid: u32, sig: i32) {
    unsafe {
        libc::kill(pid as libc::pid_t, sig);
    }
}

/// Spawn a task that forwards SIGTERM and SIGINT to the child process.
#[cfg(unix)]
async fn forward_signals(pid: u32) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut sigterm = signal(SignalKind::terminate()).expect("failed to register SIGTERM handler");
    let mut sigint = signal(SignalKind::interrupt()).expect("failed to register SIGINT handler");

    tokio::select! {
        _ = sigterm.recv() => send_signal(pid, libc::SIGTERM),
        _ = sigint.recv() => send_signal(pid, libc::SIGINT),
    }
}

// ── Entry point ──────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("strait-gateway: {e}");
            eprintln!(
                "usage: strait-gateway --socket <path> [--listen <addr>] -- <command> [args...]"
            );
            return ExitCode::from(2);
        }
    };

    // Bind the TCP listener before spawning the child so the child can
    // immediately use the proxy.
    let listener = match TcpListener::bind(&args.listen).await {
        Ok(l) => l,
        Err(e) => {
            eprintln!("strait-gateway: failed to bind {}: {e}", args.listen);
            return ExitCode::from(1);
        }
    };

    // Spawn the child command.
    let mut child = match Command::new(&args.command[0])
        .args(&args.command[1..])
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("strait-gateway: failed to spawn {}: {e}", args.command[0]);
            return ExitCode::from(1);
        }
    };

    let child_pid = child.id().unwrap_or(0);

    // Channel to signal the accept loop to stop when the child exits.
    let (stop_tx, stop_rx) = watch::channel(false);

    // Forward signals to the child.
    #[cfg(unix)]
    let signal_handle = tokio::spawn(forward_signals(child_pid));

    // Accept loop: forward connections until the child exits.
    let socket_path = args.socket.clone();
    let accept_handle = tokio::spawn(accept_loop(listener, socket_path, stop_rx));

    // Wait for the child to exit.
    let status = child.wait().await;

    // Tell the accept loop to stop.
    let _ = stop_tx.send(true);

    // Cancel signal forwarding.
    #[cfg(unix)]
    signal_handle.abort();

    // Wait briefly for the accept loop to finish.
    let _ = accept_handle.await;

    match status {
        Ok(s) => ExitCode::from(s.code().unwrap_or(1) as u8),
        Err(e) => {
            eprintln!("strait-gateway: failed to wait on child: {e}");
            ExitCode::from(1)
        }
    }
}

/// Accept TCP connections and forward each to the Unix socket.
/// Stops when the `stop` channel signals true.
async fn accept_loop(listener: TcpListener, socket_path: String, mut stop: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            biased;
            _ = stop.changed() => {
                if *stop.borrow() {
                    break;
                }
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, _)) => {
                        let path = socket_path.clone();
                        tokio::spawn(async move {
                            if let Err(e) = forward(stream, &path).await {
                                eprintln!("strait-gateway: forward error: {e}");
                            }
                        });
                    }
                    Err(e) => {
                        eprintln!("strait-gateway: accept error: {e}");
                    }
                }
            }
        }
    }
}

// ── Tests ────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpStream, UnixListener};

    use super::*;

    /// Start a Unix socket echo server that reads data and writes it back.
    async fn unix_echo_server(path: &str) -> UnixListener {
        let _ = std::fs::remove_file(path);
        let listener = UnixListener::bind(path).expect("failed to bind unix socket");
        listener
    }

    /// Accept one connection on the Unix listener and echo all data back.
    async fn echo_one(listener: &UnixListener) {
        let (mut stream, _) = listener.accept().await.expect("accept failed");
        let mut buf = vec![0u8; 4096];
        loop {
            let n = stream.read(&mut buf).await.expect("read failed");
            if n == 0 {
                break;
            }
            stream.write_all(&buf[..n]).await.expect("write failed");
        }
    }

    #[tokio::test]
    async fn forward_round_trip() {
        let dir = tempdir();
        let sock_path = format!("{}/proxy.sock", dir);

        // Start the Unix echo server.
        let unix_listener = unix_echo_server(&sock_path).await;

        // Bind a TCP listener on an ephemeral port.
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = tcp_listener.local_addr().unwrap();

        // Spawn accept loop.
        let (stop_tx, stop_rx) = watch::channel(false);
        let sock_clone = sock_path.clone();
        let accept = tokio::spawn(accept_loop(tcp_listener, sock_clone, stop_rx));

        // Spawn echo handler for one connection.
        let echo = tokio::spawn(async move { echo_one(&unix_listener).await });

        // Connect and send data.
        let mut client = TcpStream::connect(addr).await.expect("connect failed");
        client.write_all(b"hello gateway").await.unwrap();

        // Read echo back.
        let mut buf = vec![0u8; 64];
        let n = client.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello gateway");

        // Shut down.
        drop(client);
        echo.await.unwrap();
        let _ = stop_tx.send(true);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn forward_large_payload() {
        let dir = tempdir();
        let sock_path = format!("{}/proxy.sock", dir);

        let unix_listener = unix_echo_server(&sock_path).await;
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = tcp_listener.local_addr().unwrap();

        let (stop_tx, stop_rx) = watch::channel(false);
        let sock_clone = sock_path.clone();
        let accept = tokio::spawn(accept_loop(tcp_listener, sock_clone, stop_rx));
        let echo = tokio::spawn(async move { echo_one(&unix_listener).await });

        let mut client = TcpStream::connect(addr).await.expect("connect failed");
        let payload = vec![0xABu8; 64 * 1024]; // 64 KB
        client.write_all(&payload).await.unwrap();
        client.shutdown().await.unwrap();

        let mut result = Vec::new();
        client.read_to_end(&mut result).await.unwrap();
        assert_eq!(result.len(), payload.len());
        assert_eq!(result, payload);

        echo.await.unwrap();
        let _ = stop_tx.send(true);
        accept.await.unwrap();
    }

    #[tokio::test]
    async fn child_exit_code_propagation() {
        // Spawn a child that exits with code 42 and verify we capture it.
        let mut child = Command::new("sh")
            .arg("-c")
            .arg("exit 42")
            .spawn()
            .expect("spawn failed");

        let status = child.wait().await.expect("wait failed");
        assert_eq!(status.code(), Some(42));
    }

    #[tokio::test]
    async fn child_exit_code_zero() {
        let mut child = Command::new("true").spawn().expect("spawn failed");
        let status = child.wait().await.expect("wait failed");
        assert_eq!(status.code(), Some(0));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn child_signal_forwarding() {
        use tokio::time::timeout;

        // Start a long-running child.
        let mut child = Command::new("sleep")
            .arg("60")
            .spawn()
            .expect("spawn failed");

        let pid = child.id().expect("no pid");

        // Send SIGTERM to the child.
        send_signal(pid, libc::SIGTERM);

        // Child should exit promptly.
        let status = timeout(Duration::from_secs(5), child.wait())
            .await
            .expect("child did not exit after signal")
            .expect("wait failed");

        // On Unix, a process killed by SIGTERM has no exit code but a signal.
        assert!(!status.success());
    }

    #[tokio::test]
    async fn multiple_connections() {
        let dir = tempdir();
        let sock_path = format!("{}/proxy.sock", dir);

        let unix_listener = unix_echo_server(&sock_path).await;
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.expect("bind failed");
        let addr = tcp_listener.local_addr().unwrap();

        let (stop_tx, stop_rx) = watch::channel(false);
        let sock_clone = sock_path.clone();
        let accept = tokio::spawn(accept_loop(tcp_listener, sock_clone, stop_rx));

        // Handle two connections sequentially on the echo server side.
        let echo_handle = tokio::spawn(async move {
            echo_one(&unix_listener).await;
            echo_one(&unix_listener).await;
        });

        for i in 0..2u8 {
            let mut client = TcpStream::connect(addr).await.expect("connect failed");
            let msg = format!("msg-{i}");
            client.write_all(msg.as_bytes()).await.unwrap();
            client.shutdown().await.unwrap();

            let mut buf = Vec::new();
            client.read_to_end(&mut buf).await.unwrap();
            assert_eq!(buf, msg.as_bytes());
        }

        echo_handle.await.unwrap();
        let _ = stop_tx.send(true);
        accept.await.unwrap();
    }

    /// Create a unique temporary directory and return its path as a String.
    fn tempdir() -> String {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("strait-gw-test-{}-{}", std::process::id(), n));
        let _ = std::fs::create_dir_all(&dir);
        dir.to_string_lossy().to_string()
    }
}
