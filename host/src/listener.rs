//! Listener wiring for `strait-host`.
//!
//! Binds a Unix domain socket for the in-container proxy and a TCP socket
//! for the desktop app, then accepts connections until a shutdown signal
//! fires. Connection handling is intentionally stubbed -- this crate wires
//! up the process skeleton; the real protocol lives in H-HCP-2.

use std::net::SocketAddr;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio::sync::{watch, Notify};
use tracing::{debug, info, warn};

use crate::config::HostConfig;

/// Shutdown signal shared by the listeners. Drop it to close listeners;
/// call [`ShutdownSignal::trigger`] to request graceful termination.
#[derive(Clone)]
pub struct ShutdownSignal {
    tx: watch::Sender<bool>,
    // Fires once both listeners have observed shutdown and stopped accepting.
    drained: Arc<Notify>,
}

impl ShutdownSignal {
    /// Create a new signal in the "running" state.
    pub fn new() -> Self {
        let (tx, _rx) = watch::channel(false);
        Self {
            tx,
            drained: Arc::new(Notify::new()),
        }
    }

    /// Subscribe to the shutdown signal. Each listener task keeps its own
    /// receiver.
    pub fn subscribe(&self) -> watch::Receiver<bool> {
        self.tx.subscribe()
    }

    /// Request graceful shutdown. Idempotent.
    pub fn trigger(&self) {
        let _ = self.tx.send(true);
    }

    /// Wait for both listener tasks to report they have stopped accepting
    /// new connections.
    pub async fn wait_drained(&self) {
        self.drained.notified().await;
    }

    /// Notify waiters that a listener has drained. Called internally when
    /// both listeners exit. Tests can use this to wait for graceful exit.
    fn signal_drained(&self) {
        self.drained.notify_waiters();
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the host listeners. Blocks until `shutdown` fires and both listeners
/// have stopped accepting. On return, the Unix socket file has been removed
/// and the TCP listener has been dropped.
pub async fn serve(cfg: &HostConfig, shutdown: ShutdownSignal) -> Result<()> {
    let unix = bind_unix(&cfg.unix_socket, cfg.socket_mode)
        .with_context(|| format!("binding unix socket {}", cfg.unix_socket.display()))?;
    info!(
        target: "strait_host::listener",
        path = %cfg.unix_socket.display(),
        mode = format!("0o{:o}", cfg.socket_mode),
        "listening on unix socket",
    );

    let tcp = TcpListener::bind(cfg.tcp_listen)
        .await
        .with_context(|| format!("binding tcp {}", cfg.tcp_listen))?;
    let local_addr = tcp.local_addr().unwrap_or(cfg.tcp_listen);
    info!(
        target: "strait_host::listener",
        addr = %local_addr,
        "listening on tcp",
    );

    let unix_path = cfg.unix_socket.clone();
    let unix_rx = shutdown.subscribe();
    let unix_task = tokio::spawn(unix_accept_loop(unix, unix_path.clone(), unix_rx));

    let tcp_rx = shutdown.subscribe();
    let tcp_task = tokio::spawn(tcp_accept_loop(tcp, tcp_rx));

    // Wait for both accept loops to exit.
    let (u, t) = tokio::join!(unix_task, tcp_task);
    if let Err(e) = u {
        warn!(target: "strait_host::listener", error = %e, "unix accept task panicked");
    }
    if let Err(e) = t {
        warn!(target: "strait_host::listener", error = %e, "tcp accept task panicked");
    }

    // Best-effort cleanup of the socket file; the listener drop already did
    // the close, but the file entry can linger.
    if unix_path.exists() {
        let _ = std::fs::remove_file(&unix_path);
    }

    shutdown.signal_drained();
    Ok(())
}

/// Bind the Unix listener, removing any stale socket file and creating the
/// parent directory if needed. Sets the socket's permission bits to
/// `mode` so only the owning user can connect.
fn bind_unix(path: &Path, mode: u32) -> Result<UnixListener> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir {}", parent.display()))?;
        }
    }
    // Remove stale socket file from a previous run. Ignore "not found".
    match std::fs::remove_file(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("removing stale socket {}", path.display()));
        }
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind unix listener {}", path.display()))?;

    // chmod the socket. Umask may have stripped the bits we asked for.
    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod unix socket {}", path.display()))?;

    Ok(listener)
}

async fn unix_accept_loop(
    listener: UnixListener,
    path: PathBuf,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, _addr)) => {
                        debug!(target: "strait_host::listener", path = %path.display(), "unix connection accepted");
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream).await {
                                debug!(target: "strait_host::listener", error = %e, "unix connection handler error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(target: "strait_host::listener", error = %e, "unix accept error");
                    }
                }
            }
        }
    }
    debug!(target: "strait_host::listener", path = %path.display(), "unix accept loop exited");
}

async fn tcp_accept_loop(listener: TcpListener, mut shutdown: watch::Receiver<bool>) {
    loop {
        tokio::select! {
            biased;
            _ = shutdown.changed() => {
                if *shutdown.borrow() { break; }
            }
            accept = listener.accept() => {
                match accept {
                    Ok((stream, addr)) => {
                        debug!(target: "strait_host::listener", %addr, "tcp connection accepted");
                        tokio::spawn(async move {
                            if let Err(e) = handle_connection(stream).await {
                                debug!(target: "strait_host::listener", error = %e, "tcp connection handler error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(target: "strait_host::listener", error = %e, "tcp accept error");
                    }
                }
            }
        }
    }
    debug!(target: "strait_host::listener", "tcp accept loop exited");
}

/// Stubbed heartbeat handler. Reads one inbound frame, writes an `OK\n`
/// acknowledgement, and closes. The real protocol (gRPC over both sockets)
/// lands in H-HCP-2; this handler exists so smoke tests can confirm both
/// listeners are reachable end to end.
async fn handle_connection<S>(stream: S) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin + Send,
{
    let (mut r, mut w) = tokio::io::split(stream);
    let mut buf = [0u8; 256];
    let n = r.read(&mut buf).await?;
    if n > 0 {
        w.write_all(b"OK\n").await?;
        w.flush().await?;
    }
    let _ = w.shutdown().await;
    Ok(())
}

// Expose typed variants for callers that already have a concrete stream.
// These are thin wrappers over the generic handler and exist mostly for
// symmetry with future protocol-aware handlers.
#[allow(dead_code)]
async fn handle_unix(stream: UnixStream) -> std::io::Result<()> {
    handle_connection(stream).await
}

#[allow(dead_code)]
async fn handle_tcp(stream: TcpStream) -> std::io::Result<()> {
    handle_connection(stream).await
}

/// Return the effective TCP listener address (for logging and tests). The
/// caller passes the configured value; when the configured port is 0 the
/// kernel assigns one at bind time, so tests that need the real port should
/// obtain it from `TcpListener::local_addr` instead.
#[allow(dead_code)]
pub fn describe_tcp(addr: SocketAddr) -> String {
    format!("{addr}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    use tempfile::tempdir;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpStream as TokioTcpStream;
    use tokio::net::UnixStream as TokioUnixStream;
    use tokio::time::timeout;

    fn test_config(dir: &Path) -> HostConfig {
        HostConfig {
            unix_socket: dir.join("host.sock"),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            socket_mode: 0o600,
        }
    }

    #[tokio::test]
    async fn bind_unix_sets_requested_mode() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("chmod.sock");
        let _listener = bind_unix(&sock, 0o600).unwrap();
        let mode = std::fs::metadata(&sock).unwrap().mode() & 0o777;
        assert_eq!(mode, 0o600, "expected 0o600 got 0o{mode:o}");
    }

    #[tokio::test]
    async fn bind_unix_removes_stale_file() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("stale.sock");
        std::fs::write(&sock, b"not a socket").unwrap();
        let _listener = bind_unix(&sock, 0o600).unwrap();
        assert!(sock.exists());
    }

    #[tokio::test]
    async fn bind_unix_creates_parent_dir() {
        let dir = tempdir().unwrap();
        let sock = dir.path().join("nested/host.sock");
        let _listener = bind_unix(&sock, 0o600).unwrap();
        assert!(sock.exists());
    }

    #[tokio::test]
    async fn both_sockets_accept_stub_heartbeat() {
        let dir = tempdir().unwrap();
        let cfg = test_config(dir.path());
        let unix_path = cfg.unix_socket.clone();

        let shutdown = ShutdownSignal::new();
        let s = shutdown.clone();
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move { serve(&server_cfg, s).await });

        // Wait for the unix socket file to appear.
        for _ in 0..100 {
            if unix_path.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        assert!(unix_path.exists(), "unix socket never appeared");

        // The TCP port is ephemeral; we bound :0, so a test can't predict
        // the port. For this test we pass an explicit port via the config
        // by re-binding on a known address instead.
        // To keep things simple, reserve a port ourselves and rebind the
        // server: easier to just connect by asking the OS for a port we
        // know won't conflict.
        // Workaround: pick a port ahead of time by binding a throwaway
        // listener and dropping it, then use that port in the config.
        // This test path is covered by `tcp_listener_accepts_with_reserved_port`
        // below; here we focus on the unix half.

        // Unix: send a stub heartbeat and confirm the "OK" response.
        let mut u = TokioUnixStream::connect(&unix_path)
            .await
            .expect("unix connect");
        u.write_all(b"HEARTBEAT\n").await.unwrap();
        u.shutdown().await.unwrap();
        let mut resp = Vec::new();
        u.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"OK\n");

        shutdown.trigger();
        // serve() should exit quickly.
        let r = timeout(Duration::from_secs(2), server).await;
        assert!(r.is_ok(), "server did not exit within 2s");
    }

    #[tokio::test]
    async fn tcp_listener_accepts_with_reserved_port() {
        // Pick a free port by binding a throwaway listener.
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = probe.local_addr().unwrap().port();
        drop(probe);

        let dir = tempdir().unwrap();
        let mut cfg = test_config(dir.path());
        cfg.tcp_listen = format!("127.0.0.1:{port}").parse().unwrap();
        let tcp_addr = cfg.tcp_listen;

        let shutdown = ShutdownSignal::new();
        let s = shutdown.clone();
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move { serve(&server_cfg, s).await });

        // Wait for TCP to bind.
        let mut connected: Option<TokioTcpStream> = None;
        for _ in 0..100 {
            if let Ok(s) = TokioTcpStream::connect(tcp_addr).await {
                connected = Some(s);
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        let mut t = connected.expect("tcp connect");
        t.write_all(b"HEARTBEAT\n").await.unwrap();
        t.shutdown().await.unwrap();
        let mut resp = Vec::new();
        t.read_to_end(&mut resp).await.unwrap();
        assert_eq!(resp, b"OK\n");

        shutdown.trigger();
        let r = timeout(Duration::from_secs(2), server).await;
        assert!(r.is_ok(), "server did not exit within 2s");
    }

    #[tokio::test]
    async fn shutdown_exits_within_two_seconds() {
        let dir = tempdir().unwrap();
        let cfg = test_config(dir.path());
        let shutdown = ShutdownSignal::new();
        let s = shutdown.clone();
        let server_cfg = cfg.clone();
        let server = tokio::spawn(async move { serve(&server_cfg, s).await });

        // Let the server get its listeners up.
        for _ in 0..100 {
            if cfg.unix_socket.exists() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }

        let t0 = std::time::Instant::now();
        shutdown.trigger();
        let r = timeout(Duration::from_secs(2), server).await;
        assert!(r.is_ok(), "server did not exit within 2s");
        let elapsed = t0.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "shutdown took {elapsed:?}"
        );

        // Unix socket file should be cleaned up.
        assert!(
            !cfg.unix_socket.exists(),
            "unix socket file still exists after shutdown",
        );
    }
}
