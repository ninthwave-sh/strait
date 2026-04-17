//! Listener wiring for `strait-host`.
//!
//! Binds a Unix domain socket for the in-container agent and a TCP socket
//! for the desktop app, then serves the strait host-control-plane gRPC
//! service on both until a shutdown signal fires.
//!
//! Two listeners, one service instance: both tonic servers share a single
//! `StraitHostService` value so session counters stay coherent no matter
//! which transport a client used. The gRPC service trait's auto-generated
//! server wrapper is also Clone, so each tonic `Server::builder()` gets its
//! own shallow copy.

use std::path::Path;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use anyhow::{Context as AnyhowContext, Result};
use strait_proto::v1::strait_host_server::StraitHostServer;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::{watch, Notify};
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::server::{Connected, UdsConnectInfo};
use tonic::transport::Server as TonicServer;
use tracing::{info, warn};

use crate::config::HostConfig;
use crate::grpc::StraitHostService;
use crate::observations::ObservationHub;
use crate::rule_store::RuleStore;

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

    /// Notify waiters that the listeners have drained. Called internally
    /// when both listeners exit. Tests can use this to wait for graceful
    /// exit without polling process state.
    fn signal_drained(&self) {
        self.drained.notify_waiters();
    }
}

impl Default for ShutdownSignal {
    fn default() -> Self {
        Self::new()
    }
}

/// Run the host listeners using the default production service.
///
/// Blocks until `shutdown` fires and both listeners have stopped accepting.
/// On return, the Unix socket file has been removed and the TCP listener
/// has been dropped.
///
/// The persistent rule store is opened from `cfg.rules_db`; tests that need
/// a throwaway store can construct a `StraitHostService` manually and call
/// [`serve_with_service`] instead.
pub async fn serve(cfg: &HostConfig, shutdown: ShutdownSignal) -> Result<()> {
    let rules = RuleStore::open(&cfg.rules_db)
        .with_context(|| format!("opening rule store {}", cfg.rules_db.display()))?;
    info!(
        target: "strait_host::listener",
        path = %cfg.rules_db.display(),
        "rule store ready",
    );
    let hub = ObservationHub::open(&cfg.observations_log)
        .await
        .with_context(|| {
            format!(
                "opening observations log {}",
                cfg.observations_log.display()
            )
        })?;
    info!(
        target: "strait_host::listener",
        path = %cfg.observations_log.display(),
        "observations log ready",
    );
    let svc =
        StraitHostService::with_rule_store(Arc::new(rules)).with_observation_hub(Arc::new(hub));
    serve_with_service(cfg, shutdown, svc).await
}

/// Run the host listeners with a caller-provided service implementation.
///
/// Integration tests use this to inject an alternative `StraitHost` impl
/// (for example one that echoes `SubmitDecision` requests back as verdicts).
pub async fn serve_with_service<S>(cfg: &HostConfig, shutdown: ShutdownSignal, svc: S) -> Result<()>
where
    S: strait_proto::v1::strait_host_server::StraitHost,
{
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

    // Shared server wrapper. `StraitHostServer` is Clone, so each listener
    // owns a cheap copy that talks to the same underlying service value.
    let server = StraitHostServer::new(svc);

    // Each listener has its own shutdown future; both observe the same
    // underlying watch channel.
    let unix_shutdown = shutdown_future(shutdown.subscribe());
    let tcp_shutdown = shutdown_future(shutdown.subscribe());

    let unix_path = cfg.unix_socket.clone();
    let unix_incoming = uds_incoming(unix);

    let unix_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let result = TonicServer::builder()
                .add_service(server)
                .serve_with_incoming_shutdown(unix_incoming, unix_shutdown)
                .await;
            if let Err(e) = result {
                warn!(target: "strait_host::listener", error = %e, "unix grpc server exited with error");
            }
        })
    };

    let tcp_incoming = TcpListenerStream::new(tcp);
    let tcp_task = {
        let server = server.clone();
        tokio::spawn(async move {
            let result = TonicServer::builder()
                .add_service(server)
                .serve_with_incoming_shutdown(tcp_incoming, tcp_shutdown)
                .await;
            if let Err(e) = result {
                warn!(target: "strait_host::listener", error = %e, "tcp grpc server exited with error");
            }
        })
    };

    // Wait for both listener tasks to exit.
    let (u, t) = tokio::join!(unix_task, tcp_task);
    if let Err(e) = u {
        warn!(target: "strait_host::listener", error = %e, "unix listener task panicked");
    }
    if let Err(e) = t {
        warn!(target: "strait_host::listener", error = %e, "tcp listener task panicked");
    }

    // Best-effort cleanup of the socket file; tonic drops the listener and
    // the socket FD but the filesystem entry can linger.
    if unix_path.exists() {
        let _ = std::fs::remove_file(&unix_path);
    }

    shutdown.signal_drained();
    Ok(())
}

/// Bind the Unix listener, removing any stale socket file and creating the
/// parent directory if needed. Sets the socket's permission bits to `mode`
/// so only the owning user can connect.
fn bind_unix(path: &Path, mode: u32) -> Result<UnixListener> {
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating parent dir {}", parent.display()))?;
        }
    }
    match std::fs::remove_file(path) {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            return Err(e).with_context(|| format!("removing stale socket {}", path.display()));
        }
    }

    let listener = UnixListener::bind(path)
        .with_context(|| format!("bind unix listener {}", path.display()))?;

    let perms = std::fs::Permissions::from_mode(mode);
    std::fs::set_permissions(path, perms)
        .with_context(|| format!("chmod unix socket {}", path.display()))?;

    Ok(listener)
}

/// Convert a tokio `UnixListener` into a stream of tonic-compatible
/// connections. The stream yields `UnixConn` values wrapping each accepted
/// `UnixStream` so tonic can read peer credentials via `UdsConnectInfo`.
fn uds_incoming(
    listener: UnixListener,
) -> impl tokio_stream::Stream<Item = std::io::Result<UnixConn>> {
    async_stream::stream! {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => yield Ok(UnixConn(stream)),
                Err(e) => yield Err(e),
            }
        }
    }
}

/// Tonic-compatible wrapper around a `tokio::net::UnixStream`. Implements
/// `Connected` so `tonic::transport::Server::serve_with_incoming` can
/// expose peer credentials to RPC handlers via `UdsConnectInfo`.
#[derive(Debug)]
pub(crate) struct UnixConn(tokio::net::UnixStream);

impl Connected for UnixConn {
    type ConnectInfo = UdsConnectInfo;

    fn connect_info(&self) -> Self::ConnectInfo {
        self.0.connect_info()
    }
}

// tokio's UnixStream already implements Connected via a blanket tonic impl,
// but that blanket impl only lights up inside tonic-internal contexts. We
// forward explicitly above so external callers can obtain the info.

impl AsyncRead for UnixConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnixConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Build a future that resolves when the shutdown watch flips to `true`.
/// Tonic's `serve_with_incoming_shutdown` takes any future; we want the
/// first `true` to win so the future resolves promptly on shutdown.
async fn shutdown_future(mut rx: watch::Receiver<bool>) {
    // If the signal is already set, return immediately.
    if *rx.borrow() {
        return;
    }
    // Otherwise wait for the next change. We ignore errors: a closed sender
    // just means the signal source is gone, which is also "time to stop".
    let _ = rx.changed().await;
}

/// Return the effective TCP listener address (for logging). The caller
/// passes the configured value; when the configured port is 0 the kernel
/// assigns one at bind time, so tests that need the real port should obtain
/// it from `TcpListener::local_addr` instead.
#[allow(dead_code)]
pub fn describe_tcp(addr: std::net::SocketAddr) -> String {
    format!("{addr}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;
    use std::time::Duration;
    use strait_proto::v1::strait_host_client::StraitHostClient;
    use strait_proto::v1::{HeartbeatRequest, RegisterContainerRequest};
    use tempfile::tempdir;
    use tokio::time::timeout;

    fn test_config(dir: &Path) -> HostConfig {
        HostConfig {
            unix_socket: dir.join("host.sock"),
            tcp_listen: "127.0.0.1:0".parse().unwrap(),
            socket_mode: 0o600,
            rules_db: dir.join("rules.db"),
            observations_log: dir.join("observations.jsonl"),
        }
    }

    async fn connect_unix(path: std::path::PathBuf) -> StraitHostClient<tonic::transport::Channel> {
        use hyper_util::rt::TokioIo;
        use tonic::transport::{Endpoint, Uri};
        use tower::service_fn;
        let endpoint = Endpoint::try_from("http://strait-host.local").unwrap();
        let channel = endpoint
            .connect_with_connector(service_fn(move |_: Uri| {
                let path = path.clone();
                async move {
                    let s = tokio::net::UnixStream::connect(&path).await?;
                    Ok::<_, std::io::Error>(TokioIo::new(s))
                }
            }))
            .await
            .expect("connect");
        StraitHostClient::new(channel)
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
    async fn unix_listener_serves_heartbeat_rpc() {
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
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(unix_path.exists(), "unix socket never appeared");

        let mut client = connect_unix(unix_path.clone()).await;
        let resp = client
            .heartbeat(HeartbeatRequest {
                sent_at_unix_ms: 777,
                ..Default::default()
            })
            .await
            .expect("heartbeat rpc")
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 777);
        assert!(resp.server_time_unix_ms >= 0);

        // A follow-up RegisterContainer RPC over the same channel proves
        // the transport keeps the connection alive between calls.
        let reg = client
            .register_container(RegisterContainerRequest {
                container_id: "c1".into(),
                ..Default::default()
            })
            .await
            .expect("register rpc")
            .into_inner();
        assert!(reg.session_id.starts_with("sess-"));

        shutdown.trigger();
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
        for _ in 0..100 {
            if tokio::net::TcpStream::connect(tcp_addr).await.is_ok() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }

        let channel = tonic::transport::Endpoint::try_from(format!("http://{tcp_addr}"))
            .unwrap()
            .connect()
            .await
            .expect("tcp connect");
        let mut client = StraitHostClient::new(channel);
        let resp = client
            .heartbeat(HeartbeatRequest {
                sent_at_unix_ms: 9,
                ..Default::default()
            })
            .await
            .expect("heartbeat rpc")
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 9);

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
            tokio::time::sleep(Duration::from_millis(20)).await;
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
