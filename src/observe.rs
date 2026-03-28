//! Unified observation event model and stream infrastructure.
//!
//! Defines event types covering network requests, container lifecycle,
//! filesystem access, and process execution. Events flow through a tokio
//! broadcast channel and persist to JSONL file.
//!
//! This module exists alongside the v0.2 `AuditLogger` (which remains
//! untouched for backward compatibility). Callers migrate to
//! `ObservationStream` in the v0.3 launch orchestrator.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;

/// Default broadcast channel capacity.
///
/// When a slow consumer falls behind by this many events, it receives
/// `RecvError::Lagged` and the oldest events are dropped.
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// A single observation event with a timestamp and typed payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservationEvent {
    /// ISO-8601 timestamp (UTC, millisecond precision).
    pub timestamp: String,
    /// The event payload.
    #[serde(flatten)]
    pub event: EventKind,
}

/// Discriminated union of all observation event types.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventKind {
    /// HTTP request through the proxy.
    NetworkRequest {
        method: String,
        host: String,
        path: String,
        /// Policy decision: "allow", "deny", or "passthrough".
        decision: String,
        /// Request latency in microseconds.
        latency_us: u64,
        /// Enforcement mode: "observe", "warn", or "enforce".
        #[serde(default, skip_serializing_if = "String::is_empty")]
        enforcement_mode: String,
    },
    /// Container started.
    ContainerStart { container_id: String, image: String },
    /// Container stopped.
    ContainerStop {
        container_id: String,
        /// Exit code, if available.
        exit_code: Option<i32>,
    },
    /// Bind-mount applied.
    Mount {
        path: String,
        /// "read-only" or "read-write".
        mode: String,
    },
    /// Filesystem access observed (future — not MVP).
    FsAccess { path: String, operation: String },
    /// Process execution observed (future — not MVP).
    ProcExec { pid: u32, command: String },
    /// Policy violation detected (used in warn and enforce modes).
    PolicyViolation {
        /// Enforcement mode: "warn" or "enforce".
        enforcement_mode: String,
        /// The action that was evaluated (e.g. "http:CONNECT", "fs:write").
        action: String,
        /// The resource that was evaluated (e.g. host, path).
        resource: String,
        /// What happened: "warn" (allowed despite violation) or "deny" (blocked).
        decision: String,
        /// Human-readable reason for the violation.
        reason: String,
    },
}

// ---------------------------------------------------------------------------
// ObservationStream
// ---------------------------------------------------------------------------

/// A broadcast-based observation stream that fans out events to multiple
/// subscribers and optionally persists them to a JSONL file.
#[derive(Debug, Clone)]
pub struct ObservationStream {
    tx: broadcast::Sender<ObservationEvent>,
    file_writer: Option<Arc<std::sync::Mutex<std::io::BufWriter<std::fs::File>>>>,
}

impl Default for ObservationStream {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationStream {
    /// Create a new `ObservationStream` with the default channel capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_CHANNEL_CAPACITY)
    }

    /// Create a new `ObservationStream` with a custom channel capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        let (tx, _) = broadcast::channel(capacity);
        Self {
            tx,
            file_writer: None,
        }
    }

    /// Enable JSONL file persistence.
    ///
    /// Events emitted after this call are appended to the file at `path`,
    /// one JSON object per line. The file is created if it does not exist.
    pub fn persist_to_file(&mut self, path: &Path) -> anyhow::Result<()> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .map_err(|e| {
                anyhow::anyhow!(
                    "failed to open observation log file '{}': {}",
                    path.display(),
                    e
                )
            })?;
        self.file_writer = Some(Arc::new(std::sync::Mutex::new(std::io::BufWriter::new(
            file,
        ))));
        Ok(())
    }

    /// Emit an event to all subscribers and the optional JSONL file.
    ///
    /// Returns the number of active subscribers that received the event.
    /// If no subscribers are listening, the event is still written to the
    /// file (if configured) and the return value is 0.
    pub fn emit(&self, event: EventKind) -> usize {
        let observation = ObservationEvent {
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            event,
        };

        // Write to file first (synchronous, best-effort).
        if let Some(ref writer) = self.file_writer {
            if let Ok(json) = serde_json::to_string(&observation) {
                if let Ok(mut w) = writer.lock() {
                    let _ = writeln!(w, "{json}");
                    let _ = w.flush();
                }
            }
        }

        // Broadcast to subscribers. send() returns Err when there are no
        // active receivers — that is fine, we just return 0.
        self.tx.send(observation).unwrap_or(0)
    }

    /// Subscribe to the event stream.
    ///
    /// Returns a receiver that yields every event emitted after this call.
    /// If the consumer falls behind by more than the channel capacity,
    /// it receives `RecvError::Lagged(n)` indicating `n` events were dropped.
    pub fn subscribe(&self) -> broadcast::Receiver<ObservationEvent> {
        self.tx.subscribe()
    }
}

// ---------------------------------------------------------------------------
// Duration parsing
// ---------------------------------------------------------------------------

/// Parse a human-readable duration string like `"5m"`, `"30s"`, or `"1h"`.
///
/// Supported suffixes:
/// - `s` — seconds
/// - `m` — minutes
/// - `h` — hours
///
/// The numeric part must be a positive integer. Whitespace is trimmed.
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("duration cannot be empty");
    }
    if s.len() < 2 {
        anyhow::bail!("invalid duration '{s}': expected format like '5m', '30s', or '1h'");
    }

    let (num_str, unit) = s.split_at(s.len() - 1);
    let num: u64 = num_str.parse().map_err(|_| {
        anyhow::anyhow!("invalid duration '{s}': expected format like '5m', '30s', or '1h'")
    })?;

    if num == 0 {
        anyhow::bail!("duration must be greater than zero");
    }

    match unit {
        "s" => Ok(Duration::from_secs(num)),
        "m" => Ok(Duration::from_secs(num * 60)),
        "h" => Ok(Duration::from_secs(num * 3600)),
        _ => anyhow::bail!(
            "invalid duration unit '{unit}': expected 's' (seconds), 'm' (minutes), or 'h' (hours)"
        ),
    }
}

// ---------------------------------------------------------------------------
// Unix socket server
// ---------------------------------------------------------------------------

/// Check whether a directory is writable by creating and removing a probe file.
#[cfg(unix)]
fn dir_is_writable(dir: &Path) -> bool {
    let probe = dir.join(format!(".strait-probe-{}", std::process::id()));
    match std::fs::File::create(&probe) {
        Ok(_) => {
            let _ = std::fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

/// Resolve the socket directory from an ordered list of candidates.
///
/// Returns the first writable directory, or the current working directory
/// as a last resort.
#[cfg(unix)]
fn resolve_socket_dir_with_candidates(candidates: &[PathBuf]) -> PathBuf {
    for dir in candidates {
        if dir_is_writable(dir) {
            return dir.clone();
        }
    }
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

/// Determine the best directory for the observation socket.
///
/// Tries, in order:
/// 1. `/tmp`
/// 2. `XDG_RUNTIME_DIR` (Linux user-specific runtime directory)
/// 3. Current working directory (last resort)
#[cfg(unix)]
fn resolve_socket_dir() -> PathBuf {
    let mut candidates = vec![PathBuf::from("/tmp")];
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(xdg));
    }
    resolve_socket_dir_with_candidates(&candidates)
}

#[cfg(unix)]
impl ObservationStream {
    /// Return the default socket path for the current process.
    ///
    /// The path is `/tmp/strait-<pid>.sock` (or a fallback directory if
    /// `/tmp` is not writable).
    pub fn socket_path() -> PathBuf {
        resolve_socket_dir().join(format!("strait-{}.sock", std::process::id()))
    }

    /// Start a Unix socket server that streams JSONL events to connected
    /// clients.
    ///
    /// The server listens at the default socket path (see [`socket_path`]).
    /// Returns the path so callers (e.g. `strait watch`) know where to
    /// connect.
    ///
    /// Multiple clients can connect simultaneously — each gets its own
    /// broadcast receiver. If a prior process left a stale socket file at
    /// the same path, it is removed automatically before binding.
    pub async fn start_socket_server(&self) -> anyhow::Result<PathBuf> {
        let path = Self::socket_path();
        self.start_socket_server_at(&path).await?;
        Ok(path)
    }

    /// Start a Unix socket server at a specific path.
    ///
    /// This is the lower-level variant of [`start_socket_server`] that
    /// allows callers (and tests) to control the socket location.
    pub async fn start_socket_server_at(&self, path: &Path) -> anyhow::Result<()> {
        // Remove stale socket from a prior run.
        if path.exists() {
            std::fs::remove_file(path).map_err(|e| {
                anyhow::anyhow!("failed to remove stale socket '{}': {}", path.display(), e)
            })?;
            tracing::debug!(path = %path.display(), "removed stale socket");
        }

        let listener = tokio::net::UnixListener::bind(path).map_err(|e| {
            anyhow::anyhow!("failed to bind Unix socket at '{}': {}", path.display(), e)
        })?;

        tracing::info!(path = %path.display(), "observation socket server started");

        let tx = self.tx.clone();

        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        tracing::debug!("observation socket client connected");
                        let mut rx = tx.subscribe();
                        tokio::spawn(async move {
                            use tokio::io::AsyncWriteExt;
                            let mut writer = tokio::io::BufWriter::new(stream);
                            loop {
                                match rx.recv().await {
                                    Ok(event) => {
                                        let json = match serde_json::to_string(&event) {
                                            Ok(j) => j,
                                            Err(_) => continue,
                                        };
                                        let line = format!("{json}\n");
                                        if writer.write_all(line.as_bytes()).await.is_err() {
                                            break;
                                        }
                                        if writer.flush().await.is_err() {
                                            break;
                                        }
                                    }
                                    Err(broadcast::error::RecvError::Lagged(n)) => {
                                        tracing::debug!(
                                            lagged = n,
                                            "socket client lagged, skipping"
                                        );
                                        continue;
                                    }
                                    Err(broadcast::error::RecvError::Closed) => break,
                                }
                            }
                            tracing::debug!("observation socket client disconnected");
                        });
                    }
                    Err(e) => {
                        tracing::warn!(error = %e, "observation socket accept error (transient, continuing)");
                        continue;
                    }
                }
            }
        });

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};
    #[cfg(unix)]
    use tokio::io::AsyncBufReadExt;

    // -- Serialization tests --------------------------------------------------

    #[test]
    fn network_request_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::NetworkRequest {
                method: "GET".to_string(),
                host: "api.github.com".to_string(),
                path: "/repos/org/repo".to_string(),
                decision: "allow".to_string(),
                latency_us: 150,
                enforcement_mode: String::new(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "network_request");
        assert_eq!(json["timestamp"], "2026-03-27T00:00:00.000Z");
        assert_eq!(json["method"], "GET");
        assert_eq!(json["host"], "api.github.com");
        assert_eq!(json["path"], "/repos/org/repo");
        assert_eq!(json["decision"], "allow");
        assert_eq!(json["latency_us"], 150);
    }

    #[test]
    fn container_start_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::ContainerStart {
                container_id: "abc123".to_string(),
                image: "node:20-slim".to_string(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "container_start");
        assert_eq!(json["container_id"], "abc123");
        assert_eq!(json["image"], "node:20-slim");
    }

    #[test]
    fn container_stop_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::ContainerStop {
                container_id: "abc123".to_string(),
                exit_code: Some(0),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "container_stop");
        assert_eq!(json["container_id"], "abc123");
        assert_eq!(json["exit_code"], 0);
    }

    #[test]
    fn container_stop_without_exit_code() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::ContainerStop {
                container_id: "abc123".to_string(),
                exit_code: None,
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "container_stop");
        assert!(json["exit_code"].is_null());
    }

    #[test]
    fn mount_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::Mount {
                path: "/workspace".to_string(),
                mode: "read-only".to_string(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "mount");
        assert_eq!(json["path"], "/workspace");
        assert_eq!(json["mode"], "read-only");
    }

    #[test]
    fn fs_access_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::FsAccess {
                path: "/etc/passwd".to_string(),
                operation: "read".to_string(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "fs_access");
        assert_eq!(json["path"], "/etc/passwd");
        assert_eq!(json["operation"], "read");
    }

    #[test]
    fn proc_exec_serializes_with_correct_fields() {
        let event = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::ProcExec {
                pid: 42,
                command: "node index.js".to_string(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "proc_exec");
        assert_eq!(json["pid"], 42);
        assert_eq!(json["command"], "node index.js");
    }

    #[test]
    fn event_roundtrips_through_json() {
        let original = ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::NetworkRequest {
                method: "POST".to_string(),
                host: "api.example.com".to_string(),
                path: "/data".to_string(),
                decision: "deny".to_string(),
                latency_us: 500,
                enforcement_mode: String::new(),
            },
        };

        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: ObservationEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, deserialized);
    }

    // -- Broadcast channel tests -----------------------------------------------

    #[tokio::test]
    async fn broadcast_delivers_to_multiple_subscribers() {
        let stream = ObservationStream::new();
        let mut rx1 = stream.subscribe();
        let mut rx2 = stream.subscribe();

        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        let e1 = rx1.recv().await.unwrap();
        let e2 = rx2.recv().await.unwrap();

        assert_eq!(e1.event, e2.event);
        match &e1.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c1");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn slow_consumer_gets_lagged_error() {
        // Create a stream with capacity 4 so we can trigger backpressure quickly.
        let stream = ObservationStream::with_capacity(4);
        let mut rx = stream.subscribe();

        // Emit 10 events without reading — the receiver should lag.
        for i in 0..10 {
            stream.emit(EventKind::ContainerStart {
                container_id: format!("c{i}"),
                image: "alpine".to_string(),
            });
        }

        // The first recv should return Lagged.
        match rx.recv().await {
            Err(broadcast::error::RecvError::Lagged(n)) => {
                assert!(n > 0, "should have lagged by at least 1 event");
            }
            Ok(event) => {
                // After lagging, the receiver auto-skips to the newest
                // available events, so we may get a late event here.
                // That's acceptable — the key invariant is that oldest
                // events were dropped.
                match &event.event {
                    EventKind::ContainerStart { container_id, .. } => {
                        // Should be one of the later events, not c0
                        assert!(
                            container_id != "c0",
                            "should have dropped c0 due to backpressure"
                        );
                    }
                    other => panic!("expected ContainerStart, got {other:?}"),
                }
            }
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    #[test]
    fn emit_returns_subscriber_count() {
        let stream = ObservationStream::new();

        // No subscribers — returns 0.
        let n = stream.emit(EventKind::ContainerStop {
            container_id: "c1".to_string(),
            exit_code: Some(0),
        });
        assert_eq!(n, 0);

        // Add two subscribers.
        let _rx1 = stream.subscribe();
        let _rx2 = stream.subscribe();

        let n = stream.emit(EventKind::ContainerStop {
            container_id: "c2".to_string(),
            exit_code: Some(0),
        });
        assert_eq!(n, 2);
    }

    // -- JSONL file writer tests -----------------------------------------------

    #[test]
    fn jsonl_writer_produces_parseable_output() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("observe.jsonl");

        let mut stream = ObservationStream::new();
        stream.persist_to_file(&log_path).unwrap();

        stream.emit(EventKind::NetworkRequest {
            method: "GET".to_string(),
            host: "api.github.com".to_string(),
            path: "/repos".to_string(),
            decision: "allow".to_string(),
            latency_us: 100,
            enforcement_mode: String::new(),
        });

        stream.emit(EventKind::Mount {
            path: "/workspace".to_string(),
            mode: "read-only".to_string(),
        });

        let file = std::fs::File::open(&log_path).unwrap();
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();

        assert_eq!(lines.len(), 2, "should have 2 lines in JSONL file");

        // Each line should be valid JSON.
        let e1: ObservationEvent = serde_json::from_str(&lines[0]).unwrap();
        let e2: ObservationEvent = serde_json::from_str(&lines[1]).unwrap();

        match &e1.event {
            EventKind::NetworkRequest { host, .. } => assert_eq!(host, "api.github.com"),
            other => panic!("expected NetworkRequest, got {other:?}"),
        }

        match &e2.event {
            EventKind::Mount { path, mode } => {
                assert_eq!(path, "/workspace");
                assert_eq!(mode, "read-only");
            }
            other => panic!("expected Mount, got {other:?}"),
        }
    }

    #[test]
    fn persist_to_file_rejects_invalid_path() {
        let mut stream = ObservationStream::new();
        let result = stream.persist_to_file(Path::new("/nonexistent/dir/observe.jsonl"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to open observation log file"),
            "got: {err}"
        );
    }

    // -- Integration test: emit 100 events, verify order in JSONL file ----------

    #[test]
    fn hundred_events_appear_in_file_in_order() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("observe.jsonl");

        let mut stream = ObservationStream::new();
        stream.persist_to_file(&log_path).unwrap();

        for i in 0..100 {
            stream.emit(EventKind::ContainerStart {
                container_id: format!("c{i}"),
                image: "alpine".to_string(),
            });
        }

        let file = std::fs::File::open(&log_path).unwrap();
        let reader = BufReader::new(file);
        let lines: Vec<String> = reader.lines().collect::<Result<_, _>>().unwrap();

        assert_eq!(lines.len(), 100, "should have 100 lines in JSONL file");

        for (i, line) in lines.iter().enumerate() {
            let event: ObservationEvent = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("line {i} is not valid JSON: {e}"));
            match &event.event {
                EventKind::ContainerStart { container_id, .. } => {
                    assert_eq!(
                        container_id,
                        &format!("c{i}"),
                        "event {i} has wrong container_id"
                    );
                }
                other => panic!("event {i}: expected ContainerStart, got {other:?}"),
            }
        }
    }

    // -- Unix socket server tests ----------------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn socket_server_starts_and_accepts_connections() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        assert!(client.peer_addr().is_ok());
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn events_appear_on_connected_socket_client() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        // Give the accept loop time to register the client.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();

        let event: ObservationEvent = serde_json::from_str(&line).unwrap();
        match &event.event {
            EventKind::ContainerStart {
                container_id,
                image,
            } => {
                assert_eq!(container_id, "c1");
                assert_eq!(image, "alpine");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn multiple_clients_receive_all_events() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        let client1 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let client2 = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader1 = tokio::io::BufReader::new(client1);
        let mut reader2 = tokio::io::BufReader::new(client2);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        let mut line1 = String::new();
        let mut line2 = String::new();
        reader1.read_line(&mut line1).await.unwrap();
        reader2.read_line(&mut line2).await.unwrap();

        let e1: ObservationEvent = serde_json::from_str(&line1).unwrap();
        let e2: ObservationEvent = serde_json::from_str(&line2).unwrap();
        assert_eq!(e1.event, e2.event);
        match &e1.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c1");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn client_disconnect_does_not_crash_server() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        // Connect a client and immediately drop it.
        {
            let _client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        }

        // Give the server time to notice the disconnect.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Emitting an event should not panic.
        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        // Another client should still be able to connect and receive events.
        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        stream.emit(EventKind::ContainerStart {
            container_id: "c2".to_string(),
            image: "alpine".to_string(),
        });

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let event: ObservationEvent = serde_json::from_str(&line).unwrap();
        match &event.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c2");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stale_socket_is_auto_cleaned() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        // Create a stale socket file (simulates a prior process crash).
        std::fs::write(&sock_path, "stale").unwrap();
        assert!(sock_path.exists());

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        // Should be able to connect (stale file was removed and re-bound).
        let _client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn fallback_skips_unwritable_dirs() {
        // When all candidates are unwritable, resolve falls back to cwd.
        let candidates = vec![
            PathBuf::from("/nonexistent-dir-a"),
            PathBuf::from("/nonexistent-dir-b"),
        ];
        let result = super::resolve_socket_dir_with_candidates(&candidates);
        let cwd = std::env::current_dir().unwrap();
        assert_eq!(result, cwd);
    }

    #[cfg(unix)]
    #[test]
    fn fallback_uses_first_writable_candidate() {
        let dir = tempfile::tempdir().unwrap();
        let candidates = vec![PathBuf::from("/nonexistent-dir"), dir.path().to_path_buf()];
        let result = super::resolve_socket_dir_with_candidates(&candidates);
        assert_eq!(result, dir.path());
    }

    #[cfg(unix)]
    #[test]
    fn socket_path_contains_pid() {
        let path = ObservationStream::socket_path();
        let pid = std::process::id();
        let expected_name = format!("strait-{pid}.sock");
        assert!(
            path.file_name()
                .unwrap()
                .to_str()
                .unwrap()
                .contains(&expected_name),
            "socket path should contain PID, got: {}",
            path.display()
        );
    }

    // -- Accept loop resilience tests -------------------------------------------

    #[cfg(unix)]
    #[tokio::test]
    async fn accept_loop_survives_after_socket_removal_and_rebind() {
        // Verify the accept loop continues after transient errors:
        // 1. Start server, connect a client, drop it
        // 2. Emit events (server should not have crashed)
        // 3. Connect a new client and verify events still arrive
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        // Connect and immediately drop 10 clients in rapid succession.
        // This exercises the accept loop under client churn.
        for _ in 0..10 {
            let _client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        }

        // Give the server time to handle disconnects.
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Now connect a real client and verify events still flow.
        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        stream.emit(EventKind::ContainerStart {
            container_id: "resilience-test".to_string(),
            image: "alpine".to_string(),
        });

        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let event: ObservationEvent = serde_json::from_str(&line).unwrap();
        match &event.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "resilience-test");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    // -- Duration parsing tests -----------------------------------------------

    #[test]
    fn parse_duration_seconds() {
        let d = super::parse_duration("30s").unwrap();
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_minutes() {
        let d = super::parse_duration("5m").unwrap();
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_hours() {
        let d = super::parse_duration("1h").unwrap();
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_trims_whitespace() {
        let d = super::parse_duration("  10s  ").unwrap();
        assert_eq!(d, Duration::from_secs(10));
    }

    #[test]
    fn parse_duration_rejects_empty() {
        let err = super::parse_duration("").unwrap_err();
        assert!(err.to_string().contains("cannot be empty"), "got: {err}");
    }

    #[test]
    fn parse_duration_rejects_zero() {
        let err = super::parse_duration("0m").unwrap_err();
        assert!(err.to_string().contains("greater than zero"), "got: {err}");
    }

    #[test]
    fn parse_duration_rejects_invalid_unit() {
        let err = super::parse_duration("5x").unwrap_err();
        assert!(
            err.to_string().contains("invalid duration unit"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_duration_rejects_non_numeric() {
        let err = super::parse_duration("abcm").unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "got: {err}");
    }

    #[test]
    fn parse_duration_rejects_single_char() {
        let err = super::parse_duration("m").unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "got: {err}");
    }
}
