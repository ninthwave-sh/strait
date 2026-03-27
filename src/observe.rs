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
use std::path::Path;
use std::sync::Arc;

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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{BufRead, BufReader};

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
}
