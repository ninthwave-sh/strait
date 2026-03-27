//! Unified observation event model, stream infrastructure, and traffic
//! observation with Cedar policy generation.
//!
//! Defines event types covering network requests, container lifecycle,
//! filesystem access, and process execution. Events flow through a tokio
//! broadcast channel and persist to JSONL file.
//!
//! The `ObservationLog` and policy generation functions support the
//! `strait init --observe` workflow: record traffic, then auto-generate
//! a permissive Cedar policy and schema from the observed requests.
//!
//! This module exists alongside the v0.2 `AuditLogger` (which remains
//! untouched for backward compatibility). Callers migrate to
//! `ObservationStream` in the v0.3 launch orchestrator.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
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
// Duration parsing
// ---------------------------------------------------------------------------

/// Parse a human-readable duration string.
///
/// Supported formats: `30s` (seconds), `5m` (minutes), `1h` (hours).
/// Returns an error for empty input, invalid numeric values, or unknown
/// suffixes.
pub fn parse_duration(s: &str) -> anyhow::Result<Duration> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty duration string");
    }
    if s.len() < 2 {
        anyhow::bail!(
            "invalid duration: '{}' — expected format like '5m', '30s', '1h'",
            s
        );
    }

    let (num_str, suffix) = s.split_at(s.len() - 1);
    let value: u64 = num_str.parse().map_err(|_| {
        anyhow::anyhow!(
            "invalid duration: '{}' — expected format like '5m', '30s', '1h'",
            s
        )
    })?;

    match suffix {
        "s" => Ok(Duration::from_secs(value)),
        "m" => Ok(Duration::from_secs(value * 60)),
        "h" => Ok(Duration::from_secs(value * 3600)),
        _ => anyhow::bail!(
            "invalid duration suffix '{}' in '{}' — expected 's', 'm', or 'h'",
            suffix,
            s
        ),
    }
}

// ---------------------------------------------------------------------------
// Path normalization
// ---------------------------------------------------------------------------

/// Check if a URL path segment looks like a dynamic identifier.
///
/// Returns `true` for:
/// - Pure digits: `42`, `123456`
/// - UUIDs: `550e8400-e29b-41d4-a716-446655440000`
/// - SHA-like hex strings: 7–40 hex characters (e.g. `abc1234`, `deadbeef`)
fn is_id_like(segment: &str) -> bool {
    if segment.is_empty() {
        return false;
    }

    // Pure digits
    if segment.chars().all(|c| c.is_ascii_digit()) {
        return true;
    }

    // UUID: 8-4-4-4-12 hex digits with dashes
    if segment.len() == 36 {
        let parts: Vec<&str> = segment.split('-').collect();
        if parts.len() == 5
            && parts[0].len() == 8
            && parts[1].len() == 4
            && parts[2].len() == 4
            && parts[3].len() == 4
            && parts[4].len() == 12
            && parts
                .iter()
                .all(|p| p.chars().all(|c| c.is_ascii_hexdigit()))
        {
            return true;
        }
    }

    // SHA-like hex hash: 7–40 hex characters
    if segment.len() >= 7 && segment.len() <= 40 && segment.chars().all(|c| c.is_ascii_hexdigit()) {
        return true;
    }

    false
}

/// Normalize a URL path by replacing ID-like segments with `*`.
///
/// Strips the leading `/` and collapses segments matching [`is_id_like`]
/// into wildcards.
///
/// # Examples
/// ```
/// # use strait::observe::normalize_path;
/// assert_eq!(normalize_path("/repos/org/repo/pulls/42"), "repos/org/repo/pulls/*");
/// assert_eq!(normalize_path("/users/550e8400-e29b-41d4-a716-446655440000"), "users/*");
/// ```
pub fn normalize_path(path: &str) -> String {
    let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    let normalized: Vec<&str> = segments
        .iter()
        .map(|s| if is_id_like(s) { "*" } else { s })
        .collect();

    normalized.join("/")
}

// ---------------------------------------------------------------------------
// ObservationLog — in-memory traffic recorder + policy generator
// ---------------------------------------------------------------------------

/// An observed HTTP request recorded during observation mode.
#[derive(Debug, Clone)]
struct ObservedRequest {
    method: String,
    host: String,
    path: String,
}

/// In-memory log of HTTP requests observed during `strait init --observe`.
///
/// Thread-safe: uses a `Mutex` internally so multiple connection handlers
/// can record concurrently.
#[derive(Debug)]
pub struct ObservationLog {
    requests: Mutex<Vec<ObservedRequest>>,
}

impl Default for ObservationLog {
    fn default() -> Self {
        Self::new()
    }
}

impl ObservationLog {
    /// Create an empty observation log.
    pub fn new() -> Self {
        Self {
            requests: Mutex::new(Vec::new()),
        }
    }

    /// Record an observed HTTP request.
    pub fn record(&self, method: &str, host: &str, path: &str) {
        let mut requests = self.requests.lock().unwrap();
        requests.push(ObservedRequest {
            method: method.to_uppercase(),
            host: host.to_string(),
            path: path.to_string(),
        });
    }

    /// Return the number of recorded requests.
    pub fn len(&self) -> usize {
        self.requests.lock().unwrap().len()
    }

    /// Return `true` if no requests have been recorded.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Generate a Cedar policy from observed traffic.
    ///
    /// Groups requests by `(method, host, normalized_path)` and emits one
    /// `permit` statement per unique combination. Observed request counts
    /// are included as comments so users understand what they are allowing.
    ///
    /// Path segments that look like IDs (UUIDs, numeric, SHA-like) are
    /// collapsed to `*` wildcards. Paths that differ only in variable
    /// segments are grouped together.
    pub fn generate_policy(&self) -> String {
        let requests = self.requests.lock().unwrap();

        // Group by (method, host, normalized_path) → count
        let mut groups: BTreeMap<(String, String, String), usize> = BTreeMap::new();
        for req in requests.iter() {
            let normalized = normalize_path(&req.path);
            let key = (req.method.clone(), req.host.clone(), normalized);
            *groups.entry(key).or_insert(0) += 1;
        }

        // Second pass: collapse paths that differ at certain positions.
        // Group by (method, host, segment_count) and merge positions that
        // have more than one distinct value into wildcards.
        let groups = collapse_variable_positions(groups);

        if groups.is_empty() {
            return "// No requests observed.\n".to_string();
        }

        let mut output = String::new();
        output.push_str("// Auto-generated by `strait init --observe`.\n");
        output.push_str("// Review and tighten before use in production.\n\n");

        for ((method, host, path), count) in &groups {
            let display_path = if path.is_empty() {
                "/".to_string()
            } else {
                format!("/{path}")
            };
            output.push_str(&format!(
                "// Observed {count} {method} {display_path} requests\n"
            ));

            // Resource: host or host/first_segment
            let segments: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
            let resource = if segments.is_empty() {
                host.clone()
            } else {
                format!("{host}/{}", segments[0])
            };

            if segments.len() <= 1 {
                output.push_str(&format!(
                    "permit(principal, action == Action::\"{method}\", resource in Resource::\"{resource}\");\n"
                ));
            } else {
                // Build path pattern for `when` clause, omitting the first segment
                // (already covered by the resource hierarchy).
                let tail_pattern = segments[1..].join("/");
                output.push_str(&format!(
                    "permit(principal, action == Action::\"{method}\", resource in Resource::\"{resource}\")\n  when {{ context.path like \"*/{tail_pattern}\" }};\n"
                ));
            }
            output.push('\n');
        }

        output.trim_end_matches('\n').to_string()
    }

    /// Generate a Cedar schema covering the entity model and observed HTTP methods.
    ///
    /// The schema is compatible with strait's policy engine entity model:
    /// `Agent` principals, `Resource` hierarchy, and `Action` for each
    /// observed HTTP method.
    pub fn generate_schema(&self) -> String {
        let requests = self.requests.lock().unwrap();
        let mut methods: BTreeSet<String> = BTreeSet::new();
        for req in requests.iter() {
            methods.insert(req.method.clone());
        }

        // Always include the standard HTTP methods so the schema isn't
        // overly narrow for future policy edits.
        for m in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            methods.insert(m.to_string());
        }

        let methods_str = methods
            .iter()
            .map(|m| format!("\"{m}\""))
            .collect::<Vec<_>>()
            .join(", ");

        format!(
            "\
// Auto-generated by `strait init --observe`.

// The calling process (agent identity).
entity Agent;

// URL path hierarchy. Each path prefix is a parent resource.
entity Resource in [Resource];

// HTTP methods observed during traffic recording.
action {methods_str}
    appliesTo {{
        principal: Agent,
        resource: Resource,
        context: {{
            \"host\": String,
            \"path\": String,
            \"method\": String,
        }},
    }};
"
        )
    }
}

/// Key for grouping paths by shape: (method, host, segment_count).
type ShapeKey = (String, String, usize);

/// A parsed path with its observation count: (segments, count).
type ShapeEntry = (Vec<String>, usize);

/// Merge observation groups that share `(method, host, segment_count)` by
/// collapsing positions where values differ into wildcards.
///
/// For example, `GET /repos/org-a/pulls` and `GET /repos/org-b/pulls` merge
/// into `GET /repos/*/pulls` with their counts summed.
fn collapse_variable_positions(
    groups: BTreeMap<(String, String, String), usize>,
) -> BTreeMap<(String, String, String), usize> {
    let mut by_shape: BTreeMap<ShapeKey, Vec<ShapeEntry>> = BTreeMap::new();

    for ((method, host, path), count) in &groups {
        let segments: Vec<String> = if path.is_empty() {
            vec![]
        } else {
            path.split('/').map(|s| s.to_string()).collect()
        };
        let key = (method.clone(), host.clone(), segments.len());
        by_shape.entry(key).or_default().push((segments, *count));
    }

    let mut merged: BTreeMap<(String, String, String), usize> = BTreeMap::new();

    for ((method, host, seg_count), entries) in &by_shape {
        if entries.len() <= 1 || *seg_count == 0 {
            // No merging needed
            for (segs, count) in entries {
                let path = segs.join("/");
                *merged
                    .entry((method.clone(), host.clone(), path))
                    .or_insert(0) += count;
            }
            continue;
        }

        // For each position, check if all entries have the same value.
        let mut merged_segments: Vec<String> = Vec::with_capacity(*seg_count);
        let mut total_count: usize = 0;
        for i in 0..*seg_count {
            let values: BTreeSet<&str> = entries.iter().map(|(segs, _)| segs[i].as_str()).collect();
            if values.len() == 1 {
                merged_segments.push(values.into_iter().next().unwrap().to_string());
            } else {
                merged_segments.push("*".to_string());
            }
        }
        for (_, count) in entries {
            total_count += count;
        }
        let path = merged_segments.join("/");
        *merged
            .entry((method.clone(), host.clone(), path))
            .or_insert(0) += total_count;
    }

    merged
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

    // -- Duration parsing tests ------------------------------------------------

    #[test]
    fn parse_duration_seconds() {
        let d = parse_duration("30s").unwrap();
        assert_eq!(d, Duration::from_secs(30));
    }

    #[test]
    fn parse_duration_minutes() {
        let d = parse_duration("5m").unwrap();
        assert_eq!(d, Duration::from_secs(300));
    }

    #[test]
    fn parse_duration_hours() {
        let d = parse_duration("1h").unwrap();
        assert_eq!(d, Duration::from_secs(3600));
    }

    #[test]
    fn parse_duration_rejects_empty() {
        let err = parse_duration("").unwrap_err();
        assert!(err.to_string().contains("empty"), "got: {err}");
    }

    #[test]
    fn parse_duration_rejects_invalid_suffix() {
        let err = parse_duration("5x").unwrap_err();
        assert!(
            err.to_string().contains("invalid duration suffix"),
            "got: {err}"
        );
    }

    #[test]
    fn parse_duration_rejects_non_numeric() {
        let err = parse_duration("abcm").unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "got: {err}");
    }

    #[test]
    fn parse_duration_rejects_single_char() {
        let err = parse_duration("m").unwrap_err();
        assert!(err.to_string().contains("invalid duration"), "got: {err}");
    }

    // -- Path normalization tests ----------------------------------------------

    #[test]
    fn normalize_path_collapses_numeric_ids() {
        assert_eq!(
            normalize_path("/repos/org/repo/pulls/42"),
            "repos/org/repo/pulls/*"
        );
    }

    #[test]
    fn normalize_path_collapses_uuids() {
        assert_eq!(
            normalize_path("/users/550e8400-e29b-41d4-a716-446655440000"),
            "users/*"
        );
    }

    #[test]
    fn normalize_path_collapses_sha_hashes() {
        assert_eq!(
            normalize_path("/repos/org/repo/commits/abc1234"),
            "repos/org/repo/commits/*"
        );
        assert_eq!(
            normalize_path("/repos/org/repo/commits/deadbeefcafe1234567890abcdef1234deadbeef"),
            "repos/org/repo/commits/*"
        );
    }

    #[test]
    fn normalize_path_preserves_non_id_segments() {
        assert_eq!(normalize_path("/repos/pulls"), "repos/pulls");
    }

    #[test]
    fn normalize_path_handles_root() {
        assert_eq!(normalize_path("/"), "");
    }

    #[test]
    fn normalize_path_handles_empty() {
        assert_eq!(normalize_path(""), "");
    }

    #[test]
    fn normalize_path_multiple_ids() {
        assert_eq!(
            normalize_path("/repos/123/issues/456/comments/789"),
            "repos/*/issues/*/comments/*"
        );
    }

    #[test]
    fn is_id_like_pure_digits() {
        assert!(is_id_like("42"));
        assert!(is_id_like("0"));
        assert!(is_id_like("123456789"));
    }

    #[test]
    fn is_id_like_uuid() {
        assert!(is_id_like("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_id_like("ABCDEF00-1234-5678-9ABC-DEF012345678"));
    }

    #[test]
    fn is_id_like_sha_hex() {
        assert!(is_id_like("abc1234")); // 7 hex chars (short SHA)
        assert!(is_id_like("deadbeefcafe1234567890abcdef1234deadbeef")); // 40 hex (full SHA)
    }

    #[test]
    fn is_id_like_rejects_short_hex() {
        assert!(!is_id_like("abc12")); // only 5 hex chars
        assert!(!is_id_like("dead")); // only 4 hex chars
    }

    #[test]
    fn is_id_like_rejects_words() {
        assert!(!is_id_like("repos"));
        assert!(!is_id_like("pulls"));
        assert!(!is_id_like("my-org"));
        assert!(!is_id_like(""));
    }

    // -- ObservationLog tests --------------------------------------------------

    #[test]
    fn observation_log_records_requests() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos/org/repo");
        log.record("POST", "api.github.com", "/repos/org/repo/pulls");
        assert_eq!(log.len(), 2);
        assert!(!log.is_empty());
    }

    #[test]
    fn observation_log_empty_by_default() {
        let log = ObservationLog::new();
        assert!(log.is_empty());
        assert_eq!(log.len(), 0);
    }

    #[test]
    fn generate_policy_single_get() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos/org/repo");

        let policy = log.generate_policy();
        assert!(policy.contains("permit("), "got:\n{policy}");
        assert!(policy.contains("Action::\"GET\""), "got:\n{policy}");
        assert!(
            policy.contains("Resource::\"api.github.com/repos\""),
            "got:\n{policy}"
        );
        assert!(policy.contains("// Observed 1 GET"), "got:\n{policy}");
    }

    #[test]
    fn generate_policy_multiple_methods() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos");
        log.record("POST", "api.github.com", "/repos");
        log.record("GET", "api.github.com", "/repos");

        let policy = log.generate_policy();
        assert!(policy.contains("Observed 2 GET"), "got:\n{policy}");
        assert!(policy.contains("Observed 1 POST"), "got:\n{policy}");
    }

    #[test]
    fn generate_policy_collapses_numeric_ids() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos/org/repo/pulls/42");
        log.record("GET", "api.github.com", "/repos/org/repo/pulls/99");

        let policy = log.generate_policy();
        // Both should merge because 42 and 99 both normalize to *
        assert!(policy.contains("Observed 2 GET"), "got:\n{policy}");
        assert!(policy.contains("pulls/*"), "got:\n{policy}");
    }

    #[test]
    fn generate_policy_variable_position_collapse() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos/org-a/pulls");
        log.record("GET", "api.github.com", "/repos/org-b/pulls");

        let policy = log.generate_policy();
        // org-a and org-b differ at position 1 → collapsed to *
        assert!(policy.contains("repos/*/pulls"), "got:\n{policy}");
        assert!(policy.contains("Observed 2 GET"), "got:\n{policy}");
    }

    #[test]
    fn generate_policy_empty_log() {
        let log = ObservationLog::new();
        let policy = log.generate_policy();
        assert!(policy.contains("No requests observed"), "got:\n{policy}");
    }

    #[test]
    fn generate_policy_root_path() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/");

        let policy = log.generate_policy();
        assert!(
            policy.contains("Resource::\"api.github.com\""),
            "got:\n{policy}"
        );
    }

    #[test]
    fn generate_schema_includes_observed_methods() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos");
        log.record("POST", "api.github.com", "/repos");

        let schema = log.generate_schema();
        assert!(schema.contains("\"GET\""), "got:\n{schema}");
        assert!(schema.contains("\"POST\""), "got:\n{schema}");
        assert!(schema.contains("entity Agent"), "got:\n{schema}");
        assert!(
            schema.contains("entity Resource in [Resource]"),
            "got:\n{schema}"
        );
        assert!(schema.contains("\"host\": String"), "got:\n{schema}");
        assert!(schema.contains("\"path\": String"), "got:\n{schema}");
    }

    #[test]
    fn generate_schema_includes_standard_methods() {
        let log = ObservationLog::new();
        log.record("GET", "api.github.com", "/repos");

        let schema = log.generate_schema();
        // Even though only GET was observed, all standard methods should be included
        assert!(schema.contains("\"DELETE\""), "got:\n{schema}");
        assert!(schema.contains("\"PUT\""), "got:\n{schema}");
        assert!(schema.contains("\"PATCH\""), "got:\n{schema}");
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
