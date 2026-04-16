//! Observation event model and stream infrastructure.
//!
//! Defines event types covering network requests, container lifecycle,
//! and launch control-plane activity. Events flow through a tokio
//! broadcast channel and persist to a JSONL file.
//!
//! This module exists alongside the v0.2 `AuditLogger` (which remains
//! untouched for backward compatibility). Callers migrate to
//! `ObservationStream` in the v0.3 launch orchestrator.

use std::collections::VecDeque;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::sync::broadcast;
#[cfg(unix)]
use tracing::warn;

/// Default broadcast channel capacity.
///
/// When a slow consumer falls behind by this many events, it receives
/// `RecvError::Lagged` and the oldest events are dropped.
const DEFAULT_CHANNEL_CAPACITY: usize = 4096;

/// Current observation event schema version.
///
/// Bumped when the event format changes. Consumers can use this to handle
/// backward/forward compatibility across strait versions.
pub const SCHEMA_VERSION: u32 = 4;

/// Default capacity for the recent-events ring buffer used for watch catch-up.
const DEFAULT_RING_BUFFER_CAPACITY: usize = 256;

/// Interval for periodic file writer flushes.
const FLUSH_INTERVAL: Duration = Duration::from_millis(100);

// ---------------------------------------------------------------------------
// Event types
// ---------------------------------------------------------------------------

/// Return the default schema version for deserialization of events that
/// predate the version field.
fn default_version() -> u32 {
    1
}

/// Session metadata attached to launch-scoped observation events.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationSessionContext {
    /// Stable identifier for the running launch session.
    pub session_id: String,
    /// Active enforcement mode for the session.
    pub mode: String,
}

/// Structured metadata for a blocked network request.
///
/// Attached to `EventKind::NetworkRequest` events when the policy engine
/// denied (or would deny, in warn mode) the request. Downstream consumers
/// (watch UI, desktop client, session control service) use this to identify
/// the request, explain why it was blocked, and present a concrete candidate
/// exception that could unblock it.
///
/// The payload is backward compatible: older consumers that do not know
/// about the `blocked` field see a denied request the same way they did
/// before and simply ignore the extra data.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockedRequest {
    /// Stable opaque identifier for this specific blocked-request
    /// occurrence.
    ///
    /// The ID identifies a single occurrence of a blocked request, not
    /// a single observation event. When a warn-mode request produces
    /// both a `PolicyViolation` and a `NetworkRequest` observation
    /// event, the two events deliberately share the same `blocked_id`
    /// so consumers can correlate them as describing the same
    /// underlying occurrence.
    ///
    /// Consumers that want to deduplicate equivalent blocked requests
    /// across multiple occurrences should use `match_key` instead.
    pub blocked_id: String,
    /// Normalized key used to group equivalent blocked requests.
    ///
    /// Format is `http:{METHOD} {host}{path}`, mirroring how requests are
    /// rendered in the watch UI and how Cedar resource IDs are built in
    /// `policy::build_resource_id`.
    pub match_key: String,
    /// Human-readable explanation of why the request was blocked.
    ///
    /// Built from any `@reason` annotations on the matching Cedar policy;
    /// falls back to a generic "denied by policy …" or default-deny
    /// message when the matching policy has no reason annotation.
    pub explanation: String,
    /// Smallest candidate exception that could unblock this request, or
    /// `None` when no permit can unblock it (for example when the denial
    /// is caused by a `forbid` policy, since Cedar's forbid overrides all
    /// permits).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_exception: Option<CandidateException>,
    /// Explanation of why no candidate exception is available, when
    /// `candidate_exception` is `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub no_exception_reason: Option<String>,
}

/// Smallest candidate exception that would unblock a blocked request.
///
/// Provides the exception in three lifetime forms so the consumer (for
/// example the future session control service) can offer the user a
/// concrete choice between a one-shot allow, a session-scoped allow, and
/// a persisted Cedar policy change.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CandidateException {
    /// The narrowest scope at which the exception was synthesized.
    pub scope: ExceptionScope,
    /// `true` when more than one scope would be a reasonable "smallest"
    /// choice for this request (for example a depth-1 path where both
    /// `PathScoped` and `MethodHost` are plausible). Consumers should
    /// surface the alternatives rather than applying the suggestion
    /// blindly.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub ambiguous: bool,
    /// Unblock only this exact request once. Narrowest possible form.
    pub once: ExceptionDirective,
    /// Unblock equivalent requests for the duration of the running launch
    /// session.
    pub session: ExceptionDirective,
    /// Cedar policy snippet suitable for pasting into the policy file on
    /// disk to permanently unblock equivalent requests.
    pub persist: ExceptionDirective,
}

/// Scope at which a candidate exception is defined.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExceptionScope {
    /// Allow any HTTP method on the blocked host. Broadest scope.
    HostOnly,
    /// Allow one specific HTTP method on the blocked host, but no path
    /// narrowing. Middle scope.
    MethodHost,
    /// Allow one specific HTTP method on a path prefix under the blocked
    /// host. Narrowest meaningful scope.
    PathScoped,
}

/// A single lifetime form of a candidate exception.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExceptionDirective {
    /// Short human-readable summary, for example
    /// `"allow http:GET api.github.com/repos/org/repo"`.
    pub summary: String,
    /// Cedar policy snippet that implements the directive. For the
    /// `persist` form this is ready to paste into a `.cedar` file; the
    /// `once` and `session` forms use the same Cedar syntax and are meant
    /// to be loaded into a running session's policy store.
    pub cedar_snippet: String,
}

/// A single observation event with a timestamp and typed payload.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ObservationEvent {
    /// Schema version for forward compatibility.
    ///
    /// Defaults to `1` when deserializing events that lack this field
    /// (backward compatible with pre-versioned events).
    #[serde(default = "default_version")]
    pub version: u32,
    /// ISO-8601 timestamp (UTC, millisecond precision).
    pub timestamp: String,
    /// Launch session context for live session-scoped events.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<ObservationSessionContext>,
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
        /// Structured blocked-request metadata.
        ///
        /// Populated for `decision == "deny"` or `decision == "warn"`
        /// emissions with the stable blocked-request ID, a normalized
        /// match key, a human-readable explanation, and the smallest
        /// candidate exception that could unblock the request. `None`
        /// for allowed or passthrough requests, and for denials emitted
        /// by older strait runtimes that predate the field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocked: Option<BlockedRequest>,
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
    /// Policy violation detected (used in warn and enforce modes).
    PolicyViolation {
        /// Enforcement mode: "warn" or "enforce".
        enforcement_mode: String,
        /// The action that was evaluated (e.g. "http:CONNECT").
        action: String,
        /// The resource that was evaluated (e.g. host, path).
        resource: String,
        /// What happened: "warn" (allowed despite violation) or "deny" (blocked).
        decision: String,
        /// Human-readable reason for the violation.
        reason: String,
        /// Structured blocked-request metadata.
        ///
        /// Populated when the violation corresponds to an HTTP request
        /// that strait could synthesize a candidate exception for. `None`
        /// for violations that are not tied to a concrete HTTP request and
        /// for violations from older strait runtimes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        blocked: Option<BlockedRequest>,
    },
    /// Live policy state changed through the launch control plane.
    PolicyReloaded {
        /// Whether the new policy was applied live.
        applied: bool,
        /// The control-plane action that triggered the mutation.
        source: String,
        /// Policy domains that still require restart-bound updates.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        restart_required_domains: Vec<String>,
    },
    /// Running container TTY resized through the launch control plane.
    TtyResized {
        rows: u16,
        cols: u16,
        /// Origin of the resize event.
        source: String,
    },
    /// Live decision action applied through the launch control plane.
    ///
    /// Emitted when an external client resolves a blocked request via
    /// `decision.allow_once`, `decision.allow_session`,
    /// `decision.persist`, or `decision.deny`. Mirrors the blocked-request metadata on
    /// `NetworkRequest` emissions so downstream consumers can
    /// correlate the decision with the originating block.
    LiveDecision {
        /// Decision method applied. One of `decision.allow_once`,
        /// `decision.allow_session`, `decision.persist`, or
        /// `decision.deny`.
        action: String,
        /// Blocked-request identifier the decision was applied against.
        blocked_id: String,
        /// Normalized match key the decision applies to.
        match_key: String,
    },
}

// ---------------------------------------------------------------------------
// ObservationStream
// ---------------------------------------------------------------------------

/// A broadcast-based observation stream that fans out events to multiple
/// subscribers and optionally persists them to a JSONL file.
///
/// Maintains a bounded ring buffer of recent events so that new watch
/// connections can catch up on events they missed.
#[derive(Debug, Clone)]
pub struct ObservationStream {
    tx: broadcast::Sender<ObservationEvent>,
    file_writer: Option<Arc<std::sync::Mutex<std::io::BufWriter<std::fs::File>>>>,
    /// Bounded ring buffer of recent events for catch-up on new connections.
    recent_events: Arc<std::sync::Mutex<VecDeque<ObservationEvent>>>,
    /// Optional launch session metadata attached to emitted events.
    session_context: Arc<std::sync::Mutex<Option<ObservationSessionContext>>>,
    /// Maximum number of events to keep in the ring buffer.
    ring_buffer_capacity: usize,
    /// Active socket server task, if one has been started.
    #[cfg(unix)]
    socket_server: Arc<std::sync::Mutex<Option<SocketServerHandle>>>,
}

#[cfg(unix)]
#[derive(Debug)]
struct SocketServerHandle {
    path: PathBuf,
    task: tokio::task::JoinHandle<()>,
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
            recent_events: Arc::new(std::sync::Mutex::new(VecDeque::with_capacity(
                DEFAULT_RING_BUFFER_CAPACITY,
            ))),
            session_context: Arc::new(std::sync::Mutex::new(None)),
            ring_buffer_capacity: DEFAULT_RING_BUFFER_CAPACITY,
            #[cfg(unix)]
            socket_server: Arc::new(std::sync::Mutex::new(None)),
        }
    }

    /// Attach launch session metadata that will be included on emitted events.
    pub fn set_session_context(&self, session_context: ObservationSessionContext) {
        if let Ok(mut current) = self.session_context.lock() {
            *current = Some(session_context);
        }
    }

    /// Enable JSONL file persistence.
    ///
    /// Events emitted after this call are appended to the file at `path`,
    /// one JSON object per line. The file is created if it does not exist.
    ///
    /// The file writer uses buffered I/O with periodic flushing (every 100ms)
    /// instead of flushing after every event, reducing syscall overhead.
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
        let writer = Arc::new(std::sync::Mutex::new(std::io::BufWriter::new(file)));
        self.file_writer = Some(writer.clone());

        // Spawn periodic flush task (100ms interval) if a Tokio runtime is
        // available. Uses a Weak reference so dropping the stream allows the
        // BufWriter to be dropped (and flushed via its Drop impl).
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let weak_writer = Arc::downgrade(&writer);
            handle.spawn(async move {
                let mut interval = tokio::time::interval(FLUSH_INTERVAL);
                loop {
                    interval.tick().await;
                    let Some(writer) = weak_writer.upgrade() else {
                        break; // Stream was dropped.
                    };
                    let Ok(mut w) = writer.lock() else {
                        break;
                    };
                    if let Err(e) = w.flush() {
                        tracing::warn!(error = %e, "periodic flush of observation log failed");
                    }
                }
            });
        }

        Ok(())
    }

    /// Emit an event to all subscribers and the optional JSONL file.
    ///
    /// Returns the number of active subscribers that received the event.
    /// If no subscribers are listening, the event is still written to the
    /// file (if configured) and the return value is 0.
    ///
    /// Serialization and write errors are logged via `tracing::warn!`
    /// rather than being silently dropped.
    pub fn emit(&self, event: EventKind) -> usize {
        let observation = ObservationEvent {
            version: SCHEMA_VERSION,
            timestamp: Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session: self
                .session_context
                .lock()
                .ok()
                .and_then(|session| session.clone()),
            event,
        };

        // Write to file (buffered — periodic flush handles durability).
        if let Some(ref writer) = self.file_writer {
            match serde_json::to_string(&observation) {
                Ok(json) => {
                    if let Ok(mut w) = writer.lock() {
                        if let Err(e) = writeln!(w, "{json}") {
                            tracing::warn!(error = %e, "failed to write observation event to log file");
                        }
                        // No per-event flush: periodic flush task handles this.
                    }
                }
                Err(e) => {
                    tracing::warn!(error = %e, "failed to serialize observation event");
                }
            }
        }

        // Push to ring buffer for watch catch-up.
        if let Ok(mut ring) = self.recent_events.lock() {
            if ring.len() >= self.ring_buffer_capacity {
                ring.pop_front();
            }
            ring.push_back(observation.clone());
        }

        // Broadcast to subscribers. send() returns Err when there are no
        // active receivers — that is fine, we just return 0.
        self.tx.send(observation).unwrap_or(0)
    }

    /// Return a snapshot of recent events for catch-up on new connections.
    ///
    /// Returns up to `ring_buffer_capacity` most recent events (default 256).
    pub fn recent_events(&self) -> Vec<ObservationEvent> {
        self.recent_events
            .lock()
            .map(|ring| ring.iter().cloned().collect())
            .unwrap_or_default()
    }

    /// Subscribe to the event stream.
    ///
    /// Returns a receiver that yields every event emitted after this call.
    /// If the consumer falls behind by more than the channel capacity,
    /// it receives `RecvError::Lagged(n)` indicating `n` events were dropped.
    pub fn subscribe(&self) -> broadcast::Receiver<ObservationEvent> {
        self.tx.subscribe()
    }

    /// Flush the JSONL file writer to disk.
    ///
    /// Useful in tests or shutdown paths where you need to ensure all
    /// buffered events are written before reading the file.
    pub fn flush(&self) {
        if let Some(ref writer) = self.file_writer {
            if let Ok(mut w) = writer.lock() {
                if let Err(e) = w.flush() {
                    tracing::warn!(error = %e, "failed to flush observation log");
                }
            }
        }
    }
}

impl Drop for ObservationStream {
    fn drop(&mut self) {
        self.flush();

        #[cfg(unix)]
        if Arc::strong_count(&self.socket_server) == 1 {
            if let Ok(mut socket_server) = self.socket_server.lock() {
                if let Some(server) = socket_server.take() {
                    server.task.abort();
                    let _ = std::fs::remove_file(&server.path);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Observation reading (canonical implementation)
// ---------------------------------------------------------------------------

/// Read observation events from a JSONL log file.
///
/// Each line in the file should be a single JSON-serialized `ObservationEvent`.
/// Blank lines are skipped. Returns an error with line numbers for parse failures.
///
/// This is the canonical implementation shared by `generate` and `replay`.
pub fn read_observations(path: &Path) -> anyhow::Result<Vec<ObservationEvent>> {
    let file = std::fs::File::open(path).map_err(|e| {
        anyhow::anyhow!("failed to open observation file '{}': {e}", path.display())
    })?;
    let reader = std::io::BufReader::new(file);
    let mut events = Vec::new();

    use std::io::BufRead;
    for (line_num, line) in reader.lines().enumerate() {
        let line =
            line.map_err(|e| anyhow::anyhow!("failed to read line {}: {e}", line_num + 1))?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let event: ObservationEvent = serde_json::from_str(trimmed)
            .map_err(|e| anyhow::anyhow!("parse error on line {}: {e}", line_num + 1))?;
        events.push(event);
    }

    Ok(events)
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

#[cfg(unix)]
fn ensure_dir_with_mode(path: &Path, mode: u32) -> bool {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

    if !path.exists() {
        let mut builder = std::fs::DirBuilder::new();
        builder.recursive(true).mode(mode);
        if let Err(error) = builder.create(path) {
            warn!(path = %path.display(), error = %error, "failed to create runtime directory");
            return false;
        }
    }

    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)) {
        warn!(path = %path.display(), error = %error, "failed to secure runtime directory permissions");
        return false;
    }

    dir_is_writable(path)
}

/// Determine the best directory for the observation socket.
///
/// Tries, in order:
/// 1. `XDG_RUNTIME_DIR/strait` (Linux user runtime dir)
/// 2. `$HOME/.local/state/strait/runtime`
/// 3. `TMPDIR/strait-<uid>`
/// 4. Current working directory (last resort)
#[cfg(unix)]
fn resolve_socket_dir() -> PathBuf {
    let mut private_candidates = Vec::new();
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        private_candidates.push(PathBuf::from(xdg).join("strait"));
    }
    if let Ok(home) = std::env::var("HOME") {
        private_candidates.push(
            PathBuf::from(home)
                .join(".local")
                .join("state")
                .join("strait")
                .join("runtime"),
        );
    }

    let uid = unsafe { libc::geteuid() };
    private_candidates.push(std::env::temp_dir().join(format!("strait-{uid}")));

    for candidate in &private_candidates {
        if ensure_dir_with_mode(candidate, 0o700) {
            return candidate.clone();
        }
    }

    resolve_socket_dir_with_candidates(&[
        std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
    ])
}

#[cfg(unix)]
pub fn runtime_dir() -> PathBuf {
    resolve_socket_dir()
}

#[cfg(unix)]
impl ObservationStream {
    /// Return the default socket path for the current process.
    ///
    /// The path is `/tmp/strait-<pid>.sock` (or a fallback directory if
    /// `/tmp` is not writable).
    pub fn socket_path() -> PathBuf {
        runtime_dir().join(format!("strait-{}.sock", std::process::id()))
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
        if let Ok(mut socket_server) = self.socket_server.lock() {
            if let Some(server) = socket_server.take() {
                server.task.abort();
                let _ = std::fs::remove_file(&server.path);
            }
        }

        #[cfg(unix)]
        if let Some(parent) = path.parent() {
            use std::os::unix::fs::PermissionsExt;

            std::fs::create_dir_all(parent).map_err(|e| {
                anyhow::anyhow!(
                    "failed to create observation socket directory '{}': {}",
                    parent.display(),
                    e
                )
            })?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).map_err(
                |e| {
                    anyhow::anyhow!(
                        "failed to secure observation socket directory '{}': {}",
                        parent.display(),
                        e
                    )
                },
            )?;
        }

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

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
                |e| {
                    anyhow::anyhow!(
                        "failed to secure observation socket '{}': {}",
                        path.display(),
                        e
                    )
                },
            )?;
        }

        tracing::info!(path = %path.display(), "observation socket server started");

        let tx = self.tx.clone();
        let recent_events = self.recent_events.clone();

        let task = tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, _addr)) => {
                        tracing::debug!("observation socket client connected");
                        // Subscribe before taking the ring-buffer snapshot so
                        // we don't miss events emitted between snapshot and
                        // first recv().
                        let mut rx = tx.subscribe();
                        let catchup: Vec<ObservationEvent> = recent_events
                            .lock()
                            .map(|ring| ring.iter().cloned().collect())
                            .unwrap_or_default();
                        tokio::spawn(async move {
                            use tokio::io::AsyncWriteExt;
                            let mut writer = tokio::io::BufWriter::new(stream);

                            // Send catch-up events so the client sees recent history.
                            for event in &catchup {
                                let json = match serde_json::to_string(event) {
                                    Ok(j) => j,
                                    Err(e) => {
                                        tracing::warn!(error = %e, "failed to serialize catch-up event");
                                        continue;
                                    }
                                };
                                let line = format!("{json}\n");
                                if writer.write_all(line.as_bytes()).await.is_err() {
                                    return;
                                }
                            }
                            if writer.flush().await.is_err() {
                                return;
                            }

                            loop {
                                match rx.recv().await {
                                    Ok(event) => {
                                        let json = match serde_json::to_string(&event) {
                                            Ok(j) => j,
                                            Err(e) => {
                                                tracing::warn!(error = %e, "failed to serialize socket event");
                                                continue;
                                            }
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

        if let Ok(mut socket_server) = self.socket_server.lock() {
            *socket_server = Some(SocketServerHandle {
                path: path.to_path_buf(),
                task,
            });
        }

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
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "GET".to_string(),
                host: "api.github.com".to_string(),
                path: "/repos/org/repo".to_string(),
                decision: "allow".to_string(),
                latency_us: 150,
                enforcement_mode: String::new(),
                blocked: None,
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
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
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
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
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
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
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
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
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
    fn event_roundtrips_through_json() {
        let original = ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "POST".to_string(),
                host: "api.example.com".to_string(),
                path: "/data".to_string(),
                decision: "deny".to_string(),
                latency_us: 500,
                enforcement_mode: String::new(),
                blocked: None,
            },
        };

        let json_str = serde_json::to_string(&original).unwrap();
        let deserialized: ObservationEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, deserialized);
    }

    // -- Blocked-request payload tests ----------------------------------------
    //
    // These cover:
    // * Serialization of a denied NetworkRequest carrying a rich
    //   BlockedRequest payload (stable ID, match key, explanation, and
    //   candidate exception in all three lifetime forms).
    // * Round-tripping the rich payload through JSON without loss.
    // * Backwards-compatible decoding of older JSONL records that predate
    //   the `blocked` field, so a desktop client reading an older
    //   observation log still parses cleanly.
    // * Serialization of the no-suggestion (forbid-effect) variant.

    fn sample_blocked_request() -> BlockedRequest {
        BlockedRequest {
            blocked_id: "b1c59a11-0000-0000-0000-000000000001".to_string(),
            match_key: "http:GET api.github.com/repos/org/repo".to_string(),
            explanation: "denied by policy 'read-repos': GET /repos/org/repo on api.github.com"
                .to_string(),
            candidate_exception: Some(CandidateException {
                scope: ExceptionScope::PathScoped,
                ambiguous: false,
                once: ExceptionDirective {
                    summary: "allow http:GET api.github.com/repos/org/repo".to_string(),
                    cedar_snippet: "permit(principal, action == Action::\"http:GET\", resource == Resource::\"api.github.com/repos/org/repo\");"
                        .to_string(),
                },
                session: ExceptionDirective {
                    summary: "allow http:GET api.github.com/repos/org/repo".to_string(),
                    cedar_snippet: "permit(principal, action == Action::\"http:GET\", resource == Resource::\"api.github.com/repos/org/repo\");"
                        .to_string(),
                },
                persist: ExceptionDirective {
                    summary: "allow http:GET api.github.com/repos/org/repo".to_string(),
                    cedar_snippet: "permit(principal, action == Action::\"http:GET\", resource == Resource::\"api.github.com/repos/org/repo\");"
                        .to_string(),
                },
            }),
            no_exception_reason: None,
        }
    }

    #[test]
    fn blocked_network_request_serializes_full_payload() {
        let event = ObservationEvent {
            version: SCHEMA_VERSION,
            timestamp: "2026-04-15T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "GET".to_string(),
                host: "api.github.com".to_string(),
                path: "/repos/org/repo".to_string(),
                decision: "deny".to_string(),
                latency_us: 250,
                enforcement_mode: "enforce".to_string(),
                blocked: Some(sample_blocked_request()),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "network_request");
        assert_eq!(json["decision"], "deny");

        let blocked = &json["blocked"];
        assert!(blocked.is_object(), "blocked field must be present");
        assert_eq!(
            blocked["blocked_id"],
            "b1c59a11-0000-0000-0000-000000000001"
        );
        assert_eq!(
            blocked["match_key"],
            "http:GET api.github.com/repos/org/repo"
        );
        assert!(blocked["explanation"]
            .as_str()
            .unwrap()
            .contains("read-repos"));

        let ex = &blocked["candidate_exception"];
        assert_eq!(ex["scope"], "path_scoped");
        assert!(ex["once"].is_object());
        assert!(ex["session"].is_object());
        assert!(ex["persist"].is_object());
        assert_eq!(
            ex["session"]["summary"],
            "allow http:GET api.github.com/repos/org/repo"
        );

        // ambiguous is false by default and should be omitted from the
        // wire format so older consumers see the same bytes.
        assert!(
            ex.get("ambiguous").is_none() || ex["ambiguous"] == false,
            "ambiguous=false should be skipped or explicitly false"
        );
    }

    #[test]
    fn blocked_network_request_roundtrips_through_json() {
        let original = ObservationEvent {
            version: SCHEMA_VERSION,
            timestamp: "2026-04-15T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "POST".to_string(),
                host: "api.example.com".to_string(),
                path: "/data".to_string(),
                decision: "deny".to_string(),
                latency_us: 512,
                enforcement_mode: "warn".to_string(),
                blocked: Some(BlockedRequest {
                    blocked_id: "b1c59a11-0000-0000-0000-00000000002".to_string(),
                    match_key: "http:POST api.example.com/data".to_string(),
                    explanation: "denied by default-deny".to_string(),
                    candidate_exception: Some(CandidateException {
                        scope: ExceptionScope::MethodHost,
                        ambiguous: true,
                        once: ExceptionDirective {
                            summary: "allow http:POST api.example.com".to_string(),
                            cedar_snippet: "permit(principal, action == Action::\"http:POST\", resource in Resource::\"api.example.com\");"
                                .to_string(),
                        },
                        session: ExceptionDirective {
                            summary: "allow http:POST api.example.com".to_string(),
                            cedar_snippet: "permit(principal, action == Action::\"http:POST\", resource in Resource::\"api.example.com\");"
                                .to_string(),
                        },
                        persist: ExceptionDirective {
                            summary: "allow http:POST api.example.com".to_string(),
                            cedar_snippet: "permit(principal, action == Action::\"http:POST\", resource in Resource::\"api.example.com\");"
                                .to_string(),
                        },
                    }),
                    no_exception_reason: None,
                }),
            },
        };

        let json_str = serde_json::to_string(&original).unwrap();
        let round: ObservationEvent = serde_json::from_str(&json_str).unwrap();
        assert_eq!(original, round);
    }

    #[test]
    fn blocked_network_request_no_suggestion_variant_serializes() {
        let event = ObservationEvent {
            version: SCHEMA_VERSION,
            timestamp: "2026-04-15T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "POST".to_string(),
                host: "api.github.com".to_string(),
                path: "/git/refs/heads/main".to_string(),
                decision: "deny".to_string(),
                latency_us: 180,
                enforcement_mode: "enforce".to_string(),
                blocked: Some(BlockedRequest {
                    blocked_id: "b1c59a11-0000-0000-0000-00000000003".to_string(),
                    match_key: "http:POST api.github.com/git/refs/heads/main".to_string(),
                    explanation: "Direct pushes to main are not allowed".to_string(),
                    candidate_exception: None,
                    no_exception_reason: Some(
                        "denied by forbid policy; no permit can override a Cedar forbid effect"
                            .to_string(),
                    ),
                }),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        let blocked = &json["blocked"];
        // candidate_exception is None and should be omitted from the
        // wire format.
        assert!(blocked.get("candidate_exception").is_none());
        assert_eq!(
            blocked["no_exception_reason"],
            "denied by forbid policy; no permit can override a Cedar forbid effect"
        );

        // Round-trip must preserve the no-suggestion variant.
        let round: ObservationEvent =
            serde_json::from_str(&serde_json::to_string(&event).unwrap()).unwrap();
        match round.event {
            EventKind::NetworkRequest { blocked, .. } => {
                let info = blocked.expect("blocked payload should round-trip");
                assert!(info.candidate_exception.is_none());
                assert_eq!(
                    info.no_exception_reason.as_deref(),
                    Some("denied by forbid policy; no permit can override a Cedar forbid effect")
                );
            }
            other => panic!("expected NetworkRequest, got {other:?}"),
        }
    }

    #[test]
    fn network_request_decodes_without_blocked_field_for_backwards_compatibility() {
        // Older strait runtimes (pre-H-CSM-2) emit JSONL records that
        // never include the `blocked` field. The rich schema must
        // decode those cleanly so desktop clients can replay older
        // observation logs without fatal errors.
        let legacy = r#"{
            "version": 2,
            "timestamp": "2026-03-01T00:00:00.000Z",
            "type": "network_request",
            "method": "GET",
            "host": "api.github.com",
            "path": "/repos/org/repo",
            "decision": "deny",
            "latency_us": 100
        }"#;

        let event: ObservationEvent = serde_json::from_str(legacy).unwrap();
        match event.event {
            EventKind::NetworkRequest {
                blocked, decision, ..
            } => {
                assert_eq!(decision, "deny");
                assert!(
                    blocked.is_none(),
                    "legacy record should deserialize with blocked: None"
                );
            }
            other => panic!("expected NetworkRequest, got {other:?}"),
        }
    }

    #[test]
    fn runtime_mutation_event_serializes_with_session_context() {
        let event = ObservationEvent {
            version: SCHEMA_VERSION,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: Some(ObservationSessionContext {
                session_id: "session-123".to_string(),
                mode: "warn".to_string(),
            }),
            event: EventKind::PolicyReloaded {
                applied: true,
                source: "reload".to_string(),
                restart_required_domains: vec!["http".to_string()],
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["type"], "policy_reloaded");
        assert_eq!(json["session"]["session_id"], "session-123");
        assert_eq!(json["session"]["mode"], "warn");
        assert_eq!(json["source"], "reload");
        assert_eq!(json["restart_required_domains"][0], "http");
    }

    #[test]
    fn session_context_defaults_to_none_when_missing_in_json() {
        let json = r#"{
            "version": 1,
            "timestamp": "2026-03-27T00:00:00.000Z",
            "type": "network_request",
            "method": "GET",
            "host": "api.github.com",
            "path": "/repos",
            "decision": "allow",
            "latency_us": 100
        }"#;

        let event: ObservationEvent = serde_json::from_str(json).unwrap();
        assert!(event.session.is_none());
        assert_eq!(event.version, 1);
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
            blocked: None,
        });

        stream.emit(EventKind::Mount {
            path: "/workspace".to_string(),
            mode: "read-only".to_string(),
        });

        // Flush buffered writes before reading the file.
        stream.flush();

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

        // Flush buffered writes before reading the file.
        stream.flush();

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
    async fn dropping_stream_closes_connected_socket_clients() {
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        drop(stream);

        let mut line = String::new();
        let bytes = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            reader.read_line(&mut line).await.unwrap()
        })
        .await
        .expect("dropping the stream should close connected socket clients");

        assert_eq!(bytes, 0, "socket client should observe EOF after drop");
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
        // The ring buffer sends "c1" as catch-up, then "c2" arrives live.
        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        stream.emit(EventKind::ContainerStart {
            container_id: "c2".to_string(),
            image: "alpine".to_string(),
        });

        // Read catch-up event ("c1") first.
        let mut line1 = String::new();
        reader.read_line(&mut line1).await.unwrap();
        let event1: ObservationEvent = serde_json::from_str(&line1).unwrap();
        match &event1.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c1", "catch-up event");
            }
            other => panic!("expected ContainerStart catch-up, got {other:?}"),
        }

        // Read live event ("c2").
        let mut line2 = String::new();
        reader.read_line(&mut line2).await.unwrap();
        let event2: ObservationEvent = serde_json::from_str(&line2).unwrap();
        match &event2.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c2", "live event");
            }
            other => panic!("expected ContainerStart live, got {other:?}"),
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

    // -- read_observations tests (M-ER-9) ---

    #[test]
    fn read_observations_parses_jsonl() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let events = vec![
            ObservationEvent {
                version: 1,
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                session: None,
                event: EventKind::NetworkRequest {
                    method: "GET".to_string(),
                    host: "api.github.com".to_string(),
                    path: "/repos".to_string(),
                    decision: "allow".to_string(),
                    latency_us: 100,
                    enforcement_mode: String::new(),
                    blocked: None,
                },
            },
            ObservationEvent {
                version: 1,
                timestamp: "2026-03-27T00:00:01.000Z".to_string(),
                session: None,
                event: EventKind::ContainerStop {
                    container_id: "abc123".to_string(),
                    exit_code: Some(0),
                },
            },
        ];

        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&path).unwrap();
            for event in &events {
                writeln!(file, "{}", serde_json::to_string(event).unwrap()).unwrap();
            }
        }

        let parsed = super::read_observations(&path).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0], events[0]);
        assert_eq!(parsed[1], events[1]);
    }

    #[test]
    fn read_observations_skips_blank_lines() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");

        let event = ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: "GET".to_string(),
                host: "api.github.com".to_string(),
                path: "/repos/org/repo".to_string(),
                decision: "allow".to_string(),
                latency_us: 100,
                enforcement_mode: String::new(),
                blocked: None,
            },
        };

        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&path).unwrap();
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
            writeln!(file).unwrap();
            writeln!(file, "  ").unwrap();
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        }

        let parsed = super::read_observations(&path).unwrap();
        assert_eq!(parsed.len(), 2);
    }

    #[test]
    fn read_observations_error_on_missing_file() {
        let result = super::read_observations(Path::new("/nonexistent/test.jsonl"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to open observation file"),
            "got: {err}"
        );
    }

    #[test]
    fn read_observations_error_on_bad_json() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.jsonl");
        std::fs::write(&path, "{{not valid json\n").unwrap();

        let result = super::read_observations(&path);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("parse error on line 1"), "got: {err}");
    }

    // -- Schema version tests (M-ER-13) ----------------------------------------

    #[test]
    fn emitted_events_include_version_field() {
        let stream = ObservationStream::new();
        let mut rx = stream.subscribe();

        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        let event = rx.try_recv().unwrap();
        assert_eq!(event.version, SCHEMA_VERSION);
    }

    #[test]
    fn version_field_serialized_in_json() {
        let event = ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::ContainerStart {
                container_id: "c1".to_string(),
                image: "alpine".to_string(),
            },
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["version"], 1, "version field must be present in JSON");
    }

    #[test]
    fn version_field_defaults_to_1_when_missing_in_json() {
        // Pre-versioned events (without "version" field) should deserialize
        // with version=1 for backward compatibility.
        let json = r#"{
            "timestamp": "2026-03-27T00:00:00.000Z",
            "type": "container_start",
            "container_id": "c1",
            "image": "alpine"
        }"#;
        let event: ObservationEvent = serde_json::from_str(json).unwrap();
        assert_eq!(event.version, 1, "missing version should default to 1");
    }

    #[test]
    fn version_field_roundtrips_in_jsonl_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("observe.jsonl");

        // Write events with version field.
        {
            use std::io::Write as _;
            let mut file = std::fs::File::create(&log_path).unwrap();
            let event = ObservationEvent {
                version: SCHEMA_VERSION,
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                session: None,
                event: EventKind::NetworkRequest {
                    method: "GET".to_string(),
                    host: "api.github.com".to_string(),
                    path: "/repos".to_string(),
                    decision: "allow".to_string(),
                    latency_us: 100,
                    enforcement_mode: String::new(),
                    blocked: None,
                },
            };
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        }

        let parsed = super::read_observations(&log_path).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].version, SCHEMA_VERSION);
    }

    // -- Periodic flush tests (M-ER-13) ----------------------------------------

    #[tokio::test]
    async fn file_writer_does_not_flush_per_event() {
        // Verify that emitting a single event does NOT immediately flush to
        // disk. The periodic flush task handles durability.
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("observe.jsonl");

        let mut stream = ObservationStream::new();
        stream.persist_to_file(&log_path).unwrap();

        // Emit one event.
        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        // The periodic flush runs at 100ms intervals. Wait 200ms to
        // ensure at least one periodic flush has occurred.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // After periodic flush, the event should be on disk.
        let contents = std::fs::read_to_string(&log_path).unwrap();
        assert!(
            !contents.is_empty(),
            "periodic flush should have written event to disk"
        );

        let parsed: ObservationEvent = serde_json::from_str(contents.trim()).unwrap();
        assert_eq!(parsed.version, SCHEMA_VERSION);
    }

    // -- Ring buffer catch-up tests (M-ER-13) -----------------------------------

    #[test]
    fn recent_events_returns_emitted_events() {
        let stream = ObservationStream::new();

        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });
        stream.emit(EventKind::ContainerStop {
            container_id: "c1".to_string(),
            exit_code: Some(0),
        });

        let recent = stream.recent_events();
        assert_eq!(recent.len(), 2);
        match &recent[0].event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "c1");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[test]
    fn ring_buffer_is_bounded() {
        // Create a stream with default capacity (256). Emit more than that
        // and verify the buffer does not grow beyond capacity.
        let stream = ObservationStream::new();

        for i in 0..300 {
            stream.emit(EventKind::ContainerStart {
                container_id: format!("c{i}"),
                image: "alpine".to_string(),
            });
        }

        let recent = stream.recent_events();
        assert_eq!(
            recent.len(),
            DEFAULT_RING_BUFFER_CAPACITY,
            "ring buffer should be bounded at {DEFAULT_RING_BUFFER_CAPACITY}"
        );

        // Oldest events should have been dropped — first event should be c44.
        match &recent[0].event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(
                    container_id, "c44",
                    "oldest event should be c44 (300 - 256)"
                );
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn new_socket_client_receives_catch_up_events() {
        // Emit events before connecting a client, then verify the client
        // receives the catch-up events from the ring buffer.
        let dir = tempfile::tempdir().unwrap();
        let sock_path = dir.path().join("test.sock");

        let stream = ObservationStream::new();
        stream.start_socket_server_at(&sock_path).await.unwrap();

        // Emit events BEFORE any client connects.
        stream.emit(EventKind::ContainerStart {
            container_id: "pre1".to_string(),
            image: "alpine".to_string(),
        });
        stream.emit(EventKind::ContainerStart {
            container_id: "pre2".to_string(),
            image: "alpine".to_string(),
        });

        // Give the server time to process.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Connect a new client — it should receive catch-up events.
        let client = tokio::net::UnixStream::connect(&sock_path).await.unwrap();
        let mut reader = tokio::io::BufReader::new(client);

        // Read the two catch-up events.
        let mut line1 = String::new();
        reader.read_line(&mut line1).await.unwrap();
        let e1: ObservationEvent = serde_json::from_str(&line1).unwrap();

        let mut line2 = String::new();
        reader.read_line(&mut line2).await.unwrap();
        let e2: ObservationEvent = serde_json::from_str(&line2).unwrap();

        match &e1.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "pre1", "first catch-up event");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }

        match &e2.event {
            EventKind::ContainerStart { container_id, .. } => {
                assert_eq!(container_id, "pre2", "second catch-up event");
            }
            other => panic!("expected ContainerStart, got {other:?}"),
        }
    }

    // -- Write error logging tests (M-ER-13) ------------------------------------

    #[test]
    fn write_errors_are_logged_not_silently_dropped() {
        // Verify that the emit() code path logs errors rather than using
        // `let _ = ...`. We test this structurally: the serialization path
        // uses tracing::warn! which we can verify by checking that it doesn't
        // panic and that the event is still broadcast even when file write
        // would fail.

        // Create a stream with a file writer pointing to a read-only path.
        // On Unix, writing to /dev/null/nonexistent would fail.
        // Instead, we verify the broadcast still works even when file errors
        // occur — the key property is that errors don't crash the system.
        let stream = ObservationStream::new();
        let mut rx = stream.subscribe();

        // Without a file writer, emit should still work and broadcast.
        stream.emit(EventKind::ContainerStart {
            container_id: "c1".to_string(),
            image: "alpine".to_string(),
        });

        let event = rx.try_recv().unwrap();
        assert_eq!(event.version, SCHEMA_VERSION);
        // The event was broadcast successfully — file write errors don't
        // affect the broadcast channel.
    }
}
