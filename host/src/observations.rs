//! Observation pipeline for `strait-host` (M-HCP-5).
//!
//! The in-container agent streams observation events upstream via the
//! `StreamObservations` gRPC client-streaming RPC. The host forwards every
//! event it accepts to two sinks:
//!
//!   1. A JSONL file on disk at the configured path (defaults to
//!      `~/.local/share/strait/observations.jsonl`). Events are augmented
//!      with `session_id` and `container_registration_id` as top-level JSON
//!      keys so downstream tools (the desktop UI, `strait generate`, and
//!      `strait test --replay`) can distinguish sessions without digging
//!      into the nested `session` context.
//!   2. An in-memory broadcast channel that desktop sessions and
//!      `strait watch`-style CLI clients subscribe to through the new
//!      `SubscribeObservations` server-streaming RPC.
//!
//! The schema inside each JSONL line is the strait v0.3 `ObservationEvent`
//! shape defined in `strait::observe`. The agent serializes one of those
//! values and places it in `raw_json`; the host writes the same text back
//! out verbatim, only merging two extra top-level keys. That keeps the
//! disk format backward compatible: `strait::observe::read_observations`
//! ignores the extra keys because the struct does not declare
//! `deny_unknown_fields`.
//!
//! The hub is deliberately cheap to clone: every sink is behind an `Arc`.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Map, Value};
use strait_proto::v1::ObservationEvent as WireObservation;
use tokio::sync::broadcast;
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;

/// Broadcast channel capacity for live observation fan-out.
///
/// Large enough to absorb a burst across a handful of registered sessions
/// without lagging a slow desktop subscriber; small enough that a wedged
/// subscriber cannot keep unbounded memory pinned.
const BROADCAST_CAPACITY: usize = 1024;

/// Shared observation sink used by both the gRPC server and integration tests.
///
/// Construct one hub per host process and clone it into the
/// [`crate::grpc::StraitHostService`]. Cloning is cheap -- all state sits
/// behind `Arc`.
#[derive(Debug, Clone)]
pub struct ObservationHub {
    tx: broadcast::Sender<WireObservation>,
    file: Arc<ObservationFile>,
}

#[derive(Debug)]
struct ObservationFile {
    path: PathBuf,
    writer: AsyncMutex<tokio::fs::File>,
}

impl ObservationHub {
    /// Open the JSONL log at `path`, creating the parent directory and the
    /// file itself if missing. Subsequent calls to
    /// [`ObservationHub::record`] append to this file.
    pub async fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                tokio::fs::create_dir_all(parent).await.with_context(|| {
                    format!("creating observations log dir {}", parent.display())
                })?;
            }
        }
        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("opening observations log {}", path.display()))?;

        let (tx, _rx) = broadcast::channel(BROADCAST_CAPACITY);
        Ok(Self {
            tx,
            file: Arc::new(ObservationFile {
                path: path.to_path_buf(),
                writer: AsyncMutex::new(file),
            }),
        })
    }

    /// Path the hub persists events to. Exposed for tests and operator
    /// diagnostics; production code should treat this as read-only.
    pub fn path(&self) -> &Path {
        &self.file.path
    }

    /// Subscribe to the live observation stream. Each subscriber sees every
    /// event accepted after [`ObservationHub::subscribe`] returns; there is
    /// no replay. Desktop consumers that need history read the JSONL file
    /// separately.
    pub fn subscribe(&self) -> broadcast::Receiver<WireObservation> {
        self.tx.subscribe()
    }

    /// Number of currently-attached subscribers. Intended for tests and
    /// diagnostics -- do not branch on this value in production code.
    pub fn subscriber_count(&self) -> usize {
        self.tx.receiver_count()
    }

    /// Accept a single observation from a streaming agent connection.
    ///
    /// The event is augmented with `session_id` and
    /// `container_registration_id` top-level keys, appended to the JSONL
    /// log, and broadcast to subscribers. Returns `Ok(())` on success; the
    /// gRPC layer treats any error as a rejected event.
    pub async fn record(&self, event: WireObservation) -> Result<()> {
        let line = build_jsonl_line(&event)?;
        {
            use tokio::io::AsyncWriteExt;
            let mut guard = self.file.writer.lock().await;
            guard
                .write_all(line.as_bytes())
                .await
                .context("append observation line")?;
            guard.flush().await.context("flush observation log")?;
        }
        if self.tx.send(event).is_err() {
            // No active subscribers; that's fine. The event is still
            // durably logged. We only reach here when every receiver has
            // been dropped, and the broadcast channel returns Err in that
            // case to avoid leaking memory.
        }
        Ok(())
    }
}

/// Serialize a wire observation event into a JSONL line (including the
/// terminating newline) with the two M-HCP-5 top-level keys merged in.
///
/// Visible for tests so they can assert the on-disk shape without invoking
/// the async writer.
fn build_jsonl_line(event: &WireObservation) -> Result<String> {
    let mut value: Value = if event.raw_json.trim().is_empty() {
        // Older agents / tests might send an empty payload; emit a minimal
        // object so the injected top-level keys still round-trip.
        Value::Object(Map::new())
    } else {
        serde_json::from_str(&event.raw_json)
            .with_context(|| format!("parse observation raw_json: {}", event.raw_json))?
    };

    if let Value::Object(ref mut map) = value {
        // Agents that persist locally already write `session_id` / `container_
        // registration_id` at the top level; respect those if present, but
        // make sure every line carries whatever the wire envelope supplied.
        if !event.session_id.is_empty() {
            map.insert(
                "session_id".to_string(),
                Value::String(event.session_id.clone()),
            );
        }
        if !event.container_registration_id.is_empty() {
            map.insert(
                "container_registration_id".to_string(),
                Value::String(event.container_registration_id.clone()),
            );
        }
    } else {
        anyhow::bail!(
            "observation raw_json must be a JSON object, got: {}",
            event.raw_json
        );
    }

    let mut s = serde_json::to_string(&value).context("serialize augmented observation")?;
    s.push('\n');
    Ok(s)
}

/// Test-only accessor so the integration tests can build the same on-disk
/// line the hub would emit without spinning up a tokio file handle.
#[doc(hidden)]
pub fn render_jsonl_line(event: &WireObservation) -> Result<String> {
    build_jsonl_line(event)
}

impl ObservationHub {
    /// Best-effort warning when the broadcast channel reports the subscriber
    /// fell behind. Used by the gRPC server-streaming impl to keep logs
    /// consistent with the pattern in `StreamRules`.
    pub(crate) fn warn_lagged(session_id: &str, skipped: u64) {
        warn!(
            target: "strait_host::observations",
            session_id = %session_id,
            skipped,
            "observation subscriber lagged"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn wire_event(session_id: &str, reg_id: &str, raw_json: &str) -> WireObservation {
        WireObservation {
            session_id: session_id.into(),
            container_registration_id: reg_id.into(),
            observation_id: "obs-1".into(),
            observed_at_unix_ms: 12345,
            raw_json: raw_json.into(),
        }
    }

    #[test]
    fn build_jsonl_line_merges_top_level_keys() {
        let inner = r#"{"version":4,"timestamp":"2026-04-17T00:00:00Z","type":"container_start","container_id":"c1","image":"alpine"}"#;
        let line = build_jsonl_line(&wire_event("sess-1", "reg-A", inner)).unwrap();
        assert!(line.ends_with('\n'), "line must end with newline");
        let trimmed = line.trim_end_matches('\n');
        let parsed: Value = serde_json::from_str(trimmed).unwrap();
        assert_eq!(parsed["session_id"], "sess-1");
        assert_eq!(parsed["container_registration_id"], "reg-A");
        // Original keys must still be intact.
        assert_eq!(parsed["type"], "container_start");
        assert_eq!(parsed["image"], "alpine");
        assert_eq!(parsed["version"], 4);
    }

    #[test]
    fn build_jsonl_line_preserves_agent_supplied_keys() {
        // If the agent already wrote session_id/container_registration_id at
        // the top level (as local file tooling might), the wire envelope
        // wins. This keeps the persisted file canonical against the host's
        // view of who produced what.
        let inner = r#"{"version":4,"timestamp":"2026-04-17T00:00:01Z","type":"container_stop","container_id":"c1","exit_code":0,"session_id":"agent-picked","container_registration_id":"agent-picked"}"#;
        let line = build_jsonl_line(&wire_event("host-picked", "host-picked", inner)).unwrap();
        let parsed: Value = serde_json::from_str(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed["session_id"], "host-picked");
        assert_eq!(parsed["container_registration_id"], "host-picked");
    }

    #[test]
    fn build_jsonl_line_rejects_non_object_payload() {
        let err = build_jsonl_line(&wire_event("s", "r", "\"a string\"")).unwrap_err();
        let msg = format!("{err:#}");
        assert!(msg.contains("must be a JSON object"), "unexpected: {msg}");
    }

    #[test]
    fn build_jsonl_line_tolerates_empty_raw_json() {
        let line = build_jsonl_line(&wire_event("sess-x", "reg-x", "")).unwrap();
        let parsed: Value = serde_json::from_str(line.trim_end_matches('\n')).unwrap();
        assert_eq!(parsed["session_id"], "sess-x");
        assert_eq!(parsed["container_registration_id"], "reg-x");
    }

    #[tokio::test]
    async fn record_appends_one_line_per_call() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("observations.jsonl");
        let hub = ObservationHub::open(&path).await.unwrap();

        let a = wire_event(
            "sess-A",
            "reg-A",
            r#"{"version":4,"timestamp":"t1","type":"container_start","container_id":"c","image":"i"}"#,
        );
        let b = wire_event(
            "sess-B",
            "reg-B",
            r#"{"version":4,"timestamp":"t2","type":"container_stop","container_id":"c","exit_code":0}"#,
        );
        hub.record(a).await.unwrap();
        hub.record(b).await.unwrap();

        let body = tokio::fs::read_to_string(&path).await.unwrap();
        let lines: Vec<&str> = body.lines().collect();
        assert_eq!(lines.len(), 2, "expected two JSONL lines, got {lines:?}");
        let first: Value = serde_json::from_str(lines[0]).unwrap();
        let second: Value = serde_json::from_str(lines[1]).unwrap();
        assert_eq!(first["session_id"], "sess-A");
        assert_eq!(second["session_id"], "sess-B");
    }

    #[tokio::test]
    async fn subscribers_receive_live_events() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("observations.jsonl");
        let hub = ObservationHub::open(&path).await.unwrap();
        let mut rx = hub.subscribe();

        let evt = wire_event(
            "sess-1",
            "reg-1",
            r#"{"version":4,"timestamp":"t","type":"container_start","container_id":"c","image":"i"}"#,
        );
        hub.record(evt.clone()).await.unwrap();
        let received = tokio::time::timeout(std::time::Duration::from_secs(1), rx.recv())
            .await
            .expect("recv timed out")
            .expect("channel closed");
        assert_eq!(received.session_id, "sess-1");
        assert_eq!(received.container_registration_id, "reg-1");
    }

    #[tokio::test]
    async fn subscriber_drop_does_not_prevent_persistence() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("observations.jsonl");
        let hub = ObservationHub::open(&path).await.unwrap();
        // No subscribers attached; the broadcast send returns Err but that
        // must not fail the whole record call.
        let evt = wire_event(
            "sess-X",
            "reg-X",
            r#"{"version":4,"timestamp":"t","type":"container_start","container_id":"c","image":"i"}"#,
        );
        hub.record(evt).await.unwrap();
        let body = tokio::fs::read_to_string(&path).await.unwrap();
        assert!(body.contains("sess-X"));
    }
}
