//! Structured JSON audit logging for every policy decision.
//!
//! Every request that flows through the proxy -- whether allowed, denied, or
//! passed through without inspection -- produces a structured audit event.
//! Events are written to stderr as JSON-per-line and optionally to a file.

use std::io::Write;
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use serde::Serialize;
use uuid::Uuid;

/// A single audit event recording a policy decision.
#[derive(Debug, Serialize)]
pub struct AuditEvent {
    /// ISO-8601 timestamp.
    pub timestamp: String,
    /// Unique session identifier (generated at proxy startup).
    pub session_id: String,
    /// Request details.
    pub request: AuditRequest,
    /// Policy decision: "allow", "deny", or "passthrough".
    pub decision: String,
    /// Names of Cedar policies that contributed to the decision.
    pub matched_policies: Vec<String>,
    /// Whether a credential was injected on this request.
    pub credential_injected: bool,
    /// Policy evaluation latency in microseconds.
    pub eval_latency_us: u64,
    /// Human-readable reason for denial (present only on deny events).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub denial_reason: Option<String>,
}

/// Request metadata included in audit events.
#[derive(Debug, Serialize)]
pub struct AuditRequest {
    pub host: String,
    pub port: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub method: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Identity of the requesting agent (extracted from the identity header).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    pub mitm: bool,
}

/// Audit logger that writes events to stderr and optionally a file.
#[derive(Clone, Debug)]
pub struct AuditLogger {
    session_id: String,
    file_writer: Option<Arc<Mutex<std::io::BufWriter<std::fs::File>>>>,
}

impl AuditLogger {
    /// Create a new audit logger.
    ///
    /// If `log_path` is provided, events are also appended to that file.
    pub fn new(log_path: Option<&Path>) -> anyhow::Result<Self> {
        let file_writer = match log_path {
            Some(path) => {
                let file = std::fs::OpenOptions::new()
                    .create(true)
                    .append(true)
                    .open(path)
                    .map_err(|e| {
                        anyhow::anyhow!("failed to open audit log file '{}': {}", path.display(), e)
                    })?;
                Some(Arc::new(Mutex::new(std::io::BufWriter::new(file))))
            }
            None => None,
        };

        Ok(Self {
            session_id: Uuid::new_v4().to_string(),
            file_writer,
        })
    }

    /// Return the session ID for this logger.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Log a MITM policy decision (allow or deny).
    #[allow(clippy::too_many_arguments)]
    pub fn log_decision(
        &self,
        host: &str,
        port: u16,
        method: &str,
        path: &str,
        agent_id: &str,
        decision: &str,
        matched_policies: &[String],
        credential_injected: bool,
        denial_reason: Option<&str>,
        eval_start: Instant,
    ) {
        let eval_latency_us = eval_start.elapsed().as_micros() as u64;

        let event = AuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session_id: self.session_id.clone(),
            request: AuditRequest {
                host: host.to_string(),
                port,
                method: Some(method.to_string()),
                path: Some(path.to_string()),
                agent: Some(agent_id.to_string()),
                mitm: true,
            },
            decision: decision.to_string(),
            matched_policies: matched_policies.to_vec(),
            credential_injected,
            eval_latency_us,
            denial_reason: denial_reason.map(|s| s.to_string()),
        };

        self.emit(&event);
    }

    /// Log a passthrough CONNECT event (no MITM, no policy evaluation).
    pub fn log_passthrough(&self, host: &str, port: u16) {
        let event = AuditEvent {
            timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            session_id: self.session_id.clone(),
            request: AuditRequest {
                host: host.to_string(),
                port,
                method: None,
                path: None,
                agent: None,
                mitm: false,
            },
            decision: "passthrough".to_string(),
            matched_policies: vec![],
            credential_injected: false,
            eval_latency_us: 0,
            denial_reason: None,
        };

        self.emit(&event);
    }

    /// Serialize and write the event to stderr and optionally to a file.
    fn emit(&self, event: &AuditEvent) {
        if let Ok(json) = serde_json::to_string(event) {
            // Always write to stderr
            eprintln!("{json}");

            // Optionally write to file
            if let Some(ref writer) = self.file_writer {
                if let Ok(mut w) = writer.lock() {
                    let _ = writeln!(w, "{json}");
                    let _ = w.flush();
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn audit_event_serializes_with_all_fields() {
        let event = AuditEvent {
            timestamp: "2026-03-26T00:00:00.000Z".to_string(),
            session_id: "test-session".to_string(),
            request: AuditRequest {
                host: "api.github.com".to_string(),
                port: 443,
                method: Some("GET".to_string()),
                path: Some("/repos/org/repo".to_string()),
                agent: Some("worker".to_string()),
                mitm: true,
            },
            decision: "allow".to_string(),
            matched_policies: vec!["read-repos".to_string()],
            credential_injected: true,
            eval_latency_us: 150,
            denial_reason: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["timestamp"], "2026-03-26T00:00:00.000Z");
        assert_eq!(json["session_id"], "test-session");
        assert_eq!(json["request"]["host"], "api.github.com");
        assert_eq!(json["request"]["port"], 443);
        assert_eq!(json["request"]["method"], "GET");
        assert_eq!(json["request"]["path"], "/repos/org/repo");
        assert_eq!(json["request"]["agent"], "worker");
        assert_eq!(json["request"]["mitm"], true);
        assert_eq!(json["decision"], "allow");
        assert_eq!(json["matched_policies"], serde_json::json!(["read-repos"]));
        assert_eq!(json["credential_injected"], true);
        assert!(json["eval_latency_us"].as_u64().unwrap() > 0);
        // denial_reason should be absent on allow events
        assert!(json.get("denial_reason").is_none());
    }

    #[test]
    fn passthrough_event_omits_method_and_path() {
        let event = AuditEvent {
            timestamp: "2026-03-26T00:00:00.000Z".to_string(),
            session_id: "test-session".to_string(),
            request: AuditRequest {
                host: "example.com".to_string(),
                port: 443,
                method: None,
                path: None,
                agent: None,
                mitm: false,
            },
            decision: "passthrough".to_string(),
            matched_policies: vec![],
            credential_injected: false,
            eval_latency_us: 0,
            denial_reason: None,
        };

        let json_str = serde_json::to_string(&event).unwrap();
        assert!(
            !json_str.contains("\"method\""),
            "passthrough should not have method"
        );
        assert!(
            !json_str.contains("\"path\""),
            "passthrough should not have path"
        );
        assert!(
            !json_str.contains("\"agent\""),
            "passthrough should not have agent"
        );
        assert!(
            !json_str.contains("\"denial_reason\""),
            "passthrough should not have denial_reason"
        );

        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["request"]["mitm"], false);
        assert_eq!(json["decision"], "passthrough");
    }

    #[test]
    fn logger_creates_with_no_file() {
        let logger = AuditLogger::new(None).unwrap();
        assert!(!logger.session_id().is_empty());
    }

    #[test]
    fn logger_creates_with_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(Some(&log_path)).unwrap();
        assert!(!logger.session_id().is_empty());

        // Log a decision and verify it was written to file
        let start = Instant::now();
        logger.log_decision(
            "api.github.com",
            443,
            "GET",
            "/repos/org/repo",
            "worker",
            "allow",
            &["read-repos".to_string()],
            true,
            None,
            start,
        );

        let content = std::fs::read_to_string(&log_path).unwrap();
        assert!(!content.is_empty(), "audit log file should have content");
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert_eq!(parsed["request"]["host"], "api.github.com");
        assert_eq!(parsed["request"]["agent"], "worker");
        assert_eq!(parsed["credential_injected"], true);
        assert_eq!(
            parsed["matched_policies"],
            serde_json::json!(["read-repos"])
        );
        assert!(parsed.get("denial_reason").is_none());
    }

    #[test]
    fn logger_passthrough_writes_to_file() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(Some(&log_path)).unwrap();

        logger.log_passthrough("example.com", 443);

        let content = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "passthrough");
        assert_eq!(parsed["request"]["mitm"], false);
        assert_eq!(parsed["request"]["host"], "example.com");
    }

    #[test]
    fn logger_invalid_path_fails() {
        let result = AuditLogger::new(Some(Path::new("/nonexistent/dir/audit.jsonl")));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to open audit log file"), "got: {err}");
    }

    #[test]
    fn session_id_is_unique() {
        let l1 = AuditLogger::new(None).unwrap();
        let l2 = AuditLogger::new(None).unwrap();
        assert_ne!(l1.session_id(), l2.session_id());
    }

    // --- Enriched audit event tests ---

    #[test]
    fn matched_policies_serializes_as_json_array() {
        let event = AuditEvent {
            timestamp: "2026-03-26T00:00:00.000Z".to_string(),
            session_id: "test".to_string(),
            request: AuditRequest {
                host: "api.github.com".to_string(),
                port: 443,
                method: Some("GET".to_string()),
                path: Some("/repos".to_string()),
                agent: Some("worker".to_string()),
                mitm: true,
            },
            decision: "allow".to_string(),
            matched_policies: vec!["read-repos".to_string(), "fallback".to_string()],
            credential_injected: false,
            eval_latency_us: 50,
            denial_reason: None,
        };

        let json = serde_json::to_value(&event).unwrap();
        let policies = json["matched_policies"].as_array().unwrap();
        assert_eq!(policies.len(), 2);
        assert_eq!(policies[0], "read-repos");
        assert_eq!(policies[1], "fallback");
    }

    #[test]
    fn denial_reason_present_on_deny_events() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(Some(&log_path)).unwrap();

        let start = Instant::now();
        logger.log_decision(
            "api.github.com",
            443,
            "DELETE",
            "/repos/org/repo",
            "worker",
            "deny",
            &["deny-destructive".to_string()],
            false,
            Some("Destructive operations are not allowed"),
            start,
        );

        let content = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "deny");
        assert_eq!(
            parsed["denial_reason"],
            "Destructive operations are not allowed"
        );
    }

    #[test]
    fn denial_reason_absent_on_allow_events() {
        let dir = tempfile::tempdir().unwrap();
        let log_path = dir.path().join("audit.jsonl");
        let logger = AuditLogger::new(Some(&log_path)).unwrap();

        let start = Instant::now();
        logger.log_decision(
            "api.github.com",
            443,
            "GET",
            "/repos/org/repo",
            "worker",
            "allow",
            &["read-repos".to_string()],
            true,
            None,
            start,
        );

        let content = std::fs::read_to_string(&log_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(content.trim()).unwrap();
        assert_eq!(parsed["decision"], "allow");
        assert!(
            parsed.get("denial_reason").is_none(),
            "allow events should not have denial_reason"
        );
    }
}
