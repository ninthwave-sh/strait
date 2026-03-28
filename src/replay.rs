//! Replay engine for testing Cedar policies against observation logs.
//!
//! Reads a JSONL observation log (produced by `ObservationStream`) and
//! evaluates every event against a specified Cedar policy. Reports
//! matches, mismatches, and skipped events.
//!
//! Exit code: 0 when all evaluable events match the policy, 1 on any mismatch.

use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str::FromStr;

use cedar_policy::{
    Authorizer, Context, Decision, EntityId, EntityTypeName, EntityUid, PolicySet, Request,
    RestrictedExpression,
};

use crate::credentials::parse_aws_host;
use crate::observe::{EventKind, ObservationEvent};
use crate::policy::{
    build_fs_entities, build_http_entity_hierarchy, build_proc_entities, escape_cedar_string,
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of replaying an observation log against a Cedar policy.
#[derive(Debug)]
pub struct ReplayResult {
    /// Total number of events in the log.
    pub total: usize,
    /// Events where the policy decision matches the observed decision.
    pub matches: usize,
    /// Events where the policy decision differs from the observed decision.
    pub mismatches: Vec<Mismatch>,
    /// Events that could not be evaluated (e.g., container lifecycle).
    pub skipped: usize,
}

/// A single mismatch between observed and policy decisions.
#[derive(Debug)]
pub struct Mismatch {
    /// 1-based line number in the observation log.
    pub line: usize,
    /// The observation event that mismatched.
    pub event: ObservationEvent,
    /// The decision recorded in the observation log.
    pub observed: String,
    /// The decision produced by the Cedar policy.
    pub policy_decision: String,
}

/// Replay an observation log against a Cedar policy.
///
/// Loads the policy file, reads every event from the JSONL log, evaluates
/// each evaluable event against the policy, and returns the results.
///
/// The `agent_id` parameter specifies the Cedar principal identity to use
/// during evaluation. If `None`, defaults to `"agent"`.
pub fn replay(
    observations_path: &Path,
    policy_path: &Path,
    agent_id: Option<&str>,
) -> anyhow::Result<ReplayResult> {
    // Load the Cedar policy first — fail fast on invalid policy.
    let policy_text = std::fs::read_to_string(policy_path).map_err(|e| {
        anyhow::anyhow!(
            "failed to read policy file '{}': {e}",
            policy_path.display()
        )
    })?;

    let policy_set = PolicySet::from_str(&policy_text)
        .map_err(|e| anyhow::anyhow!("invalid Cedar policy '{}': {e}", policy_path.display()))?;

    let authorizer = Authorizer::new();

    // Resolve agent identity: use the provided value, or fall back to default.
    let agent = agent_id.unwrap_or(DEFAULT_AGENT_ID);

    // Read and process the observation log.
    let events = read_observations(observations_path)?;
    let total = events.len();
    let mut matches = 0usize;
    let mut mismatches = Vec::new();
    let mut skipped = 0usize;

    for (idx, event) in events.iter().enumerate() {
        let line = idx + 1;

        match evaluate_event(event, &policy_set, &authorizer, agent) {
            EventEvaluation::Match => {
                matches += 1;
            }
            EventEvaluation::Mismatch {
                observed,
                policy_decision,
            } => {
                mismatches.push(Mismatch {
                    line,
                    event: event.clone(),
                    observed,
                    policy_decision,
                });
            }
            EventEvaluation::Skip => {
                skipped += 1;
            }
        }
    }

    Ok(ReplayResult {
        total,
        matches,
        mismatches,
        skipped,
    })
}

/// Print the replay results to stdout and return the appropriate exit code.
pub fn print_results(result: &ReplayResult) -> i32 {
    let evaluated = result.matches + result.mismatches.len();

    // Print summary.
    if result.mismatches.is_empty() {
        println!(
            "{}/{} events match policy ({} skipped)",
            result.matches, evaluated, result.skipped
        );
        0
    } else {
        println!(
            "{}/{} events match policy ({} mismatches, {} skipped)",
            result.matches,
            evaluated,
            result.mismatches.len(),
            result.skipped
        );
        println!();

        // Print each mismatch with details.
        for m in &result.mismatches {
            println!("MISMATCH line {}:", m.line);
            println!("  event:    {}", format_event_summary(&m.event));
            println!("  observed: {}", m.observed);
            println!("  policy:   {}", m.policy_decision);
            println!();
        }

        1
    }
}

// ---------------------------------------------------------------------------
// Observation reading
// ---------------------------------------------------------------------------

fn read_observations(path: &Path) -> anyhow::Result<Vec<ObservationEvent>> {
    let file = std::fs::File::open(path).map_err(|e| {
        anyhow::anyhow!("failed to open observation file '{}': {e}", path.display())
    })?;
    let reader = BufReader::new(file);
    let mut events = Vec::new();

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
// Event evaluation
// ---------------------------------------------------------------------------

/// The default agent identity used for replay evaluation when no agent ID
/// is specified by the caller.
const DEFAULT_AGENT_ID: &str = "agent";

enum EventEvaluation {
    /// The policy decision matches the observed decision.
    Match,
    /// The policy decision differs from the observed decision.
    Mismatch {
        observed: String,
        policy_decision: String,
    },
    /// The event cannot be evaluated against a policy (e.g., container lifecycle).
    Skip,
}

/// Evaluate a single observation event against the Cedar policy.
fn evaluate_event(
    event: &ObservationEvent,
    policy_set: &PolicySet,
    authorizer: &Authorizer,
    agent_id: &str,
) -> EventEvaluation {
    match &event.event {
        EventKind::NetworkRequest {
            method,
            host,
            path,
            decision,
            ..
        } => {
            let action_str = format!("http:{method}");
            let entities = match build_http_entity_hierarchy(host, path, agent_id) {
                Ok(e) => e,
                Err(_) => return EventEvaluation::Skip,
            };

            let context = match build_http_context(host, path, method) {
                Ok(c) => c,
                Err(_) => return EventEvaluation::Skip,
            };

            let policy_allowed = cedar_evaluate(
                agent_id,
                &action_str,
                &build_http_resource_id(host, path),
                &entities,
                &context,
                policy_set,
                authorizer,
            );

            let policy_decision_str = if policy_allowed { "allow" } else { "deny" };

            // "passthrough" means traffic was not inspected — it effectively went through,
            // so we treat it as "allow" for comparison purposes.
            // "warn" means the policy denied the request but warn mode allowed it
            // through anyway, so it counts as observed-allowed for comparison.
            let observed_allowed =
                decision == "allow" || decision == "passthrough" || decision == "warn";
            let observed_str = decision.as_str();

            if policy_allowed == observed_allowed {
                EventEvaluation::Match
            } else {
                EventEvaluation::Mismatch {
                    observed: observed_str.to_string(),
                    policy_decision: policy_decision_str.to_string(),
                }
            }
        }

        EventKind::FsAccess { path, operation } => {
            let action_str = format!("fs:{operation}");
            let resource_id = format!("fs::{path}");
            let entities = match build_fs_entities(path, agent_id) {
                Ok(e) => e,
                Err(_) => return EventEvaluation::Skip,
            };

            let context = match build_fs_context(path, operation) {
                Ok(c) => c,
                Err(_) => return EventEvaluation::Skip,
            };

            let policy_allowed = cedar_evaluate(
                agent_id,
                &action_str,
                &resource_id,
                &entities,
                &context,
                policy_set,
                authorizer,
            );

            // Observed events were allowed (they happened).
            if policy_allowed {
                EventEvaluation::Match
            } else {
                EventEvaluation::Mismatch {
                    observed: "allow".to_string(),
                    policy_decision: "deny".to_string(),
                }
            }
        }

        EventKind::ProcExec { command, .. } => {
            let resource_id = format!("proc::{command}");
            let entities = match build_proc_entities(command, agent_id) {
                Ok(e) => e,
                Err(_) => return EventEvaluation::Skip,
            };

            let context = match build_proc_context(command) {
                Ok(c) => c,
                Err(_) => return EventEvaluation::Skip,
            };

            let policy_allowed = cedar_evaluate(
                agent_id,
                "proc:exec",
                &resource_id,
                &entities,
                &context,
                policy_set,
                authorizer,
            );

            // Observed events were allowed (they happened).
            if policy_allowed {
                EventEvaluation::Match
            } else {
                EventEvaluation::Mismatch {
                    observed: "allow".to_string(),
                    policy_decision: "deny".to_string(),
                }
            }
        }

        EventKind::Mount { path, mode } => {
            let resource_id = format!("fs::{path}");
            let entities = match build_fs_entities(path, agent_id) {
                Ok(e) => e,
                Err(_) => return EventEvaluation::Skip,
            };

            let context = match build_mount_context(path, mode) {
                Ok(c) => c,
                Err(_) => return EventEvaluation::Skip,
            };

            let policy_allowed = cedar_evaluate(
                agent_id,
                "fs:mount",
                &resource_id,
                &entities,
                &context,
                policy_set,
                authorizer,
            );

            // Observed mounts were allowed (they happened).
            if policy_allowed {
                EventEvaluation::Match
            } else {
                EventEvaluation::Mismatch {
                    observed: "allow".to_string(),
                    policy_decision: "deny".to_string(),
                }
            }
        }

        // Container lifecycle and policy violation events cannot be evaluated against a Cedar policy.
        EventKind::ContainerStart { .. }
        | EventKind::ContainerStop { .. }
        | EventKind::PolicyViolation { .. } => EventEvaluation::Skip,
    }
}

/// Perform a Cedar authorization evaluation.
fn cedar_evaluate(
    agent_id: &str,
    action: &str,
    resource_id: &str,
    entities: &cedar_policy::Entities,
    context: &Context,
    policy_set: &PolicySet,
    authorizer: &Authorizer,
) -> bool {
    let principal = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Agent").unwrap(),
        EntityId::from_str(agent_id).unwrap(),
    );

    let action_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Action").unwrap(),
        EntityId::from_str(action).unwrap(),
    );

    let resource = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Resource").unwrap(),
        EntityId::from_str(resource_id).unwrap(),
    );

    let request = match Request::new(principal, action_uid, resource, context.clone(), None) {
        Ok(r) => r,
        Err(_) => return false,
    };

    let response = authorizer.is_authorized(&request, policy_set, entities);
    response.decision() == Decision::Allow
}

// ---------------------------------------------------------------------------
// Context builders
// ---------------------------------------------------------------------------

/// Build a Cedar context for an HTTP network request.
///
/// Populates `host`, `path`, and `method` attributes, plus AWS-specific
/// `aws_service` and `aws_region` when the host is an AWS endpoint.
/// This mirrors the context construction in `PolicyEngine::evaluate()`.
fn build_http_context(host: &str, path: &str, method: &str) -> anyhow::Result<Context> {
    let mut pairs: Vec<(String, RestrictedExpression)> = vec![
        (
            "host".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(host)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for host: {e}"))?,
        ),
        (
            "path".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(path)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for path: {e}"))?,
        ),
        (
            "method".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(method)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for method: {e}"))?,
        ),
    ];

    // Add AWS-specific context attributes when the host is an AWS endpoint.
    if let Some(aws_info) = parse_aws_host(host) {
        pairs.push((
            "aws_service".to_string(),
            RestrictedExpression::from_str(&format!(
                "\"{}\"",
                escape_cedar_string(&aws_info.service)
            ))
            .map_err(|e| anyhow::anyhow!("failed to build Cedar context for aws_service: {e}"))?,
        ));
        let region = aws_info.region.as_deref().unwrap_or("us-east-1");
        pairs.push((
            "aws_region".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(region)))
                .map_err(|e| {
                    anyhow::anyhow!("failed to build Cedar context for aws_region: {e}")
                })?,
        ));
    }

    Context::from_pairs(pairs).map_err(|e| anyhow::anyhow!("failed to build HTTP context: {e}"))
}

/// Build a Cedar context for a filesystem access event.
///
/// Populates `path` and `operation` attributes.
fn build_fs_context(path: &str, operation: &str) -> anyhow::Result<Context> {
    let pairs: Vec<(String, RestrictedExpression)> = vec![
        (
            "path".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(path)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for path: {e}"))?,
        ),
        (
            "operation".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(operation)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for operation: {e}"))?,
        ),
    ];

    Context::from_pairs(pairs).map_err(|e| anyhow::anyhow!("failed to build fs context: {e}"))
}

/// Build a Cedar context for a process execution event.
///
/// Populates `command` attribute.
fn build_proc_context(command: &str) -> anyhow::Result<Context> {
    let pairs: Vec<(String, RestrictedExpression)> = vec![(
        "command".to_string(),
        RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(command)))
            .map_err(|e| anyhow::anyhow!("failed to build Cedar context for command: {e}"))?,
    )];

    Context::from_pairs(pairs).map_err(|e| anyhow::anyhow!("failed to build proc context: {e}"))
}

/// Build a Cedar context for a mount event.
///
/// Populates `path` and `mode` attributes.
fn build_mount_context(path: &str, mode: &str) -> anyhow::Result<Context> {
    let pairs: Vec<(String, RestrictedExpression)> = vec![
        (
            "path".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(path)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for path: {e}"))?,
        ),
        (
            "mode".to_string(),
            RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(mode)))
                .map_err(|e| anyhow::anyhow!("failed to build Cedar context for mode: {e}"))?,
        ),
    ];

    Context::from_pairs(pairs).map_err(|e| anyhow::anyhow!("failed to build mount context: {e}"))
}

/// Build a resource ID for an HTTP request (mirrors `policy.rs::build_resource_id`).
fn build_http_resource_id(host: &str, path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        host.to_string()
    } else {
        format!("{host}/{trimmed}")
    }
}

/// Format a one-line summary of an observation event.
fn format_event_summary(event: &ObservationEvent) -> String {
    match &event.event {
        EventKind::NetworkRequest {
            method, host, path, ..
        } => {
            format!("{method} {host}{path}")
        }
        EventKind::FsAccess { path, operation } => {
            format!("fs:{operation} {path}")
        }
        EventKind::ProcExec { command, .. } => {
            format!("proc:exec {command}")
        }
        EventKind::Mount { path, mode } => {
            format!("fs:mount {path} ({mode})")
        }
        EventKind::ContainerStart {
            container_id,
            image,
        } => {
            format!("container start {container_id} ({image})")
        }
        EventKind::ContainerStop {
            container_id,
            exit_code,
        } => {
            format!(
                "container stop {container_id} (exit: {})",
                exit_code
                    .map(|c| c.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            )
        }
        EventKind::PolicyViolation {
            action,
            resource,
            decision,
            ..
        } => {
            format!("policy:{decision} {action} {resource}")
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    /// Helper: write JSONL events to a temp file and return the path.
    fn write_observations(
        dir: &tempfile::TempDir,
        events: &[ObservationEvent],
    ) -> std::path::PathBuf {
        let path = dir.path().join("observations.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for event in events {
            let json = serde_json::to_string(event).unwrap();
            writeln!(file, "{json}").unwrap();
        }
        path
    }

    /// Helper: write a Cedar policy file and return the path.
    fn write_policy(dir: &tempfile::TempDir, content: &str) -> std::path::PathBuf {
        let path = dir.path().join("policy.cedar");
        std::fs::write(&path, content).unwrap();
        path
    }

    fn make_network_event(
        method: &str,
        host: &str,
        path: &str,
        decision: &str,
    ) -> ObservationEvent {
        ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::NetworkRequest {
                method: method.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                decision: decision.to_string(),
                latency_us: 100,
                enforcement_mode: String::new(),
            },
        }
    }

    // -- All events match policy -> exit 0 ------------------------------------

    #[test]
    fn all_events_match_returns_zero() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            make_network_event("GET", "api.github.com", "/repos/org/repo", "allow"),
            make_network_event("POST", "api.github.com", "/repos/org/repo/issues", "allow"),
        ];
        let obs_path = write_observations(&dir, &events);

        // Policy that allows all HTTP methods to api.github.com/**
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
permit(
  principal,
  action == Action::"http:POST",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 2);
        assert!(result.mismatches.is_empty());
        assert_eq!(result.skipped, 0);
        assert_eq!(print_results(&result), 0);
    }

    // -- One mismatch -> exit 1 with details ----------------------------------

    #[test]
    fn mismatch_returns_one_with_details() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            make_network_event("GET", "api.github.com", "/repos/org/repo", "allow"),
            // This event was allowed but policy will deny it
            make_network_event("DELETE", "api.github.com", "/repos/org/repo", "allow"),
        ];
        let obs_path = write_observations(&dir, &events);

        // Policy only allows GET, not DELETE
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert_eq!(result.mismatches.len(), 1);

        let mismatch = &result.mismatches[0];
        assert_eq!(mismatch.line, 2);
        assert_eq!(mismatch.observed, "allow");
        assert_eq!(mismatch.policy_decision, "deny");
        assert_eq!(print_results(&result), 1);
    }

    // -- Corrupted line -> parse error with line number -----------------------

    #[test]
    fn corrupted_line_produces_parse_error_with_line_number() {
        let dir = tempfile::tempdir().unwrap();
        let obs_path = dir.path().join("observations.jsonl");

        {
            let mut file = std::fs::File::create(&obs_path).unwrap();
            let good_event = make_network_event("GET", "api.github.com", "/repos", "allow");
            writeln!(file, "{}", serde_json::to_string(&good_event).unwrap()).unwrap();
            writeln!(file, "{{not valid json!!!").unwrap();
        }

        let policy_path = write_policy(&dir, "permit(principal, action, resource);");

        let result = replay(&obs_path, &policy_path, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("line 2"),
            "error should mention line number, got: {err}"
        );
    }

    // -- Invalid policy file -> clear error before replay starts --------------

    #[test]
    fn invalid_policy_produces_clear_error() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "allow",
        )];
        let obs_path = write_observations(&dir, &events);

        let policy_path = write_policy(&dir, "this is not valid cedar policy syntax!!!");

        let result = replay(&obs_path, &policy_path, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("invalid Cedar policy"),
            "error should mention invalid policy, got: {err}"
        );
    }

    // -- Container lifecycle events are skipped gracefully --------------------

    #[test]
    fn container_events_are_skipped() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            make_network_event("GET", "api.github.com", "/repos", "allow"),
            ObservationEvent {
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                event: EventKind::ContainerStart {
                    container_id: "abc123".to_string(),
                    image: "node:20-slim".to_string(),
                },
            },
            ObservationEvent {
                timestamp: "2026-03-27T00:00:01.000Z".to_string(),
                event: EventKind::ContainerStop {
                    container_id: "abc123".to_string(),
                    exit_code: Some(0),
                },
            },
        ];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.total, 3);
        assert_eq!(result.matches, 1);
        assert_eq!(result.skipped, 2);
        assert!(result.mismatches.is_empty());
        assert_eq!(print_results(&result), 0);
    }

    // -- Denied event matches deny policy ------------------------------------

    #[test]
    fn denied_event_matches_when_policy_also_denies() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "deny",
        )];
        let obs_path = write_observations(&dir, &events);

        // Empty policy — Cedar denies by default when no permit matches.
        let policy = "// empty policy — deny all\n";
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.mismatches.is_empty());
        assert_eq!(print_results(&result), 0);
    }

    // -- Passthrough is treated as allowed ------------------------------------

    #[test]
    fn passthrough_event_treated_as_allow() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "passthrough",
        )];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.mismatches.is_empty());
    }

    // -- Passthrough mismatch when policy denies ------------------------------

    #[test]
    fn passthrough_mismatch_when_policy_denies() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "DELETE",
            "api.github.com",
            "/repos/org/repo",
            "passthrough",
        )];
        let obs_path = write_observations(&dir, &events);

        // Policy only allows GET
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].observed, "passthrough");
        assert_eq!(result.mismatches[0].policy_decision, "deny");
    }

    // -- Missing policy file --------------------------------------------------

    #[test]
    fn missing_policy_file_produces_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "allow",
        )];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("nonexistent.cedar");

        let result = replay(&obs_path, &policy_path, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to read policy file"),
            "error should mention policy file, got: {err}"
        );
    }

    // -- Missing observation file ---------------------------------------------

    #[test]
    fn missing_observation_file_produces_clear_error() {
        let dir = tempfile::tempdir().unwrap();
        let obs_path = dir.path().join("nonexistent.jsonl");
        let policy_path = write_policy(&dir, "permit(principal, action, resource);");

        let result = replay(&obs_path, &policy_path, None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to open observation file"),
            "error should mention observation file, got: {err}"
        );
    }

    // -- FsAccess events are evaluated ----------------------------------------

    #[test]
    fn fs_access_event_evaluated() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::FsAccess {
                path: "/workspace/src/main.rs".to_string(),
                operation: "read".to_string(),
            },
        }];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"fs:read",
  resource in Resource::"fs::/"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.mismatches.is_empty());
    }

    // -- ProcExec events are evaluated ----------------------------------------

    #[test]
    fn proc_exec_event_evaluated() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::ProcExec {
                pid: 42,
                command: "node index.js".to_string(),
            },
        }];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"proc:exec",
  resource == Resource::"proc::node index.js"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.mismatches.is_empty());
    }

    // -- Mount events are evaluated -------------------------------------------

    #[test]
    fn mount_event_evaluated() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::Mount {
                path: "/workspace".to_string(),
                mode: "read-only".to_string(),
            },
        }];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"fs:mount",
  resource in Resource::"fs::/"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1);
        assert!(result.mismatches.is_empty());
    }

    // -- Empty observation log ------------------------------------------------

    #[test]
    fn empty_observation_log_exits_zero() {
        let dir = tempfile::tempdir().unwrap();
        let obs_path = dir.path().join("empty.jsonl");
        std::fs::write(&obs_path, "").unwrap();

        let policy_path = write_policy(&dir, "permit(principal, action, resource);");

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.total, 0);
        assert_eq!(result.matches, 0);
        assert!(result.mismatches.is_empty());
        assert_eq!(print_results(&result), 0);
    }

    // -- Blank lines in observation log are skipped ---------------------------

    #[test]
    fn blank_lines_are_skipped() {
        let dir = tempfile::tempdir().unwrap();
        let obs_path = dir.path().join("observations.jsonl");

        {
            let mut file = std::fs::File::create(&obs_path).unwrap();
            let event = make_network_event("GET", "api.github.com", "/repos", "allow");
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
            writeln!(file).unwrap(); // blank line
            writeln!(file, "  ").unwrap(); // whitespace-only line
            writeln!(file, "{}", serde_json::to_string(&event).unwrap()).unwrap();
        }

        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.total, 2);
        assert_eq!(result.matches, 2);
    }

    // -- Context: path condition on HTTP events --------------------------------

    #[test]
    fn context_path_condition_evaluated_for_http() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            // This path matches the /admin/* pattern
            make_network_event("GET", "api.example.com", "/admin/users", "allow"),
            // This path does NOT match the /admin/* pattern
            make_network_event("GET", "api.example.com", "/public/docs", "allow"),
        ];
        let obs_path = write_observations(&dir, &events);

        // Policy only allows GET to paths matching /admin/*
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource
) when { context.path like "/admin/*" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        // First event matches (path is /admin/users)
        // Second event mismatches (path is /public/docs, policy denies)
        assert_eq!(result.matches, 1, "only /admin/users should match");
        assert_eq!(result.mismatches.len(), 1, "/public/docs should mismatch");
        assert_eq!(result.mismatches[0].policy_decision, "deny");
    }

    // -- Context: host condition on HTTP events --------------------------------

    #[test]
    fn context_host_condition_evaluated_for_http() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            make_network_event("GET", "api.github.com", "/repos", "allow"),
            make_network_event("GET", "evil.example.com", "/repos", "allow"),
        ];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource
) when { context.host == "api.github.com" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1, "only api.github.com should match");
        assert_eq!(result.mismatches.len(), 1);
    }

    // -- Context: method condition on HTTP events ------------------------------

    #[test]
    fn context_method_condition_evaluated_for_http() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            make_network_event("GET", "api.github.com", "/repos", "allow"),
            make_network_event("DELETE", "api.github.com", "/repos", "allow"),
        ];
        let obs_path = write_observations(&dir, &events);

        // Allow all actions but only when method is GET
        let policy = r#"
permit(
  principal,
  action,
  resource
) when { context.method == "GET" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1, "only GET should match");
        assert_eq!(result.mismatches.len(), 1, "DELETE should mismatch");
    }

    // -- Agent-specific policy uses correct principal --------------------------

    #[test]
    fn agent_specific_policy_uses_correct_principal() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "allow",
        )];
        let obs_path = write_observations(&dir, &events);

        // Policy only allows principal "worker"
        let policy = r#"
permit(
  principal == Agent::"worker",
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        // Default agent ("agent") should NOT match "worker"-only policy
        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(
            result.mismatches.len(),
            1,
            "default agent should not match worker-only policy"
        );

        // Specifying agent_id = "worker" should match
        let result = replay(&obs_path, &policy_path, Some("worker")).unwrap();
        assert_eq!(result.matches, 1, "worker agent should match");
        assert!(result.mismatches.is_empty());
    }

    // -- FS context: path condition -------------------------------------------

    #[test]
    fn fs_context_path_condition_evaluated() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            ObservationEvent {
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                event: EventKind::FsAccess {
                    path: "/workspace/secret/keys".to_string(),
                    operation: "read".to_string(),
                },
            },
            ObservationEvent {
                timestamp: "2026-03-27T00:00:01.000Z".to_string(),
                event: EventKind::FsAccess {
                    path: "/workspace/src/main.rs".to_string(),
                    operation: "read".to_string(),
                },
            },
        ];
        let obs_path = write_observations(&dir, &events);

        // Allow fs:read only for paths under /workspace/src
        let policy = r#"
permit(
  principal,
  action == Action::"fs:read",
  resource
) when { context.path like "/workspace/src/*" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(
            result.matches, 1,
            "only /workspace/src/main.rs should match"
        );
        assert_eq!(
            result.mismatches.len(),
            1,
            "/workspace/secret/keys should mismatch"
        );
    }

    // -- Proc context: command condition ---------------------------------------

    #[test]
    fn proc_context_command_condition_evaluated() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![
            ObservationEvent {
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                event: EventKind::ProcExec {
                    pid: 1,
                    command: "node index.js".to_string(),
                },
            },
            ObservationEvent {
                timestamp: "2026-03-27T00:00:01.000Z".to_string(),
                event: EventKind::ProcExec {
                    pid: 2,
                    command: "rm -rf /".to_string(),
                },
            },
        ];
        let obs_path = write_observations(&dir, &events);

        // Only allow "node" commands
        let policy = r#"
permit(
  principal,
  action == Action::"proc:exec",
  resource
) when { context.command like "node*" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1, "only 'node index.js' should match");
        assert_eq!(result.mismatches.len(), 1, "'rm -rf /' should mismatch");
    }

    // -- Warn decision treated as allowed ---------------------------------------

    #[test]
    fn warn_decision_treated_as_allowed() {
        let dir = tempfile::tempdir().unwrap();

        // "warn" means the proxy allowed the request despite a policy denial
        // (warn mode). For replay comparison, this counts as "allowed".
        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos/org/repo",
            "warn",
        )];
        let obs_path = write_observations(&dir, &events);

        // Policy allows this request — should match because warn == allowed.
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1, "warn should be treated as allowed");
        assert!(result.mismatches.is_empty());
    }

    #[test]
    fn warn_decision_mismatch_when_policy_denies() {
        let dir = tempfile::tempdir().unwrap();

        // Observed "warn" (allowed through) but policy would deny.
        let events = vec![make_network_event(
            "DELETE",
            "api.github.com",
            "/repos/org/repo",
            "warn",
        )];
        let obs_path = write_observations(&dir, &events);

        // Policy only allows GET — DELETE is denied.
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.mismatches.len(), 1);
        assert_eq!(result.mismatches[0].observed, "warn");
        assert_eq!(result.mismatches[0].policy_decision, "deny");
    }

    #[test]
    fn deny_decision_still_counted_as_denied() {
        let dir = tempfile::tempdir().unwrap();

        // Observed "deny" — should count as denied, not allowed.
        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos",
            "deny",
        )];
        let obs_path = write_observations(&dir, &events);

        // Policy allows GET — so this is a mismatch (observed deny, policy allow).
        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.github.com"
);
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.mismatches.len(), 1, "deny should remain denied");
        assert_eq!(result.mismatches[0].observed, "deny");
        assert_eq!(result.mismatches[0].policy_decision, "allow");
    }

    // -- AWS context attributes in replay -------------------------------------

    #[test]
    fn aws_context_attributes_populated_in_replay() {
        let dir = tempfile::tempdir().unwrap();

        let events = vec![make_network_event(
            "GET",
            "s3.us-east-1.amazonaws.com",
            "/my-bucket/object",
            "allow",
        )];
        let obs_path = write_observations(&dir, &events);

        let policy = r#"
permit(
  principal,
  action == Action::"http:GET",
  resource
) when { context.aws_service == "s3" && context.aws_region == "us-east-1" };
"#;
        let policy_path = write_policy(&dir, policy);

        let result = replay(&obs_path, &policy_path, None).unwrap();
        assert_eq!(result.matches, 1, "AWS S3 context should match");
        assert!(result.mismatches.is_empty());
    }
}
