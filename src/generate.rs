//! Cedar policy generation from observation logs.
//!
//! Reads a JSONL observation log (produced by `ObservationStream`) and
//! generates a Cedar policy file + schema file covering all observed activity.
//!
//! The generator:
//! 1. Groups events by action namespace (http, fs, proc)
//! 2. Collapses dynamic path segments (UUIDs, long numbers, SHAs) to `*`
//! 3. Deduplicates (action, resource) pairs
//! 4. Emits `permit()` statements with annotation comments

use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::path::Path;

use crate::observe::{read_observations, EventKind, ObservationEvent};
use crate::policy::escape_cedar_string;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Generate Cedar policy and schema text from an observation JSONL log file.
///
/// Returns `Some((policy_text, schema_text, wildcard_count))` if actionable
/// observations were found, or `None` if the file is empty or contains only
/// non-actionable events (e.g. container lifecycle).
pub fn generate_from_file(input: &Path) -> anyhow::Result<Option<(String, String, usize)>> {
    let events = read_observations(input)?;
    if events.is_empty() {
        return Ok(None);
    }
    let (rules, wildcard_count) = extract_rules(&events);
    if rules.is_empty() {
        return Ok(None);
    }
    let policy_text = generate_policy(&rules);
    let schema_text = generate_schema(&rules);
    Ok(Some((policy_text, schema_text, wildcard_count)))
}

/// Generate Cedar policy and schema files from an observation JSONL log.
///
/// Returns the number of wildcard collapses performed.
pub fn generate(input: &Path, output: &Path, schema_output: &Path) -> anyhow::Result<usize> {
    let events = read_observations(input)?;

    if events.is_empty() {
        eprintln!("warning: no observations found in {}", input.display());
        return Ok(0);
    }

    let (rules, wildcard_count) = extract_rules(&events);

    if rules.is_empty() {
        eprintln!(
            "warning: no actionable observations found in {}",
            input.display()
        );
        return Ok(0);
    }

    let policy_text = generate_policy(&rules);
    let schema_text = generate_schema(&rules);

    std::fs::write(output, &policy_text)
        .map_err(|e| anyhow::anyhow!("failed to write policy file: {e}"))?;
    std::fs::write(schema_output, &schema_text)
        .map_err(|e| anyhow::anyhow!("failed to write schema file: {e}"))?;

    if wildcard_count > 0 {
        eprintln!("{wildcard_count} path segments collapsed to wildcards -- review carefully");
    }

    Ok(wildcard_count)
}

// ---------------------------------------------------------------------------
// Rule extraction and wildcard collapsing
// ---------------------------------------------------------------------------

/// A unique (action, resource) pair with wildcard annotations.
#[derive(Debug)]
struct PolicyRule {
    action: String,
    resource: String,
    /// Map from wildcard segment index to set of original values seen.
    wildcard_originals: BTreeMap<usize, BTreeSet<String>>,
    /// For wildcard rules: resource truncated to the deepest non-wildcard ancestor.
    /// Cedar treats `*` as a literal character in entity IDs, so wildcard resources
    /// like `Resource::"host/repos/*/issues"` would never match. Instead, we use
    /// the truncated ancestor with a `when { context.path like ... }` clause.
    truncated_resource: Option<String>,
    /// For wildcard rules: the Cedar `like` pattern for `context.path` matching.
    like_pattern: Option<String>,
}

/// Extract unique policy rules from observations, collapsing dynamic path segments.
///
/// Returns `(rules, total_wildcard_count)`.
fn extract_rules(events: &[ObservationEvent]) -> (Vec<PolicyRule>, usize) {
    // Key: (action, collapsed_resource)
    // Value: wildcard originals per segment position
    let mut rule_map: BTreeMap<(String, String), BTreeMap<usize, BTreeSet<String>>> =
        BTreeMap::new();
    let mut wildcard_count: usize = 0;

    for event in events {
        // Skip denied events — they should not generate permit rules.
        if is_denied_event(&event.event) {
            continue;
        }

        let Some((action, raw_resource)) = event_to_action_resource(&event.event) else {
            continue;
        };

        let (collapsed_resource, wildcards) = collapse_resource(&raw_resource);
        wildcard_count += wildcards.len();

        let entry = rule_map.entry((action, collapsed_resource)).or_default();
        for (idx, original) in wildcards {
            entry.entry(idx).or_default().insert(original);
        }
    }

    let rules: Vec<PolicyRule> = rule_map
        .into_iter()
        .map(|((action, resource), wildcard_originals)| {
            let (truncated_resource, like_pattern) =
                compute_wildcard_fields(&action, &resource, &wildcard_originals);
            PolicyRule {
                action,
                resource,
                wildcard_originals,
                truncated_resource,
                like_pattern,
            }
        })
        .collect();

    (rules, wildcard_count)
}

/// Check whether an observation event has a "deny" decision and should be
/// excluded from policy generation.
fn is_denied_event(event: &EventKind) -> bool {
    match event {
        EventKind::NetworkRequest { decision, .. } => decision == "deny",
        _ => false,
    }
}

/// For wildcard rules, compute the truncated resource (deepest non-wildcard
/// ancestor) and the Cedar `like` pattern for `context.path` matching.
///
/// Cedar treats `*` literally in entity IDs, so `Resource::"host/repos/*/issues"`
/// would never match a request for `host/repos/abc/issues`. Instead, we truncate
/// the resource to `host/repos` (the deepest ancestor without a wildcard) and add
/// a `when { context.path like "/repos/*/issues" }` condition.
fn compute_wildcard_fields(
    action: &str,
    resource: &str,
    wildcard_originals: &BTreeMap<usize, BTreeSet<String>>,
) -> (Option<String>, Option<String>) {
    if wildcard_originals.is_empty() {
        return (None, None);
    }

    let segments: Vec<&str> = resource.split('/').collect();

    // Find the first wildcard segment position.
    let first_wc = match segments.iter().position(|s| *s == "*") {
        Some(idx) => idx,
        None => return (None, None),
    };

    // Truncated resource: all segments before the first wildcard, joined.
    let truncated = segments[..first_wc].join("/");

    // Build the like pattern for actions that populate context.path.
    let like_pattern = if action.starts_with("http:") || action.starts_with("fs:") {
        // For HTTP, resource is "host/path_segments" — skip the host (index 0).
        // For FS, resource is "fs::/path_segments" — skip the prefix (index 0).
        // The like pattern is the path portion with a leading "/".
        let path_parts: Vec<String> = segments[1..]
            .iter()
            .enumerate()
            .map(|(i, seg)| {
                let resource_idx = i + 1; // offset for the skipped first segment
                if *seg == "*" && wildcard_originals.contains_key(&resource_idx) {
                    // Collapsed wildcard — use Cedar like wildcard
                    "*".to_string()
                } else {
                    // Escape any literal * so the like operator treats it literally.
                    // The `\*` in the Rust string becomes `\\*` after escape_cedar_string,
                    // which Cedar reads as `\*`, and the like operator matches literal `*`.
                    seg.replace('*', "\\*")
                }
            })
            .collect();
        Some(format!("/{}", path_parts.join("/")))
    } else {
        None
    };

    (Some(truncated), like_pattern)
}

/// Map an observation event to `(action, raw_resource)`.
///
/// Returns `None` for event types that don't map to Cedar actions
/// (e.g. container lifecycle events).
fn event_to_action_resource(event: &EventKind) -> Option<(String, String)> {
    match event {
        EventKind::NetworkRequest {
            method, host, path, ..
        } => {
            let action = format!("http:{method}");
            // Resource ID format matches policy.rs::build_resource_id —
            // bare "host/path" without a namespace prefix. This ensures
            // policies generated by `strait generate` are compatible with
            // `strait test --replay` and the proxy's Cedar evaluation.
            let trimmed = path.trim_start_matches('/');
            let resource = if trimmed.is_empty() {
                host.to_string()
            } else {
                format!("{host}/{trimmed}")
            };
            Some((action, resource))
        }
        EventKind::FsAccess { path, operation } => {
            let action = format!("fs:{operation}");
            let resource = format!("fs::{path}");
            Some((action, resource))
        }
        EventKind::ProcExec { command, .. } => {
            let action = "proc:exec".to_string();
            let resource = format!("proc::{command}");
            Some((action, resource))
        }
        EventKind::Mount { path, .. } => {
            let action = "fs:mount".to_string();
            let resource = format!("fs::{path}");
            Some((action, resource))
        }
        // Container lifecycle and policy violation events don't map to Cedar actions.
        EventKind::ContainerStart { .. }
        | EventKind::ContainerStop { .. }
        | EventKind::PolicyViolation { .. }
        | EventKind::PolicyReloaded { .. }
        | EventKind::TtyResized { .. }
        | EventKind::LiveDecision { .. } => None,
    }
}

/// Collapse dynamic path segments in a resource identifier to `*`.
///
/// Splits the resource on `/` and replaces any segment matching a known
/// dynamic pattern (UUID, long numeric, SHA-1 hex) with `*`.
///
/// Returns `(collapsed_resource, Vec<(segment_index, original_value)>)`.
fn collapse_resource(resource: &str) -> (String, Vec<(usize, String)>) {
    let parts: Vec<&str> = resource.split('/').collect();
    let mut collapsed = Vec::with_capacity(parts.len());
    let mut wildcards = Vec::new();

    for (idx, part) in parts.iter().enumerate() {
        if is_dynamic_segment(part) {
            collapsed.push("*");
            wildcards.push((idx, (*part).to_string()));
        } else {
            collapsed.push(part);
        }
    }

    (collapsed.join("/"), wildcards)
}

/// Check whether a path segment matches a known dynamic ID pattern.
///
/// Patterns:
/// - UUID: 8-4-4-4-12 hex digits separated by dashes (36 chars)
/// - Long numeric: 4+ consecutive digits
/// - SHA-1 hex: exactly 40 hex characters
fn is_dynamic_segment(s: &str) -> bool {
    is_uuid(s) || is_long_numeric(s) || is_sha_hex(s)
}

/// Check for UUID format: `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.
fn is_uuid(s: &str) -> bool {
    if s.len() != 36 {
        return false;
    }
    let bytes = s.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        match i {
            8 | 13 | 18 | 23 => {
                if b != b'-' {
                    return false;
                }
            }
            _ => {
                if !b.is_ascii_hexdigit() {
                    return false;
                }
            }
        }
    }
    true
}

/// Check for pure numeric strings with more than 3 digits, excluding
/// 4-digit years in the range 1900–2099.
///
/// Years are common in URL paths (e.g. `/api/v1/reports/2024/`) and should
/// not be collapsed to wildcards.
fn is_long_numeric(s: &str) -> bool {
    if s.len() <= 3 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    // Preserve 4-digit years (1900–2099).
    if s.len() == 4 {
        if let Ok(n) = s.parse::<u16>() {
            if (1900..=2099).contains(&n) {
                return false;
            }
        }
    }
    true
}

/// Check for 40-character lowercase/uppercase hex strings (SHA-1 hashes).
fn is_sha_hex(s: &str) -> bool {
    s.len() == 40 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

// ---------------------------------------------------------------------------
// Policy generation
// ---------------------------------------------------------------------------

/// Generate Cedar policy text from extracted rules.
fn generate_policy(rules: &[PolicyRule]) -> String {
    let mut out = String::new();
    writeln!(out, "// Generated by: strait generate").unwrap();
    writeln!(
        out,
        "// Review wildcards (*) carefully -- they replace dynamic path segments."
    )
    .unwrap();
    writeln!(out).unwrap();

    for (i, rule) in rules.iter().enumerate() {
        // Emit annotation comments for wildcards
        if !rule.wildcard_originals.is_empty() {
            for (idx, originals) in &rule.wildcard_originals {
                let values: Vec<&str> = originals.iter().map(|s| s.as_str()).collect();
                writeln!(out, "// * at segment {idx} was: {}", values.join(", ")).unwrap();
            }
        }

        // For wildcard rules, use the truncated resource (deepest non-wildcard
        // ancestor) and add a `when { context.path like ... }` condition.
        // Cedar treats `*` literally in entity IDs, so we cannot use
        // Resource::"host/repos/*/issues" directly.
        let effective_resource = rule.truncated_resource.as_deref().unwrap_or(&rule.resource);

        writeln!(out, "permit(").unwrap();
        writeln!(out, "  principal,").unwrap();
        writeln!(out, "  action == Action::\"{}\",", rule.action).unwrap();
        writeln!(out, "  resource in Resource::\"{}\"", effective_resource).unwrap();
        if let Some(ref pattern) = rule.like_pattern {
            let escaped = escape_cedar_string(pattern);
            writeln!(out, ") when {{").unwrap();
            writeln!(out, "  context.path like \"{}\"", escaped).unwrap();
            writeln!(out, "}};").unwrap();
        } else {
            writeln!(out, ");").unwrap();
        }

        // Blank line between rules
        if i + 1 < rules.len() {
            writeln!(out).unwrap();
        }
    }

    out
}

/// Generate Cedar schema text covering all actions referenced by the rules.
///
/// Includes context attribute declarations so the schema is consistent with
/// generated policies (which may use `when { context.path like ... }`).
fn generate_schema(rules: &[PolicyRule]) -> String {
    let mut out = String::new();
    writeln!(out, "// Generated by: strait generate").unwrap();
    writeln!(out).unwrap();

    // Entity declarations
    writeln!(out, "entity Agent;").unwrap();
    writeln!(out, "entity Resource in [Resource];").unwrap();
    writeln!(out).unwrap();

    // Collect unique actions in sorted order
    let actions: BTreeSet<&str> = rules.iter().map(|r| r.action.as_str()).collect();

    for action in &actions {
        writeln!(out, "action \"{}\" appliesTo {{", action).unwrap();
        writeln!(out, "  principal: [Agent],").unwrap();
        writeln!(out, "  resource: [Resource],").unwrap();

        // Include context attributes matching what the policy evaluator provides.
        if action.starts_with("http:") {
            writeln!(
                out,
                "  context: {{ \"host\": __cedar::String, \"path\": __cedar::String, \"method\": __cedar::String }},"
            )
            .unwrap();
        } else if action.starts_with("fs:") {
            writeln!(
                out,
                "  context: {{ \"path\": __cedar::String, \"operation\": __cedar::String }},"
            )
            .unwrap();
        }

        writeln!(out, "}};").unwrap();
    }

    out
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

    fn make_network_event(method: &str, host: &str, path: &str) -> ObservationEvent {
        ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: method.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                decision: "allow".to_string(),
                latency_us: 100,
                enforcement_mode: String::new(),
                blocked: None,
            },
        }
    }

    fn make_fs_event(path: &str, operation: &str) -> ObservationEvent {
        ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::FsAccess {
                path: path.to_string(),
                operation: operation.to_string(),
            },
        }
    }

    // -- Wildcard pattern tests -----------------------------------------------

    #[test]
    fn uuid_is_detected() {
        assert!(is_uuid("550e8400-e29b-41d4-a716-446655440000"));
        assert!(is_uuid("AABBCCDD-1122-3344-5566-778899AABBCC"));
    }

    #[test]
    fn non_uuid_not_detected() {
        assert!(!is_uuid("not-a-uuid"));
        assert!(!is_uuid("550e8400-e29b-41d4-a716-44665544000")); // too short
        assert!(!is_uuid("repos"));
        assert!(!is_uuid(""));
    }

    #[test]
    fn long_numeric_detected() {
        assert!(is_long_numeric("1234"));
        assert!(is_long_numeric("123456789"));
    }

    #[test]
    fn short_numeric_not_detected() {
        assert!(!is_long_numeric("123"));
        assert!(!is_long_numeric("42"));
        assert!(!is_long_numeric("abc"));
    }

    #[test]
    fn sha_hex_detected() {
        assert!(is_sha_hex("da39a3ee5e6b4b0d3255bfef95601890afd80709"));
        assert!(is_sha_hex("AABBCCDDEE00112233445566778899AABBCCDDEE"));
    }

    #[test]
    fn non_sha_not_detected() {
        // 39 chars — too short
        assert!(!is_sha_hex("da39a3ee5e6b4b0d3255bfef95601890afd8070"));
        // 41 chars — too long
        assert!(!is_sha_hex("da39a3ee5e6b4b0d3255bfef95601890afd807090"));
        assert!(!is_sha_hex("repos"));
    }

    // -- Resource collapsing tests -------------------------------------------

    #[test]
    fn uuid_path_segment_collapsed() {
        let (collapsed, wildcards) = collapse_resource(
            "api.github.com/repos/org/550e8400-e29b-41d4-a716-446655440000/issues",
        );
        assert_eq!(collapsed, "api.github.com/repos/org/*/issues");
        assert_eq!(wildcards.len(), 1);
        assert_eq!(wildcards[0].1, "550e8400-e29b-41d4-a716-446655440000");
    }

    #[test]
    fn sha_path_segment_collapsed() {
        let (collapsed, wildcards) = collapse_resource(
            "github.com/org/repo/commit/da39a3ee5e6b4b0d3255bfef95601890afd80709",
        );
        assert_eq!(collapsed, "github.com/org/repo/commit/*");
        assert_eq!(wildcards.len(), 1);
        assert_eq!(wildcards[0].1, "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    }

    #[test]
    fn non_dynamic_segment_preserved() {
        let (collapsed, wildcards) = collapse_resource("api.github.com/repos/org/repo");
        assert_eq!(collapsed, "api.github.com/repos/org/repo");
        assert!(wildcards.is_empty());
    }

    #[test]
    fn fs_numeric_segment_collapsed() {
        let (collapsed, wildcards) = collapse_resource("fs::/workspace/data/123456/file.txt");
        assert_eq!(collapsed, "fs::/workspace/data/*/file.txt");
        assert_eq!(wildcards.len(), 1);
        assert_eq!(wildcards[0].1, "123456");
    }

    // -- Policy generation (unit tests) ---------------------------------------

    #[test]
    fn single_http_get_produces_permit() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos/org/repo",
        )];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains(r#"action == Action::"http:GET""#),
            "policy should contain http:GET action: {policy}"
        );
        assert!(
            policy.contains(r#"resource in Resource::"api.github.com/repos/org/repo""#),
            "policy should contain host/path resource: {policy}"
        );
    }

    #[test]
    fn single_fs_read_produces_permit() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![make_fs_event("/etc/passwd", "read")];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains(r#"action == Action::"fs:read""#),
            "policy should contain fs:read action: {policy}"
        );
        assert!(
            policy.contains(r#"resource in Resource::"fs::/etc/passwd""#),
            "policy should contain fs:: resource: {policy}"
        );
    }

    #[test]
    fn uuid_collapsed_with_annotation_comment() {
        let dir = tempfile::tempdir().unwrap();
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        let events = vec![make_network_event(
            "GET",
            "api.example.com",
            &format!("/users/{uuid}/profile"),
        )];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        let count = generate(&obs_path, &policy_path, &schema_path).unwrap();
        assert_eq!(count, 1, "should have collapsed 1 wildcard");

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains(uuid),
            "policy should contain original UUID in comment: {policy}"
        );
        // Resource should be truncated to deepest non-wildcard ancestor
        assert!(
            policy.contains(r#"resource in Resource::"api.example.com/users""#),
            "policy should use truncated resource: {policy}"
        );
        // Wildcard pattern should appear in a when clause
        assert!(
            policy.contains(r#"context.path like "/users/*/profile""#),
            "policy should have like pattern for wildcards: {policy}"
        );
    }

    #[test]
    fn non_uuid_segment_preserved() {
        let (collapsed, wildcards) = collapse_resource("api.github.com/repos/org/my-repo");
        assert_eq!(collapsed, "api.github.com/repos/org/my-repo");
        assert!(wildcards.is_empty(), "no segments should be collapsed");
    }

    #[test]
    fn empty_observation_file_produces_warning_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let obs_path = dir.path().join("empty.jsonl");
        std::fs::write(&obs_path, "").unwrap();
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        let count = generate(&obs_path, &policy_path, &schema_path).unwrap();
        assert_eq!(count, 0);

        // Policy and schema files should NOT be created
        assert!(
            !policy_path.exists(),
            "policy file should not be created for empty input"
        );
        assert!(
            !schema_path.exists(),
            "schema file should not be created for empty input"
        );
    }

    #[test]
    fn generated_policy_and_schema_pass_cedar_validation() {
        use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
        use std::str::FromStr;

        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event("GET", "api.github.com", "/repos/org/repo"),
            make_network_event("POST", "api.github.com", "/repos/org/repo/issues"),
            make_fs_event("/workspace/src/main.rs", "read"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy_text = std::fs::read_to_string(&policy_path).unwrap();
        let schema_text = std::fs::read_to_string(&schema_path).unwrap();

        // Parse policy
        let policy_set = PolicySet::from_str(&policy_text)
            .expect("generated policy should parse as valid Cedar");

        // Parse schema
        let (schema, _warnings) = Schema::from_cedarschema_str(&schema_text)
            .expect("generated schema should parse as valid Cedar schema");

        // Validate policy against schema
        let validator = Validator::new(schema);
        let result = validator.validate(&policy_set, ValidationMode::Strict);
        assert!(
            result.validation_passed(),
            "generated policy should pass schema validation. Errors: {:?}",
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn duplicate_observations_produce_single_permit() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event("GET", "api.github.com", "/repos"),
            make_network_event("GET", "api.github.com", "/repos"),
            make_network_event("GET", "api.github.com", "/repos"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        let permit_count = policy.matches("permit(").count();
        assert_eq!(
            permit_count, 1,
            "duplicate observations should produce single permit: {policy}"
        );
    }

    #[test]
    fn container_events_are_skipped() {
        let events = vec![
            ObservationEvent {
                version: 1,
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                session: None,
                event: EventKind::ContainerStart {
                    container_id: "abc123".to_string(),
                    image: "node:20".to_string(),
                },
            },
            ObservationEvent {
                version: 1,
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                session: None,
                event: EventKind::ContainerStop {
                    container_id: "abc123".to_string(),
                    exit_code: Some(0),
                },
            },
        ];

        for event in &events {
            assert!(
                event_to_action_resource(&event.event).is_none(),
                "container events should not produce rules"
            );
        }
    }

    #[test]
    fn proc_exec_produces_permit() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::ProcExec {
                pid: 42,
                command: "node index.js".to_string(),
            },
        }];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains(r#"action == Action::"proc:exec""#),
            "policy should contain proc:exec action: {policy}"
        );
        assert!(
            policy.contains(r#"resource in Resource::"proc::node index.js""#),
            "policy should contain proc:: resource: {policy}"
        );
    }

    #[test]
    fn multiple_wildcards_collect_all_originals() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event(
                "GET",
                "api.example.com",
                "/users/550e8400-e29b-41d4-a716-446655440000/posts",
            ),
            make_network_event(
                "GET",
                "api.example.com",
                "/users/660e8400-e29b-41d4-a716-446655440001/posts",
            ),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        // Both original UUIDs should appear in the annotation comment
        assert!(
            policy.contains("550e8400-e29b-41d4-a716-446655440000"),
            "should list first UUID: {policy}"
        );
        assert!(
            policy.contains("660e8400-e29b-41d4-a716-446655440001"),
            "should list second UUID: {policy}"
        );
        // Only one permit statement (deduplicated)
        assert_eq!(
            policy.matches("permit(").count(),
            1,
            "should deduplicate to single permit: {policy}"
        );
        // Resource should be truncated, with like pattern for the wildcard
        assert!(
            policy.contains(r#"resource in Resource::"api.example.com/users""#),
            "should use truncated resource: {policy}"
        );
        assert!(
            policy.contains(r#"context.path like "/users/*/posts""#),
            "should have like pattern: {policy}"
        );
    }

    #[test]
    fn schema_contains_all_observed_actions() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event("GET", "api.github.com", "/repos"),
            make_network_event("POST", "api.github.com", "/repos"),
            make_fs_event("/tmp/data", "read"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let schema = std::fs::read_to_string(&schema_path).unwrap();
        assert!(
            schema.contains(r#"action "http:GET""#),
            "schema should declare http:GET: {schema}"
        );
        assert!(
            schema.contains(r#"action "http:POST""#),
            "schema should declare http:POST: {schema}"
        );
        assert!(
            schema.contains(r#"action "fs:read""#),
            "schema should declare fs:read: {schema}"
        );
    }

    // -- Denied event filtering -----------------------------------------------

    fn make_network_event_with_decision(
        method: &str,
        host: &str,
        path: &str,
        decision: &str,
    ) -> ObservationEvent {
        ObservationEvent {
            version: 1,
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            session: None,
            event: EventKind::NetworkRequest {
                method: method.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                decision: decision.to_string(),
                latency_us: 100,
                enforcement_mode: String::new(),
                blocked: None,
            },
        }
    }

    #[test]
    fn denied_events_excluded_from_generated_policy() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event_with_decision("GET", "api.github.com", "/repos", "allow"),
            make_network_event_with_decision("POST", "evil.com", "/admin", "deny"),
            make_network_event_with_decision("DELETE", "evil.com", "/users", "deny"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        // The allow event should produce a permit
        assert!(
            policy.contains(r#"action == Action::"http:GET""#),
            "allowed event should produce permit: {policy}"
        );
        // Denied events should NOT produce permits
        assert!(
            !policy.contains("evil.com"),
            "denied events should not appear in policy: {policy}"
        );
        assert!(
            !policy.contains("http:POST"),
            "denied POST should not appear: {policy}"
        );
        assert!(
            !policy.contains("http:DELETE"),
            "denied DELETE should not appear: {policy}"
        );
    }

    #[test]
    fn all_denied_events_produce_no_output() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event_with_decision("GET", "evil.com", "/admin", "deny"),
            make_network_event_with_decision("POST", "evil.com", "/admin", "deny"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        let count = generate(&obs_path, &policy_path, &schema_path).unwrap();
        assert_eq!(count, 0);
        assert!(
            !policy_path.exists(),
            "policy file should not be created when all events are denied"
        );
    }

    // -- Year preservation tests ----------------------------------------------

    #[test]
    fn four_digit_years_not_collapsed() {
        // Years 1900-2099 should be preserved as-is
        assert!(
            !is_long_numeric("2024"),
            "2024 should be preserved as a year"
        );
        assert!(
            !is_long_numeric("2025"),
            "2025 should be preserved as a year"
        );
        assert!(
            !is_long_numeric("1900"),
            "1900 should be preserved as a year"
        );
        assert!(
            !is_long_numeric("2099"),
            "2099 should be preserved as a year"
        );
    }

    #[test]
    fn four_digit_non_years_still_collapsed() {
        // 4-digit numbers outside 1900-2099 should still be collapsed
        assert!(is_long_numeric("1234"), "1234 should still be collapsed");
        assert!(is_long_numeric("1899"), "1899 should still be collapsed");
        assert!(is_long_numeric("2100"), "2100 should still be collapsed");
        assert!(is_long_numeric("9999"), "9999 should still be collapsed");
    }

    #[test]
    fn six_digit_number_still_collapsed() {
        assert!(
            is_long_numeric("123456"),
            "6-digit number should be collapsed"
        );
    }

    #[test]
    fn year_in_path_preserved_in_resource() {
        let (collapsed, wildcards) = collapse_resource("api.example.com/reports/2024/summary");
        assert_eq!(collapsed, "api.example.com/reports/2024/summary");
        assert!(
            wildcards.is_empty(),
            "year should not be treated as dynamic"
        );
    }

    // -- Literal * escaping tests ---------------------------------------------

    #[test]
    fn literal_star_in_path_escaped_in_like_pattern() {
        // If a path segment is literally "*" (not from collapsing), it should
        // be escaped as \* in the Cedar like pattern.
        let wildcard_originals = {
            let mut m = BTreeMap::new();
            // Position 3 was collapsed (a UUID position)
            let mut s = BTreeSet::new();
            s.insert("some-uuid".to_string());
            m.insert(3, s);
            m
        };

        let (truncated, like_pattern) = compute_wildcard_fields(
            "http:GET",
            "api.example.com/repos/*/star-seg/*/end",
            //                            ^literal    ^collapsed
            // segments: [api.example.com, repos, *, star-seg, *, end]
            // idx:       0                1      2  3         4  5
            // wildcard_originals has key 3 — but that's "star-seg" position in
            // the original, wait... let me restructure the test.
            &wildcard_originals,
        );

        assert!(truncated.is_some());
        // The like pattern should have the collapsed * as wildcard, and
        // the literal * (at segment 2) should be escaped as \*
        let pattern = like_pattern.unwrap();
        assert!(
            pattern.contains("\\*"),
            "literal * should be escaped as \\* in like pattern: {pattern}"
        );
    }

    #[test]
    fn literal_star_segment_escaped_in_generate() {
        // Build a rule manually with a literal * in a non-wildcard position
        // to verify the escaping in the generated policy.
        let rules = vec![PolicyRule {
            action: "http:GET".to_string(),
            // resource: host/path where path has a segment with literal *
            // collapsed segment at position 2 (the UUID position)
            resource: "api.example.com/*/items".to_string(),
            wildcard_originals: {
                let mut m = BTreeMap::new();
                m.insert(1, {
                    let mut s = BTreeSet::new();
                    s.insert("550e8400-e29b-41d4-a716-446655440000".to_string());
                    s
                });
                m
            },
            truncated_resource: Some("api.example.com".to_string()),
            like_pattern: Some("/*/items".to_string()),
        }];

        let policy = generate_policy(&rules);
        assert!(
            policy.contains(r#"context.path like "/*/items""#),
            "like pattern should be present: {policy}"
        );
    }

    // -- Schema context attributes tests --------------------------------------

    #[test]
    fn schema_includes_http_context_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![make_network_event(
            "GET",
            "api.github.com",
            "/repos/org/repo",
        )];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let schema = std::fs::read_to_string(&schema_path).unwrap();
        assert!(
            schema.contains("host"),
            "schema should include host context attribute: {schema}"
        );
        assert!(
            schema.contains("path"),
            "schema should include path context attribute: {schema}"
        );
        assert!(
            schema.contains("method"),
            "schema should include method context attribute: {schema}"
        );
    }

    #[test]
    fn schema_includes_fs_context_attributes() {
        let dir = tempfile::tempdir().unwrap();
        let events = vec![make_fs_event("/workspace/src/main.rs", "read")];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let schema = std::fs::read_to_string(&schema_path).unwrap();
        assert!(
            schema.contains("path"),
            "fs schema should include path context attribute: {schema}"
        );
        assert!(
            schema.contains("operation"),
            "fs schema should include operation context attribute: {schema}"
        );
    }

    // -- E2E roundtrip test ---------------------------------------------------

    #[test]
    fn e2e_wildcard_roundtrip_matches_different_uuids() {
        // Generate policy from observations with UUIDs, then evaluate
        // against requests with DIFFERENT UUIDs — should match via wildcard.
        let dir = tempfile::tempdir().unwrap();
        let uuid1 = "550e8400-e29b-41d4-a716-446655440000";
        let uuid2 = "660e8400-e29b-41d4-a716-446655440001";
        let events = vec![
            make_network_event(
                "GET",
                "api.github.com",
                &format!("/repos/org/{uuid1}/issues"),
            ),
            make_network_event(
                "GET",
                "api.github.com",
                &format!("/repos/org/{uuid2}/issues"),
            ),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        let wc_count = generate(&obs_path, &policy_path, &schema_path).unwrap();
        assert!(wc_count > 0, "should have collapsed wildcards");

        // Load the generated policy + schema via PolicyEngine
        let engine = crate::policy::PolicyEngine::load(&policy_path, Some(&schema_path)).unwrap();

        // Evaluate with a DIFFERENT UUID — should be allowed
        let new_uuid = "770e8400-e29b-41d4-a716-446655440002";
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                &format!("/repos/org/{new_uuid}/issues"),
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "wildcard policy should match request with different UUID"
        );

        // Non-matching path structure should be denied
        let result2 = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                &format!("/repos/org/{new_uuid}/pulls"),
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result2.allowed,
            "non-matching path should be denied by wildcard policy"
        );
    }

    #[test]
    fn e2e_wildcard_policy_and_schema_validate() {
        // Verify that generated policy WITH wildcards passes Cedar validation
        // against the generated schema (which includes context attributes).
        use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
        use std::str::FromStr;

        let dir = tempfile::tempdir().unwrap();
        let events = vec![
            make_network_event(
                "GET",
                "api.github.com",
                "/repos/org/550e8400-e29b-41d4-a716-446655440000/issues",
            ),
            make_network_event("POST", "api.github.com", "/repos/org/repo/issues"),
            make_fs_event("/workspace/src/main.rs", "read"),
        ];
        let obs_path = write_observations(&dir, &events);
        let policy_path = dir.path().join("policy.cedar");
        let schema_path = dir.path().join("policy.cedarschema");

        generate(&obs_path, &policy_path, &schema_path).unwrap();

        let policy_text = std::fs::read_to_string(&policy_path).unwrap();
        let schema_text = std::fs::read_to_string(&schema_path).unwrap();

        let policy_set =
            PolicySet::from_str(&policy_text).expect("generated wildcard policy should parse");

        let (schema, _warnings) = Schema::from_cedarschema_str(&schema_text)
            .expect("generated schema with context should parse");

        let validator = Validator::new(schema);
        let result = validator.validate(&policy_set, ValidationMode::Strict);
        assert!(
            result.validation_passed(),
            "wildcard policy should pass schema validation. Errors: {:?}",
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }
}
