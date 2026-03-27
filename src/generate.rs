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
use std::io::{BufRead, BufReader};
use std::path::Path;

use crate::observe::{EventKind, ObservationEvent};

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
            .map_err(|e| anyhow::anyhow!("invalid JSON on line {}: {e}", line_num + 1))?;
        events.push(event);
    }

    Ok(events)
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
        .map(|((action, resource), wildcard_originals)| PolicyRule {
            action,
            resource,
            wildcard_originals,
        })
        .collect();

    (rules, wildcard_count)
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
        | EventKind::PolicyViolation { .. } => None,
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

/// Check for pure numeric strings with more than 3 digits.
fn is_long_numeric(s: &str) -> bool {
    s.len() > 3 && s.bytes().all(|b| b.is_ascii_digit())
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

        writeln!(out, "permit(").unwrap();
        writeln!(out, "  principal,").unwrap();
        writeln!(out, "  action == Action::\"{}\",", rule.action).unwrap();
        writeln!(out, "  resource in Resource::\"{}\"", rule.resource).unwrap();
        writeln!(out, ");").unwrap();

        // Blank line between rules
        if i + 1 < rules.len() {
            writeln!(out).unwrap();
        }
    }

    out
}

/// Generate Cedar schema text covering all actions referenced by the rules.
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
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
            event: EventKind::NetworkRequest {
                method: method.to_string(),
                host: host.to_string(),
                path: path.to_string(),
                decision: "allow".to_string(),
                latency_us: 100,
                enforcement_mode: String::new(),
            },
        }
    }

    fn make_fs_event(path: &str, operation: &str) -> ObservationEvent {
        ObservationEvent {
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
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
        assert!(
            policy.contains("api.example.com/users/*/profile"),
            "policy should contain wildcard: {policy}"
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
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
                event: EventKind::ContainerStart {
                    container_id: "abc123".to_string(),
                    image: "node:20".to_string(),
                },
            },
            ObservationEvent {
                timestamp: "2026-03-27T00:00:00.000Z".to_string(),
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
            timestamp: "2026-03-27T00:00:00.000Z".to_string(),
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
}
