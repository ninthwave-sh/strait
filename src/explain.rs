//! Human-readable Cedar policy summaries.
//!
//! Parses a Cedar policy file and produces a plain-English description of
//! what the policy set allows and denies. Groups rules by action namespace
//! (http, fs, proc) so non-Cedar-experts can review generated policies.

use std::fmt::Write as _;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context as _;
use cedar_policy::{ActionConstraint, Effect, PolicySet, ResourceConstraint};

/// A single human-readable rule extracted from a Cedar policy.
#[derive(Debug)]
#[allow(dead_code)]
struct Rule {
    /// The policy's `@id` annotation, if present.
    id: Option<String>,
    /// The action namespace (e.g. "http", "fs", "proc") or "any".
    namespace: String,
    /// The specific action within the namespace (e.g. "GET", "read", "exec") or "any".
    action: String,
    /// Human-readable resource description.
    resource: String,
    /// Whether the policy has additional `when`/`unless` conditions.
    has_conditions: bool,
    /// The `@reason` annotation text, if present.
    reason: Option<String>,
}

/// Parse a Cedar policy file and return a human-readable explanation string.
pub fn explain(path: &Path) -> anyhow::Result<String> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;

    let policy_set =
        PolicySet::from_str(&text).map_err(|e| anyhow::anyhow!("invalid Cedar policy: {e}"))?;

    let mut permits: Vec<Rule> = Vec::new();
    let mut forbids: Vec<Rule> = Vec::new();

    for policy in policy_set.policies() {
        let effect = policy.effect();

        // Extract @id annotation
        let id = policy.annotation("id").map(|s| s.to_string());

        // Extract @reason annotation
        let reason = policy.annotation("reason").map(|s| s.to_string());

        // Parse action constraint
        let (namespace, action) = match policy.action_constraint() {
            ActionConstraint::Any => ("any".to_string(), "any".to_string()),
            ActionConstraint::Eq(uid) => parse_action_uid(&uid.to_string()),
            ActionConstraint::In(uids) => {
                if uids.len() == 1 {
                    parse_action_uid(&uids[0].to_string())
                } else {
                    let actions: Vec<String> = uids
                        .iter()
                        .map(|u| {
                            let (_, a) = parse_action_uid(&u.to_string());
                            a
                        })
                        .collect();
                    let ns = {
                        let (n, _) = parse_action_uid(&uids[0].to_string());
                        n
                    };
                    (ns, actions.join(", "))
                }
            }
        };

        // Parse resource constraint
        let resource = match policy.resource_constraint() {
            ResourceConstraint::Any => "any resource".to_string(),
            ResourceConstraint::Eq(uid) => format_resource(&uid.to_string()),
            ResourceConstraint::In(uid) => {
                format!("{} (and children)", format_resource(&uid.to_string()))
            }
            ResourceConstraint::Is(type_name) => format!("any {type_name}"),
            ResourceConstraint::IsIn(type_name, uid) => {
                format!("any {type_name} in {}", format_resource(&uid.to_string()))
            }
        };

        let has_conditions = policy.has_non_scope_constraint();

        let rule = Rule {
            id,
            namespace,
            action,
            resource,
            has_conditions,
            reason,
        };

        match effect {
            Effect::Permit => permits.push(rule),
            Effect::Forbid => forbids.push(rule),
        }
    }

    let mut output = String::new();

    if !permits.is_empty() {
        writeln!(output, "This policy allows:").unwrap();
        for rule in &permits {
            let desc = format_rule(rule);
            write!(output, "  - {desc}").unwrap();
            if rule.has_conditions {
                write!(output, " (conditional)").unwrap();
            }
            writeln!(output).unwrap();
        }
    }

    if !permits.is_empty() && !forbids.is_empty() {
        writeln!(output).unwrap();
    }

    if !forbids.is_empty() {
        writeln!(output, "This policy denies:").unwrap();
        for rule in &forbids {
            let desc = format_rule(rule);
            write!(output, "  - {desc}").unwrap();
            if rule.has_conditions {
                write!(output, " (conditional)").unwrap();
            }
            if let Some(ref reason) = rule.reason {
                write!(output, " — {reason}").unwrap();
            }
            writeln!(output).unwrap();
        }
    }

    if permits.is_empty() && forbids.is_empty() {
        writeln!(output, "This policy contains no permit or forbid rules.").unwrap();
        writeln!(
            output,
            "Cedar's default disposition is DENY — all requests will be denied."
        )
        .unwrap();
    }

    Ok(output)
}

/// Parse an action UID string like `Action::"http:GET"` into (namespace, action).
fn parse_action_uid(uid_str: &str) -> (String, String) {
    // Cedar UIDs look like: Action::"http:GET"
    // Extract the entity ID part between quotes
    let id = extract_entity_id(uid_str);

    if let Some((ns, act)) = id.split_once(':') {
        (ns.to_string(), act.to_string())
    } else {
        ("other".to_string(), id.to_string())
    }
}

/// Format a resource UID like `Resource::"api.github.com/repos/org"` into
/// a human-readable string like `api.github.com/repos/org`.
fn format_resource(uid_str: &str) -> String {
    extract_entity_id(uid_str)
}

/// Extract the entity ID from a Cedar entity UID string.
///
/// Handles formats like:
/// - `Action::"http:GET"` → `http:GET`
/// - `Resource::"api.github.com/repos/org"` → `api.github.com/repos/org`
fn extract_entity_id(uid_str: &str) -> String {
    // Find the first `"` and last `"`, extract what's between them
    if let Some(start) = uid_str.find('"') {
        let rest = &uid_str[start + 1..];
        if let Some(end) = rest.rfind('"') {
            return rest[..end].to_string();
        }
    }
    // Fallback: return as-is
    uid_str.to_string()
}

/// Format a single rule into a human-readable description.
fn format_rule(rule: &Rule) -> String {
    match rule.namespace.as_str() {
        "http" => format_http_rule(rule),
        "fs" => format_fs_rule(rule),
        "proc" => format_proc_rule(rule),
        "any" => format_any_rule(rule),
        _ => format_generic_rule(rule),
    }
}

fn format_http_rule(rule: &Rule) -> String {
    let method = &rule.action;
    let resource = &rule.resource;

    if resource == "any resource" {
        if method == "any" {
            "All HTTP requests".to_string()
        } else {
            format!("{method} requests")
        }
    } else {
        format!("{method} requests to {resource}")
    }
}

fn format_fs_rule(rule: &Rule) -> String {
    let action = &rule.action;
    let resource = &rule.resource;

    let verb = match action.as_str() {
        "read" => "Read",
        "write" => "Write",
        "read, write" | "write, read" => "Read and write",
        "any" => "Access",
        other => other,
    };

    if resource == "any resource" {
        format!("{verb} files")
    } else {
        format!("{verb} files under {resource}")
    }
}

fn format_proc_rule(rule: &Rule) -> String {
    let action = &rule.action;
    let resource = &rule.resource;

    let verb = match action.as_str() {
        "exec" => "Execute",
        "fork" => "Fork",
        "any" => "Run",
        other => other,
    };

    if resource == "any resource" {
        format!("{verb} any process")
    } else {
        format!("{verb} {resource}")
    }
}

fn format_any_rule(rule: &Rule) -> String {
    let resource = &rule.resource;
    if resource == "any resource" {
        "Any action on any resource".to_string()
    } else {
        format!("Any action on {resource}")
    }
}

fn format_generic_rule(rule: &Rule) -> String {
    let ns = &rule.namespace;
    let action = &rule.action;
    let resource = &rule.resource;

    if resource == "any resource" {
        format!("{ns}:{action}")
    } else {
        format!("{ns}:{action} on {resource}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn explain_text(cedar: &str) -> String {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(cedar.as_bytes()).unwrap();
        explain(f.path()).unwrap()
    }

    #[test]
    fn test_simple_permit() {
        let output = explain_text(
            r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/our-org"
);
"#,
        );
        assert!(output.contains("This policy allows:"), "output: {output}");
        assert!(
            output.contains("GET requests to api.github.com/repos/our-org"),
            "output: {output}"
        );
    }

    #[test]
    fn test_simple_forbid() {
        let output = explain_text(
            r#"
@reason("Repository deletion is too destructive")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);
"#,
        );
        assert!(output.contains("This policy denies:"), "output: {output}");
        assert!(output.contains("DELETE requests"), "output: {output}");
        assert!(
            output.contains("Repository deletion is too destructive"),
            "output: {output}"
        );
    }

    #[test]
    fn test_fs_actions() {
        let output = explain_text(
            r#"
permit(
    principal,
    action == Action::"fs:read",
    resource in Resource::"fs::/project/src"
);
"#,
        );
        assert!(output.contains("Read files under"), "output: {output}");
        assert!(output.contains("/project/src"), "output: {output}");
    }

    #[test]
    fn test_proc_actions() {
        let output = explain_text(
            r#"
permit(
    principal,
    action == Action::"proc:exec",
    resource == Resource::"proc::git"
);
"#,
        );
        assert!(output.contains("Execute"), "output: {output}");
        assert!(output.contains("git"), "output: {output}");
    }

    #[test]
    fn test_conditional_policy() {
        let output = explain_text(
            r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };
"#,
        );
        assert!(output.contains("(conditional)"), "output: {output}");
    }

    #[test]
    fn test_empty_policy() {
        let output = explain_text("");
        assert!(
            output.contains("no permit or forbid rules"),
            "output: {output}"
        );
    }

    #[test]
    fn test_mixed_permit_and_forbid() {
        let output = explain_text(
            r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);

@reason("Too destructive")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);
"#,
        );
        assert!(output.contains("This policy allows:"), "output: {output}");
        assert!(output.contains("This policy denies:"), "output: {output}");
    }

    #[test]
    fn test_unconstrained_action() {
        let output = explain_text(
            r#"
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/our-org" };
"#,
        );
        assert!(output.contains("Any action"), "output: {output}");
        assert!(output.contains("(conditional)"), "output: {output}");
    }

    #[test]
    fn test_file_not_found() {
        let result = explain(Path::new("/nonexistent/policy.cedar"));
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_cedar() {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(b"this is not cedar syntax {{{").unwrap();
        let result = explain(f.path());
        assert!(result.is_err());
    }

    #[test]
    fn test_github_example_policy() {
        // Test against a realistic policy similar to examples/github.cedar
        let output = explain_text(
            r#"
@id("read-org-repos")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/our-org"
);

@id("create-prs")
permit(
    principal == Agent::"worker",
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

@id("deny-repo-delete")
@reason("Repository deletion is too destructive for proxy access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);

@id("deny-outside-org")
@reason("Only repos in the allowed organization are accessible through this proxy")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/our-org" };
"#,
        );

        // Verify structure
        assert!(output.contains("This policy allows:"), "output: {output}");
        assert!(output.contains("This policy denies:"), "output: {output}");
        assert!(output.contains("GET requests"), "output: {output}");
        assert!(output.contains("POST requests"), "output: {output}");
        assert!(output.contains("DELETE requests"), "output: {output}");
        assert!(output.contains("conditional"), "output: {output}");
    }
}
