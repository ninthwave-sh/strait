//! Cedar policy evaluation for MITM'd HTTP requests.
//!
//! Loads a `.cedar` policy file at startup and evaluates each intercepted
//! request against the policy set. The entity hierarchy is built from the
//! request's URL path: splitting `/a/b/c` produces `Resource::"a/b/c"` as a
//! child of `Resource::"a/b"`, which is a child of `Resource::"a"`.
//!
//! Default disposition is DENY (Cedar's native behavior when no permit
//! policy matches).

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context as _;
use cedar_policy::{
    Authorizer, Context, Decision, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};

/// Result of a Cedar policy evaluation.
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Names of policies that contributed to the decision.
    pub policy_names: Vec<String>,
    /// `@reason` annotation values from matching policies (if any).
    pub policy_reasons: Vec<String>,
}

/// Holds the parsed Cedar policy set and authorizer, ready for per-request evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy_set: Arc<PolicySet>,
    authorizer: Arc<Authorizer>,
}

impl PolicyEngine {
    /// Load a Cedar policy file from disk, optionally validating it against a
    /// `.cedarschema` file. Returns an error if the file cannot be read,
    /// contains invalid Cedar syntax, or violates the schema.
    pub fn load(path: &Path, schema_path: Option<&Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;

        let policy_set = PolicySet::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid Cedar policy file: {e}"))?;

        // Validate against schema if provided
        if let Some(schema_path) = schema_path {
            let schema_text = std::fs::read_to_string(schema_path).with_context(|| {
                format!("failed to read schema file: {}", schema_path.display())
            })?;

            let (schema, _warnings) = Schema::from_cedarschema_str(&schema_text).map_err(|e| {
                anyhow::anyhow!("invalid Cedar schema file {}: {e}", schema_path.display())
            })?;

            let validator = Validator::new(schema);
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            if !result.validation_passed() {
                let errors: Vec<String> = result
                    .validation_errors()
                    .map(|e| format!("  - {e}"))
                    .collect();
                anyhow::bail!(
                    "Cedar policy validation failed against schema {}:\n{}",
                    schema_path.display(),
                    errors.join("\n")
                );
            }
        }

        Ok(Self {
            policy_set: Arc::new(policy_set),
            authorizer: Arc::new(Authorizer::new()),
        })
    }

    /// Evaluate a request against the loaded policy set.
    ///
    /// - `host`: target hostname (e.g. `api.github.com`)
    /// - `method`: HTTP method (e.g. `GET`, `POST`)
    /// - `path`: URL path (e.g. `/repos/org/repo`)
    /// - `headers`: list of (name, value) header pairs
    /// - `agent_id`: identity of the requesting agent (e.g. `"worker"`, `"ci-bot"`)
    pub fn evaluate(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        agent_id: &str,
    ) -> anyhow::Result<PolicyDecision> {
        // Build entity hierarchy from the path segments.
        // For path "/repos/org/repo", we create:
        //   Resource::"repos/org/repo" in Resource::"repos/org" in Resource::"repos"
        let entities = build_entity_hierarchy(host, path, agent_id)?;

        // Principal: Agent::"<agent_id>"
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str(agent_id).unwrap(),
        );

        // Action: Action::"<METHOD>"
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(method).unwrap(),
        );

        // Resource: Resource::"<host>/<path_without_leading_slash>"
        let resource_id = build_resource_id(host, path);
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str(&resource_id).unwrap(),
        );

        // Context: { host, path, method, headers }
        let header_pairs: Vec<(String, RestrictedExpression)> = headers
            .iter()
            .map(|(k, v)| {
                (
                    k.to_lowercase(),
                    RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(v)))
                        .unwrap(),
                )
            })
            .collect();

        let mut context_pairs: Vec<(String, RestrictedExpression)> = vec![
            (
                "host".to_string(),
                RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(host)))
                    .unwrap(),
            ),
            (
                "path".to_string(),
                RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(path)))
                    .unwrap(),
            ),
            (
                "method".to_string(),
                RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(method)))
                    .unwrap(),
            ),
        ];

        // Add individual headers as context attributes
        context_pairs.extend(header_pairs);

        let context =
            Context::from_pairs(context_pairs).context("failed to build Cedar context")?;

        let request = Request::new(principal, action, resource, context, None)
            .map_err(|e| anyhow::anyhow!("failed to build Cedar request: {e}"))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        // Resolve policy IDs: prefer @id annotation value over auto-generated name.
        // Also collect @reason annotations for human-readable denial messages.
        let mut policy_names = Vec::new();
        let mut policy_reasons = Vec::new();

        for pid in response.diagnostics().reason() {
            let name = self
                .policy_set
                .annotation(pid, "id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| pid.to_string());
            policy_names.push(name);

            // Collect @reason annotation if present (strait convention for
            // human-readable denial messages in audit logs).
            if let Some(reason) = self.policy_set.annotation(pid, "reason") {
                policy_reasons.push(reason.to_string());
            }
        }

        Ok(PolicyDecision {
            allowed: response.decision() == Decision::Allow,
            policy_names,
            policy_reasons,
        })
    }
}

/// Build a resource ID string from host and path.
/// e.g. host="api.github.com", path="/repos/org/repo" -> "api.github.com/repos/org/repo"
fn build_resource_id(host: &str, path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        host.to_string()
    } else {
        format!("{host}/{trimmed}")
    }
}

/// Build the Cedar entity hierarchy from the host and URL path.
///
/// For host="api.github.com" and path="/repos/org/repo", creates:
/// - Resource::"api.github.com/repos/org/repo" (parent: api.github.com/repos/org)
/// - Resource::"api.github.com/repos/org" (parent: api.github.com/repos)
/// - Resource::"api.github.com/repos" (parent: api.github.com)
/// - Resource::"api.github.com" (no parent)
/// - Agent::"<agent_id>" (no parent)
fn build_entity_hierarchy(host: &str, path: &str, agent_id: &str) -> anyhow::Result<Entities> {
    let resource_type = EntityTypeName::from_str("Resource").unwrap();
    let mut entities = Vec::new();

    // Build the chain of resource segments
    let trimmed = path.trim_start_matches('/');
    let segments: Vec<&str> = if trimmed.is_empty() {
        vec![]
    } else {
        trimmed.split('/').collect()
    };

    // Build resource IDs from most specific to least specific
    // e.g. ["api.github.com/repos/org/repo", "api.github.com/repos/org", "api.github.com/repos", "api.github.com"]
    let mut resource_ids: Vec<String> = Vec::new();
    for i in (0..=segments.len()).rev() {
        let id = if i == 0 {
            host.to_string()
        } else {
            format!("{host}/{}", segments[..i].join("/"))
        };
        resource_ids.push(id);
    }

    // Create entities with parent relationships
    for (idx, id) in resource_ids.iter().enumerate() {
        let uid = EntityUid::from_type_name_and_id(
            resource_type.clone(),
            EntityId::from_str(id).unwrap(),
        );

        let parents: HashSet<EntityUid> = if idx + 1 < resource_ids.len() {
            let parent_uid = EntityUid::from_type_name_and_id(
                resource_type.clone(),
                EntityId::from_str(&resource_ids[idx + 1]).unwrap(),
            );
            HashSet::from([parent_uid])
        } else {
            HashSet::new()
        };

        entities.push(Entity::new_no_attrs(uid, parents));
    }

    // Add the principal entity
    let agent_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Agent").unwrap(),
        EntityId::from_str(agent_id).unwrap(),
    );
    entities.push(Entity::new_no_attrs(agent_uid, HashSet::new()));

    // Add action entities for common HTTP methods
    for method in &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(method).unwrap(),
        );
        entities.push(Entity::new_no_attrs(action_uid, HashSet::new()));
    }

    Entities::from_entities(entities, None)
        .map_err(|e| anyhow::anyhow!("failed to build entity set: {e}"))
}

/// Escape a string for use in a Cedar string literal.
fn escape_cedar_string(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

/// Build the structured JSON body for a 403 denial response.
pub fn deny_response_body(
    host: &str,
    method: &str,
    path: &str,
    policy_names: &[String],
) -> serde_json::Value {
    let policy_display = if policy_names.is_empty() {
        "default-deny".to_string()
    } else {
        policy_names.join(", ")
    };

    serde_json::json!({
        "error": "policy_denied",
        "message": format!("Request denied by Cedar policy: {policy_display}"),
        "host": host,
        "method": method,
        "path": path,
        "policy": policy_display,
        "hint": format!(
            "No permit policy allows {method} {path} on {host}. Check your .cedar policy file."
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_policy(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// Example GitHub Cedar policy from the design doc.
    ///
    /// Annotations used by strait:
    /// - `@id("...")` — human-readable policy name (used in audit logs and deny responses)
    /// - `@reason("...")` — human-readable denial reason (strait convention, included in
    ///   audit `denial_reason` field when this policy causes a deny)
    const GITHUB_POLICY: &str = r#"
// Allow read access to org repos
@id("read-repos")
permit(
  principal == Agent::"worker",
  action == Action::"GET",
  resource in Resource::"api.github.com/repos/our-org"
);

// Allow PR creation on org repos
@id("create-prs")
permit(
  principal == Agent::"worker",
  action == Action::"POST",
  resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

// Deny push to main (forbid overrides permit).
// @reason is a strait convention: its value appears in the audit log's
// denial_reason field when this policy causes a deny.
@id("deny-push-main")
@reason("Direct pushes to main are not allowed; use a pull request")
forbid(
  principal,
  action == Action::"POST",
  resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
"#;

    #[test]
    fn load_valid_policy_file() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_missing_policy_file() {
        let result = PolicyEngine::load(Path::new("/nonexistent/policy.cedar"), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read policy file"), "got: {err}");
    }

    #[test]
    fn load_invalid_policy_file() {
        let f = write_policy("this is not valid cedar @@@ {{{");
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid Cedar policy"), "got: {err}");
    }

    #[test]
    fn entity_hierarchy_structure() {
        let entities =
            build_entity_hierarchy("api.github.com", "/repos/org/repo", "worker").unwrap();
        // Should have: 4 resource entities + 1 agent + 7 action entities = 12
        let count = entities.iter().count();
        assert!(count >= 4, "expected at least 4 entities, got {count}");
    }

    #[test]
    fn build_resource_id_basic() {
        assert_eq!(
            build_resource_id("api.github.com", "/repos/org/repo"),
            "api.github.com/repos/org/repo"
        );
    }

    #[test]
    fn build_resource_id_root_path() {
        assert_eq!(build_resource_id("api.github.com", "/"), "api.github.com");
    }

    // --- 6 test cases from the TODO ---

    #[test]
    fn allow_get_repos_org_repo() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "GET",
                "/repos/our-org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "GET /repos/our-org/repo should be allowed");
        assert!(
            result.policy_names.iter().any(|n| n.contains("read-repos")),
            "expected read-repos policy, got {:?}",
            result.policy_names
        );
    }

    #[test]
    fn allow_post_pulls() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/repo/pulls",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "POST /repos/our-org/repo/pulls should be allowed"
        );
        assert!(
            result.policy_names.iter().any(|n| n.contains("create-prs")),
            "expected create-prs policy, got {:?}",
            result.policy_names
        );
    }

    #[test]
    fn deny_delete_repos_org_repo() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "DELETE",
                "/repos/our-org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "DELETE /repos/our-org/repo should be denied"
        );
    }

    #[test]
    fn deny_post_git_refs_heads_main() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/repo/git/refs/heads/main",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "POST /repos/our-org/repo/git/refs/heads/main should be denied"
        );
    }

    #[test]
    fn deny_patch_settings() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate("api.github.com", "PATCH", "/settings", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "PATCH /settings should be denied");
    }

    #[test]
    fn deny_get_unknown() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate("api.github.com", "GET", "/unknown", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "GET /unknown should be denied");
    }

    // --- 403 response body ---

    #[test]
    fn deny_response_body_has_required_fields() {
        let body = deny_response_body(
            "api.github.com",
            "DELETE",
            "/repos/org/repo",
            &["deny-destructive".to_string()],
        );

        assert_eq!(body["error"], "policy_denied");
        assert!(body["message"]
            .as_str()
            .unwrap()
            .contains("deny-destructive"));
        assert_eq!(body["host"], "api.github.com");
        assert_eq!(body["method"], "DELETE");
        assert_eq!(body["path"], "/repos/org/repo");
        assert_eq!(body["policy"], "deny-destructive");
        assert!(body["hint"].as_str().unwrap().contains("DELETE"));
    }

    #[test]
    fn deny_response_body_default_deny() {
        let body = deny_response_body("host", "GET", "/path", &[]);
        assert_eq!(body["policy"], "default-deny");
    }

    // --- Entity hierarchy descent test ---

    #[test]
    fn entity_hierarchy_descent() {
        // Verify that resource a/b/c is descendant of a/b which is descendant of a
        let f = write_policy(
            r#"
@id("allow-in-parent")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"example.com/a"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // a/b/c should be allowed because it's in Resource::"example.com/a"
        let result = engine
            .evaluate("example.com", "GET", "/a/b/c", &[], "worker")
            .unwrap();
        assert!(
            result.allowed,
            "GET /a/b/c should be allowed (descendant of /a)"
        );

        // /x should be denied (not in Resource::"example.com/a")
        let result = engine
            .evaluate("example.com", "GET", "/x", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "GET /x should be denied (not in /a)");
    }

    // --- Schema validation tests ---

    fn write_schema(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::with_suffix(".cedarschema").unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    /// A valid Cedar schema matching our entity model.
    const VALID_SCHEMA: &str = r#"
entity Agent;
entity Resource in [Resource];
action "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"
    appliesTo { principal: Agent, resource: Resource, context: {} };
"#;

    /// A Cedar policy that conforms to VALID_SCHEMA.
    const SCHEMA_CONFORMING_POLICY: &str = r#"
@id("allow-get")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"example.com/api"
);
"#;

    #[test]
    fn load_valid_policy_with_valid_schema() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let schema_file = write_schema(VALID_SCHEMA);
        let engine = PolicyEngine::load(policy_file.path(), Some(schema_file.path())).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_valid_policy_without_schema_backward_compat() {
        // Existing behavior: no schema → skip validation
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let engine = PolicyEngine::load(policy_file.path(), None).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_policy_violating_schema() {
        // Policy references an entity type not in the schema
        let bad_policy = r#"
@id("bad-principal")
permit(
    principal == UnknownType::"foo",
    action == Action::"GET",
    resource
);
"#;
        let policy_file = write_policy(bad_policy);
        let schema_file = write_schema(VALID_SCHEMA);
        let result = PolicyEngine::load(policy_file.path(), Some(schema_file.path()));
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("Cedar policy validation failed"),
            "expected validation failure message, got: {err}"
        );
    }

    #[test]
    fn load_invalid_schema_file() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let schema_file = write_schema("this is not valid cedarschema @@@ {{{");
        let result = PolicyEngine::load(policy_file.path(), Some(schema_file.path()));
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("invalid Cedar schema file"),
            "expected schema parse error, got: {err}"
        );
    }

    #[test]
    fn load_missing_schema_file() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let result = PolicyEngine::load(
            policy_file.path(),
            Some(Path::new("/nonexistent/schema.cedarschema")),
        );
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to read schema file"),
            "expected file-not-found error, got: {err}"
        );
    }

    // --- Agent identity tests ---

    #[test]
    fn agent_identity_used_as_cedar_principal() {
        // Policy allows only Agent::"ci-bot"
        let f = write_policy(
            r#"
@id("ci-read")
permit(
    principal == Agent::"ci-bot",
    action == Action::"GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // ci-bot should be allowed
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "ci-bot")
            .unwrap();
        assert!(result.allowed, "ci-bot should be allowed");

        // anonymous should be denied (different principal)
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "anonymous")
            .unwrap();
        assert!(!result.allowed, "anonymous should be denied");
    }

    #[test]
    fn different_agents_get_different_cedar_results() {
        // Policy allows worker to read, ci-bot to write, denies others
        let f = write_policy(
            r#"
@id("worker-read")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"api.github.com"
);

@id("ci-bot-write")
permit(
    principal == Agent::"ci-bot",
    action == Action::"POST",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // worker can GET, cannot POST
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "worker")
            .unwrap();
        assert!(result.allowed, "worker GET should be allowed");
        let result = engine
            .evaluate("api.github.com", "POST", "/repos/org/repo", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "worker POST should be denied");

        // ci-bot can POST, cannot GET
        let result = engine
            .evaluate("api.github.com", "POST", "/repos/org/repo", &[], "ci-bot")
            .unwrap();
        assert!(result.allowed, "ci-bot POST should be allowed");
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "ci-bot")
            .unwrap();
        assert!(!result.allowed, "ci-bot GET should be denied");
    }

    // --- @reason annotation test ---

    #[test]
    fn reason_annotation_collected_from_matching_policies() {
        let f = write_policy(
            r#"
// @reason is a strait convention for human-readable denial messages in audit logs.
@id("deny-destructive")
@reason("Destructive operations are not allowed on production repos")
forbid(
    principal,
    action == Action::"DELETE",
    resource in Resource::"api.github.com"
);

@id("allow-read")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // DELETE triggers the forbid with @reason
        let result = engine
            .evaluate("api.github.com", "DELETE", "/repos/org/repo", &[], "worker")
            .unwrap();
        assert!(!result.allowed);
        assert!(
            result
                .policy_reasons
                .iter()
                .any(|r| r.contains("Destructive operations")),
            "expected @reason annotation, got {:?}",
            result.policy_reasons
        );

        // GET triggers the permit (no @reason annotation)
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "worker")
            .unwrap();
        assert!(result.allowed);
        assert!(
            result.policy_reasons.is_empty(),
            "permit without @reason should have empty reasons, got {:?}",
            result.policy_reasons
        );
    }

    // --- Example file validation tests ---

    #[test]
    fn example_policy_loads_without_errors() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None);
        assert!(
            engine.is_ok(),
            "example policy failed to load: {:#}",
            engine.unwrap_err()
        );
    }

    #[test]
    fn generic_denial_reason_when_no_annotation() {
        let f = write_policy(
            r#"
@id("deny-all")
forbid(
    principal,
    action,
    resource
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate("api.github.com", "GET", "/repos/org/repo", &[], "worker")
            .unwrap();
        assert!(!result.allowed);
        // No @reason annotation → policy_reasons is empty
        assert!(
            result.policy_reasons.is_empty(),
            "policy without @reason should have empty reasons"
        );
    }

    // --- Example file validation tests ---

    #[test]
    fn example_schema_validates_example_policy() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let schema_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedarschema");
        let engine = PolicyEngine::load(&policy_path, Some(&schema_path));
        assert!(
            engine.is_ok(),
            "example policy failed schema validation: {:#}",
            engine.unwrap_err()
        );
    }

    #[test]
    fn example_policy_allows_get_org_repos() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let schema_path =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedarschema");
        let engine = PolicyEngine::load(&policy_path, Some(&schema_path)).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "GET",
                "/repos/our-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "GET /repos/our-org/my-repo should be allowed"
        );
    }

    #[test]
    fn example_policy_allows_create_pr() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/my-repo/pulls",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "POST /repos/our-org/my-repo/pulls should be allowed"
        );
    }

    #[test]
    fn example_policy_denies_push_to_main() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/my-repo/git/refs/heads/main",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "POST to git/refs/heads/main should be denied"
        );
    }

    #[test]
    fn example_policy_denies_push_to_release_branch() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/my-repo/git/refs/heads/release/v1.0",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "POST to git/refs/heads/release/v1.0 should be denied"
        );
    }

    #[test]
    fn example_policy_denies_repo_deletion() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "DELETE",
                "/repos/our-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "DELETE /repos/our-org/my-repo should be denied"
        );
    }

    #[test]
    fn example_policy_denies_settings_access() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "PATCH",
                "/repos/our-org/my-repo/settings",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "PATCH /repos/our-org/my-repo/settings should be denied"
        );
    }

    #[test]
    fn example_policy_denies_outside_org() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "GET",
                "/repos/other-org/their-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "GET /repos/other-org/their-repo should be denied"
        );
    }
}
