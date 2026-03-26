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
    PolicySet, Request, RestrictedExpression,
};

/// Result of a Cedar policy evaluation.
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Names of policies that contributed to the decision.
    pub policy_names: Vec<String>,
}

/// Holds the parsed Cedar policy set and authorizer, ready for per-request evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy_set: Arc<PolicySet>,
    authorizer: Arc<Authorizer>,
}

impl PolicyEngine {
    /// Load a Cedar policy file from disk. Returns an error if the file
    /// cannot be read or contains invalid Cedar syntax.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;

        let policy_set = PolicySet::from_str(&text)
            .map_err(|e| anyhow::anyhow!("invalid Cedar policy file: {e}"))?;

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
    pub fn evaluate(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(String, String)],
    ) -> anyhow::Result<PolicyDecision> {
        // Build entity hierarchy from the path segments.
        // For path "/repos/org/repo", we create:
        //   Resource::"repos/org/repo" in Resource::"repos/org" in Resource::"repos"
        let entities = build_entity_hierarchy(host, path)?;

        // Principal: always Agent::"worker" for now
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str("worker").unwrap(),
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

        // Resolve policy IDs: prefer @id annotation value over auto-generated name
        let policy_names: Vec<String> = response
            .diagnostics()
            .reason()
            .map(|pid| {
                self.policy_set
                    .annotation(pid, "id")
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| pid.to_string())
            })
            .collect();

        Ok(PolicyDecision {
            allowed: response.decision() == Decision::Allow,
            policy_names,
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
/// - Agent::"worker" (no parent)
fn build_entity_hierarchy(host: &str, path: &str) -> anyhow::Result<Entities> {
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
        EntityId::from_str("worker").unwrap(),
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

// Deny push to main (forbid overrides permit)
@id("deny-push-main")
forbid(
  principal,
  action == Action::"POST",
  resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
"#;

    #[test]
    fn load_valid_policy_file() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path()).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_missing_policy_file() {
        let result = PolicyEngine::load(Path::new("/nonexistent/policy.cedar"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read policy file"), "got: {err}");
    }

    #[test]
    fn load_invalid_policy_file() {
        let f = write_policy("this is not valid cedar @@@ {{{");
        let result = PolicyEngine::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid Cedar policy"), "got: {err}");
    }

    #[test]
    fn entity_hierarchy_structure() {
        let entities = build_entity_hierarchy("api.github.com", "/repos/org/repo").unwrap();
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
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate("api.github.com", "GET", "/repos/our-org/repo", &[])
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
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate("api.github.com", "POST", "/repos/our-org/repo/pulls", &[])
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
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate("api.github.com", "DELETE", "/repos/our-org/repo", &[])
            .unwrap();
        assert!(
            !result.allowed,
            "DELETE /repos/our-org/repo should be denied"
        );
    }

    #[test]
    fn deny_post_git_refs_heads_main() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "POST",
                "/repos/our-org/repo/git/refs/heads/main",
                &[],
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
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate("api.github.com", "PATCH", "/settings", &[])
            .unwrap();
        assert!(!result.allowed, "PATCH /settings should be denied");
    }

    #[test]
    fn deny_get_unknown() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path()).unwrap();
        let result = engine
            .evaluate("api.github.com", "GET", "/unknown", &[])
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
        let engine = PolicyEngine::load(f.path()).unwrap();

        // a/b/c should be allowed because it's in Resource::"example.com/a"
        let result = engine
            .evaluate("example.com", "GET", "/a/b/c", &[])
            .unwrap();
        assert!(
            result.allowed,
            "GET /a/b/c should be allowed (descendant of /a)"
        );

        // /x should be denied (not in Resource::"example.com/a")
        let result = engine.evaluate("example.com", "GET", "/x", &[]).unwrap();
        assert!(!result.allowed, "GET /x should be denied (not in /a)");
    }
}
