//! Cedar policy evaluation for agent requests.
//!
//! Loads a `.cedar` policy file at startup and evaluates each request
//! against the policy set. Actions use namespaced identifiers:
//!
//! - `Action::"http:GET"`, `Action::"http:POST"`, … — HTTP methods
//!
//! For HTTP requests, the entity hierarchy is built from the URL path:
//! splitting `/a/b/c` produces `Resource::"host/a/b/c"` as a child of
//! `Resource::"host/a/b"`, which is a child of `Resource::"host/a"`.
//!
//! Default disposition is DENY (Cedar's native behavior when no permit
//! policy matches).

use std::collections::HashSet;
use std::path::Path;
use std::str::FromStr;
use std::sync::Arc;

use anyhow::Context as _;

use crate::credentials::parse_aws_host;
use crate::observe::{BlockedRequest, CandidateException, ExceptionDirective, ExceptionScope};
use cedar_policy::{
    Authorizer, Context, Decision, Effect, Entities, Entity, EntityId, EntityTypeName, EntityUid,
    PolicyId, PolicySet, Request, RestrictedExpression, Schema, ValidationMode, Validator,
};

/// Result of a Cedar policy evaluation.
pub struct PolicyDecision {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Names of policies that contributed to the decision.
    pub policy_names: Vec<String>,
    /// `@reason` annotation values from matching policies (if any).
    pub policy_reasons: Vec<String>,
    /// `true` when the denial was caused by a `forbid` policy. Cedar's
    /// forbid-overrides-permit semantics mean no additional permit can
    /// unblock such a request: the only remedy is to remove or narrow the
    /// forbid policy itself. Used by blocked-request synthesis to mark the
    /// request as "no candidate exception available" instead of inventing
    /// a permit that would not actually work.
    pub blocked_by_forbid: bool,
}

/// Holds the parsed Cedar policy set and authorizer, ready for per-request evaluation.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    policy_set: Arc<PolicySet>,
    authorizer: Arc<Authorizer>,
}

impl PolicyEngine {
    fn from_policy_text(
        text: &str,
        schema_text: Option<&str>,
        schema_label: Option<&str>,
    ) -> anyhow::Result<Self> {
        // Check for old-format (pre-v0.3) actions before parsing
        check_old_format_actions(text)?;
        reject_removed_action_domains(text)?;

        let policy_set = PolicySet::from_str(text)
            .map_err(|e| anyhow::anyhow!("invalid Cedar policy file: {e}"))?;

        // Validate against schema if provided
        if let Some(schema_text) = schema_text {
            let schema_label = schema_label.unwrap_or("<inline schema>");
            let (schema, _warnings) = Schema::from_cedarschema_str(schema_text)
                .map_err(|e| anyhow::anyhow!("invalid Cedar schema file {schema_label}: {e}"))?;

            let validator = Validator::new(schema);
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            if !result.validation_passed() {
                let errors: Vec<String> = result
                    .validation_errors()
                    .map(|e| format!("  - {e}"))
                    .collect();
                anyhow::bail!(
                    "Cedar policy validation failed against schema {schema_label}:\n{}",
                    errors.join("\n")
                );
            }
        }

        Ok(Self {
            policy_set: Arc::new(policy_set),
            authorizer: Arc::new(Authorizer::new()),
        })
    }

    /// Load a Cedar policy file from disk, optionally validating it against a
    /// `.cedarschema` file. Returns an error if the file cannot be read,
    /// contains invalid Cedar syntax, or violates the schema.
    pub fn load(path: &Path, schema_path: Option<&Path>) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read policy file: {}", path.display()))?;
        let schema_text = schema_path
            .map(|path| {
                std::fs::read_to_string(path)
                    .with_context(|| format!("failed to read schema file: {}", path.display()))
            })
            .transpose()?;
        let schema_label = schema_path.map(|path| path.display().to_string());
        Self::from_policy_text(&text, schema_text.as_deref(), schema_label.as_deref())
    }

    /// Load a Cedar policy from an in-memory string, optionally validating it
    /// against an in-memory Cedar schema string.
    pub fn from_text(
        policy_text: &str,
        schema_text: Option<&str>,
        schema_label: Option<&str>,
    ) -> anyhow::Result<Self> {
        Self::from_policy_text(policy_text, schema_text, schema_label)
    }

    /// Evaluate a request against the loaded policy set.
    ///
    /// - `host`: target hostname (e.g. `api.github.com`)
    /// - `action`: HTTP action string (e.g. `http:GET`, `http:POST`)
    /// - `path`: URL path (e.g. `/repos/org/repo`)
    /// - `headers`: list of (name, value) header pairs
    /// - `agent_id`: identity of the requesting agent (e.g. `"worker"`, `"ci-bot"`)
    pub fn evaluate(
        &self,
        host: &str,
        action: &str,
        path: &str,
        headers: &[(String, String)],
        agent_id: &str,
    ) -> anyhow::Result<PolicyDecision> {
        // Build entity hierarchy from the path segments.
        // For path "/repos/org/repo", we create:
        //   Resource::"repos/org/repo" in Resource::"repos/org" in Resource::"repos"
        let entities = build_http_entity_hierarchy(host, path, agent_id)?;

        // Principal: Agent::"<agent_id>"
        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str(agent_id).unwrap(),
        );

        // Action: Action::"<action>" (e.g. "http:GET")
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(action).unwrap(),
        );

        // Resource: Resource::"<host>/<path_without_leading_slash>"
        let resource_id = build_resource_id(host, path);
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str(&resource_id).unwrap(),
        );

        // Derive raw method from the action for context backward compatibility.
        // For "http:GET" → "GET".
        let method = action.strip_prefix("http:").unwrap_or(action);

        // Build base context pairs (host, path, method, AWS) using shared builder
        let mut context_pairs = build_http_context_pairs(host, path, method)?;

        // Add headers as namespaced "header:<name>" context attributes to prevent
        // overwriting built-in context attributes (host, path, method).
        for (k, v) in headers {
            let lower = k.to_lowercase();
            if BUILTIN_CONTEXT_KEYS.contains(&lower.as_str()) {
                tracing::warn!(
                    header = %lower,
                    "header key collides with built-in context attribute; namespaced as header:{}",
                    lower
                );
            }
            let expr = RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(v)))
                .map_err(|e| {
                anyhow::anyhow!(
                    "invalid header value for Cedar context key '{}': {e}",
                    lower
                )
            })?;
            context_pairs.push((format!("header:{lower}"), expr));
        }

        let context =
            Context::from_pairs(context_pairs).context("failed to build Cedar context")?;

        let request = Request::new(principal, action_uid, resource, context, None)
            .map_err(|e| anyhow::anyhow!("failed to build Cedar request: {e}"))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        let (policy_names, policy_reasons, blocked_by_forbid) =
            self.collect_decision_metadata(response.diagnostics().reason());

        Ok(PolicyDecision {
            allowed: response.decision() == Decision::Allow,
            policy_names,
            policy_reasons,
            blocked_by_forbid,
        })
    }

    /// Collect per-decision metadata (policy names, `@reason`
    /// annotations, and whether any matching policy has `Effect::Forbid`)
    /// from the Cedar diagnostics.
    ///
    /// Shared by policy evaluation paths so
    /// a future change to the metadata collection rules only has to be
    /// made in one place.
    ///
    /// When a `forbid` policy contributes to the decision, Cedar's
    /// forbid-overrides-permit semantics mean no added permit can
    /// unblock the request, so the downstream blocked-request synthesis
    /// uses the returned `blocked_by_forbid` flag to emit the
    /// no-candidate-exception variant.
    fn collect_decision_metadata<'a, I>(&self, pids: I) -> (Vec<String>, Vec<String>, bool)
    where
        I: IntoIterator<Item = &'a PolicyId>,
    {
        let mut policy_names = Vec::new();
        let mut policy_reasons = Vec::new();
        let mut blocked_by_forbid = false;
        for pid in pids {
            // Resolve policy ID: prefer @id annotation value over
            // auto-generated name.
            let name = self
                .policy_set
                .annotation(pid, "id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| pid.to_string());
            policy_names.push(name);
            // Collect @reason annotation if present (strait convention
            // for human-readable denial messages in audit logs).
            if let Some(reason) = self.policy_set.annotation(pid, "reason") {
                policy_reasons.push(reason.to_string());
            }
            if let Some(policy) = self.policy_set.policy(pid) {
                if policy.effect() == Effect::Forbid {
                    blocked_by_forbid = true;
                }
            }
        }
        (policy_names, policy_reasons, blocked_by_forbid)
    }

    /// Check if a host is permitted by any http: policy.
    ///
    /// Evaluates each standard HTTP method against the host's root resource.
    /// Returns `true` if any method is permitted, indicating the agent is
    /// allowed to connect to this host.
    pub fn is_host_permitted(&self, host: &str, agent_id: &str) -> anyhow::Result<bool> {
        for method in &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            let action = format!("http:{method}");
            let result = self.evaluate(host, &action, "/", &[], agent_id)?;
            if result.allowed {
                return Ok(true);
            }
        }
        Ok(false)
    }
}
/// e.g. host="api.github.com", path="/repos/org/repo" -> "api.github.com/repos/org/repo"
pub fn build_resource_id(host: &str, path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.is_empty() {
        host.to_string()
    } else {
        format!("{host}/{trimmed}")
    }
}

/// Build the Cedar entity hierarchy from the host and URL path (HTTP domain).
///
/// For host="api.github.com" and path="/repos/org/repo", creates:
/// - Resource::"api.github.com/repos/org/repo" (parent: api.github.com/repos/org)
/// - Resource::"api.github.com/repos/org" (parent: api.github.com/repos)
/// - Resource::"api.github.com/repos" (parent: api.github.com)
/// - Resource::"api.github.com" (no parent)
/// - Agent::"<agent_id>" (no parent)
/// - Action::"http:GET", Action::"http:POST", … (HTTP method actions)
pub fn build_http_entity_hierarchy(
    host: &str,
    path: &str,
    agent_id: &str,
) -> anyhow::Result<Entities> {
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

    // Add action entities for namespaced HTTP methods
    for method in &["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
        let action_id = format!("http:{method}");
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(&action_id).unwrap(),
        );
        entities.push(Entity::new_no_attrs(action_uid, HashSet::new()));
    }

    Entities::from_entities(entities, None)
        .map_err(|e| anyhow::anyhow!("failed to build entity set: {e}"))
}

/// Check policy text for old-format (pre-v0.3) action identifiers.
///
/// Old format: `Action::"GET"`, `Action::"POST"`, etc.
/// New format: `Action::"http:GET"`, `Action::"http:POST"`, etc.
///
/// Returns an error with migration instructions if old-format actions are detected.
fn check_old_format_actions(policy_text: &str) -> anyhow::Result<()> {
    let http_methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
    let mut found = Vec::new();

    for method in &http_methods {
        let old_pattern = format!(r#"Action::"{method}""#);
        if policy_text.contains(&old_pattern) {
            found.push(format!(
                "  Action::\"{method}\" → Action::\"http:{method}\""
            ));
        }
    }

    if !found.is_empty() {
        anyhow::bail!(
            "Cedar policy uses old-format actions (pre-v0.3). \
             Actions must be namespaced. Please update:\n\n{}\n\n\
             All HTTP method actions now require the 'http:' prefix.\n\
             Example: action == Action::\"http:GET\"",
            found.join("\n")
        );
    }
    Ok(())
}

fn reject_removed_action_domains(policy_text: &str) -> anyhow::Result<()> {
    let has_fs = policy_text.contains(&format!("Action::\"{}:", "fs"));
    let has_proc = policy_text.contains(&format!("Action::\"{}:", "proc"));

    if !has_fs && !has_proc {
        return Ok(());
    }

    let mut removed = Vec::new();
    if has_fs {
        removed.push("fs");
    }
    if has_proc {
        removed.push("proc");
    }

    anyhow::bail!(
        "Cedar policy references removed action domains: {}. Strait now supports only http: actions. See docs/designs/devcontainer-strategy.md (decision 4) for the network-only strategy.",
        removed.join(", ")
    );
}

// ---------------------------------------------------------------------------
// Context builders (shared by evaluate methods and replay)
// ---------------------------------------------------------------------------

/// Build the base Cedar context pairs for an HTTP request.
///
/// Populates `host`, `path`, and `method` attributes, plus AWS-specific
/// `aws_service` and `aws_region` when the host is an AWS endpoint.
fn build_http_context_pairs(
    host: &str,
    path: &str,
    method: &str,
) -> anyhow::Result<Vec<(String, RestrictedExpression)>> {
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

    Ok(pairs)
}

/// Build a Cedar context for an HTTP network request.
///
/// Populates `host`, `path`, and `method` attributes, plus AWS-specific
/// `aws_service` and `aws_region` when the host is an AWS endpoint.
/// This is the canonical implementation shared by `PolicyEngine::evaluate()`
/// and the replay engine.
pub fn build_http_context(host: &str, path: &str, method: &str) -> anyhow::Result<Context> {
    let pairs = build_http_context_pairs(host, path, method)?;
    Context::from_pairs(pairs).map_err(|e| anyhow::anyhow!("failed to build HTTP context: {e}"))
}

/// Build a Cedar context for a filesystem access event.
///
/// Populates `path` and `operation` attributes.
pub fn build_fs_context(path: &str, operation: &str) -> anyhow::Result<Context> {
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
pub fn build_proc_context(command: &str) -> anyhow::Result<Context> {
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
pub fn build_mount_context(path: &str, mode: &str) -> anyhow::Result<Context> {
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

/// Built-in Cedar context attribute names that must not be overwritten by headers.
const BUILTIN_CONTEXT_KEYS: &[&str] = &["host", "path", "method", "aws_service", "aws_region"];

/// Escape a string for use in a Cedar string literal.
///
/// Escapes backslashes, double quotes, and control characters (\n, \r, \t, \0)
/// to prevent injection or panics in Cedar expression parsing.
pub(crate) fn escape_cedar_string(s: &str) -> String {
    s.replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
        .replace('\t', "\\t")
        .replace('\0', "\\0")
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

// ---------------------------------------------------------------------------
// Blocked-request synthesis
// ---------------------------------------------------------------------------

/// Build the normalized match key for a blocked HTTP request.
///
/// Format is `http:{METHOD} {host}{path}`. The key mirrors how `strait
/// watch` renders requests and how `build_resource_id` names Cedar
/// resources, so the blocked-request payload, the watch UI, and the
/// Cedar policy entity model all agree on how to refer to "this
/// request".
///
/// The path is preserved verbatim (including any leading `/`) so callers
/// can round-trip the match key back to the original request.
pub fn build_match_key(host: &str, method: &str, path: &str) -> String {
    format!("http:{method} {host}{path}")
}

/// Parse a normalized blocked-request match key back into request parts.
pub fn parse_match_key(match_key: &str) -> anyhow::Result<(String, String, String)> {
    let (action, resource) = match_key
        .split_once(' ')
        .ok_or_else(|| anyhow::anyhow!("invalid match key '{match_key}': missing separator"))?;
    let method = action.strip_prefix("http:").ok_or_else(|| {
        anyhow::anyhow!("invalid match key '{match_key}': action must start with http:")
    })?;
    let slash = resource.find('/').unwrap_or(resource.len());
    let host = &resource[..slash];
    let path = if slash == resource.len() {
        "/"
    } else {
        &resource[slash..]
    };

    if host.is_empty() {
        anyhow::bail!("invalid match key '{match_key}': missing host");
    }

    Ok((host.to_string(), method.to_string(), path.to_string()))
}

/// Build the human-readable explanation string for a blocked request.
///
/// Prefers any `@reason("...")` annotations attached to matching Cedar
/// policies (joined with `"; "`). Falls back to a generic
/// `"denied by policy '{name}': {method} {path} on {host}"` message when
/// the matching policy has no `@reason` annotation, and to
/// `"denied by default-deny"` when no policy matched at all (Cedar's
/// native no-permit-matches path).
pub fn build_denial_explanation(
    host: &str,
    method: &str,
    path: &str,
    policy_names: &[String],
    policy_reasons: &[String],
) -> String {
    if !policy_reasons.is_empty() {
        return policy_reasons.join("; ");
    }
    if policy_names.is_empty() {
        return format!("denied by default-deny: {method} {path} on {host}");
    }
    format!(
        "denied by policy '{}': {method} {path} on {host}",
        policy_names.join(", ")
    )
}

/// Synthesize structured blocked-request metadata for a denied HTTP
/// request.
///
/// Produces a stable blocked-request ID, a normalized match key, a
/// human-readable explanation, and either:
///
/// * the smallest candidate exception (in `once`, `session`, and
///   `persist` forms) that could unblock equivalent requests, for
///   denials caused by a missing permit, or
/// * `None` with a `no_exception_reason` when the denial was caused by
///   a Cedar `forbid` policy (since no added permit can override a
///   forbid).
///
/// Callers should supply `blocked_by_forbid: true` when any matching
/// Cedar policy had `Effect::Forbid`. The evaluator sets this on
/// `PolicyDecision::blocked_by_forbid`.
pub fn synthesize_blocked_request(
    host: &str,
    method: &str,
    path: &str,
    policy_names: &[String],
    policy_reasons: &[String],
    blocked_by_forbid: bool,
) -> BlockedRequest {
    let blocked_id = uuid::Uuid::new_v4().to_string();
    let match_key = build_match_key(host, method, path);
    let explanation = build_denial_explanation(host, method, path, policy_names, policy_reasons);

    if blocked_by_forbid {
        return BlockedRequest {
            blocked_id,
            match_key,
            explanation,
            candidate_exception: None,
            no_exception_reason: Some(
                "denied by forbid policy; no permit can override a Cedar forbid effect".to_string(),
            ),
        };
    }

    let candidate = synthesize_candidate_exception(host, method, path);
    BlockedRequest {
        blocked_id,
        match_key,
        explanation,
        candidate_exception: Some(candidate),
        no_exception_reason: None,
    }
}

/// Synthesize the smallest candidate exception that could unblock the
/// given request.
///
/// Scope selection:
///
/// * `PathScoped` — path has at least two non-empty segments. The
///   exception permits the exact method on the full path prefix.
/// * `MethodHost` — path has one or zero non-empty segments, or is
///   empty. The exception permits the exact method on the whole host.
///   Marked `ambiguous` when the path has exactly one segment, since
///   `PathScoped` at depth 1 is also a plausible "smallest" choice.
/// * `HostOnly` — reserved for future use when the caller cannot
///   confidently identify a single method; the current synthesizer
///   always has a method, so it does not emit `HostOnly`.
fn synthesize_candidate_exception(host: &str, method: &str, path: &str) -> CandidateException {
    let segments: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    let depth = segments.len();

    if depth >= 2 {
        CandidateException {
            scope: ExceptionScope::PathScoped,
            ambiguous: false,
            once: path_scoped_directive(host, method, path, "once"),
            session: path_scoped_directive(host, method, path, "session"),
            persist: path_scoped_directive(host, method, path, "persist"),
        }
    } else if depth == 1 {
        // Depth-1 path: path-scoped and method-host are both plausible
        // "smallest" choices. Pick method-host (broader, more likely to
        // match equivalent requests) but flag the suggestion as
        // ambiguous so the consumer surfaces the alternative.
        CandidateException {
            scope: ExceptionScope::MethodHost,
            ambiguous: true,
            once: method_host_directive(host, method, "once"),
            session: method_host_directive(host, method, "session"),
            persist: method_host_directive(host, method, "persist"),
        }
    } else {
        // Empty path or no segments: method-host is unambiguously the
        // smallest meaningful scope.
        CandidateException {
            scope: ExceptionScope::MethodHost,
            ambiguous: false,
            once: method_host_directive(host, method, "once"),
            session: method_host_directive(host, method, "session"),
            persist: method_host_directive(host, method, "persist"),
        }
    }
}

/// Normalize a string into an identifier suitable for embedding in a
/// Cedar `@id("...")` annotation without risking collisions.
///
/// Replaces any character that is not alphanumeric or `_` with `_`, and
/// collapses consecutive underscores. This is a best-effort sanitizer,
/// not a canonical form -- two distinct inputs can still normalize to
/// the same identifier (for example `foo.bar` and `foo_bar`). The goal
/// is to produce human-readable IDs that incorporate the host and path
/// so separate blocked requests do not all share the same `@id`, which
/// would make Cedar reject the resulting policy set or silently collide.
fn sanitize_id_segment(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut last_was_underscore = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            last_was_underscore = false;
        } else if !last_was_underscore {
            out.push('_');
            last_was_underscore = true;
        }
    }
    // Trim leading/trailing underscores so an input like "/foo" does not
    // render as "_foo_" in the final ID.
    out.trim_matches('_').to_string()
}

/// Build a `PathScoped` exception directive for the given lifetime form.
fn path_scoped_directive(host: &str, method: &str, path: &str, form: &str) -> ExceptionDirective {
    let resource_id = build_resource_id(host, path);
    let summary = format!("allow http:{method} {host}{path}");
    // Include host and path in the ID so two distinct blocked requests
    // synthesized in the same session do not collide on a shared `@id`.
    let host_slug = sanitize_id_segment(host);
    let path_slug = sanitize_id_segment(path);
    let id = format!(
        "allow_http_{}_path_{host_slug}_{path_slug}_{form}",
        method.to_lowercase()
    );
    let cedar_snippet = format!(
        "@id(\"{id}\")\n@reason(\"strait-synthesized {form} exception for {method} {path} on {host}\")\npermit(\n    principal,\n    action == Action::\"http:{method}\",\n    resource == Resource::\"{resource}\"\n);",
        resource = resource_id,
    );
    ExceptionDirective {
        summary,
        cedar_snippet,
    }
}

/// Build a `MethodHost` exception directive for the given lifetime form.
fn method_host_directive(host: &str, method: &str, form: &str) -> ExceptionDirective {
    let summary = format!("allow http:{method} {host}");
    // Include host in the ID for the same collision-avoidance reason as
    // `path_scoped_directive`.
    let host_slug = sanitize_id_segment(host);
    let id = format!(
        "allow_http_{}_host_{host_slug}_{form}",
        method.to_lowercase()
    );
    let cedar_snippet = format!(
        "@id(\"{id}\")\n@reason(\"strait-synthesized {form} exception for {method} on {host}\")\npermit(\n    principal,\n    action == Action::\"http:{method}\",\n    resource in Resource::\"{host}\"\n);",
    );
    ExceptionDirective {
        summary,
        cedar_snippet,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::path::Path;
    use tempfile::NamedTempFile;

    fn write_policy(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn write_schema(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::with_suffix(".cedarschema").unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    const VALID_SCHEMA: &str = r#"
entity Agent;
entity Resource in [Resource];
action "http:GET", "http:POST", "http:PUT", "http:PATCH", "http:DELETE", "http:HEAD", "http:OPTIONS"
    appliesTo { principal: Agent, resource: Resource, context: {} };
"#;

    const SCHEMA_CONFORMING_POLICY: &str = r#"
@id("allow-get")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"example.com/api"
);
"#;

    #[test]
    fn parse_match_key_round_trips_root_and_path_requests() {
        assert_eq!(
            parse_match_key("http:GET api.github.com/").unwrap(),
            (
                "api.github.com".to_string(),
                "GET".to_string(),
                "/".to_string()
            )
        );
        assert_eq!(
            parse_match_key("http:POST api.github.com/repos/org/repo").unwrap(),
            (
                "api.github.com".to_string(),
                "POST".to_string(),
                "/repos/org/repo".to_string()
            )
        );
    }

    #[test]
    fn persist_exception_serializes_path_scoped_rule_for_deep_paths() {
        let blocked =
            synthesize_blocked_request("api.github.com", "GET", "/repos/org/repo", &[], &[], false);
        let candidate = blocked.candidate_exception.unwrap();
        assert_eq!(candidate.scope, ExceptionScope::PathScoped);
        assert_eq!(
            candidate.persist.cedar_snippet,
            concat!(
                "@id(\"allow_http_get_path_api_github_com_repos_org_repo_persist\")\n",
                "@reason(\"strait-synthesized persist exception for GET /repos/org/repo on api.github.com\")\n",
                "permit(\n",
                "    principal,\n",
                "    action == Action::\"http:GET\",\n",
                "    resource == Resource::\"api.github.com/repos/org/repo\"\n",
                ");"
            )
        );
    }

    #[test]
    fn persist_exception_serializes_method_host_rule_for_shallow_paths() {
        let shallow =
            synthesize_blocked_request("api.github.com", "POST", "/graphql", &[], &[], false);
        let shallow_candidate = shallow.candidate_exception.unwrap();
        assert_eq!(shallow_candidate.scope, ExceptionScope::MethodHost);
        assert!(shallow_candidate.ambiguous);
        assert_eq!(
            shallow_candidate.persist.cedar_snippet,
            concat!(
                "@id(\"allow_http_post_host_api_github_com_persist\")\n",
                "@reason(\"strait-synthesized persist exception for POST on api.github.com\")\n",
                "permit(\n",
                "    principal,\n",
                "    action == Action::\"http:POST\",\n",
                "    resource in Resource::\"api.github.com\"\n",
                ");"
            )
        );

        let root = synthesize_blocked_request("api.github.com", "HEAD", "/", &[], &[], false);
        let root_candidate = root.candidate_exception.unwrap();
        assert_eq!(root_candidate.scope, ExceptionScope::MethodHost);
        assert!(!root_candidate.ambiguous);
        assert_eq!(
            root_candidate.persist.cedar_snippet,
            concat!(
                "@id(\"allow_http_head_host_api_github_com_persist\")\n",
                "@reason(\"strait-synthesized persist exception for HEAD on api.github.com\")\n",
                "permit(\n",
                "    principal,\n",
                "    action == Action::\"http:HEAD\",\n",
                "    resource in Resource::\"api.github.com\"\n",
                ");"
            )
        );
    }

    #[test]
    fn load_valid_policy_file() {
        let f = write_policy(SCHEMA_CONFORMING_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_missing_policy_file() {
        let result = PolicyEngine::load(Path::new("/nonexistent/policy.cedar"), None);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read policy file"));
    }

    #[test]
    fn load_valid_policy_with_valid_schema() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let schema_file = write_schema(VALID_SCHEMA);
        let engine = PolicyEngine::load(policy_file.path(), Some(schema_file.path())).unwrap();
        assert!(Arc::strong_count(&engine.policy_set) >= 1);
    }

    #[test]
    fn load_invalid_schema_file() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let schema_file = write_schema("this is not valid cedarschema @@@ {{{");
        let result = PolicyEngine::load(policy_file.path(), Some(schema_file.path()));
        assert!(result.is_err());
        assert!(format!("{:#}", result.unwrap_err()).contains("invalid Cedar schema file"));
    }

    #[test]
    fn load_missing_schema_file() {
        let policy_file = write_policy(SCHEMA_CONFORMING_POLICY);
        let result = PolicyEngine::load(
            policy_file.path(),
            Some(Path::new("/nonexistent/schema.cedarschema")),
        );
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read schema file"));
    }

    #[test]
    fn http_entity_hierarchy_contains_only_http_actions() {
        let entities =
            build_http_entity_hierarchy("api.github.com", "/repos/org/repo", "worker").unwrap();
        let entity_ids: Vec<String> = entities
            .iter()
            .map(|entity| entity.uid().to_string())
            .collect();

        for method in ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"] {
            assert!(
                entity_ids
                    .iter()
                    .any(|id| id == &format!("Action::\"http:{method}\"")),
                "missing http action entity for {method}: {entity_ids:?}"
            );
        }
        assert!(
            !entity_ids
                .iter()
                .any(|id| id.contains(&format!("{}:", "fs"))),
            "fs actions should not exist in entity hierarchy: {entity_ids:?}"
        );
        assert!(
            !entity_ids
                .iter()
                .any(|id| id.contains(&format!("{}:", "proc"))),
            "proc actions should not exist in entity hierarchy: {entity_ids:?}"
        );
    }

    #[test]
    fn old_format_policy_triggers_migration_error() {
        let f = write_policy(
            r#"
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource
);
"#,
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("old-format actions"));
        assert!(err.contains("http:GET"));
    }

    #[test]
    fn load_policy_with_removed_fs_actions_fails() {
        let removed_action = format!("{}:{}", "fs", "read");
        let f = write_policy(
            &format!(
                "permit(\n    principal,\n    action == Action::\"{removed_action}\",\n    resource\n);\n"
            ),
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("removed action domains: fs"), "got: {err}");
        assert!(err.contains("http: actions"), "got: {err}");
        assert!(
            err.contains("docs/designs/devcontainer-strategy.md"),
            "got: {err}"
        );
    }

    #[test]
    fn load_policy_with_removed_proc_actions_fails() {
        let removed_action = format!("{}:{}", "proc", "exec");
        let f = write_policy(
            &format!(
                "permit(\n    principal,\n    action == Action::\"{removed_action}\",\n    resource\n);\n"
            ),
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("removed action domains: proc"), "got: {err}");
        assert!(err.contains("http: actions"), "got: {err}");
    }

    #[test]
    fn load_policy_with_both_removed_domains_fails() {
        let fs_action = format!("{}:{}", "fs", "read");
        let proc_action = format!("{}:{}", "proc", "exec");
        let f = write_policy(
            &format!(
                "permit(\n    principal,\n    action in [Action::\"{fs_action}\", Action::\"{proc_action}\"],\n    resource\n);\n"
            ),
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("fs, proc"));
    }

    #[test]
    fn evaluate_http_policy_still_works() {
        let f = write_policy(
            r#"
@id("allow-read")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/our-org"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/our-org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed);
    }

    #[test]
    fn is_host_permitted_checks_http_methods() {
        let f = write_policy(
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:POST",
    resource in Resource::"api.example.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        assert!(engine
            .is_host_permitted("api.example.com", "agent")
            .unwrap());
        assert!(!engine
            .is_host_permitted("evil.example.com", "agent")
            .unwrap());
    }
}
