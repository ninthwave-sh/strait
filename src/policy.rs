//! Cedar policy evaluation for agent requests.
//!
//! Loads a `.cedar` policy file at startup and evaluates each request
//! against the policy set. Actions use namespaced identifiers:
//!
//! - `Action::"http:GET"`, `Action::"http:POST"`, … — HTTP methods
//! - `Action::"fs:read"`, `Action::"fs:write"`, … — filesystem operations
//! - `Action::"proc:exec"`, `Action::"proc:fork"`, … — process operations
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

        // Check for old-format (pre-v0.3) actions before parsing
        check_old_format_actions(&text)?;

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
    /// - `action`: domain-agnostic action string (e.g. `http:GET`, `fs:read`, `proc:exec`)
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

        // Action: Action::"<action>" (e.g. "http:GET", "fs:read")
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
        // For "http:GET" → "GET"; for non-HTTP actions, use the full action string.
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

    /// Evaluate a filesystem action against the loaded policy set.
    ///
    /// - `path`: filesystem path (e.g. `/project/src`)
    /// - `action`: fs action string (e.g. `fs:read`, `fs:write`)
    /// - `agent_id`: identity of the requesting agent
    pub fn evaluate_fs(
        &self,
        path: &str,
        action: &str,
        agent_id: &str,
    ) -> anyhow::Result<PolicyDecision> {
        let entities = build_fs_entities(path, agent_id)?;

        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str(agent_id).unwrap(),
        );

        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(action).unwrap(),
        );

        let normalized = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let resource_id = format!("fs::{normalized}");
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str(&resource_id).unwrap(),
        );

        // Build context using shared builder so Cedar policies using
        // `when { context.path like ... }` or `context.operation` work
        // consistently in both live enforcement and replay.
        let operation = action.strip_prefix("fs:").unwrap_or(action);
        let context = build_fs_context(&normalized, operation)?;
        let request = Request::new(principal, action_uid, resource, context, None)
            .map_err(|e| anyhow::anyhow!("failed to build Cedar fs request: {e}"))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        let mut policy_names = Vec::new();
        let mut policy_reasons = Vec::new();
        for pid in response.diagnostics().reason() {
            let name = self
                .policy_set
                .annotation(pid, "id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| pid.to_string());
            policy_names.push(name);
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

    /// Evaluate a process action against the loaded policy set.
    ///
    /// - `command`: command string (e.g. `"node index.js"`)
    /// - `action`: proc action string (e.g. `proc:exec`)
    /// - `agent_id`: identity of the requesting agent
    pub fn evaluate_proc(
        &self,
        command: &str,
        action: &str,
        agent_id: &str,
    ) -> anyhow::Result<PolicyDecision> {
        let entities = build_proc_entities(command, agent_id)?;

        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str(agent_id).unwrap(),
        );

        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(action).unwrap(),
        );

        let resource_id = format!("proc::{command}");
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str(&resource_id).unwrap(),
        );

        let context = build_proc_context(command)?;
        let request = Request::new(principal, action_uid, resource, context, None)
            .map_err(|e| anyhow::anyhow!("failed to build Cedar proc request: {e}"))?;

        let response = self
            .authorizer
            .is_authorized(&request, &self.policy_set, &entities);

        let mut policy_names = Vec::new();
        let mut policy_reasons = Vec::new();
        for pid in response.diagnostics().reason() {
            let name = self
                .policy_set
                .annotation(pid, "id")
                .map(|v| v.to_string())
                .unwrap_or_else(|| pid.to_string());
            policy_names.push(name);
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

/// Extract filesystem permissions from a Cedar policy for container configuration.
///
/// For each candidate path, evaluates `fs:write` and `fs:read` actions against
/// the policy engine. Returns:
/// - `FsWrite` if `fs:write` is permitted (implies read access too)
/// - `FsRead` if only `fs:read` is permitted
/// - Nothing if neither is permitted (path will not be mounted)
pub fn extract_fs_permissions(
    engine: &PolicyEngine,
    paths: &[String],
    agent_id: &str,
) -> Vec<crate::container::ContainerPermission> {
    use crate::container::ContainerPermission;
    let mut perms = Vec::new();
    for path in paths {
        // Check write first (more permissive — write implies read)
        if let Ok(result) = engine.evaluate_fs(path, "fs:write", agent_id) {
            if result.allowed {
                perms.push(ContainerPermission::FsWrite(path.clone()));
                continue;
            }
        }
        // Check read
        if let Ok(result) = engine.evaluate_fs(path, "fs:read", agent_id) {
            if result.allowed {
                perms.push(ContainerPermission::FsRead(path.clone()));
            }
        }
        // If neither is allowed, path is not mounted
    }
    perms
}

/// Build a resource ID string from host and path.
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

/// Build the Cedar entity set for a filesystem operation.
///
/// Creates a resource hierarchy from the filesystem path:
/// - `Resource::"fs::/project/src/main.rs"` (parent: `fs::/project/src`)
/// - `Resource::"fs::/project/src"` (parent: `fs::/project`)
/// - `Resource::"fs::/project"` (parent: `fs::/`)
/// - `Resource::"fs::/"` (root, no parent)
///
/// Also creates action entities for `fs:read`, `fs:write`, `fs:create`, `fs:delete`
/// and the agent entity.
pub fn build_fs_entities(path: &str, agent_id: &str) -> anyhow::Result<Entities> {
    let resource_type = EntityTypeName::from_str("Resource").unwrap();
    let mut entities = Vec::new();

    // Normalize path: ensure leading slash
    let normalized = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };

    // Build resource IDs from most specific to root
    // e.g. "/project/src" → ["fs::/project/src", "fs::/project", "fs::/"]
    let mut resource_ids: Vec<String> = Vec::new();
    let mut current = normalized.as_str();
    loop {
        resource_ids.push(format!("fs::{current}"));
        if current == "/" {
            break;
        }
        // Go up one level
        match current.rfind('/') {
            Some(0) => {
                // Parent is root
                resource_ids.push("fs::/".to_string());
                break;
            }
            Some(pos) => current = &current[..pos],
            None => break,
        }
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

    // Add action entities for filesystem operations
    for action in &["fs:read", "fs:write", "fs:create", "fs:delete"] {
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str(action).unwrap(),
        );
        entities.push(Entity::new_no_attrs(action_uid, HashSet::new()));
    }

    Entities::from_entities(entities, None)
        .map_err(|e| anyhow::anyhow!("failed to build fs entity set: {e}"))
}

/// Build the Cedar entity set for a process operation.
///
/// Creates a single resource entity for the command:
/// - `Resource::"proc::command"` (no hierarchy)
///
/// Also creates action entities for `proc:exec`, `proc:fork`, `proc:signal`
/// and the agent entity.
pub fn build_proc_entities(command: &str, agent_id: &str) -> anyhow::Result<Entities> {
    let mut entities = Vec::new();

    // Resource: proc::<command>
    let resource_id = format!("proc::{command}");
    let resource_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Resource").unwrap(),
        EntityId::from_str(&resource_id).unwrap(),
    );
    entities.push(Entity::new_no_attrs(resource_uid, HashSet::new()));

    // Add the principal entity
    let agent_uid = EntityUid::from_type_name_and_id(
        EntityTypeName::from_str("Agent").unwrap(),
        EntityId::from_str(agent_id).unwrap(),
    );
    entities.push(Entity::new_no_attrs(agent_uid, HashSet::new()));

    // Add action entity for proc:exec (the only process action used).
    {
        let action_uid = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str("proc:exec").unwrap(),
        );
        entities.push(Entity::new_no_attrs(action_uid, HashSet::new()));
    }

    Entities::from_entities(entities, None)
        .map_err(|e| anyhow::anyhow!("failed to build proc entity set: {e}"))
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
  action == Action::"http:GET",
  resource in Resource::"api.github.com/repos/our-org"
);

// Allow PR creation on org repos
@id("create-prs")
permit(
  principal == Agent::"worker",
  action == Action::"http:POST",
  resource in Resource::"api.github.com/repos/our-org"
) when { context.path like "*/pulls" };

// Deny push to main (forbid overrides permit).
// @reason is a strait convention: its value appears in the audit log's
// denial_reason field when this policy causes a deny.
@id("deny-push-main")
@reason("Direct pushes to main are not allowed; use a pull request")
forbid(
  principal,
  action == Action::"http:POST",
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
            build_http_entity_hierarchy("api.github.com", "/repos/org/repo", "worker").unwrap();
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
                "http:GET",
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
                "http:POST",
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
                "http:DELETE",
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
                "http:POST",
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
            .evaluate("api.github.com", "http:PATCH", "/settings", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "PATCH /settings should be denied");
    }

    #[test]
    fn deny_get_unknown() {
        let f = write_policy(GITHUB_POLICY);
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate("api.github.com", "http:GET", "/unknown", &[], "worker")
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
    action == Action::"http:GET",
    resource in Resource::"example.com/a"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // a/b/c should be allowed because it's in Resource::"example.com/a"
        let result = engine
            .evaluate("example.com", "http:GET", "/a/b/c", &[], "worker")
            .unwrap();
        assert!(
            result.allowed,
            "GET /a/b/c should be allowed (descendant of /a)"
        );

        // /x should be denied (not in Resource::"example.com/a")
        let result = engine
            .evaluate("example.com", "http:GET", "/x", &[], "worker")
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
action "http:GET", "http:POST", "http:PUT", "http:PATCH", "http:DELETE", "http:HEAD", "http:OPTIONS"
    appliesTo { principal: Agent, resource: Resource, context: {} };
"#;

    /// A Cedar policy that conforms to VALID_SCHEMA.
    const SCHEMA_CONFORMING_POLICY: &str = r#"
@id("allow-get")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
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
    action == Action::"http:GET",
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
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // ci-bot should be allowed
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "ci-bot",
            )
            .unwrap();
        assert!(result.allowed, "ci-bot should be allowed");

        // anonymous should be denied (different principal)
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "anonymous",
            )
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
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);

@id("ci-bot-write")
permit(
    principal == Agent::"ci-bot",
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // worker can GET, cannot POST
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "worker GET should be allowed");
        let result = engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "worker POST should be denied");

        // ci-bot can POST, cannot GET
        let result = engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/org/repo",
                &[],
                "ci-bot",
            )
            .unwrap();
        assert!(result.allowed, "ci-bot POST should be allowed");
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "ci-bot",
            )
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
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com"
);

@id("allow-read")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // DELETE triggers the forbid with @reason
        let result = engine
            .evaluate(
                "api.github.com",
                "http:DELETE",
                "/repos/org/repo",
                &[],
                "worker",
            )
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
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "worker",
            )
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
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "worker",
            )
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
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedarschema");
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
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedarschema");
        let engine = PolicyEngine::load(&policy_path, Some(&schema_path)).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
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
                "http:POST",
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
                "http:POST",
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
                "http:POST",
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
                "http:DELETE",
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
                "http:PATCH",
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

    // --- AWS context attribute tests ---

    #[test]
    fn aws_context_attributes_set_for_aws_host() {
        let f = write_policy(
            r#"
@id("allow-s3")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.aws_service == "s3" && context.aws_region == "us-east-1" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // S3 regional request should match
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:GET",
                "/bucket/key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "S3 us-east-1 request should be allowed");

        // Lambda request should NOT match (wrong service)
        let result = engine
            .evaluate(
                "lambda.us-east-1.amazonaws.com",
                "http:GET",
                "/functions",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "Lambda request should not match S3 policy");

        // Non-AWS request should NOT match (no aws_service in context)
        let result = engine
            .evaluate("api.github.com", "http:GET", "/repos", &[], "worker")
            .unwrap();
        assert!(
            !result.allowed,
            "GitHub request should not match AWS policy"
        );
    }

    #[test]
    fn aws_context_region_defaults_to_us_east_1_for_global() {
        let f = write_policy(
            r#"
@id("allow-iam-read")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.aws_service == "iam" && context.aws_region == "us-east-1" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Global endpoint (iam.amazonaws.com) should default to us-east-1
        let result = engine
            .evaluate("iam.amazonaws.com", "http:GET", "/", &[], "worker")
            .unwrap();
        assert!(
            result.allowed,
            "IAM global endpoint should default to us-east-1"
        );
    }

    #[test]
    fn aws_context_different_regions_distinguished() {
        let f = write_policy(
            r#"
@id("allow-s3-us-east-1")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.aws_service == "s3" && context.aws_region == "us-east-1" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // us-east-1 should be allowed
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:GET",
                "/bucket",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "S3 us-east-1 should be allowed");

        // eu-west-1 should be denied (different region)
        let result = engine
            .evaluate(
                "s3.eu-west-1.amazonaws.com",
                "http:GET",
                "/bucket",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "S3 eu-west-1 should be denied");
    }

    // --- Example AWS file validation tests ---

    #[test]
    fn example_aws_policy_loads_without_errors() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aws.cedar");
        let engine = PolicyEngine::load(&policy_path, None);
        assert!(
            engine.is_ok(),
            "AWS example policy failed to load: {:#}",
            engine.unwrap_err()
        );
    }

    #[test]
    fn example_aws_schema_validates_example_aws_policy() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aws.cedar");
        let schema_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aws.cedarschema");
        let engine = PolicyEngine::load(&policy_path, Some(&schema_path));
        assert!(
            engine.is_ok(),
            "AWS example policy failed schema validation: {:#}",
            engine.unwrap_err()
        );
    }

    #[test]
    fn example_aws_policy_allows_s3_us_east_1() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aws.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:PUT",
                "/my-bucket/object.txt",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "S3 PUT in us-east-1 should be allowed by example AWS policy"
        );
    }

    #[test]
    fn example_aws_policy_denies_govcloud() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/aws.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "s3.us-gov-west-1.amazonaws.com",
                "http:GET",
                "/bucket",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "GovCloud access should be denied by example AWS policy"
        );
    }

    #[test]
    fn example_policy_denies_outside_org() {
        let policy_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/github.cedar");
        let engine = PolicyEngine::load(&policy_path, None).unwrap();

        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
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

    // --- Namespaced action entity tests ---

    #[test]
    fn http_get_action_entity_construction() {
        // Verify Action::"http:GET" entity is created and usable
        let f = write_policy(
            r#"
@id("allow-http-get")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();
        let result = engine
            .evaluate("example.com", "http:GET", "/test", &[], "worker")
            .unwrap();
        assert!(result.allowed, "http:GET action should match");

        // Bare "GET" (without http: prefix) should NOT match
        let result = engine
            .evaluate("example.com", "GET", "/test", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "bare GET should not match http:GET policy");
    }

    #[test]
    fn fs_read_action_entity_construction() {
        let entities = build_fs_entities("/project/src", "worker").unwrap();
        let count = entities.iter().count();
        // Should have: 3 resource entities (fs::/project/src, fs::/project, fs::/) +
        //              1 agent + 4 fs action entities = 8
        assert!(count >= 8, "expected at least 8 fs entities, got {count}");
    }

    #[test]
    fn proc_exec_action_entity_construction() {
        let entities = build_proc_entities("curl", "worker").unwrap();
        let count = entities.iter().count();
        // Should have: 1 resource (proc::curl) + 1 agent + 1 proc action (proc:exec) = 3
        assert_eq!(count, 3, "expected 3 proc entities, got {count}");
    }

    #[test]
    fn fs_resource_hierarchy_builds_parent_chain() {
        // Verify that Resource::"fs::/project/src" has parent fs::/project, which has parent fs::/
        let f = write_policy(
            r#"
@id("allow-fs-read-project")
permit(
    principal == Agent::"worker",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Build fs entities for /project/src and evaluate
        let entities = build_fs_entities("/project/src", "worker").unwrap();

        let principal = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str("worker").unwrap(),
        );
        let action = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str("fs:read").unwrap(),
        );
        let resource = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str("fs::/project/src").unwrap(),
        );
        let context = Context::empty();

        let request = Request::new(principal, action, resource, context, None).unwrap();
        let authorizer = Authorizer::new();
        let response = authorizer.is_authorized(&request, &engine.policy_set, &entities);
        assert_eq!(
            response.decision(),
            Decision::Allow,
            "fs::/project/src should be in fs::/project (parent chain)"
        );

        // /other/path should be denied (not in fs::/project)
        let entities2 = build_fs_entities("/other/path", "worker").unwrap();
        let resource2 = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Resource").unwrap(),
            EntityId::from_str("fs::/other/path").unwrap(),
        );
        let principal2 = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Agent").unwrap(),
            EntityId::from_str("worker").unwrap(),
        );
        let action2 = EntityUid::from_type_name_and_id(
            EntityTypeName::from_str("Action").unwrap(),
            EntityId::from_str("fs:read").unwrap(),
        );
        let request2 =
            Request::new(principal2, action2, resource2, Context::empty(), None).unwrap();
        let response2 = authorizer.is_authorized(&request2, &engine.policy_set, &entities2);
        assert_eq!(
            response2.decision(),
            Decision::Deny,
            "fs::/other/path should NOT be in fs::/project"
        );
    }

    #[test]
    fn old_format_policy_triggers_migration_error() {
        let f = write_policy(
            r#"
@id("old-format")
permit(
    principal == Agent::"worker",
    action == Action::"GET",
    resource
);
"#,
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_err(), "old-format action should be rejected");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("old-format actions"),
            "error should mention old-format: {err}"
        );
        assert!(
            err.contains("http:GET"),
            "error should suggest http:GET migration: {err}"
        );
    }

    #[test]
    fn old_format_detection_does_not_flag_namespaced_actions() {
        // Policy using correct namespaced format should load fine
        let f = write_policy(
            r#"
@id("namespaced")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
"#,
        );
        let result = PolicyEngine::load(f.path(), None);
        assert!(result.is_ok(), "namespaced action should not be flagged");
    }

    // --- evaluate_fs tests ---

    #[test]
    fn evaluate_fs_read_allowed() {
        let f = write_policy(
            r#"
@id("allow-fs-read")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/project/src/main.rs", "fs:read", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "fs:read should be allowed for /project/src/main.rs"
        );
    }

    #[test]
    fn evaluate_fs_write_denied() {
        let f = write_policy(
            r#"
@id("allow-fs-read-only")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/project/src", "fs:write", "agent")
            .unwrap();
        assert!(
            !result.allowed,
            "fs:write should be denied (only read allowed)"
        );
    }

    #[test]
    fn evaluate_fs_write_allowed() {
        let f = write_policy(
            r#"
@id("allow-fs-write")
permit(
    principal == Agent::"agent",
    action == Action::"fs:write",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/project/src", "fs:write", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "fs:write should be allowed for /project/src"
        );
    }

    #[test]
    fn evaluate_fs_outside_scope_denied() {
        let f = write_policy(
            r#"
@id("allow-project")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/etc/passwd", "fs:read", "agent")
            .unwrap();
        assert!(!result.allowed, "fs:read outside /project should be denied");
    }

    #[test]
    fn evaluate_fs_context_path_condition_matches() {
        // Policy uses `when { context.path like "/project/*" }` — should match
        // now that evaluate_fs populates context with path and operation.
        let f = write_policy(
            r#"
@id("allow-fs-context-path")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource
) when { context.path like "/project/*" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/project/src/main.rs", "fs:read", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "fs:read should be allowed when context.path matches /project/*"
        );

        // Path outside /project should be denied by the `when` condition.
        let result = engine
            .evaluate_fs("/etc/passwd", "fs:read", "agent")
            .unwrap();
        assert!(
            !result.allowed,
            "fs:read should be denied when context.path does not match /project/*"
        );
    }

    #[test]
    fn evaluate_fs_context_operation_populated() {
        // Policy gates on context.operation — only allow "read" operations.
        let f = write_policy(
            r#"
@id("allow-fs-read-only-by-context")
permit(
    principal == Agent::"agent",
    action,
    resource in Resource::"fs::/project"
) when { context.operation == "read" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_fs("/project/src", "fs:read", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "fs:read should be allowed when context.operation == 'read'"
        );

        let result = engine
            .evaluate_fs("/project/src", "fs:write", "agent")
            .unwrap();
        assert!(
            !result.allowed,
            "fs:write should be denied when context.operation != 'read'"
        );
    }

    // --- is_host_permitted tests ---

    #[test]
    fn is_host_permitted_when_policy_allows() {
        let f = write_policy(
            r#"
@id("allow-github")
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        assert!(
            engine.is_host_permitted("api.github.com", "agent").unwrap(),
            "api.github.com should be permitted"
        );
    }

    #[test]
    fn is_host_not_permitted_when_no_policy() {
        let f = write_policy(
            r#"
@id("allow-github")
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        assert!(
            !engine
                .is_host_permitted("evil.example.com", "agent")
                .unwrap(),
            "evil.example.com should not be permitted"
        );
    }

    #[test]
    fn is_host_permitted_with_post_only_policy() {
        let f = write_policy(
            r#"
@id("allow-post-only")
permit(
    principal == Agent::"agent",
    action == Action::"http:POST",
    resource in Resource::"api.example.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        assert!(
            engine
                .is_host_permitted("api.example.com", "agent")
                .unwrap(),
            "host with POST-only policy should still be permitted for CONNECT"
        );
    }

    // --- extract_fs_permissions tests ---

    #[test]
    fn extract_fs_permissions_read_only() {
        use crate::container::ContainerPermission;

        let f = write_policy(
            r#"
@id("read-project")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let paths = vec!["/project".to_string()];
        let perms = extract_fs_permissions(&engine, &paths, "agent");

        assert_eq!(perms.len(), 1);
        assert_eq!(
            perms[0],
            ContainerPermission::FsRead("/project".to_string())
        );
    }

    #[test]
    fn extract_fs_permissions_read_write() {
        use crate::container::ContainerPermission;

        let f = write_policy(
            r#"
@id("write-project")
permit(
    principal == Agent::"agent",
    action == Action::"fs:write",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let paths = vec!["/project".to_string()];
        let perms = extract_fs_permissions(&engine, &paths, "agent");

        assert_eq!(perms.len(), 1);
        // fs:write should produce FsWrite (not FsRead)
        assert_eq!(
            perms[0],
            ContainerPermission::FsWrite("/project".to_string())
        );
    }

    #[test]
    fn extract_fs_permissions_denied_path_not_mounted() {
        let f = write_policy(
            r#"
@id("allow-project")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/project"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let paths = vec!["/project".to_string(), "/etc".to_string()];
        let perms = extract_fs_permissions(&engine, &paths, "agent");

        // /etc should not be mounted (no policy permits it)
        assert_eq!(perms.len(), 1);
    }

    #[test]
    fn extract_fs_permissions_empty_policy_denies_all() {
        // A policy with no fs: permits should produce no mounts
        let f = write_policy(
            r#"
@id("allow-http-only")
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let paths = vec!["/project".to_string()];
        let perms = extract_fs_permissions(&engine, &paths, "agent");

        assert!(
            perms.is_empty(),
            "HTTP-only policy should produce no fs mounts"
        );
    }

    // --- Header namespace security tests (H-ER-1) ---

    #[test]
    fn header_named_path_does_not_override_url_path() {
        // A header named "path" must NOT override the actual URL path in context.
        // The header should appear as "header:path", not "path".
        let f = write_policy(
            r#"
@id("allow-by-path")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.path == "/safe" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Request to /safe should be allowed
        let result = engine
            .evaluate("example.com", "http:GET", "/safe", &[], "worker")
            .unwrap();
        assert!(result.allowed, "GET /safe should be allowed");

        // Request to /secret with a header named "path" set to "/safe"
        // must NOT bypass the policy — the header is namespaced as "header:path"
        let malicious_headers = vec![("path".to_string(), "/safe".to_string())];
        let result = engine
            .evaluate(
                "example.com",
                "http:GET",
                "/secret",
                &malicious_headers,
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "GET /secret with path header should still be denied — header must not override context.path"
        );
    }

    #[test]
    fn header_named_host_does_not_override_host() {
        // A header named "host" must NOT override the actual host in context.
        let f = write_policy(
            r#"
@id("allow-example")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.host == "safe.example.com" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Header named "host" should not override the actual host
        let malicious_headers = vec![("host".to_string(), "safe.example.com".to_string())];
        let result = engine
            .evaluate(
                "evil.example.com",
                "http:GET",
                "/",
                &malicious_headers,
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "header named 'host' must not override context.host"
        );
    }

    #[test]
    fn header_named_method_does_not_override_method() {
        // A header named "method" must NOT override the actual method in context.
        let f = write_policy(
            r#"
@id("allow-get-only")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context.method == "GET" };

@id("allow-delete-action")
permit(
    principal == Agent::"worker",
    action == Action::"http:DELETE",
    resource
) when { context.method == "GET" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Header named "method" set to "GET" should not make a DELETE appear as GET
        let malicious_headers = vec![("method".to_string(), "GET".to_string())];
        let result = engine
            .evaluate(
                "example.com",
                "http:DELETE",
                "/resource",
                &malicious_headers,
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "header named 'method' must not override context.method"
        );
    }

    #[test]
    fn headers_appear_as_namespaced_keys_in_context() {
        // Headers should appear in Cedar context with the "header:" prefix.
        let f = write_policy(
            r#"
@id("check-auth-header")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when { context["header:authorization"] == "Bearer token123" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let headers = vec![("Authorization".to_string(), "Bearer token123".to_string())];
        let result = engine
            .evaluate("example.com", "http:GET", "/api", &headers, "worker")
            .unwrap();
        assert!(
            result.allowed,
            "header should be accessible as context[\"header:authorization\"]"
        );
    }

    #[test]
    fn control_chars_in_header_values_are_escaped() {
        // Control characters in header values should not cause panics.
        let f = write_policy(
            r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Header values with control characters should not panic
        let headers = vec![
            (
                "x-test".to_string(),
                "line1\nline2\rline3\ttab\0null".to_string(),
            ),
            ("x-quotes".to_string(), "has \"quotes\" inside".to_string()),
            ("x-backslash".to_string(), "path\\to\\file".to_string()),
        ];
        let result = engine.evaluate("example.com", "http:GET", "/", &headers, "worker");
        assert!(
            result.is_ok(),
            "control chars in headers should not cause panic: {:?}",
            result.err()
        );
    }

    #[test]
    fn escape_cedar_string_handles_control_chars() {
        assert_eq!(escape_cedar_string("hello\nworld"), "hello\\nworld");
        assert_eq!(escape_cedar_string("tab\there"), "tab\\there");
        assert_eq!(escape_cedar_string("cr\rhere"), "cr\\rhere");
        assert_eq!(escape_cedar_string("null\0here"), "null\\0here");
        assert_eq!(escape_cedar_string("quote\"here"), "quote\\\"here");
        assert_eq!(escape_cedar_string("back\\slash"), "back\\\\slash");
        // Multiple control chars in combination
        assert_eq!(escape_cedar_string("a\nb\rc\td\0e"), "a\\nb\\rc\\td\\0e");
    }

    #[test]
    fn restricted_expression_errors_propagate_not_panic() {
        // Verify that the evaluate function returns Err (not panic)
        // when given input that could produce invalid Cedar expressions.
        // After the fix, RestrictedExpression::from_str errors propagate
        // via ? rather than unwrap().
        //
        // Note: with proper escaping, well-formed strings won't trigger
        // RestrictedExpression parse errors. This test verifies the overall
        // error handling path works correctly for valid inputs with special chars.
        let f = write_policy(
            r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // Various edge cases that should be handled gracefully
        let edge_cases = vec![
            ("x-empty".to_string(), "".to_string()),
            ("x-unicode".to_string(), "héllo wörld".to_string()),
            (
                "x-special".to_string(),
                "<script>alert(1)</script>".to_string(),
            ),
            ("x-long".to_string(), "a".repeat(10000)),
        ];

        for (key, value) in &edge_cases {
            let headers = vec![(key.clone(), value.clone())];
            let result = engine.evaluate("example.com", "http:GET", "/", &headers, "worker");
            assert!(
                result.is_ok(),
                "evaluate should handle header '{}' gracefully, got: {:?}",
                key,
                result.err()
            );
        }
    }

    // --- Shared context builder tests (M-ER-9) ---

    #[test]
    fn shared_http_context_matches_evaluate_output() {
        // Verify that the shared build_http_context produces an equivalent
        // context to what evaluate() builds internally (same attributes).
        // We do this by evaluating a policy that uses context.host, context.path,
        // and context.method — if context is wrong, the policy won't match.
        let f = write_policy(
            r#"
@id("match-all-context")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when {
    context.host == "api.github.com" &&
    context.path == "/repos/org/repo" &&
    context.method == "GET"
};
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        // This exercises the shared context builder path in evaluate()
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "shared context builder should produce host/path/method for evaluate()"
        );
    }

    #[test]
    fn shared_http_context_aws_attrs_match_evaluate() {
        // Verify AWS context attributes work through the shared builder
        let f = write_policy(
            r#"
@id("match-aws-context")
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
) when {
    context.aws_service == "s3" &&
    context.aws_region == "us-east-1"
};
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:GET",
                "/bucket",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "shared context builder should produce AWS attrs for evaluate()"
        );
    }

    // --- evaluate_proc tests (M-ER-9) ---

    #[test]
    fn evaluate_proc_allows_matching_command() {
        let f = write_policy(
            r#"
@id("allow-node")
permit(
    principal == Agent::"agent",
    action == Action::"proc:exec",
    resource == Resource::"proc::node index.js"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_proc("node index.js", "proc:exec", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "proc:exec should be allowed for matching command"
        );
        assert!(
            result.policy_names.iter().any(|n| n.contains("allow-node")),
            "expected allow-node policy, got {:?}",
            result.policy_names
        );
    }

    #[test]
    fn evaluate_proc_denies_non_matching_command() {
        let f = write_policy(
            r#"
@id("allow-node")
permit(
    principal == Agent::"agent",
    action == Action::"proc:exec",
    resource == Resource::"proc::node index.js"
);
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_proc("rm -rf /", "proc:exec", "agent")
            .unwrap();
        assert!(
            !result.allowed,
            "proc:exec should be denied for non-matching command"
        );
    }

    #[test]
    fn evaluate_proc_context_command_condition() {
        // Policy uses context.command to gate access
        let f = write_policy(
            r#"
@id("allow-node-by-context")
permit(
    principal == Agent::"agent",
    action == Action::"proc:exec",
    resource
) when { context.command like "node*" };
"#,
        );
        let engine = PolicyEngine::load(f.path(), None).unwrap();

        let result = engine
            .evaluate_proc("node index.js", "proc:exec", "agent")
            .unwrap();
        assert!(
            result.allowed,
            "proc:exec should be allowed when context.command matches"
        );

        let result = engine
            .evaluate_proc("python script.py", "proc:exec", "agent")
            .unwrap();
        assert!(
            !result.allowed,
            "proc:exec should be denied when context.command doesn't match"
        );
    }

    // --- Dead entity removal tests (M-ER-9) ---

    #[test]
    fn proc_entities_do_not_include_fork_or_signal() {
        let entities = build_proc_entities("curl", "worker").unwrap();
        let entity_ids: Vec<String> = entities.iter().map(|e| e.uid().to_string()).collect();

        // Should contain proc:exec
        assert!(
            entity_ids.iter().any(|id| id.contains("proc:exec")),
            "should have proc:exec entity, got: {:?}",
            entity_ids
        );

        // Should NOT contain proc:fork or proc:signal
        assert!(
            !entity_ids.iter().any(|id| id.contains("proc:fork")),
            "should not have proc:fork entity, got: {:?}",
            entity_ids
        );
        assert!(
            !entity_ids.iter().any(|id| id.contains("proc:signal")),
            "should not have proc:signal entity, got: {:?}",
            entity_ids
        );
    }
}
