//! Unified TOML configuration and shared proxy context.
//!
//! All file parsing lives here. `strait.toml` is the single config file that
//! replaces the old CLI flags. The [`ProxyContext`] struct bundles every piece
//! of shared state that connection handlers need, replacing the previous 8+
//! positional parameters.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use std::{fs, io::Write as _};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::audit::AuditLogger;
use crate::ca::SessionCa;
use crate::credentials::CredentialStore;
use crate::decisions::PendingDecisionStore;
use crate::observe::ObservationStream;
use crate::policy::PolicyEngine;

// ---------------------------------------------------------------------------
// TOML configuration types
// ---------------------------------------------------------------------------

/// Top-level configuration parsed from `strait.toml`.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct StraitConfig {
    /// Path to write the session CA certificate PEM (required).
    pub ca_cert_path: PathBuf,

    /// Listener configuration.
    #[serde(default)]
    pub listen: ListenConfig,

    /// MITM host configuration.
    #[serde(default)]
    pub mitm: MitmConfig,

    /// Cedar policy file configuration.
    pub policy: Option<PolicyConfig>,

    /// Credential entries for header injection.
    #[serde(default)]
    pub credential: Vec<CredentialEntryConfig>,

    /// Audit logging configuration.
    pub audit: Option<AuditConfig>,

    /// Identity configuration (reserved for future use).
    pub identity: Option<IdentityConfig>,

    /// Health check configuration (reserved for future use).
    pub health: Option<HealthConfig>,
}

/// `[listen]` section — address and port for the proxy listener.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct ListenConfig {
    /// Bind address (default `"127.0.0.1"`).
    #[serde(default = "default_address")]
    pub address: String,

    /// Port to listen on (0 = ephemeral, default `0`).
    #[serde(default)]
    pub port: u16,
}

impl Default for ListenConfig {
    fn default() -> Self {
        Self {
            address: default_address(),
            port: 0,
        }
    }
}

fn default_address() -> String {
    "127.0.0.1".to_string()
}

/// Default maximum body size for MITM buffering (10 MB).
const DEFAULT_MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Default keep-alive idle timeout (seconds).
const DEFAULT_KEEPALIVE_TIMEOUT_SECS: u64 = 30;

/// Default upstream connection timeout (seconds).
const DEFAULT_UPSTREAM_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Default upstream response timeout (seconds).
const DEFAULT_UPSTREAM_RESPONSE_TIMEOUT_SECS: u64 = 60;

/// Default live decision hold timeout (seconds).
const DEFAULT_DECISION_TIMEOUT_SECS: u64 = 30;

/// Strategy doc referenced by devcontainer validation errors.
const DEVCONTAINER_STRATEGY_DOC: &str = "docs/designs/devcontainer-strategy.md";

/// `[mitm]` section — which hosts to intercept.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct MitmConfig {
    /// Hostnames that should be MITM'd for policy inspection.
    #[serde(default)]
    pub hosts: Vec<String>,

    /// Maximum request body size (in bytes) that the MITM pipeline will buffer.
    /// Requests with `Content-Length` exceeding this limit are rejected with
    /// HTTP 413. Defaults to 10 MB.
    #[serde(default = "default_max_body_size")]
    pub max_body_size: usize,

    /// Keep-alive idle timeout (seconds) for MITM connections. The proxy
    /// closes the client TLS connection if no new request arrives within
    /// this interval after the last response. Defaults to 30 seconds.
    #[serde(default = "default_keepalive_timeout_secs")]
    pub keepalive_timeout_secs: u64,

    /// Timeout (seconds) for establishing a TCP connection to the upstream
    /// server. Requests that exceed this limit receive HTTP 504.
    /// Defaults to 30 seconds.
    #[serde(default = "default_upstream_connect_timeout_secs")]
    pub upstream_connect_timeout_secs: u64,

    /// Timeout (seconds) for receiving the complete HTTP response from the
    /// upstream server after the request has been sent. Requests that exceed
    /// this limit receive HTTP 504. Defaults to 60 seconds.
    #[serde(default = "default_upstream_response_timeout_secs")]
    pub upstream_response_timeout_secs: u64,

    /// Timeout (seconds) to hold a blocked request open while waiting for a
    /// live decision from the local control plane. Defaults to 30 seconds.
    #[serde(default = "default_decision_timeout_secs")]
    pub decision_timeout_secs: u64,
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            keepalive_timeout_secs: DEFAULT_KEEPALIVE_TIMEOUT_SECS,
            upstream_connect_timeout_secs: DEFAULT_UPSTREAM_CONNECT_TIMEOUT_SECS,
            upstream_response_timeout_secs: DEFAULT_UPSTREAM_RESPONSE_TIMEOUT_SECS,
            decision_timeout_secs: DEFAULT_DECISION_TIMEOUT_SECS,
        }
    }
}

fn default_max_body_size() -> usize {
    DEFAULT_MAX_BODY_SIZE
}

fn default_keepalive_timeout_secs() -> u64 {
    DEFAULT_KEEPALIVE_TIMEOUT_SECS
}

fn default_upstream_connect_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_CONNECT_TIMEOUT_SECS
}

fn default_upstream_response_timeout_secs() -> u64 {
    DEFAULT_UPSTREAM_RESPONSE_TIMEOUT_SECS
}

fn default_decision_timeout_secs() -> u64 {
    DEFAULT_DECISION_TIMEOUT_SECS
}

/// `[policy]` section — Cedar policy source (local file or git repository).
///
/// Exactly one of `file` or `git_url` must be set:
/// - `file`: load a `.cedar` policy from a local path (no polling, no hot-reload).
/// - `git_url`: clone a git repository and load the policy from it. The repo is
///   polled at `poll_interval_secs` for changes and hot-reloaded atomically.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct PolicyConfig {
    /// Path to a local `.cedar` policy file (mutually exclusive with `git_url`).
    pub file: Option<PathBuf>,
    /// Git repository URL to clone policies from (mutually exclusive with `file`).
    pub git_url: Option<String>,
    /// Relative path to the `.cedar` file within the git repo.
    /// When omitted, auto-detects a single `.cedar` file in the repo root.
    pub git_path: Option<String>,
    /// Optional path to a `.cedarschema` file for policy validation.
    /// In file mode: local filesystem path. In git mode: relative to repo root.
    pub schema: Option<PathBuf>,
    /// Polling interval (seconds) for git-hosted policies (default: 60).
    /// Only used when `git_url` is set; ignored for file mode.
    pub poll_interval_secs: Option<u64>,
}

impl PolicyConfig {
    /// Validate that the policy configuration is consistent.
    fn validate(&self) -> anyhow::Result<()> {
        match (&self.file, &self.git_url) {
            (Some(_), Some(_)) => {
                anyhow::bail!("[policy] `file` and `git_url` are mutually exclusive")
            }
            (None, None) => {
                anyhow::bail!("[policy] requires either `file` or `git_url`")
            }
            _ => {}
        }
        if self.file.is_some() && self.git_path.is_some() {
            anyhow::bail!("[policy] `git_path` is only valid with `git_url`");
        }
        if self.file.is_some() && self.poll_interval_secs.is_some() {
            anyhow::bail!("[policy] `poll_interval_secs` is only valid with `git_url`");
        }
        Ok(())
    }
}

/// `[[credential]]` array entry — a single credential for header injection.
///
/// Exactly one of `host` or `host_pattern` must be set:
/// - `host`: exact hostname match (e.g. `"api.github.com"`)
/// - `host_pattern`: glob pattern with leading wildcard (e.g. `"*.amazonaws.com"`)
///
/// Supported credential types:
/// - `"bearer"` (default) — injects a single static header/value pair.
/// - `"aws-sigv4"` — signs the request with AWS Signature Version 4.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct CredentialEntryConfig {
    /// Exact hostname this credential applies to (e.g. `"api.github.com"`).
    /// Mutually exclusive with `host_pattern`.
    pub host: Option<String>,
    /// Hostname glob pattern for pattern-based matching (e.g. `"*.amazonaws.com"`).
    /// Mutually exclusive with `host`.
    pub host_pattern: Option<String>,
    /// HTTP header name to inject (e.g. `"Authorization"`).
    /// Required for `"bearer"` type; ignored for `"aws-sigv4"`.
    #[serde(default)]
    pub header: String,
    /// Prefix prepended to the resolved secret value (e.g. `"token "`).
    /// Only used by `"bearer"` type.
    #[serde(default)]
    pub value_prefix: String,
    /// Source type. Currently only `"env"` is supported.
    pub source: String,
    /// Environment variable name (required when `source = "env"` and type is `"bearer"`).
    pub env_var: Option<String>,
    /// Credential type: `"bearer"` (default) or `"aws-sigv4"`.
    #[serde(rename = "type", default = "default_credential_type")]
    pub credential_type: String,

    // --- AWS SigV4-specific fields (optional, type = "aws-sigv4" only) ---
    /// Environment variable for the AWS access key ID.
    /// Defaults to `"AWS_ACCESS_KEY_ID"`.
    pub access_key_id_var: Option<String>,
    /// Environment variable for the AWS secret access key.
    /// Defaults to `"AWS_SECRET_ACCESS_KEY"`.
    pub secret_access_key_var: Option<String>,
    /// Environment variable for the optional AWS session token.
    /// Defaults to `"AWS_SESSION_TOKEN"`.
    pub session_token_var: Option<String>,
}

fn default_credential_type() -> String {
    "bearer".to_string()
}

/// `[audit]` section — audit log file configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct AuditConfig {
    /// Path to an audit log file. If omitted, events are only written to stderr.
    pub log_path: Option<PathBuf>,
}

/// `[identity]` section — agent identity extraction from request headers.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct IdentityConfig {
    /// HTTP header name to extract the agent identity from (default `"X-Strait-Agent"`).
    #[serde(default = "default_identity_header")]
    pub header: String,

    /// Default agent identity when the header is absent (default `"anonymous"`).
    #[serde(default = "default_identity_default")]
    pub default: String,
}

impl Default for IdentityConfig {
    fn default() -> Self {
        Self {
            header: default_identity_header(),
            default: default_identity_default(),
        }
    }
}

fn default_identity_header() -> String {
    "X-Strait-Agent".to_string()
}

fn default_identity_default() -> String {
    "anonymous".to_string()
}

/// `[health]` section — health check endpoint configuration.
#[derive(Debug, Deserialize, Clone)]
#[serde(deny_unknown_fields)]
pub struct HealthConfig {
    /// Port for the health check endpoint (required when `[health]` is present).
    pub port: u16,
}

/// Typed subset of devcontainer.json fields honored by strait.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevcontainerConfig {
    /// Prebuilt image reference from `image`.
    pub image: Option<String>,
    /// Docker build configuration from `build`.
    pub build: Option<DevcontainerBuildConfig>,
    /// Environment variables injected into the container.
    pub container_env: BTreeMap<String, String>,
    /// Mount declarations inherited from `devcontainer.json`.
    pub mounts: Vec<String>,
    /// Lifecycle hook run before the agent command.
    pub post_create_command: Option<DevcontainerCommand>,
    /// Lifecycle hook run during container creation.
    pub on_create_command: Option<DevcontainerCommand>,
    /// Preferred workspace folder inside the container.
    pub workspace_folder: Option<String>,
    /// User account the agent should run as.
    pub remote_user: Option<String>,
}

/// Docker build configuration extracted from `devcontainer.json`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DevcontainerBuildConfig {
    /// Dockerfile path resolved relative to the devcontainer file.
    pub dockerfile: PathBuf,
    /// Optional build context resolved relative to the devcontainer file.
    pub context: Option<PathBuf>,
}

/// Lifecycle command shape used by `postCreateCommand` and `onCreateCommand`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevcontainerCommand {
    /// Shell command string.
    Shell(String),
    /// Exec-form argv list.
    Exec(Vec<String>),
    /// Named commands represented as an object map.
    Named(BTreeMap<String, DevcontainerCommandStep>),
}

/// Leaf command shape for named lifecycle commands.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DevcontainerCommandStep {
    /// Shell command string.
    Shell(String),
    /// Exec-form argv list.
    Exec(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDevcontainerConfig {
    image: Option<String>,
    build: Option<RawDevcontainerBuildConfig>,
    #[serde(default)]
    container_env: BTreeMap<String, String>,
    post_create_command: Option<RawDevcontainerCommand>,
    on_create_command: Option<RawDevcontainerCommand>,
    workspace_folder: Option<String>,
    remote_user: Option<String>,
    privileged: Option<bool>,
    cap_add: Option<serde_json::Value>,
    run_args: Option<Vec<String>>,
    forward_ports: Option<serde_json::Value>,
    mounts: Option<RawDevcontainerMounts>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RawDevcontainerBuildConfig {
    dockerfile: String,
    context: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawDevcontainerCommand {
    Shell(String),
    Exec(Vec<String>),
    Named(BTreeMap<String, RawDevcontainerCommandStep>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawDevcontainerCommandStep {
    Shell(String),
    Exec(Vec<String>),
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
enum RawDevcontainerMounts {
    Single(String),
    Multiple(Vec<String>),
}

impl From<RawDevcontainerCommand> for DevcontainerCommand {
    fn from(value: RawDevcontainerCommand) -> Self {
        match value {
            RawDevcontainerCommand::Shell(command) => Self::Shell(command),
            RawDevcontainerCommand::Exec(command) => Self::Exec(command),
            RawDevcontainerCommand::Named(commands) => Self::Named(
                commands
                    .into_iter()
                    .map(|(name, step)| (name, step.into()))
                    .collect(),
            ),
        }
    }
}

impl From<RawDevcontainerCommandStep> for DevcontainerCommandStep {
    fn from(value: RawDevcontainerCommandStep) -> Self {
        match value {
            RawDevcontainerCommandStep::Shell(command) => Self::Shell(command),
            RawDevcontainerCommandStep::Exec(command) => Self::Exec(command),
        }
    }
}

/// Load and validate a `devcontainer.json` / JSONC file.
pub fn parse_devcontainer(path: &Path) -> anyhow::Result<DevcontainerConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read devcontainer file: {}", path.display()))?;
    let raw: RawDevcontainerConfig = json5::from_str(&text)
        .with_context(|| format!("invalid devcontainer.json: {}", path.display()))?;

    validate_devcontainer_fields(&raw)?;
    warn_on_ignored_devcontainer_fields(&raw, path);

    let base_dir = path.parent().unwrap_or_else(|| Path::new("."));
    Ok(DevcontainerConfig {
        image: raw.image,
        build: raw.build.map(|build| DevcontainerBuildConfig {
            dockerfile: resolve_devcontainer_path(base_dir, &build.dockerfile),
            context: build
                .context
                .as_deref()
                .map(|context| resolve_devcontainer_path(base_dir, context)),
        }),
        container_env: raw.container_env,
        mounts: raw
            .mounts
            .map(RawDevcontainerMounts::into_vec)
            .unwrap_or_default(),
        post_create_command: raw.post_create_command.map(Into::into),
        on_create_command: raw.on_create_command.map(Into::into),
        workspace_folder: raw.workspace_folder,
        remote_user: raw.remote_user,
    })
}

impl RawDevcontainerMounts {
    fn into_vec(self) -> Vec<String> {
        match self {
            Self::Single(mount) => vec![mount],
            Self::Multiple(mounts) => mounts,
        }
    }
}

fn resolve_devcontainer_path(base_dir: &Path, raw_path: &str) -> PathBuf {
    let path = Path::new(raw_path);
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base_dir.join(path)
    }
}

fn validate_devcontainer_fields(config: &RawDevcontainerConfig) -> anyhow::Result<()> {
    if config.privileged.unwrap_or(false) {
        return Err(reject_devcontainer_field(
            "privileged",
            "privileged containers can bypass Strait's network boundary",
        ));
    }

    if has_nonempty_value(config.cap_add.as_ref()) {
        return Err(reject_devcontainer_field(
            "capAdd",
            "Linux capability additions are not compatible with Strait's network isolation",
        ));
    }

    if let Some(run_arg) = config
        .run_args
        .as_ref()
        .and_then(|args| args.iter().find(|arg| is_unsafe_run_arg(arg)))
    {
        return Err(reject_devcontainer_field(
            "runArgs",
            &format!("unsafe value '{run_arg}' can weaken Strait's network boundary"),
        ));
    }

    Ok(())
}

fn reject_devcontainer_field(field: &str, reason: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "devcontainer.json field '{field}' is not supported: {reason}. See {DEVCONTAINER_STRATEGY_DOC}."
    )
}

fn warn_on_ignored_devcontainer_fields(config: &RawDevcontainerConfig, path: &Path) {
    if has_nonempty_value(config.forward_ports.as_ref()) {
        warn!(
            path = %path.display(),
            "ignoring devcontainer field 'forwardPorts'; inbound port forwarding does not fit Strait's network model. See {}.",
            DEVCONTAINER_STRATEGY_DOC
        );
    }
}

fn has_nonempty_value(value: Option<&impl HasNonEmptyValue>) -> bool {
    value.is_some_and(HasNonEmptyValue::has_nonempty_value)
}

trait HasNonEmptyValue {
    fn has_nonempty_value(&self) -> bool;
}

impl HasNonEmptyValue for serde_json::Value {
    fn has_nonempty_value(&self) -> bool {
        match self {
            serde_json::Value::Array(items) => !items.is_empty(),
            serde_json::Value::Object(map) => !map.is_empty(),
            serde_json::Value::String(text) => !text.is_empty(),
            serde_json::Value::Null => false,
            _ => true,
        }
    }
}

impl HasNonEmptyValue for RawDevcontainerMounts {
    fn has_nonempty_value(&self) -> bool {
        match self {
            Self::Single(text) => !text.is_empty(),
            Self::Multiple(items) => !items.is_empty(),
        }
    }
}

fn is_unsafe_run_arg(arg: &str) -> bool {
    if matches!(
        arg,
        "--privileged"
            | "--cap-add"
            | "--net"
            | "--network"
            | "--pid"
            | "--ipc"
            | "--uts"
            | "--device"
            | "--mount"
            | "--volume"
            | "-v"
            | "--security-opt"
    ) {
        return true;
    }

    let prefixes = [
        "--privileged=",
        "--cap-add=",
        "--net=",
        "--network=",
        "--pid=",
        "--ipc=",
        "--uts=",
        "--device=",
        "--mount=",
        "--volume=",
        "-v=",
        "--security-opt=",
    ];

    prefixes.iter().any(|prefix| arg.starts_with(prefix))
}

impl StraitConfig {
    /// Load and parse a `strait.toml` configuration file.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file: {}", path.display()))?;
        let config: Self = toml::from_str(&text)
            .with_context(|| format!("invalid strait.toml: {}", path.display()))?;
        Ok(config)
    }
}

// ---------------------------------------------------------------------------
// ProxyContext — bundles all shared state for connection handlers
// ---------------------------------------------------------------------------

/// State for git-hosted policy polling.
///
/// Created at startup when `[policy].git_url` is set. Holds the cloned repo
/// directory and paths needed by the background poll task.
pub struct GitPolicyState {
    /// Temp directory holding the cloned repo (kept alive for cleanup on drop).
    _temp_dir: tempfile::TempDir,
    /// Path to the cloned git repository.
    pub repo_dir: PathBuf,
    /// Absolute path to the `.cedar` policy file within the cloned repo.
    pub policy_path: PathBuf,
    /// Absolute path to the `.cedarschema` file within the cloned repo (if any).
    pub schema_path: Option<PathBuf>,
    /// Polling interval for git fetch.
    pub poll_interval: Duration,
}

/// All shared state needed by connection handlers.
///
/// Built once at startup from [`StraitConfig`] and passed (via `Arc`) to every
/// spawned connection task, replacing the previous 8+ positional parameters.
pub struct ProxyContext {
    /// Session-local CA for issuing per-host leaf certificates.
    pub session_ca: SessionCa,
    /// Cedar policy engine, wrapped in [`ArcSwap`] for atomic hot-reload.
    ///
    /// In git mode, the background poll task swaps in a new engine when the
    /// upstream repo changes. In-flight requests hold the old `Arc` until they
    /// complete — no partial policy states are ever visible.
    pub policy_engine: Option<ArcSwap<PolicyEngine>>,
    /// Credential store for header injection (if credentials are configured).
    pub credential_store: Option<Arc<CredentialStore>>,
    /// Structured JSON audit logger.
    pub audit_logger: Arc<AuditLogger>,
    /// Hostnames that should be MITM'd for policy inspection.
    pub mitm_hosts: Vec<String>,
    /// Maximum request body size (bytes) the MITM pipeline will buffer.
    pub max_body_size: usize,
    /// Keep-alive idle timeout for MITM connections.
    pub keepalive_timeout: Duration,
    /// Timeout for establishing a TCP connection to the upstream server.
    pub upstream_connect_timeout: Duration,
    /// Timeout for receiving the complete HTTP response from upstream.
    pub upstream_response_timeout: Duration,
    /// Timeout to hold a blocked request while awaiting a live decision.
    pub decision_timeout: Duration,
    /// Instant when the proxy context was created (for uptime calculation).
    pub startup_instant: Instant,
    /// HTTP header name to extract agent identity from.
    pub identity_header: String,
    /// Default agent identity when the identity header is absent.
    pub identity_default: String,
    /// Git policy state for the background poll task (`None` for file mode).
    pub git_policy: Option<GitPolicyState>,
    /// Original policy configuration for SIGHUP-triggered reloads.
    pub policy_config: Option<PolicyConfig>,
    /// Optional observation stream for recording proxy activity.
    ///
    /// When set (e.g. during `init --observe`), every MITM'd request emits
    /// a `NetworkRequest` event through this stream.
    pub observation_stream: Option<ObservationStream>,

    /// Current enforcement mode: `"observe"`, `"warn"`, or `"enforce"`.
    ///
    /// Populated by the caller after construction (e.g. `launch` derives it
    /// from the `EnforcementMode` enum). Emitted in `NetworkRequest`
    /// observation events so downstream consumers (`strait watch`,
    /// `strait generate`) can distinguish modes.
    pub enforcement_mode: String,

    /// When true, MITM all connections regardless of the `mitm_hosts` list.
    ///
    /// Used by `launch` modes where all traffic must be observed or evaluated.
    /// Bypasses the `should_mitm()` allowlist check.
    pub mitm_all: bool,

    /// When true, policy denials are logged as warnings but traffic is still
    /// forwarded upstream. Used by `launch --warn` mode.
    pub warn_only: bool,
    /// Live-update boundaries for launch sessions.
    ///
    /// When present, policy mutations may update network enforcement in place,
    /// but any effective change to filesystem mounts or proc allowlists is
    /// rejected with a restart-required outcome.
    pub live_policy_bounds: Option<LivePolicyBounds>,
    /// Override the upstream TCP address for testing.
    ///
    /// When set, `handle_mitm` connects to this address instead of `{host}:{port}`.
    /// Production code leaves this as `None`.
    pub upstream_addr_override: Option<std::net::SocketAddr>,
    /// Override the TLS client config for upstream connections (for testing).
    ///
    /// When set, `handle_mitm` uses this config instead of building one from
    /// webpki roots. Production code leaves this as `None`.
    pub upstream_tls_override: Option<Arc<rustls::ClientConfig>>,
    /// Pending live decisions and session-scoped live allows.
    ///
    /// Tracks blocked-request IDs that are currently waiting on a control-plane
    /// decision and caches allow-session selections for later matching requests.
    pub pending_decisions: Arc<PendingDecisionStore>,
}

/// Runtime information needed to keep launch-time fs/proc policy state restart-bound.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LivePolicyBounds {
    /// Paths whose mount permissions were derived from the Cedar policy at startup.
    pub fs_candidate_paths: Vec<String>,
    /// Agent identity used for launch-time fs/proc permission extraction.
    pub agent_id: String,
}

/// Source for a live policy mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyMutation {
    /// Reload from the configured file or git source.
    Reload,
    /// Replace the active policy with the provided Cedar text.
    Replace { policy: String },
}

/// Result of attempting a live policy mutation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyMutationOutcome {
    /// Whether the new policy was atomically applied.
    pub applied: bool,
    /// Policy domains that still require a restart to take effect.
    pub restart_required_domains: Vec<String>,
}

impl PolicyMutationOutcome {
    fn applied() -> Self {
        Self {
            applied: true,
            restart_required_domains: Vec::new(),
        }
    }

    fn restart_required(domains: Vec<String>) -> Self {
        Self {
            applied: false,
            restart_required_domains: domains,
        }
    }
}

impl ProxyContext {
    /// Build a [`ProxyContext`] from a parsed [`StraitConfig`].
    ///
    /// This generates the session CA, loads the Cedar policy file (from disk or
    /// git), resolves credentials, and initializes the audit logger. If
    /// `[policy].git_url` is set, the repository is cloned at startup.
    pub fn from_config(config: &StraitConfig) -> anyhow::Result<Self> {
        // Generate session CA
        let session_ca = SessionCa::generate()?;
        info!("session CA generated");

        // Load Cedar policy (if configured)
        let (policy_engine, git_policy) = match &config.policy {
            Some(policy_config) => {
                policy_config.validate()?;

                if let Some(ref git_url) = policy_config.git_url {
                    // Git mode: clone repo and load policy from it
                    let temp_dir = tempfile::TempDir::new()
                        .context("failed to create temp directory for git clone")?;
                    let repo_dir = temp_dir.path().join("repo");

                    git_clone(git_url, &repo_dir)
                        .with_context(|| format!("failed to clone policy repo: {git_url}"))?;
                    info!(url = git_url, "policy git repo cloned");

                    let policy_path = match &policy_config.git_path {
                        Some(p) => repo_dir.join(p),
                        None => find_cedar_file(&repo_dir)?,
                    };

                    let schema_path = policy_config.schema.as_ref().map(|s| repo_dir.join(s));

                    let engine = PolicyEngine::load(&policy_path, schema_path.as_deref())?;
                    info!(path = %policy_path.display(), "Cedar policy loaded from git");

                    let poll_interval =
                        Duration::from_secs(policy_config.poll_interval_secs.unwrap_or(60));

                    let git_state = GitPolicyState {
                        _temp_dir: temp_dir,
                        repo_dir,
                        policy_path,
                        schema_path,
                        poll_interval,
                    };

                    (Some(ArcSwap::from_pointee(engine)), Some(git_state))
                } else if let Some(ref file) = policy_config.file {
                    // File mode: load from local path (no polling, no hot-reload)
                    let engine = PolicyEngine::load(file, policy_config.schema.as_deref())?;
                    info!(path = %file.display(), "Cedar policy loaded");
                    (Some(ArcSwap::from_pointee(engine)), None)
                } else {
                    // Unreachable: validate() ensures one of file/git_url is set
                    unreachable!("PolicyConfig validation should have caught this")
                }
            }
            None => (None, None),
        };

        // Build credential store (if credentials are present)
        let credential_store = if config.credential.is_empty() {
            None
        } else {
            let store = CredentialStore::from_entries(&config.credential)?;
            info!(count = config.credential.len(), "credentials loaded");
            Some(Arc::new(store))
        };

        // Initialize audit logger
        let audit_log_path = config.audit.as_ref().and_then(|a| a.log_path.as_deref());
        let audit_logger = Arc::new(AuditLogger::new(audit_log_path)?);
        info!(
            session_id = audit_logger.session_id(),
            "audit logger initialized"
        );

        // Resolve identity configuration
        let identity = config.identity.clone().unwrap_or_default();

        // Derive enforcement mode from policy engine presence.
        // `from_config` always sets warn_only=false, so the mode is either
        // "enforce" (policy present) or "observe" (no policy).
        let enforcement_mode = if policy_engine.is_some() {
            "enforce".to_string()
        } else {
            "observe".to_string()
        };

        Ok(Self {
            session_ca,
            policy_engine,
            credential_store,
            audit_logger,
            mitm_hosts: config.mitm.hosts.clone(),
            max_body_size: config.mitm.max_body_size,
            keepalive_timeout: Duration::from_secs(config.mitm.keepalive_timeout_secs),
            upstream_connect_timeout: Duration::from_secs(
                config.mitm.upstream_connect_timeout_secs,
            ),
            upstream_response_timeout: Duration::from_secs(
                config.mitm.upstream_response_timeout_secs,
            ),
            decision_timeout: Duration::from_secs(config.mitm.decision_timeout_secs),
            startup_instant: Instant::now(),
            identity_header: identity.header,
            identity_default: identity.default,
            git_policy,
            policy_config: config.policy.clone(),
            observation_stream: None,
            enforcement_mode,
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: None,
            upstream_tls_override: None,
            pending_decisions: Arc::new(PendingDecisionStore::new()),
        })
    }
}

// ---------------------------------------------------------------------------
// Git operations
// ---------------------------------------------------------------------------

/// Clone a git repository to the given destination path.
fn git_clone(url: &str, dest: &Path) -> anyhow::Result<()> {
    let output = std::process::Command::new("git")
        .args(["clone", "--quiet", url])
        .arg(dest)
        .output()
        .context("failed to execute `git clone`")?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("git clone failed: {}", stderr.trim());
    }
    Ok(())
}

/// Get the current HEAD commit SHA from a git repository.
fn git_head_sha(repo_dir: &Path) -> anyhow::Result<String> {
    let output = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_dir)
        .output()
        .context("failed to execute `git rev-parse HEAD`")?;

    if !output.status.success() {
        anyhow::bail!("git rev-parse HEAD failed");
    }

    Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
}

/// Find a single `.cedar` policy file in the given directory.
///
/// Returns an error if zero or more than one `.cedar` file is found.
fn find_cedar_file(dir: &Path) -> anyhow::Result<PathBuf> {
    let entries: Vec<PathBuf> = std::fs::read_dir(dir)
        .with_context(|| format!("failed to read directory: {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|ext| ext == "cedar"))
        .collect();

    match entries.len() {
        0 => anyhow::bail!(
            "no .cedar policy files found in {}; set `git_path` in [policy]",
            dir.display()
        ),
        1 => Ok(entries.into_iter().next().unwrap()),
        n => anyhow::bail!(
            "{n} .cedar files found in {}; set `git_path` to specify which one",
            dir.display()
        ),
    }
}

/// Background task that polls a git repository for policy changes.
///
/// Runs `git fetch` + `git reset --hard origin/HEAD` at the configured interval.
/// When a change is detected (by comparing HEAD SHA), the policy is reloaded and
/// atomically swapped via [`ArcSwap`]. In-flight requests see the old policy until
/// the swap completes.
pub async fn git_policy_poll_task(ctx: Arc<ProxyContext>) {
    let git_state = match &ctx.git_policy {
        Some(s) => s,
        None => return,
    };

    let repo_dir = &git_state.repo_dir;
    let mut last_sha = git_head_sha(repo_dir).unwrap_or_default();

    info!(
        interval_secs = git_state.poll_interval.as_secs(),
        sha = %last_sha,
        "git policy poll task started"
    );

    let mut interval = tokio::time::interval(git_state.poll_interval);
    interval.tick().await; // skip first immediate tick

    loop {
        interval.tick().await;

        // Fetch updates from origin
        let fetch = tokio::process::Command::new("git")
            .args(["fetch", "origin", "--quiet"])
            .current_dir(repo_dir)
            .output()
            .await;

        match fetch {
            Ok(ref output) if output.status.success() => {}
            Ok(ref output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(error = %stderr.trim(), "git fetch failed, retrying next interval");
                continue;
            }
            Err(ref e) => {
                warn!(error = %e, "git fetch execution failed, retrying next interval");
                continue;
            }
        }

        // Reset to latest origin/HEAD
        let reset = tokio::process::Command::new("git")
            .args(["reset", "--hard", "origin/HEAD", "--quiet"])
            .current_dir(repo_dir)
            .output()
            .await;

        match reset {
            Ok(ref output) if output.status.success() => {}
            Ok(ref output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                warn!(error = %stderr.trim(), "git reset failed, retrying next interval");
                continue;
            }
            Err(ref e) => {
                warn!(error = %e, "git reset execution failed, retrying next interval");
                continue;
            }
        }

        // Check if HEAD changed
        let new_sha = match git_head_sha(repo_dir) {
            Ok(sha) => sha,
            Err(e) => {
                warn!(error = %e, "failed to read git HEAD after fetch");
                continue;
            }
        };

        if new_sha == last_sha {
            continue;
        }

        // Policy changed — reload and swap atomically
        info!(
            old_sha = %&last_sha[..last_sha.len().min(8)],
            new_sha = %&new_sha[..new_sha.len().min(8)],
            "git policy change detected, reloading"
        );

        let policy_path = git_state.policy_path.clone();
        let schema_path = git_state.schema_path.clone();

        let load_result = tokio::task::spawn_blocking(move || {
            PolicyEngine::load(&policy_path, schema_path.as_deref())
        })
        .await;

        match load_result {
            Ok(Ok(new_engine)) => {
                if let Some(ref swap) = ctx.policy_engine {
                    swap.store(Arc::new(new_engine));
                    info!(sha = %new_sha, "git policy hot-reloaded successfully");
                    last_sha = new_sha;
                }
            }
            Ok(Err(e)) => {
                warn!(
                    error = %e,
                    "failed to load updated git policy, keeping previous version"
                );
            }
            Err(e) => {
                warn!(error = %e, "policy reload task panicked");
            }
        }
    }
}

// ---------------------------------------------------------------------------
// SIGHUP policy reload
// ---------------------------------------------------------------------------

fn load_schema_text_for_replace(ctx: &ProxyContext) -> anyhow::Result<Option<(String, String)>> {
    let schema_path = if let Some(git_state) = &ctx.git_policy {
        git_state.schema_path.as_ref()
    } else {
        ctx.policy_config
            .as_ref()
            .and_then(|config| config.schema.as_ref())
    };

    schema_path
        .map(|path| {
            let schema = std::fs::read_to_string(path)
                .with_context(|| format!("failed to read schema file: {}", path.display()))?;
            Ok((schema, path.display().to_string()))
        })
        .transpose()
}

fn durable_policy_file_path(ctx: &ProxyContext) -> anyhow::Result<&Path> {
    let policy_config = ctx
        .policy_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no policy configured, nothing to persist"))?;

    if ctx.git_policy.is_some() || policy_config.git_url.is_some() {
        anyhow::bail!(
            "persist requires [policy].file; git-backed policy sources are read-only for durable updates"
        );
    }

    policy_config
        .file
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("persist requires [policy].file"))
}

fn policy_allows_request(
    policy_text: &str,
    schema: Option<&(String, String)>,
    host: &str,
    method: &str,
    path: &str,
    agent_id: &str,
) -> anyhow::Result<bool> {
    let engine = PolicyEngine::from_text(
        policy_text,
        schema.map(|(text, _)| text.as_str()),
        schema.map(|(_, label)| label.as_str()),
    )?;
    let decision = engine.evaluate(host, &format!("http:{method}"), path, &[], agent_id)?;
    Ok(decision.allowed)
}

fn append_policy_snippet(existing: &str, snippet: &str) -> String {
    let snippet = snippet.trim();
    if existing.trim().is_empty() {
        return format!("{snippet}\n");
    }

    let mut updated = existing.to_string();
    if !updated.ends_with('\n') {
        updated.push('\n');
    }
    if !updated.ends_with("\n\n") {
        updated.push('\n');
    }
    updated.push_str(snippet);
    updated.push('\n');
    updated
}

fn write_text_atomic(path: &Path, content: &str) -> anyhow::Result<()> {
    let parent = path.parent().ok_or_else(|| {
        anyhow::anyhow!("policy file '{}' has no parent directory", path.display())
    })?;
    let mut temp = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary file next to policy source '{}'",
            path.display()
        )
    })?;
    temp.write_all(content.as_bytes()).with_context(|| {
        format!(
            "failed to write temporary contents for policy source '{}'",
            path.display()
        )
    })?;
    temp.flush().with_context(|| {
        format!(
            "failed to flush temporary contents for policy source '{}'",
            path.display()
        )
    })?;
    temp.persist(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to replace policy source '{}': {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

/// Persist a durable Cedar exception to the configured policy file, then reload
/// the running session from disk so the new network rule applies live.
pub fn persist_policy_exception(
    ctx: &ProxyContext,
    match_key: &str,
    cedar_snippet: &str,
) -> anyhow::Result<PolicyMutationOutcome> {
    let policy_path = durable_policy_file_path(ctx)?;
    let existing = fs::read_to_string(policy_path)
        .with_context(|| format!("failed to read policy file: {}", policy_path.display()))?;
    let schema = load_schema_text_for_replace(ctx)?;
    let (host, method, path) = crate::policy::parse_match_key(match_key)?;
    let agent_id = ctx
        .live_policy_bounds
        .as_ref()
        .map(|bounds| bounds.agent_id.as_str())
        .unwrap_or(ctx.identity_default.as_str());

    if policy_allows_request(&existing, schema.as_ref(), &host, &method, &path, agent_id)? {
        return reload_policy(ctx);
    }

    let updated = append_policy_snippet(&existing, cedar_snippet);
    PolicyEngine::from_text(
        &updated,
        schema.as_ref().map(|(text, _)| text.as_str()),
        schema.as_ref().map(|(_, label)| label.as_str()),
    )?;

    write_text_atomic(policy_path, &updated)?;
    match reload_policy(ctx) {
        Ok(outcome) => Ok(outcome),
        Err(error) => {
            let rollback = write_text_atomic(policy_path, &existing)
                .and_then(|_| reload_policy(ctx).map(|_| ()))
                .map_err(|rollback_error| {
                    anyhow::anyhow!("{}; rollback failed: {rollback_error}", error)
                });
            rollback?;
            Err(error)
        }
    }
}

fn restart_required_domains(
    ctx: &ProxyContext,
    _current_engine: &PolicyEngine,
    _new_engine: &PolicyEngine,
) -> Vec<String> {
    let Some(_bounds) = &ctx.live_policy_bounds else {
        return Vec::new();
    };
    Vec::new()
}

fn load_mutated_policy(
    ctx: &ProxyContext,
    mutation: &PolicyMutation,
) -> anyhow::Result<PolicyEngine> {
    let policy_config = ctx
        .policy_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no policy configured, nothing to reload"))?;

    match mutation {
        PolicyMutation::Reload => {
            if let Some(git_state) = &ctx.git_policy {
                // Git mode: fetch latest, then reload from the local clone
                let repo_dir = &git_state.repo_dir;

                let fetch = std::process::Command::new("git")
                    .args(["fetch", "origin", "--quiet"])
                    .current_dir(repo_dir)
                    .output()
                    .context("failed to execute `git fetch`")?;

                if !fetch.status.success() {
                    let stderr = String::from_utf8_lossy(&fetch.stderr);
                    anyhow::bail!("git fetch failed: {}", stderr.trim());
                }

                let reset = std::process::Command::new("git")
                    .args(["reset", "--hard", "origin/HEAD", "--quiet"])
                    .current_dir(repo_dir)
                    .output()
                    .context("failed to execute `git reset`")?;

                if !reset.status.success() {
                    let stderr = String::from_utf8_lossy(&reset.stderr);
                    anyhow::bail!("git reset failed: {}", stderr.trim());
                }

                PolicyEngine::load(&git_state.policy_path, git_state.schema_path.as_deref())
            } else if let Some(ref file) = policy_config.file {
                PolicyEngine::load(file, policy_config.schema.as_deref())
            } else {
                anyhow::bail!("policy configuration has no file or git source");
            }
        }
        PolicyMutation::Replace { policy } => {
            let schema = load_schema_text_for_replace(ctx)?;
            PolicyEngine::from_text(
                policy,
                schema.as_ref().map(|(text, _)| text.as_str()),
                schema.as_ref().map(|(_, label)| label.as_str()),
            )
        }
    }
}

/// Apply a live policy mutation, atomically swapping the policy engine when the
/// update is valid and does not require restart-bound fs/proc changes.
pub fn mutate_policy(
    ctx: &ProxyContext,
    mutation: PolicyMutation,
) -> anyhow::Result<PolicyMutationOutcome> {
    if ctx.policy_config.is_none() {
        anyhow::bail!("no policy configured, nothing to reload");
    }

    let swap = ctx
        .policy_engine
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no policy engine initialized, nothing to reload"))?;

    let current_engine = swap.load();
    let new_engine = load_mutated_policy(ctx, &mutation)?;
    let restart_required = restart_required_domains(ctx, current_engine.as_ref(), &new_engine);
    if !restart_required.is_empty() {
        return Ok(PolicyMutationOutcome::restart_required(restart_required));
    }

    swap.store(Arc::new(new_engine));
    Ok(PolicyMutationOutcome::applied())
}

/// Reload the policy from its configured source (file or git).
pub fn reload_policy(ctx: &ProxyContext) -> anyhow::Result<PolicyMutationOutcome> {
    mutate_policy(ctx, PolicyMutation::Reload)
}

/// Replace the active policy with the provided Cedar source.
pub fn replace_policy(
    ctx: &ProxyContext,
    policy: impl Into<String>,
) -> anyhow::Result<PolicyMutationOutcome> {
    mutate_policy(
        ctx,
        PolicyMutation::Replace {
            policy: policy.into(),
        },
    )
}

/// Background task that listens for `SIGHUP` and triggers a policy reload.
///
/// On Unix (Linux and macOS), registers a `SIGHUP` signal handler using
/// `tokio::signal::unix`. Each received signal triggers an immediate policy
/// reload via [`reload_policy`]. On success, the new policy takes effect for
/// all subsequent requests. On failure, the previous policy is retained and
/// the error is logged — the process never crashes.
#[cfg(unix)]
pub async fn sighup_reload_task(ctx: Arc<ProxyContext>) {
    use tokio::signal::unix::{signal, SignalKind};

    let mut stream = match signal(SignalKind::hangup()) {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "failed to register SIGHUP handler");
            return;
        }
    };

    info!("SIGHUP reload handler registered");

    loop {
        stream.recv().await;
        info!("SIGHUP received, reloading policy");

        // Run the (potentially blocking) reload on the blocking pool
        let reload_ctx = ctx.clone();
        let result = tokio::task::spawn_blocking(move || reload_policy(&reload_ctx)).await;

        match result {
            Ok(Ok(outcome)) if outcome.applied => {
                info!("policy reloaded successfully via SIGHUP");
            }
            Ok(Ok(outcome)) => {
                warn!(
                    domains = ?outcome.restart_required_domains,
                    "SIGHUP policy reload requires restart to apply fs/proc changes; keeping previous policy"
                );
            }
            Ok(Err(e)) => {
                error!(
                    error = %e,
                    "SIGHUP policy reload failed, keeping previous policy"
                );
            }
            Err(e) => {
                error!(error = %e, "SIGHUP policy reload task panicked");
            }
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
    use std::sync::{Arc, Mutex};
    use tempfile::{NamedTempFile, TempDir};

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn write_devcontainer(content: &str) -> (TempDir, PathBuf) {
        let temp_dir = tempfile::tempdir().unwrap();
        let devcontainer_dir = temp_dir.path().join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).unwrap();

        let path = devcontainer_dir.join("devcontainer.json");
        std::fs::write(&path, content).unwrap();

        (temp_dir, path)
    }

    struct WarnCollector {
        messages: Arc<Mutex<Vec<String>>>,
    }

    impl tracing::Subscriber for WarnCollector {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            *metadata.level() <= tracing::Level::WARN
        }

        fn new_span(&self, _: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _: &tracing::span::Id, _: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _: &tracing::span::Id, _: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            let mut visitor = MsgExtractor(String::new());
            event.record(&mut visitor);
            self.messages.lock().unwrap().push(visitor.0);
        }

        fn enter(&self, _: &tracing::span::Id) {}

        fn exit(&self, _: &tracing::span::Id) {}
    }

    struct MsgExtractor(String);

    impl tracing::field::Visit for MsgExtractor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{:?}", value);
            }
        }
    }

    fn persist_snippet_for(host: &str, method: &str, path: &str) -> String {
        crate::policy::synthesize_blocked_request(host, method, path, &[], &[], false)
            .candidate_exception
            .unwrap()
            .persist
            .cedar_snippet
    }

    #[test]
    fn load_valid_config_all_sections() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[listen]
address = "0.0.0.0"
port = 8080

[mitm]
hosts = ["api.github.com", "api.stripe.com"]

[policy]
file = "policy.cedar"

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "GITHUB_TOKEN"

[audit]
log_path = "/tmp/audit.jsonl"

[identity]
header = "X-Custom-Agent"
default = "system"

[health]
port = 9090
"#,
        );

        let config = StraitConfig::load(f.path()).unwrap();
        assert_eq!(config.ca_cert_path, PathBuf::from("/tmp/ca.pem"));
        assert_eq!(config.listen.address, "0.0.0.0");
        assert_eq!(config.listen.port, 8080);
        assert_eq!(config.mitm.hosts, vec!["api.github.com", "api.stripe.com"]);
        assert_eq!(
            config.policy.as_ref().unwrap().file,
            Some(PathBuf::from("policy.cedar"))
        );
        assert_eq!(config.credential.len(), 1);
        assert_eq!(
            config.credential[0].host,
            Some("api.github.com".to_string())
        );
        assert_eq!(
            config.audit.as_ref().unwrap().log_path,
            Some(PathBuf::from("/tmp/audit.jsonl"))
        );
        let identity = config.identity.as_ref().unwrap();
        assert_eq!(identity.header, "X-Custom-Agent");
        assert_eq!(identity.default, "system");
        assert_eq!(config.health.as_ref().unwrap().port, 9090);
    }

    #[test]
    fn missing_config_file_errors() {
        let result = StraitConfig::load(Path::new("/nonexistent/strait.toml"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("failed to read config file"), "got: {err}");
    }

    #[test]
    fn invalid_toml_errors() {
        let f = write_config("this is not valid toml {{{}}}");
        let result = StraitConfig::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid strait.toml"), "got: {err}");
    }

    #[test]
    fn empty_mitm_hosts_is_valid_passthrough_mode() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
hosts = []
"#,
        );

        let config = StraitConfig::load(f.path()).unwrap();
        assert!(config.mitm.hosts.is_empty());
    }

    #[test]
    fn missing_optional_sections_get_defaults() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );

        let config = StraitConfig::load(f.path()).unwrap();
        assert_eq!(config.listen.address, "127.0.0.1");
        assert_eq!(config.listen.port, 0);
        assert!(config.mitm.hosts.is_empty());
        assert!(config.policy.is_none());
        assert!(config.credential.is_empty());
        assert!(config.audit.is_none());
        assert!(config.identity.is_none());
        assert!(config.health.is_none());
    }

    #[test]
    fn ca_cert_path_is_required() {
        let f = write_config(
            r#"
[listen]
port = 8080
"#,
        );

        let result = StraitConfig::load(f.path());
        assert!(result.is_err());
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("ca_cert_path"),
            "error should mention ca_cert_path, got: {err}"
        );
    }

    #[test]
    fn proxy_context_from_minimal_config() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert!(ctx.policy_engine.is_none());
        assert!(ctx.credential_store.is_none());
        assert!(ctx.mitm_hosts.is_empty());
        assert!(!ctx.session_ca.ca_cert_pem.is_empty());
        assert!(!ctx.audit_logger.session_id().is_empty());
        // Identity defaults when [identity] section is absent
        assert_eq!(ctx.identity_header, "X-Strait-Agent");
        assert_eq!(ctx.identity_default, "anonymous");
        // No policy engine → observe mode
        assert_eq!(ctx.enforcement_mode, "observe");
    }

    #[test]
    fn proxy_context_enforcement_mode_enforce_with_policy() {
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.cedar");
        std::fs::write(&policy_path, "permit(principal, action, resource);\n").unwrap();

        let config_str = format!(
            r#"
ca_cert_path = "/tmp/ca.pem"

[policy]
file = "{}"
"#,
            policy_path.display()
        );
        let f = write_config(&config_str);
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert!(ctx.policy_engine.is_some());
        assert_eq!(ctx.enforcement_mode, "enforce");
    }

    #[test]
    fn proxy_context_with_credentials() {
        std::env::set_var("STRAIT_CONFIG_TEST_TOKEN", "ghp_test");

        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "STRAIT_CONFIG_TEST_TOKEN"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert!(ctx.credential_store.is_some());
        let store = ctx.credential_store.as_ref().unwrap();
        let cred = store.get("api.github.com").unwrap();
        let injected = cred.inject("GET", "/", &[], None).unwrap();
        assert_eq!(injected.len(), 1);
        assert_eq!(injected[0].0, "Authorization");
        assert_eq!(injected[0].1, "token ghp_test");

        std::env::remove_var("STRAIT_CONFIG_TEST_TOKEN");
    }

    #[test]
    fn proxy_context_with_mitm_hosts() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
hosts = ["api.github.com", "api.stripe.com"]
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert_eq!(ctx.mitm_hosts, vec!["api.github.com", "api.stripe.com"]);
    }

    #[test]
    fn proxy_context_with_custom_identity() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[identity]
header = "X-My-Agent"
default = "system"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert_eq!(ctx.identity_header, "X-My-Agent");
        assert_eq!(ctx.identity_default, "system");
    }

    #[test]
    fn identity_section_empty_uses_defaults() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[identity]
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let identity = config.identity.unwrap();
        assert_eq!(identity.header, "X-Strait-Agent");
        assert_eq!(identity.default, "anonymous");
    }

    // --- Example config file test ---

    #[test]
    fn example_config_parses_without_errors() {
        let config_path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/strait.toml");
        let config = StraitConfig::load(&config_path);
        assert!(
            config.is_ok(),
            "example config failed to parse: {:#}",
            config.unwrap_err()
        );
        let config = config.unwrap();
        assert_eq!(config.listen.port, 8080);
        assert_eq!(
            config.mitm.hosts,
            vec![
                "api.github.com",
                "s3.us-east-1.amazonaws.com",
                "lambda.us-east-1.amazonaws.com",
            ]
        );
        let policy = config.policy.as_ref().unwrap();
        assert_eq!(policy.file, Some(PathBuf::from("examples/github.cedar")));
        assert!(policy.git_url.is_none());
        // Two credentials: GitHub bearer + AWS SigV4
        assert_eq!(config.credential.len(), 2);
        assert_eq!(
            config.credential[0].host,
            Some("api.github.com".to_string())
        );
        assert_eq!(config.credential[0].credential_type, "bearer");
        assert_eq!(
            config.credential[1].host_pattern,
            Some("*.amazonaws.com".to_string())
        );
        assert_eq!(config.credential[1].credential_type, "aws-sigv4");
        assert_eq!(config.health.as_ref().unwrap().port, 9090);
    }

    // --- Policy config validation tests ---

    #[test]
    fn policy_git_url_mode_parses() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
git_url = "https://example.com/policies.git"
git_path = "policies/main.cedar"
schema = "policies/schema.cedarschema"
poll_interval_secs = 30
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let policy = config.policy.unwrap();
        assert!(policy.file.is_none());
        assert_eq!(
            policy.git_url.as_deref(),
            Some("https://example.com/policies.git")
        );
        assert_eq!(policy.git_path.as_deref(), Some("policies/main.cedar"));
        assert_eq!(
            policy.schema,
            Some(PathBuf::from("policies/schema.cedarschema"))
        );
        assert_eq!(policy.poll_interval_secs, Some(30));
    }

    #[test]
    fn policy_file_mode_parses() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
file = "policy.cedar"
schema = "policy.cedarschema"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let policy = config.policy.unwrap();
        assert_eq!(policy.file, Some(PathBuf::from("policy.cedar")));
        assert!(policy.git_url.is_none());
        assert!(policy.git_path.is_none());
        assert_eq!(policy.schema, Some(PathBuf::from("policy.cedarschema")));
        assert!(policy.poll_interval_secs.is_none());
    }

    #[test]
    fn policy_file_and_git_url_both_set_errors() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
file = "policy.cedar"
git_url = "https://example.com/policies.git"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let result = config.policy.unwrap().validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("mutually exclusive"), "got: {err}");
    }

    #[test]
    fn policy_neither_file_nor_git_url_errors() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
schema = "policy.cedarschema"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let result = config.policy.unwrap().validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("requires either"), "got: {err}");
    }

    #[test]
    fn policy_git_path_invalid_with_file_mode() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
file = "policy.cedar"
git_path = "some/path.cedar"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let result = config.policy.unwrap().validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("git_path"),
            "error should mention git_path, got: {err}"
        );
    }

    #[test]
    fn policy_poll_interval_invalid_with_file_mode() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
[policy]
file = "policy.cedar"
poll_interval_secs = 30
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let result = config.policy.unwrap().validate();
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("poll_interval_secs"),
            "error should mention poll_interval_secs, got: {err}"
        );
    }

    // --- deny_unknown_fields tests ---

    #[test]
    fn unknown_top_level_field_errors() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
ploicy = "typo.cedar"
"#,
        );
        let result = StraitConfig::load(f.path());
        assert!(result.is_err(), "typo field 'ploicy' should be rejected");
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn unknown_section_errors() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[ploicy]
file = "policy.cedar"
"#,
        );
        let result = StraitConfig::load(f.path());
        assert!(
            result.is_err(),
            "typo section '[ploicy]' should be rejected"
        );
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field, got: {err}"
        );
    }

    #[test]
    fn unknown_field_in_nested_section_errors() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[listen]
address = "127.0.0.1"
port = 8080
typo_field = true
"#,
        );
        let result = StraitConfig::load(f.path());
        assert!(
            result.is_err(),
            "unknown field in [listen] should be rejected"
        );
        let err = format!("{:#}", result.unwrap_err());
        assert!(
            err.contains("unknown field"),
            "error should mention unknown field, got: {err}"
        );
    }

    // --- ArcSwap verification ---

    #[test]
    fn arcswap_policy_engine_load_and_store() {
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(decision.allowed, "permit-all policy should allow");

        let deny_all = r#"forbid(principal, action, resource);"#;
        let mut df = NamedTempFile::new().unwrap();
        df.write_all(deny_all.as_bytes()).unwrap();
        df.flush().unwrap();
        let new_engine = PolicyEngine::load(df.path(), None).unwrap();
        ctx.policy_engine
            .as_ref()
            .unwrap()
            .store(Arc::new(new_engine));

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(!decision.allowed, "deny-all policy should deny");
    }

    // --- Git clone integration tests ---

    fn setup_bare_repo(
        policy_content: &str,
        schema_content: Option<&str>,
    ) -> (tempfile::TempDir, String) {
        use std::process::Command as Cmd;

        let dir = tempfile::TempDir::new().unwrap();
        let bare_path = dir.path().join("policies.git");
        let work_path = dir.path().join("work");

        let out = Cmd::new("git")
            .args(["init", "--bare"])
            .arg(&bare_path)
            .output()
            .unwrap();
        assert!(out.status.success(), "git init --bare failed");

        let out = Cmd::new("git")
            .args(["clone"])
            .arg(&bare_path)
            .arg(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success(), "git clone failed");

        std::fs::write(work_path.join("policy.cedar"), policy_content).unwrap();
        if let Some(schema) = schema_content {
            std::fs::write(work_path.join("policy.cedarschema"), schema).unwrap();
        }

        let out = Cmd::new("git")
            .args(["add", "."])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success());

        let out = Cmd::new("git")
            .args([
                "-c",
                "user.email=test@test.com",
                "-c",
                "user.name=Test",
                "commit",
                "-m",
                "initial policy",
            ])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success(), "git commit failed");

        let out = Cmd::new("git")
            .args(["push"])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success(), "git push failed");

        let url = format!("file://{}", bare_path.display());
        (dir, url)
    }

    fn push_policy_update(bare_dir: &Path, policy_content: &str) {
        use std::process::Command as Cmd;

        let work_path = bare_dir.join("work_update");
        let bare_path = bare_dir.join("policies.git");

        let out = Cmd::new("git")
            .args(["clone"])
            .arg(&bare_path)
            .arg(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success());

        std::fs::write(work_path.join("policy.cedar"), policy_content).unwrap();

        let out = Cmd::new("git")
            .args(["add", "."])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success());

        let out = Cmd::new("git")
            .args([
                "-c",
                "user.email=test@test.com",
                "-c",
                "user.name=Test",
                "commit",
                "-m",
                "update policy",
            ])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success());

        let out = Cmd::new("git")
            .args(["push"])
            .current_dir(&work_path)
            .output()
            .unwrap();
        assert!(out.status.success());
    }

    #[test]
    fn git_clone_loads_policy() {
        let policy = r#"permit(principal, action, resource);"#;
        let (_bare_dir, url) = setup_bare_repo(policy, None);

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\ngit_url = \"{}\"",
            url
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        assert!(ctx.policy_engine.is_some());
        assert!(ctx.git_policy.is_some());

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("example.com", "http:GET", "/test", &[], "worker")
            .unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn git_clone_with_explicit_git_path() {
        use std::process::Command as Cmd;

        let dir = tempfile::TempDir::new().unwrap();
        let bare_path = dir.path().join("policies.git");
        let work_path = dir.path().join("work");

        Cmd::new("git")
            .args(["init", "--bare"])
            .arg(&bare_path)
            .output()
            .unwrap();
        Cmd::new("git")
            .args(["clone"])
            .arg(&bare_path)
            .arg(&work_path)
            .output()
            .unwrap();

        std::fs::create_dir_all(work_path.join("policies")).unwrap();
        std::fs::write(
            work_path.join("policies/main.cedar"),
            r#"permit(principal, action, resource);"#,
        )
        .unwrap();

        Cmd::new("git")
            .args(["add", "."])
            .current_dir(&work_path)
            .output()
            .unwrap();
        Cmd::new("git")
            .args([
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=T",
                "commit",
                "-m",
                "init",
            ])
            .current_dir(&work_path)
            .output()
            .unwrap();
        Cmd::new("git")
            .args(["push"])
            .current_dir(&work_path)
            .output()
            .unwrap();

        let url = format!("file://{}", bare_path.display());
        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n\
             [policy]\n\
             git_url = \"{}\"\n\
             git_path = \"policies/main.cedar\"",
            url
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("example.com", "http:GET", "/", &[], "worker")
            .unwrap();
        assert!(decision.allowed);
    }

    #[test]
    fn git_clone_with_schema_validation() {
        let policy = r#"permit(principal, action, resource);"#;
        let schema = r#"
entity Agent;
entity Resource;
action "http:GET", "http:POST", "http:PUT", "http:PATCH", "http:DELETE", "http:HEAD", "http:OPTIONS"
  appliesTo { principal: Agent, resource: Resource };
"#;
        let (_bare_dir, url) = setup_bare_repo(policy, Some(schema));

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n\
             [policy]\n\
             git_url = \"{}\"\n\
             schema = \"policy.cedarschema\"",
            url
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("example.com", "http:GET", "/test", &[], "worker")
            .unwrap();
        assert!(decision.allowed);
    }

    #[tokio::test]
    async fn git_poll_detects_change_and_hot_reloads() {
        let policy_v1 = r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
"#;
        let (bare_dir, url) = setup_bare_repo(policy_v1, None);

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n\
             [policy]\n\
             git_url = \"{}\"\n\
             poll_interval_secs = 1",
            url
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = Arc::new(ProxyContext::from_config(&config).unwrap());

        let poll_ctx = ctx.clone();
        let handle = tokio::spawn(async move {
            git_policy_poll_task(poll_ctx).await;
        });

        // V1: GET allowed, POST denied
        {
            let engine = ctx.policy_engine.as_ref().unwrap().load();
            let d = engine
                .evaluate("example.com", "http:GET", "/test", &[], "worker")
                .unwrap();
            assert!(d.allowed, "GET should be allowed in v1");
            let d = engine
                .evaluate("example.com", "http:POST", "/test", &[], "worker")
                .unwrap();
            assert!(!d.allowed, "POST should be denied in v1");
        }

        // Push v2: also allow POST
        let policy_v2 = r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource
);
permit(
    principal == Agent::"worker",
    action == Action::"http:POST",
    resource
);
"#;
        push_policy_update(bare_dir.path(), policy_v2);

        tokio::time::sleep(Duration::from_secs(3)).await;

        // V2: POST now allowed
        {
            let engine = ctx.policy_engine.as_ref().unwrap().load();
            let d = engine
                .evaluate("example.com", "http:POST", "/test", &[], "worker")
                .unwrap();
            assert!(d.allowed, "POST should be allowed after hot-reload");
        }

        handle.abort();
    }

    // --- SIGHUP reload tests ---

    #[test]
    fn reload_policy_file_mode_swaps_engine() {
        // Start with permit-all
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        // Verify initial permit-all
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(decision.allowed, "initial policy should allow");

        // Overwrite the policy file with forbid-all
        std::fs::write(pf.path(), r#"forbid(principal, action, resource);"#).unwrap();

        // Reload via reload_policy
        let outcome = reload_policy(&ctx).unwrap();
        assert!(outcome.applied, "reload should report an applied update");
        assert!(
            outcome.restart_required_domains.is_empty(),
            "network-only reload should not require restart"
        );

        // Verify deny-all is now active
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(!decision.allowed, "reloaded policy should deny");
    }

    #[test]
    fn reload_policy_invalid_file_keeps_old_policy() {
        // Start with permit-all
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        // Overwrite with invalid Cedar syntax
        std::fs::write(pf.path(), "this is not valid cedar {{{}}}").unwrap();

        // Reload should fail
        let result = reload_policy(&ctx);
        assert!(result.is_err(), "reload with invalid syntax should fail");

        // Old permit-all policy should still be active
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "old policy should be retained on reload failure"
        );
    }

    #[test]
    fn replace_policy_swaps_engine() {
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let outcome = replace_policy(&ctx, "forbid(principal, action, resource);").unwrap();
        assert!(outcome.applied, "replace should apply a valid policy");
        assert!(
            outcome.restart_required_domains.is_empty(),
            "network-only replace should not require restart"
        );

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(!decision.allowed, "replacement policy should deny");
    }

    #[test]
    fn replace_policy_invalid_keeps_old_policy() {
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let result = replace_policy(&ctx, "this is not valid cedar {{{}}}");
        assert!(result.is_err(), "replace with invalid syntax should fail");

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "old policy should be retained when replace fails"
        );
    }

    #[test]
    fn persist_policy_exception_appends_rule_and_reloads_live_engine() {
        let initial_policy = r#"
@id("allow-health")
permit(
    principal,
    action == Action::"http:GET",
    resource == Resource::"api.github.com/health"
);
"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(initial_policy.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();
        let snippet = persist_snippet_for("api.github.com", "GET", "/repos/org/repo");

        let outcome =
            persist_policy_exception(&ctx, "http:GET api.github.com/repos/org/repo", &snippet)
                .unwrap();

        assert!(outcome.applied);
        let persisted = std::fs::read_to_string(pf.path()).unwrap();
        assert!(persisted.contains(&snippet));

        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("api.github.com", "http:GET", "/repos/org/repo", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "persisted rule should apply live after reload"
        );
    }

    #[test]
    fn persist_policy_exception_skips_duplicate_rule_churn() {
        let snippet = persist_snippet_for("api.github.com", "GET", "/repos/org/repo");
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(format!("{snippet}\n").as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();
        let before = std::fs::read_to_string(pf.path()).unwrap();

        let outcome =
            persist_policy_exception(&ctx, "http:GET api.github.com/repos/org/repo", &snippet)
                .unwrap();

        assert!(outcome.applied);
        let after = std::fs::read_to_string(pf.path()).unwrap();
        assert_eq!(
            after, before,
            "duplicate persist should not rewrite policy text"
        );
    }

    #[test]
    fn persist_policy_exception_skips_when_broader_rule_already_exists() {
        let broader = r#"
@id("allow-get-host")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(broader.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();
        let snippet = persist_snippet_for("api.github.com", "GET", "/repos/org/repo");
        let before = std::fs::read_to_string(pf.path()).unwrap();

        let outcome =
            persist_policy_exception(&ctx, "http:GET api.github.com/repos/org/repo", &snippet)
                .unwrap();

        assert!(outcome.applied);
        let after = std::fs::read_to_string(pf.path()).unwrap();
        assert_eq!(after, before, "broader rule should prevent append churn");
    }

    #[test]
    fn reload_policy_fs_or_proc_change_requires_restart() {
        let permit_all = r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let mut ctx = ProxyContext::from_config(&config).unwrap();
        ctx.live_policy_bounds = Some(LivePolicyBounds {
            fs_candidate_paths: vec!["/workspace".to_string()],
            agent_id: "agent".to_string(),
        });

        std::fs::write(
            pf.path(),
            &format!(
                "permit(\n    principal == Agent::\"agent\",\n    action == Action::\"http:GET\",\n    resource\n);\npermit(\n    principal == Agent::\"agent\",\n    action == Action::\"{}:{}\",\n    resource\n);\npermit(\n    principal == Agent::\"agent\",\n    action == Action::\"{}:{}\",\n    resource\n);\n",
                "fs",
                "read",
                "proc",
                "exec"
            ),
        )
        .unwrap();

        let err = reload_policy(&ctx).unwrap_err().to_string();
        assert!(err.contains("removed action domains"), "got: {err}");
    }

    #[test]
    fn reload_policy_no_config_returns_error() {
        // ProxyContext with no policy configured
        let cf = write_config("ca_cert_path = \"/tmp/ca.pem\"");
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        let result = reload_policy(&ctx);
        assert!(result.is_err(), "reload with no policy config should fail");
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("no policy configured"),
            "error should mention no policy configured"
        );
    }

    #[test]
    fn reload_policy_schema_validation_failure_keeps_old() {
        // Create a schema file matching strait's entity model
        let schema_text = r#"
entity Agent;
entity Resource in [Resource];
action "http:GET"
    appliesTo {
        principal: Agent,
        resource: Resource,
        context: {
            "host": String,
            "path": String,
            "method": String,
        },
    };
"#;
        let mut sf = NamedTempFile::with_suffix(".cedarschema").unwrap();
        sf.write_all(schema_text.as_bytes()).unwrap();
        sf.flush().unwrap();

        // Start with a valid policy that matches the schema
        let valid_policy = "permit(principal, action == Action::\"http:GET\", resource);";
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(valid_policy.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"\nschema = \"{}\"",
            pf.path().display(),
            sf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        // Verify initial policy allows GET
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(decision.allowed, "initial policy should allow GET");

        // Overwrite with a policy that references an action not in the schema
        std::fs::write(
            pf.path(),
            "permit(principal, action == Action::\"http:INVALID_NOT_IN_SCHEMA\", resource);",
        )
        .unwrap();

        // Reload should fail due to schema validation
        let result = reload_policy(&ctx);
        assert!(result.is_err(), "reload should fail with schema violation");

        // Old policy should still be active
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "old policy retained after schema validation failure"
        );
    }

    #[test]
    fn reload_policy_no_sighup_policy_unchanged() {
        // Verify that without calling reload_policy, the engine stays the same
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();

        // Overwrite file on disk but DON'T reload
        std::fs::write(pf.path(), r#"forbid(principal, action, resource);"#).unwrap();

        // Policy should still be permit-all (no reload happened)
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "policy should be unchanged without reload"
        );
    }

    // --- SIGHUP signal handler integration tests ---

    /// Send SIGHUP to ourselves → sighup_reload_task picks it up, reloads the
    /// policy, new policy takes effect on next eval. No external network access.
    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_signal_reloads_policy() {
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = Arc::new(ProxyContext::from_config(&config).unwrap());

        // Verify initial permit-all
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(decision.allowed, "initial policy should allow");
        drop(engine);

        // Spawn SIGHUP reload task
        let sighup_ctx = ctx.clone();
        let handle = tokio::spawn(async move {
            sighup_reload_task(sighup_ctx).await;
        });

        // Give the signal handler a moment to register
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Overwrite with forbid-all
        std::fs::write(pf.path(), "forbid(principal, action, resource);").unwrap();

        // Send SIGHUP to ourselves
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }

        // Wait for the reload to complete
        tokio::time::sleep(Duration::from_millis(200)).await;

        // New deny-all policy should be in effect
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(!decision.allowed, "policy should deny after SIGHUP reload");

        handle.abort();
    }

    /// SIGHUP with invalid policy → old policy retained, task stays alive.
    #[cfg(unix)]
    #[tokio::test]
    async fn sighup_invalid_policy_keeps_old_stays_alive() {
        let permit_all = r#"permit(principal, action, resource);"#;
        let mut pf = NamedTempFile::new().unwrap();
        pf.write_all(permit_all.as_bytes()).unwrap();
        pf.flush().unwrap();

        let config_str = format!(
            "ca_cert_path = \"/tmp/ca.pem\"\n[policy]\nfile = \"{}\"",
            pf.path().display()
        );
        let cf = write_config(&config_str);
        let config = StraitConfig::load(cf.path()).unwrap();
        let ctx = Arc::new(ProxyContext::from_config(&config).unwrap());

        // Spawn SIGHUP reload task
        let sighup_ctx = ctx.clone();
        let handle = tokio::spawn(async move {
            sighup_reload_task(sighup_ctx).await;
        });

        // Give the signal handler time to register
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Overwrite with invalid Cedar
        std::fs::write(pf.path(), "this is NOT valid cedar {{{}}}").unwrap();

        // Send SIGHUP
        unsafe {
            libc::kill(libc::getpid(), libc::SIGHUP);
        }

        // Wait for reload attempt
        tokio::time::sleep(Duration::from_millis(200)).await;

        // Old policy retained
        let engine = ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("host", "http:GET", "/", &[], "test")
            .unwrap();
        assert!(
            decision.allowed,
            "old policy should be retained when reload fails"
        );

        // Task still running (process didn't crash)
        assert!(!handle.is_finished(), "reload task should still be running");

        handle.abort();
    }

    // --- Upstream timeout config tests ---

    #[test]
    fn upstream_timeout_defaults() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        assert_eq!(config.mitm.upstream_connect_timeout_secs, 30);
        assert_eq!(config.mitm.upstream_response_timeout_secs, 60);
    }

    #[test]
    fn upstream_timeout_custom_values() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
upstream_connect_timeout_secs = 10
upstream_response_timeout_secs = 120
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        assert_eq!(config.mitm.upstream_connect_timeout_secs, 10);
        assert_eq!(config.mitm.upstream_response_timeout_secs, 120);
    }

    #[test]
    fn proxy_context_upstream_timeout_from_config() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
upstream_connect_timeout_secs = 15
upstream_response_timeout_secs = 90
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        let ctx = ProxyContext::from_config(&config).unwrap();
        assert_eq!(ctx.upstream_connect_timeout, Duration::from_secs(15));
        assert_eq!(ctx.upstream_response_timeout, Duration::from_secs(90));
    }

    // -- devcontainer.json tests -----------------------------------------------

    #[test]
    fn parse_devcontainer_minimal_image_only_jsonc() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              // minimal image-based config
              image: "ghcr.io/example/agent:latest",
            }
            "#,
        );

        let config = parse_devcontainer(&path).unwrap();
        assert_eq!(
            config.image.as_deref(),
            Some("ghcr.io/example/agent:latest")
        );
        assert!(config.build.is_none());
        assert!(config.container_env.is_empty());
        assert!(config.mounts.is_empty());
        assert!(config.post_create_command.is_none());
        assert!(config.on_create_command.is_none());
        assert!(config.workspace_folder.is_none());
        assert!(config.remote_user.is_none());
    }

    #[test]
    fn parse_devcontainer_build_based_config() {
        let (temp_dir, path) = write_devcontainer(
            r#"
            {
              build: {
                dockerfile: "Dockerfile",
                context: "..",
              },
            }
            "#,
        );

        let config = parse_devcontainer(&path).unwrap();
        let build = config.build.as_ref().unwrap();
        assert_eq!(
            build.dockerfile,
            temp_dir.path().join(".devcontainer").join("Dockerfile")
        );
        assert_eq!(
            build.context.as_ref(),
            Some(&temp_dir.path().join(".devcontainer").join(".."))
        );
        assert!(config.image.is_none());
    }

    #[test]
    fn parse_devcontainer_full_config() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              image: "mcr.microsoft.com/devcontainers/rust:1",
              build: {
                dockerfile: "Dockerfile",
                context: "..",
              },
              containerEnv: {
                RUST_LOG: "debug",
                CI: "1",
              },
              mounts: [
                "source=${localWorkspaceFolder}/cache,target=/tmp/cache,type=bind,readonly",
              ],
              postCreateCommand: ["cargo", "test"],
              onCreateCommand: {
                bootstrap: "scripts/bootstrap.sh",
                verify: ["cargo", "fmt", "--check"],
              },
              workspaceFolder: "/workspaces/strait",
              remoteUser: "vscode",
            }
            "#,
        );

        let config = parse_devcontainer(&path).unwrap();
        assert_eq!(
            config.image.as_deref(),
            Some("mcr.microsoft.com/devcontainers/rust:1")
        );
        assert_eq!(
            config.container_env.get("RUST_LOG").map(String::as_str),
            Some("debug")
        );
        assert_eq!(
            config.container_env.get("CI").map(String::as_str),
            Some("1")
        );
        assert_eq!(
            config.mounts,
            vec![
                "source=${localWorkspaceFolder}/cache,target=/tmp/cache,type=bind,readonly"
                    .to_string()
            ]
        );
        assert_eq!(
            config.post_create_command,
            Some(DevcontainerCommand::Exec(vec![
                "cargo".to_string(),
                "test".to_string(),
            ]))
        );
        assert_eq!(
            config.on_create_command,
            Some(DevcontainerCommand::Named(BTreeMap::from([
                (
                    "bootstrap".to_string(),
                    DevcontainerCommandStep::Shell("scripts/bootstrap.sh".to_string()),
                ),
                (
                    "verify".to_string(),
                    DevcontainerCommandStep::Exec(vec![
                        "cargo".to_string(),
                        "fmt".to_string(),
                        "--check".to_string(),
                    ]),
                ),
            ])))
        );
        assert_eq!(
            config.workspace_folder.as_deref(),
            Some("/workspaces/strait")
        );
        assert_eq!(config.remote_user.as_deref(), Some("vscode"));
    }

    #[test]
    fn parse_devcontainer_rejects_privileged_true() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              image: "ubuntu:24.04",
              privileged: true,
            }
            "#,
        );

        let err = parse_devcontainer(&path).unwrap_err().to_string();
        assert!(
            err.contains("privileged"),
            "error should name the field, got: {err}"
        );
        assert!(
            err.contains(DEVCONTAINER_STRATEGY_DOC),
            "error should point to the strategy doc, got: {err}"
        );
    }

    #[test]
    fn parse_devcontainer_rejects_cap_add() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              image: "ubuntu:24.04",
              capAdd: ["NET_ADMIN"],
            }
            "#,
        );

        let err = parse_devcontainer(&path).unwrap_err().to_string();
        assert!(
            err.contains("capAdd"),
            "error should name the field, got: {err}"
        );
    }

    #[test]
    fn parse_devcontainer_rejects_unsafe_run_args() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              image: "ubuntu:24.04",
              runArgs: ["--network=host"],
            }
            "#,
        );

        let err = parse_devcontainer(&path).unwrap_err().to_string();
        assert!(
            err.contains("runArgs"),
            "error should name the field, got: {err}"
        );
        assert!(
            err.contains("--network=host"),
            "error should name the value, got: {err}"
        );
    }

    #[test]
    fn parse_devcontainer_warns_on_forward_ports_and_preserves_mounts() {
        let (_temp_dir, path) = write_devcontainer(
            r#"
            {
              image: "ubuntu:24.04",
              forwardPorts: [3000],
              mounts: ["source=/tmp,target=/mnt,type=bind"],
            }
            "#,
        );

        let messages = Arc::new(Mutex::new(Vec::new()));
        let collector = WarnCollector {
            messages: messages.clone(),
        };
        let _guard = tracing::subscriber::set_default(collector);

        let config = parse_devcontainer(&path).unwrap();
        assert_eq!(config.image.as_deref(), Some("ubuntu:24.04"));
        assert_eq!(
            config.mounts,
            vec!["source=/tmp,target=/mnt,type=bind".to_string()]
        );

        let messages = messages.lock().unwrap();
        assert!(
            messages
                .iter()
                .any(|message| message.contains("forwardPorts")),
            "warning should mention forwardPorts, got: {:?}",
            *messages
        );
        assert!(
            messages.iter().all(|message| !message.contains("mounts")),
            "mounts should no longer be warned as ignored, got: {:?}",
            *messages
        );
    }
}
