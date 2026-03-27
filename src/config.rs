//! Unified TOML configuration and shared proxy context.
//!
//! All file parsing lives here. `strait.toml` is the single config file that
//! replaces the old CLI flags. The [`ProxyContext`] struct bundles every piece
//! of shared state that connection handlers need, replacing the previous 8+
//! positional parameters.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use serde::Deserialize;
use tracing::{error, info, warn};

use crate::audit::AuditLogger;
use crate::ca::SessionCa;
use crate::credentials::CredentialStore;
use crate::policy::PolicyEngine;

// ---------------------------------------------------------------------------
// TOML configuration types
// ---------------------------------------------------------------------------

/// Top-level configuration parsed from `strait.toml`.
#[derive(Debug, Deserialize, Clone)]
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

/// `[mitm]` section — which hosts to intercept.
#[derive(Debug, Deserialize, Clone)]
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
}

impl Default for MitmConfig {
    fn default() -> Self {
        Self {
            hosts: Vec::new(),
            max_body_size: DEFAULT_MAX_BODY_SIZE,
            keepalive_timeout_secs: DEFAULT_KEEPALIVE_TIMEOUT_SECS,
        }
    }
}

fn default_max_body_size() -> usize {
    DEFAULT_MAX_BODY_SIZE
}

fn default_keepalive_timeout_secs() -> u64 {
    DEFAULT_KEEPALIVE_TIMEOUT_SECS
}

/// `[policy]` section — Cedar policy source (local file or git repository).
///
/// Exactly one of `file` or `git_url` must be set:
/// - `file`: load a `.cedar` policy from a local path (no polling, no hot-reload).
/// - `git_url`: clone a git repository and load the policy from it. The repo is
///   polled at `poll_interval_secs` for changes and hot-reloaded atomically.
#[derive(Debug, Deserialize, Clone)]
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
pub struct AuditConfig {
    /// Path to an audit log file. If omitted, events are only written to stderr.
    pub log_path: Option<PathBuf>,
}

/// `[identity]` section — agent identity extraction from request headers.
#[derive(Debug, Deserialize, Clone)]
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
pub struct HealthConfig {
    /// Port for the health check endpoint (required when `[health]` is present).
    pub port: u16,
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

        Ok(Self {
            session_ca,
            policy_engine,
            credential_store,
            audit_logger,
            mitm_hosts: config.mitm.hosts.clone(),
            max_body_size: config.mitm.max_body_size,
            keepalive_timeout: Duration::from_secs(config.mitm.keepalive_timeout_secs),
            startup_instant: Instant::now(),
            identity_header: identity.header,
            identity_default: identity.default,
            git_policy,
            policy_config: config.policy.clone(),
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

/// Reload the policy from its configured source (file or git).
///
/// On success, atomically swaps the policy in `ProxyContext.policy_engine` via
/// [`ArcSwap`] and returns `Ok(())`. On failure, the previous policy is retained
/// and the error is returned (caller should log it).
///
/// This is called by the SIGHUP handler task and can also be used for
/// programmatic reload.
pub fn reload_policy(ctx: &ProxyContext) -> anyhow::Result<()> {
    let policy_config = ctx
        .policy_config
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no policy configured, nothing to reload"))?;

    let swap = ctx
        .policy_engine
        .as_ref()
        .ok_or_else(|| anyhow::anyhow!("no policy engine initialized, nothing to reload"))?;

    let new_engine = if let Some(git_state) = &ctx.git_policy {
        // Git mode: fetch latest, then reload from the local clone
        let repo_dir = &git_state.repo_dir;

        // Fetch from origin
        let fetch = std::process::Command::new("git")
            .args(["fetch", "origin", "--quiet"])
            .current_dir(repo_dir)
            .output()
            .context("failed to execute `git fetch`")?;

        if !fetch.status.success() {
            let stderr = String::from_utf8_lossy(&fetch.stderr);
            anyhow::bail!("git fetch failed: {}", stderr.trim());
        }

        // Reset to latest origin/HEAD
        let reset = std::process::Command::new("git")
            .args(["reset", "--hard", "origin/HEAD", "--quiet"])
            .current_dir(repo_dir)
            .output()
            .context("failed to execute `git reset`")?;

        if !reset.status.success() {
            let stderr = String::from_utf8_lossy(&reset.stderr);
            anyhow::bail!("git reset failed: {}", stderr.trim());
        }

        PolicyEngine::load(&git_state.policy_path, git_state.schema_path.as_deref())?
    } else if let Some(ref file) = policy_config.file {
        // File mode: re-read from disk
        PolicyEngine::load(file, policy_config.schema.as_deref())?
    } else {
        anyhow::bail!("policy configuration has no file or git source");
    };

    swap.store(Arc::new(new_engine));
    Ok(())
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
            Ok(Ok(())) => {
                info!("policy reloaded successfully via SIGHUP");
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
    use tempfile::NamedTempFile;

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
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
        reload_policy(&ctx).unwrap();

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
}
