//! Unified TOML configuration and shared proxy context.
//!
//! All file parsing lives here. `strait.toml` is the single config file that
//! replaces the old CLI flags. The [`ProxyContext`] struct bundles every piece
//! of shared state that connection handlers need, replacing the previous 8+
//! positional parameters.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use serde::Deserialize;
use tracing::info;

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

/// `[mitm]` section — which hosts to intercept.
#[derive(Debug, Deserialize, Clone, Default)]
pub struct MitmConfig {
    /// Hostnames that should be MITM'd for policy inspection.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// `[policy]` section — path to a Cedar policy file and optional schema.
#[derive(Debug, Deserialize, Clone)]
pub struct PolicyConfig {
    /// Path to a `.cedar` policy file.
    pub path: PathBuf,
    /// Optional path to a `.cedarschema` file for policy validation at startup.
    pub schema: Option<PathBuf>,
}

/// `[[credential]]` array entry — a single credential for header injection.
#[derive(Debug, Deserialize, Clone)]
pub struct CredentialEntryConfig {
    /// Hostname this credential applies to (e.g. `"api.github.com"`).
    pub host: String,
    /// HTTP header name to inject (e.g. `"Authorization"`).
    pub header: String,
    /// Prefix prepended to the resolved secret value (e.g. `"token "`).
    #[serde(default)]
    pub value_prefix: String,
    /// Source type. Currently only `"env"` is supported.
    pub source: String,
    /// Environment variable name (required when `source = "env"`).
    pub env_var: Option<String>,
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

/// All shared state needed by connection handlers.
///
/// Built once at startup from [`StraitConfig`] and passed (via `Arc`) to every
/// spawned connection task, replacing the previous 8+ positional parameters.
pub struct ProxyContext {
    /// Session-local CA for issuing per-host leaf certificates.
    pub session_ca: SessionCa,
    /// Cedar policy engine (if a policy file is configured).
    pub policy_engine: Option<Arc<PolicyEngine>>,
    /// Credential store for header injection (if credentials are configured).
    pub credential_store: Option<Arc<CredentialStore>>,
    /// Structured JSON audit logger.
    pub audit_logger: Arc<AuditLogger>,
    /// Hostnames that should be MITM'd for policy inspection.
    pub mitm_hosts: Vec<String>,
    /// Instant when the proxy context was created (for uptime calculation).
    pub startup_instant: Instant,
    /// HTTP header name to extract agent identity from.
    pub identity_header: String,
    /// Default agent identity when the identity header is absent.
    pub identity_default: String,
}

impl ProxyContext {
    /// Build a [`ProxyContext`] from a parsed [`StraitConfig`].
    ///
    /// This generates the session CA, loads the Cedar policy file, resolves
    /// credentials, and initializes the audit logger.
    pub fn from_config(config: &StraitConfig) -> anyhow::Result<Self> {
        // Generate session CA
        let session_ca = SessionCa::generate()?;
        info!("session CA generated");

        // Load Cedar policy (if configured)
        let policy_engine = match &config.policy {
            Some(policy_config) => {
                let engine =
                    PolicyEngine::load(&policy_config.path, policy_config.schema.as_deref())?;
                info!(path = %policy_config.path.display(), "Cedar policy loaded");
                Some(Arc::new(engine))
            }
            None => None,
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
            startup_instant: Instant::now(),
            identity_header: identity.header,
            identity_default: identity.default,
        })
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
path = "policy.cedar"

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
            config.policy.as_ref().unwrap().path,
            PathBuf::from("policy.cedar")
        );
        assert_eq!(config.credential.len(), 1);
        assert_eq!(config.credential[0].host, "api.github.com");
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
        assert_eq!(cred.header, "Authorization");
        assert_eq!(cred.value, "token ghp_test");

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
        assert_eq!(config.mitm.hosts, vec!["api.github.com"]);
        assert!(config.policy.is_some());
        assert_eq!(config.credential.len(), 1);
        assert_eq!(config.credential[0].host, "api.github.com");
        assert_eq!(config.health.as_ref().unwrap().port, 9090);
    }
}
