//! Credential configuration: parse credentials.toml and resolve secrets at startup.
//!
//! The credentials file maps services to credential sources. Currently only
//! environment variable sources are supported (keychain is planned for later).
//!
//! Example `credentials.toml`:
//! ```toml
//! [[credential]]
//! host = "api.github.com"
//! header = "Authorization"
//! value_prefix = "token "
//! source = "env"
//! env_var = "GITHUB_TOKEN"
//! ```

use std::collections::HashMap;
use std::path::Path;

use anyhow::Context as _;
use serde::Deserialize;

/// Top-level credentials.toml structure.
#[derive(Debug, Deserialize)]
struct CredentialsFile {
    credential: Vec<CredentialEntry>,
}

/// A single credential entry from the TOML file.
#[derive(Debug, Deserialize)]
struct CredentialEntry {
    /// Hostname this credential applies to (e.g. "api.github.com").
    host: String,
    /// HTTP header name to inject (e.g. "Authorization").
    header: String,
    /// Prefix prepended to the resolved secret value (e.g. "token ").
    #[serde(default)]
    value_prefix: String,
    /// Source type. Currently only "env" is supported.
    source: String,
    /// Environment variable name (required when source = "env").
    env_var: Option<String>,
}

/// A resolved credential ready for injection.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    /// HTTP header name (e.g. "Authorization").
    pub header: String,
    /// Full header value including prefix (e.g. "token ghp_abc123").
    pub value: String,
}

/// Holds all resolved credentials, keyed by hostname.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    /// Map from hostname to resolved credential.
    credentials: HashMap<String, ResolvedCredential>,
}

impl CredentialStore {
    /// Load and resolve credentials from a TOML file.
    ///
    /// All credential sources (env vars) are resolved eagerly at startup.
    /// Returns an error if the file is missing/invalid or any env var is not set.
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read credentials file: {}", path.display()))?;

        let file: CredentialsFile = toml::from_str(&text)
            .with_context(|| format!("invalid credentials.toml: {}", path.display()))?;

        let mut credentials = HashMap::new();

        for entry in file.credential {
            let resolved = resolve_entry(&entry)?;
            credentials.insert(entry.host.clone(), resolved);
        }

        Ok(Self { credentials })
    }

    /// Look up the credential for a given hostname.
    pub fn get(&self, host: &str) -> Option<&ResolvedCredential> {
        self.credentials.get(host)
    }
}

/// Resolve a single credential entry, reading the secret from its source.
fn resolve_entry(entry: &CredentialEntry) -> anyhow::Result<ResolvedCredential> {
    match entry.source.as_str() {
        "env" => {
            let var_name = entry.env_var.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "credential for host '{}': source is 'env' but 'env_var' is missing",
                    entry.host
                )
            })?;

            let secret = std::env::var(var_name).with_context(|| {
                format!(
                    "credential for host '{}': environment variable '{}' is not set",
                    entry.host, var_name
                )
            })?;

            let value = format!("{}{}", entry.value_prefix, secret);

            Ok(ResolvedCredential {
                header: entry.header.clone(),
                value,
            })
        }
        other => anyhow::bail!(
            "credential for host '{}': unsupported source type '{}' (only 'env' is supported)",
            entry.host,
            other
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_toml(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn load_valid_credentials() {
        // Set the env var for the test
        std::env::set_var("STRAIT_TEST_TOKEN_1", "ghp_test123");

        let f = write_toml(
            r#"
[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "STRAIT_TEST_TOKEN_1"
"#,
        );

        let store = CredentialStore::load(f.path()).unwrap();
        let cred = store.get("api.github.com").unwrap();
        assert_eq!(cred.header, "Authorization");
        assert_eq!(cred.value, "token ghp_test123");

        std::env::remove_var("STRAIT_TEST_TOKEN_1");
    }

    #[test]
    fn missing_env_var_fails_at_load() {
        // Make sure the var is NOT set
        std::env::remove_var("STRAIT_TEST_NONEXISTENT_VAR");

        let f = write_toml(
            r#"
[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "STRAIT_TEST_NONEXISTENT_VAR"
"#,
        );

        let result = CredentialStore::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("STRAIT_TEST_NONEXISTENT_VAR"),
            "error should mention the env var, got: {err}"
        );
        assert!(
            err.contains("not set"),
            "error should say 'not set', got: {err}"
        );
    }

    #[test]
    fn missing_credentials_file() {
        let result = CredentialStore::load(Path::new("/nonexistent/credentials.toml"));
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("failed to read credentials file"),
            "got: {err}"
        );
    }

    #[test]
    fn invalid_toml_fails() {
        let f = write_toml("this is not valid toml {{{}}}");
        let result = CredentialStore::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("invalid credentials.toml"), "got: {err}");
    }

    #[test]
    fn unsupported_source_type() {
        std::env::set_var("STRAIT_TEST_TOKEN_2", "test");

        let f = write_toml(
            r#"
[[credential]]
host = "api.github.com"
header = "Authorization"
source = "keychain"
"#,
        );

        let result = CredentialStore::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported source type"), "got: {err}");

        std::env::remove_var("STRAIT_TEST_TOKEN_2");
    }

    #[test]
    fn no_credential_for_unknown_host() {
        std::env::set_var("STRAIT_TEST_TOKEN_3", "test");

        let f = write_toml(
            r#"
[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "STRAIT_TEST_TOKEN_3"
"#,
        );

        let store = CredentialStore::load(f.path()).unwrap();
        assert!(store.get("example.com").is_none());

        std::env::remove_var("STRAIT_TEST_TOKEN_3");
    }

    #[test]
    fn env_var_field_missing_with_env_source() {
        let f = write_toml(
            r#"
[[credential]]
host = "api.github.com"
header = "Authorization"
source = "env"
"#,
        );

        let result = CredentialStore::load(f.path());
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("env_var"),
            "error should mention missing env_var, got: {err}"
        );
    }
}
