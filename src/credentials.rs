//! Credential store: runtime types and secret resolution.
//!
//! The TOML parsing for credential entries lives in [`crate::config`]. This
//! module keeps only the runtime types ([`CredentialStore`],
//! [`ResolvedCredential`]) and the [`resolve_entry`] logic that reads secrets
//! from their sources (currently only environment variables).
//!
//! Example credential entry in `strait.toml`:
//! ```toml
//! [[credential]]
//! host = "api.github.com"
//! header = "Authorization"
//! value_prefix = "token "
//! source = "env"
//! env_var = "GITHUB_TOKEN"
//! ```

use std::collections::HashMap;

use anyhow::Context as _;

use crate::config::CredentialEntryConfig;

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
    /// Build a credential store from parsed config entries.
    ///
    /// All credential sources (env vars) are resolved eagerly at startup.
    /// Returns an error if any env var is not set or a source type is unsupported.
    pub fn from_entries(entries: &[CredentialEntryConfig]) -> anyhow::Result<Self> {
        let mut credentials = HashMap::new();

        for entry in entries {
            let resolved = resolve_entry(entry)?;
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
fn resolve_entry(entry: &CredentialEntryConfig) -> anyhow::Result<ResolvedCredential> {
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

    fn entry(
        host: &str,
        header: &str,
        prefix: &str,
        source: &str,
        env_var: Option<&str>,
    ) -> CredentialEntryConfig {
        CredentialEntryConfig {
            host: host.to_string(),
            header: header.to_string(),
            value_prefix: prefix.to_string(),
            source: source.to_string(),
            env_var: env_var.map(|s| s.to_string()),
        }
    }

    #[test]
    fn from_entries_resolves_env_var() {
        std::env::set_var("STRAIT_TEST_TOKEN_1", "ghp_test123");

        let entries = vec![entry(
            "api.github.com",
            "Authorization",
            "token ",
            "env",
            Some("STRAIT_TEST_TOKEN_1"),
        )];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let cred = store.get("api.github.com").unwrap();
        assert_eq!(cred.header, "Authorization");
        assert_eq!(cred.value, "token ghp_test123");

        std::env::remove_var("STRAIT_TEST_TOKEN_1");
    }

    #[test]
    fn missing_env_var_fails() {
        std::env::remove_var("STRAIT_TEST_NONEXISTENT_VAR");

        let entries = vec![entry(
            "api.github.com",
            "Authorization",
            "token ",
            "env",
            Some("STRAIT_TEST_NONEXISTENT_VAR"),
        )];

        let result = CredentialStore::from_entries(&entries);
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
    fn unsupported_source_type() {
        let entries = vec![entry(
            "api.github.com",
            "Authorization",
            "",
            "keychain",
            None,
        )];

        let result = CredentialStore::from_entries(&entries);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported source type"), "got: {err}");
    }

    #[test]
    fn no_credential_for_unknown_host() {
        std::env::set_var("STRAIT_TEST_TOKEN_3", "test");

        let entries = vec![entry(
            "api.github.com",
            "Authorization",
            "token ",
            "env",
            Some("STRAIT_TEST_TOKEN_3"),
        )];

        let store = CredentialStore::from_entries(&entries).unwrap();
        assert!(store.get("example.com").is_none());

        std::env::remove_var("STRAIT_TEST_TOKEN_3");
    }

    #[test]
    fn env_var_field_missing_with_env_source() {
        let entries = vec![entry("api.github.com", "Authorization", "", "env", None)];

        let result = CredentialStore::from_entries(&entries);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("env_var"),
            "error should mention missing env_var, got: {err}"
        );
    }
}
