//! Credential store: runtime types, secret resolution, and AWS host parsing.
//!
//! The TOML parsing for credential entries lives in [`crate::config`]. This
//! module keeps only the runtime types ([`CredentialStore`],
//! [`ResolvedCredential`]) and the [`resolve_entry`] logic that reads secrets
//! from their sources (currently only environment variables).
//!
//! ## Lookup priority
//!
//! [`CredentialStore::get`] uses a two-tier lookup:
//! 1. **Exact match** — `host = "api.github.com"` matches only that hostname.
//! 2. **Pattern match** — `host_pattern = "*.amazonaws.com"` matches any
//!    hostname ending in `.amazonaws.com`.
//!
//! Exact matches always win over pattern matches.
//!
//! ## AWS host parsing
//!
//! [`parse_aws_host`] extracts service and region from standard AWS endpoint
//! hostnames (`<service>.<region>.amazonaws.com`). This enables a single
//! `host_pattern = "*.amazonaws.com"` credential entry to cover all AWS
//! services.
//!
//! Example credential entries in `strait.toml`:
//! ```toml
//! [[credential]]
//! host = "api.github.com"
//! header = "Authorization"
//! value_prefix = "token "
//! source = "env"
//! env_var = "GITHUB_TOKEN"
//!
//! [[credential]]
//! host_pattern = "*.amazonaws.com"
//! header = "Authorization"
//! source = "env"
//! env_var = "AWS_SECRET_ACCESS_KEY"
//! ```

use std::collections::HashMap;

use anyhow::Context as _;

use crate::config::CredentialEntryConfig;

// ---------------------------------------------------------------------------
// AWS host parsing
// ---------------------------------------------------------------------------

/// Extracted service and region from an AWS hostname.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsHostInfo {
    /// AWS service name (e.g. `"s3"`, `"lambda"`, `"iam"`).
    pub service: String,
    /// AWS region, if present. `None` for global endpoints like `iam.amazonaws.com`.
    pub region: Option<String>,
}

/// Parse an AWS hostname into its service and region components.
///
/// Recognises standard AWS endpoint formats:
/// - `<service>.<region>.amazonaws.com` (regional, e.g. `s3.us-east-1.amazonaws.com`)
/// - `<service>.amazonaws.com` (global, e.g. `iam.amazonaws.com`)
/// - `<prefix>.<service>.<region>.amazonaws.com` (virtual-hosted, e.g.
///   `bucket.s3.us-east-1.amazonaws.com` — returns service `s3`, region `us-east-1`)
///
/// Returns `None` for non-AWS hostnames, bare `amazonaws.com`, and look-alikes
/// like `notamazonaws.com`.
pub fn parse_aws_host(host: &str) -> Option<AwsHostInfo> {
    let suffix = ".amazonaws.com";
    if !host.ends_with(suffix) {
        return None;
    }

    let prefix = &host[..host.len() - suffix.len()];
    if prefix.is_empty() {
        // Bare "amazonaws.com" (after stripping the dot-prefix, this catches
        // hosts that are exactly ".amazonaws.com" which can't happen, but also
        // guards the split below).
        return None;
    }

    let parts: Vec<&str> = prefix.split('.').collect();
    match parts.len() {
        // <service>.amazonaws.com — global endpoint
        1 => Some(AwsHostInfo {
            service: parts[0].to_string(),
            region: None,
        }),
        // <service>.<region>.amazonaws.com — standard regional
        2 => Some(AwsHostInfo {
            service: parts[0].to_string(),
            region: Some(parts[1].to_string()),
        }),
        // <prefix>.<service>.<region>.amazonaws.com — virtual-hosted style
        // Take the last two segments as service and region.
        n if n >= 3 => {
            let service = parts[n - 2].to_string();
            let region = parts[n - 1].to_string();
            Some(AwsHostInfo {
                service,
                region: Some(region),
            })
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Credential types
// ---------------------------------------------------------------------------

/// A resolved credential ready for injection.
#[derive(Debug, Clone)]
pub struct ResolvedCredential {
    /// HTTP header name (e.g. "Authorization").
    pub header: String,
    /// Full header value including prefix (e.g. "token ghp_abc123").
    pub value: String,
}

/// Holds all resolved credentials, keyed by hostname or hostname pattern.
///
/// Lookup priority: exact hostname match first, then pattern-based fallback.
#[derive(Debug, Clone)]
pub struct CredentialStore {
    /// Map from exact hostname to resolved credential.
    exact: HashMap<String, ResolvedCredential>,
    /// Pattern-based credentials: `(glob_pattern, credential)`.
    patterns: Vec<(String, ResolvedCredential)>,
}

impl CredentialStore {
    /// Build a credential store from parsed config entries.
    ///
    /// All credential sources (env vars) are resolved eagerly at startup.
    /// Returns an error if any env var is not set, a source type is
    /// unsupported, or a credential entry has invalid host/host_pattern fields.
    pub fn from_entries(entries: &[CredentialEntryConfig]) -> anyhow::Result<Self> {
        let mut exact = HashMap::new();
        let mut patterns = Vec::new();

        for entry in entries {
            // Validate host/host_pattern before resolving secrets
            match (&entry.host, &entry.host_pattern) {
                (Some(_), None) | (None, Some(_)) => {}
                (Some(_), Some(_)) => {
                    anyhow::bail!(
                        "credential entry for '{}': has both 'host' and 'host_pattern'; use only one",
                        entry_identifier(entry)
                    );
                }
                (None, None) => {
                    anyhow::bail!("credential entry must have either 'host' or 'host_pattern'");
                }
            }

            let resolved = resolve_entry(entry)?;

            match (&entry.host, &entry.host_pattern) {
                (Some(host), None) => {
                    exact.insert(host.clone(), resolved);
                }
                (None, Some(pattern)) => {
                    patterns.push((pattern.clone(), resolved));
                }
                _ => unreachable!("validated above"),
            }
        }

        Ok(Self { exact, patterns })
    }

    /// Look up the credential for a given hostname.
    ///
    /// Returns the exact-match credential if one exists, otherwise falls back
    /// to the first matching pattern entry.
    pub fn get(&self, host: &str) -> Option<&ResolvedCredential> {
        // Exact match takes priority
        if let Some(cred) = self.exact.get(host) {
            return Some(cred);
        }

        // Pattern match fallback
        for (pattern, cred) in &self.patterns {
            if host_matches_pattern(host, pattern) {
                return Some(cred);
            }
        }

        None
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Return a human-readable identifier for a credential entry (for error messages).
fn entry_identifier(entry: &CredentialEntryConfig) -> &str {
    entry
        .host
        .as_deref()
        .or(entry.host_pattern.as_deref())
        .unwrap_or("<unknown>")
}

/// Check if a hostname matches a glob pattern.
///
/// Supports:
/// - `*.suffix` — matches any host ending in `.suffix` (but not `suffix` itself)
/// - Exact string match as fallback for patterns without wildcards
fn host_matches_pattern(host: &str, pattern: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // *.amazonaws.com matches s3.us-east-1.amazonaws.com
        // but NOT bare "amazonaws.com"
        host.ends_with(suffix)
            && host.len() > suffix.len()
            && host.as_bytes()[host.len() - suffix.len() - 1] == b'.'
    } else {
        host == pattern
    }
}

/// Resolve a single credential entry, reading the secret from its source.
fn resolve_entry(entry: &CredentialEntryConfig) -> anyhow::Result<ResolvedCredential> {
    let id = entry_identifier(entry);

    match entry.source.as_str() {
        "env" => {
            let var_name = entry.env_var.as_deref().ok_or_else(|| {
                anyhow::anyhow!(
                    "credential for '{}': source is 'env' but 'env_var' is missing",
                    id
                )
            })?;

            let secret = std::env::var(var_name).with_context(|| {
                format!(
                    "credential for '{}': environment variable '{}' is not set",
                    id, var_name
                )
            })?;

            let value = format!("{}{}", entry.value_prefix, secret);

            Ok(ResolvedCredential {
                header: entry.header.clone(),
                value,
            })
        }
        other => anyhow::bail!(
            "credential for '{}': unsupported source type '{}' (only 'env' is supported)",
            id,
            other
        ),
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helper ---

    fn entry(
        host: &str,
        header: &str,
        prefix: &str,
        source: &str,
        env_var: Option<&str>,
    ) -> CredentialEntryConfig {
        CredentialEntryConfig {
            host: Some(host.to_string()),
            host_pattern: None,
            header: header.to_string(),
            value_prefix: prefix.to_string(),
            source: source.to_string(),
            env_var: env_var.map(|s| s.to_string()),
        }
    }

    fn pattern_entry(
        host_pattern: &str,
        header: &str,
        prefix: &str,
        source: &str,
        env_var: Option<&str>,
    ) -> CredentialEntryConfig {
        CredentialEntryConfig {
            host: None,
            host_pattern: Some(host_pattern.to_string()),
            header: header.to_string(),
            value_prefix: prefix.to_string(),
            source: source.to_string(),
            env_var: env_var.map(|s| s.to_string()),
        }
    }

    // -----------------------------------------------------------------------
    // parse_aws_host tests
    // -----------------------------------------------------------------------

    #[test]
    fn parse_aws_host_s3_regional() {
        let info = parse_aws_host("s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_lambda() {
        let info = parse_aws_host("lambda.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "lambda");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_sqs() {
        let info = parse_aws_host("sqs.us-west-2.amazonaws.com").unwrap();
        assert_eq!(info.service, "sqs");
        assert_eq!(info.region, Some("us-west-2".to_string()));
    }

    #[test]
    fn parse_aws_host_dynamodb() {
        let info = parse_aws_host("dynamodb.eu-west-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "dynamodb");
        assert_eq!(info.region, Some("eu-west-1".to_string()));
    }

    #[test]
    fn parse_aws_host_global_iam() {
        let info = parse_aws_host("iam.amazonaws.com").unwrap();
        assert_eq!(info.service, "iam");
        assert_eq!(info.region, None);
    }

    #[test]
    fn parse_aws_host_global_sts() {
        let info = parse_aws_host("sts.amazonaws.com").unwrap();
        assert_eq!(info.service, "sts");
        assert_eq!(info.region, None);
    }

    #[test]
    fn parse_aws_host_virtual_hosted_s3() {
        // bucket.s3.us-east-1.amazonaws.com — virtual-hosted S3
        let info = parse_aws_host("bucket.s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_non_aws_returns_none() {
        assert!(parse_aws_host("api.github.com").is_none());
        assert!(parse_aws_host("example.com").is_none());
        assert!(parse_aws_host("google.com").is_none());
    }

    #[test]
    fn parse_aws_host_notamazonaws_returns_none() {
        // "notamazonaws.com" does NOT end with ".amazonaws.com"
        assert!(parse_aws_host("notamazonaws.com").is_none());
    }

    #[test]
    fn parse_aws_host_bare_amazonaws_returns_none() {
        // bare "amazonaws.com" — no service prefix
        assert!(parse_aws_host("amazonaws.com").is_none());
    }

    #[test]
    fn parse_aws_host_deep_subdomain() {
        // deep.nested.s3.us-east-1.amazonaws.com
        let info = parse_aws_host("deep.nested.s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    // -----------------------------------------------------------------------
    // Existing credential store tests (updated for Option<String> host)
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Pattern matching tests
    // -----------------------------------------------------------------------

    #[test]
    fn pattern_match_amazonaws_wildcard() {
        std::env::set_var("STRAIT_TEST_AWS_1", "aws_secret");

        let entries = vec![pattern_entry(
            "*.amazonaws.com",
            "Authorization",
            "",
            "env",
            Some("STRAIT_TEST_AWS_1"),
        )];

        let store = CredentialStore::from_entries(&entries).unwrap();

        // Various AWS hosts should match the pattern
        assert!(
            store.get("s3.us-east-1.amazonaws.com").is_some(),
            "S3 regional should match"
        );
        assert!(
            store.get("lambda.us-east-1.amazonaws.com").is_some(),
            "Lambda should match"
        );
        assert!(
            store.get("iam.amazonaws.com").is_some(),
            "IAM global should match"
        );
        assert!(
            store.get("bucket.s3.us-east-1.amazonaws.com").is_some(),
            "Virtual-hosted S3 should match"
        );

        // Non-AWS hosts should NOT match
        assert!(
            store.get("api.github.com").is_none(),
            "GitHub should not match AWS pattern"
        );
        assert!(
            store.get("example.com").is_none(),
            "example.com should not match"
        );
        assert!(
            store.get("notamazonaws.com").is_none(),
            "notamazonaws.com should not match"
        );
        assert!(
            store.get("amazonaws.com").is_none(),
            "bare amazonaws.com should not match *.amazonaws.com"
        );

        std::env::remove_var("STRAIT_TEST_AWS_1");
    }

    #[test]
    fn exact_match_wins_over_pattern() {
        std::env::set_var("STRAIT_TEST_AWS_EXACT", "exact_secret");
        std::env::set_var("STRAIT_TEST_AWS_PATTERN", "pattern_secret");

        let entries = vec![
            entry(
                "s3.us-east-1.amazonaws.com",
                "Authorization",
                "exact:",
                "env",
                Some("STRAIT_TEST_AWS_EXACT"),
            ),
            pattern_entry(
                "*.amazonaws.com",
                "Authorization",
                "pattern:",
                "env",
                Some("STRAIT_TEST_AWS_PATTERN"),
            ),
        ];

        let store = CredentialStore::from_entries(&entries).unwrap();

        // Exact match should win for s3.us-east-1
        let cred = store.get("s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(cred.value, "exact:exact_secret");

        // Other AWS hosts fall back to pattern
        let cred = store.get("lambda.us-east-1.amazonaws.com").unwrap();
        assert_eq!(cred.value, "pattern:pattern_secret");

        std::env::remove_var("STRAIT_TEST_AWS_EXACT");
        std::env::remove_var("STRAIT_TEST_AWS_PATTERN");
    }

    #[test]
    fn non_aws_hosts_unaffected_by_pattern() {
        std::env::set_var("STRAIT_TEST_GH_ONLY", "gh_token");
        std::env::set_var("STRAIT_TEST_AWS_ONLY", "aws_key");

        let entries = vec![
            entry(
                "api.github.com",
                "Authorization",
                "token ",
                "env",
                Some("STRAIT_TEST_GH_ONLY"),
            ),
            pattern_entry(
                "*.amazonaws.com",
                "Authorization",
                "",
                "env",
                Some("STRAIT_TEST_AWS_ONLY"),
            ),
        ];

        let store = CredentialStore::from_entries(&entries).unwrap();

        // GitHub exact match works
        let cred = store.get("api.github.com").unwrap();
        assert_eq!(cred.value, "token gh_token");

        // Random non-AWS host has no credential
        assert!(store.get("api.stripe.com").is_none());

        std::env::remove_var("STRAIT_TEST_GH_ONLY");
        std::env::remove_var("STRAIT_TEST_AWS_ONLY");
    }

    #[test]
    fn both_host_and_pattern_is_error() {
        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: Some("*.github.com".to_string()),
            header: "Authorization".to_string(),
            value_prefix: String::new(),
            source: "env".to_string(),
            env_var: Some("IRRELEVANT".to_string()),
        }];

        let result = CredentialStore::from_entries(&entries);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("both 'host' and 'host_pattern'"), "got: {err}");
    }

    #[test]
    fn neither_host_nor_pattern_is_error() {
        let entries = vec![CredentialEntryConfig {
            host: None,
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: String::new(),
            source: "env".to_string(),
            env_var: Some("IRRELEVANT".to_string()),
        }];

        let result = CredentialStore::from_entries(&entries);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("must have either 'host' or 'host_pattern'"),
            "got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // host_matches_pattern unit tests
    // -----------------------------------------------------------------------

    #[test]
    fn pattern_wildcard_suffix_matches() {
        assert!(host_matches_pattern(
            "s3.us-east-1.amazonaws.com",
            "*.amazonaws.com"
        ));
        assert!(host_matches_pattern("iam.amazonaws.com", "*.amazonaws.com"));
    }

    #[test]
    fn pattern_wildcard_does_not_match_bare_suffix() {
        assert!(!host_matches_pattern("amazonaws.com", "*.amazonaws.com"));
    }

    #[test]
    fn pattern_exact_fallback() {
        assert!(host_matches_pattern("example.com", "example.com"));
        assert!(!host_matches_pattern("other.com", "example.com"));
    }

    #[test]
    fn pattern_wildcard_does_not_match_embedded() {
        // "notamazonaws.com" ends with "amazonaws.com" but not ".amazonaws.com"
        assert!(!host_matches_pattern("notamazonaws.com", "*.amazonaws.com"));
    }
}
