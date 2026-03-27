//! Credential store: runtime types, trait abstraction, secret resolution, and AWS host parsing.
//!
//! The TOML parsing for credential entries lives in [`crate::config`]. This
//! module keeps the runtime types ([`CredentialStore`], [`BearerCredential`]),
//! the [`Credential`] trait, and the [`resolve_entry`] logic that reads secrets
//! from their sources (currently only environment variables).
//!
//! The [`Credential`] trait abstracts over different authentication methods.
//! Each implementation knows how to produce the HTTP headers needed for its
//! auth scheme. `BearerCredential` injects a single static header/value pair.
//! Future implementations (e.g. SigV4) can inspect method, path, headers, and
//! body to compute a signature.
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
//! [`parse_aws_host`] extracts service and region from AWS endpoint hostnames
//! across all partitions (standard, China, GovCloud). It handles dualstack,
//! FIPS, VPC, and virtual-hosted endpoint variants. This enables a single
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
use std::fmt::Debug;

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

/// Known qualifier segments that appear in AWS endpoint hostnames but are
/// neither service names nor region names.  These are filtered out before
/// extracting service and region.
const AWS_HOST_QUALIFIERS: &[&str] = &["dualstack", "fips", "vpce"];

/// Parse an AWS hostname into its service and region components.
///
/// Recognises standard AWS endpoint formats across all partitions:
///
/// | Format | Example |
/// |--------|---------|
/// | `<service>.<region>.amazonaws.com` | `s3.us-east-1.amazonaws.com` |
/// | `<service>.amazonaws.com` (global) | `iam.amazonaws.com` |
/// | `<service>.dualstack.<region>.amazonaws.com` | `s3.dualstack.us-east-1.amazonaws.com` |
/// | `<service>-fips.<region>.amazonaws.com` | `s3-fips.us-east-1.amazonaws.com` |
/// | `<prefix>.<service>.<region>.amazonaws.com` | `bucket.s3.us-east-1.amazonaws.com` |
/// | `<service>.<region>.amazonaws.com.cn` (China) | `dynamodb.cn-north-1.amazonaws.com.cn` |
///
/// Known qualifier segments (`dualstack`, `fips`, `vpce`) are skipped.
/// A `-fips` suffix on the service segment is stripped (e.g. `s3-fips` → `s3`).
/// GovCloud regions (e.g. `us-gov-west-1`) use the standard `.amazonaws.com`
/// suffix and are handled automatically.
///
/// Returns `None` for non-AWS hostnames, bare `amazonaws.com`, and look-alikes
/// like `notamazonaws.com`.
pub fn parse_aws_host(host: &str) -> Option<AwsHostInfo> {
    // Recognise AWS hostname suffixes for different partitions.
    // Check the longer suffix first so `.amazonaws.com` doesn't partially
    // match a `.amazonaws.com.cn` hostname.
    let prefix = if let Some(p) = host.strip_suffix(".amazonaws.com.cn") {
        p
    } else if let Some(p) = host.strip_suffix(".amazonaws.com") {
        p
    } else {
        return None;
    };

    if prefix.is_empty() {
        return None;
    }

    let parts: Vec<&str> = prefix.split('.').collect();

    // Filter out known qualifier segments (dualstack, fips, vpce).
    let meaningful: Vec<&str> = parts
        .iter()
        .filter(|s| !AWS_HOST_QUALIFIERS.contains(s))
        .copied()
        .collect();

    match meaningful.len() {
        0 => None,
        // <service>.amazonaws.com — global endpoint
        1 => Some(AwsHostInfo {
            service: strip_service_qualifier(meaningful[0]),
            region: None,
        }),
        // <service>.<region>.amazonaws.com — standard regional
        2 => Some(AwsHostInfo {
            service: strip_service_qualifier(meaningful[0]),
            region: Some(meaningful[1].to_string()),
        }),
        // <prefix>.<service>.<region>.amazonaws.com — virtual-hosted style
        // Take the last two meaningful segments as service and region.
        n => {
            let service = strip_service_qualifier(meaningful[n - 2]);
            let region = meaningful[n - 1].to_string();
            Some(AwsHostInfo {
                service,
                region: Some(region),
            })
        }
    }
}

/// Strip known qualifier suffixes from an AWS service name.
///
/// Currently handles `-fips` (e.g. `s3-fips` → `s3`).
fn strip_service_qualifier(service: &str) -> String {
    service.strip_suffix("-fips").unwrap_or(service).to_string()
}

// ---------------------------------------------------------------------------
// Credential trait and implementations
// ---------------------------------------------------------------------------

/// Trait for credential injection into HTTP requests.
///
/// Each implementation produces the HTTP headers needed to authenticate a
/// request. The caller is responsible for removing any existing headers with
/// the same names before injecting the returned headers.
pub trait Credential: Debug + Send + Sync {
    /// Returns the headers to inject for this credential, or `None` if the
    /// credential does not apply to this request.
    fn inject(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Option<Vec<(String, String)>>;
}

/// A bearer-token credential that injects a single header with a static value.
///
/// This is the simplest credential type: it always returns the same
/// header/value pair regardless of the request contents.
#[derive(Clone)]
pub struct BearerCredential {
    /// HTTP header name (e.g. "Authorization").
    pub header: String,
    /// Full header value including prefix (e.g. "token ghp_abc123").
    pub value: String,
}

impl std::fmt::Debug for BearerCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BearerCredential")
            .field("header", &self.header)
            .field("value", &"***")
            .finish()
    }
}

impl Credential for BearerCredential {
    fn inject(
        &self,
        _method: &str,
        _path: &str,
        _headers: &[(String, String)],
        _body: Option<&[u8]>,
    ) -> Option<Vec<(String, String)>> {
        Some(vec![(self.header.clone(), self.value.clone())])
    }
}

// ---------------------------------------------------------------------------
// Credential store
// ---------------------------------------------------------------------------

/// Holds all resolved credentials, keyed by hostname or hostname pattern.
///
/// Lookup priority: exact hostname match first, then pattern-based fallback.
#[derive(Debug)]
pub struct CredentialStore {
    /// Map from exact hostname to resolved credential.
    exact: HashMap<String, Box<dyn Credential>>,
    /// Pattern-based credentials: `(glob_pattern, credential)`.
    patterns: Vec<(String, Box<dyn Credential>)>,
}

impl CredentialStore {
    /// Build a credential store from parsed config entries.
    ///
    /// All credential sources (env vars) are resolved eagerly at startup.
    /// Returns an error if any env var is not set, a source type is
    /// unsupported, or a credential entry has invalid host/host_pattern fields.
    pub fn from_entries(entries: &[CredentialEntryConfig]) -> anyhow::Result<Self> {
        let mut exact: HashMap<String, Box<dyn Credential>> = HashMap::new();
        let mut patterns: Vec<(String, Box<dyn Credential>)> = Vec::new();

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
    pub fn get(&self, host: &str) -> Option<&dyn Credential> {
        // Exact match takes priority
        if let Some(cred) = self.exact.get(host) {
            return Some(cred.as_ref());
        }

        // Pattern match fallback
        for (pattern, cred) in &self.patterns {
            if host_matches_pattern(host, pattern) {
                return Some(cred.as_ref());
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
fn resolve_entry(entry: &CredentialEntryConfig) -> anyhow::Result<Box<dyn Credential>> {
    match entry.credential_type.as_str() {
        "bearer" => resolve_bearer(entry),
        "aws-sigv4" => resolve_sigv4(entry),
        other => anyhow::bail!(
            "credential for '{}': unsupported credential type '{}' (supported: 'bearer', 'aws-sigv4')",
            entry_identifier(entry),
            other
        ),
    }
}

/// Resolve a bearer-token credential entry.
fn resolve_bearer(entry: &CredentialEntryConfig) -> anyhow::Result<Box<dyn Credential>> {
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

            Ok(Box::new(BearerCredential {
                header: entry.header.clone(),
                value,
            }))
        }
        other => anyhow::bail!(
            "credential for '{}': unsupported source type '{}' (only 'env' is supported)",
            id,
            other
        ),
    }
}

/// Resolve an AWS SigV4 credential entry.
///
/// Reads the access key, secret key, and optional session token from
/// environment variables. The env var names default to the standard
/// AWS SDK names but can be overridden in the config.
fn resolve_sigv4(entry: &CredentialEntryConfig) -> anyhow::Result<Box<dyn Credential>> {
    let id = entry_identifier(entry);

    if entry.source != "env" {
        anyhow::bail!(
            "credential for '{}': aws-sigv4 only supports source 'env', got '{}'",
            id,
            entry.source
        );
    }

    use crate::sigv4::{
        SigV4Credential, DEFAULT_ACCESS_KEY_ID_VAR, DEFAULT_SECRET_ACCESS_KEY_VAR,
        DEFAULT_SESSION_TOKEN_VAR,
    };

    let ak_var = entry
        .access_key_id_var
        .as_deref()
        .unwrap_or(DEFAULT_ACCESS_KEY_ID_VAR);
    let sk_var = entry
        .secret_access_key_var
        .as_deref()
        .unwrap_or(DEFAULT_SECRET_ACCESS_KEY_VAR);
    let tok_var = entry
        .session_token_var
        .as_deref()
        .unwrap_or(DEFAULT_SESSION_TOKEN_VAR);

    let cred = SigV4Credential::from_env(ak_var, sk_var, tok_var).with_context(|| {
        format!(
            "credential for '{}': failed to resolve aws-sigv4 credentials",
            id
        )
    })?;

    Ok(Box::new(cred))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // --- Helpers ---

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
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
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
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
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
        assert!(parse_aws_host("notamazonaws.com").is_none());
    }

    #[test]
    fn parse_aws_host_bare_amazonaws_returns_none() {
        assert!(parse_aws_host("amazonaws.com").is_none());
    }

    #[test]
    fn parse_aws_host_deep_subdomain() {
        let info = parse_aws_host("deep.nested.s3.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_aws_host — dualstack, FIPS, and VPC endpoints
    // -----------------------------------------------------------------------

    #[test]
    fn parse_aws_host_s3_dualstack() {
        let info = parse_aws_host("s3.dualstack.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_s3_fips() {
        let info = parse_aws_host("s3-fips.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_s3_dualstack_fips() {
        let info = parse_aws_host("s3.dualstack.fips.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_s3_fips_dualstack() {
        let info = parse_aws_host("s3-fips.dualstack.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_dynamodb_dualstack() {
        let info = parse_aws_host("dynamodb.dualstack.eu-west-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "dynamodb");
        assert_eq!(info.region, Some("eu-west-1".to_string()));
    }

    #[test]
    fn parse_aws_host_virtual_hosted_s3_dualstack() {
        let info = parse_aws_host("bucket.s3.dualstack.us-east-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    #[test]
    fn parse_aws_host_vpce_endpoint() {
        let info = parse_aws_host("vpce-1a2b3c4d.s3.us-east-1.vpce.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-east-1".to_string()));
    }

    // -----------------------------------------------------------------------
    // parse_aws_host — China and GovCloud partitions
    // -----------------------------------------------------------------------

    #[test]
    fn parse_aws_host_china_dynamodb() {
        let info = parse_aws_host("dynamodb.cn-north-1.amazonaws.com.cn").unwrap();
        assert_eq!(info.service, "dynamodb");
        assert_eq!(info.region, Some("cn-north-1".to_string()));
    }

    #[test]
    fn parse_aws_host_china_s3() {
        let info = parse_aws_host("s3.cn-northwest-1.amazonaws.com.cn").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("cn-northwest-1".to_string()));
    }

    #[test]
    fn parse_aws_host_china_global() {
        let info = parse_aws_host("iam.amazonaws.com.cn").unwrap();
        assert_eq!(info.service, "iam");
        assert_eq!(info.region, None);
    }

    #[test]
    fn parse_aws_host_china_dualstack() {
        let info = parse_aws_host("s3.dualstack.cn-north-1.amazonaws.com.cn").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("cn-north-1".to_string()));
    }

    #[test]
    fn parse_aws_host_govcloud() {
        // GovCloud uses the standard .amazonaws.com suffix with us-gov-* regions
        let info = parse_aws_host("s3.us-gov-west-1.amazonaws.com").unwrap();
        assert_eq!(info.service, "s3");
        assert_eq!(info.region, Some("us-gov-west-1".to_string()));
    }

    #[test]
    fn parse_aws_host_bare_amazonaws_cn_returns_none() {
        assert!(parse_aws_host("amazonaws.com.cn").is_none());
    }

    // -----------------------------------------------------------------------
    // Credential trait tests
    // -----------------------------------------------------------------------

    #[test]
    fn bearer_credential_inject_returns_header() {
        let cred = BearerCredential {
            header: "Authorization".to_string(),
            value: "token abc123".to_string(),
        };

        let result = cred.inject("POST", "/api/v1", &[], Some(b"body"));
        assert!(result.is_some());
        let headers = result.unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].0, "Authorization");
        assert_eq!(headers[0].1, "token abc123");
    }

    #[test]
    fn bearer_credential_ignores_request_details() {
        let cred = BearerCredential {
            header: "X-Api-Key".to_string(),
            value: "key_123".to_string(),
        };

        // Same result regardless of method, path, headers, or body
        let existing_headers = vec![("Host".to_string(), "example.com".to_string())];

        let r1 = cred.inject("GET", "/foo", &[], None).unwrap();
        let r2 = cred
            .inject("POST", "/bar", &existing_headers, Some(b"body"))
            .unwrap();

        assert_eq!(r1, r2);
        assert_eq!(r1[0].0, "X-Api-Key");
        assert_eq!(r1[0].1, "key_123");
    }

    // -----------------------------------------------------------------------
    // Credential store tests
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
        let injected = cred.inject("GET", "/", &[], None).unwrap();
        assert_eq!(injected.len(), 1);
        assert_eq!(injected[0].0, "Authorization");
        assert_eq!(injected[0].1, "token ghp_test123");

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

    #[test]
    fn unsupported_credential_type() {
        let entries = vec![CredentialEntryConfig {
            host: Some("example.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: String::new(),
            source: "env".to_string(),
            env_var: Some("SOME_VAR".to_string()),
            credential_type: "oauth2".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let result = CredentialStore::from_entries(&entries);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(err.contains("unsupported credential type"), "got: {err}");
    }

    #[test]
    fn trait_dispatch_returns_correct_impl_per_host() {
        std::env::set_var("STRAIT_TEST_DISPATCH_1", "github_token");
        std::env::set_var("STRAIT_TEST_DISPATCH_2", "stripe_key");

        let entries = vec![
            CredentialEntryConfig {
                host: Some("api.github.com".to_string()),
                host_pattern: None,
                header: "Authorization".to_string(),
                value_prefix: "token ".to_string(),
                source: "env".to_string(),
                env_var: Some("STRAIT_TEST_DISPATCH_1".to_string()),
                credential_type: "bearer".to_string(),
                access_key_id_var: None,
                secret_access_key_var: None,
                session_token_var: None,
            },
            CredentialEntryConfig {
                host: Some("api.stripe.com".to_string()),
                host_pattern: None,
                header: "Authorization".to_string(),
                value_prefix: "Bearer ".to_string(),
                source: "env".to_string(),
                env_var: Some("STRAIT_TEST_DISPATCH_2".to_string()),
                credential_type: "bearer".to_string(),
                access_key_id_var: None,
                secret_access_key_var: None,
                session_token_var: None,
            },
        ];

        let store = CredentialStore::from_entries(&entries).unwrap();

        // GitHub credential
        let gh = store.get("api.github.com").unwrap();
        let gh_headers = gh.inject("GET", "/repos", &[], None).unwrap();
        assert_eq!(gh_headers[0].1, "token github_token");

        // Stripe credential
        let stripe = store.get("api.stripe.com").unwrap();
        let stripe_headers = stripe.inject("POST", "/charges", &[], None).unwrap();
        assert_eq!(stripe_headers[0].1, "Bearer stripe_key");

        // Unknown host
        assert!(store.get("unknown.com").is_none());

        std::env::remove_var("STRAIT_TEST_DISPATCH_1");
        std::env::remove_var("STRAIT_TEST_DISPATCH_2");
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
        let headers = cred.inject("GET", "/", &[], None).unwrap();
        assert_eq!(headers[0].1, "exact:exact_secret");

        // Other AWS hosts fall back to pattern
        let cred = store.get("lambda.us-east-1.amazonaws.com").unwrap();
        let headers = cred.inject("GET", "/", &[], None).unwrap();
        assert_eq!(headers[0].1, "pattern:pattern_secret");

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
        let headers = cred.inject("GET", "/", &[], None).unwrap();
        assert_eq!(headers[0].1, "token gh_token");

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
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
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
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
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
    // Debug redaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn bearer_credential_debug_redacts_value() {
        let cred = BearerCredential {
            header: "Authorization".to_string(),
            value: "token super_secret_ghp_abc123".to_string(),
        };

        let debug_output = format!("{:?}", cred);

        // Must NOT contain the actual secret
        assert!(
            !debug_output.contains("super_secret_ghp_abc123"),
            "Debug output must not contain the secret value, got: {debug_output}"
        );

        // Must contain the struct name and redacted marker
        assert!(
            debug_output.contains("BearerCredential"),
            "Debug output should contain struct name, got: {debug_output}"
        );
        assert!(
            debug_output.contains("***"),
            "Debug output should contain redaction marker, got: {debug_output}"
        );

        // Header name is non-secret metadata and should be visible
        assert!(
            debug_output.contains("Authorization"),
            "Debug output should show the header name, got: {debug_output}"
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
