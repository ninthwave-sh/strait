//! AWS Signature Version 4 credential implementation.
//!
//! [`SigV4Credential`] implements the [`Credential`] trait for AWS Signature
//! Version 4 signing. It uses the `aws-sigv4` crate to produce the standard
//! AWS auth headers: `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`,
//! and optionally `X-Amz-Security-Token`.
//!
//! Credentials are resolved eagerly at startup from environment variables.
//! Service and region are extracted at request time from the `Host` header via
//! [`parse_aws_host`](crate::credentials::parse_aws_host).
//!
//! ## Config example
//!
//! ```toml
//! [[credential]]
//! host_pattern = "*.amazonaws.com"
//! type = "aws-sigv4"
//! source = "env"
//! # Optional: override env var names (defaults shown)
//! # access_key_id_var = "AWS_ACCESS_KEY_ID"
//! # secret_access_key_var = "AWS_SECRET_ACCESS_KEY"
//! # session_token_var = "AWS_SESSION_TOKEN"
//! ```

use std::time::SystemTime;

use aws_credential_types::Credentials;
use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
use aws_sigv4::sign::v4;
use aws_smithy_runtime_api::client::identity::Identity;
use sha2::{Digest, Sha256};

use tracing::warn;

use crate::credentials::{parse_aws_host, Credential, CredentialKind};

/// Default environment variable names for AWS credentials.
pub const DEFAULT_ACCESS_KEY_ID_VAR: &str = "AWS_ACCESS_KEY_ID";
pub const DEFAULT_SECRET_ACCESS_KEY_VAR: &str = "AWS_SECRET_ACCESS_KEY";
pub const DEFAULT_SESSION_TOKEN_VAR: &str = "AWS_SESSION_TOKEN";

/// Default region when the hostname is a global endpoint (e.g. `iam.amazonaws.com`).
const DEFAULT_REGION: &str = "us-east-1";

/// AWS Signature Version 4 credential.
///
/// Holds the resolved access key, secret key, and optional session token.
/// At request time, extracts the service and region from the `Host` header
/// and signs the request using the `aws-sigv4` crate.
#[derive(Clone)]
pub struct SigV4Credential {
    access_key_id: String,
    secret_access_key: String,
    session_token: Option<String>,
}

impl std::fmt::Debug for SigV4Credential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigV4Credential")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"***")
            .field("session_token", &self.session_token.as_ref().map(|_| "***"))
            .finish()
    }
}

impl SigV4Credential {
    /// Resolve AWS credentials from environment variables.
    ///
    /// The `session_token_var` is optional: if the env var is not set, signing
    /// proceeds without a session token (permanent credentials).
    ///
    /// # Errors
    ///
    /// Returns an error if `access_key_id_var` or `secret_access_key_var` is
    /// not set in the environment.
    pub fn from_env(
        access_key_id_var: &str,
        secret_access_key_var: &str,
        session_token_var: &str,
    ) -> anyhow::Result<Self> {
        let access_key_id = std::env::var(access_key_id_var).map_err(|_| {
            anyhow::anyhow!(
                "aws-sigv4 credential: environment variable '{}' is not set",
                access_key_id_var
            )
        })?;

        let secret_access_key = std::env::var(secret_access_key_var).map_err(|_| {
            anyhow::anyhow!(
                "aws-sigv4 credential: environment variable '{}' is not set",
                secret_access_key_var
            )
        })?;

        let session_token = std::env::var(session_token_var).ok();

        Ok(Self {
            access_key_id,
            secret_access_key,
            session_token,
        })
    }

    /// Sign a request and return the headers to inject.
    ///
    /// Factored out of `inject` so that callers can provide a custom timestamp
    /// (useful for deterministic tests).
    fn sign_request(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
        time: SystemTime,
    ) -> Option<Vec<(String, String)>> {
        let body_bytes = body.unwrap_or(&[]);
        let body_sha256_hex = sha256_hex(body_bytes);
        self.sign_core(method, path, headers, &body_sha256_hex, time)
    }

    /// Sign a request using a caller-supplied body SHA-256 digest.
    ///
    /// The in-container agent never ships request bodies to the host. It
    /// hashes the body locally and sends only the digest over the
    /// `FetchCredential` RPC, so the host signs using the pre-computed
    /// digest via this method.
    ///
    /// `body_sha256_hex` must be a lowercase hex-encoded SHA-256 (64
    /// characters). The AWS SigV4 canonical-request construction puts this
    /// string directly into the `x-amz-content-sha256` header and the
    /// canonical-request body line.
    pub fn sign_with_body_hash(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body_sha256_hex: &str,
        time: SystemTime,
    ) -> Option<Vec<(String, String)>> {
        self.sign_core(method, path, headers, body_sha256_hex, time)
    }

    /// Shared signing core. Both [`sign_request`] (body-bytes path) and
    /// [`sign_with_body_hash`] (pre-computed digest path) funnel into this
    /// helper. Uses `SignableBody::Precomputed` so the `aws-sigv4` crate
    /// never rehashes the body.
    fn sign_core(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body_sha256_hex: &str,
        time: SystemTime,
    ) -> Option<Vec<(String, String)>> {
        // Extract host from request headers
        let host = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.as_str())?;

        // Extract service and region from the AWS hostname
        let aws_info = parse_aws_host(host)?;
        let region = aws_info.region.as_deref().unwrap_or(DEFAULT_REGION);

        // Build AWS identity from resolved credentials
        let creds = Credentials::new(
            &self.access_key_id,
            &self.secret_access_key,
            self.session_token.clone(),
            None,     // no expiry
            "strait", // provider name
        );
        let identity: Identity = creds.into();

        // Build signing parameters
        let settings = SigningSettings::default();
        let params = match v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(&aws_info.service)
            .time(time)
            .settings(settings)
            .build()
        {
            Ok(p) => p,
            Err(e) => {
                warn!(
                    error = %e,
                    host = %host,
                    service = %aws_info.service,
                    region = %region,
                    "SigV4 SigningParams::build() failed"
                );
                return None;
            }
        };

        let signing_params: aws_sigv4::http_request::SigningParams<'_> = params.into();

        // Construct the full URI for signing
        let uri = format!("https://{host}{path}");

        // Add x-amz-content-sha256 to the headers before signing so it's
        // included in the canonical request's signed headers.
        let mut signing_headers: Vec<(String, String)> = headers.to_vec();
        signing_headers.push((
            "x-amz-content-sha256".to_string(),
            body_sha256_hex.to_string(),
        ));

        // Build the signable body and request. `Precomputed` tells the
        // signer to trust the hex digest we're providing instead of
        // rehashing bytes it does not have.
        let signable_body = SignableBody::Precomputed(body_sha256_hex.to_string());
        let header_iter = signing_headers
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()));

        let signable = match SignableRequest::new(method, &uri, header_iter, signable_body) {
            Ok(s) => s,
            Err(e) => {
                warn!(
                    error = %e,
                    host = %host,
                    service = %aws_info.service,
                    region = %region,
                    "SigV4 SignableRequest::new() failed"
                );
                return None;
            }
        };

        // Sign the request
        let (instructions, _signature) = match sign(signable, &signing_params) {
            Ok(output) => output.into_parts(),
            Err(e) => {
                warn!(
                    error = %e,
                    host = %host,
                    service = %aws_info.service,
                    region = %region,
                    "SigV4 sign() failed"
                );
                return None;
            }
        };

        // Collect the headers returned by the signing process (Authorization,
        // X-Amz-Date, and optionally X-Amz-Security-Token), plus the
        // content-sha256 header we computed (only if the signer didn't
        // already include it).
        let mut result: Vec<(String, String)> = instructions
            .headers()
            .map(|(name, value)| (name.to_string(), value.to_string()))
            .collect();

        let has_content_sha = result
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"));
        if !has_content_sha {
            result.push((
                "x-amz-content-sha256".to_string(),
                body_sha256_hex.to_string(),
            ));
        }

        Some(result)
    }
}

impl Credential for SigV4Credential {
    fn inject(
        &self,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body: Option<&[u8]>,
    ) -> Option<Vec<(String, String)>> {
        self.sign_request(method, path, headers, body, SystemTime::now())
    }

    fn fetch_for_request(
        &self,
        host: &str,
        method: &str,
        path: &str,
        headers: &[(String, String)],
        body_sha256_hex: &str,
    ) -> CredentialKind {
        // Ensure the Host header is present so `sign_core` can extract it
        // and derive service/region. The agent should already include Host
        // via the headers map, but this is the secrets path so we defend
        // against a missing entry explicitly.
        let mut signing_headers: Vec<(String, String)> = headers.to_vec();
        let has_host = signing_headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("host"));
        if !has_host {
            signing_headers.push(("host".to_string(), host.to_string()));
        }

        let Some(signed_headers) = self.sign_with_body_hash(
            method,
            path,
            &signing_headers,
            body_sha256_hex,
            SystemTime::now(),
        ) else {
            // parse_aws_host returned None, missing Host, or the signer
            // failed. Treat as "no credential" rather than surfacing an
            // error -- the agent will proceed unsigned, and the Cedar
            // policy still gated the request.
            return CredentialKind::None;
        };

        // Merge signing headers into the original header set, replacing
        // same-named predecessors (case-insensitive). The proto tells the
        // agent to apply the full headers map verbatim, so we build the
        // final shape here.
        let mut merged: Vec<(String, String)> = signing_headers;
        for (name, _) in &signed_headers {
            merged.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
        }
        merged.extend(signed_headers);

        let url = format!("https://{host}{path}");
        CredentialKind::Signed {
            method: method.to_string(),
            url,
            headers: merged,
        }
    }
}

/// Compute lowercase hex-encoded SHA-256 digest.
pub(crate) fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hex::encode(hasher.finalize())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use std::time::{Duration, UNIX_EPOCH};

    /// Helper: create a SigV4Credential with known keys (no env vars needed).
    fn test_credential() -> SigV4Credential {
        SigV4Credential {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: None,
        }
    }

    fn test_credential_with_token() -> SigV4Credential {
        SigV4Credential {
            access_key_id: "AKIAIOSFODNN7EXAMPLE".to_string(),
            secret_access_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".to_string(),
            session_token: Some("AQoDYXdzEJr...".to_string()),
        }
    }

    /// Fixed timestamp for deterministic tests: 2024-01-15T12:00:00Z
    fn fixed_time() -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(1_705_320_000)
    }

    // -----------------------------------------------------------------------
    // Authorization header format
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_produces_well_formed_authorization_header() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/test-bucket/key", &headers, None, fixed_time())
            .expect("signing should succeed");

        let auth = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .expect("Authorization header should be present");

        assert!(
            auth.1.starts_with("AWS4-HMAC-SHA256 Credential="),
            "Authorization header should start with 'AWS4-HMAC-SHA256 Credential=', got: {}",
            auth.1
        );

        // Verify the credential contains the access key ID
        assert!(
            auth.1.contains("AKIAIOSFODNN7EXAMPLE"),
            "Authorization should contain the access key ID"
        );

        // Verify it contains the service and region
        assert!(
            auth.1.contains("us-east-1/s3/aws4_request"),
            "Authorization should contain region/service/aws4_request"
        );
    }

    // -----------------------------------------------------------------------
    // X-Amz-Date header
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_produces_x_amz_date_header() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let date = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-date"))
            .expect("X-Amz-Date header should be present");

        // ISO-8601 basic format: YYYYMMDD'T'HHMMSS'Z'
        assert!(
            date.1.len() == 16
                && date.1.ends_with('Z')
                && date.1.contains('T')
                && date
                    .1
                    .chars()
                    .all(|c| c.is_ascii_digit() || c == 'T' || c == 'Z'),
            "X-Amz-Date should be ISO-8601 basic format (YYYYMMDDTHHmmSSZ), got: {}",
            date.1
        );

        // Verify it matches our fixed timestamp (2024-01-15T12:00:00Z)
        assert_eq!(date.1, "20240115T120000Z");
    }

    // -----------------------------------------------------------------------
    // X-Amz-Content-Sha256 header
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_content_sha256_matches_body() {
        let cred = test_credential();
        let headers = vec![
            ("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string()),
            ("Content-Length".to_string(), "13".to_string()),
        ];
        let body = b"hello, world!";

        let result = cred
            .sign_request("PUT", "/bucket/key", &headers, Some(body), fixed_time())
            .expect("signing should succeed");

        let content_sha = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"))
            .expect("X-Amz-Content-Sha256 header should be present");

        let expected = sha256_hex(body);
        assert_eq!(
            content_sha.1, expected,
            "X-Amz-Content-Sha256 should match SHA-256 of body"
        );
    }

    #[test]
    fn sigv4_empty_body_produces_sha256_of_empty_string() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let content_sha = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"))
            .expect("X-Amz-Content-Sha256 header should be present");

        let expected = sha256_hex(&[]);
        assert_eq!(
            content_sha.1, expected,
            "empty body should produce SHA-256 of empty string"
        );
    }

    // -----------------------------------------------------------------------
    // Session token handling
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_session_token_present_adds_security_token_header() {
        let cred = test_credential_with_token();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let token = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-security-token"));
        assert!(
            token.is_some(),
            "X-Amz-Security-Token header should be present when session token is set"
        );
        assert_eq!(token.unwrap().1, "AQoDYXdzEJr...");
    }

    #[test]
    fn sigv4_no_session_token_omits_security_token_header() {
        let cred = test_credential(); // no session token
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let token = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("x-amz-security-token"));
        assert!(
            token.is_none(),
            "X-Amz-Security-Token header should NOT be present without session token"
        );
    }

    // -----------------------------------------------------------------------
    // Service and region extraction from hostname
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_extracts_service_and_region_from_host() {
        let cred = test_credential();

        // Lambda in eu-west-1
        let headers = vec![(
            "Host".to_string(),
            "lambda.eu-west-1.amazonaws.com".to_string(),
        )];
        let result = cred
            .sign_request("GET", "/functions", &headers, None, fixed_time())
            .expect("signing should succeed");

        let auth = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .unwrap();

        assert!(
            auth.1.contains("eu-west-1/lambda/aws4_request"),
            "Authorization should contain eu-west-1/lambda, got: {}",
            auth.1
        );
    }

    #[test]
    fn sigv4_global_endpoint_defaults_to_us_east_1() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "iam.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let auth = result
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .unwrap();

        assert!(
            auth.1.contains("us-east-1/iam/aws4_request"),
            "Global endpoint should default to us-east-1, got: {}",
            auth.1
        );
    }

    // -----------------------------------------------------------------------
    // Error cases
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_non_aws_host_returns_none() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "api.github.com".to_string())];

        let result = cred.sign_request("GET", "/", &headers, None, fixed_time());
        assert!(
            result.is_none(),
            "non-AWS host should return None (signing not applicable)"
        );
    }

    #[test]
    fn sigv4_missing_host_header_returns_none() {
        let cred = test_credential();
        let headers = vec![("Accept".to_string(), "application/json".to_string())];

        let result = cred.sign_request("GET", "/", &headers, None, fixed_time());
        assert!(result.is_none(), "missing Host header should return None");
    }

    #[test]
    fn sigv4_missing_access_key_env_var_fails() {
        // Ensure the env var is not set
        std::env::remove_var("STRAIT_TEST_SV4_MISSING_KEY");

        let result = SigV4Credential::from_env(
            "STRAIT_TEST_SV4_MISSING_KEY",
            "STRAIT_TEST_SV4_SECRET",
            "STRAIT_TEST_SV4_TOKEN",
        );

        assert!(result.is_err(), "missing access key should fail at startup");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("STRAIT_TEST_SV4_MISSING_KEY"),
            "error should mention the env var name, got: {err}"
        );
    }

    #[test]
    fn sigv4_missing_secret_key_env_var_fails() {
        std::env::set_var("STRAIT_TEST_SV4_AK_PRESENT", "AKID");
        std::env::remove_var("STRAIT_TEST_SV4_SK_MISSING");

        let result = SigV4Credential::from_env(
            "STRAIT_TEST_SV4_AK_PRESENT",
            "STRAIT_TEST_SV4_SK_MISSING",
            "STRAIT_TEST_SV4_TOKEN",
        );

        assert!(result.is_err(), "missing secret key should fail at startup");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("STRAIT_TEST_SV4_SK_MISSING"),
            "error should mention the env var name, got: {err}"
        );

        std::env::remove_var("STRAIT_TEST_SV4_AK_PRESENT");
    }

    // -----------------------------------------------------------------------
    // Credential trait dispatch
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_implements_credential_trait() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        // Use the trait method (inject) rather than sign_request
        let result = cred.inject("GET", "/", &headers, None);
        assert!(result.is_some(), "inject should succeed for AWS hosts");

        let injected = result.unwrap();
        assert!(
            injected
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization")),
            "should inject Authorization header"
        );
    }

    // -----------------------------------------------------------------------
    // from_env with session token
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_from_env_with_session_token() {
        std::env::set_var("STRAIT_TEST_SV4_AK", "AKIATEST");
        std::env::set_var("STRAIT_TEST_SV4_SK", "secret123");
        std::env::set_var("STRAIT_TEST_SV4_TOK", "session_tok_xyz");

        let cred = SigV4Credential::from_env(
            "STRAIT_TEST_SV4_AK",
            "STRAIT_TEST_SV4_SK",
            "STRAIT_TEST_SV4_TOK",
        )
        .unwrap();

        assert_eq!(cred.access_key_id, "AKIATEST");
        assert_eq!(cred.secret_access_key, "secret123");
        assert_eq!(cred.session_token, Some("session_tok_xyz".to_string()));

        std::env::remove_var("STRAIT_TEST_SV4_AK");
        std::env::remove_var("STRAIT_TEST_SV4_SK");
        std::env::remove_var("STRAIT_TEST_SV4_TOK");
    }

    #[test]
    fn sigv4_from_env_without_session_token() {
        std::env::set_var("STRAIT_TEST_SV4_AK2", "AKIATEST2");
        std::env::set_var("STRAIT_TEST_SV4_SK2", "secret456");
        std::env::remove_var("STRAIT_TEST_SV4_TOK2");

        let cred = SigV4Credential::from_env(
            "STRAIT_TEST_SV4_AK2",
            "STRAIT_TEST_SV4_SK2",
            "STRAIT_TEST_SV4_TOK2",
        )
        .unwrap();

        assert_eq!(cred.access_key_id, "AKIATEST2");
        assert_eq!(cred.secret_access_key, "secret456");
        assert!(cred.session_token.is_none());

        std::env::remove_var("STRAIT_TEST_SV4_AK2");
        std::env::remove_var("STRAIT_TEST_SV4_SK2");
    }

    // -----------------------------------------------------------------------
    // Warning capture helper for tracing tests
    // -----------------------------------------------------------------------

    /// Minimal tracing subscriber that captures event messages at WARN level.
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

    /// Extracts the `message` field from a tracing event.
    struct MsgExtractor(String);

    impl tracing::field::Visit for MsgExtractor {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            if field.name() == "message" {
                self.0 = format!("{:?}", value);
            }
        }
    }

    // -----------------------------------------------------------------------
    // Signing failure logging
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_signing_failure_emits_warning() {
        let messages = Arc::new(Mutex::new(Vec::new()));
        let collector = WarnCollector {
            messages: messages.clone(),
        };
        let _guard = tracing::subscriber::set_default(collector);

        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        // A path with a space produces an invalid URI ("https://host/foo bar"),
        // which causes SignableRequest::new() to fail and trigger a warn! log.
        let result = cred.sign_request("GET", "/foo bar", &headers, None, fixed_time());

        assert!(
            result.is_none(),
            "signing with invalid URI path should return None"
        );

        let msgs = messages.lock().unwrap();
        assert!(!msgs.is_empty(), "signing failure should emit a warn! log");
        assert!(
            msgs.iter().any(|m| m.contains("SigV4")),
            "warning should mention SigV4, got: {:?}",
            *msgs
        );
    }

    // -----------------------------------------------------------------------
    // Debug redaction tests
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_debug_redacts_secret_key() {
        let cred = test_credential();
        let debug_output = format!("{:?}", cred);

        // Must NOT contain the secret access key
        assert!(
            !debug_output.contains("wJalrXUtnFEMI"),
            "Debug output must not contain the secret access key, got: {debug_output}"
        );

        // Access key ID is non-secret metadata and should be visible
        assert!(
            debug_output.contains("AKIAIOSFODNN7EXAMPLE"),
            "Debug output should show the access key ID, got: {debug_output}"
        );

        // Should contain redaction markers
        assert!(
            debug_output.contains("***"),
            "Debug output should contain redaction marker, got: {debug_output}"
        );
    }

    #[test]
    fn sigv4_debug_redacts_session_token() {
        let cred = test_credential_with_token();
        let debug_output = format!("{:?}", cred);

        // Must NOT contain the session token value
        assert!(
            !debug_output.contains("AQoDYXdzEJr"),
            "Debug output must not contain the session token, got: {debug_output}"
        );

        // Should show that a session token exists (redacted)
        assert!(
            debug_output.contains("session_token"),
            "Debug output should mention session_token field, got: {debug_output}"
        );
    }

    #[test]
    fn sigv4_debug_shows_none_session_token() {
        let cred = test_credential(); // no session token
        let debug_output = format!("{:?}", cred);

        assert!(
            debug_output.contains("None"),
            "Debug output should show None for missing session token, got: {debug_output}"
        );
    }

    // -----------------------------------------------------------------------
    // No duplicate x-amz-content-sha256 header
    // -----------------------------------------------------------------------

    #[test]
    fn sigv4_no_duplicate_content_sha256_header() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];

        let result = cred
            .sign_request("GET", "/", &headers, None, fixed_time())
            .expect("signing should succeed");

        let count = result
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"))
            .count();

        assert_eq!(
            count, 1,
            "should have exactly one x-amz-content-sha256 header, got {count}"
        );
    }

    // -----------------------------------------------------------------------
    // Body-hash parity (acceptance criterion: "SigV4 signing produces the
    // same output as the current src/sigv4.rs for canned inputs")
    // -----------------------------------------------------------------------

    #[test]
    fn sign_with_body_hash_matches_sign_request_for_same_body() {
        // The in-container agent sends only the body digest over the
        // FetchCredential RPC, so the host signs via
        // `sign_with_body_hash`. This test locks in that the two code
        // paths produce byte-identical output for the same input body.
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let body = b"payload bytes, non-empty";
        let body_hex = sha256_hex(body);

        let bytes_sig = cred
            .sign_request("PUT", "/bucket/key", &headers, Some(body), fixed_time())
            .expect("sign_request should succeed");
        let hash_sig = cred
            .sign_with_body_hash("PUT", "/bucket/key", &headers, &body_hex, fixed_time())
            .expect("sign_with_body_hash should succeed");

        assert_eq!(
            bytes_sig, hash_sig,
            "body-bytes and body-hash signing paths must produce identical headers"
        );
    }

    #[test]
    fn sign_with_body_hash_matches_sign_request_for_empty_body() {
        let cred = test_credential();
        let headers = vec![("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string())];
        let empty_hex = sha256_hex(&[]);

        let bytes_sig = cred
            .sign_request("GET", "/bucket/key", &headers, None, fixed_time())
            .expect("sign_request should succeed");
        let hash_sig = cred
            .sign_with_body_hash("GET", "/bucket/key", &headers, &empty_hex, fixed_time())
            .expect("sign_with_body_hash should succeed");

        assert_eq!(bytes_sig, hash_sig);
    }
}
