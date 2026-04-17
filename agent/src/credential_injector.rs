//! Credential injection for the in-container proxy.
//!
//! Design tenets (docs/designs/in-container-rewrite.md, Phase 2):
//!
//! - **Credentials live on the host.** The agent never reads env vars,
//!   never opens a secrets file, never keeps a bearer token in memory
//!   across requests.
//! - **One RPC per allowed outbound.** For every request the Cedar
//!   policy allows, the agent calls `FetchCredential(session_id, host,
//!   action)` and applies whatever the host returns. If the next allowed
//!   request fires five milliseconds later, it calls `FetchCredential`
//!   again. There is no in-agent cache.
//! - **Body bytes stay in the container.** We hash the body locally
//!   (SHA-256) and send only the 32-byte digest over the wire. AWS SigV4
//!   canonical-request construction depends on that digest, so the host
//!   can still produce a correct signature.
//!
//! This module is deliberately thin: it wraps the generated
//! `StraitHostClient`, computes the body digest, and translates the
//! response into a flat edit list the proxy can apply to the outbound
//! request. No retries, no caching, no per-credential policy decisions.
//! Those all belong on the host.
//!
//! The public surface is:
//!
//! - [`CredentialInjector`] -- trait the proxy holds as
//!   `Arc<dyn CredentialInjector>` so unit tests can substitute fakes
//!   without spinning up a gRPC server.
//! - [`RpcCredentialInjector`] -- production impl backed by the agent's
//!   `HostClient`.
//! - [`NoopCredentialInjector`] -- default impl that always returns
//!   "no credential", used before the agent has a session id or when
//!   the host client is unavailable.
//! - [`CredentialOutcome`] -- the flat edit list.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use tracing::warn;

use strait_proto::v1::fetch_credential_response::Kind as FetchKind;
use strait_proto::v1::FetchCredentialRequest;

use crate::host_client::HostClient;

/// Edit list the proxy applies to an outbound request once the host has
/// told it how this specific request should be authenticated.
///
/// Kept flat and owned so the proxy can apply it synchronously without
/// holding a borrow on the injector. `None` means "host had nothing to
/// inject"; the proxy forwards the request unmodified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CredentialOutcome {
    /// No credential configured for this (host, action).
    None,
    /// Add a single HTTP header (bearer / basic / api-key). The proxy
    /// removes any existing header with the same name (case-insensitive)
    /// before appending this one.
    Header {
        /// Header name (e.g. "Authorization").
        name: String,
        /// Fully computed header value. Opaque to the proxy -- written
        /// verbatim, never parsed.
        value: String,
    },
    /// Full signed-request rewrite (AWS SigV4). The proxy replaces the
    /// method, the full URL, and the header set with the signed versions
    /// exactly as delivered. The request body is unchanged -- the signed
    /// headers already commit to it via `x-amz-content-sha256`.
    Signed {
        /// Signed HTTP method (verbatim).
        method: String,
        /// Full signed URL, e.g. `https://api.example.com/path?query`.
        url: String,
        /// Complete outbound header set.
        headers: Vec<(String, String)>,
    },
}

/// Future type returned by the [`CredentialInjector`] trait method.
/// Boxed so callers can hold `Arc<dyn CredentialInjector>` without
/// pulling `async-trait` into the dep graph.
pub type InjectFuture<'a> =
    Pin<Box<dyn Future<Output = anyhow::Result<CredentialOutcome>> + Send + 'a>>;

/// Abstraction the proxy uses to fetch credentials on each allowed
/// request. Implementations must be cheap to clone/share because the
/// proxy holds them behind `Arc`.
pub trait CredentialInjector: Send + Sync {
    /// Fetch the credential material for a single outbound request.
    ///
    /// `body` is the in-memory request body. The implementation hashes
    /// it (or the equivalent, for empty bodies) and sends the digest to
    /// the host; the raw bytes never leave the container.
    fn fetch<'a>(
        &'a self,
        host: &'a str,
        action: &'a str,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: Option<&'a [u8]>,
    ) -> InjectFuture<'a>;
}

/// Default injector used when no session id is available, or in tests
/// that only exercise the allow/deny plumbing. Every `fetch` call
/// resolves to `CredentialOutcome::None` immediately, so the proxy
/// forwards the request unmodified.
pub struct NoopCredentialInjector;

impl CredentialInjector for NoopCredentialInjector {
    fn fetch<'a>(
        &'a self,
        _host: &'a str,
        _action: &'a str,
        _method: &'a str,
        _path: &'a str,
        _headers: &'a [(String, String)],
        _body: Option<&'a [u8]>,
    ) -> InjectFuture<'a> {
        Box::pin(async { Ok(CredentialOutcome::None) })
    }
}

/// Production injector backed by a gRPC `HostClient`.
///
/// The client is wrapped in `Mutex` because `StraitHostClient` takes
/// `&mut self` on every RPC call (tonic internally serialises state per
/// channel). The channel itself multiplexes requests, so holding the
/// lock across the `await` is fine for concurrent load.
pub struct RpcCredentialInjector {
    session_id: String,
    client: Mutex<HostClient>,
}

impl RpcCredentialInjector {
    /// Build an injector that attaches `session_id` to every outbound
    /// RPC. The session id comes from the `RegisterContainer` response
    /// the agent received at boot.
    pub fn new(session_id: String, client: HostClient) -> Self {
        Self {
            session_id,
            client: Mutex::new(client),
        }
    }

    /// Wrap in an `Arc<dyn CredentialInjector>` for consumption by the
    /// proxy config.
    pub fn into_arc(self) -> Arc<dyn CredentialInjector> {
        Arc::new(self)
    }
}

impl CredentialInjector for RpcCredentialInjector {
    fn fetch<'a>(
        &'a self,
        host: &'a str,
        action: &'a str,
        method: &'a str,
        path: &'a str,
        headers: &'a [(String, String)],
        body: Option<&'a [u8]>,
    ) -> InjectFuture<'a> {
        Box::pin(async move {
            let body_sha256 = sha256_bytes(body.unwrap_or(&[]));
            // Convert `(name, value)` pairs to the HashMap the proto
            // expects. Lowercasing the header names would lose the
            // original casing; we keep what the client sent so the SigV4
            // signer sees the same canonical form.
            let headers_map: std::collections::HashMap<String, String> =
                headers.iter().cloned().collect();

            let req = FetchCredentialRequest {
                session_id: self.session_id.clone(),
                host: host.to_string(),
                action: action.to_string(),
                method: method.to_string(),
                path: path.to_string(),
                body_sha256,
                headers: headers_map,
            };

            let mut client = self.client.lock().await;
            let resp = match client.fetch_credential(req).await {
                Ok(resp) => resp.into_inner(),
                Err(err) => {
                    warn!(
                        host = %host,
                        action = %action,
                        error = %err,
                        "FetchCredential RPC failed; forwarding unsigned"
                    );
                    // Fail open on credential fetch: the Cedar policy
                    // already allowed the request, and denying the
                    // outbound because the secrets plane wobbled would
                    // be worse than a missing Authorization header.
                    return Ok(CredentialOutcome::None);
                }
            };

            Ok(match resp.kind {
                Some(FetchKind::Header(h)) => CredentialOutcome::Header {
                    name: h.header_name,
                    value: h.header_value,
                },
                Some(FetchKind::Signed(s)) => CredentialOutcome::Signed {
                    method: s.method,
                    url: s.url,
                    headers: s.headers.into_iter().collect(),
                },
                Some(FetchKind::None(_)) | None => CredentialOutcome::None,
            })
        })
    }
}

/// Compute SHA-256 of a byte slice and return the raw 32-byte digest.
/// The proto carries it as bytes; the host hex-encodes once before
/// handing the value to the AWS signer.
fn sha256_bytes(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_injector_returns_none() {
        let inj = NoopCredentialInjector;
        let out = inj
            .fetch(
                "api.github.com",
                "http:GET",
                "GET",
                "/",
                &[("Host".to_string(), "api.github.com".to_string())],
                None,
            )
            .await
            .unwrap();
        assert_eq!(out, CredentialOutcome::None);
    }

    #[test]
    fn sha256_empty_body_is_e3b0c442() {
        // Known SHA-256 of the empty string.
        let expected =
            hex::decode("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
                .unwrap();
        assert_eq!(sha256_bytes(&[]), expected);
    }

    #[test]
    fn sha256_known_body() {
        // SHA-256("hello, world!")
        let expected =
            hex::decode("68e656b251e67e8358bef8483ab0d51c6619f3e7a1a9f0e75838d41ff368f728")
                .unwrap();
        assert_eq!(sha256_bytes(b"hello, world!"), expected);
    }

    /// Fake injector that records its last input and returns a fixed
    /// outcome. Used by the proxy unit tests to verify that the allow
    /// path calls the injector and applies the result.
    struct FakeInjector {
        outcome: CredentialOutcome,
        last_host: std::sync::Mutex<Option<String>>,
    }

    impl CredentialInjector for FakeInjector {
        fn fetch<'a>(
            &'a self,
            host: &'a str,
            _action: &'a str,
            _method: &'a str,
            _path: &'a str,
            _headers: &'a [(String, String)],
            _body: Option<&'a [u8]>,
        ) -> InjectFuture<'a> {
            *self.last_host.lock().unwrap() = Some(host.to_string());
            let out = self.outcome.clone();
            Box::pin(async move { Ok(out) })
        }
    }

    #[tokio::test]
    async fn fake_injector_records_host_and_returns_outcome() {
        let fake = FakeInjector {
            outcome: CredentialOutcome::Header {
                name: "Authorization".into(),
                value: "token xyz".into(),
            },
            last_host: std::sync::Mutex::new(None),
        };
        let out = fake
            .fetch("api.github.com", "http:GET", "GET", "/", &[], None)
            .await
            .unwrap();
        assert_eq!(
            out,
            CredentialOutcome::Header {
                name: "Authorization".into(),
                value: "token xyz".into(),
            }
        );
        assert_eq!(
            fake.last_host.lock().unwrap().as_deref(),
            Some("api.github.com")
        );
    }
}
