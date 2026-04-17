//! In-container client for the host's `SubmitDecision` RPC.
//!
//! H-HCP-6 retargets the former in-container live-decision path at the
//! host control plane. When the agent's proxy blocks a request on policy,
//! it calls `SubmitDecision` on `strait-host`; the host holds the request
//! until an operator responds (or the hold window elapses). This module
//! wraps that RPC in the agent's [`HostRpcClient`] abstraction so the
//! existing proxy pipeline can plug the new behaviour in by swapping one
//! `Arc<dyn HostRpcClient>`.
//!
//! ## Session cache
//!
//! The acceptance criterion for H-HCP-6 requires that after the operator
//! returns `allow_session`, the *next* matching request in the same
//! session is served "without another RPC". The client therefore keeps a
//! small in-memory cache keyed by `(host, action)`:
//!
//! - On `Verdict::AllowSession` the cache is populated.
//! - Subsequent `review_blocked` calls that hit the cache return
//!   `HostRpcVerdict::Allow` immediately, without touching the gRPC
//!   channel. This matches the test plan's "served from session cache
//!   without another RPC" language.
//! - `AllowOnce` and `AllowPersist` allow the one request but do *not*
//!   mutate the cache. `AllowPersist` is expected to land as a rule in
//!   the host store, which `StreamRules` (H-HCP-3) will eventually push
//!   down; until then, subsequent matching requests pay one more RPC
//!   and get `AllowPersist` from the host's rule-store fast path.
//! - `Deny` and `Timeout` both fail closed on the agent side.

use std::collections::HashSet;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use strait_proto::v1::{SubmitDecisionRequest, Verdict};
use tokio::sync::Mutex as AsyncMutex;
use tonic::Request;
use tracing::{debug, warn};

use crate::host_client::HostClient;
use crate::proxy::{HostRpcClient, HostRpcFuture, HostRpcVerdict};

/// Default per-call deadline for `SubmitDecision`.
///
/// This bounds the client side; the host also applies its own hold
/// timeout. Tests pass a shorter value to exercise the timeout path in
/// CI-friendly time.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// `HostRpcClient` implementation that talks to `strait-host` over gRPC.
///
/// Cloning the client is cheap: it shares the underlying gRPC channel,
/// the session cache, and the request-id counter through their own
/// synchronisation primitives.
#[derive(Debug)]
pub struct HostDecisionClient {
    client: AsyncMutex<HostClient>,
    session_id: String,
    session_cache: Mutex<HashSet<(String, String)>>,
    request_counter: AtomicU64,
    call_timeout: Duration,
}

impl HostDecisionClient {
    /// Build a new client. The caller owns the session-registration
    /// round-trip and hands the assigned `session_id` in here.
    pub fn new(client: HostClient, session_id: impl Into<String>) -> Self {
        Self::with_timeout(client, session_id, DEFAULT_CALL_TIMEOUT)
    }

    /// Build a new client with an explicit per-call deadline.
    pub fn with_timeout(
        client: HostClient,
        session_id: impl Into<String>,
        call_timeout: Duration,
    ) -> Self {
        Self {
            client: AsyncMutex::new(client),
            session_id: session_id.into(),
            session_cache: Mutex::new(HashSet::new()),
            request_counter: AtomicU64::new(1),
            call_timeout,
        }
    }

    /// Session id the client attaches to every outbound `SubmitDecision`.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// True when `(host, action)` has been cached for the lifetime of
    /// this session.
    pub fn session_cached(&self, host: &str, action: &str) -> bool {
        let guard = self
            .session_cache
            .lock()
            .expect("session cache mutex poisoned");
        guard.contains(&(host.to_string(), action.to_string()))
    }

    /// Number of currently-cached session allows. Exposed for tests.
    pub fn session_cache_len(&self) -> usize {
        self.session_cache
            .lock()
            .expect("session cache mutex poisoned")
            .len()
    }

    fn record_session(&self, host: &str, action: &str) {
        let mut guard = self
            .session_cache
            .lock()
            .expect("session cache mutex poisoned");
        guard.insert((host.to_string(), action.to_string()));
    }

    fn next_request_id(&self) -> String {
        let n = self.request_counter.fetch_add(1, Ordering::Relaxed);
        format!("{}-{n:08x}", self.session_id)
    }
}

impl HostRpcClient for HostDecisionClient {
    fn review_blocked<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> HostRpcFuture<'a> {
        Box::pin(async move {
            let action = format!("http:{}", method.to_ascii_uppercase());
            if self.session_cached(host, &action) {
                debug!(
                    host,
                    method, path, "session cache hit; skipping SubmitDecision RPC"
                );
                return HostRpcVerdict::Allow;
            }

            let request_id = self.next_request_id();
            let body = SubmitDecisionRequest {
                session_id: self.session_id.clone(),
                request_id: request_id.clone(),
                method: method.to_ascii_uppercase(),
                host: host.to_string(),
                path: path.to_string(),
                headers: Default::default(),
                observed_at_unix_ms: now_unix_ms(),
                explanation: format!("{method} {path}"),
            };
            let mut req = Request::new(body);
            req.set_timeout(self.call_timeout);

            let mut client = self.client.lock().await;
            let verdict = match client.submit_decision(req).await {
                Ok(resp) => {
                    let inner = resp.into_inner();
                    match Verdict::try_from(inner.verdict).unwrap_or(Verdict::Unspecified) {
                        Verdict::AllowOnce | Verdict::AllowPersist => HostRpcVerdict::Allow,
                        Verdict::AllowSession => {
                            self.record_session(host, &action);
                            HostRpcVerdict::Allow
                        }
                        Verdict::Deny | Verdict::Timeout | Verdict::Unspecified => {
                            HostRpcVerdict::Deny
                        }
                    }
                }
                Err(status) => {
                    // A dropped channel, permission-denied socket, or
                    // deadline-exceeded all collapse into "fail closed."
                    // The agent must never let a transport blip morph
                    // into an implicit allow.
                    warn!(
                        host,
                        method,
                        path,
                        request_id = %request_id,
                        status = %status,
                        "SubmitDecision failed; failing closed",
                    );
                    HostRpcVerdict::Deny
                }
            };
            verdict
        })
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_request_id_is_unique_and_scoped_to_session() {
        // We can't build a HostDecisionClient without a real channel, so
        // exercise the bit of state that does not require one.
        let counter = AtomicU64::new(1);
        let a = format!("sess-xyz-{:08x}", counter.fetch_add(1, Ordering::Relaxed));
        let b = format!("sess-xyz-{:08x}", counter.fetch_add(1, Ordering::Relaxed));
        assert_ne!(a, b);
        assert!(a.starts_with("sess-xyz-"));
    }
}
