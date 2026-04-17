//! Host-side hold-and-resume decision queue.
//!
//! H-HCP-6 retargets the former in-container live-decision coordinator at
//! the host control plane. The queue owns the state an operator (desktop
//! app or CLI stub) needs to resolve a blocked request:
//!
//! - A pending map keyed by `request_id` so the agent's `SubmitDecision`
//!   call can park itself on a `oneshot::Receiver` and wake up when an
//!   operator produces a verdict.
//! - A default hold timeout. If no operator resolves a held request within
//!   the window, `hold()` returns [`Verdict::Timeout`] so the agent fails
//!   closed. A container with no attached desktop therefore behaves
//!   identically to "operator said deny", which is the invariant the test
//!   plan calls out.
//!
//! The queue does *not* own the persisted rule store, the session allow
//! cache, or the credential cache; those are separate concerns owned by
//! sibling modules (see `persist.rs`) so each can grow independently.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use strait_proto::v1::Verdict;
use tokio::sync::oneshot;

/// Default hold window: if no operator resolves a held request within
/// this time, the queue fires a `Timeout` verdict.
///
/// Thirty seconds is long enough for a human to respond to a desktop
/// notification and short enough to keep an unattended container from
/// wedging on every blocked request. Tests override this with a much
/// shorter window so the "default-deny" path is observable in CI time.
pub const DEFAULT_HOLD_TIMEOUT: Duration = Duration::from_secs(30);

/// Static description of a blocked request, for operator UIs and tests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingSummary {
    /// Client-generated id the agent passed in `SubmitDecisionRequest`.
    pub request_id: String,
    /// Session id the host assigned at `RegisterContainer`.
    pub session_id: String,
    /// Host the agent saw in the blocked request.
    pub host: String,
    /// Cedar action id (for example `http:GET`).
    pub action: String,
    /// HTTP method, upper-cased.
    pub method: String,
    /// URL path as seen by the proxy.
    pub path: String,
    /// Short explanation the agent supplied (if any).
    pub explanation: String,
    /// Wall-clock time (in Unix milliseconds) the agent observed the block.
    pub observed_at_unix_ms: i64,
}

/// Info the caller passes to `hold()` beyond the correlation id.
#[derive(Debug, Clone)]
pub struct HoldInfo {
    pub session_id: String,
    pub host: String,
    pub action: String,
    pub method: String,
    pub path: String,
    pub explanation: String,
    pub observed_at_unix_ms: i64,
}

/// Errors surfaced by resolve paths.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// No entry exists for the given request id. Either the request
    /// already resolved, already timed out, or never existed.
    UnknownRequest,
    /// A different caller is already holding the same request id. The
    /// agent is responsible for assigning unique ids per session.
    Duplicate,
}

impl std::fmt::Display for DecisionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownRequest => f.write_str("unknown request id"),
            Self::Duplicate => f.write_str("duplicate request id"),
        }
    }
}

impl std::error::Error for DecisionError {}

#[derive(Debug)]
struct Pending {
    summary: PendingSummary,
    tx: Option<oneshot::Sender<Verdict>>,
    #[allow(dead_code)] // kept for future operator UI ordering / debugging
    observed_at: Instant,
}

#[derive(Debug, Default)]
struct Inner {
    pending: HashMap<String, Pending>,
}

/// Shared hold-and-resume queue.
///
/// Cheap to clone through `Arc`; the gRPC service holds one and hands the
/// same instance to any resolver paths (library-level API, tests, future
/// desktop RPCs).
#[derive(Debug)]
pub struct DecisionQueue {
    inner: Mutex<Inner>,
    default_timeout: Duration,
}

impl Default for DecisionQueue {
    fn default() -> Self {
        Self::new(DEFAULT_HOLD_TIMEOUT)
    }
}

impl DecisionQueue {
    /// Build a queue with an explicit hold timeout.
    pub fn new(default_timeout: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            default_timeout,
        }
    }

    /// Hold timeout the queue applies to `hold()` calls.
    pub fn default_timeout(&self) -> Duration {
        self.default_timeout
    }

    /// Park a blocked request and await the operator's verdict.
    ///
    /// Returns `Verdict::Timeout` if no operator resolves within the
    /// queue's hold window. On timeout the entry is removed so a later
    /// resolve for the same request id reports `UnknownRequest`.
    ///
    /// Returns `Duplicate` as the error via the caller: duplicate request
    /// ids are treated as a programming error; `hold()` panics-free by
    /// returning `Verdict::Timeout` immediately rather than overwriting a
    /// live `oneshot::Sender`. See [`hold_checked`] for the variant that
    /// surfaces the `Duplicate` case explicitly.
    pub async fn hold(&self, request_id: &str, info: HoldInfo) -> Verdict {
        match self.hold_checked(request_id, info).await {
            Ok(v) => v,
            // Duplicate is a caller-side bug; the safest behavior from the
            // agent's perspective is "fail closed" exactly like a timeout.
            Err(DecisionError::Duplicate) => Verdict::Timeout,
            Err(DecisionError::UnknownRequest) => Verdict::Timeout,
        }
    }

    /// Like [`hold`](Self::hold) but returns `Err(Duplicate)` instead of
    /// silently collapsing the second hold to `Timeout`. Exposed for tests
    /// that want to assert the invariant directly.
    pub async fn hold_checked(
        &self,
        request_id: &str,
        info: HoldInfo,
    ) -> Result<Verdict, DecisionError> {
        let rx = self.register(request_id, info)?;

        match tokio::time::timeout(self.default_timeout, rx).await {
            Ok(Ok(verdict)) => {
                // Resolver removed the entry; nothing to do.
                Ok(verdict)
            }
            Ok(Err(_recv_err)) => {
                // Sender was dropped without a verdict. Treat as timeout
                // — from the agent's perspective there is nothing else
                // safe to do.
                self.remove_if_pending(request_id);
                Ok(Verdict::Timeout)
            }
            Err(_elapsed) => {
                self.remove_if_pending(request_id);
                Ok(Verdict::Timeout)
            }
        }
    }

    fn register(
        &self,
        request_id: &str,
        info: HoldInfo,
    ) -> Result<oneshot::Receiver<Verdict>, DecisionError> {
        let mut inner = self.inner.lock().expect("decision queue poisoned");
        if inner.pending.contains_key(request_id) {
            return Err(DecisionError::Duplicate);
        }
        let (tx, rx) = oneshot::channel();
        let summary = PendingSummary {
            request_id: request_id.to_string(),
            session_id: info.session_id,
            host: info.host,
            action: info.action,
            method: info.method,
            path: info.path,
            explanation: info.explanation,
            observed_at_unix_ms: info.observed_at_unix_ms,
        };
        inner.pending.insert(
            request_id.to_string(),
            Pending {
                summary,
                tx: Some(tx),
                observed_at: Instant::now(),
            },
        );
        Ok(rx)
    }

    fn remove_if_pending(&self, request_id: &str) {
        let mut inner = self.inner.lock().expect("decision queue poisoned");
        inner.pending.remove(request_id);
    }

    /// Resolve a held request. Returns the summary of what was resolved so
    /// the caller can react (for example, persist the matched rule when
    /// the verdict is [`Verdict::AllowPersist`]).
    pub fn resolve(
        &self,
        request_id: &str,
        verdict: Verdict,
    ) -> Result<PendingSummary, DecisionError> {
        let mut inner = self.inner.lock().expect("decision queue poisoned");
        let Some(mut entry) = inner.pending.remove(request_id) else {
            return Err(DecisionError::UnknownRequest);
        };
        let summary = entry.summary.clone();
        if let Some(tx) = entry.tx.take() {
            // Ignore the send error: the waiter may have timed out
            // between `remove` and `send`. We still return Ok because the
            // caller's intent ("mark this request resolved") succeeded.
            let _ = tx.send(verdict);
        }
        Ok(summary)
    }

    /// Return every currently-pending decision. Order is unspecified.
    pub fn pending(&self) -> Vec<PendingSummary> {
        let inner = self.inner.lock().expect("decision queue poisoned");
        inner.pending.values().map(|p| p.summary.clone()).collect()
    }

    /// Look up a pending decision without removing it.
    pub fn pending_info(&self, request_id: &str) -> Option<PendingSummary> {
        let inner = self.inner.lock().expect("decision queue poisoned");
        inner.pending.get(request_id).map(|p| p.summary.clone())
    }

    /// Drop any held requests for the given session. Returns the number of
    /// entries removed. Used when a container disconnects or the session
    /// is ended; the agent will re-issue `SubmitDecision` if the same
    /// request actually shows up again.
    pub fn drop_session(&self, session_id: &str) -> usize {
        let mut inner = self.inner.lock().expect("decision queue poisoned");
        let to_remove: Vec<String> = inner
            .pending
            .iter()
            .filter(|(_, p)| p.summary.session_id == session_id)
            .map(|(k, _)| k.clone())
            .collect();
        let n = to_remove.len();
        for k in to_remove {
            inner.pending.remove(&k);
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn info_for(session: &str, host: &str, action: &str) -> HoldInfo {
        HoldInfo {
            session_id: session.to_string(),
            host: host.to_string(),
            action: action.to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            explanation: String::new(),
            observed_at_unix_ms: 0,
        }
    }

    #[tokio::test]
    async fn resolve_delivers_verdict_to_holder() {
        let q = DecisionQueue::new(Duration::from_secs(5));
        let q = std::sync::Arc::new(q);

        let q_for_hold = q.clone();
        let handle = tokio::spawn(async move {
            q_for_hold
                .hold("req-1", info_for("sess", "api.github.com", "http:GET"))
                .await
        });

        // Give the hold a chance to register before we resolve it.
        tokio::task::yield_now().await;
        tokio::time::sleep(Duration::from_millis(10)).await;

        let summary = q.resolve("req-1", Verdict::AllowOnce).unwrap();
        assert_eq!(summary.host, "api.github.com");

        let verdict = handle.await.unwrap();
        assert_eq!(verdict, Verdict::AllowOnce);
        assert!(q.pending().is_empty());
    }

    #[tokio::test]
    async fn timeout_fires_default_deny_when_no_responder() {
        let q = DecisionQueue::new(Duration::from_millis(40));
        let verdict = q
            .hold("req-t", info_for("sess", "api.github.com", "http:GET"))
            .await;
        assert_eq!(verdict, Verdict::Timeout);
        assert!(q.pending().is_empty());
    }

    #[tokio::test]
    async fn resolve_before_hold_fails() {
        let q = DecisionQueue::new(Duration::from_secs(1));
        let err = q.resolve("never", Verdict::AllowOnce).unwrap_err();
        assert_eq!(err, DecisionError::UnknownRequest);
    }

    #[tokio::test]
    async fn duplicate_hold_returns_duplicate_error() {
        let q = DecisionQueue::new(Duration::from_millis(50));
        let q = std::sync::Arc::new(q);

        let q_bg = q.clone();
        let bg = tokio::spawn(async move {
            q_bg.hold_checked("req-dup", info_for("sess", "host", "http:GET"))
                .await
        });

        // Give the background hold a chance to register.
        tokio::time::sleep(Duration::from_millis(5)).await;

        let err = q
            .hold_checked("req-dup", info_for("sess", "host", "http:GET"))
            .await
            .unwrap_err();
        assert_eq!(err, DecisionError::Duplicate);

        // Let the background hold time out cleanly.
        let _ = bg.await;
    }

    #[tokio::test]
    async fn pending_exposes_live_entries_until_resolved() {
        let q = DecisionQueue::new(Duration::from_secs(5));
        let q = std::sync::Arc::new(q);

        let q_bg = q.clone();
        let bg = tokio::spawn(async move {
            q_bg.hold("r1", info_for("sess-a", "api.github.com", "http:GET"))
                .await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        let pending = q.pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].request_id, "r1");
        assert_eq!(pending[0].session_id, "sess-a");

        q.resolve("r1", Verdict::Deny).unwrap();
        let verdict = bg.await.unwrap();
        assert_eq!(verdict, Verdict::Deny);
        assert!(q.pending().is_empty());
    }

    #[tokio::test]
    async fn drop_session_removes_only_matching_entries() {
        let q = DecisionQueue::new(Duration::from_secs(5));
        let q = std::sync::Arc::new(q);

        let q_a = q.clone();
        let q_b = q.clone();
        let a = tokio::spawn(async move {
            q_a.hold("a1", info_for("sess-a", "api.github.com", "http:GET"))
                .await
        });
        let b = tokio::spawn(async move {
            q_b.hold("b1", info_for("sess-b", "example.net", "http:POST"))
                .await
        });

        tokio::time::sleep(Duration::from_millis(10)).await;
        let removed = q.drop_session("sess-a");
        assert_eq!(removed, 1);

        // Task a's hold now wakes up via sender-drop → Timeout.
        let va = a.await.unwrap();
        assert_eq!(va, Verdict::Timeout);

        // Task b is untouched; resolving it delivers the verdict.
        q.resolve("b1", Verdict::AllowOnce).unwrap();
        let vb = b.await.unwrap();
        assert_eq!(vb, Verdict::AllowOnce);
    }
}
