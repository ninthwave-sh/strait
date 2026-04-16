//! Live decision coordination for container-backed launch sessions.
//!
//! Blocked requests are held open while an external client decides whether to
//! deny the request, allow just this occurrence, or allow every equivalent
//! request for the rest of the session. The coordination point is a pending
//! decision map keyed by the blocked-request ID emitted in observation events.

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use tokio::sync::oneshot;

/// Maximum number of blocked-request records retained for control lookups.
const DEFAULT_RECENT_BLOCKS_CAPACITY: usize = 1024;

/// How long to retain blocked-request history after it is seen.
///
/// This is intentionally longer than the live hold timeout so operators get a
/// stable `expired_blocked_id` error instead of a generic unknown ID when they
/// act on a request shortly after it times out.
const RECENT_BLOCK_TTL: Duration = Duration::from_secs(5 * 60);

/// Live decision sent from the control plane to a blocked request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// Allow only the currently held request.
    AllowOnce,
    /// Allow the currently held request and cache the match for the session.
    AllowSession,
    /// Deny the currently held request.
    Deny,
}

/// Error emitted when a control-plane decision cannot be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecisionError {
    /// The blocked-request ID does not exist or was already resolved.
    UnknownBlockedId,
    /// The blocked-request ID existed but the held request is no longer waiting.
    Expired,
    /// The blocked request has no durable persist suggestion.
    NoPersistSuggestion,
}

impl DecisionError {
    /// Stable machine-readable error code for the control protocol.
    pub fn code(&self) -> &'static str {
        match self {
            Self::UnknownBlockedId => "unknown_blocked_id",
            Self::Expired => "expired_blocked_id",
            Self::NoPersistSuggestion => "no_persist_suggestion",
        }
    }

    /// Human-readable error message for the control protocol.
    pub fn message(&self) -> String {
        match self {
            Self::UnknownBlockedId => {
                "no blocked request exists for the supplied blocked_id; it may have already been resolved or never existed"
                    .to_string()
            }
            Self::Expired => {
                "blocked request is no longer waiting for a live decision; retry the request to generate a fresh blocked_id"
                    .to_string()
            }
            Self::NoPersistSuggestion => {
                "blocked request does not include a persistable candidate exception"
                    .to_string()
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BlockState {
    Pending,
    Resolved,
    Expired,
}

#[derive(Debug, Clone)]
struct BlockRecord {
    match_key: String,
    persist_snippet: Option<String>,
    observed_at: Instant,
    state: BlockState,
}

/// Durable policy payload for a blocked request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PersistCandidate {
    /// Normalized match key for the blocked request.
    pub match_key: String,
    /// Minimal Cedar snippet to append to the durable policy source.
    pub cedar_snippet: String,
}

#[derive(Debug, Default)]
struct Inner {
    order: VecDeque<String>,
    blocks: HashMap<String, BlockRecord>,
    pending: HashMap<String, oneshot::Sender<Decision>>,
    session_allows: HashSet<String>,
}

/// Shared live-decision coordinator for a launch session.
#[derive(Debug)]
pub struct PendingDecisionStore {
    inner: Mutex<Inner>,
    capacity: usize,
    ttl: Duration,
}

impl Default for PendingDecisionStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PendingDecisionStore {
    /// Build a new store with default bounds.
    pub fn new() -> Self {
        Self::with_capacity_and_ttl(DEFAULT_RECENT_BLOCKS_CAPACITY, RECENT_BLOCK_TTL)
    }

    /// Build a new store with explicit bounds for tests.
    pub fn with_capacity_and_ttl(capacity: usize, ttl: Duration) -> Self {
        Self {
            inner: Mutex::new(Inner::default()),
            capacity: capacity.max(1),
            ttl,
        }
    }

    /// Return whether a session-scoped allow already exists for this match key.
    pub fn is_session_allowed(&self, match_key: &str) -> bool {
        let inner = self.inner.lock().expect("pending decision store poisoned");
        inner.session_allows.contains(match_key)
    }

    /// Register a blocked request and return the receiver the MITM handler
    /// should await.
    pub fn register_pending(
        &self,
        blocked_id: &str,
        match_key: &str,
    ) -> oneshot::Receiver<Decision> {
        self.register_pending_with_persist(blocked_id, match_key, None)
    }

    /// Register a blocked request and retain its persist suggestion.
    pub fn register_pending_with_persist(
        &self,
        blocked_id: &str,
        match_key: &str,
        persist_snippet: Option<String>,
    ) -> oneshot::Receiver<Decision> {
        self.register_pending_at(blocked_id, match_key, persist_snippet, Instant::now())
    }

    fn register_pending_at(
        &self,
        blocked_id: &str,
        match_key: &str,
        persist_snippet: Option<String>,
        now: Instant,
    ) -> oneshot::Receiver<Decision> {
        let mut inner = self.inner.lock().expect("pending decision store poisoned");
        Self::evict_expired(&mut inner, now, self.ttl);
        while inner.order.len() >= self.capacity {
            if let Some(oldest) = inner.order.pop_front() {
                inner.blocks.remove(&oldest);
                inner.pending.remove(&oldest);
            }
        }

        let (tx, rx) = oneshot::channel();
        inner.order.push_back(blocked_id.to_string());
        inner.blocks.insert(
            blocked_id.to_string(),
            BlockRecord {
                match_key: match_key.to_string(),
                persist_snippet,
                observed_at: now,
                state: BlockState::Pending,
            },
        );
        inner.pending.insert(blocked_id.to_string(), tx);
        rx
    }

    /// Resolve the blocked request by allowing just this occurrence.
    pub fn resolve_allow_once(&self, blocked_id: &str) -> Result<String, DecisionError> {
        self.resolve(blocked_id, Decision::AllowOnce, Instant::now())
    }

    /// Resolve the blocked request and allow future equivalent requests for the
    /// lifetime of the session.
    pub fn resolve_allow_session(&self, blocked_id: &str) -> Result<String, DecisionError> {
        self.resolve(blocked_id, Decision::AllowSession, Instant::now())
    }

    /// Resolve the blocked request by denying it.
    pub fn resolve_deny(&self, blocked_id: &str) -> Result<String, DecisionError> {
        self.resolve(blocked_id, Decision::Deny, Instant::now())
    }

    /// Return the durable persist suggestion for a pending blocked request.
    pub fn persist_candidate(&self, blocked_id: &str) -> Result<PersistCandidate, DecisionError> {
        self.persist_candidate_at(blocked_id, Instant::now())
    }

    fn persist_candidate_at(
        &self,
        blocked_id: &str,
        now: Instant,
    ) -> Result<PersistCandidate, DecisionError> {
        let mut inner = self.inner.lock().expect("pending decision store poisoned");
        Self::evict_expired(&mut inner, now, self.ttl);

        let Some(record) = inner.blocks.get_mut(blocked_id) else {
            return Err(DecisionError::UnknownBlockedId);
        };
        if now.duration_since(record.observed_at) > self.ttl {
            record.state = BlockState::Expired;
            inner.pending.remove(blocked_id);
            return Err(DecisionError::Expired);
        }
        match record.state {
            BlockState::Pending => {}
            BlockState::Resolved => return Err(DecisionError::UnknownBlockedId),
            BlockState::Expired => return Err(DecisionError::Expired),
        }

        let Some(cedar_snippet) = record.persist_snippet.clone() else {
            return Err(DecisionError::NoPersistSuggestion);
        };

        Ok(PersistCandidate {
            match_key: record.match_key.clone(),
            cedar_snippet,
        })
    }

    fn resolve(
        &self,
        blocked_id: &str,
        decision: Decision,
        now: Instant,
    ) -> Result<String, DecisionError> {
        let mut inner = self.inner.lock().expect("pending decision store poisoned");
        Self::evict_expired(&mut inner, now, self.ttl);

        let match_key = {
            let Some(record) = inner.blocks.get_mut(blocked_id) else {
                return Err(DecisionError::UnknownBlockedId);
            };
            if now.duration_since(record.observed_at) > self.ttl {
                record.state = BlockState::Expired;
                inner.pending.remove(blocked_id);
                return Err(DecisionError::Expired);
            }
            match record.state {
                BlockState::Pending => record.match_key.clone(),
                BlockState::Resolved => return Err(DecisionError::UnknownBlockedId),
                BlockState::Expired => return Err(DecisionError::Expired),
            }
        };

        if matches!(decision, Decision::AllowSession) {
            inner.session_allows.insert(match_key.clone());
        }

        let Some(sender) = inner.pending.remove(blocked_id) else {
            if matches!(decision, Decision::AllowSession) {
                inner.session_allows.remove(&match_key);
            }
            if let Some(record) = inner.blocks.get_mut(blocked_id) {
                record.state = BlockState::Expired;
            }
            return Err(DecisionError::Expired);
        };

        if sender.send(decision).is_err() {
            if matches!(decision, Decision::AllowSession) {
                inner.session_allows.remove(&match_key);
            }
            if let Some(record) = inner.blocks.get_mut(blocked_id) {
                record.state = BlockState::Expired;
            }
            return Err(DecisionError::Expired);
        }

        if let Some(record) = inner.blocks.get_mut(blocked_id) {
            record.state = BlockState::Resolved;
        }

        Ok(match_key)
    }

    /// Mark a blocked request as expired after the hold timeout fires.
    pub fn expire(&self, blocked_id: &str) {
        self.expire_at(blocked_id, Instant::now());
    }

    fn expire_at(&self, blocked_id: &str, now: Instant) {
        let mut inner = self.inner.lock().expect("pending decision store poisoned");
        Self::evict_expired(&mut inner, now, self.ttl);
        inner.pending.remove(blocked_id);
        if let Some(record) = inner.blocks.get_mut(blocked_id) {
            record.state = BlockState::Expired;
        }
    }

    #[cfg(test)]
    pub fn snapshot(&self) -> (usize, usize, usize) {
        let inner = self.inner.lock().expect("pending decision store poisoned");
        (
            inner.blocks.len(),
            inner.pending.len(),
            inner.session_allows.len(),
        )
    }

    fn evict_expired(inner: &mut Inner, now: Instant, ttl: Duration) {
        while let Some(front) = inner.order.front() {
            let remove = match inner.blocks.get(front) {
                Some(record) => now.duration_since(record.observed_at) > ttl,
                None => true,
            };
            if !remove {
                break;
            }
            let Some(front) = inner.order.pop_front() else {
                break;
            };
            inner.blocks.remove(&front);
            inner.pending.remove(&front);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_pending_tracks_blocked_request() {
        let store = PendingDecisionStore::new();
        let _rx = store.register_pending("abc", "http:GET api.example.com/repos");

        let (blocks, pending, session_allows) = store.snapshot();
        assert_eq!(blocks, 1);
        assert_eq!(pending, 1);
        assert_eq!(session_allows, 0);
    }

    #[tokio::test]
    async fn allow_once_resolves_current_request_only() {
        let store = PendingDecisionStore::new();
        let rx = store.register_pending("id-1", "http:GET api.example.com/repos");

        let match_key = store.resolve_allow_once("id-1").unwrap();
        assert_eq!(match_key, "http:GET api.example.com/repos");
        assert_eq!(rx.await.unwrap(), Decision::AllowOnce);
        assert!(!store.is_session_allowed(&match_key));
    }

    #[tokio::test]
    async fn allow_session_resolves_current_request_and_caches_match() {
        let store = PendingDecisionStore::new();
        let rx = store.register_pending("id-2", "http:GET api.example.com/repos");

        let match_key = store.resolve_allow_session("id-2").unwrap();
        assert_eq!(rx.await.unwrap(), Decision::AllowSession);
        assert!(store.is_session_allowed(&match_key));
    }

    #[tokio::test]
    async fn deny_resolves_current_request_without_caching_allow() {
        let store = PendingDecisionStore::new();
        let rx = store.register_pending("id-3", "http:POST api.example.com/repos");

        let match_key = store.resolve_deny("id-3").unwrap();
        assert_eq!(match_key, "http:POST api.example.com/repos");
        assert_eq!(rx.await.unwrap(), Decision::Deny);
        assert!(!store.is_session_allowed(&match_key));
    }

    #[test]
    fn unknown_blocked_id_returns_error() {
        let store = PendingDecisionStore::new();
        assert_eq!(
            store.resolve_allow_once("missing").unwrap_err(),
            DecisionError::UnknownBlockedId
        );
        assert_eq!(
            store.resolve_allow_session("missing").unwrap_err(),
            DecisionError::UnknownBlockedId
        );
        assert_eq!(
            store.resolve_deny("missing").unwrap_err(),
            DecisionError::UnknownBlockedId
        );
    }

    #[test]
    fn expired_blocked_id_returns_error() {
        let store = PendingDecisionStore::with_capacity_and_ttl(16, Duration::from_secs(60));
        let origin = Instant::now();
        let _rx = store.register_pending_at("old", "http:GET example.com/stale", None, origin);
        store.expire_at("old", origin + Duration::from_secs(11));

        assert_eq!(
            store
                .resolve("old", Decision::AllowOnce, origin + Duration::from_secs(12))
                .unwrap_err(),
            DecisionError::Expired
        );
    }

    #[test]
    fn recent_blocks_are_evicted_when_capacity_exceeded() {
        let store = PendingDecisionStore::with_capacity_and_ttl(2, Duration::from_secs(60));
        let _a = store.register_pending("a", "http:GET example/a");
        let _b = store.register_pending("b", "http:GET example/b");
        let _c = store.register_pending("c", "http:GET example/c");

        assert_eq!(
            store.resolve_allow_once("a").unwrap_err(),
            DecisionError::UnknownBlockedId
        );
        assert!(store.resolve_allow_once("b").is_ok());
        assert!(store.resolve_allow_once("c").is_ok());
    }

    #[test]
    fn resolving_twice_returns_unknown_for_second_attempt() {
        let store = PendingDecisionStore::new();
        let _rx = store.register_pending("id", "http:GET example.com/");
        store.resolve_allow_once("id").unwrap();

        assert_eq!(
            store.resolve_deny("id").unwrap_err(),
            DecisionError::UnknownBlockedId
        );
    }

    #[test]
    fn decision_error_codes_are_stable() {
        assert_eq!(DecisionError::UnknownBlockedId.code(), "unknown_blocked_id");
        assert_eq!(DecisionError::Expired.code(), "expired_blocked_id");
        assert_eq!(
            DecisionError::NoPersistSuggestion.code(),
            "no_persist_suggestion"
        );
        assert!(!DecisionError::UnknownBlockedId.message().is_empty());
        assert!(!DecisionError::Expired.message().is_empty());
        assert!(!DecisionError::NoPersistSuggestion.message().is_empty());
    }

    #[test]
    fn persist_candidate_returns_snippet_for_pending_request() {
        let store = PendingDecisionStore::new();
        let _rx = store.register_pending_with_persist(
            "id",
            "http:GET example.com/repos/org/repo",
            Some("permit(principal, action, resource);".to_string()),
        );

        let candidate = store.persist_candidate("id").unwrap();
        assert_eq!(candidate.match_key, "http:GET example.com/repos/org/repo");
        assert_eq!(
            candidate.cedar_snippet,
            "permit(principal, action, resource);"
        );
    }

    #[test]
    fn persist_candidate_rejects_requests_without_suggestion() {
        let store = PendingDecisionStore::new();
        let _rx = store.register_pending("id", "http:GET example.com/repos/org/repo");

        assert_eq!(
            store.persist_candidate("id").unwrap_err(),
            DecisionError::NoPersistSuggestion
        );
    }
}
