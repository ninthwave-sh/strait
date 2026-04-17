//! gRPC service implementation for `strait-host`.
//!
//! This module wires the generated `strait_proto::v1::StraitHost` service
//! trait to a concrete implementation. The following RPCs are live today:
//!
//!   * `RegisterContainer` and `Heartbeat` -- session management shipped
//!     in H-HCP-2.
//!   * `StreamRules` -- multi-container rule store backed by SQLite,
//!     shipped in H-HCP-3. Delivers an initial snapshot terminated by
//!     `KIND_SNAPSHOT_END` and then tails a broadcast channel for live
//!     updates, filtering by scope so default-scope rules reach every
//!     subscribing session and session-scope rules reach only their owner.
//!   * `SubmitDecision` -- hold-and-resume decision queue plus the
//!     persist action, shipped in H-HCP-6. Blocked requests park on the
//!     queue until an operator resolves them; if a matching persisted
//!     rule already exists the call short-circuits with
//!     `Verdict::AllowPersist` without ever touching the queue.
//!
//! `FetchCredential` and `StreamObservations` still return
//! `Status::unimplemented` with a pointer to the follow-on work item.
//!
//! Tests that need different behaviour (for example an echoing
//! `SubmitDecision` stub for latency measurements) can define their own
//! `StraitHost` impl; this struct is just the default production handler.

use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use futures_core::Stream;
use strait_proto::v1::strait_host_server::StraitHost;
use strait_proto::v1::{
    rule_event, FetchCredentialRequest, FetchCredentialResponse, HeartbeatRequest,
    HeartbeatResponse, ObservationEvent, RegisterContainerRequest, RegisterContainerResponse,
    RuleEvent, StreamObservationsAck, StreamRulesRequest, SubmitDecisionRequest,
    SubmitDecisionResponse, Verdict,
};
use tokio::sync::broadcast::error::RecvError;
use tonic::{Request, Response, Status, Streaming};
use tracing::warn;

use crate::decisions::{DecisionError, DecisionQueue, HoldInfo, PendingSummary};
use crate::rule_store::{Rule, RuleAction, RuleChange, RuleDuration, RuleStore};

/// Production implementation of the `StraitHost` gRPC service.
///
/// The service is Clone + Send + Sync so it can be cheaply handed to both
/// the Unix-socket and TCP `tonic::transport::Server` instances. Internal
/// state is held behind atomics/arcs so neither listener sees the other's
/// concurrent mutations.
#[derive(Debug, Clone)]
pub struct StraitHostService {
    sessions: Arc<AtomicU64>,
    decisions: Arc<DecisionQueue>,
    rules: Arc<RuleStore>,
}

impl Default for StraitHostService {
    fn default() -> Self {
        Self::new()
    }
}

impl StraitHostService {
    /// Fresh service with an in-memory rule store and a default decision
    /// queue. The in-memory store is convenient for tests and smoke-check
    /// invocations; production callers use
    /// [`StraitHostService::with_state`] to plug in a persistent store.
    pub fn new() -> Self {
        let rules = RuleStore::in_memory().expect("in-memory rule store should always open");
        Self::with_state(Arc::new(DecisionQueue::default()), Arc::new(rules))
    }

    /// Build a service that shares the supplied decision queue and rule
    /// store with other subsystems (the desktop-facing resolver, the
    /// rule-stream implementation, etc.).
    pub fn with_state(decisions: Arc<DecisionQueue>, rules: Arc<RuleStore>) -> Self {
        Self {
            sessions: Arc::new(AtomicU64::new(0)),
            decisions,
            rules,
        }
    }

    /// Back-compat convenience: build a service with just a rule store and
    /// the default decision queue. Used by the binary entry point and
    /// pre-existing tests.
    pub fn with_rule_store(rules: Arc<RuleStore>) -> Self {
        Self::with_state(Arc::new(DecisionQueue::default()), rules)
    }

    /// Number of `RegisterContainer` calls served since the process started.
    /// Exposed for operator health endpoints and tests.
    pub fn sessions_registered(&self) -> u64 {
        self.sessions.load(Ordering::Relaxed)
    }

    /// Shared decision queue handle, for desktop-side resolvers and tests.
    pub fn decision_queue(&self) -> Arc<DecisionQueue> {
        self.decisions.clone()
    }

    /// Borrow the rule store the service is wired to. Callers can use this
    /// to insert rules from elsewhere and watch them flow through
    /// `StreamRules` to connected agents.
    pub fn rule_store(&self) -> &Arc<RuleStore> {
        &self.rules
    }

    /// Resolve a held `SubmitDecision` request with an operator verdict.
    ///
    /// When the verdict is [`Verdict::AllowPersist`], the matched
    /// `(host, action)` is written into the rule store under
    /// [`RuleStore::DEFAULT_SCOPE`] before the waiter is unparked; that way
    /// a second in-flight request from any session that matches the newly
    /// persisted rule short-circuits in `submit_decision` without bothering
    /// the operator again.
    ///
    /// This is the library-level hook the desktop app and test harnesses
    /// drive. The proto-level "operator" surface will be added in a later
    /// item (for example M-HCP-7); until then, callers embed the host
    /// crate to reach this entry point.
    pub fn resolve_decision(
        &self,
        request_id: &str,
        verdict: Verdict,
    ) -> Result<PendingSummary, ResolveError> {
        if matches!(verdict, Verdict::AllowPersist) {
            // Look up the pending info so we know what to persist.
            let info = self
                .decisions
                .pending_info(request_id)
                .ok_or(ResolveError::Decision(DecisionError::UnknownRequest))?;
            persist_allow_rule(
                &self.rules,
                RuleStore::DEFAULT_SCOPE,
                &info.host,
                &info.action,
            )
            .map_err(|e| ResolveError::Persist(e.to_string()))?;
        }
        self.decisions
            .resolve(request_id, verdict)
            .map_err(ResolveError::Decision)
    }
}

/// Error surfaced by [`StraitHostService::resolve_decision`].
#[derive(Debug)]
pub enum ResolveError {
    /// The decision queue rejected the resolve.
    Decision(DecisionError),
    /// The rule store could not persist the rule. The `String` is the
    /// underlying error message; we avoid leaking `anyhow::Error` into the
    /// public surface so this type stays `Clone`-ish in the future if we
    /// need it to be.
    Persist(String),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Decision(d) => write!(f, "{d}"),
            Self::Persist(m) => write!(f, "persist rule: {m}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// Stream type returned by server-streaming RPCs. Boxed so the production
/// impl and any test double share a single type.
pub type RuleEventStream = Pin<Box<dyn Stream<Item = Result<RuleEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl StraitHost for StraitHostService {
    async fn register_container(
        &self,
        request: Request<RegisterContainerRequest>,
    ) -> Result<Response<RegisterContainerResponse>, Status> {
        let req = request.into_inner();
        if req.container_id.is_empty() {
            return Err(Status::invalid_argument("container_id must be set"));
        }

        let seq = self.sessions.fetch_add(1, Ordering::Relaxed) + 1;
        let session_id = format!("sess-{seq:08x}");
        Ok(Response::new(RegisterContainerResponse {
            session_id,
            default_scope: RuleStore::DEFAULT_SCOPE.to_string(),
            registered_at_unix_ms: now_unix_ms(),
            rules_resume_token: String::new(),
        }))
    }

    async fn submit_decision(
        &self,
        request: Request<SubmitDecisionRequest>,
    ) -> Result<Response<SubmitDecisionResponse>, Status> {
        let inner = request.into_inner();
        if inner.request_id.is_empty() {
            return Err(Status::invalid_argument("request_id must be set"));
        }
        if inner.host.is_empty() {
            return Err(Status::invalid_argument("host must be set"));
        }
        let action = if inner.method.is_empty() {
            "http:*".to_string()
        } else {
            format!("http:{}", inner.method.to_ascii_uppercase())
        };

        // Fast path: a persisted rule already covers this request. Rules
        // land under default scope or the session's own scope; the rule
        // store's `get` is keyed by the rule_id convention used on
        // persist. We look up both scopes explicitly rather than scanning
        // every rule in the store.
        if let Some(rule) =
            lookup_persisted_allow(&self.rules, &inner.session_id, &inner.host, &action)
                .map_err(|e| Status::internal(format!("rule lookup: {e:#}")))?
        {
            return Ok(Response::new(SubmitDecisionResponse {
                request_id: inner.request_id,
                verdict: Verdict::AllowPersist as i32,
                reason: format!("matched persisted rule {}", rule.rule_id),
                decided_at_unix_ms: now_unix_ms(),
                credential: None,
            }));
        }

        // Slow path: park the request until an operator decides or the
        // hold window elapses. The queue enforces the timeout; a missing
        // operator therefore falls through to Verdict::Timeout, which the
        // agent treats as default-deny.
        let info = HoldInfo {
            session_id: inner.session_id.clone(),
            host: inner.host.clone(),
            action: action.clone(),
            method: inner.method.clone(),
            path: inner.path.clone(),
            explanation: inner.explanation.clone(),
            observed_at_unix_ms: inner.observed_at_unix_ms,
        };
        let verdict = self.decisions.hold(&inner.request_id, info).await;
        let reason = match verdict {
            Verdict::Timeout => "no operator responded before timeout".to_string(),
            Verdict::Deny => "operator denied".to_string(),
            Verdict::AllowOnce => "operator allowed for this request".to_string(),
            Verdict::AllowSession => "operator allowed for the session".to_string(),
            Verdict::AllowPersist => "operator persisted allow rule".to_string(),
            Verdict::Unspecified => String::new(),
        };
        Ok(Response::new(SubmitDecisionResponse {
            request_id: inner.request_id,
            verdict: verdict as i32,
            reason,
            decided_at_unix_ms: now_unix_ms(),
            credential: None,
        }))
    }

    async fn fetch_credential(
        &self,
        _request: Request<FetchCredentialRequest>,
    ) -> Result<Response<FetchCredentialResponse>, Status> {
        // Credential store moves off the agent in H-HCP-4.
        Err(Status::unimplemented(
            "FetchCredential is implemented in H-HCP-4",
        ))
    }

    type StreamRulesStream = RuleEventStream;

    async fn stream_rules(
        &self,
        request: Request<StreamRulesRequest>,
    ) -> Result<Response<Self::StreamRulesStream>, Status> {
        let req = request.into_inner();
        if req.session_id.is_empty() {
            return Err(Status::invalid_argument("session_id must be set"));
        }
        let session_id = req.session_id;

        // Subscribe *before* reading the snapshot so no updates fall between
        // the snapshot read and the first tail. Events seen in both the
        // snapshot and the subscription are de-duplicated by `version_token`
        // below.
        let mut updates = self.rules.subscribe();
        let snapshot = self
            .rules
            .snapshot_for_session(&session_id)
            .map_err(|e| Status::internal(format!("rule snapshot: {e:#}")))?;

        let stream = async_stream::stream! {
            // Track the version tokens we already delivered in the snapshot
            // so a concurrent add we saw in the SELECT *and* on the channel
            // is not delivered twice. Rule ids are unique per store, so the
            // map key is the rule id; the value is the last version token
            // we emitted.
            let mut seen: std::collections::HashMap<String, String> = std::collections::HashMap::with_capacity(snapshot.len());
            for rule in snapshot.into_iter() {
                seen.insert(rule.rule_id.clone(), rule.version_token.clone());
                yield Ok(rule_add_event(&rule));
            }
            yield Ok(RuleEvent {
                kind: rule_event::Kind::SnapshotEnd as i32,
                rule_id: String::new(),
                scope: String::new(),
                cedar_source: String::new(),
                version_token: String::new(),
            });

            loop {
                match updates.recv().await {
                    Ok(change) => {
                        if let Some(event) = event_for_session(&change, &session_id) {
                            // De-duplicate snapshot-vs-tail overlap: if we
                            // already delivered this exact version_token for
                            // this rule, skip it. Remove records clear the
                            // entry so a subsequent re-add is re-delivered.
                            match (&change, seen.get(&event.rule_id)) {
                                (RuleChange::Add(_) | RuleChange::Update(_), Some(prev))
                                    if prev == &event.version_token => continue,
                                _ => {}
                            }
                            match &change {
                                RuleChange::Add(r) | RuleChange::Update(r) => {
                                    seen.insert(r.rule_id.clone(), r.version_token.clone());
                                }
                                RuleChange::Remove { rule_id, .. } => {
                                    seen.remove(rule_id);
                                }
                            }
                            yield Ok(event);
                        }
                    }
                    Err(RecvError::Lagged(skipped)) => {
                        // The subscriber fell behind the broadcast buffer.
                        // Log and keep tailing; the agent is expected to
                        // reconnect and resume from its last version token
                        // if it cares about a perfect log.
                        warn!(
                            target: "strait_host::grpc",
                            session_id = %session_id,
                            skipped,
                            "rule stream subscriber lagged"
                        );
                    }
                    Err(RecvError::Closed) => break,
                }
            }
        };

        Ok(Response::new(Box::pin(stream)))
    }

    async fn stream_observations(
        &self,
        _request: Request<Streaming<ObservationEvent>>,
    ) -> Result<Response<StreamObservationsAck>, Status> {
        // Observation forwarding lands in M-HCP-5.
        Err(Status::unimplemented(
            "StreamObservations is implemented in M-HCP-5",
        ))
    }

    async fn heartbeat(
        &self,
        request: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        let now = now_unix_ms();
        // `sent_at_unix_ms` is echoed through `received_at_unix_ms` so
        // clients can measure round-trip latency without a second RPC.
        let received_at_unix_ms = request.into_inner().sent_at_unix_ms;
        Ok(Response::new(HeartbeatResponse {
            received_at_unix_ms,
            server_time_unix_ms: now,
        }))
    }
}

fn now_unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Compose the conventional rule id for a `(scope, host, action)` triple
/// persisted via the `SubmitDecision` → `AllowPersist` flow. The id is
/// stable so a second persist for the same triple upserts the existing
/// row, and a lookup at `submit_decision` time can find the rule without
/// scanning every entry in the store.
fn persisted_allow_rule_id(scope: &str, host: &str, action: &str) -> String {
    let host = host.to_ascii_lowercase();
    format!("persist-allow:{scope}:{host}:{action}")
}

/// Cedar source for a single persist-allow rule. The rule is intentionally
/// narrow: the decision pipeline already routes on `(host, action)`, so a
/// broadly-worded `permit` that always fires is exactly what the host
/// evaluator wants once the agent has matched the request against this
/// rule id. Richer Cedar grammar belongs to operator-authored rules, not
/// to the implicit persist button.
fn persist_cedar_source(host: &str, action: &str) -> String {
    format!("// auto-persisted allow for {host} / {action}\npermit(principal, action, resource);\n")
}

fn persist_allow_rule(
    rules: &RuleStore,
    scope: &str,
    host: &str,
    action: &str,
) -> anyhow::Result<Rule> {
    let rule_id = persisted_allow_rule_id(scope, host, action);
    rules.upsert(Rule {
        rule_id,
        scope: scope.to_string(),
        cedar_source: persist_cedar_source(host, action),
        action: RuleAction::Allow,
        duration: RuleDuration::Persist,
        ttl_unix_ms: None,
        version_token: String::new(),
    })
}

/// Look up a persisted-allow rule that covers `(session_id, host, action)`.
/// Checks the session-scoped rule first (narrower wins), then the
/// default-scoped rule. Returns `Ok(None)` when neither exists so
/// `submit_decision` falls back to the hold queue.
fn lookup_persisted_allow(
    rules: &RuleStore,
    session_id: &str,
    host: &str,
    action: &str,
) -> anyhow::Result<Option<Rule>> {
    if !session_id.is_empty() {
        let id = persisted_allow_rule_id(session_id, host, action);
        if let Some(rule) = rules.get(&id)? {
            if matches!(rule.action, RuleAction::Allow) {
                return Ok(Some(rule));
            }
        }
    }
    let id = persisted_allow_rule_id(RuleStore::DEFAULT_SCOPE, host, action);
    if let Some(rule) = rules.get(&id)? {
        if matches!(rule.action, RuleAction::Allow) {
            return Ok(Some(rule));
        }
    }
    Ok(None)
}

fn rule_add_event(rule: &Rule) -> RuleEvent {
    RuleEvent {
        kind: rule_event::Kind::Add as i32,
        rule_id: rule.rule_id.clone(),
        scope: rule.scope.clone(),
        cedar_source: rule.cedar_source.clone(),
        version_token: rule.version_token.clone(),
    }
}

/// Translate a [`RuleChange`] into a `RuleEvent` visible to the given
/// session, or `None` if the change is outside the session's scope. Session
/// sees: `DEFAULT_SCOPE` plus its own `session_id`.
fn event_for_session(change: &RuleChange, session_id: &str) -> Option<RuleEvent> {
    let (kind, rule_id, scope, cedar_source, version_token) = match change {
        RuleChange::Add(r) => (
            rule_event::Kind::Add,
            r.rule_id.clone(),
            r.scope.clone(),
            r.cedar_source.clone(),
            r.version_token.clone(),
        ),
        RuleChange::Update(r) => (
            rule_event::Kind::Update,
            r.rule_id.clone(),
            r.scope.clone(),
            r.cedar_source.clone(),
            r.version_token.clone(),
        ),
        RuleChange::Remove {
            rule_id,
            scope,
            version_token,
        } => (
            rule_event::Kind::Remove,
            rule_id.clone(),
            scope.clone(),
            String::new(),
            version_token.clone(),
        ),
    };
    if scope != RuleStore::DEFAULT_SCOPE && scope != session_id {
        return None;
    }
    Some(RuleEvent {
        kind: kind as i32,
        rule_id,
        scope,
        cedar_source,
        version_token,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio_stream::StreamExt;

    fn test_rule(id: &str, scope: &str) -> Rule {
        Rule {
            rule_id: id.into(),
            scope: scope.into(),
            cedar_source: format!("permit(principal, action, resource == \"{id}\");"),
            action: RuleAction::Allow,
            duration: RuleDuration::Persist,
            ttl_unix_ms: None,
            version_token: String::new(),
        }
    }

    #[tokio::test]
    async fn register_container_assigns_unique_session_ids() {
        let svc = StraitHostService::new();
        let a = svc
            .register_container(Request::new(RegisterContainerRequest {
                container_id: "a".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        let b = svc
            .register_container(Request::new(RegisterContainerRequest {
                container_id: "b".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_ne!(a.session_id, b.session_id, "session ids should differ");
        assert_eq!(svc.sessions_registered(), 2);
        assert_eq!(a.default_scope, RuleStore::DEFAULT_SCOPE);
    }

    #[tokio::test]
    async fn register_container_rejects_empty_id() {
        let svc = StraitHostService::new();
        let err = svc
            .register_container(Request::new(RegisterContainerRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn submit_decision_rejects_empty_request_id() {
        let svc = StraitHostService::new();
        let err = svc
            .submit_decision(Request::new(SubmitDecisionRequest {
                host: "api.github.com".into(),
                method: "GET".into(),
                ..Default::default()
            }))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn submit_decision_short_circuits_on_persisted_rule() {
        let decisions = Arc::new(DecisionQueue::new(Duration::from_millis(50)));
        let rules = Arc::new(RuleStore::in_memory().unwrap());
        // Pre-seed the rule the way resolve_decision(AllowPersist) would.
        persist_allow_rule(
            &rules,
            RuleStore::DEFAULT_SCOPE,
            "api.github.com",
            "http:GET",
        )
        .unwrap();
        let svc = StraitHostService::with_state(decisions, rules);

        let resp = svc
            .submit_decision(Request::new(SubmitDecisionRequest {
                session_id: "sess-any".into(),
                request_id: "r1".into(),
                method: "GET".into(),
                host: "api.github.com".into(),
                path: "/".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.verdict, Verdict::AllowPersist as i32);
        assert!(resp.reason.contains("persisted rule"));
    }

    #[tokio::test]
    async fn submit_decision_times_out_with_no_responder() {
        let decisions = Arc::new(DecisionQueue::new(Duration::from_millis(30)));
        let rules = Arc::new(RuleStore::in_memory().unwrap());
        let svc = StraitHostService::with_state(decisions, rules);

        let resp = svc
            .submit_decision(Request::new(SubmitDecisionRequest {
                session_id: "sess".into(),
                request_id: "r-timeout".into(),
                method: "GET".into(),
                host: "api.github.com".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.verdict, Verdict::Timeout as i32);
        assert!(!resp.reason.is_empty());
    }

    #[tokio::test]
    async fn submit_decision_resolves_when_operator_allows_session() {
        let decisions = Arc::new(DecisionQueue::new(Duration::from_secs(5)));
        let rules = Arc::new(RuleStore::in_memory().unwrap());
        let svc = StraitHostService::with_state(decisions.clone(), rules);

        let svc_bg = svc.clone();
        let handle = tokio::spawn(async move {
            svc_bg
                .submit_decision(Request::new(SubmitDecisionRequest {
                    session_id: "sess".into(),
                    request_id: "r-session".into(),
                    method: "GET".into(),
                    host: "api.github.com".into(),
                    ..Default::default()
                }))
                .await
        });

        // Wait for the hold to register before resolving.
        for _ in 0..50 {
            if decisions.pending_info("r-session").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        svc.resolve_decision("r-session", Verdict::AllowSession)
            .unwrap();
        let resp = handle.await.unwrap().unwrap().into_inner();
        assert_eq!(resp.verdict, Verdict::AllowSession as i32);
    }

    #[tokio::test]
    async fn resolve_with_persist_writes_rule() {
        let decisions = Arc::new(DecisionQueue::new(Duration::from_secs(5)));
        let rules = Arc::new(RuleStore::in_memory().unwrap());
        let svc = StraitHostService::with_state(decisions.clone(), rules.clone());

        let svc_bg = svc.clone();
        let handle = tokio::spawn(async move {
            svc_bg
                .submit_decision(Request::new(SubmitDecisionRequest {
                    session_id: "sess".into(),
                    request_id: "r-persist".into(),
                    method: "GET".into(),
                    host: "api.github.com".into(),
                    ..Default::default()
                }))
                .await
        });

        for _ in 0..50 {
            if decisions.pending_info("r-persist").is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }

        let summary = svc
            .resolve_decision("r-persist", Verdict::AllowPersist)
            .unwrap();
        assert_eq!(summary.host, "api.github.com");
        assert_eq!(summary.action, "http:GET");

        let resp = handle.await.unwrap().unwrap().into_inner();
        assert_eq!(resp.verdict, Verdict::AllowPersist as i32);

        // A fresh SubmitDecision from any session should now hit the
        // persisted rule and short-circuit.
        let followup = svc
            .submit_decision(Request::new(SubmitDecisionRequest {
                session_id: "sess-other".into(),
                request_id: "r-follow".into(),
                method: "GET".into(),
                host: "api.github.com".into(),
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(followup.verdict, Verdict::AllowPersist as i32);
    }

    #[tokio::test]
    async fn resolve_unknown_request_returns_error() {
        let svc = StraitHostService::new();
        let err = svc
            .resolve_decision("does-not-exist", Verdict::AllowOnce)
            .unwrap_err();
        match err {
            ResolveError::Decision(DecisionError::UnknownRequest) => {}
            other => panic!("unexpected error: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unimplemented_rpcs_return_unimplemented() {
        let svc = StraitHostService::new();
        let err = svc
            .fetch_credential(Request::new(FetchCredentialRequest::default()))
            .await
            .unwrap_err();
        assert_eq!(err.code(), tonic::Code::Unimplemented);
    }

    #[tokio::test]
    async fn stream_rules_rejects_empty_session_id() {
        let svc = StraitHostService::new();
        let err = svc
            .stream_rules(Request::new(StreamRulesRequest::default()))
            .await
            .err()
            .expect("must require session_id");
        assert_eq!(err.code(), tonic::Code::InvalidArgument);
    }

    #[tokio::test]
    async fn stream_rules_emits_snapshot_then_tails_live_updates() {
        let svc = StraitHostService::new();
        let store = svc.rule_store().clone();
        store.upsert(test_rule("preexisting", "default")).unwrap();

        let stream = svc
            .stream_rules(Request::new(StreamRulesRequest {
                session_id: "sess-00000001".into(),
                resume_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        tokio::pin!(stream);

        let first = stream.next().await.unwrap().unwrap();
        assert_eq!(first.kind, rule_event::Kind::Add as i32);
        assert_eq!(first.rule_id, "preexisting");
        let end = stream.next().await.unwrap().unwrap();
        assert_eq!(end.kind, rule_event::Kind::SnapshotEnd as i32);

        // Add a second rule that should be tailed.
        store.upsert(test_rule("live-1", "default")).unwrap();
        let live = stream.next().await.unwrap().unwrap();
        assert_eq!(live.kind, rule_event::Kind::Add as i32);
        assert_eq!(live.rule_id, "live-1");

        // Update the first rule; expect an Update event.
        store
            .upsert(Rule {
                cedar_source: "permit(principal, action, resource);".into(),
                ..test_rule("preexisting", "default")
            })
            .unwrap();
        let upd = stream.next().await.unwrap().unwrap();
        assert_eq!(upd.kind, rule_event::Kind::Update as i32);
        assert_eq!(upd.rule_id, "preexisting");

        // Remove the first rule; expect a Remove event.
        store.remove("preexisting").unwrap();
        let rem = stream.next().await.unwrap().unwrap();
        assert_eq!(rem.kind, rule_event::Kind::Remove as i32);
        assert_eq!(rem.rule_id, "preexisting");
    }

    #[tokio::test]
    async fn stream_rules_filters_other_sessions() {
        let svc = StraitHostService::new();
        let store = svc.rule_store().clone();

        let stream = svc
            .stream_rules(Request::new(StreamRulesRequest {
                session_id: "sess-A".into(),
                resume_token: String::new(),
            }))
            .await
            .unwrap()
            .into_inner();
        tokio::pin!(stream);

        // Snapshot has no rules; we still see the SNAPSHOT_END marker.
        let end = stream.next().await.unwrap().unwrap();
        assert_eq!(end.kind, rule_event::Kind::SnapshotEnd as i32);

        // A rule scoped to a different session must not show up.
        store.upsert(test_rule("other", "sess-B")).unwrap();
        // A default-scoped rule must show up.
        store.upsert(test_rule("shared", "default")).unwrap();

        let visible = stream.next().await.unwrap().unwrap();
        assert_eq!(
            visible.rule_id, "shared",
            "session A must not see rules scoped to session B"
        );
    }

    #[tokio::test]
    async fn heartbeat_round_trips_sent_at() {
        let svc = StraitHostService::new();
        let resp = svc
            .heartbeat(Request::new(HeartbeatRequest {
                sent_at_unix_ms: 12345,
                ..Default::default()
            }))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 12345);
        assert!(
            resp.server_time_unix_ms >= 0,
            "server_time_unix_ms should be populated"
        );
    }

    #[test]
    fn verdict_default_is_unspecified() {
        // Defense-in-depth: if someone adds a new Verdict variant above
        // `Unspecified`, proto3 semantics change. Lock the default value.
        assert_eq!(Verdict::default(), Verdict::Unspecified);
    }

    #[test]
    fn persisted_allow_rule_id_is_lowercase_and_scoped() {
        let a = persisted_allow_rule_id("default", "API.github.COM", "http:GET");
        let b = persisted_allow_rule_id("default", "api.github.com", "http:GET");
        assert_eq!(a, b, "host should be case-insensitive");
        assert!(a.starts_with("persist-allow:default:"));
    }
}
