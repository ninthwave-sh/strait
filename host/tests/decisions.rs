//! End-to-end tests for the hold-and-resume and persist paths (H-HCP-6).
//!
//! These tests spin up an in-process `strait-host` (via
//! `serve_with_service`), connect a real `strait-agent` decision client
//! through the Unix-domain-socket channel, and exercise the three
//! scenarios called out in the H-HCP-6 work-item test plan:
//!
//! 1. `SubmitDecision` held on the host; library-level resolver responds
//!    `allow_session`; next matching call in the same session is served
//!    from the agent's session cache without another RPC.
//! 2. Persisted rule survives a host restart. After `resolve_decision`
//!    with `AllowPersist` and a host shutdown, reopening the rule store
//!    on a new host process still short-circuits the next
//!    `SubmitDecision` for the same host/action.
//! 3. A container with no attached desktop fails closed after the host's
//!    configured hold timeout elapses.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use strait_agent::host_client::connect_unix;
use strait_agent::proxy::{HostRpcClient, HostRpcVerdict};
use strait_agent::HostDecisionClient;
use strait_host::{
    serve_with_service, DecisionQueue, HostConfig, RuleStore, ShutdownSignal, StraitHostService,
    DEFAULT_SOCKET_MODE,
};
use strait_proto::v1::{strait_host_client::StraitHostClient, RegisterContainerRequest, Verdict};
use tempfile::tempdir;
use tokio::time::timeout;

/// Short hold timeout for the tests that want to observe the default-deny
/// path without waiting the production 30s.
const TEST_HOLD_TIMEOUT: Duration = Duration::from_millis(80);

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

async fn wait_for_socket(path: &std::path::Path) -> bool {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    path.exists()
}

fn test_config(sock: PathBuf, port: u16, rules_db: PathBuf) -> HostConfig {
    HostConfig {
        unix_socket: sock,
        tcp_listen: format!("127.0.0.1:{port}").parse().unwrap(),
        socket_mode: DEFAULT_SOCKET_MODE,
        rules_db,
    }
}

/// Spawn a host server with the given service and wait for the socket to
/// appear. Returns the shutdown handle and the server task so the caller
/// can shut the host down cleanly at the end of the test.
async fn spawn_server(
    sock: PathBuf,
    port: u16,
    rules_db: PathBuf,
    svc: StraitHostService,
) -> (ShutdownSignal, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let cfg = test_config(sock.clone(), port, rules_db);
    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, svc).await });
    assert!(wait_for_socket(&sock).await, "socket never appeared");
    (shutdown, server)
}

/// Register a container over the supplied UDS client and return the
/// assigned session id. We go through the raw client (rather than the
/// agent-side `HostDecisionClient`) because the decision client wants a
/// session id it was handed, not one it discovered itself.
async fn register(client: &mut StraitHostClient<tonic::transport::Channel>) -> String {
    let resp = client
        .register_container(RegisterContainerRequest {
            container_id: "abc".into(),
            container_name: "agent-1".into(),
            ..Default::default()
        })
        .await
        .expect("register_container")
        .into_inner();
    resp.session_id
}

/// Wait up to 2s for the decision queue to surface a held request from
/// the given session; return its request id.
async fn wait_for_pending(queue: Arc<DecisionQueue>, session_id: String) -> String {
    timeout(Duration::from_secs(2), async move {
        loop {
            let pending = queue.pending();
            if let Some(p) = pending.into_iter().find(|p| p.session_id == session_id) {
                return p.request_id;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("pending decision never appeared")
}

#[tokio::test]
async fn allow_session_verdict_is_cached_agent_side() {
    // Shared queue + rule store so the test can drive the operator side
    // of the decision alongside the agent-side RPC.
    let decisions = Arc::new(DecisionQueue::new(Duration::from_secs(5)));
    let rules = Arc::new(RuleStore::in_memory().unwrap());
    let svc = StraitHostService::with_state(decisions.clone(), rules.clone());

    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let rules_db = dir.path().join("rules.db");
    let port = pick_port();
    let (shutdown, server) = spawn_server(sock.clone(), port, rules_db, svc.clone()).await;

    // Two channels: one raw for registration (so we control the session
    // id), one wrapped in a HostDecisionClient for the SubmitDecision
    // path under test.
    let mut raw = connect_unix(&sock).await.expect("connect raw");
    let session_id = register(&mut raw).await;

    let decision_client = connect_unix(&sock).await.expect("connect decision client");
    let agent = HostDecisionClient::with_timeout(
        decision_client,
        session_id.clone(),
        Duration::from_secs(5),
    );

    // Spawn the agent call first so it registers the hold before the
    // operator responds.
    let agent_arc = Arc::new(agent);
    let agent_for_call = agent_arc.clone();
    let first_call = tokio::spawn(async move {
        agent_for_call
            .review_blocked("api.github.com", "GET", "/repos")
            .await
    });

    let request_id = wait_for_pending(decisions.clone(), session_id.clone()).await;
    let summary = svc
        .resolve_decision(&request_id, Verdict::AllowSession)
        .expect("resolve_decision");
    assert_eq!(summary.host, "api.github.com");
    assert_eq!(summary.action, "http:GET");

    let verdict = timeout(Duration::from_secs(2), first_call)
        .await
        .expect("first call completed")
        .unwrap();
    assert_eq!(verdict, HostRpcVerdict::Allow);

    // Second call must be served from the session cache — no new RPC, no
    // new pending entry on the queue, and the agent-side cache count
    // stayed at 1.
    assert!(agent_arc.session_cached("api.github.com", "http:GET"));
    let second_verdict = agent_arc
        .review_blocked("api.github.com", "GET", "/other")
        .await;
    assert_eq!(second_verdict, HostRpcVerdict::Allow);
    assert!(
        decisions.pending().is_empty(),
        "session-cached call should not enqueue a new hold",
    );
    assert_eq!(agent_arc.session_cache_len(), 1);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn persist_rule_survives_host_restart() {
    let dir = tempdir().unwrap();
    let rules_db = dir.path().join("rules.db");

    // ── First host run: operator persists an allow rule ──
    {
        let decisions = Arc::new(DecisionQueue::new(Duration::from_secs(5)));
        let rules = Arc::new(RuleStore::open(&rules_db).expect("open rule store"));
        let svc = StraitHostService::with_state(decisions.clone(), rules.clone());

        let sock = dir.path().join("host.sock");
        let port = pick_port();
        let (shutdown, server) =
            spawn_server(sock.clone(), port, rules_db.clone(), svc.clone()).await;

        let mut raw = connect_unix(&sock).await.expect("connect raw");
        let session_id = register(&mut raw).await;

        let dc = connect_unix(&sock).await.expect("connect decision");
        let agent = Arc::new(HostDecisionClient::with_timeout(
            dc,
            session_id.clone(),
            Duration::from_secs(5),
        ));

        let agent_for_call = agent.clone();
        let call = tokio::spawn(async move {
            agent_for_call
                .review_blocked("api.github.com", "GET", "/repos/org/repo")
                .await
        });

        let request_id = wait_for_pending(decisions.clone(), session_id.clone()).await;
        svc.resolve_decision(&request_id, Verdict::AllowPersist)
            .expect("resolve_decision");

        let verdict = timeout(Duration::from_secs(2), call)
            .await
            .expect("call completed")
            .unwrap();
        assert_eq!(verdict, HostRpcVerdict::Allow);

        shutdown.trigger();
        let _ = timeout(Duration::from_secs(2), server).await;

        assert!(rules_db.exists(), "rules.db should have been flushed");
    }

    // ── Second host run: fresh process, same rules file ──
    //
    // With a short hold timeout. Without the persisted rule the agent's
    // call would time out (TEST_HOLD_TIMEOUT) and see Deny. With the rule
    // loaded, the host short-circuits with AllowPersist.
    {
        let decisions = Arc::new(DecisionQueue::new(TEST_HOLD_TIMEOUT));
        let rules = Arc::new(RuleStore::open(&rules_db).expect("reopen rule store"));
        // Sanity: the persisted rule is present in the reopened store.
        assert!(
            rules
                .list_all()
                .unwrap()
                .iter()
                .any(|r| r.rule_id.contains("api.github.com")),
            "persisted rule should survive restart",
        );
        let svc = StraitHostService::with_state(decisions, rules);

        let sock = dir.path().join("host2.sock");
        let port = pick_port();
        let (shutdown, server) = spawn_server(sock.clone(), port, rules_db.clone(), svc).await;

        let mut raw = connect_unix(&sock).await.expect("connect raw");
        let session_id = register(&mut raw).await;

        // A different session issues the same request. The persisted
        // rule should short-circuit the decision without touching the
        // decision queue.
        let dc = connect_unix(&sock).await.expect("connect decision");
        let agent =
            HostDecisionClient::with_timeout(dc, session_id.clone(), Duration::from_secs(5));
        let verdict = timeout(
            Duration::from_secs(2),
            agent.review_blocked("api.github.com", "GET", "/repos/x/y"),
        )
        .await
        .expect("call completed");
        assert_eq!(verdict, HostRpcVerdict::Allow);

        shutdown.trigger();
        let _ = timeout(Duration::from_secs(2), server).await;
    }
}

#[tokio::test]
async fn hold_timeout_fires_default_deny_when_no_responder() {
    let decisions = Arc::new(DecisionQueue::new(TEST_HOLD_TIMEOUT));
    let rules = Arc::new(RuleStore::in_memory().unwrap());
    let svc = StraitHostService::with_state(decisions, rules);

    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let rules_db = dir.path().join("rules.db");
    let port = pick_port();
    let (shutdown, server) = spawn_server(sock.clone(), port, rules_db, svc).await;

    let mut raw = connect_unix(&sock).await.expect("connect raw");
    let session_id = register(&mut raw).await;

    let dc = connect_unix(&sock).await.expect("connect decision");
    let agent = HostDecisionClient::with_timeout(dc, session_id, Duration::from_secs(5));

    let t0 = Instant::now();
    let verdict = timeout(
        Duration::from_secs(2),
        agent.review_blocked("api.github.com", "GET", "/"),
    )
    .await
    .expect("call completed");
    let elapsed = t0.elapsed();

    assert_eq!(
        verdict,
        HostRpcVerdict::Deny,
        "no operator attached -> agent must fail closed",
    );
    // The host's hold timeout is ~80ms, with gRPC and scheduling slack
    // we allow up to a second.
    assert!(
        elapsed < Duration::from_secs(1),
        "timeout path took {elapsed:?}, expected < 1s",
    );
    assert!(
        elapsed >= TEST_HOLD_TIMEOUT,
        "call returned before the hold window elapsed: {elapsed:?}",
    );

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}
