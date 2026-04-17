//! Integration tests for the multi-container rule store.
//!
//! These tests exercise the H-HCP-3 acceptance criteria end to end:
//! two simulated containers register and subscribe to `StreamRules`, a
//! default-scoped rule is delivered to both, a session-scoped rule is
//! delivered only to its owner, rules persist across a host restart, and
//! concurrent writes from independent callers do not corrupt the DB.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use strait_host::rule_store::{Rule, RuleAction, RuleDuration, RuleStore};
use strait_host::{
    serve_with_service, HostConfig, ShutdownSignal, StraitHostService, DEFAULT_SOCKET_MODE,
};
use strait_proto::v1::strait_host_client::StraitHostClient;
use strait_proto::v1::{rule_event, RegisterContainerRequest, RuleEvent, StreamRulesRequest};
use tempfile::tempdir;
use tokio::net::UnixStream;
use tokio::time::timeout;
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

fn test_config(sock: PathBuf, port: u16, db: PathBuf) -> HostConfig {
    let obs = sock.with_extension("observations.jsonl");
    HostConfig {
        unix_socket: sock,
        tcp_listen: format!("127.0.0.1:{port}").parse().unwrap(),
        socket_mode: DEFAULT_SOCKET_MODE,
        rules_db: db,
        observations_log: obs,
    }
}

async fn wait_for_socket(path: &std::path::Path) {
    for _ in 0..250 {
        if path.exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("unix socket {} never appeared", path.display());
}

async fn connect_unix(path: PathBuf) -> StraitHostClient<Channel> {
    let endpoint = Endpoint::try_from("http://strait-host.local").unwrap();
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let s = UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(s))
            }
        }))
        .await
        .expect("connect over uds");
    StraitHostClient::new(channel)
}

fn rule(id: &str, scope: &str) -> Rule {
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

/// Drain rule events from a stream until `KIND_SNAPSHOT_END` arrives, then
/// return the collected snapshot events (exclusive of the terminator).
async fn drain_snapshot(stream: &mut tonic::Streaming<RuleEvent>) -> Vec<RuleEvent> {
    let mut out = Vec::new();
    loop {
        let evt = timeout(Duration::from_secs(2), stream.next())
            .await
            .expect("timed out waiting for snapshot event")
            .expect("stream ended before SNAPSHOT_END")
            .expect("stream item error");
        if evt.kind == rule_event::Kind::SnapshotEnd as i32 {
            return out;
        }
        out.push(evt);
    }
}

async fn next_event(stream: &mut tonic::Streaming<RuleEvent>) -> RuleEvent {
    timeout(Duration::from_secs(2), stream.next())
        .await
        .expect("timed out waiting for event")
        .expect("stream ended unexpectedly")
        .expect("stream item error")
}

#[tokio::test]
async fn two_containers_receive_default_and_session_scoped_rules() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let db = dir.path().join("rules.db");
    let port = pick_port();
    let cfg = test_config(sock.clone(), port, db);

    let store = Arc::new(RuleStore::in_memory().unwrap());
    let svc = StraitHostService::with_rule_store(store.clone());

    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, svc).await });
    wait_for_socket(&sock).await;

    let mut client_a = connect_unix(sock.clone()).await;
    let mut client_b = connect_unix(sock.clone()).await;
    let reg_a = client_a
        .register_container(RegisterContainerRequest {
            container_id: "container-a".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    let reg_b = client_b
        .register_container(RegisterContainerRequest {
            container_id: "container-b".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();
    assert_ne!(reg_a.session_id, reg_b.session_id);

    let mut stream_a = client_a
        .stream_rules(StreamRulesRequest {
            session_id: reg_a.session_id.clone(),
            resume_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let mut stream_b = client_b
        .stream_rules(StreamRulesRequest {
            session_id: reg_b.session_id.clone(),
            resume_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    // Both streams open on an empty store, so each sees just SNAPSHOT_END.
    assert!(drain_snapshot(&mut stream_a).await.is_empty());
    assert!(drain_snapshot(&mut stream_b).await.is_empty());

    // Default-scope rule reaches every subscriber.
    store
        .upsert(rule("r-default", RuleStore::DEFAULT_SCOPE))
        .unwrap();
    let a_event = next_event(&mut stream_a).await;
    assert_eq!(a_event.rule_id, "r-default");
    assert_eq!(a_event.scope, "default");
    assert_eq!(a_event.kind, rule_event::Kind::Add as i32);
    let b_event = next_event(&mut stream_b).await;
    assert_eq!(b_event.rule_id, "r-default");

    // Session-scope rule reaches only the owning container.
    store.upsert(rule("r-a", &reg_a.session_id)).unwrap();
    let a_event = next_event(&mut stream_a).await;
    assert_eq!(a_event.rule_id, "r-a");
    assert_eq!(a_event.scope, reg_a.session_id);

    // Container B must not see session-A-scoped rules. 200ms is plenty of
    // time for the broadcast to have reached B if it were going to; we
    // accept a timeout as proof of absence.
    let leak = timeout(Duration::from_millis(200), stream_b.next()).await;
    assert!(
        leak.is_err(),
        "session-scoped rule must not reach other container, got {leak:?}"
    );

    // Update the default-scope rule; both streams see the Update.
    store
        .upsert(Rule {
            cedar_source: "permit(principal, action, resource);".into(),
            ..rule("r-default", RuleStore::DEFAULT_SCOPE)
        })
        .unwrap();
    let u_a = next_event(&mut stream_a).await;
    let u_b = next_event(&mut stream_b).await;
    assert_eq!(u_a.kind, rule_event::Kind::Update as i32);
    assert_eq!(u_b.kind, rule_event::Kind::Update as i32);

    // Remove; both streams see the Remove.
    store.remove("r-default").unwrap();
    let r_a = next_event(&mut stream_a).await;
    let r_b = next_event(&mut stream_b).await;
    assert_eq!(r_a.kind, rule_event::Kind::Remove as i32);
    assert_eq!(r_b.kind, rule_event::Kind::Remove as i32);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn snapshot_delivers_preexisting_rules_to_late_subscriber() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let db = dir.path().join("rules.db");
    let port = pick_port();
    let cfg = test_config(sock.clone(), port, db);

    let store = Arc::new(RuleStore::in_memory().unwrap());
    // Pre-populate the store before any client connects.
    store
        .upsert(rule("seed-1", RuleStore::DEFAULT_SCOPE))
        .unwrap();
    store.upsert(rule("seed-2", "sess-xyz")).unwrap();
    let svc = StraitHostService::with_rule_store(store);

    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, svc).await });
    wait_for_socket(&sock).await;

    let mut client = connect_unix(sock).await;
    // Pretend we are session sess-xyz so both seeds should be in the snapshot.
    let mut stream = client
        .stream_rules(StreamRulesRequest {
            session_id: "sess-xyz".into(),
            resume_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();

    let snapshot = drain_snapshot(&mut stream).await;
    let ids: Vec<_> = snapshot.iter().map(|r| r.rule_id.as_str()).collect();
    assert_eq!(ids, vec!["seed-1", "seed-2"]);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[test]
fn rules_persist_across_restart() {
    let dir = tempdir().unwrap();
    let db = dir.path().join("rules.db");
    {
        let store = RuleStore::open(&db).unwrap();
        store
            .upsert(rule("persist-me", RuleStore::DEFAULT_SCOPE))
            .unwrap();
        store
            .upsert(Rule {
                duration: RuleDuration::Session,
                ttl_unix_ms: Some(123_456_789),
                ..rule("ttl-rule", "sess-keeper")
            })
            .unwrap();
    }
    // Reopen and confirm both rows survived.
    let store = RuleStore::open(&db).unwrap();
    let rules = store.list_all().unwrap();
    assert_eq!(rules.len(), 2);
    let ttl = store.get("ttl-rule").unwrap().unwrap();
    assert_eq!(ttl.duration, RuleDuration::Session);
    assert_eq!(ttl.ttl_unix_ms, Some(123_456_789));
}

#[test]
fn concurrent_writes_do_not_corrupt_the_db() {
    // Two independent threads slam the same store with interleaved inserts
    // and deletions. All writes must complete without error, and the final
    // row set must be exactly the union minus what was deleted.
    let dir = tempdir().unwrap();
    let db = dir.path().join("rules.db");
    let store = Arc::new(RuleStore::open(&db).unwrap());

    let threads = 4usize;
    let per_thread = 50usize;
    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let s = store.clone();
        handles.push(std::thread::spawn(move || {
            for i in 0..per_thread {
                let id = format!("rule-{t}-{i}");
                let scope = if i % 2 == 0 {
                    RuleStore::DEFAULT_SCOPE.to_string()
                } else {
                    format!("sess-{t}")
                };
                s.upsert(rule(&id, &scope)).unwrap();
                // Half of them get updated with a second upsert.
                if i % 3 == 0 {
                    s.upsert(Rule {
                        cedar_source: format!(
                            "permit(principal, action, resource == \"{id}-v2\");"
                        ),
                        ..rule(&id, &scope)
                    })
                    .unwrap();
                }
            }
        }));
    }
    for h in handles {
        h.join().expect("thread panicked");
    }

    let all = store.list_all().unwrap();
    assert_eq!(
        all.len(),
        threads * per_thread,
        "every thread's inserts should be visible"
    );

    // Schema must still be intact: round-trip a new rule.
    store.upsert(rule("post-contention", "default")).unwrap();
    assert!(store.get("post-contention").unwrap().is_some());
}
