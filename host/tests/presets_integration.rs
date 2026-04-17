//! Integration tests for the preset library in the host control plane.
//!
//! Exercises the M-ONB-2 acceptance criteria end to end: a registered
//! container opts into `preset:github-read` via `RegisterContainer`, the
//! host copies the preset's Cedar source into the rule store at the
//! session's scope, and `StreamRules` delivers the resulting rule to
//! that container only.
//!
//! The second test covers the version-bump edge case from the work item's
//! test plan: a preset update does not retroactively overwrite rules
//! that an already-registered session is relying on.

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use strait_host::presets::{
    apply_policy_preset_to_store, find_policy_preset, preset_rule_id, split_preset_rule_id,
    PolicyPreset, PRESET_RULE_ID_PREFIX,
};
use strait_host::rule_store::{RuleDuration, RuleStore};
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
        credentials: Vec::new(),
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

#[tokio::test]
async fn register_container_with_preset_delivers_rule_to_opting_session_only() {
    // Acceptance: "container A opts into `preset:github-read`;
    // `StreamRules` delivers the preset's rules to A only."
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

    // Container A opts into the github-read preset. Container B does not.
    let reg_a = client_a
        .register_container(RegisterContainerRequest {
            container_id: "container-a".into(),
            preset_ids: vec!["github-read".into()],
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

    // The register response echoes which presets were applied so the
    // caller can display the result to the operator.
    assert_eq!(reg_a.applied_preset_ids, vec!["github-read".to_string()]);
    assert!(reg_a.ignored_preset_ids.is_empty());
    assert!(reg_b.applied_preset_ids.is_empty());
    assert!(reg_b.ignored_preset_ids.is_empty());

    let preset = find_policy_preset("github-read").expect("github-read preset exists");
    let expected_rule_id = preset_rule_id(preset.id, preset.version);

    // Session A's snapshot must include the preset rule, scoped to its
    // session id, with the preset's Cedar source copied verbatim.
    let mut stream_a = client_a
        .stream_rules(StreamRulesRequest {
            session_id: reg_a.session_id.clone(),
            resume_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let snapshot_a = drain_snapshot(&mut stream_a).await;
    assert_eq!(
        snapshot_a.len(),
        1,
        "session A should see exactly the preset rule"
    );
    let rule = &snapshot_a[0];
    assert_eq!(rule.rule_id, expected_rule_id);
    assert_eq!(rule.scope, reg_a.session_id);
    assert_eq!(rule.cedar_source, preset.cedar_source);
    assert!(
        rule.rule_id.starts_with(PRESET_RULE_ID_PREFIX),
        "preset-sourced rules must carry the preset:<id> marker"
    );
    let (preset_id, version) =
        split_preset_rule_id(&rule.rule_id).expect("preset rule id should split");
    assert_eq!(preset_id, "github-read");
    assert_eq!(version, preset.version);

    // Session B's snapshot must be empty -- the preset rule is scoped to
    // session A and default-scoped rules should not leak in from elsewhere.
    let mut stream_b = client_b
        .stream_rules(StreamRulesRequest {
            session_id: reg_b.session_id.clone(),
            resume_token: String::new(),
        })
        .await
        .unwrap()
        .into_inner();
    let snapshot_b = drain_snapshot(&mut stream_b).await;
    assert!(
        snapshot_b.is_empty(),
        "session B opted out of the preset and must not see it: {snapshot_b:?}"
    );
    // Confirm by timeout that session B never receives the preset rule.
    let leak = timeout(Duration::from_millis(200), stream_b.next()).await;
    assert!(
        leak.is_err(),
        "preset rule must not cross into session B, got {leak:?}"
    );

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn unknown_preset_ids_are_ignored_not_fatal() {
    // A desktop shell may pass preset ids the running host does not
    // recognise yet (for example a newer shell version than the host).
    // Registration must succeed and surface the unknown ids to the
    // caller so it can warn the operator.
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let db = dir.path().join("rules.db");
    let port = pick_port();
    let cfg = test_config(sock.clone(), port, db);

    let svc = StraitHostService::new();
    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, svc).await });
    wait_for_socket(&sock).await;

    let mut client = connect_unix(sock.clone()).await;
    let reg = client
        .register_container(RegisterContainerRequest {
            container_id: "container-mixed".into(),
            preset_ids: vec![
                "github-read".into(),
                "not-a-real-preset".into(),
                "container-sandbox".into(),
            ],
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    assert_eq!(
        reg.applied_preset_ids,
        vec!["github-read".to_string(), "container-sandbox".to_string()]
    );
    assert_eq!(
        reg.ignored_preset_ids,
        vec!["not-a-real-preset".to_string()]
    );

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[test]
fn preset_version_bump_keeps_pinned_rule_for_existing_session() {
    // Edge case from the work item's test plan: "preset updated across a
    // version bump -- existing containers keep their pinned version
    // unless explicitly upgraded." Simulate the bump by applying two
    // `PolicyPreset`s that share an id but carry different versions to a
    // live rule store; the older row survives under its versioned
    // rule_id so the session that registered pre-bump keeps its Cedar
    // source.
    let store = RuleStore::open(&tempdir().unwrap().path().join("rules.db")).unwrap();
    let v1 = PolicyPreset {
        id: "example",
        version: "1",
        description: "v1",
        cedar_source: "permit(principal, action, resource);\n",
    };
    let v2 = PolicyPreset {
        id: "example",
        version: "2",
        description: "v2",
        cedar_source: "permit(principal, action, resource == Resource::\"only-v2\");\n",
    };

    let old_rule = apply_policy_preset_to_store(&store, &v1, "sess-old").unwrap();
    let new_rule = apply_policy_preset_to_store(&store, &v2, "sess-new").unwrap();
    assert_ne!(old_rule.rule_id, new_rule.rule_id);
    assert_eq!(old_rule.duration, RuleDuration::Session);
    assert_eq!(new_rule.duration, RuleDuration::Session);

    // Both rows remain; the old session is still pinned to v1's Cedar.
    let pinned = store.get(&old_rule.rule_id).unwrap().unwrap();
    assert_eq!(pinned.cedar_source, v1.cedar_source);
    let upgraded = store.get(&new_rule.rule_id).unwrap().unwrap();
    assert_eq!(upgraded.cedar_source, v2.cedar_source);

    // And each session's scope surfaces its own pinned version only.
    let old_view = store.snapshot_for_session("sess-old").unwrap();
    assert!(old_view.iter().any(|r| r.rule_id == old_rule.rule_id));
    assert!(!old_view.iter().any(|r| r.rule_id == new_rule.rule_id));
    let new_view = store.snapshot_for_session("sess-new").unwrap();
    assert!(new_view.iter().any(|r| r.rule_id == new_rule.rule_id));
    assert!(!new_view.iter().any(|r| r.rule_id == old_rule.rule_id));
}
