//! End-to-end tests for the M-HCP-5 observation pipeline.
//!
//! Two containers open separate `StreamObservations` calls against the
//! default `StraitHostService`. A single desktop subscriber attaches via
//! `SubscribeObservations`. The test asserts:
//!
//!   1. The on-disk JSONL log contains one line per accepted event,
//!      augmented with top-level `session_id` and `container_registration_id`.
//!   2. The subscriber receives the same events with the correct session
//!      tags.
//!   3. `strait::observe::read_observations` parses the host-written
//!      JSONL file unchanged (the generate / replay regression).

#![cfg(unix)]

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use hyper_util::rt::TokioIo;
use strait::observe::{read_observations, EventKind};
use strait_host::{
    serve_with_service, HostConfig, ObservationHub, ShutdownSignal, StraitHostService,
    DEFAULT_SOCKET_MODE,
};
use strait_proto::v1::strait_host_client::StraitHostClient;
use strait_proto::v1::{ObservationEvent, RegisterContainerRequest, SubscribeObservationsRequest};
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

async fn wait_for_socket(path: &std::path::Path) -> bool {
    for _ in 0..200 {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    path.exists()
}

fn test_config(dir: &std::path::Path) -> HostConfig {
    HostConfig {
        unix_socket: dir.join("host.sock"),
        tcp_listen: format!("127.0.0.1:{}", pick_port()).parse().unwrap(),
        socket_mode: DEFAULT_SOCKET_MODE,
        rules_db: dir.join("rules.db"),
        observations_log: dir.join("observations.jsonl"),
        credentials: Vec::new(),
    }
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

fn network_event_json(method: &str, host: &str, path: &str, decision: &str) -> String {
    // Match the exact shape `ObservationEvent` serializes to so the file
    // is readable by `strait::observe::read_observations`.
    serde_json::json!({
        "version": 4,
        "timestamp": "2026-04-17T00:00:00.000Z",
        "type": "network_request",
        "method": method,
        "host": host,
        "path": path,
        "decision": decision,
        "latency_us": 12u64,
    })
    .to_string()
}

#[tokio::test]
async fn two_containers_stream_and_one_subscriber_sees_interleaved() {
    let dir = tempdir().unwrap();
    let cfg = test_config(dir.path());
    let sock = cfg.unix_socket.clone();
    let obs_path = cfg.observations_log.clone();

    // Build the service with a hub so we can inspect it from the test too.
    let hub = Arc::new(ObservationHub::open(&cfg.observations_log).await.unwrap());
    let svc = StraitHostService::new().with_observation_hub(hub.clone());

    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server_cfg = cfg.clone();
    let server = tokio::spawn(async move { serve_with_service(&server_cfg, s, svc).await });
    assert!(wait_for_socket(&sock).await, "socket never appeared");

    // Subscriber attaches first so it catches every event we emit below.
    let mut subscriber_client = connect_unix(sock.clone()).await;
    let mut subscriber_stream = subscriber_client
        .subscribe_observations(SubscribeObservationsRequest::default())
        .await
        .expect("subscribe_observations")
        .into_inner();

    // Two container agents register and stream a handful of events each.
    let mut agent_a = connect_unix(sock.clone()).await;
    let mut agent_b = connect_unix(sock.clone()).await;
    let reg_a = agent_a
        .register_container(RegisterContainerRequest {
            container_id: "container-A".into(),
            container_name: "agent-A".into(),
            ..Default::default()
        })
        .await
        .expect("register A")
        .into_inner();
    let reg_b = agent_b
        .register_container(RegisterContainerRequest {
            container_id: "container-B".into(),
            container_name: "agent-B".into(),
            ..Default::default()
        })
        .await
        .expect("register B")
        .into_inner();

    let outbound_a = tokio_stream::iter(vec![
        ObservationEvent {
            session_id: reg_a.session_id.clone(),
            container_registration_id: "container-A".into(),
            observation_id: "a-1".into(),
            observed_at_unix_ms: 1,
            raw_json: network_event_json("GET", "api.github.com", "/user", "allow"),
        },
        ObservationEvent {
            session_id: reg_a.session_id.clone(),
            container_registration_id: "container-A".into(),
            observation_id: "a-2".into(),
            observed_at_unix_ms: 2,
            raw_json: network_event_json("POST", "api.github.com", "/repos", "deny"),
        },
    ]);
    let outbound_b = tokio_stream::iter(vec![ObservationEvent {
        session_id: reg_b.session_id.clone(),
        // Leave container_registration_id empty so we prove the host
        // backfills from the registration map.
        container_registration_id: String::new(),
        observation_id: "b-1".into(),
        observed_at_unix_ms: 3,
        raw_json: network_event_json("GET", "api.openai.com", "/v1/models", "allow"),
    }]);

    let ack_a_fut = agent_a.stream_observations(outbound_a);
    let ack_b_fut = agent_b.stream_observations(outbound_b);
    let (ack_a, ack_b) = tokio::join!(ack_a_fut, ack_b_fut);
    let ack_a = ack_a.expect("ack A").into_inner();
    let ack_b = ack_b.expect("ack B").into_inner();
    assert_eq!(ack_a.accepted, 2);
    assert_eq!(ack_b.accepted, 1);

    // Collect three subscriber events. They may arrive in any order; the
    // test checks the *set* matches what we sent.
    let mut received = Vec::new();
    for _ in 0..3 {
        let evt = timeout(Duration::from_secs(5), subscriber_stream.next())
            .await
            .expect("subscriber recv timed out")
            .expect("subscriber stream ended")
            .expect("subscriber stream error");
        received.push(evt);
    }
    let received_ids: std::collections::BTreeSet<_> = received
        .iter()
        .map(|e| (e.session_id.clone(), e.observation_id.clone()))
        .collect();
    assert!(received_ids.contains(&(reg_a.session_id.clone(), "a-1".into())));
    assert!(received_ids.contains(&(reg_a.session_id.clone(), "a-2".into())));
    assert!(received_ids.contains(&(reg_b.session_id.clone(), "b-1".into())));

    // Agent B left container_registration_id blank; the host must have
    // filled it in from the registration map.
    let b_event = received
        .iter()
        .find(|e| e.session_id == reg_b.session_id)
        .expect("b event present");
    assert_eq!(b_event.container_registration_id, "container-B");

    // On-disk JSONL file: one line per accepted event, each line parsable
    // by `strait::observe::read_observations`.
    let body = tokio::fs::read_to_string(&obs_path).await.unwrap();
    let lines: Vec<&str> = body.lines().collect();
    assert_eq!(lines.len(), 3, "expected three JSONL lines, got {lines:?}");
    for line in &lines {
        let parsed: serde_json::Value = serde_json::from_str(line).unwrap();
        assert!(parsed.get("session_id").is_some(), "missing session_id");
        assert!(
            parsed.get("container_registration_id").is_some(),
            "missing container_registration_id"
        );
    }

    // Regression: generate/replay read the new JSONL format unchanged.
    let events = read_observations(&obs_path).expect("read_observations");
    assert_eq!(events.len(), 3);
    assert!(events
        .iter()
        .all(|e| matches!(e.event, EventKind::NetworkRequest { .. })));

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn subscribe_observations_respects_session_filter() {
    let dir = tempdir().unwrap();
    let cfg = test_config(dir.path());
    let sock = cfg.unix_socket.clone();

    let hub = Arc::new(ObservationHub::open(&cfg.observations_log).await.unwrap());
    let svc = StraitHostService::new().with_observation_hub(hub.clone());

    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server_cfg = cfg.clone();
    let server = tokio::spawn(async move { serve_with_service(&server_cfg, s, svc).await });
    assert!(wait_for_socket(&sock).await);

    let mut client = connect_unix(sock.clone()).await;
    let reg = client
        .register_container(RegisterContainerRequest {
            container_id: "c1".into(),
            container_name: "c1".into(),
            ..Default::default()
        })
        .await
        .unwrap()
        .into_inner();

    // Subscribe with a filter that does NOT match the session we will emit.
    let mut filtered_client = connect_unix(sock.clone()).await;
    let mut filtered_stream = filtered_client
        .subscribe_observations(SubscribeObservationsRequest {
            session_id: "other-session".into(),
        })
        .await
        .expect("subscribe_observations")
        .into_inner();

    let outbound = tokio_stream::iter(vec![ObservationEvent {
        session_id: reg.session_id.clone(),
        container_registration_id: "c1".into(),
        observation_id: "only".into(),
        observed_at_unix_ms: 1,
        raw_json: network_event_json("GET", "example.com", "/", "allow"),
    }]);
    let ack = client
        .stream_observations(outbound)
        .await
        .expect("ack")
        .into_inner();
    assert_eq!(ack.accepted, 1);

    // The filter rejects this event; a short timeout should yield None.
    let got = timeout(Duration::from_millis(300), filtered_stream.next()).await;
    assert!(
        got.is_err(),
        "filtered subscriber unexpectedly received {got:?}"
    );

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}
