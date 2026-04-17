//! Integration tests for `strait-host`.
//!
//! Two layers:
//!   1. Binary-level: spawn the published `strait-host serve` process with
//!      override paths, confirm both listeners come up, and verify SIGTERM
//!      exits the process within the budget documented in H-HCP-1.
//!   2. Protocol-level: drive the gRPC service through the library entry
//!      point using a caller-supplied `StraitHost` impl. This is where the
//!      H-HCP-2 acceptance criterion ("integration test covers at least one
//!      round-trip per RPC") lives. Running against the library, not the
//!      binary, keeps these tests fast and independent of a live host.

#![cfg(unix)]

use std::path::PathBuf;
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hyper_util::rt::TokioIo;
use strait_host::{
    serve, serve_with_service, HostConfig, ShutdownSignal, StraitHostService, DEFAULT_SOCKET_MODE,
};
use strait_proto::v1::fetch_credential_response::Kind as CredKind;
use strait_proto::v1::strait_host_client::StraitHostClient;
use strait_proto::v1::strait_host_server::StraitHost;
use strait_proto::v1::{
    FetchCredentialRequest, FetchCredentialResponse, HeaderCredential, HeartbeatRequest,
    HeartbeatResponse, InjectedCredential, ObservationEvent, RegisterContainerRequest,
    RegisterContainerResponse, RuleEvent, StreamObservationsAck, StreamRulesRequest,
    SubmitDecisionRequest, SubmitDecisionResponse, Verdict,
};
use tempfile::tempdir;
use tokio::net::UnixStream;
use tokio::process::Command;
use tokio::sync::Mutex;
use tokio::time::timeout;
use tonic::transport::{Channel, Endpoint, Uri};
use tonic::{Request, Response, Status, Streaming};
use tower::service_fn;

/// Path to the built `strait-host` binary, injected by cargo at compile time.
const BIN: &str = env!("CARGO_BIN_EXE_strait-host");

/// Pick a free TCP port on loopback by binding and dropping a throwaway listener.
fn pick_port() -> u16 {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    drop(l);
    port
}

/// Wait for a predicate up to `budget`. Poll every 20ms.
async fn wait_until<F: Fn() -> bool>(budget: Duration, predicate: F) -> bool {
    let deadline = Instant::now() + budget;
    while Instant::now() < deadline {
        if predicate() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    predicate()
}

/// Build a gRPC channel over a Unix domain socket. Mirrors the production
/// connector in `strait_agent::host_client`; duplicated rather than pulled
/// in as a dev-dependency so these tests do not also drag in the whole
/// strait-agent build graph for the binary-level checks above.
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

fn test_config(sock: PathBuf, port: u16) -> HostConfig {
    let db = sock.with_extension("rules.db");
    HostConfig {
        unix_socket: sock,
        tcp_listen: format!("127.0.0.1:{port}").parse().unwrap(),
        socket_mode: DEFAULT_SOCKET_MODE,
        rules_db: db,
    }
}

async fn wait_for_socket(path: &std::path::Path) -> bool {
    let p = path.to_path_buf();
    wait_until(Duration::from_secs(5), move || p.exists()).await
}

// ── Binary-level smoke tests (retained from H-HCP-1) ──────────────────

#[tokio::test]
async fn both_listeners_accept_grpc_heartbeat() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let tcp_addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--unix-socket")
        .arg(&sock)
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--log-format")
        .arg("text")
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn strait-host");

    assert!(wait_for_socket(&sock).await, "unix socket never appeared");
    assert!(
        wait_until(Duration::from_secs(5), || {
            std::net::TcpStream::connect_timeout(
                &tcp_addr.parse().unwrap(),
                Duration::from_millis(200),
            )
            .is_ok()
        })
        .await,
        "tcp listener did not start",
    );

    // Unix: gRPC heartbeat round-trip.
    {
        let mut client = connect_unix(sock.clone()).await;
        let resp = client
            .heartbeat(HeartbeatRequest {
                sent_at_unix_ms: 11,
                ..Default::default()
            })
            .await
            .expect("unix heartbeat rpc")
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 11);
    }

    // TCP: gRPC heartbeat round-trip.
    {
        let channel = Endpoint::try_from(format!("http://{tcp_addr}"))
            .unwrap()
            .connect()
            .await
            .expect("tcp connect");
        let mut client = StraitHostClient::new(channel);
        let resp = client
            .heartbeat(HeartbeatRequest {
                sent_at_unix_ms: 22,
                ..Default::default()
            })
            .await
            .expect("tcp heartbeat rpc")
            .into_inner();
        assert_eq!(resp.received_at_unix_ms, 22);
    }

    let pid = child.id().expect("child has no pid");
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let _ = timeout(Duration::from_secs(5), child.wait()).await;
}

#[tokio::test]
async fn sigterm_exits_within_two_seconds() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let tcp_addr = format!("127.0.0.1:{port}");

    let mut child = Command::new(BIN)
        .arg("serve")
        .arg("--unix-socket")
        .arg(&sock)
        .arg("--tcp-listen")
        .arg(&tcp_addr)
        .arg("--log-format")
        .arg("text")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .expect("spawn strait-host");

    assert!(wait_for_socket(&sock).await, "unix socket never appeared");

    let pid = child.id().expect("child has no pid");
    let t0 = Instant::now();
    unsafe {
        libc::kill(pid as libc::pid_t, libc::SIGTERM);
    }
    let status = timeout(Duration::from_secs(2), child.wait())
        .await
        .expect("process did not exit within 2s after SIGTERM")
        .expect("wait failed");
    let elapsed = t0.elapsed();
    assert!(
        elapsed < Duration::from_secs(2),
        "SIGTERM shutdown took {elapsed:?}",
    );
    assert!(status.success(), "exit status: {status:?}");
}

#[tokio::test]
async fn help_documents_defaults() {
    let output = std::process::Command::new(BIN)
        .arg("serve")
        .arg("--help")
        .output()
        .expect("run strait-host serve --help");
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("/var/run/strait/host.sock"),
        "--help missing default unix socket path:\n{text}",
    );
    assert!(
        text.contains("127.0.0.1:3129"),
        "--help missing default tcp listener:\n{text}",
    );

    let top = std::process::Command::new(BIN)
        .arg("--help")
        .output()
        .expect("run strait-host --help");
    let text = String::from_utf8_lossy(&top.stdout);
    assert!(
        text.contains("host.toml"),
        "top-level --help missing config path mention:\n{text}",
    );
}

// ── Protocol-level round-trips ────────────────────────────────────────
//
// These tests cover the H-HCP-2 acceptance criterion that an integration
// test exercises at least one round-trip per RPC. They run the server via
// `serve()` in-process so we can drive it at the library level and avoid
// the cost of a fresh subprocess per test.

async fn spawn_default_server(
    sock: PathBuf,
    tcp_port: u16,
) -> (ShutdownSignal, tokio::task::JoinHandle<anyhow::Result<()>>) {
    let cfg = test_config(sock.clone(), tcp_port);
    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve(&cfg, s).await });
    assert!(wait_for_socket(&sock).await, "socket never appeared");
    (shutdown, server)
}

#[tokio::test]
async fn default_service_supports_register_and_heartbeat() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let (shutdown, server) = spawn_default_server(sock.clone(), port).await;

    let mut client = connect_unix(sock).await;

    let reg: RegisterContainerResponse = client
        .register_container(RegisterContainerRequest {
            container_id: "abc".into(),
            container_name: "agent-1".into(),
            ..Default::default()
        })
        .await
        .expect("register round-trip")
        .into_inner();
    assert!(reg.session_id.starts_with("sess-"));
    assert_eq!(reg.default_scope, "default");
    assert!(reg.registered_at_unix_ms > 0);

    let hb: HeartbeatResponse = client
        .heartbeat(HeartbeatRequest {
            session_id: reg.session_id,
            sent_at_unix_ms: 100,
            ..Default::default()
        })
        .await
        .expect("heartbeat round-trip")
        .into_inner();
    assert_eq!(hb.received_at_unix_ms, 100);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn default_service_returns_unimplemented_for_deferred_rpcs() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let (shutdown, server) = spawn_default_server(sock.clone(), port).await;

    let mut client = connect_unix(sock).await;

    // SubmitDecision is now implemented in H-HCP-6. We only check the
    // other RPCs here; the SubmitDecision behaviour has dedicated
    // coverage in `tests/decisions.rs`.

    // FetchCredential: unary.
    let err = client
        .fetch_credential(FetchCredentialRequest::default())
        .await
        .expect_err("should be unimplemented");
    assert_eq!(err.code(), tonic::Code::Unimplemented);

    // StreamRules: server-streaming. Now implemented (H-HCP-3); an empty
    // session_id still yields InvalidArgument, which proves the server is
    // validating the request before opening a stream.
    let err = client
        .stream_rules(StreamRulesRequest::default())
        .await
        .expect_err("empty session_id must be rejected");
    assert_eq!(err.code(), tonic::Code::InvalidArgument);

    // StreamObservations: client-streaming. Empty outbound stream; server
    // returns Unimplemented immediately.
    let outbound = tokio_stream::iter(Vec::<ObservationEvent>::new());
    let err = client
        .stream_observations(outbound)
        .await
        .expect_err("should be unimplemented");
    assert_eq!(err.code(), tonic::Code::Unimplemented);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

// ── Echo service: SubmitDecision hold-and-resume ──────────────────────
//
// A replacement `StraitHost` impl that echoes SubmitDecision into an
// ALLOW_ONCE verdict. Demonstrates the protocol surface supports the
// hold-and-resume pattern H-HCP-6 will build on, and satisfies the test
// plan's "strait-host stub that echoes SubmitDecision requests".

#[derive(Default, Clone)]
struct EchoHost {
    inner: StraitHostService,
    // Record the latest seen request so the test can prove the server
    // actually received the payload rather than fabricating the verdict.
    last_request: Arc<Mutex<Option<SubmitDecisionRequest>>>,
}

type RuleEventStream =
    std::pin::Pin<Box<dyn futures_core::Stream<Item = Result<RuleEvent, Status>> + Send + 'static>>;

#[tonic::async_trait]
impl StraitHost for EchoHost {
    async fn register_container(
        &self,
        req: Request<RegisterContainerRequest>,
    ) -> Result<Response<RegisterContainerResponse>, Status> {
        self.inner.register_container(req).await
    }

    async fn submit_decision(
        &self,
        req: Request<SubmitDecisionRequest>,
    ) -> Result<Response<SubmitDecisionResponse>, Status> {
        let inner = req.into_inner();
        {
            let mut guard = self.last_request.lock().await;
            *guard = Some(inner.clone());
        }
        Ok(Response::new(SubmitDecisionResponse {
            request_id: inner.request_id,
            verdict: Verdict::AllowOnce as i32,
            reason: format!("echo:{}", inner.host),
            decided_at_unix_ms: 0,
            credential: Some(InjectedCredential {
                header_name: "Authorization".into(),
                header_value: "Bearer echo".into(),
            }),
        }))
    }

    async fn fetch_credential(
        &self,
        _req: Request<FetchCredentialRequest>,
    ) -> Result<Response<FetchCredentialResponse>, Status> {
        Ok(Response::new(FetchCredentialResponse {
            kind: Some(CredKind::Header(HeaderCredential {
                header_name: "Authorization".into(),
                header_value: "Bearer echo".into(),
            })),
        }))
    }

    type StreamRulesStream = RuleEventStream;

    async fn stream_rules(
        &self,
        _req: Request<StreamRulesRequest>,
    ) -> Result<Response<Self::StreamRulesStream>, Status> {
        // Emit one ADD followed by SNAPSHOT_END so the test can observe a
        // server-streaming round trip with real messages on the wire.
        let events = vec![
            Ok(RuleEvent {
                kind: strait_proto::v1::rule_event::Kind::Add as i32,
                rule_id: "echo-rule".into(),
                scope: "default".into(),
                cedar_source: "permit(principal, action, resource);".into(),
                version_token: "v1".into(),
            }),
            Ok(RuleEvent {
                kind: strait_proto::v1::rule_event::Kind::SnapshotEnd as i32,
                rule_id: String::new(),
                scope: String::new(),
                cedar_source: String::new(),
                version_token: "v1".into(),
            }),
        ];
        let stream: Self::StreamRulesStream = Box::pin(tokio_stream::iter(events));
        Ok(Response::new(stream))
    }

    async fn stream_observations(
        &self,
        req: Request<Streaming<ObservationEvent>>,
    ) -> Result<Response<StreamObservationsAck>, Status> {
        use tokio_stream::StreamExt;
        let mut stream = req.into_inner();
        let mut accepted = 0u64;
        while let Some(next) = stream.next().await {
            match next {
                Ok(_) => accepted += 1,
                Err(_) => break,
            }
        }
        Ok(Response::new(StreamObservationsAck {
            accepted,
            rejected: 0,
        }))
    }

    async fn heartbeat(
        &self,
        req: Request<HeartbeatRequest>,
    ) -> Result<Response<HeartbeatResponse>, Status> {
        self.inner.heartbeat(req).await
    }
}

#[tokio::test]
async fn echo_service_round_trips_every_rpc() {
    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let cfg = test_config(sock.clone(), port);

    let echo = EchoHost::default();
    let captured = echo.last_request.clone();
    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, echo).await });
    assert!(wait_for_socket(&sock).await, "socket never appeared");

    let mut client = connect_unix(sock).await;

    // RegisterContainer
    let reg = client
        .register_container(RegisterContainerRequest {
            container_id: "c1".into(),
            ..Default::default()
        })
        .await
        .expect("register")
        .into_inner();
    assert!(reg.session_id.starts_with("sess-"));

    // SubmitDecision echoes with ALLOW_ONCE and an injected credential.
    // This is the "hold-and-resume" round trip called out in the test plan.
    let decision = client
        .submit_decision(SubmitDecisionRequest {
            session_id: reg.session_id.clone(),
            request_id: "req-1".into(),
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/user".into(),
            headers: Default::default(),
            observed_at_unix_ms: 123,
            explanation: "test".into(),
        })
        .await
        .expect("submit_decision")
        .into_inner();
    assert_eq!(decision.verdict, Verdict::AllowOnce as i32);
    assert_eq!(decision.request_id, "req-1");
    assert_eq!(
        decision.credential.as_ref().map(|c| c.header_name.as_str()),
        Some("Authorization"),
    );
    let captured = captured.lock().await.clone();
    let captured = captured.expect("server saw the request");
    assert_eq!(captured.host, "api.github.com");

    // FetchCredential
    let cred = client
        .fetch_credential(FetchCredentialRequest {
            session_id: reg.session_id.clone(),
            host: "api.github.com".into(),
            action: "http:GET".into(),
            ..Default::default()
        })
        .await
        .expect("fetch_credential")
        .into_inner();
    match cred.kind {
        Some(CredKind::Header(h)) => assert_eq!(h.header_name, "Authorization"),
        other => panic!("expected header credential, got {other:?}"),
    }

    // StreamRules: server-streaming. Drain until SNAPSHOT_END.
    use tokio_stream::StreamExt;
    let mut rules = client
        .stream_rules(StreamRulesRequest {
            session_id: reg.session_id.clone(),
            resume_token: String::new(),
        })
        .await
        .expect("stream_rules")
        .into_inner();
    let first = rules
        .next()
        .await
        .expect("first rule event")
        .expect("stream ok");
    assert_eq!(first.rule_id, "echo-rule");
    let second = rules
        .next()
        .await
        .expect("second rule event")
        .expect("stream ok");
    assert_eq!(
        second.kind,
        strait_proto::v1::rule_event::Kind::SnapshotEnd as i32
    );

    // StreamObservations: client-streaming. Send three events, expect the
    // ack to report them accepted.
    let outbound = tokio_stream::iter(vec![
        ObservationEvent {
            session_id: reg.session_id.clone(),
            observation_id: "o1".into(),
            observed_at_unix_ms: 1,
            raw_json: "{}".into(),
        },
        ObservationEvent {
            session_id: reg.session_id.clone(),
            observation_id: "o2".into(),
            observed_at_unix_ms: 2,
            raw_json: "{}".into(),
        },
        ObservationEvent {
            session_id: reg.session_id.clone(),
            observation_id: "o3".into(),
            observed_at_unix_ms: 3,
            raw_json: "{}".into(),
        },
    ]);
    let ack = client
        .stream_observations(outbound)
        .await
        .expect("stream_observations")
        .into_inner();
    assert_eq!(ack.accepted, 3);
    assert_eq!(ack.rejected, 0);

    // Heartbeat
    let hb = client
        .heartbeat(HeartbeatRequest {
            session_id: reg.session_id,
            sent_at_unix_ms: 99,
            ..Default::default()
        })
        .await
        .expect("heartbeat")
        .into_inner();
    assert_eq!(hb.received_at_unix_ms, 99);

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}

#[tokio::test]
async fn hold_and_resume_honours_client_timeout() {
    // Acceptance: "fake client sends one, waits for verdict, closes stream on
    // timeout." We use a service that never returns a verdict for
    // SubmitDecision to prove the client-side timeout path works cleanly.

    #[derive(Default, Clone)]
    struct NeverDecides;

    #[tonic::async_trait]
    impl StraitHost for NeverDecides {
        async fn register_container(
            &self,
            _req: Request<RegisterContainerRequest>,
        ) -> Result<Response<RegisterContainerResponse>, Status> {
            Err(Status::unimplemented("not needed"))
        }

        async fn submit_decision(
            &self,
            _req: Request<SubmitDecisionRequest>,
        ) -> Result<Response<SubmitDecisionResponse>, Status> {
            // Block forever. The client cancellation will drop this future.
            std::future::pending::<()>().await;
            unreachable!()
        }

        async fn fetch_credential(
            &self,
            _req: Request<FetchCredentialRequest>,
        ) -> Result<Response<FetchCredentialResponse>, Status> {
            Err(Status::unimplemented("not needed"))
        }

        type StreamRulesStream = RuleEventStream;

        async fn stream_rules(
            &self,
            _req: Request<StreamRulesRequest>,
        ) -> Result<Response<Self::StreamRulesStream>, Status> {
            Err(Status::unimplemented("not needed"))
        }

        async fn stream_observations(
            &self,
            _req: Request<Streaming<ObservationEvent>>,
        ) -> Result<Response<StreamObservationsAck>, Status> {
            Err(Status::unimplemented("not needed"))
        }

        async fn heartbeat(
            &self,
            _req: Request<HeartbeatRequest>,
        ) -> Result<Response<HeartbeatResponse>, Status> {
            Err(Status::unimplemented("not needed"))
        }
    }

    let dir = tempdir().unwrap();
    let sock = dir.path().join("host.sock");
    let port = pick_port();
    let cfg = test_config(sock.clone(), port);

    let shutdown = ShutdownSignal::new();
    let s = shutdown.clone();
    let server = tokio::spawn(async move { serve_with_service(&cfg, s, NeverDecides).await });
    assert!(wait_for_socket(&sock).await, "socket never appeared");

    let mut client = connect_unix(sock).await;

    // Apply a client-side deadline on the SubmitDecision call.
    let mut req = Request::new(SubmitDecisionRequest {
        request_id: "timeout-1".into(),
        ..Default::default()
    });
    req.set_timeout(Duration::from_millis(200));
    let t0 = Instant::now();
    let err = client
        .submit_decision(req)
        .await
        .expect_err("server never decides, call must time out");
    assert!(
        matches!(
            err.code(),
            tonic::Code::DeadlineExceeded | tonic::Code::Cancelled
        ),
        "unexpected status {err:?}",
    );
    assert!(
        t0.elapsed() < Duration::from_secs(2),
        "timeout took {:?}",
        t0.elapsed(),
    );

    shutdown.trigger();
    let _ = timeout(Duration::from_secs(2), server).await;
}
