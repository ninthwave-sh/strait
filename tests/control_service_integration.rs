#![cfg(unix)]

use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;
use tokio_stream::iter;

use strait::control::{
    self, proto, ControlServiceOptions, ManagedSessionOptions, SessionControlServiceClient,
    TcpTlsOptions,
};

const TEST_IMAGE: &str = "ubuntu:24.04";
const DEFAULT_DENY_POLICY_TEXT: &str = r#"
@id("allow-only-post")
permit(
    principal == Agent::"agent",
    action == Action::"http:POST",
    resource
);
"#;

fn control_test_guard() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(guard) => guard,
        Err(poisoned) => poisoned.into_inner(),
    }
}

struct EnvVarGuard {
    key: &'static str,
    previous: Option<std::ffi::OsString>,
}

impl EnvVarGuard {
    fn set(key: &'static str, value: &Path) -> Self {
        let previous = std::env::var_os(key);
        std::env::set_var(key, value);
        Self { key, previous }
    }
}

impl Drop for EnvVarGuard {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var(self.key, previous);
        } else {
            std::env::remove_var(self.key);
        }
    }
}

fn repo_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn strait_binary() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_strait"))
}

fn live_policy_probe_fixture() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_live-policy-probe-fixture"))
}

async fn docker_available() -> bool {
    let docker = match bollard::Docker::connect_with_local_defaults() {
        Ok(docker) => docker,
        Err(_) => return false,
    };
    if docker.ping().await.is_err() {
        return false;
    }
    docker.inspect_image(TEST_IMAGE).await.is_ok()
}

fn gateway_compatible_with_container() -> bool {
    cfg!(target_os = "linux")
}

async fn require_docker() -> bool {
    if !docker_available().await {
        return false;
    }
    if !gateway_compatible_with_container() {
        return false;
    }

    let host_target = if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        return false;
    };

    strait::launch::resolve_gateway_binary(host_target).is_ok()
}

async fn wait_for_unix_health(socket_path: &Path) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(channel) = control::connect_unix_channel(socket_path).await {
                let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
                if let Ok(response) = client
                    .check(tonic_health::pb::HealthCheckRequest {
                        service: "strait.control.v1.SessionControlService".to_string(),
                    })
                    .await
                {
                    if response.into_inner().status
                        == tonic_health::pb::health_check_response::ServingStatus::Serving as i32
                    {
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("Unix health check should become ready");
}

async fn wait_for_tcp_health(
    addr: SocketAddr,
    ca_pem: Vec<u8>,
    client_identity: (Vec<u8>, Vec<u8>),
) {
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Ok(channel) = control::connect_tcp_tls_channel(
                addr,
                "localhost",
                ca_pem.clone(),
                Some(client_identity.clone()),
            )
            .await
            {
                let mut client = tonic_health::pb::health_client::HealthClient::new(channel);
                if let Ok(response) = client
                    .check(tonic_health::pb::HealthCheckRequest {
                        service: "strait.control.v1.SessionControlService".to_string(),
                    })
                    .await
                {
                    if response.into_inner().status
                        == tonic_health::pb::health_check_response::ServingStatus::Serving as i32
                    {
                        return;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("TCP health check should become ready");
}

async fn wait_for_sessions(socket_path: &Path, minimum: usize) -> Vec<proto::Session> {
    tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Ok(channel) = control::connect_unix_channel(socket_path).await {
                let mut client = SessionControlServiceClient::new(channel);
                if let Ok(response) = client
                    .list_sessions(proto::ListSessionsRequest {})
                    .await
                    .map(|response| response.into_inner())
                {
                    if response.sessions.len() >= minimum {
                        return response.sessions;
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("expected sessions should appear")
}

async fn wait_for_session_removed(session_id: &str) {
    tokio::time::timeout(Duration::from_secs(15), async {
        loop {
            let sessions = strait::launch::list_launch_sessions().unwrap();
            if sessions
                .iter()
                .all(|session| session.session_id != session_id)
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("managed launch session should be removed");
}

async fn start_upstream_close_server() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _ = stream.read(&mut [0_u8; 1024]).await;
        }
    });

    addr
}

fn write_default_deny_policy(path: &Path) {
    std::fs::write(path, DEFAULT_DENY_POLICY_TEXT).unwrap();
}

fn issue_leaf_cert(
    common_name: &str,
    ca_cert: &rcgen::Certificate,
    ca_key: &KeyPair,
    add_localhost_san: bool,
) -> (String, String) {
    let leaf_key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    if add_localhost_san {
        params
            .subject_alt_names
            .push(SanType::DnsName("localhost".try_into().unwrap()));
        params
            .subject_alt_names
            .push(SanType::IpAddress(Ipv4Addr::LOCALHOST.into()));
    }
    let cert = params.signed_by(&leaf_key, ca_cert, ca_key).unwrap();
    (cert.pem(), leaf_key.serialize_pem())
}

fn unused_tcp_addr() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

#[tokio::test]
async fn service_health_check_and_subscribe_disconnect_cycle() {
    let _guard = control_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let socket_path = temp_dir.path().join("control.sock");
    let service = tokio::spawn(control::run_control_service(ControlServiceOptions {
        socket_path: socket_path.clone(),
        tcp_tls: None,
        managed_session: ManagedSessionOptions {
            observe: false,
            warn: None,
            policy: None,
            image: None,
            output: None,
            env: Vec::new(),
            mount: Vec::new(),
            command: Vec::new(),
        },
    }));

    wait_for_unix_health(&socket_path).await;

    let channel = control::connect_unix_channel(&socket_path).await.unwrap();
    let mut client = SessionControlServiceClient::new(channel);
    let mut stream = client
        .subscribe(iter(vec![proto::SubscribeRequest {
            session_id: String::new(),
            include_inventory: true,
        }]))
        .await
        .unwrap()
        .into_inner();

    let first = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        first.event,
        Some(proto::subscribe_event::Event::Inventory(_))
    ));
    drop(stream);

    let channel = control::connect_unix_channel(&socket_path).await.unwrap();
    let mut client = SessionControlServiceClient::new(channel);
    let mut stream = client
        .subscribe(iter(vec![proto::SubscribeRequest {
            session_id: String::new(),
            include_inventory: true,
        }]))
        .await
        .unwrap()
        .into_inner();
    let second = tokio::time::timeout(Duration::from_secs(5), stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(matches!(
        second.event,
        Some(proto::subscribe_event::Event::Inventory(_))
    ));
    drop(stream);

    control::request_service_stop(&socket_path).await.unwrap();
    service.await.unwrap().unwrap();
}

#[tokio::test]
async fn service_startup_prunes_stale_socket_and_registry() {
    let _guard = control_test_guard();
    let runtime_root = tempfile::tempdir().unwrap();
    let _env = EnvVarGuard::set("XDG_RUNTIME_DIR", runtime_root.path());
    let socket_path = runtime_root.path().join("service.sock");
    std::fs::File::create(&socket_path).unwrap();

    let session_dir = runtime_root
        .path()
        .join("strait")
        .join("strait-sessions")
        .join("stale-session");
    std::fs::create_dir_all(&session_dir).unwrap();
    let stale_metadata = strait::launch::LaunchSessionMetadata {
        version: strait::launch::SESSION_CONTROL_PROTOCOL_VERSION,
        session_id: "stale-session".to_string(),
        mode: "observe".to_string(),
        decision_timeout_secs: 30,
        control_socket_path: session_dir.join("control.sock"),
        observation: strait::launch::ObservationHandle {
            transport: "unix_socket".to_string(),
            path: session_dir.join("observe.sock"),
        },
        container_id: None,
        container_name: None,
    };
    std::fs::write(
        session_dir.join("session.json"),
        serde_json::to_vec_pretty(&stale_metadata).unwrap(),
    )
    .unwrap();

    let service = tokio::spawn(control::run_control_service(ControlServiceOptions {
        socket_path: socket_path.clone(),
        tcp_tls: None,
        managed_session: ManagedSessionOptions {
            observe: false,
            warn: None,
            policy: None,
            image: None,
            output: None,
            env: Vec::new(),
            mount: Vec::new(),
            command: Vec::new(),
        },
    }));

    wait_for_unix_health(&socket_path).await;
    assert!(socket_path.exists(), "service socket should be rebound");
    assert!(
        !session_dir.exists(),
        "stale registry entries should be pruned on startup"
    );

    control::request_service_stop(&socket_path).await.unwrap();
    service.await.unwrap().unwrap();
}

#[tokio::test]
async fn service_startup_publishes_managed_session_for_other_clients() {
    let _guard = control_test_guard();
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let socket_path = temp_dir.path().join("control.sock");
    let output_path = temp_dir.path().join("observations.jsonl");

    let mut child = tokio::process::Command::new(strait_binary())
        .arg("service")
        .arg("start")
        .arg("--socket")
        .arg(&socket_path)
        .arg("--observe")
        .arg("--image")
        .arg(TEST_IMAGE)
        .arg("--output")
        .arg(&output_path)
        .arg("--")
        .arg("sh")
        .arg("-lc")
        .arg("sleep 60")
        .current_dir(repo_root())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();

    wait_for_unix_health(&socket_path).await;
    let sessions = wait_for_sessions(&socket_path, 1).await;
    let session_id = sessions[0].session_id.clone();

    let status = tokio::process::Command::new(strait_binary())
        .arg("service")
        .arg("status")
        .arg("--socket")
        .arg(&socket_path)
        .current_dir(repo_root())
        .output()
        .await
        .unwrap();
    assert!(status.status.success(), "service status should succeed");
    let stdout = String::from_utf8_lossy(&status.stdout);
    assert!(
        stdout.contains(&session_id),
        "status should list the session id"
    );

    let second = control::query_service_status(&socket_path).await.unwrap();
    assert!(
        second
            .sessions
            .iter()
            .any(|session| session.session_id == session_id),
        "a second local client should discover the same managed session"
    );

    control::request_service_stop(&socket_path).await.unwrap();
    let exit_status = tokio::time::timeout(Duration::from_secs(90), child.wait())
        .await
        .unwrap()
        .unwrap();
    assert!(exit_status.success(), "service process should exit cleanly");
    wait_for_session_removed(&session_id).await;
    assert!(
        output_path.exists(),
        "managed session should write observations"
    );
}

#[tokio::test]
async fn service_streams_blocked_requests_and_submits_decisions() {
    let _guard = control_test_guard();
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let socket_path = temp_dir.path().join("control.sock");
    let output_path = temp_dir.path().join("observations.jsonl");
    let policy_path = temp_dir.path().join("policy.cedar");
    write_default_deny_policy(&policy_path);
    let upstream_addr = start_upstream_close_server().await;
    let probe_mount = format!(
        "{}:/usr/local/bin/live-policy-probe-fixture:ro",
        live_policy_probe_fixture().display()
    );
    let script = format!(
        "(printf 'probe\\n'; sleep 5; printf 'exit\\n') | live-policy-probe-fixture --host {} --port {} --path /policy-probe",
        upstream_addr.ip(),
        upstream_addr.port()
    );

    let service = tokio::spawn(control::run_control_service(ControlServiceOptions {
        socket_path: socket_path.clone(),
        tcp_tls: None,
        managed_session: ManagedSessionOptions {
            observe: false,
            warn: None,
            policy: Some(policy_path),
            image: Some(TEST_IMAGE.to_string()),
            output: Some(output_path),
            env: Vec::new(),
            mount: vec![probe_mount],
            command: vec!["sh".to_string(), "-lc".to_string(), script],
        },
    }));

    wait_for_unix_health(&socket_path).await;
    let sessions = wait_for_sessions(&socket_path, 1).await;
    let session_id = sessions[0].session_id.clone();

    let channel = control::connect_unix_channel(&socket_path).await.unwrap();
    let mut client = SessionControlServiceClient::new(channel);
    let mut blocked_stream = client
        .stream_blocked_requests(proto::StreamBlockedRequestsRequest {
            session_id: session_id.clone(),
        })
        .await
        .unwrap()
        .into_inner();

    let blocked = tokio::time::timeout(Duration::from_secs(30), blocked_stream.message())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(
        !blocked.blocked_id.is_empty(),
        "blocked stream should surface blocked ids"
    );
    assert_eq!(blocked.host, upstream_addr.ip().to_string());
    assert_eq!(blocked.path, "/policy-probe");
    assert_eq!(blocked.hold_timeout_secs, 30);
    assert!(!blocked.observed_at.is_empty());
    assert!(!blocked.hold_expires_at.is_empty());

    let decision = client
        .submit_decision(proto::SubmitDecisionRequest {
            session_id: session_id.clone(),
            blocked_id: blocked.blocked_id.clone(),
            action: proto::DecisionAction::AllowOnce as i32,
            ttl_seconds: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(decision.session_id, session_id);
    assert_eq!(decision.blocked_id, blocked.blocked_id);
    assert!(decision.match_key.contains("http:GET"));
    drop(blocked_stream);

    control::request_service_stop(&socket_path).await.unwrap();
    service.await.unwrap().unwrap();
}

#[tokio::test]
async fn service_remote_tls_health_check_accepts_mtls_clients() {
    let _guard = control_test_guard();
    let temp_dir = tempfile::tempdir().unwrap();
    let socket_path = temp_dir.path().join("control.sock");
    let addr = unused_tcp_addr();

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "control-test-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();
    let ca_pem = ca_cert.pem();

    let (server_cert_pem, server_key_pem) = issue_leaf_cert("localhost", &ca_cert, &ca_key, true);
    let (client_cert_pem, client_key_pem) =
        issue_leaf_cert("desktop-client", &ca_cert, &ca_key, false);

    let server_cert_path = temp_dir.path().join("server-cert.pem");
    let server_key_path = temp_dir.path().join("server-key.pem");
    let client_ca_path = temp_dir.path().join("client-ca.pem");
    std::fs::write(&server_cert_path, server_cert_pem).unwrap();
    std::fs::write(&server_key_path, server_key_pem).unwrap();
    std::fs::write(&client_ca_path, &ca_pem).unwrap();

    let service = tokio::spawn(control::run_control_service(ControlServiceOptions {
        socket_path: socket_path.clone(),
        tcp_tls: Some(TcpTlsOptions {
            listen_addr: addr,
            cert_path: server_cert_path,
            key_path: server_key_path,
            client_ca_path,
        }),
        managed_session: ManagedSessionOptions {
            observe: false,
            warn: None,
            policy: None,
            image: None,
            output: None,
            env: Vec::new(),
            mount: Vec::new(),
            command: Vec::new(),
        },
    }));

    wait_for_unix_health(&socket_path).await;
    wait_for_tcp_health(
        addr,
        ca_pem.into_bytes(),
        (client_cert_pem.into_bytes(), client_key_pem.into_bytes()),
    )
    .await;

    control::request_service_stop(&socket_path).await.unwrap();
    service.await.unwrap().unwrap();
}
