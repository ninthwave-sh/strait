//! gRPC control service for published Strait runtime sessions.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context as _;
use tokio::io::AsyncBufReadExt;
use tokio::sync::{mpsc, oneshot, watch, RwLock};
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream, UnixListenerStream};
use tonic::transport::{
    Certificate, Channel, ClientTlsConfig, Endpoint, Identity, Server, ServerTlsConfig,
};
use tonic::{Request, Response, Status};
use tower::service_fn;

use crate::launch::{
    self, list_launch_sessions, request_launch_decision_allow_once,
    request_launch_decision_allow_session, request_launch_decision_deny,
    request_launch_decision_persist, request_launch_session_info, request_launch_session_stop,
    request_launch_watch_attach, LaunchSessionMetadata,
};
use crate::observe::{CandidateException, EventKind, ExceptionDirective, ObservationEvent};

pub mod proto {
    tonic::include_proto!("strait.control.v1");
}

pub use proto::service_admin_client::ServiceAdminClient;
pub use proto::service_admin_server::ServiceAdminServer;
pub use proto::session_control_service_client::SessionControlServiceClient;
pub use proto::session_control_service_server::SessionControlServiceServer;

const DEFAULT_SERVICE_SOCKET_NAME: &str = "control-service.sock";
const SESSION_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedSessionOptions {
    pub observe: bool,
    pub warn: Option<PathBuf>,
    pub policy: Option<PathBuf>,
    pub image: Option<String>,
    pub output: Option<PathBuf>,
    pub env: Vec<String>,
    pub mount: Vec<String>,
    pub command: Vec<String>,
}

impl ManagedSessionOptions {
    pub fn is_enabled(&self) -> bool {
        self.observe || self.warn.is_some() || self.policy.is_some() || !self.command.is_empty()
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let mode_count = usize::from(self.observe)
            + usize::from(self.warn.is_some())
            + usize::from(self.policy.is_some());

        if !self.is_enabled() {
            return Ok(());
        }

        if mode_count != 1 {
            anyhow::bail!(
                "managed service launches require exactly one of --observe, --warn, or --policy"
            );
        }

        if self.command.is_empty() {
            anyhow::bail!("managed service launches require a command after `--`");
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpTlsOptions {
    pub listen_addr: SocketAddr,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub client_ca_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControlServiceOptions {
    pub socket_path: PathBuf,
    pub tcp_tls: Option<TcpTlsOptions>,
    pub managed_session: ManagedSessionOptions,
}

#[derive(Debug, Clone)]
pub struct ServiceStatusSummary {
    pub local_endpoint: proto::Endpoint,
    pub remote_endpoint: Option<proto::Endpoint>,
    pub sessions: Vec<proto::Session>,
}

#[derive(Debug)]
struct ManagedLaunchHandle {
    session: Arc<RwLock<Option<LaunchSessionMetadata>>>,
    join: tokio::task::JoinHandle<anyhow::Result<i32>>,
}

#[derive(Debug)]
struct ServiceState {
    socket_path: PathBuf,
    remote_endpoint: Option<proto::Endpoint>,
    shutdown_tx: watch::Sender<bool>,
}

type SharedState = Arc<ServiceState>;

#[derive(Clone)]
struct SessionControlApi;

#[derive(Clone)]
struct ServiceAdminApi {
    state: SharedState,
}

pub fn default_service_socket_path() -> PathBuf {
    crate::observe::runtime_dir().join(DEFAULT_SERVICE_SOCKET_NAME)
}

pub async fn connect_unix_channel(path: &Path) -> anyhow::Result<Channel> {
    let socket_path = path.to_path_buf();
    Endpoint::try_from("http://[::]:50051")?
        .connect_with_connector(service_fn(move |_| {
            let socket_path = socket_path.clone();
            async move {
                tokio::net::UnixStream::connect(socket_path)
                    .await
                    .map(hyper_util::rt::TokioIo::new)
            }
        }))
        .await
        .with_context(|| format!("failed to connect to service socket '{}'", path.display()))
}

pub async fn connect_tcp_tls_channel(
    addr: SocketAddr,
    domain_name: &str,
    ca_pem: Vec<u8>,
    identity_pem: Option<(Vec<u8>, Vec<u8>)>,
) -> anyhow::Result<Channel> {
    crate::ensure_rustls_crypto_provider();
    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca_pem))
        .domain_name(domain_name);
    if let Some((cert_pem, key_pem)) = identity_pem {
        tls = tls.identity(Identity::from_pem(cert_pem, key_pem));
    }

    let endpoint = Endpoint::from_shared(format!("https://{addr}"))?.tls_config(tls)?;

    endpoint
        .connect()
        .await
        .with_context(|| format!("failed to connect to remote control service at {addr}"))
}

pub async fn query_service_status(path: &Path) -> anyhow::Result<ServiceStatusSummary> {
    let channel = connect_unix_channel(path).await?;
    let mut client = ServiceAdminClient::new(channel);
    let response = client
        .get_service_status(proto::GetServiceStatusRequest {})
        .await?
        .into_inner();

    Ok(ServiceStatusSummary {
        local_endpoint: response.local_endpoint.unwrap_or(proto::Endpoint {
            network: "unix".to_string(),
            address: path.display().to_string(),
        }),
        remote_endpoint: response.remote_endpoint,
        sessions: response.sessions,
    })
}

pub async fn request_service_stop(path: &Path) -> anyhow::Result<()> {
    let channel = connect_unix_channel(path).await?;
    let mut client = ServiceAdminClient::new(channel);
    let response = client
        .stop_service(proto::StopServiceRequest {})
        .await?
        .into_inner();
    anyhow::ensure!(response.accepted, "service stop request was rejected");
    Ok(())
}

pub async fn prune_stale_launch_sessions() -> anyhow::Result<usize> {
    let mut removed = 0;
    for session in list_launch_sessions()? {
        if request_launch_session_info(&session.control_socket_path)
            .await
            .is_ok()
        {
            continue;
        }
        if let Some(session_dir) = session.control_socket_path.parent() {
            if session_dir.exists() {
                std::fs::remove_dir_all(session_dir).with_context(|| {
                    format!(
                        "failed to remove stale launch session directory '{}'",
                        session_dir.display()
                    )
                })?;
                removed += 1;
            }
        }
    }
    Ok(removed)
}

pub async fn run_control_service(options: ControlServiceOptions) -> anyhow::Result<()> {
    options.managed_session.validate()?;
    prune_stale_launch_sessions().await?;

    let socket_path = options.socket_path.clone();
    prepare_unix_socket(&socket_path)?;

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let managed_launch = if options.managed_session.is_enabled() {
        Some(start_managed_launch(options.managed_session.clone()).await?)
    } else {
        None
    };

    let remote_endpoint = options.tcp_tls.as_ref().map(|tcp| proto::Endpoint {
        network: "tcp+tls".to_string(),
        address: tcp.listen_addr.to_string(),
    });

    let state = Arc::new(ServiceState {
        socket_path: socket_path.clone(),
        remote_endpoint,
        shutdown_tx,
    });

    let uds_server =
        start_uds_server(socket_path.clone(), state.clone(), shutdown_rx.clone()).await?;
    let tcp_server = if let Some(tcp_tls) = options.tcp_tls {
        Some(start_tcp_tls_server(tcp_tls, state.clone(), shutdown_rx.clone()).await?)
    } else {
        None
    };

    tokio::select! {
        _ = wait_for_shutdown(shutdown_rx.clone()) => {}
        _ = tokio::signal::ctrl_c() => {
            let _ = state.shutdown_tx.send(true);
        }
    }

    let _ = state.shutdown_tx.send(true);

    uds_server.await??;
    if let Some(tcp_server) = tcp_server {
        tcp_server.await??;
    }

    shutdown_managed_launch(managed_launch).await;
    let _ = std::fs::remove_file(&socket_path);

    Ok(())
}

async fn start_uds_server(
    socket_path: PathBuf,
    state: SharedState,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
    ensure_private_parent_dir(&socket_path)?;
    let listener = tokio::net::UnixListener::bind(&socket_path)
        .with_context(|| format!("failed to bind service socket '{}'", socket_path.display()))?;

    Ok(tokio::spawn(async move {
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        let session_service = SessionControlServiceServer::new(SessionControlApi);
        let admin_service = ServiceAdminServer::new(ServiceAdminApi { state });
        tokio::spawn(async move {
            health_reporter
                .set_serving::<SessionControlServiceServer<SessionControlApi>>()
                .await;
            health_reporter
                .set_serving::<ServiceAdminServer<ServiceAdminApi>>()
                .await;
        });

        Server::builder()
            .add_service(health_service)
            .add_service(session_service)
            .add_service(admin_service)
            .serve_with_incoming_shutdown(
                UnixListenerStream::new(listener),
                wait_for_shutdown(shutdown_rx),
            )
            .await
            .context("control service Unix server failed")?;
        Ok(())
    }))
}

async fn start_tcp_tls_server(
    tcp_tls: TcpTlsOptions,
    state: SharedState,
    shutdown_rx: watch::Receiver<bool>,
) -> anyhow::Result<tokio::task::JoinHandle<anyhow::Result<()>>> {
    crate::ensure_rustls_crypto_provider();
    let cert_pem = std::fs::read(&tcp_tls.cert_path)
        .with_context(|| format!("failed to read TLS cert '{}'", tcp_tls.cert_path.display()))?;
    let key_pem = std::fs::read(&tcp_tls.key_path)
        .with_context(|| format!("failed to read TLS key '{}'", tcp_tls.key_path.display()))?;
    let client_ca_pem = std::fs::read(&tcp_tls.client_ca_path).with_context(|| {
        format!(
            "failed to read TLS client CA '{}'",
            tcp_tls.client_ca_path.display()
        )
    })?;

    let tls = ServerTlsConfig::new()
        .identity(Identity::from_pem(cert_pem, key_pem))
        .client_ca_root(Certificate::from_pem(client_ca_pem));
    let listener = tokio::net::TcpListener::bind(tcp_tls.listen_addr)
        .await
        .with_context(|| {
            format!(
                "failed to bind remote control listener {}",
                tcp_tls.listen_addr
            )
        })?;

    Ok(tokio::spawn(async move {
        let (mut health_reporter, health_service) = tonic_health::server::health_reporter();
        let session_service = SessionControlServiceServer::new(SessionControlApi);
        let admin_service = ServiceAdminServer::new(ServiceAdminApi { state });
        tokio::spawn(async move {
            health_reporter
                .set_serving::<SessionControlServiceServer<SessionControlApi>>()
                .await;
            health_reporter
                .set_serving::<ServiceAdminServer<ServiceAdminApi>>()
                .await;
        });

        Server::builder()
            .tls_config(tls)?
            .add_service(health_service)
            .add_service(session_service)
            .add_service(admin_service)
            .serve_with_incoming_shutdown(
                TcpListenerStream::new(listener),
                wait_for_shutdown(shutdown_rx),
            )
            .await
            .context("remote control TCP server failed")?;
        Ok(())
    }))
}

async fn start_managed_launch(
    options: ManagedSessionOptions,
) -> anyhow::Result<ManagedLaunchHandle> {
    let session = Arc::new(RwLock::new(None));
    let session_clone = session.clone();
    let (ready_tx, ready_rx) = oneshot::channel();
    let command = options.command.clone();
    let image = options.image.clone();
    let output = options.output.clone();
    let env = options.env.clone();
    let mounts = launch::parse_extra_mounts(&options.mount)?;

    let join = tokio::spawn(async move {
        let mut ready_tx = Some(ready_tx);
        if options.observe {
            launch::run_launch_observe_with_ready_signal(
                command,
                image.as_deref(),
                output,
                None,
                Vec::new(),
                env,
                mounts,
                false,
                ready_tx
                    .take()
                    .expect("managed session ready sender missing"),
            )
            .await
        } else if let Some(policy) = options.warn {
            launch::run_launch_with_policy_with_ready_signal(
                launch::EnforcementMode::Warn,
                &policy,
                command,
                image.as_deref(),
                output,
                None,
                Vec::new(),
                env,
                mounts,
                false,
                ready_tx
                    .take()
                    .expect("managed session ready sender missing"),
            )
            .await
        } else if let Some(policy) = options.policy {
            launch::run_launch_with_policy_with_ready_signal(
                launch::EnforcementMode::Enforce,
                &policy,
                command,
                image.as_deref(),
                output,
                None,
                Vec::new(),
                env,
                mounts,
                false,
                ready_tx
                    .take()
                    .expect("managed session ready sender missing"),
            )
            .await
        } else {
            anyhow::bail!("managed launch configuration is incomplete")
        }
    });

    wait_for_managed_session(ready_rx, session_clone).await?;

    Ok(ManagedLaunchHandle { session, join })
}

async fn wait_for_managed_session(
    ready_rx: oneshot::Receiver<LaunchSessionMetadata>,
    destination: Arc<RwLock<Option<LaunchSessionMetadata>>>,
) -> anyhow::Result<()> {
    let session = tokio::time::timeout(Duration::from_secs(30), ready_rx)
        .await
        .context("timed out waiting for managed launch session")?
        .context("managed launch exited before publishing session metadata")?;

    *destination.write().await = Some(session);
    Ok(())
}

async fn shutdown_managed_launch(managed_launch: Option<ManagedLaunchHandle>) {
    let Some(managed_launch) = managed_launch else {
        return;
    };

    if let Some(session) = managed_launch.session.read().await.clone() {
        let _ = request_launch_session_stop(&session.control_socket_path).await;
    }

    let _ = tokio::time::timeout(Duration::from_secs(30), managed_launch.join).await;
}

async fn wait_for_shutdown(mut shutdown_rx: watch::Receiver<bool>) {
    if *shutdown_rx.borrow() {
        return;
    }

    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

fn prepare_unix_socket(path: &Path) -> anyhow::Result<()> {
    ensure_private_parent_dir(path)?;
    if path.exists() {
        std::fs::remove_file(path).with_context(|| {
            format!("failed to remove stale service socket '{}'", path.display())
        })?;
    }
    Ok(())
}

fn ensure_private_parent_dir(path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create control service directory '{}'",
                parent.display()
            )
        })?;
        #[cfg(unix)]
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to secure control service directory '{}'",
                    parent.display()
                )
            },
        )?;
    }
    Ok(())
}

async fn list_live_sessions() -> anyhow::Result<Vec<LaunchSessionMetadata>> {
    let mut live = Vec::new();
    for session in list_launch_sessions()? {
        match request_launch_session_info(&session.control_socket_path).await {
            Ok(session) => live.push(session),
            Err(_) => {
                if let Some(session_dir) = session.control_socket_path.parent() {
                    let _ = std::fs::remove_dir_all(session_dir);
                }
            }
        }
    }
    live.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    Ok(live)
}

async fn resolve_session(session_id: &str) -> Result<LaunchSessionMetadata, Status> {
    if session_id.trim().is_empty() {
        return Err(Status::invalid_argument("session_id is required"));
    }

    let sessions = list_live_sessions().await.map_err(internal_status)?;
    sessions
        .into_iter()
        .find(|session| session.session_id == session_id)
        .ok_or_else(|| Status::not_found(format!("session '{}' not found", session_id)))
}

fn internal_status(error: anyhow::Error) -> Status {
    Status::internal(error.to_string())
}

fn map_session(session: &LaunchSessionMetadata) -> proto::Session {
    proto::Session {
        session_id: session.session_id.clone(),
        mode: session.mode.clone(),
        control: Some(proto::Endpoint {
            network: "unix".to_string(),
            address: session.control_socket_path.display().to_string(),
        }),
        observation: Some(proto::Endpoint {
            network: session.observation.transport.clone(),
            address: session.observation.path.display().to_string(),
        }),
        container_id: session.container_id.clone().unwrap_or_default(),
        container_name: session.container_name.clone().unwrap_or_default(),
    }
}

fn filter_sessions_for_subscription(
    sessions: Vec<LaunchSessionMetadata>,
    requested_session_id: Option<&str>,
) -> Vec<LaunchSessionMetadata> {
    match requested_session_id {
        Some(session_id) => sessions
            .into_iter()
            .filter(|session| session.session_id == session_id)
            .collect(),
        None => sessions,
    }
}

fn event_type_name(event: &ObservationEvent) -> &'static str {
    match &event.event {
        EventKind::NetworkRequest { .. } => "network_request",
        EventKind::ContainerStart { .. } => "container_start",
        EventKind::ContainerStop { .. } => "container_stop",
        EventKind::Mount { .. } => "mount",
        EventKind::PolicyViolation { .. } => "policy_violation",
        EventKind::PolicyReloaded { .. } => "policy_reloaded",
        EventKind::TtyResized { .. } => "tty_resized",
        EventKind::LiveDecision { .. } => "live_decision",
    }
}

fn exception_suggestions(candidate: &CandidateException) -> Vec<proto::ExceptionSuggestion> {
    [
        ("allow_once", &candidate.once),
        ("allow_session", &candidate.session),
        ("persist", &candidate.persist),
    ]
    .into_iter()
    .map(|(lifetime, directive)| map_exception_suggestion(lifetime, candidate, directive))
    .collect()
}

fn map_exception_suggestion(
    lifetime: &str,
    candidate: &CandidateException,
    directive: &ExceptionDirective,
) -> proto::ExceptionSuggestion {
    proto::ExceptionSuggestion {
        lifetime: lifetime.to_string(),
        summary: directive.summary.clone(),
        cedar_snippet: directive.cedar_snippet.clone(),
        scope: format!("{:?}", candidate.scope).to_ascii_lowercase(),
        ambiguous: candidate.ambiguous,
    }
}

fn blocked_event_from_observation(
    session: &LaunchSessionMetadata,
    event: &ObservationEvent,
) -> Option<proto::BlockedRequestEvent> {
    let session = Some(map_session(session));
    let raw_json = serde_json::to_string(event).ok()?;

    match &event.event {
        EventKind::NetworkRequest {
            method,
            host,
            path,
            decision,
            blocked: Some(blocked),
            ..
        } => Some(proto::BlockedRequestEvent {
            session,
            source_type: "network_request".to_string(),
            blocked_id: blocked.blocked_id.clone(),
            match_key: blocked.match_key.clone(),
            explanation: blocked.explanation.clone(),
            method: method.clone(),
            host: host.clone(),
            path: path.clone(),
            decision: decision.clone(),
            suggestions: blocked
                .candidate_exception
                .as_ref()
                .map(exception_suggestions)
                .unwrap_or_default(),
            raw_json,
        }),
        EventKind::PolicyViolation {
            decision,
            blocked: Some(blocked),
            ..
        } => {
            let (method, host, path) = parse_blocked_match_key(&blocked.match_key);
            Some(proto::BlockedRequestEvent {
                session,
                source_type: "policy_violation".to_string(),
                blocked_id: blocked.blocked_id.clone(),
                match_key: blocked.match_key.clone(),
                explanation: blocked.explanation.clone(),
                method,
                host,
                path,
                decision: decision.clone(),
                suggestions: blocked
                    .candidate_exception
                    .as_ref()
                    .map(exception_suggestions)
                    .unwrap_or_default(),
                raw_json,
            })
        }
        _ => None,
    }
}

fn parse_blocked_match_key(match_key: &str) -> (String, String, String) {
    let remainder = match_key.strip_prefix("http:").unwrap_or(match_key);
    let (method, resource) = remainder.split_once(' ').unwrap_or((remainder, ""));
    if let Some((host, path)) = resource.split_once('/') {
        (method.to_string(), host.to_string(), format!("/{path}"))
    } else {
        (method.to_string(), resource.to_string(), "/".to_string())
    }
}

async fn connect_observation_socket(
    session: &LaunchSessionMetadata,
) -> anyhow::Result<tokio::io::BufReader<tokio::net::UnixStream>> {
    let observation = request_launch_watch_attach(&session.control_socket_path).await?;
    let stream = tokio::net::UnixStream::connect(&observation.path)
        .await
        .with_context(|| {
            format!(
                "failed to connect to observation socket '{}'",
                observation.path.display()
            )
        })?;
    Ok(tokio::io::BufReader::new(stream))
}

fn spawn_subscribe_observation_task(
    session: LaunchSessionMetadata,
    tx: mpsc::Sender<Result<proto::SubscribeEvent, Status>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let Ok(mut reader) = connect_observation_socket(&session).await else {
            return;
        };
        loop {
            let mut line = String::new();
            match reader.read_line(&mut line).await {
                Ok(0) => break,
                Ok(_) => {
                    let line = line.trim();
                    if line.is_empty() {
                        continue;
                    }
                    let event = match serde_json::from_str::<ObservationEvent>(line) {
                        Ok(event) => event,
                        Err(_) => continue,
                    };
                    let observation = proto::SubscribeEvent {
                        event: Some(proto::subscribe_event::Event::Observation(
                            proto::SessionObservationEvent {
                                session: Some(map_session(&session)),
                                event_type: event_type_name(&event).to_string(),
                                raw_json: match serde_json::to_string(&event) {
                                    Ok(json) => json,
                                    Err(_) => continue,
                                },
                            },
                        )),
                    };
                    if tx.send(Ok(observation)).await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    })
}

#[tonic::async_trait]
impl proto::session_control_service_server::SessionControlService for SessionControlApi {
    type StreamBlockedRequestsStream = ReceiverStream<Result<proto::BlockedRequestEvent, Status>>;
    type SubscribeStream = ReceiverStream<Result<proto::SubscribeEvent, Status>>;

    async fn list_sessions(
        &self,
        _request: Request<proto::ListSessionsRequest>,
    ) -> Result<Response<proto::ListSessionsResponse>, Status> {
        let sessions = list_live_sessions().await.map_err(internal_status)?;
        Ok(Response::new(proto::ListSessionsResponse {
            sessions: sessions.iter().map(map_session).collect(),
        }))
    }

    async fn get_session_status(
        &self,
        request: Request<proto::GetSessionStatusRequest>,
    ) -> Result<Response<proto::GetSessionStatusResponse>, Status> {
        let session = resolve_session(&request.into_inner().session_id).await?;
        Ok(Response::new(proto::GetSessionStatusResponse {
            session: Some(map_session(&session)),
        }))
    }

    async fn stream_blocked_requests(
        &self,
        request: Request<proto::StreamBlockedRequestsRequest>,
    ) -> Result<Response<Self::StreamBlockedRequestsStream>, Status> {
        let session = resolve_session(&request.into_inner().session_id).await?;
        let (tx, rx) = mpsc::channel(32);

        tokio::spawn(async move {
            let mut seen_blocked_ids = HashSet::new();
            let Ok(mut reader) = connect_observation_socket(&session).await else {
                let _ = tx
                    .send(Err(Status::internal(
                        "failed to attach to observation socket",
                    )))
                    .await;
                return;
            };

            loop {
                let mut line = String::new();
                match reader.read_line(&mut line).await {
                    Ok(0) => break,
                    Ok(_) => {
                        let line = line.trim();
                        if line.is_empty() {
                            continue;
                        }
                        let event = match serde_json::from_str::<ObservationEvent>(line) {
                            Ok(event) => event,
                            Err(error) => {
                                let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                                break;
                            }
                        };
                        if let Some(blocked) = blocked_event_from_observation(&session, &event) {
                            if seen_blocked_ids.insert(blocked.blocked_id.clone())
                                && tx.send(Ok(blocked)).await.is_err()
                            {
                                break;
                            }
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    async fn submit_decision(
        &self,
        request: Request<proto::SubmitDecisionRequest>,
    ) -> Result<Response<proto::SubmitDecisionResponse>, Status> {
        let request = request.into_inner();
        let session = resolve_session(&request.session_id).await?;
        if request.blocked_id.trim().is_empty() {
            return Err(Status::invalid_argument("blocked_id is required"));
        }

        let outcome = match proto::DecisionAction::try_from(request.action)
            .unwrap_or(proto::DecisionAction::Unspecified)
        {
            proto::DecisionAction::Deny => {
                request_launch_decision_deny(&session.control_socket_path, &request.blocked_id)
                    .await
                    .map_err(internal_status)?
            }
            proto::DecisionAction::AllowOnce => request_launch_decision_allow_once(
                &session.control_socket_path,
                &request.blocked_id,
            )
            .await
            .map_err(internal_status)?,
            proto::DecisionAction::AllowSession => request_launch_decision_allow_session(
                &session.control_socket_path,
                &request.blocked_id,
            )
            .await
            .map_err(internal_status)?,
            proto::DecisionAction::Persist => {
                request_launch_decision_persist(&session.control_socket_path, &request.blocked_id)
                    .await
                    .map_err(internal_status)?
            }
            proto::DecisionAction::Unspecified => {
                return Err(Status::invalid_argument("decision action is required"));
            }
        };

        Ok(Response::new(proto::SubmitDecisionResponse {
            session_id: session.session_id,
            blocked_id: outcome.blocked_id,
            match_key: outcome.match_key,
        }))
    }

    async fn subscribe(
        &self,
        request: Request<tonic::Streaming<proto::SubscribeRequest>>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let mut inbound = request.into_inner();
        let first = inbound.message().await?.unwrap_or(proto::SubscribeRequest {
            session_id: String::new(),
            include_inventory: true,
        });
        let requested_session_id =
            (!first.session_id.trim().is_empty()).then_some(first.session_id);
        let include_inventory = first.include_inventory || requested_session_id.is_none();

        let (tx, rx) = mpsc::channel(64);

        tokio::spawn(async move {
            let mut previous: Option<Vec<proto::Session>> = None;
            let mut observation_task: Option<tokio::task::JoinHandle<()>> = None;
            let mut observed_session: Option<LaunchSessionMetadata> = None;

            loop {
                if tx.is_closed() {
                    break;
                }

                let live_sessions = match list_live_sessions().await {
                    Ok(sessions) => {
                        filter_sessions_for_subscription(sessions, requested_session_id.as_deref())
                    }
                    Err(error) => {
                        let _ = tx.send(Err(Status::internal(error.to_string()))).await;
                        break;
                    }
                };

                if requested_session_id.is_some() {
                    let next_session = live_sessions.first().cloned();
                    if observed_session != next_session {
                        if let Some(task) = observation_task.take() {
                            task.abort();
                        }
                        observation_task = next_session.as_ref().map(|session| {
                            spawn_subscribe_observation_task(session.clone(), tx.clone())
                        });
                        observed_session = next_session;
                    }
                }

                let sessions = live_sessions.iter().map(map_session).collect::<Vec<_>>();

                if include_inventory && previous.as_ref() != Some(&sessions) {
                    let inventory = proto::SubscribeEvent {
                        event: Some(proto::subscribe_event::Event::Inventory(
                            proto::SessionInventory {
                                sessions: sessions.clone(),
                            },
                        )),
                    };
                    if tx.send(Ok(inventory)).await.is_err() {
                        break;
                    }
                }

                if previous.as_ref() != Some(&sessions) {
                    let before: HashMap<_, _> = previous
                        .as_ref()
                        .into_iter()
                        .flat_map(|sessions| sessions.iter())
                        .cloned()
                        .map(|session| (session.session_id.clone(), session))
                        .collect();
                    let after: HashMap<_, _> = sessions
                        .iter()
                        .cloned()
                        .map(|session| (session.session_id.clone(), session))
                        .collect();

                    for (session_id, session) in &after {
                        let state = match before.get(session_id) {
                            None => Some("added"),
                            Some(previous_session) if previous_session != session => {
                                Some("updated")
                            }
                            _ => None,
                        };
                        if let Some(state_value) = state {
                            let update = proto::SubscribeEvent {
                                event: Some(proto::subscribe_event::Event::Status(
                                    proto::SessionStatusChanged {
                                        session: Some(session.clone()),
                                        state: state_value.to_string(),
                                    },
                                )),
                            };
                            if tx.send(Ok(update)).await.is_err() {
                                break;
                            }
                        }
                    }

                    for (session_id, session) in &before {
                        if !after.contains_key(session_id) {
                            let update = proto::SubscribeEvent {
                                event: Some(proto::subscribe_event::Event::Status(
                                    proto::SessionStatusChanged {
                                        session: Some(session.clone()),
                                        state: "removed".to_string(),
                                    },
                                )),
                            };
                            if tx.send(Ok(update)).await.is_err() {
                                break;
                            }
                        }
                    }
                }

                previous = Some(sessions);
                tokio::time::sleep(SESSION_POLL_INTERVAL).await;
            }

            if let Some(task) = observation_task {
                task.abort();
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[tonic::async_trait]
impl proto::service_admin_server::ServiceAdmin for ServiceAdminApi {
    async fn get_service_status(
        &self,
        _request: Request<proto::GetServiceStatusRequest>,
    ) -> Result<Response<proto::GetServiceStatusResponse>, Status> {
        let sessions = list_live_sessions().await.map_err(internal_status)?;
        Ok(Response::new(proto::GetServiceStatusResponse {
            local_endpoint: Some(proto::Endpoint {
                network: "unix".to_string(),
                address: self.state.socket_path.display().to_string(),
            }),
            remote_endpoint: self.state.remote_endpoint.clone(),
            remote_enabled: self.state.remote_endpoint.is_some(),
            session_count: sessions.len() as u32,
            sessions: sessions.iter().map(map_session).collect(),
        }))
    }

    async fn stop_service(
        &self,
        _request: Request<proto::StopServiceRequest>,
    ) -> Result<Response<proto::StopServiceResponse>, Status> {
        let _ = self.state.shutdown_tx.send(true);
        Ok(Response::new(proto::StopServiceResponse { accepted: true }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn session_metadata(session_id: &str) -> LaunchSessionMetadata {
        LaunchSessionMetadata {
            version: launch::SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: session_id.to_string(),
            mode: "observe".to_string(),
            control_socket_path: PathBuf::from(format!("/tmp/{session_id}.control.sock")),
            observation: launch::ObservationHandle {
                transport: "unix".to_string(),
                path: PathBuf::from(format!("/tmp/{session_id}.observe.sock")),
            },
            container_id: None,
            container_name: None,
        }
    }

    #[test]
    fn filter_sessions_for_subscription_returns_all_sessions_when_unscoped() {
        let sessions = vec![session_metadata("alpha"), session_metadata("beta")];

        let filtered = filter_sessions_for_subscription(sessions.clone(), None);

        assert_eq!(filtered, sessions);
    }

    #[test]
    fn filter_sessions_for_subscription_limits_to_requested_session() {
        let sessions = vec![session_metadata("alpha"), session_metadata("beta")];

        let filtered = filter_sessions_for_subscription(sessions, Some("beta"));

        assert_eq!(filtered, vec![session_metadata("beta")]);
    }

    #[tokio::test]
    async fn wait_for_managed_session_uses_exact_published_metadata() {
        let destination = Arc::new(RwLock::new(None));
        let (ready_tx, ready_rx) = oneshot::channel();
        let expected = session_metadata("managed-session");

        ready_tx.send(expected.clone()).unwrap();
        wait_for_managed_session(ready_rx, destination.clone())
            .await
            .unwrap();

        assert_eq!(*destination.read().await, Some(expected));
    }
}
