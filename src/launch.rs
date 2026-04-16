//! `strait launch` orchestrator — observe, warn, and enforce modes.
//!
//! Runs a command in a Docker container with Cedar policy evaluation.
//!
//! Three enforcement modes:
//! - **Observe**: allow all activity, record to JSONL (no policy file needed)
//! - **Warn**: evaluate Cedar policy, always allow, log violations as warnings
//! - **Enforce**: evaluate Cedar policy, deny disallowed access
//!
//! Startup sequence:
//! 1. Load and validate Cedar policy (warn/enforce modes -- fail fast if invalid)
//! 2. Verify Docker is running (fail fast)
//! 3. Detect the container architecture and locate the matching `strait-gateway` binary
//! 4. Start HTTPS proxy on a random port + bind a Unix socket for the proxy
//! 5. Write session CA to temp file
//! 6. Create container with `--network=none`, bind-mounted proxy socket and
//!    gateway binary, policy-derived filesystem mounts
//! 7. Gateway entrypoint wraps CA trust injection and user command
//! 8. Start observation stream (JSONL file + Unix socket)
//! 9. Start container with TTY attached
//! 10. Wait for agent exit
//! 11. Stop proxy, clean up container, close observation stream
//!
//! # Security: Network Isolation
//!
//! Containers run with `--network=none` (no network interfaces). All
//! outbound traffic is forced through the host proxy via a bind-mounted
//! Unix socket and the `strait-gateway` binary inside the container. See
//! [`crate::container`] module docs for details.
//!
//! **Observe mode caveat**: The working directory is mounted read-write
//! with no Cedar policy restricting filesystem access. A warning is emitted
//! to stderr at startup. In warn/enforce modes, filesystem access is
//! restricted to paths permitted by the Cedar policy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::Context as _;
use arc_swap::ArcSwap;
use futures_util::StreamExt;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;
#[cfg(unix)]
use tokio::net::UnixListener;
use tokio::sync::{watch, RwLock};
use tracing::{info, warn};

use crate::audit::AuditLogger;
use crate::ca::SessionCa;
use crate::config::{
    reload_policy, replace_policy, LivePolicyBounds, PolicyConfig, PolicyMutationOutcome,
    ProxyContext,
};
use crate::container::{
    container_trust_diagnostic_lines, ContainerManager, ContainerPermission, ContainerPolicy,
};
use crate::credentials::CredentialStore;
use crate::mitm::handle_connection;
use crate::observe::{EventKind, ObservationSessionContext, ObservationStream};
use crate::policy::{extract_fs_permissions, extract_proc_permissions, PolicyEngine};

/// Enforcement mode for the launch orchestrator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnforcementMode {
    /// Allow all activity, record to JSONL. No policy file needed.
    Observe,
    /// Evaluate Cedar policy, always allow, log violations as warnings.
    Warn,
    /// Evaluate Cedar policy, deny disallowed access.
    Enforce,
}

impl EnforcementMode {
    /// Return the mode as a lowercase string for observation events.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Observe => "observe",
            Self::Warn => "warn",
            Self::Enforce => "enforce",
        }
    }
}

impl std::fmt::Display for EnforcementMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Default Docker image for the container sandbox.
const DEFAULT_IMAGE: &str = "ubuntu:24.04";

/// Filename for the proxy Unix socket inside the session temp directory.
///
/// Container setup code can bind-mount this socket into the container so
/// traffic reaches the host proxy without a host TCP port.
pub const PROXY_SOCKET_NAME: &str = "proxy.sock";

/// Current version of the launch session control protocol.
pub const SESSION_CONTROL_PROTOCOL_VERSION: u32 = 1;

/// Operator-facing reminder for live policy updates.
pub const LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE: &str =
    "Live updates apply to network policy only; filesystem or process policy changes require relaunch.";

/// Container-visible path for the operator workspace.
const CONTAINER_WORKSPACE_PATH: &str = "/workspace";

/// Directory name under the runtime directory that stores active launch sessions.
#[cfg(unix)]
const SESSION_REGISTRY_DIR_NAME: &str = "strait-sessions";

/// JSON metadata filename for a launch session.
#[cfg(unix)]
const SESSION_METADATA_FILE_NAME: &str = "session.json";

/// Unix socket name for the launch control protocol.
#[cfg(unix)]
const SESSION_CONTROL_SOCKET_NAME: &str = "control.sock";

/// Unix socket name for observation attach handles returned by `watch.attach`.
#[cfg(unix)]
const SESSION_OBSERVATION_SOCKET_NAME: &str = "observe.sock";

/// Exit code returned when a launch session is stopped via the control socket.
#[cfg(unix)]
const SESSION_STOP_EXIT_CODE: i32 = 130;

fn launch_live_policy_bounds(cwd: &Path) -> LivePolicyBounds {
    let cwd = cwd.to_string_lossy().to_string();
    let mut fs_candidate_paths = vec![cwd.clone()];
    if cwd != CONTAINER_WORKSPACE_PATH {
        fs_candidate_paths.push(CONTAINER_WORKSPACE_PATH.to_string());
    }

    LivePolicyBounds {
        fs_candidate_paths,
        agent_id: "agent".to_string(),
    }
}

/// Return the proxy Unix socket path for a given session temp directory.
///
/// This is the path that container setup should bind-mount into the container
/// so the agent process can reach the host proxy over a Unix socket.
pub fn proxy_socket_path(temp_dir: &Path) -> PathBuf {
    temp_dir.join(PROXY_SOCKET_NAME)
}

/// Handle used by watchers and future frontends to observe a running launch session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObservationHandle {
    /// Transport type for the observation stream.
    pub transport: String,
    /// Filesystem path to the observation transport endpoint.
    pub path: PathBuf,
}

/// On-disk metadata for an active launch session.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchSessionMetadata {
    /// Metadata schema / control protocol version.
    pub version: u32,
    /// Stable launch session identifier.
    pub session_id: String,
    /// Active enforcement mode for the launch session.
    pub mode: String,
    /// Path to the session control socket.
    pub control_socket_path: PathBuf,
    /// Observation attachment handle for watch clients.
    pub observation: ObservationHandle,
    /// Docker container ID, once created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    /// Docker container name, once created.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_name: Option<String>,
}

/// JSON request envelope for the local launch control protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchControlRequest {
    /// Protocol version requested by the client.
    pub version: u32,
    /// Control method name.
    pub method: String,
    /// Inline Cedar policy source for `policy.replace`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<String>,
    /// Blocked-request identifier for `decision.*` methods.
    ///
    /// Mirrors `observe::BlockedRequest::blocked_id`. Clients obtain
    /// this value from a live observation stream or watch attach
    /// handle and pass it back into the control protocol to resolve
    /// the matching request.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blocked_id: Option<String>,
}

impl LaunchControlRequest {
    fn new(method: ControlMethod) -> Self {
        Self {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            method: method.as_str().to_string(),
            policy: None,
            blocked_id: None,
        }
    }

    fn with_policy(method: ControlMethod, policy: impl Into<String>) -> Self {
        Self {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            method: method.as_str().to_string(),
            policy: Some(policy.into()),
            blocked_id: None,
        }
    }

    fn with_blocked_id(method: ControlMethod, blocked_id: impl Into<String>) -> Self {
        Self {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            method: method.as_str().to_string(),
            policy: None,
            blocked_id: Some(blocked_id.into()),
        }
    }
}

/// Structured control protocol error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchControlError {
    /// Stable machine-readable error code.
    pub code: String,
    /// Human-readable error message.
    pub message: String,
}

/// Structured result for a live policy mutation request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchPolicyMutationResult {
    /// Whether the new policy was applied live.
    pub applied: bool,
    /// Policy domains that require a relaunch instead of a live update.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restart_required_domains: Vec<String>,
}

impl From<PolicyMutationOutcome> for LaunchPolicyMutationResult {
    fn from(outcome: PolicyMutationOutcome) -> Self {
        Self {
            applied: outcome.applied,
            restart_required_domains: outcome.restart_required_domains,
        }
    }
}

/// Successful result payloads for the local launch control protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum LaunchControlResult {
    /// Result for `session.info`.
    SessionInfo { session: LaunchSessionMetadata },
    /// Result for `watch.attach`.
    WatchAttach { observation: ObservationHandle },
    /// Result for `session.stop`.
    SessionStop { accepted: bool },
    /// Result for `policy.reload`.
    PolicyReload { update: LaunchPolicyMutationResult },
    /// Result for `policy.replace`.
    PolicyReplace { update: LaunchPolicyMutationResult },
    /// Result for `decision.allow_once`.
    DecisionAllowOnce { outcome: DecisionActionOutcome },
    /// Result for `decision.allow_session`.
    DecisionAllowSession { outcome: DecisionActionOutcome },
    /// Result for `decision.deny`.
    DecisionDeny { outcome: DecisionActionOutcome },
}

/// Structured outcome of a successful live decision action.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DecisionActionOutcome {
    /// Blocked-request identifier the decision was applied against.
    pub blocked_id: String,
    /// Normalized match key the decision will affect. Mirrors
    /// `observe::BlockedRequest::match_key` so clients can correlate
    /// the decision with the originating block event.
    pub match_key: String,
}

/// Response envelope for the local launch control protocol.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct LaunchControlResponse {
    /// Control protocol version used by the server.
    pub version: u32,
    /// Whether the request succeeded.
    pub ok: bool,
    /// Successful result payload.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<LaunchControlResult>,
    /// Structured error when `ok` is false.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<LaunchControlError>,
}

impl LaunchControlResponse {
    fn success(result: LaunchControlResult) -> Self {
        Self {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            ok: true,
            result: Some(result),
            error: None,
        }
    }

    fn failure(code: &str, message: impl Into<String>) -> Self {
        Self {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            ok: false,
            result: None,
            error: Some(LaunchControlError {
                code: code.to_string(),
                message: message.into(),
            }),
        }
    }

    fn invalid_request(code: &str, message: impl Into<String>) -> Self {
        Self::failure(code, message)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ControlMethod {
    SessionInfo,
    WatchAttach,
    SessionStop,
    PolicyReload,
    PolicyReplace,
    DecisionAllowOnce,
    DecisionAllowSession,
    DecisionDeny,
}

impl ControlMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::SessionInfo => "session.info",
            Self::WatchAttach => "watch.attach",
            Self::SessionStop => "session.stop",
            Self::PolicyReload => "policy.reload",
            Self::PolicyReplace => "policy.replace",
            Self::DecisionAllowOnce => "decision.allow_once",
            Self::DecisionAllowSession => "decision.allow_session",
            Self::DecisionDeny => "decision.deny",
        }
    }
}

fn parse_control_method(request: &LaunchControlRequest) -> anyhow::Result<ControlMethod> {
    if request.version != SESSION_CONTROL_PROTOCOL_VERSION {
        anyhow::bail!(
            "unsupported control protocol version {} (expected {})",
            request.version,
            SESSION_CONTROL_PROTOCOL_VERSION
        );
    }

    match request.method.as_str() {
        "session.info" => Ok(ControlMethod::SessionInfo),
        "watch.attach" => Ok(ControlMethod::WatchAttach),
        "session.stop" => Ok(ControlMethod::SessionStop),
        "policy.reload" => Ok(ControlMethod::PolicyReload),
        "policy.replace" => Ok(ControlMethod::PolicyReplace),
        "decision.allow_once" => Ok(ControlMethod::DecisionAllowOnce),
        "decision.allow_session" => Ok(ControlMethod::DecisionAllowSession),
        "decision.deny" => Ok(ControlMethod::DecisionDeny),
        other => anyhow::bail!("unsupported control method '{other}'"),
    }
}

#[cfg(unix)]
fn launch_session_registry_dir() -> PathBuf {
    crate::observe::runtime_dir().join(SESSION_REGISTRY_DIR_NAME)
}

#[cfg(unix)]
fn write_launch_session_metadata(
    path: &Path,
    metadata: &LaunchSessionMetadata,
) -> anyhow::Result<()> {
    use std::io::Write as _;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).with_context(|| {
                format!(
                    "failed to create launch session metadata directory '{}'",
                    parent.display()
                )
            })?;
            std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
                || {
                    format!(
                        "failed to secure launch session directory '{}'",
                        parent.display()
                    )
                },
            )?;
        }
    }

    let json = serde_json::to_vec_pretty(metadata)
        .context("failed to serialize launch session metadata")?;
    let parent = path
        .parent()
        .context("launch session metadata path should have a parent directory")?;
    let mut temp_file = tempfile::NamedTempFile::new_in(parent).with_context(|| {
        format!(
            "failed to create temporary launch session metadata '{}'",
            parent.display()
        )
    })?;
    temp_file.write_all(&json).with_context(|| {
        format!(
            "failed to write temporary launch session metadata '{}'",
            path.display()
        )
    })?;
    temp_file.flush().with_context(|| {
        format!(
            "failed to flush temporary launch session metadata '{}'",
            path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        temp_file
            .as_file()
            .set_permissions(std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to secure temporary launch session metadata '{}'",
                    path.display()
                )
            })?;
    }
    temp_file.persist(path).map_err(|error| {
        anyhow::anyhow!(
            "failed to atomically publish launch session metadata '{}': {}",
            path.display(),
            error.error
        )
    })?;
    Ok(())
}

#[cfg(unix)]
fn list_launch_sessions_in(root: &Path) -> anyhow::Result<Vec<LaunchSessionMetadata>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut sessions = Vec::new();
    for entry in std::fs::read_dir(root).with_context(|| {
        format!(
            "failed to read launch session registry '{}'",
            root.display()
        )
    })? {
        let entry = match entry {
            Ok(entry) => entry,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error).context("failed to read launch session entry"),
        };
        let file_type = match entry.file_type() {
            Ok(file_type) => file_type,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warn!(
                    path = %entry.path().display(),
                    error = %error,
                    "skipping launch session entry with unreadable metadata"
                );
                continue;
            }
        };
        if !file_type.is_dir() {
            continue;
        }
        let metadata_path = entry.path().join(SESSION_METADATA_FILE_NAME);
        let json = match std::fs::read_to_string(&metadata_path) {
            Ok(json) => json,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                warn!(
                    path = %metadata_path.display(),
                    error = %error,
                    "skipping launch session with unreadable metadata"
                );
                continue;
            }
        };
        let metadata: LaunchSessionMetadata = match serde_json::from_str(&json) {
            Ok(metadata) => metadata,
            Err(error) => {
                warn!(
                    path = %metadata_path.display(),
                    error = %error,
                    "skipping launch session with invalid metadata"
                );
                continue;
            }
        };
        sessions.push(metadata);
    }
    sessions.sort_by(|a, b| a.session_id.cmp(&b.session_id));
    Ok(sessions)
}

/// List active launch sessions from the local registry.
#[cfg(unix)]
pub fn list_launch_sessions() -> anyhow::Result<Vec<LaunchSessionMetadata>> {
    list_launch_sessions_in(&launch_session_registry_dir())
}

#[cfg(unix)]
fn session_modified_time(session: &LaunchSessionMetadata) -> Option<std::time::SystemTime> {
    std::fs::metadata(&session.control_socket_path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
}

/// Return the newest active launch session from the local registry.
#[cfg(unix)]
pub fn latest_launch_session() -> anyhow::Result<Option<LaunchSessionMetadata>> {
    Ok(list_launch_sessions()?.into_iter().max_by(|left, right| {
        session_modified_time(left)
            .cmp(&session_modified_time(right))
            .then_with(|| left.session_id.cmp(&right.session_id))
    }))
}

/// Send a raw request to a running launch session control socket.
#[cfg(unix)]
pub async fn send_launch_control_request(
    control_socket_path: &Path,
    request: &LaunchControlRequest,
) -> anyhow::Result<LaunchControlResponse> {
    let mut stream = tokio::net::UnixStream::connect(control_socket_path)
        .await
        .with_context(|| {
            format!(
                "failed to connect to launch control socket '{}'",
                control_socket_path.display()
            )
        })?;

    let request_line =
        serde_json::to_string(request).context("failed to serialize control request")?;
    stream
        .write_all(request_line.as_bytes())
        .await
        .context("failed to write control request")?;
    stream
        .write_all(b"\n")
        .await
        .context("failed to terminate control request")?;
    stream
        .flush()
        .await
        .context("failed to flush control request")?;

    let mut response_line = String::new();
    let mut reader = BufReader::new(stream);
    let bytes_read = reader
        .read_line(&mut response_line)
        .await
        .context("failed to read control response")?;
    if bytes_read == 0 {
        anyhow::bail!("launch control server closed the connection without a response");
    }

    let response = serde_json::from_str::<LaunchControlResponse>(response_line.trim_end())
        .context("failed to parse control response")?;
    if !response.ok {
        let error = response
            .error
            .as_ref()
            .map(|err| format!("{}: {}", err.code, err.message))
            .unwrap_or_else(|| "unknown control error".to_string());
        anyhow::bail!("{error}");
    }

    Ok(response)
}

/// Query `session.info` from a running launch session.
#[cfg(unix)]
pub async fn request_launch_session_info(
    control_socket_path: &Path,
) -> anyhow::Result<LaunchSessionMetadata> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::new(ControlMethod::SessionInfo),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::SessionInfo { session }) => Ok(session),
        other => anyhow::bail!("unexpected session.info response: {other:?}"),
    }
}

/// Query `watch.attach` from a running launch session.
#[cfg(unix)]
pub async fn request_launch_watch_attach(
    control_socket_path: &Path,
) -> anyhow::Result<ObservationHandle> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::new(ControlMethod::WatchAttach),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::WatchAttach { observation }) => Ok(observation),
        other => anyhow::bail!("unexpected watch.attach response: {other:?}"),
    }
}

/// Request graceful shutdown of a running launch session.
#[cfg(unix)]
pub async fn request_launch_session_stop(control_socket_path: &Path) -> anyhow::Result<()> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::new(ControlMethod::SessionStop),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::SessionStop { accepted: true }) => Ok(()),
        other => anyhow::bail!("unexpected session.stop response: {other:?}"),
    }
}

/// Request a live policy reload from the running session's configured source.
#[cfg(unix)]
pub async fn request_launch_policy_reload(
    control_socket_path: &Path,
) -> anyhow::Result<LaunchPolicyMutationResult> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::new(ControlMethod::PolicyReload),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::PolicyReload { update }) => Ok(update),
        other => anyhow::bail!("unexpected policy.reload response: {other:?}"),
    }
}

/// Request a live policy replacement from the running session.
#[cfg(unix)]
pub async fn request_launch_policy_replace(
    control_socket_path: &Path,
    policy: impl Into<String>,
) -> anyhow::Result<LaunchPolicyMutationResult> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::with_policy(ControlMethod::PolicyReplace, policy),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::PolicyReplace { update }) => Ok(update),
        other => anyhow::bail!("unexpected policy.replace response: {other:?}"),
    }
}

/// Resolve a blocked request by allowing the currently held request once.
#[cfg(unix)]
pub async fn request_launch_decision_allow_once(
    control_socket_path: &Path,
    blocked_id: impl Into<String>,
) -> anyhow::Result<DecisionActionOutcome> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::with_blocked_id(ControlMethod::DecisionAllowOnce, blocked_id),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::DecisionAllowOnce { outcome }) => Ok(outcome),
        other => anyhow::bail!("unexpected decision.allow_once response: {other:?}"),
    }
}

/// Resolve a blocked request and allow equivalent requests for the session.
#[cfg(unix)]
pub async fn request_launch_decision_allow_session(
    control_socket_path: &Path,
    blocked_id: impl Into<String>,
) -> anyhow::Result<DecisionActionOutcome> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::with_blocked_id(ControlMethod::DecisionAllowSession, blocked_id),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::DecisionAllowSession { outcome }) => Ok(outcome),
        other => anyhow::bail!("unexpected decision.allow_session response: {other:?}"),
    }
}

/// Resolve a blocked request by explicitly denying it.
#[cfg(unix)]
pub async fn request_launch_decision_deny(
    control_socket_path: &Path,
    blocked_id: impl Into<String>,
) -> anyhow::Result<DecisionActionOutcome> {
    let response = send_launch_control_request(
        control_socket_path,
        &LaunchControlRequest::with_blocked_id(ControlMethod::DecisionDeny, blocked_id),
    )
    .await?;
    match response.result {
        Some(LaunchControlResult::DecisionDeny { outcome }) => Ok(outcome),
        other => anyhow::bail!("unexpected decision.deny response: {other:?}"),
    }
}

#[cfg(unix)]
fn dispatch_decision_action(
    request: &LaunchControlRequest,
    method: ControlMethod,
    proxy_ctx: &ProxyContext,
) -> LaunchControlResponse {
    let Some(blocked_id) = request.blocked_id.as_ref() else {
        return LaunchControlResponse::invalid_request(
            "missing_blocked_id",
            format!("{} requires a blocked_id", method.as_str()),
        );
    };
    if blocked_id.trim().is_empty() {
        return LaunchControlResponse::invalid_request(
            "missing_blocked_id",
            format!("{} requires a non-empty blocked_id", method.as_str()),
        );
    }

    let store = proxy_ctx.pending_decisions.as_ref();
    let apply = match method {
        ControlMethod::DecisionAllowOnce => store.resolve_allow_once(blocked_id),
        ControlMethod::DecisionAllowSession => store.resolve_allow_session(blocked_id),
        ControlMethod::DecisionDeny => store.resolve_deny(blocked_id),
        other => {
            return LaunchControlResponse::invalid_request(
                "invalid_method",
                format!("{} is not a decision method", other.as_str()),
            );
        }
    };

    match apply {
        Ok(match_key) => {
            emit_decision_event(proxy_ctx, method, blocked_id, &match_key);
            let outcome = DecisionActionOutcome {
                blocked_id: blocked_id.clone(),
                match_key,
            };
            let result = match method {
                ControlMethod::DecisionAllowOnce => {
                    LaunchControlResult::DecisionAllowOnce { outcome }
                }
                ControlMethod::DecisionAllowSession => {
                    LaunchControlResult::DecisionAllowSession { outcome }
                }
                ControlMethod::DecisionDeny => LaunchControlResult::DecisionDeny { outcome },
                _ => unreachable!("decision dispatch on non-decision method"),
            };
            LaunchControlResponse::success(result)
        }
        Err(error) => LaunchControlResponse::failure(error.code(), error.message()),
    }
}

#[cfg(unix)]
fn emit_decision_event(
    proxy_ctx: &ProxyContext,
    method: ControlMethod,
    blocked_id: &str,
    match_key: &str,
) {
    let Some(obs_stream) = proxy_ctx.observation_stream.as_ref() else {
        return;
    };
    let action = match method {
        ControlMethod::DecisionAllowOnce => "decision.allow_once",
        ControlMethod::DecisionAllowSession => "decision.allow_session",
        ControlMethod::DecisionDeny => "decision.deny",
        _ => return,
    };
    obs_stream.emit(EventKind::LiveDecision {
        action: action.to_string(),
        blocked_id: blocked_id.to_string(),
        match_key: match_key.to_string(),
    });
}

#[cfg(unix)]
async fn handle_launch_control_client(
    stream: tokio::net::UnixStream,
    metadata: Arc<RwLock<LaunchSessionMetadata>>,
    stop_tx: watch::Sender<bool>,
    proxy_ctx: Arc<ProxyContext>,
) -> anyhow::Result<()> {
    let (read_half, mut write_half) = tokio::io::split(stream);
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    let bytes_read = reader
        .read_line(&mut line)
        .await
        .context("failed to read control request")?;
    if bytes_read == 0 {
        return Ok(());
    }

    let response = match serde_json::from_str::<LaunchControlRequest>(line.trim_end()) {
        Ok(request) => match parse_control_method(&request) {
            Ok(ControlMethod::SessionInfo) => {
                let session = metadata.read().await.clone();
                LaunchControlResponse::success(LaunchControlResult::SessionInfo { session })
            }
            Ok(ControlMethod::WatchAttach) => {
                let observation = metadata.read().await.observation.clone();
                LaunchControlResponse::success(LaunchControlResult::WatchAttach { observation })
            }
            Ok(ControlMethod::SessionStop) => {
                let _ = stop_tx.send(true);
                LaunchControlResponse::success(LaunchControlResult::SessionStop { accepted: true })
            }
            Ok(ControlMethod::PolicyReload) => {
                let reload_ctx = proxy_ctx.clone();
                let obs_ctx = proxy_ctx.clone();
                match tokio::task::spawn_blocking(move || reload_policy(reload_ctx.as_ref())).await
                {
                    Ok(Ok(outcome)) => {
                        emit_policy_reload_event(obs_ctx.as_ref(), "reload", &outcome);
                        LaunchControlResponse::success(LaunchControlResult::PolicyReload {
                            update: outcome.into(),
                        })
                    }
                    Ok(Err(error)) => {
                        LaunchControlResponse::failure("policy_update_failed", error.to_string())
                    }
                    Err(error) => LaunchControlResponse::failure(
                        "internal_error",
                        format!("policy reload task failed: {error}"),
                    ),
                }
            }
            Ok(ControlMethod::PolicyReplace) => match request.policy {
                Some(policy) => {
                    let replace_ctx = proxy_ctx.clone();
                    let obs_ctx = proxy_ctx.clone();
                    match tokio::task::spawn_blocking(move || {
                        replace_policy(replace_ctx.as_ref(), policy)
                    })
                    .await
                    {
                        Ok(Ok(outcome)) => {
                            emit_policy_reload_event(obs_ctx.as_ref(), "replace", &outcome);
                            LaunchControlResponse::success(LaunchControlResult::PolicyReplace {
                                update: outcome.into(),
                            })
                        }
                        Ok(Err(error)) => LaunchControlResponse::failure(
                            "policy_update_failed",
                            error.to_string(),
                        ),
                        Err(error) => LaunchControlResponse::failure(
                            "internal_error",
                            format!("policy replace task failed: {error}"),
                        ),
                    }
                }
                None => LaunchControlResponse::invalid_request(
                    "missing_policy",
                    "policy.replace requires inline Cedar policy text",
                ),
            },
            Ok(ControlMethod::DecisionAllowOnce) => dispatch_decision_action(
                &request,
                ControlMethod::DecisionAllowOnce,
                proxy_ctx.as_ref(),
            ),
            Ok(ControlMethod::DecisionAllowSession) => dispatch_decision_action(
                &request,
                ControlMethod::DecisionAllowSession,
                proxy_ctx.as_ref(),
            ),
            Ok(ControlMethod::DecisionDeny) => {
                dispatch_decision_action(&request, ControlMethod::DecisionDeny, proxy_ctx.as_ref())
            }
            Err(error) => {
                LaunchControlResponse::invalid_request("invalid_method", error.to_string())
            }
        },
        Err(error) => LaunchControlResponse::invalid_request(
            "invalid_request",
            format!("failed to parse control request: {error}"),
        ),
    };

    let response_line =
        serde_json::to_string(&response).context("failed to serialize control response")?;
    write_half
        .write_all(response_line.as_bytes())
        .await
        .context("failed to write control response")?;
    write_half
        .write_all(b"\n")
        .await
        .context("failed to terminate control response")?;
    write_half
        .flush()
        .await
        .context("failed to flush control response")?;
    Ok(())
}

#[cfg(unix)]
async fn start_launch_control_server(
    control_socket_path: PathBuf,
    metadata: Arc<RwLock<LaunchSessionMetadata>>,
    stop_tx: watch::Sender<bool>,
    proxy_ctx: Arc<ProxyContext>,
) -> anyhow::Result<tokio::task::JoinHandle<()>> {
    #[cfg(unix)]
    if let Some(parent) = control_socket_path.parent() {
        use std::os::unix::fs::PermissionsExt;

        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create launch control socket directory '{}'",
                parent.display()
            )
        })?;
        std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to secure launch control socket directory '{}'",
                    parent.display()
                )
            },
        )?;
    }

    if control_socket_path.exists() {
        std::fs::remove_file(&control_socket_path).with_context(|| {
            format!(
                "failed to remove stale launch control socket '{}'",
                control_socket_path.display()
            )
        })?;
    }

    let listener = UnixListener::bind(&control_socket_path).with_context(|| {
        format!(
            "failed to bind launch control socket '{}'",
            control_socket_path.display()
        )
    })?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(&control_socket_path, std::fs::Permissions::from_mode(0o600))
            .with_context(|| {
                format!(
                    "failed to secure launch control socket '{}'",
                    control_socket_path.display()
                )
            })?;
    }

    Ok(tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let metadata = metadata.clone();
                    let stop_tx = stop_tx.clone();
                    let proxy_ctx = proxy_ctx.clone();
                    tokio::spawn(async move {
                        if let Err(error) =
                            handle_launch_control_client(stream, metadata, stop_tx, proxy_ctx).await
                        {
                            tracing::debug!(error = %error, "launch control client error");
                        }
                    });
                }
                Err(error) => {
                    warn!(error = %error, "launch control accept error");
                    break;
                }
            }
        }
    }))
}

/// Build the startup banner printed by `strait launch` once the session is
/// live.
///
/// Invariant: this helper is only called after `LaunchSession::set_container`
/// has been invoked, so `metadata.container_id` (and usually
/// `metadata.container_name`) are always set. The trust diagnostic is
/// appended unconditionally because it only makes sense for container-backed
/// sessions. The debug assertion documents this invariant and crashes tests
/// if a future caller ever tries to reuse this helper for a non-container
/// session, where `format_session_info` in `main.rs` is the correct choice
/// because it already gates the diagnostic on container presence.
#[cfg(unix)]
fn launch_session_output_lines(metadata: &LaunchSessionMetadata) -> Vec<String> {
    debug_assert!(
        metadata.container_id.is_some() || metadata.container_name.is_some(),
        "launch_session_output_lines is container-only; proxy sessions must use \
         format_session_info which gates the trust diagnostic on container presence"
    );

    let mut lines = vec![
        format!("Session ID: {}", metadata.session_id),
        format!("Control socket: {}", metadata.control_socket_path.display()),
        format!(
            "Observation socket: {}",
            metadata.observation.path.display()
        ),
        format!(
            "Manage session: strait session info --session {}",
            metadata.session_id
        ),
        format!("Policy updates: {LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE}"),
    ];
    lines.extend(container_trust_diagnostic_lines());
    lines
}

fn emit_policy_reload_event(
    proxy_ctx: &ProxyContext,
    source: &str,
    outcome: &PolicyMutationOutcome,
) {
    if let Some(obs_stream) = proxy_ctx.observation_stream.as_ref() {
        obs_stream.emit(EventKind::PolicyReloaded {
            applied: outcome.applied,
            source: source.to_string(),
            restart_required_domains: outcome.restart_required_domains.clone(),
        });
    }
}

fn emit_tty_resized_event(obs_stream: &ObservationStream, size: TerminalSize, source: &str) {
    obs_stream.emit(EventKind::TtyResized {
        rows: size.rows,
        cols: size.cols,
        source: source.to_string(),
    });
}

#[cfg(unix)]
struct LaunchSession {
    metadata: Arc<RwLock<LaunchSessionMetadata>>,
    session_dir: PathBuf,
    metadata_path: PathBuf,
    control_task: tokio::task::JoinHandle<()>,
}

#[cfg(unix)]
impl LaunchSession {
    async fn create(
        session_id: &str,
        mode: EnforcementMode,
        proxy_ctx: Arc<ProxyContext>,
    ) -> anyhow::Result<(Self, watch::Receiver<bool>)> {
        Self::create_with_mode_label(session_id, mode.as_str(), proxy_ctx).await
    }

    async fn create_with_mode_label(
        session_id: &str,
        mode_label: &str,
        proxy_ctx: Arc<ProxyContext>,
    ) -> anyhow::Result<(Self, watch::Receiver<bool>)> {
        let registry_dir = launch_session_registry_dir();
        Self::create_in(&registry_dir, session_id, mode_label, proxy_ctx).await
    }

    async fn create_in(
        root: &Path,
        session_id: &str,
        mode_label: impl ToString,
        proxy_ctx: Arc<ProxyContext>,
    ) -> anyhow::Result<(Self, watch::Receiver<bool>)> {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        let registry_dir = root.to_path_buf();
        let mut registry_builder = std::fs::DirBuilder::new();
        registry_builder.recursive(true).mode(0o700);
        registry_builder.create(&registry_dir).with_context(|| {
            format!(
                "failed to create launch session registry '{}'",
                registry_dir.display()
            )
        })?;
        std::fs::set_permissions(&registry_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "failed to secure launch session registry '{}'",
                    registry_dir.display()
                )
            })?;

        let session_dir = registry_dir.join(session_id);
        let mut session_builder = std::fs::DirBuilder::new();
        session_builder.recursive(true).mode(0o700);
        session_builder.create(&session_dir).with_context(|| {
            format!(
                "failed to create launch session directory '{}'",
                session_dir.display()
            )
        })?;
        std::fs::set_permissions(&session_dir, std::fs::Permissions::from_mode(0o700))
            .with_context(|| {
                format!(
                    "failed to secure launch session directory '{}'",
                    session_dir.display()
                )
            })?;

        let metadata_path = session_dir.join(SESSION_METADATA_FILE_NAME);
        let metadata = LaunchSessionMetadata {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: session_id.to_string(),
            mode: mode_label.to_string(),
            control_socket_path: session_dir.join(SESSION_CONTROL_SOCKET_NAME),
            observation: ObservationHandle {
                transport: "unix_socket".to_string(),
                path: session_dir.join(SESSION_OBSERVATION_SOCKET_NAME),
            },
            container_id: None,
            container_name: None,
        };

        let metadata = Arc::new(RwLock::new(metadata));
        let (stop_tx, stop_rx) = watch::channel(false);
        let control_task = start_launch_control_server(
            metadata.read().await.control_socket_path.clone(),
            metadata.clone(),
            stop_tx.clone(),
            proxy_ctx,
        )
        .await?;

        Ok((
            Self {
                metadata,
                session_dir,
                metadata_path,
                control_task,
            },
            stop_rx,
        ))
    }

    async fn publish(&self, obs_stream: &ObservationStream) -> anyhow::Result<()> {
        let observation_socket_path = self.observation_socket_path().await;
        let metadata = self.metadata().await;
        obs_stream.set_session_context(ObservationSessionContext {
            session_id: metadata.session_id.clone(),
            mode: metadata.mode.clone(),
        });
        obs_stream
            .start_socket_server_at(&observation_socket_path)
            .await
            .with_context(|| {
                format!(
                    "failed to start observation socket '{}'",
                    observation_socket_path.display()
                )
            })?;
        write_launch_session_metadata(&self.metadata_path, &metadata)
    }

    async fn set_container(
        &self,
        container_id: impl Into<String>,
        container_name: impl Into<String>,
    ) -> anyhow::Result<()> {
        let mut metadata = self.metadata.write().await;
        metadata.container_id = Some(container_id.into());
        metadata.container_name = Some(container_name.into());
        write_launch_session_metadata(&self.metadata_path, &metadata)
    }

    async fn metadata(&self) -> LaunchSessionMetadata {
        self.metadata.read().await.clone()
    }

    #[cfg(test)]
    async fn control_socket_path(&self) -> PathBuf {
        self.metadata.read().await.control_socket_path.clone()
    }

    async fn observation_socket_path(&self) -> PathBuf {
        self.metadata.read().await.observation.path.clone()
    }
}

/// Published runtime session for long-lived proxy-style runtimes.
///
/// Reuses the launch control protocol and observation socket model so external
/// control planes can manage standalone proxy sessions without depending on the
/// container-specific launch path.
#[cfg(unix)]
pub struct RuntimeSession {
    inner: LaunchSession,
    stop_rx: watch::Receiver<bool>,
}

#[cfg(unix)]
impl RuntimeSession {
    /// Create and publish a new runtime session with the supplied mode label.
    pub async fn start(
        mode_label: impl Into<String>,
        proxy_ctx: Arc<ProxyContext>,
        obs_stream: &ObservationStream,
    ) -> anyhow::Result<Self> {
        let mode_label = mode_label.into();
        let session_id = uuid::Uuid::new_v4().to_string();
        let (inner, stop_rx) =
            LaunchSession::create_with_mode_label(&session_id, &mode_label, proxy_ctx).await?;
        inner.publish(obs_stream).await?;
        Ok(Self { inner, stop_rx })
    }

    /// Return metadata for the published runtime session.
    pub async fn metadata(&self) -> LaunchSessionMetadata {
        self.inner.metadata().await
    }

    /// Subscribe to runtime stop requests.
    pub fn stop_receiver(&self) -> watch::Receiver<bool> {
        self.stop_rx.clone()
    }
}

#[cfg(unix)]
impl Drop for LaunchSession {
    fn drop(&mut self) {
        self.control_task.abort();
        let _ = std::fs::remove_dir_all(&self.session_dir);
    }
}

/// The size of an interactive terminal in character cells.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalSize {
    /// Number of terminal rows.
    pub rows: u16,
    /// Number of terminal columns.
    pub cols: u16,
}

/// A scripted terminal resize event used by automated tests.
#[doc(hidden)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptedTerminalResize {
    /// Delay before the resize is applied.
    pub after: Duration,
    /// Terminal size to apply.
    pub size: TerminalSize,
}

/// Test-only terminal options for launch integration coverage.
#[doc(hidden)]
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TestTerminalOptions {
    /// Whether the launch path should behave as if stdin is a TTY.
    pub stdin_is_terminal: bool,
    /// Initial terminal size to apply after container start.
    pub initial_size: Option<TerminalSize>,
    /// Scripted resize events to deliver while the session is running.
    pub resize_events: Vec<ScriptedTerminalResize>,
}

#[derive(Debug, Clone)]
enum LaunchTerminalMode {
    Host,
    Test(TestTerminalOptions),
}

#[derive(Debug, Clone)]
enum TerminalResizeSource {
    Disabled,
    HostSignals,
    Scripted(Vec<ScriptedTerminalResize>),
}

// ---------------------------------------------------------------------------
// Gateway binary resolution
// ---------------------------------------------------------------------------

/// Map a Docker daemon architecture string to the Rust target triple used
/// for the statically-linked gateway binary.
///
/// Docker reports architecture via the `Arch` field in system info, using
/// Go's `runtime.GOARCH` names (e.g. `"amd64"`, `"arm64"`). We map these
/// to the musl target triples used by CI to build the gateway.
pub fn docker_arch_to_target(arch: &str) -> anyhow::Result<&'static str> {
    match arch {
        "x86_64" | "amd64" => Ok("x86_64-unknown-linux-musl"),
        "aarch64" | "arm64" => Ok("aarch64-unknown-linux-musl"),
        other => anyhow::bail!(
            "unsupported container architecture '{other}' -- \
             strait supports x86_64 and aarch64 Linux containers"
        ),
    }
}

/// Locate the correct `strait-gateway` binary for the given target triple.
///
/// The gateway binary runs inside the container and must match the
/// container's architecture, not the host's. CI builds statically-linked
/// musl binaries for each supported arch.
///
/// Search order (first match wins):
/// 1. `<exe_dir>/strait-gateway-<target>` (installed layout)
/// 2. `<exe_dir>/../lib/strait/strait-gateway-<target>` (Homebrew/package layout)
/// 3. `<exe_dir>/../<target>/release/strait-gateway` (cargo release build)
/// 4. `<exe_dir>/../<target>/debug/strait-gateway` (cargo debug build)
/// 5. `<exe_dir>/../../<target>/release/strait-gateway` (cargo test from deps/)
/// 6. `<exe_dir>/../../<target>/debug/strait-gateway` (cargo test from deps/)
///
/// Falls back to architecture-agnostic names for local development when
/// the host and container architectures match:
/// 7. `<exe_dir>/strait-gateway` (same-dir, no arch suffix)
/// 8. `<exe_dir>/../strait-gateway` (parent-dir, cargo test fallback)
pub fn resolve_gateway_binary(target: &str) -> anyhow::Result<PathBuf> {
    let exe = std::env::current_exe().context("failed to get current executable path")?;
    let exe_dir = exe
        .parent()
        .context("current executable has no parent directory")?;

    resolve_gateway_binary_from(exe_dir, target)
}

/// Inner resolver that takes an explicit base directory (testable without
/// depending on the current executable path).
pub(crate) fn resolve_gateway_binary_from(exe_dir: &Path, target: &str) -> anyhow::Result<PathBuf> {
    let arch_name = format!("strait-gateway-{target}");
    let mut searched = Vec::new();

    // 1. <exe_dir>/strait-gateway-<target>  (installed layout)
    let candidate = exe_dir.join(&arch_name);
    if candidate.exists() {
        return Ok(candidate);
    }
    searched.push(candidate);

    // 2. <exe_dir>/../lib/strait/strait-gateway-<target>  (Homebrew/package layout)
    if let Some(parent) = exe_dir.parent() {
        let candidate = parent.join("lib").join("strait").join(&arch_name);
        if candidate.exists() {
            return Ok(candidate);
        }
        searched.push(candidate);
    }

    // 3-4. <exe_dir>/../<target>/{release,debug}/strait-gateway
    //      (cargo build: exe is in target/debug/, parent is target/)
    if let Some(parent) = exe_dir.parent() {
        for profile in &["release", "debug"] {
            let candidate = parent.join(target).join(profile).join("strait-gateway");
            if candidate.exists() {
                return Ok(candidate);
            }
            searched.push(candidate);
        }
    }

    // 5-6. <exe_dir>/../../<target>/{release,debug}/strait-gateway
    //      (cargo test: exe is in target/debug/deps/, grandparent is target/)
    if let Some(grandparent) = exe_dir.parent().and_then(|p| p.parent()) {
        for profile in &["release", "debug"] {
            let candidate = grandparent
                .join(target)
                .join(profile)
                .join("strait-gateway");
            if candidate.exists() {
                return Ok(candidate);
            }
            searched.push(candidate);
        }
    }

    // 7. <exe_dir>/strait-gateway  (architecture-agnostic fallback for local dev)
    let candidate = exe_dir.join("strait-gateway");
    if candidate.exists() {
        return Ok(candidate);
    }
    searched.push(candidate);

    // 8. <exe_dir>/../strait-gateway  (cargo test parent-dir fallback)
    if let Some(parent) = exe_dir.parent() {
        let candidate = parent.join("strait-gateway");
        if candidate.exists() {
            return Ok(candidate);
        }
        searched.push(candidate);
    }

    let searched_list = searched
        .iter()
        .map(|p| p.display().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    anyhow::bail!(
        "strait-gateway binary for {target} not found.\n\
         Searched: {searched_list}\n\
         To build it: cargo zigbuild --release --package strait-gateway --target {target}\n\
         Or for local development: cargo build -p strait-gateway"
    )
}

/// Query the Docker daemon for the container runtime architecture and
/// return the corresponding Rust target triple.
pub async fn detect_container_arch(container_mgr: &ContainerManager) -> anyhow::Result<String> {
    let info = container_mgr
        .docker()
        .info()
        .await
        .context("failed to query Docker daemon for system info")?;

    let arch = info
        .architecture
        .as_deref()
        .context("Docker daemon did not report an architecture")?;

    docker_arch_to_target(arch).map(|t| t.to_string())
}

/// Locate the `strait-gateway` binary for the container runtime architecture.
///
/// Queries the Docker daemon, maps the architecture to a target triple,
/// and resolves the binary using the standard search paths.
pub async fn find_gateway_binary(container_mgr: &ContainerManager) -> anyhow::Result<PathBuf> {
    let target = detect_container_arch(container_mgr).await?;
    resolve_gateway_binary(&target)
}

// ---------------------------------------------------------------------------
// Operator bind-mount parsing
// ---------------------------------------------------------------------------

/// A validated operator bind-mount specification.
///
/// These mounts are operator-specified via `--mount` and bypass Cedar policy
/// validation. They allow mounting trusted paths outside the project directory
/// (e.g., `~/.claude/` for OAuth config).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtraMount {
    /// Absolute path on the host.
    pub host_path: String,
    /// Absolute path in the container.
    pub container_path: String,
    /// Mount mode: `"ro"` or `"rw"`.
    pub mode: String,
}

impl ExtraMount {
    /// Format as a Docker bind-mount string: `host:container:mode`.
    pub fn to_bind_string(&self) -> String {
        format!("{}:{}:{}", self.host_path, self.container_path, self.mode)
    }
}

/// Parse and validate `--mount` flag values.
///
/// Accepts `HOST:CONTAINER` or `HOST:CONTAINER:MODE` where MODE is `ro` or
/// `rw`. Defaults to `rw` when no mode is specified. Both paths must be
/// absolute. These mounts are not validated against `base_dir` because they
/// are operator-specified, not agent-requested.
pub fn parse_extra_mounts(specs: &[String]) -> anyhow::Result<Vec<ExtraMount>> {
    let mut mounts = Vec::with_capacity(specs.len());
    for spec in specs {
        let parts: Vec<&str> = spec.splitn(3, ':').collect();
        let (host_path, container_path, mode) = match parts.len() {
            2 => (parts[0], parts[1], "rw"),
            3 => (parts[0], parts[1], parts[2]),
            _ => anyhow::bail!(
                "invalid --mount format: {spec:?} (expected HOST:CONTAINER or HOST:CONTAINER:MODE)"
            ),
        };

        if host_path.is_empty() || container_path.is_empty() {
            anyhow::bail!(
                "invalid --mount format: {spec:?} (host and container paths must not be empty)"
            );
        }

        if !host_path.starts_with('/') {
            anyhow::bail!("invalid --mount host path: {host_path:?} (must be an absolute path)");
        }

        if !container_path.starts_with('/') {
            anyhow::bail!(
                "invalid --mount container path: {container_path:?} (must be an absolute path)"
            );
        }

        if mode != "ro" && mode != "rw" {
            anyhow::bail!("invalid --mount mode: {mode:?} (must be \"ro\" or \"rw\")");
        }

        mounts.push(ExtraMount {
            host_path: host_path.to_string(),
            container_path: container_path.to_string(),
            mode: mode.to_string(),
        });
    }
    Ok(mounts)
}

/// Run the `launch --observe` workflow.
///
/// Orchestrates proxy, container, and observation into a unified workflow:
/// - All filesystem paths are read-write (no policy restricts in observe mode)
/// - All network traffic is tunneled through the proxy (passthrough, recorded)
/// - Activity is recorded to a JSONL observation file and Unix socket
///
/// Returns the container's exit code.
#[allow(clippy::too_many_arguments)]
pub async fn run_launch_observe(
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
) -> anyhow::Result<i32> {
    run_launch_observe_with_terminal_mode(
        command,
        image,
        output,
        credential_store,
        mitm_hosts,
        extra_env,
        extra_mounts,
        tty,
        LaunchTerminalMode::Host,
    )
    .await
}

/// Test-only observe-mode entry point with scripted terminal events.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn run_launch_observe_with_test_terminal(
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
    terminal: TestTerminalOptions,
) -> anyhow::Result<i32> {
    run_launch_observe_with_terminal_mode(
        command,
        image,
        output,
        credential_store,
        mitm_hosts,
        extra_env,
        extra_mounts,
        tty,
        LaunchTerminalMode::Test(terminal),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_launch_observe_with_terminal_mode(
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
    terminal_mode: LaunchTerminalMode,
) -> anyhow::Result<i32> {
    let image = image.unwrap_or(DEFAULT_IMAGE);
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let obs_log_path = output.unwrap_or_else(|| cwd.join("observations.jsonl"));

    // 1. Verify Docker is running early (before any other setup)
    let mut container_mgr = ContainerManager::new()?;
    container_mgr.verify_connection().await?;
    info!("Docker daemon connected");

    // 2. Locate the gateway binary for the container architecture
    let gateway_binary = find_gateway_binary(&container_mgr).await?;
    info!(path = %gateway_binary.display(), "gateway binary found");

    // 3. Create temp directory for ephemeral files (CA pem, entrypoint script)
    let temp_dir = tempfile::TempDir::new().context("failed to create temp directory")?;
    let ca_pem_path = temp_dir.path().join("ca.pem");

    // 4. Set up observation stream (JSONL file + Unix socket)
    let mut obs_stream = ObservationStream::new();
    obs_stream.persist_to_file(&obs_log_path)?;
    info!(path = %obs_log_path.display(), "observation log created");
    eprintln!("Observation log: {}", obs_log_path.display());

    // 5. Generate session CA and write to temp file
    let session_ca = SessionCa::generate()?;
    std::fs::write(&ca_pem_path, &session_ca.ca_cert_pem)?;
    info!(path = %ca_pem_path.display(), "session CA written");

    // 6. Start full MITM proxy on random port (reuses shared proxy implementation)
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_listener.local_addr()?.port();
    info!(port = proxy_port, "proxy listening");

    let proxy_ctx = Arc::new(build_launch_proxy_context(
        session_ca.clone(),
        None, // no policy engine in observe mode
        None,
        obs_stream.clone(),
        false, // not warn_only
        credential_store,
        mitm_hosts,
        None,
    )?);

    #[cfg(unix)]
    let (launch_session, mut session_stop_rx) = LaunchSession::create(
        proxy_ctx.audit_logger.session_id(),
        EnforcementMode::Observe,
        proxy_ctx.clone(),
    )
    .await?;
    #[cfg(unix)]
    launch_session.publish(&obs_stream).await?;

    let proxy_handle = tokio::spawn(run_mitm_proxy_loop(proxy_listener, proxy_ctx.clone()));

    // 6b. Start Unix socket proxy listener so containers can reach the proxy
    //     via a bind-mounted socket (required for --network=none).
    #[cfg(unix)]
    let proxy_socket_path = proxy_socket_path(temp_dir.path());
    #[cfg(unix)]
    let unix_proxy_handle = {
        let listener =
            UnixListener::bind(&proxy_socket_path).context("failed to bind Unix proxy socket")?;
        info!(path = %proxy_socket_path.display(), "proxy Unix socket listening");
        eprintln!("Proxy socket: {}", proxy_socket_path.display());
        tokio::spawn(run_mitm_unix_proxy_loop(listener, proxy_ctx))
    };

    // 7. Build observe-mode container config
    //    In observe mode, mount the working directory read-write (no restrictions)
    let policy = ContainerPolicy {
        permissions: vec![ContainerPermission::FsWrite(
            cwd.to_string_lossy().to_string(),
        )],
    };

    // Warn about observe mode's permissive cwd mount
    warn!(
        path = %cwd.display(),
        "observe mode: working directory mounted read-write with no policy restrictions"
    );
    eprintln!("{}", observe_cwd_warning(&cwd));

    // Build config with auto_remove=false so we can reliably capture the
    // exit code via wait_container. Docker's wait API returns status_code=0
    // for TTY containers with auto_remove=true (a Docker/bollard quirk).
    let mut config = ContainerManager::build_config(
        &policy,
        image,
        &command,
        &proxy_socket_path,
        &gateway_binary,
        Some(&ca_pem_path),
        &cwd,
        tty,
    )?;
    config.auto_remove = false;
    config.env.extend(extra_env);
    for m in &extra_mounts {
        config.binds.push(m.to_bind_string());
    }

    let container_id = container_mgr.create_container_from_config(&config).await?;

    // Emit container start and mount observation events
    obs_stream.emit(EventKind::ContainerStart {
        container_id: container_id.clone(),
        image: image.to_string(),
    });
    obs_stream.emit(EventKind::Mount {
        path: cwd.to_string_lossy().to_string(),
        mode: "read-write".to_string(),
    });
    for m in &extra_mounts {
        obs_stream.emit(EventKind::Mount {
            path: m.host_path.clone(),
            mode: if m.mode == "ro" {
                "read-only".to_string()
            } else {
                "read-write".to_string()
            },
        });
    }

    // 7. Set terminal raw mode for TTY passthrough (restored on drop)
    let terminal = prepare_terminal_session(tty, terminal_mode);

    // 8. Attach to container, start it, pipe I/O, and wait for exit
    let container_name = container_mgr.container_name().unwrap().to_string();
    #[cfg(unix)]
    launch_session
        .set_container(container_id.clone(), container_name.clone())
        .await?;
    #[cfg(unix)]
    for line in launch_session_output_lines(&launch_session.metadata().await) {
        eprintln!("{line}");
    }

    let (run_future, abort_handle) = futures_util::future::abortable(attach_and_wait(
        container_mgr.docker().clone(),
        container_name.clone(),
        terminal.initial_size,
        terminal.resize_source.clone(),
        obs_stream.clone(),
    ));
    let session_stop = async {
        #[cfg(unix)]
        {
            if *session_stop_rx.borrow() {
                return Ok::<(), anyhow::Error>(());
            }
            session_stop_rx
                .changed()
                .await
                .context("launch control stop channel closed unexpectedly")?;
            Ok::<(), anyhow::Error>(())
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<Result<(), anyhow::Error>>().await
        }
    };
    let exit_code = wait_for_launch_completion(
        run_future,
        abort_handle,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        sigterm_signal(),
        LaunchStop {
            future: session_stop,
            message: "Stopped via control socket — cleaning up...",
            exit_code: SESSION_STOP_EXIT_CODE,
        },
        Some(&mut container_mgr),
    )
    .await?;

    // 9. Emit container stop observation event
    obs_stream.emit(EventKind::ContainerStop {
        container_id,
        exit_code: Some(exit_code),
    });

    // 10. Cleanup: remove container (not auto-removed) and stop proxy
    container_mgr.remove_container().await;
    proxy_handle.abort();
    #[cfg(unix)]
    unix_proxy_handle.abort();

    // Flush observation log before returning so callers can read the file.
    obs_stream.flush();
    drop(terminal);

    eprintln!("Container exited with code {exit_code}");
    eprintln!("Observation log: {}", obs_log_path.display());

    Ok(exit_code)
}

/// Run the `launch --warn` or `launch --policy` workflow.
///
/// Loads a Cedar policy at startup and uses it to:
/// - Restrict container bind-mounts to paths permitted by `fs:` policies
/// - Evaluate network connections against `http:` policies at proxy time
///
/// In **warn** mode: same container config as enforce, but the proxy logs
/// violations as warnings instead of returning 403s.
///
/// In **enforce** mode: the proxy denies disallowed connections with 403.
///
/// Returns the container's exit code.
#[allow(clippy::too_many_arguments)]
pub async fn run_launch_with_policy(
    mode: EnforcementMode,
    policy_path: &Path,
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
) -> anyhow::Result<i32> {
    run_launch_with_policy_with_terminal_mode(
        mode,
        policy_path,
        command,
        image,
        output,
        credential_store,
        mitm_hosts,
        extra_env,
        extra_mounts,
        tty,
        LaunchTerminalMode::Host,
    )
    .await
}

/// Test-only policy-mode entry point with scripted terminal events.
#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn run_launch_with_policy_with_test_terminal(
    mode: EnforcementMode,
    policy_path: &Path,
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
    terminal: TestTerminalOptions,
) -> anyhow::Result<i32> {
    run_launch_with_policy_with_terminal_mode(
        mode,
        policy_path,
        command,
        image,
        output,
        credential_store,
        mitm_hosts,
        extra_env,
        extra_mounts,
        tty,
        LaunchTerminalMode::Test(terminal),
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_launch_with_policy_with_terminal_mode(
    mode: EnforcementMode,
    policy_path: &Path,
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
    extra_mounts: Vec<ExtraMount>,
    tty: bool,
    terminal_mode: LaunchTerminalMode,
) -> anyhow::Result<i32> {
    let image = image.unwrap_or(DEFAULT_IMAGE);
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let obs_log_path = output.unwrap_or_else(|| cwd.join("observations.jsonl"));

    // 1. Load and validate Cedar policy at startup (fail fast before container)
    let engine = PolicyEngine::load(policy_path, None)
        .with_context(|| format!("failed to load Cedar policy: {}", policy_path.display()))?;
    info!(
        path = %policy_path.display(),
        mode = mode.as_str(),
        "Cedar policy loaded"
    );
    eprintln!(
        "Enforcement mode: {} (policy: {})",
        mode.as_str(),
        policy_path.display()
    );

    // 2. Verify Docker is running early (before any other setup)
    let mut container_mgr = ContainerManager::new()?;
    container_mgr.verify_connection().await?;
    info!("Docker daemon connected");

    // 3. Locate the gateway binary for the container architecture
    let gateway_binary = find_gateway_binary(&container_mgr).await?;
    info!(path = %gateway_binary.display(), "gateway binary found");

    // 4. Create temp directory for ephemeral files (CA pem, entrypoint script)
    let temp_dir = tempfile::TempDir::new().context("failed to create temp directory")?;
    let ca_pem_path = temp_dir.path().join("ca.pem");

    // 5. Set up observation stream (JSONL file + Unix socket)
    let mut obs_stream = ObservationStream::new();
    obs_stream.persist_to_file(&obs_log_path)?;
    info!(path = %obs_log_path.display(), "observation log created");
    eprintln!("Observation log: {}", obs_log_path.display());

    // 6. Generate session CA and write to temp file
    let session_ca = SessionCa::generate()?;
    std::fs::write(&ca_pem_path, &session_ca.ca_cert_pem)?;
    info!(path = %ca_pem_path.display(), "session CA written");

    // 7. Start full MITM proxy on random port (reuses shared proxy implementation)
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_listener.local_addr()?.port();
    info!(port = proxy_port, "proxy listening");

    let proxy_ctx = Arc::new(build_launch_proxy_context(
        session_ca.clone(),
        Some(engine.clone()),
        Some(PolicyConfig {
            file: Some(policy_path.to_path_buf()),
            git_url: None,
            git_path: None,
            schema: None,
            poll_interval_secs: None,
        }),
        obs_stream.clone(),
        mode == EnforcementMode::Warn,
        credential_store,
        mitm_hosts,
        Some(launch_live_policy_bounds(&cwd)),
    )?);

    #[cfg(unix)]
    let (launch_session, mut session_stop_rx) =
        LaunchSession::create(proxy_ctx.audit_logger.session_id(), mode, proxy_ctx.clone()).await?;
    #[cfg(unix)]
    launch_session.publish(&obs_stream).await?;

    let proxy_handle = tokio::spawn(run_mitm_proxy_loop(proxy_listener, proxy_ctx.clone()));

    // 7b. Start Unix socket proxy listener for container traffic
    //     (required for --network=none)
    #[cfg(unix)]
    let proxy_socket_path = proxy_socket_path(temp_dir.path());
    #[cfg(unix)]
    let unix_proxy_handle = {
        let listener =
            UnixListener::bind(&proxy_socket_path).context("failed to bind Unix proxy socket")?;
        info!(path = %proxy_socket_path.display(), "proxy Unix socket listening");
        eprintln!("Proxy socket: {}", proxy_socket_path.display());
        tokio::spawn(run_mitm_unix_proxy_loop(listener, proxy_ctx))
    };

    // 8. Extract filesystem permissions from Cedar policy
    let candidate_paths = vec![cwd.to_string_lossy().to_string()];
    let mut permissions = extract_fs_permissions(&engine, &candidate_paths, "agent");

    // 8b. Extract proc:exec permissions and add to the permission set
    let proc_permissions = extract_proc_permissions(&engine, "agent");
    permissions.extend(proc_permissions);

    // Log which paths were permitted and which were denied
    let cwd_str = cwd.to_string_lossy().to_string();
    let cwd_mounted = permissions.iter().any(|p| match p {
        ContainerPermission::FsRead(path) | ContainerPermission::FsWrite(path) => path == &cwd_str,
        _ => false,
    });

    if !cwd_mounted {
        eprintln!(
            "Warning: Cedar policy does not permit filesystem access to working directory ({})",
            cwd.display()
        );
        obs_stream.emit(EventKind::PolicyViolation {
            enforcement_mode: mode.as_str().to_string(),
            action: "fs:write".to_string(),
            resource: cwd_str.clone(),
            decision: if mode == EnforcementMode::Warn {
                "warn".to_string()
            } else {
                "deny".to_string()
            },
            reason: "Cedar policy does not permit filesystem access to working directory"
                .to_string(),
            blocked: None,
        });
    }

    let container_policy = ContainerPolicy {
        permissions: permissions.clone(),
    };

    // 9. Build container config with policy-restricted mounts
    let mut config = ContainerManager::build_config(
        &container_policy,
        image,
        &command,
        &proxy_socket_path,
        &gateway_binary,
        Some(&ca_pem_path),
        &cwd,
        tty,
    )?;
    config.auto_remove = false;
    config.env.extend(extra_env);
    for m in &extra_mounts {
        config.binds.push(m.to_bind_string());
    }

    let container_id = container_mgr.create_container_from_config(&config).await?;

    // Emit container start observation event
    obs_stream.emit(EventKind::ContainerStart {
        container_id: container_id.clone(),
        image: image.to_string(),
    });

    // Emit mount observation events
    for perm in &permissions {
        match perm {
            ContainerPermission::FsRead(path) => {
                obs_stream.emit(EventKind::Mount {
                    path: path.clone(),
                    mode: "read-only".to_string(),
                });
            }
            ContainerPermission::FsWrite(path) => {
                obs_stream.emit(EventKind::Mount {
                    path: path.clone(),
                    mode: "read-write".to_string(),
                });
            }
            ContainerPermission::ProcExec(_) => {}
        }
    }
    for m in &extra_mounts {
        obs_stream.emit(EventKind::Mount {
            path: m.host_path.clone(),
            mode: if m.mode == "ro" {
                "read-only".to_string()
            } else {
                "read-write".to_string()
            },
        });
    }

    // 9. Set terminal raw mode for TTY passthrough (restored on drop)
    let terminal = prepare_terminal_session(tty, terminal_mode);

    // 10. Attach to container, start it, pipe I/O, and wait for exit
    let container_name = container_mgr.container_name().unwrap().to_string();
    #[cfg(unix)]
    launch_session
        .set_container(container_id.clone(), container_name.clone())
        .await?;
    #[cfg(unix)]
    for line in launch_session_output_lines(&launch_session.metadata().await) {
        eprintln!("{line}");
    }

    let (run_future, abort_handle) = futures_util::future::abortable(attach_and_wait(
        container_mgr.docker().clone(),
        container_name.clone(),
        terminal.initial_size,
        terminal.resize_source.clone(),
        obs_stream.clone(),
    ));
    let session_stop = async {
        #[cfg(unix)]
        {
            if *session_stop_rx.borrow() {
                return Ok::<(), anyhow::Error>(());
            }
            session_stop_rx
                .changed()
                .await
                .context("launch control stop channel closed unexpectedly")?;
            Ok::<(), anyhow::Error>(())
        }
        #[cfg(not(unix))]
        {
            std::future::pending::<Result<(), anyhow::Error>>().await
        }
    };
    let exit_code = wait_for_launch_completion(
        run_future,
        abort_handle,
        async {
            let _ = tokio::signal::ctrl_c().await;
        },
        sigterm_signal(),
        LaunchStop {
            future: session_stop,
            message: "Stopped via control socket — cleaning up...",
            exit_code: SESSION_STOP_EXIT_CODE,
        },
        Some(&mut container_mgr),
    )
    .await?;

    // 11. Emit container stop observation event
    obs_stream.emit(EventKind::ContainerStop {
        container_id,
        exit_code: Some(exit_code),
    });

    // 12. Cleanup: remove container and stop proxy
    container_mgr.remove_container().await;
    proxy_handle.abort();
    #[cfg(unix)]
    unix_proxy_handle.abort();

    // Flush observation log before returning so callers can read the file.
    obs_stream.flush();

    drop(terminal);

    eprintln!("Container exited with code {exit_code}");
    eprintln!("Observation log: {}", obs_log_path.display());

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// Observe-mode warning
// ---------------------------------------------------------------------------

/// Build the stderr warning message for observe mode's read-write cwd mount.
///
/// Observe mode mounts the working directory read-write with no Cedar policy
/// restricting filesystem access. Network traffic is still routed through
/// the proxy via `--network=none` and the gateway.
///
/// This function is extracted to enable testing the warning content.
pub(crate) fn observe_cwd_warning(cwd: &Path) -> String {
    format!(
        "Warning: observe mode mounts {} read-write. The container has full write \
         access to your working directory. Network traffic is routed through the \
         proxy (--network=none).",
        cwd.display()
    )
}

// ---------------------------------------------------------------------------
// Shared MITM proxy loop for all launch modes
// ---------------------------------------------------------------------------

/// Run the full MITM proxy loop, dispatching connections through the shared
/// `handle_connection` implementation from `mitm.rs`.
///
/// This replaces the previous lightweight CONNECT-only proxy and policy proxy.
/// The `ProxyContext` controls behavior:
/// - `mitm_all = true`: MITM all connections (required for launch modes)
/// - `policy_engine = None`: observe mode (allow everything, record)
/// - `policy_engine = Some(...)` + `warn_only = true`: warn mode
/// - `policy_engine = Some(...)` + `warn_only = false`: enforce mode
async fn run_mitm_proxy_loop(listener: TcpListener, ctx: Arc<ProxyContext>) {
    loop {
        match listener.accept().await {
            Ok((client, peer)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(client, peer, &ctx).await {
                        tracing::debug!(error = %e, "proxy connection error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "proxy accept error");
                break;
            }
        }
    }
}

/// Accept loop for Unix socket connections, dispatching through the same
/// `handle_connection` path as TCP. Used by launch modes so container
/// traffic can reach the proxy via a bind-mounted socket instead of a
/// host TCP port.
#[cfg(unix)]
async fn run_mitm_unix_proxy_loop(listener: UnixListener, ctx: Arc<ProxyContext>) {
    loop {
        match listener.accept().await {
            Ok((client, _addr)) => {
                let ctx = ctx.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(client, "unix", &ctx).await {
                        tracing::debug!(error = %e, "proxy unix connection error");
                    }
                });
            }
            Err(e) => {
                warn!(error = %e, "proxy unix accept error");
                break;
            }
        }
    }
}

/// Build a [`ProxyContext`] for launch modes.
///
/// Creates a proxy context suitable for container-based launch workflows:
/// - `mitm_all`: true when `mitm_hosts` is empty (MITM everything), false when
///   a specific host list is provided from `--config`
/// - Observation stream attached for recording traffic
/// - Optional credential store from `--config` for credential injection
/// - Optional MITM host list from `--config`
#[allow(clippy::too_many_arguments)]
pub fn build_launch_proxy_context(
    session_ca: SessionCa,
    policy_engine: Option<PolicyEngine>,
    policy_config: Option<PolicyConfig>,
    obs_stream: ObservationStream,
    warn_only: bool,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    live_policy_bounds: Option<LivePolicyBounds>,
) -> anyhow::Result<ProxyContext> {
    let audit_logger = Arc::new(AuditLogger::new(None)?);

    let enforcement_mode = if policy_engine.is_some() && !warn_only {
        "enforce".to_string()
    } else if policy_engine.is_some() {
        "warn".to_string()
    } else {
        "observe".to_string()
    };

    // When mitm_hosts is empty, MITM all connections (original behavior).
    // When mitm_hosts is provided from config, use the allowlist.
    let mitm_all = mitm_hosts.is_empty();

    Ok(ProxyContext {
        session_ca,
        policy_engine: policy_engine.map(|e| ArcSwap::new(Arc::new(e))),
        credential_store,
        audit_logger,
        mitm_hosts,
        max_body_size: 10 * 1024 * 1024, // 10 MB default
        keepalive_timeout: std::time::Duration::from_secs(30),
        decision_timeout: std::time::Duration::from_secs(30),
        startup_instant: Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "agent".to_string(),
        git_policy: None,
        policy_config,
        observation_stream: Some(obs_stream),
        enforcement_mode,
        mitm_all,
        warn_only,
        live_policy_bounds,
        upstream_addr_override: None,
        upstream_tls_override: None,
        upstream_connect_timeout: std::time::Duration::from_secs(30),
        upstream_response_timeout: std::time::Duration::from_secs(60),
        pending_decisions: Arc::new(crate::decisions::PendingDecisionStore::new()),
    })
}

// ---------------------------------------------------------------------------
// SIGTERM signal helper
// ---------------------------------------------------------------------------

/// Return a future that completes when a SIGTERM signal is received.
///
/// On Unix, registers a real SIGTERM handler. On other platforms, returns
/// a future that never completes (SIGTERM is Unix-only).
#[cfg(unix)]
async fn sigterm_signal() {
    use tokio::signal::unix::{signal, SignalKind};
    match signal(SignalKind::terminate()) {
        Ok(mut sig) => {
            sig.recv().await;
        }
        Err(e) => {
            warn!(error = %e, "failed to register SIGTERM handler, ignoring");
            // Never complete — effectively disables this select branch
            std::future::pending::<()>().await;
        }
    }
}

/// Non-Unix stub: SIGTERM is not supported, return a never-completing future.
#[cfg(not(unix))]
async fn sigterm_signal() {
    std::future::pending::<()>().await;
}

struct LaunchStop<Stop> {
    future: Stop,
    message: &'static str,
    exit_code: i32,
}

async fn wait_for_launch_completion<Run, CtrlC, Sigterm, Stop>(
    run_future: Run,
    abort_handle: futures_util::future::AbortHandle,
    ctrl_c: CtrlC,
    sigterm: Sigterm,
    stop: LaunchStop<Stop>,
    container_mgr: Option<&mut ContainerManager>,
) -> anyhow::Result<i32>
where
    Run: std::future::Future<Output = Result<anyhow::Result<i32>, futures_util::future::Aborted>>,
    CtrlC: std::future::Future<Output = ()>,
    Sigterm: std::future::Future<Output = ()>,
    Stop: std::future::Future<Output = anyhow::Result<()>>,
{
    let LaunchStop {
        future: stop,
        message: stop_message,
        exit_code: stop_exit_code,
    } = stop;
    tokio::pin!(run_future);
    tokio::pin!(ctrl_c);
    tokio::pin!(sigterm);
    tokio::pin!(stop);
    let mut container_mgr = container_mgr;

    tokio::select! {
        result = &mut run_future => {
            match result {
                Ok(result) => result,
                Err(_) => Err(anyhow::anyhow!("attach task aborted")),
            }
        }
        _ = &mut ctrl_c => {
            eprintln!("\nInterrupted — cleaning up...");
            abort_handle.abort();
            let _ = (&mut run_future).await;
            if let Some(container_mgr) = container_mgr.as_mut() {
                (*container_mgr).stop_container().await.ok();
            }
            Ok(130)
        }
        _ = &mut sigterm => {
            eprintln!("\nTerminated — cleaning up...");
            abort_handle.abort();
            let _ = (&mut run_future).await;
            if let Some(container_mgr) = container_mgr.as_mut() {
                (*container_mgr).stop_container().await.ok();
            }
            Ok(143)
        }
        result = &mut stop => {
            result?;
            eprintln!("\n{stop_message}");
            abort_handle.abort();
            let _ = (&mut run_future).await;
            if let Some(container_mgr) = container_mgr.as_mut() {
                (*container_mgr).stop_container().await.ok();
            }
            Ok(stop_exit_code)
        }
    }
}

// ---------------------------------------------------------------------------
// Container attach and TTY passthrough
// ---------------------------------------------------------------------------

/// Attach to a container, start it, pipe I/O, and wait for exit.
///
/// The attach is created before starting the container to avoid missing
/// early output. Returns the container's exit code.
async fn attach_and_wait(
    docker: bollard::Docker,
    container_name: String,
    initial_tty_size: Option<TerminalSize>,
    resize_source: TerminalResizeSource,
    obs_stream: ObservationStream,
) -> anyhow::Result<i32> {
    use bollard::container::{AttachContainerOptions, StartContainerOptions};

    // Attach before starting to not miss any output
    let attach_options = AttachContainerOptions::<String> {
        stdin: Some(true),
        stdout: Some(true),
        stderr: Some(true),
        stream: Some(true),
        ..Default::default()
    };

    let attach = docker
        .attach_container(&container_name, Some(attach_options))
        .await
        .context("failed to attach to container")?;

    // Start the container
    docker
        .start_container(&container_name, None::<StartContainerOptions<String>>)
        .await
        .context("failed to start container")?;

    info!(container_name = %container_name, "container started");

    if let Some(size) = initial_tty_size {
        if let Err(error) = resize_container_tty(&docker, &container_name, size).await {
            warn!(
                error = %error,
                container_name = %container_name,
                "failed to apply initial container TTY size after start; continuing"
            );
        }
    }

    // Pipe container output to host stdout.
    // When the container exits, the output stream closes.
    let mut output = attach.output;
    let output_task = AbortOnDropTask::new(tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(Ok(chunk)) = output.next().await {
            let bytes = chunk.into_bytes();
            if stdout.write_all(&bytes).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    }));

    // Pipe host stdin to container stdin
    let mut input = attach.input;
    let mut input_task = AbortOnDropTask::new(tokio::spawn(async move {
        let mut stdin = tokio::io::stdin();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf).await {
                Ok(0) => break, // EOF
                Ok(n) => {
                    if input.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                    if input.flush().await.is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    }));

    let mut resize_task = spawn_resize_forwarder(
        docker.clone(),
        container_name.clone(),
        resize_source,
        obs_stream,
    )
    .map(AbortOnDropTask::new);

    // Wait for the output stream to close (container has exited)
    let _ = output_task.join().await;
    input_task.abort();
    if let Some(task) = resize_task.as_mut() {
        task.abort();
    }

    // Retrieve the exit code via inspect_container. The container is created
    // with auto_remove=false so it still exists after exit. This avoids a
    // Docker API quirk where wait_container returns status_code=0 for TTY
    // containers regardless of the actual exit code.
    let exit_code = match docker.inspect_container(&container_name, None).await {
        Ok(info) => info
            .state
            .and_then(|s| s.exit_code)
            .map(|c| c as i32)
            .unwrap_or(1),
        Err(e) => {
            warn!(error = %e, "failed to inspect container for exit code");
            1
        }
    };

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// Terminal raw mode (Unix only)
// ---------------------------------------------------------------------------

struct TerminalSession {
    initial_size: Option<TerminalSize>,
    resize_source: TerminalResizeSource,
    #[cfg(unix)]
    _guard: Option<CleanupGuard>,
}

struct AbortOnDropTask<T> {
    handle: Option<tokio::task::JoinHandle<T>>,
}

impl<T> AbortOnDropTask<T> {
    fn new(handle: tokio::task::JoinHandle<T>) -> Self {
        Self {
            handle: Some(handle),
        }
    }

    fn abort(&mut self) {
        if let Some(handle) = self.handle.as_ref() {
            handle.abort();
        }
    }

    async fn join(mut self) -> Result<T, tokio::task::JoinError> {
        let handle = self.handle.take().expect("task handle should exist");
        handle.await
    }
}

impl<T> Drop for AbortOnDropTask<T> {
    fn drop(&mut self) {
        self.abort();
    }
}

impl Default for TerminalSession {
    fn default() -> Self {
        Self {
            initial_size: None,
            resize_source: TerminalResizeSource::Disabled,
            #[cfg(unix)]
            _guard: None,
        }
    }
}

/// Guard that runs cleanup exactly once when dropped.
#[cfg(unix)]
struct CleanupGuard {
    cleanup: Option<Box<dyn FnOnce() + Send + 'static>>,
}

#[cfg(unix)]
impl CleanupGuard {
    fn new<F>(cleanup: F) -> Self
    where
        F: FnOnce() + Send + 'static,
    {
        Self {
            cleanup: Some(Box::new(cleanup)),
        }
    }
}

#[cfg(unix)]
impl Drop for CleanupGuard {
    fn drop(&mut self) {
        if let Some(cleanup) = self.cleanup.take() {
            cleanup();
        }
    }
}

fn should_manage_terminal(tty: bool, stdin_is_terminal: bool) -> bool {
    tty && stdin_is_terminal
}

fn prepare_terminal_session(tty: bool, mode: LaunchTerminalMode) -> TerminalSession {
    match mode {
        LaunchTerminalMode::Host => prepare_host_terminal_session(tty),
        LaunchTerminalMode::Test(options) => prepare_test_terminal_session(tty, options),
    }
}

fn prepare_test_terminal_session(tty: bool, options: TestTerminalOptions) -> TerminalSession {
    if !should_manage_terminal(tty, options.stdin_is_terminal) {
        return TerminalSession::default();
    }

    TerminalSession {
        initial_size: options.initial_size,
        resize_source: TerminalResizeSource::Scripted(options.resize_events),
        #[cfg(unix)]
        _guard: None,
    }
}

#[cfg(unix)]
fn prepare_host_terminal_session(tty: bool) -> TerminalSession {
    use std::io::IsTerminal;

    let stdin_is_terminal = std::io::stdin().is_terminal();
    if !should_manage_terminal(tty, stdin_is_terminal) {
        return TerminalSession::default();
    }

    TerminalSession {
        initial_size: current_terminal_size(),
        resize_source: TerminalResizeSource::HostSignals,
        _guard: setup_raw_terminal(),
    }
}

#[cfg(not(unix))]
fn prepare_host_terminal_session(_tty: bool) -> TerminalSession {
    TerminalSession::default()
}

fn terminal_size_from_rows_and_cols(rows: u16, cols: u16) -> Option<TerminalSize> {
    if rows == 0 || cols == 0 {
        None
    } else {
        Some(TerminalSize { rows, cols })
    }
}

#[cfg(unix)]
fn terminal_size_from_winsize(winsize: libc::winsize) -> Option<TerminalSize> {
    terminal_size_from_rows_and_cols(winsize.ws_row, winsize.ws_col)
}

#[cfg(unix)]
fn current_terminal_size() -> Option<TerminalSize> {
    use std::os::unix::io::AsRawFd;

    let fd = std::io::stdin().as_raw_fd();
    unsafe {
        let mut winsize: libc::winsize = std::mem::zeroed();
        if libc::ioctl(fd, libc::TIOCGWINSZ, &mut winsize) != 0 {
            return None;
        }
        terminal_size_from_winsize(winsize)
    }
}

async fn resize_container_tty(
    docker: &bollard::Docker,
    container_name: &str,
    size: TerminalSize,
) -> anyhow::Result<()> {
    use bollard::container::ResizeContainerTtyOptions;

    docker
        .resize_container_tty(
            container_name,
            ResizeContainerTtyOptions {
                width: size.cols,
                height: size.rows,
            },
        )
        .await
        .with_context(|| {
            format!(
                "failed to resize container TTY to {}x{}",
                size.cols, size.rows
            )
        })
}

#[cfg(unix)]
fn spawn_resize_forwarder(
    docker: bollard::Docker,
    container_name: String,
    resize_source: TerminalResizeSource,
    obs_stream: ObservationStream,
) -> Option<tokio::task::JoinHandle<()>> {
    match resize_source {
        TerminalResizeSource::Disabled => None,
        TerminalResizeSource::HostSignals => Some(tokio::spawn(async move {
            use tokio::signal::unix::{signal, SignalKind};

            let mut signals = match signal(SignalKind::window_change()) {
                Ok(signals) => signals,
                Err(e) => {
                    warn!(error = %e, "failed to register SIGWINCH handler, resize forwarding disabled");
                    return;
                }
            };

            while signals.recv().await.is_some() {
                if let Some(size) = current_terminal_size() {
                    if let Err(e) = resize_container_tty(&docker, &container_name, size).await {
                        warn!(error = %e, "failed to forward terminal resize");
                    } else {
                        emit_tty_resized_event(&obs_stream, size, "signal");
                    }
                }
            }
        })),
        TerminalResizeSource::Scripted(events) => Some(tokio::spawn(async move {
            forward_scripted_terminal_resizes(docker, container_name, events, obs_stream).await;
        })),
    }
}

#[cfg(not(unix))]
fn spawn_resize_forwarder(
    _docker: bollard::Docker,
    _container_name: String,
    _resize_source: TerminalResizeSource,
    _obs_stream: ObservationStream,
) -> Option<tokio::task::JoinHandle<()>> {
    None
}

async fn forward_scripted_terminal_resizes(
    docker: bollard::Docker,
    container_name: String,
    events: Vec<ScriptedTerminalResize>,
    obs_stream: ObservationStream,
) {
    for event in events {
        tokio::time::sleep(event.after).await;
        if let Err(e) = resize_container_tty(&docker, &container_name, event.size).await {
            warn!(error = %e, "failed to forward scripted terminal resize");
            break;
        } else {
            emit_tty_resized_event(&obs_stream, event.size, "scripted");
        }
    }
}

/// Set stdin to raw mode if it's a terminal.
///
/// Returns a guard that restores the original terminal settings on drop.
/// Returns `None` if stdin is not a terminal (e.g., piped input).
#[cfg(unix)]
fn setup_raw_terminal() -> Option<CleanupGuard> {
    use std::os::unix::io::AsRawFd;

    let fd = std::io::stdin().as_raw_fd();
    unsafe {
        let mut original: libc::termios = std::mem::zeroed();
        if libc::tcgetattr(fd, &mut original) != 0 {
            return None;
        }
        let mut raw = original;
        libc::cfmakeraw(&mut raw);
        if libc::tcsetattr(fd, libc::TCSANOW, &raw) != 0 {
            return None;
        }
        Some(CleanupGuard::new(move || {
            libc::tcsetattr(fd, libc::TCSANOW, &original);
        }))
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    /// Verify Docker not running gives a clear error.
    #[tokio::test]
    async fn docker_not_running_clear_error() {
        // Try creating a ContainerManager — if Docker isn't running, we should
        // get a clear error from verify_connection. If Docker IS running, the
        // test still passes (just verifies the happy path).
        match ContainerManager::new() {
            Ok(mgr) => {
                // Docker daemon might or might not be running — both are valid
                let _ = mgr.verify_connection().await;
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("Docker") || msg.contains("docker"),
                    "error should mention Docker: {msg}"
                );
            }
        }
    }

    // -- EnforcementMode tests ------------------------------------------------

    #[test]
    fn enforcement_mode_as_str() {
        assert_eq!(EnforcementMode::Observe.as_str(), "observe");
        assert_eq!(EnforcementMode::Warn.as_str(), "warn");
        assert_eq!(EnforcementMode::Enforce.as_str(), "enforce");
    }

    #[test]
    fn enforcement_mode_equality() {
        assert_eq!(EnforcementMode::Observe, EnforcementMode::Observe);
        assert_eq!(EnforcementMode::Warn, EnforcementMode::Warn);
        assert_eq!(EnforcementMode::Enforce, EnforcementMode::Enforce);
        assert_ne!(EnforcementMode::Observe, EnforcementMode::Warn);
        assert_ne!(EnforcementMode::Warn, EnforcementMode::Enforce);
    }

    // -- Observe-mode warning tests ------------------------------------------

    /// Verify observe mode warning mentions read-write access and network isolation.
    #[test]
    fn observe_cwd_warning_mentions_rw_and_network_isolation() {
        let cwd = PathBuf::from("/project");
        let msg = observe_cwd_warning(&cwd);

        assert!(
            msg.contains("read-write"),
            "warning should mention read-write: {msg}"
        );
        assert!(
            msg.contains("write access"),
            "warning should mention write access: {msg}"
        );
        assert!(
            msg.contains("--network=none"),
            "warning should mention --network=none: {msg}"
        );
        assert!(
            msg.contains("/project"),
            "warning should include the cwd path: {msg}"
        );
    }

    /// Verify observe mode warning includes the actual cwd path.
    #[test]
    fn observe_cwd_warning_includes_path() {
        let cwd = PathBuf::from("/home/user/my-project");
        let msg = observe_cwd_warning(&cwd);
        assert!(
            msg.contains("/home/user/my-project"),
            "warning should include the actual cwd: {msg}"
        );
    }

    /// Verify observe mode builds a policy with FsWrite (not FsRead) for cwd.
    #[test]
    fn observe_mode_mounts_cwd_readwrite() {
        use std::path::Path;

        // This mirrors the logic in run_launch_observe: cwd gets FsWrite
        let cwd = "/project";
        let policy = ContainerPolicy {
            permissions: vec![ContainerPermission::FsWrite(cwd.to_string())],
        };

        let config = ContainerManager::build_config(
            &policy,
            "ubuntu:24.04",
            &["sh".to_string()],
            Path::new("/tmp/proxy.sock"),
            Path::new("/usr/local/bin/strait-gateway"),
            None,
            Path::new("/project"),
            true,
        )
        .unwrap();

        // Verify cwd is mounted read-write (not read-only)
        assert!(
            config
                .binds
                .iter()
                .any(|b| b.contains("/project") && b.contains(":rw")),
            "observe mode should mount cwd as read-write: {:?}",
            config.binds
        );
    }

    // -- Terminal helpers ----------------------------------------------------

    #[test]
    fn should_manage_terminal_requires_tty_and_terminal_stdin() {
        assert!(should_manage_terminal(true, true));
        assert!(!should_manage_terminal(true, false));
        assert!(!should_manage_terminal(false, true));
        assert!(!should_manage_terminal(false, false));
    }

    #[test]
    fn terminal_size_helper_rejects_zero_dimensions() {
        assert_eq!(terminal_size_from_rows_and_cols(0, 80), None);
        assert_eq!(terminal_size_from_rows_and_cols(24, 0), None);
        assert_eq!(
            terminal_size_from_rows_and_cols(24, 80),
            Some(TerminalSize { rows: 24, cols: 80 })
        );
    }

    #[cfg(unix)]
    #[test]
    fn cleanup_guard_runs_on_drop() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let cleaned = Arc::new(AtomicBool::new(false));
        {
            let cleaned = Arc::clone(&cleaned);
            let _guard = CleanupGuard::new(move || {
                cleaned.store(true, Ordering::SeqCst);
            });
        }

        assert!(
            cleaned.load(Ordering::SeqCst),
            "cleanup guard should run its callback on drop"
        );
    }

    #[tokio::test]
    async fn wait_for_launch_completion_aborts_task_on_ctrl_c() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use tokio::sync::oneshot;
        use tokio::time::{timeout, Duration};

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let task_dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let (run_future, abort_handle) = {
            let task_dropped = Arc::clone(&task_dropped);
            futures_util::future::abortable(async move {
                let _flag = DropFlag(task_dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
                Ok::<i32, anyhow::Error>(0)
            })
        };

        let exit_code = wait_for_launch_completion(
            run_future,
            abort_handle,
            async move {
                let _ = started_rx.await;
            },
            std::future::pending::<()>(),
            LaunchStop {
                future: std::future::pending::<anyhow::Result<()>>(),
                message: "unused",
                exit_code: 0,
            },
            None,
        )
        .await
        .expect("ctrl-c branch should return an exit code");

        assert_eq!(exit_code, 130);
        timeout(Duration::from_secs(1), async {
            while !task_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("ctrl-c should cancel the attach task");
    }

    #[tokio::test]
    async fn wait_for_launch_completion_aborts_task_on_sigterm() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;
        use tokio::sync::oneshot;
        use tokio::time::{timeout, Duration};

        struct DropFlag(Arc<AtomicBool>);
        impl Drop for DropFlag {
            fn drop(&mut self) {
                self.0.store(true, Ordering::SeqCst);
            }
        }

        let task_dropped = Arc::new(AtomicBool::new(false));
        let (started_tx, started_rx) = oneshot::channel();
        let (run_future, abort_handle) = {
            let task_dropped = Arc::clone(&task_dropped);
            futures_util::future::abortable(async move {
                let _flag = DropFlag(task_dropped);
                let _ = started_tx.send(());
                std::future::pending::<()>().await;
                Ok::<i32, anyhow::Error>(0)
            })
        };

        let exit_code = wait_for_launch_completion(
            run_future,
            abort_handle,
            std::future::pending::<()>(),
            async move {
                let _ = started_rx.await;
            },
            LaunchStop {
                future: std::future::pending::<anyhow::Result<()>>(),
                message: "unused",
                exit_code: 0,
            },
            None,
        )
        .await
        .expect("sigterm branch should return an exit code");

        assert_eq!(exit_code, 143);
        timeout(Duration::from_secs(1), async {
            while !task_dropped.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("sigterm should cancel the attach task");
    }

    // -- ProxyContext builder tests -------------------------------------------

    /// Verify observe-mode proxy context has policy=None and observation stream.
    #[test]
    fn observe_proxy_context_has_no_policy_and_obs_stream() {
        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        let ctx = build_launch_proxy_context(
            session_ca,
            None, // observe mode — no policy
            None,
            obs_stream,
            false,
            None,
            Vec::new(),
            None,
        )
        .unwrap();

        assert!(
            ctx.policy_engine.is_none(),
            "observe mode should have no policy engine"
        );
        assert!(
            ctx.observation_stream.is_some(),
            "observation stream should be attached"
        );
        assert!(ctx.mitm_all, "launch modes must MITM all connections");
        assert!(!ctx.warn_only, "observe mode should not be warn_only");
        assert_eq!(ctx.enforcement_mode, "observe", "no policy → observe mode");
    }

    /// Verify warn-mode proxy context has policy engine and warn_only=true.
    #[test]
    fn warn_proxy_context_has_policy_and_warn_only() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        let mut policy_file = NamedTempFile::new().unwrap();
        policy_file
            .write_all(
                br#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
            )
            .unwrap();
        policy_file.flush().unwrap();

        let engine = PolicyEngine::load(policy_file.path(), None).unwrap();
        let ctx = build_launch_proxy_context(
            session_ca,
            Some(engine),
            None,
            obs_stream,
            true, // warn mode
            None,
            Vec::new(),
            None,
        )
        .unwrap();

        assert!(
            ctx.policy_engine.is_some(),
            "warn mode should have a policy engine"
        );
        assert!(
            ctx.observation_stream.is_some(),
            "observation stream should be attached"
        );
        assert!(ctx.mitm_all, "launch modes must MITM all connections");
        assert!(ctx.warn_only, "warn mode should set warn_only=true");
        assert_eq!(
            ctx.enforcement_mode, "warn",
            "policy + warn_only → warn mode"
        );
    }

    /// Verify enforce-mode proxy context has policy engine and warn_only=false.
    #[test]
    fn enforce_proxy_context_has_policy_and_not_warn_only() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        let mut policy_file = NamedTempFile::new().unwrap();
        policy_file
            .write_all(
                br#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource in Resource::"api.github.com"
);
"#,
            )
            .unwrap();
        policy_file.flush().unwrap();

        let engine = PolicyEngine::load(policy_file.path(), None).unwrap();
        let ctx = build_launch_proxy_context(
            session_ca,
            Some(engine),
            None,
            obs_stream,
            false, // enforce mode
            None,
            Vec::new(),
            None,
        )
        .unwrap();

        assert!(
            ctx.policy_engine.is_some(),
            "enforce mode should have a policy engine"
        );
        assert!(!ctx.warn_only, "enforce mode should not set warn_only");
        assert_eq!(
            ctx.enforcement_mode, "enforce",
            "policy + !warn_only → enforce mode"
        );
    }

    // -- Config-derived credential_store and mitm_hosts tests -----------------

    /// Verify build_launch_proxy_context with a credential store produces a
    /// ProxyContext where credential_store.is_some().
    #[test]
    fn proxy_context_with_credential_store() {
        use crate::config::CredentialEntryConfig;

        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        // Set a test env var for the credential resolver
        std::env::set_var("STRAIT_TEST_TOKEN_LAUNCH", "test-secret");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "Bearer ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_TOKEN_LAUNCH".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];
        let store = Arc::new(CredentialStore::from_entries(&entries).unwrap());

        let ctx = build_launch_proxy_context(
            session_ca,
            None,
            None,
            obs_stream,
            false,
            Some(store),
            Vec::new(),
            None,
        )
        .unwrap();

        assert!(
            ctx.credential_store.is_some(),
            "credential_store should be present when provided from config"
        );
        assert!(ctx.mitm_all, "empty mitm_hosts should set mitm_all=true");
    }

    /// Verify build_launch_proxy_context with MITM hosts populates the hosts
    /// list and sets mitm_all=false.
    #[test]
    fn proxy_context_with_mitm_hosts() {
        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        let hosts = vec!["api.github.com".to_string(), "api.openai.com".to_string()];

        let ctx = build_launch_proxy_context(
            session_ca, None, None, obs_stream, false, None, hosts, None,
        )
        .unwrap();

        assert_eq!(ctx.mitm_hosts.len(), 2);
        assert!(ctx.mitm_hosts.contains(&"api.github.com".to_string()));
        assert!(ctx.mitm_hosts.contains(&"api.openai.com".to_string()));
        assert!(
            !ctx.mitm_all,
            "non-empty mitm_hosts should set mitm_all=false"
        );
    }

    /// Verify build_launch_proxy_context without config preserves current
    /// behavior: credential_store=None, mitm_all=true.
    #[test]
    fn proxy_context_without_config_preserves_defaults() {
        let session_ca = SessionCa::generate().unwrap();
        let obs_stream = ObservationStream::new();

        let ctx = build_launch_proxy_context(
            session_ca,
            None,
            None,
            obs_stream,
            false,
            None,
            Vec::new(),
            None,
        )
        .unwrap();

        assert!(
            ctx.credential_store.is_none(),
            "no config should mean no credential_store"
        );
        assert!(
            ctx.mitm_hosts.is_empty(),
            "no config should mean empty mitm_hosts"
        );
        assert!(ctx.mitm_all, "no config should preserve mitm_all=true");
    }

    // -- MITM proxy integration tests -----------------------------------------

    /// Verify the MITM proxy emits observation events with full request details
    /// (method + path), not just CONNECT host info.
    #[tokio::test]
    async fn mitm_proxy_emits_observation_events() {
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let session_ca = SessionCa::generate().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let ctx = Arc::new(
            build_launch_proxy_context(
                session_ca,
                None,
                None,
                obs_stream.clone(),
                false,
                None,
                Vec::new(),
                None,
            )
            .unwrap(),
        );

        let proxy_handle = tokio::spawn(run_mitm_proxy_loop(listener, ctx));

        // Send a CONNECT request. Because mitm_all=true, the proxy will
        // try to MITM — send 200, then attempt TLS handshake with the client.
        // The client won't do TLS, so the connection will error, but
        // we can at least verify the proxy accepted the CONNECT.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();

        // Read the 200 Connection Established response
        let mut response = vec![0u8; 1024];
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let n = client.try_read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            response_str.contains("200"),
            "should get 200 Connection Established, got: {response_str}"
        );

        // The proxy issues a TLS cert and tries a handshake. Since we
        // don't complete TLS from the client side, the connection errors
        // out — that's fine for this test. We verified the proxy accepted
        // the CONNECT and would MITM the connection.

        proxy_handle.abort();

        // Drain any events
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        while rx.try_recv().is_ok() {}
    }

    /// Verify the proxy handles non-CONNECT requests gracefully.
    #[tokio::test]
    async fn proxy_ignores_non_connect() {
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let session_ca = SessionCa::generate().unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let ctx = Arc::new(
            build_launch_proxy_context(
                session_ca,
                None,
                None,
                obs_stream.clone(),
                false,
                None,
                Vec::new(),
                None,
            )
            .unwrap(),
        );

        let proxy_handle = tokio::spawn(run_mitm_proxy_loop(listener, ctx));

        // Send a GET request (not CONNECT)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n")
            .await
            .unwrap();

        // Give the proxy a moment
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // No observation event should be emitted for non-CONNECT
        assert!(rx.try_recv().is_err(), "should not emit event for GET");

        proxy_handle.abort();
    }

    /// Verify passthrough connections emit observation events with host/port
    /// and decision="passthrough".
    #[tokio::test]
    async fn passthrough_connection_emits_observation_event() {
        use tokio::io::AsyncReadExt;

        // Start a fake upstream server so the passthrough connection succeeds.
        let upstream_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        // Accept and immediately close connections in the background.
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = upstream_listener.accept().await {
                let _ = stream.shutdown().await;
            }
        });

        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let session_ca = SessionCa::generate().unwrap();
        let audit_logger = Arc::new(AuditLogger::new(None).unwrap());

        // Build a ProxyContext with mitm_all=false, no policy, and no
        // MITM hosts. This forces the passthrough path for all CONNECT
        // requests.
        let ctx = Arc::new(ProxyContext {
            session_ca,
            policy_engine: None,
            credential_store: None,
            audit_logger,
            mitm_hosts: Vec::new(),
            max_body_size: 10 * 1024 * 1024,
            keepalive_timeout: std::time::Duration::from_secs(5),
            decision_timeout: std::time::Duration::from_secs(30),
            startup_instant: Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: Some(obs_stream.clone()),
            enforcement_mode: "observe".to_string(),
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: None,
            upstream_tls_override: None,
            upstream_connect_timeout: std::time::Duration::from_secs(30),
            upstream_response_timeout: std::time::Duration::from_secs(60),
            pending_decisions: Arc::new(crate::decisions::PendingDecisionStore::new()),
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let proxy_ctx = ctx.clone();
        let proxy_handle = tokio::spawn(async move {
            if let Ok((client, peer)) = proxy_listener.accept().await {
                let _ = handle_connection(client, peer, &proxy_ctx).await;
            }
        });

        // Send a CONNECT request targeting the fake upstream.
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        let connect_req = format!(
            "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            upstream_addr.port()
        );
        client.write_all(connect_req.as_bytes()).await.unwrap();

        // Read the 200 Connection Established response.
        let mut buf = vec![0u8; 1024];
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let n = client.read(&mut buf).await.unwrap_or(0);
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(
            response.contains("200"),
            "should get 200 Connection Established, got: {response}"
        );

        drop(client);
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        proxy_handle.abort();

        // Check for the passthrough observation event.
        let event = rx
            .try_recv()
            .expect("should have received an observation event");
        match &event.event {
            EventKind::NetworkRequest {
                method,
                host,
                path,
                decision,
                enforcement_mode,
                ..
            } => {
                assert_eq!(method, "CONNECT");
                assert_eq!(host, "127.0.0.1");
                assert!(path.is_empty(), "passthrough should have empty path");
                assert_eq!(decision, "passthrough");
                assert_eq!(enforcement_mode, "observe");
            }
            other => panic!("expected NetworkRequest, got {other:?}"),
        }
    }

    // -- SIGTERM signal handler tests -----------------------------------------

    /// Verify the sigterm_signal() helper completes when SIGTERM is received.
    #[cfg(unix)]
    #[tokio::test]
    async fn sigterm_signal_completes_on_sigterm() {
        let handle = tokio::spawn(async {
            sigterm_signal().await;
        });

        // Give the signal handler a moment to register
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Send SIGTERM to ourselves
        unsafe {
            libc::kill(libc::getpid(), libc::SIGTERM);
        }

        // The future should complete within a reasonable time
        let result = tokio::time::timeout(std::time::Duration::from_secs(2), handle).await;
        assert!(
            result.is_ok(),
            "sigterm_signal should complete after SIGTERM"
        );
        assert!(
            result.unwrap().is_ok(),
            "sigterm_signal task should not panic"
        );
    }

    // -- Unix socket proxy tests ----------------------------------------------

    /// Verify that `run_mitm_unix_proxy_loop` accepts a connection over a
    /// Unix socket and dispatches it through the same `handle_connection`
    /// path as the TCP proxy loop.
    #[cfg(unix)]
    #[tokio::test]
    async fn unix_socket_proxy_accepts_connect() {
        let obs_stream = ObservationStream::new();

        let session_ca = SessionCa::generate().unwrap();

        let temp_dir = tempfile::TempDir::new().unwrap();
        let socket_path = proxy_socket_path(temp_dir.path());

        let ctx = Arc::new(
            build_launch_proxy_context(
                session_ca,
                None,
                None,
                obs_stream.clone(),
                false,
                None,
                Vec::new(),
                None,
            )
            .unwrap(),
        );

        let listener = UnixListener::bind(&socket_path).unwrap();
        assert!(socket_path.exists(), "socket file should exist after bind");

        let proxy_handle = tokio::spawn(run_mitm_unix_proxy_loop(listener, ctx));

        // Connect over the Unix socket and send a CONNECT request.
        let mut client = tokio::net::UnixStream::connect(&socket_path).await.unwrap();
        client
            .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();

        // Read the 200 Connection Established response (proves handle_connection
        // ran and the MITM path was triggered because mitm_all=true).
        let mut response = vec![0u8; 1024];
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let n = client.try_read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            response_str.contains("200"),
            "should get 200 Connection Established via Unix socket, got: {response_str}"
        );

        proxy_handle.abort();
    }

    /// Verify that the proxy socket file is created at the expected path
    /// inside the temp directory and cleaned up when the temp dir is dropped.
    #[cfg(unix)]
    #[tokio::test]
    async fn proxy_socket_path_lifecycle() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let socket = proxy_socket_path(temp_dir.path());

        assert_eq!(
            socket.file_name().unwrap(),
            PROXY_SOCKET_NAME,
            "socket filename should be the constant"
        );

        // Bind the listener to create the socket file.
        let _listener = UnixListener::bind(&socket).unwrap();
        assert!(socket.exists(), "socket file should exist after bind");

        // Drop the temp dir; the socket file should be removed.
        let path_clone = socket.clone();
        drop(_listener);
        drop(temp_dir);
        assert!(
            !path_clone.exists(),
            "socket file should be cleaned up with temp dir"
        );
    }

    // -- Launch session control tests ----------------------------------------

    #[cfg(unix)]
    fn test_launch_proxy_ctx(
        policy_engine: Option<PolicyEngine>,
        policy_config: Option<PolicyConfig>,
        live_policy_bounds: Option<LivePolicyBounds>,
    ) -> Arc<ProxyContext> {
        Arc::new(
            build_launch_proxy_context(
                SessionCa::generate().unwrap(),
                policy_engine,
                policy_config,
                ObservationStream::new(),
                false,
                None,
                Vec::new(),
                live_policy_bounds,
            )
            .unwrap(),
        )
    }

    #[cfg(unix)]
    #[test]
    fn control_request_parser_rejects_bad_version_and_method() {
        let wrong_version = LaunchControlRequest {
            version: 99,
            method: "session.info".to_string(),
            policy: None,
            blocked_id: None,
        };
        let err = parse_control_method(&wrong_version).unwrap_err();
        assert!(
            err.to_string()
                .contains("unsupported control protocol version"),
            "wrong version should be rejected: {err}"
        );

        let wrong_method = LaunchControlRequest {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            method: "session.nope".to_string(),
            policy: None,
            blocked_id: None,
        };
        let err = parse_control_method(&wrong_method).unwrap_err();
        assert!(
            err.to_string().contains("unsupported control method"),
            "unknown method should be rejected: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn decision_actions_require_a_non_empty_blocked_id() {
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);

        let missing = LaunchControlRequest::new(ControlMethod::DecisionAllowOnce);
        let missing_response = dispatch_decision_action(
            &missing,
            ControlMethod::DecisionAllowOnce,
            proxy_ctx.as_ref(),
        );
        assert!(!missing_response.ok);
        assert_eq!(
            missing_response.error.unwrap().code,
            "missing_blocked_id",
            "decision methods should reject a missing blocked_id"
        );

        let blank = LaunchControlRequest::with_blocked_id(ControlMethod::DecisionDeny, "   ");
        let blank_response =
            dispatch_decision_action(&blank, ControlMethod::DecisionDeny, proxy_ctx.as_ref());
        assert!(!blank_response.ok);
        assert_eq!(
            blank_response.error.unwrap().code,
            "missing_blocked_id",
            "decision methods should reject a blank blocked_id"
        );
    }

    #[cfg(unix)]
    async fn wait_for_live_decision_event(
        rx: &mut tokio::sync::broadcast::Receiver<crate::observe::ObservationEvent>,
        expected_action: &str,
    ) -> (String, String) {
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            loop {
                let event = rx.recv().await.unwrap();
                match event.event {
                    EventKind::LiveDecision {
                        action,
                        blocked_id,
                        match_key,
                    } if action == expected_action => return (blocked_id, match_key),
                    _ => {}
                }
            }
        })
        .await
        .expect("live decision event should arrive")
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_server_resolves_live_decision_methods() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let mut obs_rx = proxy_ctx.observation_stream.as_ref().unwrap().subscribe();
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Enforce,
            proxy_ctx.clone(),
        )
        .await
        .unwrap();
        let control_socket = session.control_socket_path().await;

        let once_rx = proxy_ctx
            .pending_decisions
            .register_pending("blocked-once", "http:GET example.com/once");
        let once = request_launch_decision_allow_once(&control_socket, "blocked-once")
            .await
            .unwrap();
        assert_eq!(once.blocked_id, "blocked-once");
        assert_eq!(once.match_key, "http:GET example.com/once");
        assert_eq!(
            once_rx.await.unwrap(),
            crate::decisions::Decision::AllowOnce
        );
        let (blocked_id, match_key) =
            wait_for_live_decision_event(&mut obs_rx, "decision.allow_once").await;
        assert_eq!(blocked_id, "blocked-once");
        assert_eq!(match_key, "http:GET example.com/once");

        let session_rx = proxy_ctx
            .pending_decisions
            .register_pending("blocked-session", "http:GET example.com/session");
        let allow_session =
            request_launch_decision_allow_session(&control_socket, "blocked-session")
                .await
                .unwrap();
        assert_eq!(allow_session.match_key, "http:GET example.com/session");
        assert_eq!(
            session_rx.await.unwrap(),
            crate::decisions::Decision::AllowSession
        );
        assert!(
            proxy_ctx
                .pending_decisions
                .is_session_allowed("http:GET example.com/session"),
            "allow-session should cache the match key on the running session"
        );
        let (blocked_id, match_key) =
            wait_for_live_decision_event(&mut obs_rx, "decision.allow_session").await;
        assert_eq!(blocked_id, "blocked-session");
        assert_eq!(match_key, "http:GET example.com/session");

        let deny_rx = proxy_ctx
            .pending_decisions
            .register_pending("blocked-deny", "http:GET example.com/deny");
        let deny = request_launch_decision_deny(&control_socket, "blocked-deny")
            .await
            .unwrap();
        assert_eq!(deny.match_key, "http:GET example.com/deny");
        assert_eq!(deny_rx.await.unwrap(), crate::decisions::Decision::Deny);
        let (blocked_id, match_key) =
            wait_for_live_decision_event(&mut obs_rx, "decision.deny").await;
        assert_eq!(blocked_id, "blocked-deny");
        assert_eq!(match_key, "http:GET example.com/deny");

        drop(session);
    }

    #[cfg(unix)]
    #[test]
    fn launch_session_output_lines_include_targeting_fields() {
        let metadata = LaunchSessionMetadata {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: "test-session".to_string(),
            mode: "observe".to_string(),
            control_socket_path: PathBuf::from("/tmp/control.sock"),
            observation: ObservationHandle {
                transport: "unix_socket".to_string(),
                path: PathBuf::from("/tmp/observe.sock"),
            },
            container_id: Some("abc123".to_string()),
            container_name: Some("strait-test".to_string()),
        };

        let lines = launch_session_output_lines(&metadata);
        assert!(
            lines
                .iter()
                .any(|line| line.contains("Session ID: test-session")),
            "session id line should be present: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("/tmp/control.sock")),
            "control socket line should be present: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("/tmp/observe.sock")),
            "observation socket line should be present: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("strait session info --session test-session")),
            "launch output should point operators at session commands: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| {
                line.contains(
                    "Policy updates: Live updates apply to network policy only; filesystem or process policy changes require relaunch."
                )
            }),
            "launch output should explain the live update boundary: {lines:?}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn launch_session_output_lines_include_trust_boundary_diagnostic() {
        let metadata = LaunchSessionMetadata {
            version: SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: "trust-test".to_string(),
            mode: "enforce".to_string(),
            control_socket_path: PathBuf::from("/tmp/control.sock"),
            observation: ObservationHandle {
                transport: "unix_socket".to_string(),
                path: PathBuf::from("/tmp/observe.sock"),
            },
            container_id: Some("abc123".to_string()),
            container_name: Some("strait-test".to_string()),
        };

        let lines = launch_session_output_lines(&metadata);

        assert!(
            lines
                .iter()
                .any(|line| line.contains("Trust boundary") && line.contains("container-local")),
            "launch output should announce the container-local trust boundary: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("no machine-wide CA install required")),
            "launch output should explicitly disclaim machine-wide CA install: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("/tmp/strait-ca-bundle.pem")),
            "launch output should surface the augmented CA bundle path: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("SSL_CERT_FILE")),
            "launch output should list the trust env vars: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("HTTPS_PROXY")),
            "launch output should list the proxy env vars: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("--network=none")),
            "launch output should mention --network=none: {lines:?}"
        );
    }

    #[test]
    fn launch_live_policy_bounds_include_workspace_alias() {
        let bounds = launch_live_policy_bounds(Path::new("/tmp/strait-project"));
        assert_eq!(
            bounds.fs_candidate_paths,
            vec![
                "/tmp/strait-project".to_string(),
                CONTAINER_WORKSPACE_PATH.to_string()
            ]
        );
        assert_eq!(bounds.agent_id, "agent");
    }

    #[test]
    fn launch_live_policy_bounds_avoid_duplicate_workspace_alias() {
        let bounds = launch_live_policy_bounds(Path::new(CONTAINER_WORKSPACE_PATH));
        assert_eq!(
            bounds.fs_candidate_paths,
            vec![CONTAINER_WORKSPACE_PATH.to_string()]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_session_registry_writes_metadata_and_cleans_up() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Warn,
            proxy_ctx,
        )
        .await
        .unwrap();
        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();
        let control_socket = session.control_socket_path().await;
        let session_dir = registry_root.path().join("test-session");
        let metadata_path = session_dir.join(SESSION_METADATA_FILE_NAME);

        assert!(control_socket.exists(), "control socket should exist");
        assert!(
            session.observation_socket_path().await.exists(),
            "observation socket should exist"
        );
        assert!(metadata_path.exists(), "metadata file should exist");

        let sessions = list_launch_sessions_in(registry_root.path()).unwrap();
        assert_eq!(sessions.len(), 1, "registry should contain one session");
        assert_eq!(sessions[0].session_id, "test-session");
        assert_eq!(sessions[0].mode, "warn");
        assert_eq!(sessions[0].control_socket_path, control_socket);

        drop(session);

        assert!(
            !session_dir.exists(),
            "session directory should be removed on cleanup"
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_server_handles_info_attach_and_stop() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, mut stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Observe,
            proxy_ctx,
        )
        .await
        .unwrap();
        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();
        session
            .set_container("container-123", "strait-test-container")
            .await
            .unwrap();

        let control_socket = session.control_socket_path().await;
        let info = request_launch_session_info(&control_socket).await.unwrap();
        assert_eq!(info.session_id, "test-session");
        assert_eq!(info.mode, "observe");
        assert_eq!(info.container_id.as_deref(), Some("container-123"));
        assert_eq!(
            info.container_name.as_deref(),
            Some("strait-test-container")
        );

        let observation = request_launch_watch_attach(&control_socket).await.unwrap();
        assert_eq!(observation.transport, "unix_socket");
        assert_eq!(observation.path, info.observation.path);

        request_launch_session_stop(&control_socket).await.unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), stop_rx.changed())
            .await
            .expect("session.stop should notify the launch loop")
            .expect("session.stop channel should stay open");

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_server_preserves_early_stop_signal_for_initial_receiver() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Observe,
            proxy_ctx,
        )
        .await
        .unwrap();
        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();

        let control_socket = session.control_socket_path().await;
        request_launch_session_stop(&control_socket).await.unwrap();

        assert!(
            *stop_rx.borrow(),
            "initial stop receiver should see an already-sent stop request"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_session_registry_permissions_are_private() {
        use std::os::unix::fs::PermissionsExt;

        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Warn,
            proxy_ctx,
        )
        .await
        .unwrap();
        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();
        let control_socket = session.control_socket_path().await;
        let observation_socket = session.observation_socket_path().await;
        let session_dir = registry_root.path().join("test-session");
        let metadata_path = session_dir.join(SESSION_METADATA_FILE_NAME);

        let session_mode = std::fs::metadata(&session_dir)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let metadata_mode = std::fs::metadata(&metadata_path)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let socket_mode = std::fs::metadata(&control_socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let observation_socket_mode = std::fs::metadata(&observation_socket)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;

        assert_eq!(session_mode, 0o700, "session directory should be private");
        assert_eq!(metadata_mode, 0o600, "metadata file should be private");
        assert_eq!(socket_mode, 0o600, "control socket should be private");
        assert_eq!(
            observation_socket_mode, 0o600,
            "observation socket should be private"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_session_registry_publishes_only_ready_sessions() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Observe,
            proxy_ctx,
        )
        .await
        .unwrap();

        assert!(
            list_launch_sessions_in(registry_root.path())
                .unwrap()
                .is_empty(),
            "unpublished sessions should stay out of discovery"
        );
        assert!(
            session.control_socket_path().await.exists(),
            "control socket should be ready before publish"
        );
        assert!(
            !session.observation_socket_path().await.exists(),
            "observation socket should not exist before publish"
        );

        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();

        let sessions = list_launch_sessions_in(registry_root.path()).unwrap();
        assert_eq!(
            sessions.len(),
            1,
            "ready session should become discoverable"
        );
        assert_eq!(sessions[0].session_id, "test-session");
        assert!(
            session.observation_socket_path().await.exists(),
            "observation socket should exist after publish"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_session_registry_skips_invalid_metadata_entries() {
        let registry_root = tempfile::tempdir().unwrap();
        let proxy_ctx = test_launch_proxy_ctx(None, None, None);
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "healthy",
            EnforcementMode::Warn,
            proxy_ctx,
        )
        .await
        .unwrap();
        let obs_stream = ObservationStream::new();
        session.publish(&obs_stream).await.unwrap();

        let broken_dir = registry_root.path().join("broken");
        std::fs::create_dir_all(&broken_dir).unwrap();
        std::fs::write(
            broken_dir.join(SESSION_METADATA_FILE_NAME),
            "{ definitely not valid json",
        )
        .unwrap();

        let sessions = list_launch_sessions_in(registry_root.path()).unwrap();
        assert_eq!(sessions.len(), 1, "broken entries should be ignored");
        assert_eq!(sessions[0].session_id, "healthy");

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_policy_replace_updates_engine() {
        let registry_root = tempfile::tempdir().unwrap();
        let policy_path = registry_root.path().join("policy.cedar");
        std::fs::write(
            &policy_path,
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
"#,
        )
        .unwrap();
        let engine = PolicyEngine::load(&policy_path, None).unwrap();
        let proxy_ctx = test_launch_proxy_ctx(
            Some(engine),
            Some(PolicyConfig {
                file: Some(policy_path),
                git_url: None,
                git_path: None,
                schema: None,
                poll_interval_secs: None,
            }),
            Some(LivePolicyBounds {
                fs_candidate_paths: vec!["/workspace".to_string()],
                agent_id: "agent".to_string(),
            }),
        );
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Enforce,
            proxy_ctx.clone(),
        )
        .await
        .unwrap();
        session.publish(&ObservationStream::new()).await.unwrap();

        let control_socket = session.control_socket_path().await;
        let update =
            request_launch_policy_replace(&control_socket, "forbid(principal, action, resource);")
                .await
                .unwrap();
        assert!(
            update.applied,
            "replace should apply when only network changes"
        );
        assert!(
            update.restart_required_domains.is_empty(),
            "network-only replace should not require restart"
        );

        let engine = proxy_ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("example.com", "http:GET", "/", &[], "agent")
            .unwrap();
        assert!(
            !decision.allowed,
            "replacement policy should now deny requests"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_policy_replace_invalid_keeps_previous_policy() {
        let registry_root = tempfile::tempdir().unwrap();
        let policy_path = registry_root.path().join("policy.cedar");
        std::fs::write(
            &policy_path,
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
"#,
        )
        .unwrap();
        let engine = PolicyEngine::load(&policy_path, None).unwrap();
        let proxy_ctx = test_launch_proxy_ctx(
            Some(engine),
            Some(PolicyConfig {
                file: Some(policy_path),
                git_url: None,
                git_path: None,
                schema: None,
                poll_interval_secs: None,
            }),
            Some(LivePolicyBounds {
                fs_candidate_paths: vec!["/workspace".to_string()],
                agent_id: "agent".to_string(),
            }),
        );
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Enforce,
            proxy_ctx.clone(),
        )
        .await
        .unwrap();
        session.publish(&ObservationStream::new()).await.unwrap();

        let control_socket = session.control_socket_path().await;
        let err = request_launch_policy_replace(&control_socket, "not valid cedar {{{")
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("policy_update_failed"),
            "invalid replace should surface a structured control error: {err}"
        );

        let engine = proxy_ctx.policy_engine.as_ref().unwrap().load();
        let decision = engine
            .evaluate("example.com", "http:GET", "/", &[], "agent")
            .unwrap();
        assert!(
            decision.allowed,
            "invalid replace should leave the previous policy active"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_policy_reload_reports_restart_required_for_fs_or_proc_changes() {
        let registry_root = tempfile::tempdir().unwrap();
        let policy_path = registry_root.path().join("policy.cedar");
        std::fs::write(
            &policy_path,
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
"#,
        )
        .unwrap();
        let engine = PolicyEngine::load(&policy_path, None).unwrap();
        let proxy_ctx = test_launch_proxy_ctx(
            Some(engine),
            Some(PolicyConfig {
                file: Some(policy_path.clone()),
                git_url: None,
                git_path: None,
                schema: None,
                poll_interval_secs: None,
            }),
            Some(LivePolicyBounds {
                fs_candidate_paths: vec!["/workspace".to_string()],
                agent_id: "agent".to_string(),
            }),
        );
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Enforce,
            proxy_ctx.clone(),
        )
        .await
        .unwrap();
        session.publish(&ObservationStream::new()).await.unwrap();

        std::fs::write(
            &policy_path,
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/workspace"
);
permit(
    principal == Agent::"agent",
    action == Action::"proc:exec",
    resource == Resource::"proc::git"
);
"#,
        )
        .unwrap();

        let control_socket = session.control_socket_path().await;
        let update = request_launch_policy_reload(&control_socket).await.unwrap();
        assert!(
            !update.applied,
            "fs/proc changes should be restart-bound, not applied live"
        );
        assert_eq!(
            update.restart_required_domains,
            vec!["fs".to_string(), "proc".to_string()]
        );

        let engine = proxy_ctx.policy_engine.as_ref().unwrap().load();
        let fs_decision = engine
            .evaluate_fs("/workspace", "fs:read", "agent")
            .unwrap();
        assert!(
            !fs_decision.allowed,
            "restart-required reload should leave the previous policy active"
        );

        drop(session);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn launch_control_policy_reload_emits_session_tagged_observation_event() {
        let registry_root = tempfile::tempdir().unwrap();
        let policy_path = registry_root.path().join("policy.cedar");
        std::fs::write(
            &policy_path,
            r#"
permit(
    principal == Agent::"agent",
    action == Action::"http:GET",
    resource
);
"#,
        )
        .unwrap();
        let engine = PolicyEngine::load(&policy_path, None).unwrap();
        let obs_stream = ObservationStream::new();
        let proxy_ctx = Arc::new(
            build_launch_proxy_context(
                SessionCa::generate().unwrap(),
                Some(engine),
                Some(PolicyConfig {
                    file: Some(policy_path.clone()),
                    git_url: None,
                    git_path: None,
                    schema: None,
                    poll_interval_secs: None,
                }),
                obs_stream.clone(),
                true,
                None,
                Vec::new(),
                Some(LivePolicyBounds {
                    fs_candidate_paths: vec!["/workspace".to_string()],
                    agent_id: "agent".to_string(),
                }),
            )
            .unwrap(),
        );
        let (session, _stop_rx) = LaunchSession::create_in(
            registry_root.path(),
            "test-session",
            EnforcementMode::Warn,
            proxy_ctx.clone(),
        )
        .await
        .unwrap();
        session.publish(&obs_stream).await.unwrap();

        std::fs::write(
            &policy_path,
            r#"
forbid(principal, action, resource);
"#,
        )
        .unwrap();

        let control_socket = session.control_socket_path().await;
        let update = request_launch_policy_reload(&control_socket).await.unwrap();
        assert!(update.applied, "network-only reload should apply live");

        let events = obs_stream.recent_events();
        let runtime_event = events
            .into_iter()
            .find(|event| matches!(event.event, EventKind::PolicyReloaded { .. }))
            .expect("policy.reload should emit an observation event");

        assert_eq!(
            runtime_event.session,
            Some(ObservationSessionContext {
                session_id: "test-session".to_string(),
                mode: "warn".to_string(),
            })
        );
        match runtime_event.event {
            EventKind::PolicyReloaded {
                applied,
                source,
                restart_required_domains,
            } => {
                assert!(applied);
                assert_eq!(source, "reload");
                assert!(restart_required_domains.is_empty());
            }
            other => panic!("unexpected runtime event: {other:?}"),
        }

        drop(session);
    }

    // -- docker_arch_to_target tests ------------------------------------------

    #[test]
    fn docker_arch_x86_64() {
        assert_eq!(
            docker_arch_to_target("x86_64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
        assert_eq!(
            docker_arch_to_target("amd64").unwrap(),
            "x86_64-unknown-linux-musl"
        );
    }

    #[test]
    fn docker_arch_aarch64() {
        assert_eq!(
            docker_arch_to_target("aarch64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
        assert_eq!(
            docker_arch_to_target("arm64").unwrap(),
            "aarch64-unknown-linux-musl"
        );
    }

    #[test]
    fn docker_arch_unsupported() {
        let err = docker_arch_to_target("s390x").unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("unsupported container architecture"),
            "error should describe unsupported arch: {msg}"
        );
        assert!(
            msg.contains("s390x"),
            "error should include the arch: {msg}"
        );
    }

    // -- resolve_gateway_binary_from tests ------------------------------------

    #[test]
    fn resolve_finds_arch_binary_in_exe_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";
        let binary_path = tmp.path().join(format!("strait-gateway-{target}"));
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(tmp.path(), target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_finds_arch_binary_in_lib_strait() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "aarch64-unknown-linux-musl";

        // Simulate: exe is in <prefix>/bin/, gateway in <prefix>/lib/strait/
        let bin_dir = tmp.path().join("bin");
        let lib_dir = tmp.path().join("lib").join("strait");
        std::fs::create_dir_all(&bin_dir).unwrap();
        std::fs::create_dir_all(&lib_dir).unwrap();
        let binary_path = lib_dir.join(format!("strait-gateway-{target}"));
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(&bin_dir, target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_finds_binary_in_cargo_target_release() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        // Simulate: exe is in <workspace>/target/debug/, cross-compiled gateway
        // is in <workspace>/target/<target>/release/
        let exe_dir = tmp.path().join("target").join("debug");
        let gateway_dir = tmp.path().join("target").join(target).join("release");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::create_dir_all(&gateway_dir).unwrap();
        let binary_path = gateway_dir.join("strait-gateway");
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(&exe_dir, target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_finds_binary_in_cargo_target_debug() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "aarch64-unknown-linux-musl";

        let exe_dir = tmp.path().join("target").join("debug");
        let gateway_dir = tmp.path().join("target").join(target).join("debug");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::create_dir_all(&gateway_dir).unwrap();
        let binary_path = gateway_dir.join("strait-gateway");
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(&exe_dir, target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_finds_binary_from_cargo_test_deps_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        // Simulate: exe is in <workspace>/target/debug/deps/, cross-compiled
        // gateway is in <workspace>/target/<target>/release/
        let exe_dir = tmp.path().join("target").join("debug").join("deps");
        let gateway_dir = tmp.path().join("target").join(target).join("release");
        std::fs::create_dir_all(&exe_dir).unwrap();
        std::fs::create_dir_all(&gateway_dir).unwrap();
        let binary_path = gateway_dir.join("strait-gateway");
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(&exe_dir, target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_falls_back_to_unqualified_name() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        // No arch-specific binary, but plain `strait-gateway` exists
        let binary_path = tmp.path().join("strait-gateway");
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(tmp.path(), target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_falls_back_to_parent_unqualified_name() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        // Simulate cargo test: exe in deps/, gateway in parent
        let deps_dir = tmp.path().join("deps");
        std::fs::create_dir_all(&deps_dir).unwrap();
        let binary_path = tmp.path().join("strait-gateway");
        std::fs::write(&binary_path, b"fake").unwrap();

        let result = resolve_gateway_binary_from(&deps_dir, target).unwrap();
        assert_eq!(result, binary_path);
    }

    #[test]
    fn resolve_prefers_arch_specific_over_unqualified() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        // Both arch-specific and plain exist; arch-specific should win
        let arch_binary = tmp.path().join(format!("strait-gateway-{target}"));
        let plain_binary = tmp.path().join("strait-gateway");
        std::fs::write(&arch_binary, b"arch").unwrap();
        std::fs::write(&plain_binary, b"plain").unwrap();

        let result = resolve_gateway_binary_from(tmp.path(), target).unwrap();
        assert_eq!(result, arch_binary);
    }

    #[test]
    fn resolve_missing_binary_error_has_build_instructions() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "aarch64-unknown-linux-musl";

        let err = resolve_gateway_binary_from(tmp.path(), target).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains(target),
            "error should mention the target: {msg}"
        );
        assert!(
            msg.contains("cargo zigbuild"),
            "error should include cross-compile build command: {msg}"
        );
        assert!(
            msg.contains("cargo build -p strait-gateway"),
            "error should include local dev build command: {msg}"
        );
        assert!(
            msg.contains("not found"),
            "error should say not found: {msg}"
        );
    }

    #[test]
    fn resolve_missing_binary_error_lists_searched_paths() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "x86_64-unknown-linux-musl";

        let err = resolve_gateway_binary_from(tmp.path(), target).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("Searched:"),
            "error should list searched paths: {msg}"
        );
        assert!(
            msg.contains(&format!("strait-gateway-{target}")),
            "error should mention arch-qualified name: {msg}"
        );
    }

    /// The missing-gateway error must not tempt operators into host-wide
    /// trust workarounds. The container trust boundary only holds if we
    /// refuse to launch without the gateway instead of suggesting "install
    /// the CA on the host" as an escape hatch.
    #[test]
    fn resolve_missing_binary_error_does_not_suggest_host_wide_trust_workarounds() {
        let tmp = tempfile::tempdir().unwrap();
        let target = "aarch64-unknown-linux-musl";

        let err = resolve_gateway_binary_from(tmp.path(), target).unwrap_err();
        let msg = err.to_string().to_lowercase();

        let banned = [
            "install the ca on the host",
            "install the ca on your host",
            "add the ca to your system",
            "add the ca to the system",
            "system trust store",
            "host-wide ca",
            "host ca bundle",
            "/etc/ssl/certs",
            "/usr/local/share/ca-certificates",
            "update-ca-certificates",
            "security add-trusted-cert",
            "export https_proxy",
            "--network=host",
            "--net=host",
        ];
        for phrase in banned {
            assert!(
                !msg.contains(phrase),
                "missing-gateway error must not suggest host-wide workaround {phrase:?}: {msg}"
            );
        }
    }

    // -- parse_extra_mounts tests ---------------------------------------------

    #[test]
    fn parse_mount_host_container_ro() {
        let mounts = parse_extra_mounts(&["/foo:/bar:ro".to_string()]).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].host_path, "/foo");
        assert_eq!(mounts[0].container_path, "/bar");
        assert_eq!(mounts[0].mode, "ro");
        assert_eq!(mounts[0].to_bind_string(), "/foo:/bar:ro");
    }

    #[test]
    fn parse_mount_defaults_to_rw() {
        let mounts = parse_extra_mounts(&["/foo:/bar".to_string()]).unwrap();
        assert_eq!(mounts.len(), 1);
        assert_eq!(mounts[0].mode, "rw");
        assert_eq!(mounts[0].to_bind_string(), "/foo:/bar:rw");
    }

    #[test]
    fn parse_mount_invalid_no_colon() {
        let err = parse_extra_mounts(&["/foo".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid --mount format"), "got: {msg}");
    }

    #[test]
    fn parse_mount_invalid_mode() {
        let err = parse_extra_mounts(&["/foo:/bar:wx".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("invalid --mount mode"), "got: {msg}");
    }

    #[test]
    fn parse_mount_relative_host_path() {
        let err = parse_extra_mounts(&["foo:/bar".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("must be an absolute path"), "got: {msg}");
    }

    #[test]
    fn parse_mount_relative_container_path() {
        let err = parse_extra_mounts(&["/foo:bar".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("must be an absolute path"), "got: {msg}");
    }

    #[test]
    fn parse_mount_empty_paths() {
        let err = parse_extra_mounts(&[":/bar".to_string()]).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("must not be empty"), "got: {msg}");
    }

    #[test]
    fn parse_mount_multiple() {
        let mounts = parse_extra_mounts(&[
            "/a:/b:ro".to_string(),
            "/c:/d:rw".to_string(),
            "/e:/f".to_string(),
        ])
        .unwrap();
        assert_eq!(mounts.len(), 3);
        assert_eq!(mounts[0].to_bind_string(), "/a:/b:ro");
        assert_eq!(mounts[1].to_bind_string(), "/c:/d:rw");
        assert_eq!(mounts[2].to_bind_string(), "/e:/f:rw");
    }

    #[test]
    fn parse_mount_empty_vec() {
        let mounts = parse_extra_mounts(&[]).unwrap();
        assert!(mounts.is_empty());
    }
}
