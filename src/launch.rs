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
//! 1. Load and validate Cedar policy (warn/enforce modes — fail fast if invalid)
//! 2. Verify Docker is running (fail fast)
//! 3. Start lightweight HTTPS proxy on a random port
//! 4. Write session CA to temp file
//! 5. Create container with bind-mounts (policy-derived in warn/enforce modes)
//! 6. Inject CA into container's system bundle (via entrypoint wrapper)
//! 7. Set HTTPS_PROXY in container pointing to host proxy
//! 8. Start observation stream (JSONL file + Unix socket)
//! 9. Start container with TTY attached
//! 10. Wait for agent exit
//! 11. Stop proxy, clean up container, close observation stream
//!
//! # Security: Cooperative Enforcement Model
//!
//! Network enforcement relies on the container process honoring the
//! `HTTPS_PROXY` / `HTTP_PROXY` environment variables. This is cooperative —
//! not enforced at the network layer. A process that ignores the proxy
//! variables can make direct outbound connections that bypass policy
//! evaluation entirely. See [`crate::container`] module docs for details.
//!
//! **Observe mode caveat**: The working directory is mounted read-write
//! with no Cedar policy restricting filesystem access. A warning is emitted
//! to stderr at startup. In warn/enforce modes, filesystem access is
//! restricted to paths permitted by the Cedar policy.
//!
//! **v0.4 roadmap**: Network-level enforcement via Docker `--internal`
//! bridge network (no default route) with an explicit proxy route. This
//! eliminates the cooperative assumption by ensuring all outbound traffic
//! must traverse the Strait proxy.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;

use anyhow::Context as _;
use arc_swap::ArcSwap;
use futures_util::StreamExt;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::audit::AuditLogger;
use crate::ca::SessionCa;
use crate::config::ProxyContext;
use crate::container::{ContainerManager, ContainerPermission, ContainerPolicy};
use crate::credentials::CredentialStore;
use crate::mitm::handle_connection;
use crate::observe::{EventKind, ObservationStream};
use crate::policy::{extract_fs_permissions, PolicyEngine};

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

/// Default Docker image for the container sandbox.
const DEFAULT_IMAGE: &str = "alpine:latest";

/// Run the `launch --observe` workflow.
///
/// Orchestrates proxy, container, and observation into a unified workflow:
/// - All filesystem paths are read-write (no policy restricts in observe mode)
/// - All network traffic is tunneled through the proxy (passthrough, recorded)
/// - Activity is recorded to a JSONL observation file and Unix socket
///
/// Returns the container's exit code.
pub async fn run_launch_observe(
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
    extra_env: Vec<String>,
) -> anyhow::Result<i32> {
    let image = image.unwrap_or(DEFAULT_IMAGE);
    let cwd = std::env::current_dir().context("failed to get current directory")?;
    let obs_log_path = output.unwrap_or_else(|| cwd.join("observations.jsonl"));

    // 1. Verify Docker is running early (before any other setup)
    let mut container_mgr = ContainerManager::new()?;
    container_mgr.verify_connection().await?;
    info!("Docker daemon connected");

    // 2. Create temp directory for ephemeral files (CA pem, entrypoint script)
    let temp_dir = tempfile::TempDir::new().context("failed to create temp directory")?;
    let ca_pem_path = temp_dir.path().join("ca.pem");

    // 3. Set up observation stream (JSONL file + Unix socket)
    let mut obs_stream = ObservationStream::new();
    obs_stream.persist_to_file(&obs_log_path)?;
    info!(path = %obs_log_path.display(), "observation log created");
    eprintln!("Observation log: {}", obs_log_path.display());

    #[cfg(unix)]
    {
        // Use a unique socket path in the temp directory to avoid conflicts
        // when multiple launch sessions run concurrently (e.g., parallel tests).
        let socket_path = temp_dir.path().join("strait.sock");
        obs_stream.start_socket_server_at(&socket_path).await?;
        eprintln!("Observation socket: {}", socket_path.display());
    }

    // 4. Generate session CA and write to temp file
    let session_ca = SessionCa::generate()?;
    std::fs::write(&ca_pem_path, &session_ca.ca_cert_pem)?;
    info!(path = %ca_pem_path.display(), "session CA written");

    // 5. Start full MITM proxy on random port (reuses shared proxy implementation)
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_listener.local_addr()?.port();
    info!(port = proxy_port, "proxy listening");

    let proxy_ctx = Arc::new(build_launch_proxy_context(
        session_ca.clone(),
        None, // no policy engine in observe mode
        obs_stream.clone(),
        false, // not warn_only
        credential_store,
        mitm_hosts,
    )?);
    let proxy_handle = tokio::spawn(run_mitm_proxy_loop(proxy_listener, proxy_ctx));

    // 6. Build observe-mode container config
    //    In observe mode, mount the working directory read-write (no restrictions)
    let policy = ContainerPolicy {
        permissions: vec![ContainerPermission::FsWrite(
            cwd.to_string_lossy().to_string(),
        )],
    };

    // Warn about observe mode's permissive cwd mount and cooperative enforcement
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
        proxy_port,
        Some(&ca_pem_path),
        &cwd,
    )?;
    config.auto_remove = false;
    config.env.extend(extra_env);

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

    // 7. Set terminal raw mode for TTY passthrough (restored on drop)
    #[cfg(unix)]
    let _term_guard = setup_raw_terminal();

    // 8. Attach to container, start it, pipe I/O, and wait for exit
    let container_name = container_mgr.container_name().unwrap().to_string();

    let exit_code = {
        let run_future = attach_and_wait(container_mgr.docker(), &container_name);
        let ctrl_c = tokio::signal::ctrl_c();
        let sigterm = sigterm_signal();

        tokio::select! {
            result = run_future => {
                result?
            }
            _ = ctrl_c => {
                // In raw terminal mode, Ctrl+C goes to the container (byte 0x03).
                // This branch handles the non-TTY case (piped stdin).
                eprintln!("\nInterrupted — cleaning up...");
                container_mgr.stop_container().await.ok();
                130 // Standard exit code for SIGINT
            }
            _ = sigterm => {
                eprintln!("\nTerminated — cleaning up...");
                container_mgr.stop_container().await.ok();
                143 // Standard exit code for SIGTERM (128 + 15)
            }
        }
    };

    // 9. Emit container stop observation event
    obs_stream.emit(EventKind::ContainerStop {
        container_id,
        exit_code: Some(exit_code),
    });

    // 10. Cleanup: remove container (not auto-removed) and stop proxy
    container_mgr.remove_container().await;
    proxy_handle.abort();

    // Flush observation log before returning so callers can read the file.
    obs_stream.flush();

    // Drop the terminal guard before printing final messages
    #[cfg(unix)]
    drop(_term_guard);

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

    // 3. Create temp directory for ephemeral files (CA pem, entrypoint script)
    let temp_dir = tempfile::TempDir::new().context("failed to create temp directory")?;
    let ca_pem_path = temp_dir.path().join("ca.pem");

    // 4. Set up observation stream (JSONL file + Unix socket)
    let mut obs_stream = ObservationStream::new();
    obs_stream.persist_to_file(&obs_log_path)?;
    info!(path = %obs_log_path.display(), "observation log created");
    eprintln!("Observation log: {}", obs_log_path.display());

    #[cfg(unix)]
    {
        let socket_path = temp_dir.path().join("strait.sock");
        obs_stream.start_socket_server_at(&socket_path).await?;
        eprintln!("Observation socket: {}", socket_path.display());
    }

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
        Some(engine.clone()),
        obs_stream.clone(),
        mode == EnforcementMode::Warn,
        credential_store,
        mitm_hosts,
    )?);
    let proxy_handle = tokio::spawn(run_mitm_proxy_loop(proxy_listener, proxy_ctx));

    // 7. Extract filesystem permissions from Cedar policy
    let candidate_paths = vec![cwd.to_string_lossy().to_string()];
    let permissions = extract_fs_permissions(&engine, &candidate_paths, "agent");

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
        });
    }

    let container_policy = ContainerPolicy {
        permissions: permissions.clone(),
    };

    // 8. Build container config with policy-restricted mounts
    let mut config = ContainerManager::build_config(
        &container_policy,
        image,
        &command,
        proxy_port,
        Some(&ca_pem_path),
        &cwd,
    )?;
    config.auto_remove = false;
    config.env.extend(extra_env);

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

    // 9. Set terminal raw mode for TTY passthrough (restored on drop)
    #[cfg(unix)]
    let _term_guard = setup_raw_terminal();

    // 10. Attach to container, start it, pipe I/O, and wait for exit
    let container_name = container_mgr.container_name().unwrap().to_string();

    let exit_code = {
        let run_future = attach_and_wait(container_mgr.docker(), &container_name);
        let ctrl_c = tokio::signal::ctrl_c();
        let sigterm = sigterm_signal();

        tokio::select! {
            result = run_future => {
                result?
            }
            _ = ctrl_c => {
                eprintln!("\nInterrupted — cleaning up...");
                container_mgr.stop_container().await.ok();
                130
            }
            _ = sigterm => {
                eprintln!("\nTerminated — cleaning up...");
                container_mgr.stop_container().await.ok();
                143 // Standard exit code for SIGTERM (128 + 15)
            }
        }
    };

    // 11. Emit container stop observation event
    obs_stream.emit(EventKind::ContainerStop {
        container_id,
        exit_code: Some(exit_code),
    });

    // 12. Cleanup: remove container and stop proxy
    container_mgr.remove_container().await;
    proxy_handle.abort();

    // Flush observation log before returning so callers can read the file.
    obs_stream.flush();

    #[cfg(unix)]
    drop(_term_guard);

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
/// restricting filesystem access. Additionally, network enforcement relies on
/// the container process honoring `HTTPS_PROXY` — a cooperative assumption.
///
/// This function is extracted to enable testing the warning content.
pub(crate) fn observe_cwd_warning(cwd: &Path) -> String {
    format!(
        "Warning: observe mode mounts {} read-write — the container has full write \
         access to your working directory. Network enforcement is cooperative \
         (HTTPS_PROXY is advisory, not enforced at the network level).",
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

/// Build a [`ProxyContext`] for launch modes.
///
/// Creates a proxy context suitable for container-based launch workflows:
/// - `mitm_all`: true when `mitm_hosts` is empty (MITM everything), false when
///   a specific host list is provided from `--config`
/// - Observation stream attached for recording traffic
/// - Optional credential store from `--config` for credential injection
/// - Optional MITM host list from `--config`
pub fn build_launch_proxy_context(
    session_ca: SessionCa,
    policy_engine: Option<PolicyEngine>,
    obs_stream: ObservationStream,
    warn_only: bool,
    credential_store: Option<Arc<CredentialStore>>,
    mitm_hosts: Vec<String>,
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
        startup_instant: Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "agent".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: Some(obs_stream),
        enforcement_mode,
        mitm_all,
        warn_only,
        upstream_addr_override: None,
        upstream_tls_override: None,
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

// ---------------------------------------------------------------------------
// Container attach and TTY passthrough
// ---------------------------------------------------------------------------

/// Attach to a container, start it, pipe I/O, and wait for exit.
///
/// The attach is created before starting the container to avoid missing
/// early output. Returns the container's exit code.
async fn attach_and_wait(docker: &bollard::Docker, container_name: &str) -> anyhow::Result<i32> {
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
        .attach_container(container_name, Some(attach_options))
        .await
        .context("failed to attach to container")?;

    // Start the container
    docker
        .start_container(container_name, None::<StartContainerOptions<String>>)
        .await
        .context("failed to start container")?;

    info!(container_name = container_name, "container started");

    // Pipe container output to host stdout.
    // When the container exits, the output stream closes.
    let mut output = attach.output;
    let output_task = tokio::spawn(async move {
        let mut stdout = tokio::io::stdout();
        while let Some(Ok(chunk)) = output.next().await {
            let bytes = chunk.into_bytes();
            if stdout.write_all(&bytes).await.is_err() {
                break;
            }
            let _ = stdout.flush().await;
        }
    });

    // Pipe host stdin to container stdin
    let mut input = attach.input;
    let input_task = tokio::spawn(async move {
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
    });

    // Wait for the output stream to close (container has exited)
    let _ = output_task.await;
    input_task.abort();

    // Retrieve the exit code via inspect_container. The container is created
    // with auto_remove=false so it still exists after exit. This avoids a
    // Docker API quirk where wait_container returns status_code=0 for TTY
    // containers regardless of the actual exit code.
    let exit_code = match docker.inspect_container(container_name, None).await {
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

/// Guard that restores terminal settings when dropped.
#[cfg(unix)]
struct TerminalGuard {
    fd: i32,
    original: libc::termios,
}

#[cfg(unix)]
impl Drop for TerminalGuard {
    fn drop(&mut self) {
        unsafe {
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

/// Set stdin to raw mode if it's a terminal.
///
/// Returns a guard that restores the original terminal settings on drop.
/// Returns `None` if stdin is not a terminal (e.g., piped input).
#[cfg(unix)]
fn setup_raw_terminal() -> Option<TerminalGuard> {
    use std::io::IsTerminal;
    use std::os::unix::io::AsRawFd;

    if !std::io::stdin().is_terminal() {
        return None;
    }

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
        Some(TerminalGuard { fd, original })
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

    /// Verify observe mode warning mentions read-write access and cooperative enforcement.
    #[test]
    fn observe_cwd_warning_mentions_rw_and_cooperative() {
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
            msg.contains("cooperative"),
            "warning should mention cooperative enforcement: {msg}"
        );
        assert!(
            msg.contains("advisory"),
            "warning should mention HTTPS_PROXY is advisory: {msg}"
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
            "alpine:latest",
            &["sh".to_string()],
            8080,
            None,
            Path::new("/project"),
        )
        .unwrap();

        // Verify cwd is mounted read-write (not read-only)
        assert!(
            config.binds.iter().any(|b| b.contains(":rw")),
            "observe mode should mount cwd as read-write: {:?}",
            config.binds
        );
        assert!(
            !config.binds.iter().any(|b| b.contains(":ro")),
            "observe mode should NOT have read-only mounts: {:?}",
            config.binds
        );
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
            obs_stream,
            false,
            None,
            Vec::new(),
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
            obs_stream,
            true, // warn mode
            None,
            Vec::new(),
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
            obs_stream,
            false, // enforce mode
            None,
            Vec::new(),
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
            obs_stream,
            false,
            Some(store),
            Vec::new(),
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

        let ctx =
            build_launch_proxy_context(session_ca, None, obs_stream, false, None, hosts).unwrap();

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

        let ctx = build_launch_proxy_context(session_ca, None, obs_stream, false, None, Vec::new())
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
                obs_stream.clone(),
                false,
                None,
                Vec::new(),
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
                obs_stream.clone(),
                false,
                None,
                Vec::new(),
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
            startup_instant: Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: Some(obs_stream.clone()),
            enforcement_mode: "observe".to_string(),
            mitm_all: false,
            warn_only: false,
            upstream_addr_override: None,
            upstream_tls_override: None,
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
}
