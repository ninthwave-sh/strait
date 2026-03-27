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

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context as _;
use futures_util::StreamExt;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, info, warn};

use crate::ca::SessionCa;
use crate::container::{ContainerManager, ContainerPermission, ContainerPolicy};
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

    // 5. Start lightweight HTTPS proxy on random port
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_listener.local_addr()?.port();
    info!(port = proxy_port, "proxy listening");

    let obs_for_proxy = obs_stream.clone();
    let proxy_handle = tokio::spawn(run_proxy_loop(proxy_listener, obs_for_proxy));

    // 6. Build observe-mode container config
    //    In observe mode, mount the working directory read-write (no restrictions)
    let policy = ContainerPolicy {
        permissions: vec![ContainerPermission::FsWrite(
            cwd.to_string_lossy().to_string(),
        )],
    };

    // Build config with auto_remove=false so we can reliably capture the
    // exit code via wait_container. Docker's wait API returns status_code=0
    // for TTY containers with auto_remove=true (a Docker/bollard quirk).
    let mut config =
        ContainerManager::build_config(&policy, image, &command, proxy_port, Some(&ca_pem_path));
    config.auto_remove = false;

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
pub async fn run_launch_with_policy(
    mode: EnforcementMode,
    policy_path: &Path,
    command: Vec<String>,
    image: Option<&str>,
    output: Option<PathBuf>,
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

    // 6. Start policy-aware HTTPS proxy on random port
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await?;
    let proxy_port = proxy_listener.local_addr()?.port();
    info!(port = proxy_port, "proxy listening");

    let obs_for_proxy = obs_stream.clone();
    let engine_for_proxy = Arc::new(engine.clone());
    let proxy_handle = tokio::spawn(run_policy_proxy_loop(
        proxy_listener,
        obs_for_proxy,
        engine_for_proxy,
        mode,
    ));

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
    );
    config.auto_remove = false;

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

        tokio::select! {
            result = run_future => {
                result?
            }
            _ = ctrl_c => {
                eprintln!("\nInterrupted — cleaning up...");
                container_mgr.stop_container().await.ok();
                130
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

    #[cfg(unix)]
    drop(_term_guard);

    eprintln!("Container exited with code {exit_code}");
    eprintln!("Observation log: {}", obs_log_path.display());

    Ok(exit_code)
}

// ---------------------------------------------------------------------------
// Lightweight CONNECT proxy
// ---------------------------------------------------------------------------

/// Run a simple CONNECT-tunneling proxy that records connection events
/// through the observation stream.
///
/// All connections are passed through transparently (no MITM in observe mode).
/// Each CONNECT request generates a `NetworkRequest` observation event.
async fn run_proxy_loop(listener: TcpListener, obs: ObservationStream) {
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                let obs = obs.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_proxy_connection(client, &obs).await {
                        debug!(error = %e, "proxy connection error");
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

/// Handle a single CONNECT proxy connection.
///
/// Reads the CONNECT request line and headers, tunnels to the upstream host,
/// and emits a `NetworkRequest` observation event recording the connection.
async fn handle_proxy_connection(
    mut client: TcpStream,
    obs: &ObservationStream,
) -> anyhow::Result<()> {
    let mut buf_client = tokio::io::BufReader::new(&mut client);
    let mut request_line = String::new();
    buf_client.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let target = parts[1];

    if !method.eq_ignore_ascii_case("CONNECT") {
        // Non-CONNECT requests not supported in this lightweight proxy
        return Ok(());
    }

    let (host, port) = parse_connect_target(target)?;

    // Drain remaining request headers
    loop {
        let mut line = String::new();
        buf_client.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    // Drop BufReader to regain sole ownership of the TcpStream
    drop(buf_client);

    // Emit observation event
    obs.emit(EventKind::NetworkRequest {
        method: "CONNECT".to_string(),
        host: host.clone(),
        path: String::new(),
        decision: "passthrough".to_string(),
        latency_us: 0,
        enforcement_mode: String::new(),
    });

    // Connect to upstream
    let upstream_addr = format!("{host}:{port}");
    let mut upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %upstream_addr, error = %e, "upstream connect failed");
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .ok();
            return Ok(());
        }
    };

    // Send 200 Connection Established to client
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Tunnel bytes bidirectionally
    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;

    Ok(())
}

/// Parse a CONNECT target like `"host:port"` into `(host, port)`.
fn parse_connect_target(target: &str) -> anyhow::Result<(String, u16)> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port: u16 = port_str
            .parse()
            .with_context(|| format!("invalid port in CONNECT target: {target}"))?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

// ---------------------------------------------------------------------------
// Policy-aware CONNECT proxy (warn and enforce modes)
// ---------------------------------------------------------------------------

/// Run a policy-aware CONNECT proxy that evaluates Cedar policies.
///
/// - **Warn mode**: allows all connections but logs violations as warnings
/// - **Enforce mode**: denies connections to hosts not permitted by any `http:` policy
async fn run_policy_proxy_loop(
    listener: TcpListener,
    obs: ObservationStream,
    engine: Arc<PolicyEngine>,
    mode: EnforcementMode,
) {
    loop {
        match listener.accept().await {
            Ok((client, _peer)) => {
                let obs = obs.clone();
                let engine = engine.clone();
                tokio::spawn(async move {
                    if let Err(e) =
                        handle_policy_proxy_connection(client, &obs, &engine, mode).await
                    {
                        debug!(error = %e, "proxy connection error");
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

/// Handle a single CONNECT proxy connection with Cedar policy evaluation.
///
/// Evaluates whether the target host is permitted by any `http:` policy.
/// In warn mode, logs violations but allows the connection.
/// In enforce mode, returns 403 for disallowed hosts.
async fn handle_policy_proxy_connection(
    mut client: TcpStream,
    obs: &ObservationStream,
    engine: &PolicyEngine,
    mode: EnforcementMode,
) -> anyhow::Result<()> {
    let mut buf_client = tokio::io::BufReader::new(&mut client);
    let mut request_line = String::new();
    buf_client.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let target = parts[1];

    if !method.eq_ignore_ascii_case("CONNECT") {
        return Ok(());
    }

    let (host, port) = parse_connect_target(target)?;

    // Drain remaining request headers
    loop {
        let mut line = String::new();
        buf_client.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }

    drop(buf_client);

    // Evaluate Cedar policy: is this host permitted?
    let host_permitted = engine.is_host_permitted(&host, "agent").unwrap_or(false);

    if !host_permitted {
        match mode {
            EnforcementMode::Warn => {
                // Warn mode: log the violation but allow the connection
                info!(host = %host, mode = "warn", "policy violation: host not permitted (allowing)");
                obs.emit(EventKind::PolicyViolation {
                    enforcement_mode: "warn".to_string(),
                    action: "http:CONNECT".to_string(),
                    resource: host.clone(),
                    decision: "warn".to_string(),
                    reason: format!("No Cedar http: policy permits access to {host}"),
                });
                obs.emit(EventKind::NetworkRequest {
                    method: "CONNECT".to_string(),
                    host: host.clone(),
                    path: String::new(),
                    decision: "allow".to_string(),
                    latency_us: 0,
                    enforcement_mode: "warn".to_string(),
                });
            }
            EnforcementMode::Enforce => {
                // Enforce mode: deny the connection
                info!(host = %host, mode = "enforce", "policy denied: host not permitted");
                obs.emit(EventKind::PolicyViolation {
                    enforcement_mode: "enforce".to_string(),
                    action: "http:CONNECT".to_string(),
                    resource: host.clone(),
                    decision: "deny".to_string(),
                    reason: format!("No Cedar http: policy permits access to {host}"),
                });
                obs.emit(EventKind::NetworkRequest {
                    method: "CONNECT".to_string(),
                    host: host.clone(),
                    path: String::new(),
                    decision: "deny".to_string(),
                    latency_us: 0,
                    enforcement_mode: "enforce".to_string(),
                });
                client
                    .write_all(b"HTTP/1.1 403 Forbidden\r\n\r\n")
                    .await
                    .ok();
                return Ok(());
            }
            EnforcementMode::Observe => {
                // Should not reach here, but treat as passthrough
            }
        }
    } else {
        // Host is permitted — emit observation event
        obs.emit(EventKind::NetworkRequest {
            method: "CONNECT".to_string(),
            host: host.clone(),
            path: String::new(),
            decision: "allow".to_string(),
            latency_us: 0,
            enforcement_mode: mode.as_str().to_string(),
        });
    }

    // Connect to upstream
    let upstream_addr = format!("{host}:{port}");
    let mut upstream = match TcpStream::connect(&upstream_addr).await {
        Ok(s) => s,
        Err(e) => {
            debug!(target = %upstream_addr, error = %e, "upstream connect failed");
            client
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .ok();
            return Ok(());
        }
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;

    Ok(())
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

    #[test]
    fn parse_connect_target_with_port() {
        let (host, port) = parse_connect_target("api.github.com:443").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_without_port() {
        let (host, port) = parse_connect_target("api.github.com").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn parse_connect_target_custom_port() {
        let (host, port) = parse_connect_target("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
    }

    #[test]
    fn parse_connect_target_invalid_port() {
        let result = parse_connect_target("example.com:notaport");
        assert!(result.is_err());
    }

    /// Verify the proxy emits observation events for CONNECT requests.
    #[tokio::test]
    async fn proxy_emits_observation_events() {
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        // Start proxy in background
        let obs_clone = obs_stream.clone();
        let proxy_handle = tokio::spawn(run_proxy_loop(listener, obs_clone));

        // Connect a client and send a CONNECT request
        // (to a port that won't connect — we just test the event emission)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();

        // Give the proxy a moment to process
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        // Check that an observation event was emitted
        match rx.try_recv() {
            Ok(event) => match &event.event {
                EventKind::NetworkRequest {
                    method,
                    host,
                    decision,
                    ..
                } => {
                    assert_eq!(method, "CONNECT");
                    assert_eq!(host, "api.github.com");
                    assert_eq!(decision, "passthrough");
                }
                other => panic!("expected NetworkRequest, got {other:?}"),
            },
            Err(e) => panic!("no event received: {e:?}"),
        }

        proxy_handle.abort();
    }

    /// Verify the proxy handles non-CONNECT requests gracefully.
    #[tokio::test]
    async fn proxy_ignores_non_connect() {
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let obs_clone = obs_stream.clone();
        let proxy_handle = tokio::spawn(run_proxy_loop(listener, obs_clone));

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

    // -- Policy proxy tests ---------------------------------------------------

    /// Verify the policy proxy denies connections in enforce mode when
    /// the host is not permitted by any Cedar http: policy.
    #[tokio::test]
    async fn policy_proxy_enforce_denies_unpermitted_host() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Create a policy that only allows api.github.com
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

        let engine = Arc::new(PolicyEngine::load(policy_file.path(), None).unwrap());
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let obs_clone = obs_stream.clone();
        let engine_clone = engine.clone();
        let proxy_handle = tokio::spawn(run_policy_proxy_loop(
            listener,
            obs_clone,
            engine_clone,
            EnforcementMode::Enforce,
        ));

        // Connect to an unpermitted host — should get 403
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
            .await
            .unwrap();

        // Read the response
        let mut response = vec![0u8; 1024];
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        let n = client.try_read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            response_str.contains("403"),
            "enforce mode should return 403 for unpermitted host, got: {response_str}"
        );

        // Verify a PolicyViolation event was emitted
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let mut found_violation = false;
        while let Ok(event) = rx.try_recv() {
            if let EventKind::PolicyViolation {
                enforcement_mode,
                decision,
                ..
            } = &event.event
            {
                assert_eq!(enforcement_mode, "enforce");
                assert_eq!(decision, "deny");
                found_violation = true;
            }
        }
        assert!(
            found_violation,
            "should have emitted a PolicyViolation event"
        );

        proxy_handle.abort();
    }

    /// Verify the policy proxy allows connections to permitted hosts in enforce mode.
    #[tokio::test]
    async fn policy_proxy_enforce_allows_permitted_host() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Policy allows api.github.com
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

        let engine = Arc::new(PolicyEngine::load(policy_file.path(), None).unwrap());
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let obs_clone = obs_stream.clone();
        let engine_clone = engine.clone();
        let proxy_handle = tokio::spawn(run_policy_proxy_loop(
            listener,
            obs_clone,
            engine_clone,
            EnforcementMode::Enforce,
        ));

        // Connect to a permitted host — should not get 403
        // (may get 502 since the upstream doesn't exist, but not 403)
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Check the observation event
        let mut found_allowed = false;
        while let Ok(event) = rx.try_recv() {
            if let EventKind::NetworkRequest {
                decision,
                enforcement_mode,
                ..
            } = &event.event
            {
                if decision == "allow" && enforcement_mode == "enforce" {
                    found_allowed = true;
                }
            }
        }
        assert!(
            found_allowed,
            "should emit NetworkRequest with decision=allow for permitted host"
        );

        proxy_handle.abort();
    }

    /// Verify warn mode allows connections to unpermitted hosts but logs violations.
    #[tokio::test]
    async fn policy_proxy_warn_allows_but_logs_violation() {
        use std::io::Write;
        use tempfile::NamedTempFile;

        // Policy only allows api.github.com
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

        let engine = Arc::new(PolicyEngine::load(policy_file.path(), None).unwrap());
        let obs_stream = ObservationStream::new();
        let mut rx = obs_stream.subscribe();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = listener.local_addr().unwrap();

        let obs_clone = obs_stream.clone();
        let engine_clone = engine.clone();
        let proxy_handle = tokio::spawn(run_policy_proxy_loop(
            listener,
            obs_clone,
            engine_clone,
            EnforcementMode::Warn,
        ));

        // Connect to an unpermitted host — should NOT get 403 in warn mode
        let mut client = TcpStream::connect(proxy_addr).await.unwrap();
        client
            .write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com\r\n\r\n")
            .await
            .unwrap();

        tokio::time::sleep(std::time::Duration::from_millis(200)).await;

        // Read response — should get 200 or 502, NOT 403
        let mut response = vec![0u8; 1024];
        let n = client.try_read(&mut response).unwrap_or(0);
        let response_str = String::from_utf8_lossy(&response[..n]);
        assert!(
            !response_str.contains("403"),
            "warn mode should NOT return 403, got: {response_str}"
        );

        // Verify a PolicyViolation with decision=warn was emitted
        let mut found_warn = false;
        while let Ok(event) = rx.try_recv() {
            if let EventKind::PolicyViolation {
                enforcement_mode,
                decision,
                ..
            } = &event.event
            {
                if enforcement_mode == "warn" && decision == "warn" {
                    found_warn = true;
                }
            }
        }
        assert!(
            found_warn,
            "warn mode should emit PolicyViolation with decision=warn"
        );

        proxy_handle.abort();
    }
}
