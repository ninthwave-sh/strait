//! Container lifecycle management using the bollard Docker API.
//!
//! Builds Docker container configuration for Strait's network boundary.
//! The working directory is always bind-mounted into the container; Cedar
//! policy no longer controls filesystem or process access.
//!
//! # Security Model: Network Isolation
//!
//! Containers run with `--network=none` (no network interfaces). All
//! outbound traffic is forced through the Strait proxy via a bind-mounted
//! Unix socket and the `strait-gateway` binary:
//!
//! 1. The proxy Unix socket is bind-mounted into the container at
//!    `/strait/proxy.sock`.
//! 2. The `strait-gateway` binary is bind-mounted at
//!    `/strait/gateway/strait-gateway`. It listens on `127.0.0.1:3128`
//!    and forwards TCP connections to the Unix socket.
//! 3. `HTTPS_PROXY` / `HTTP_PROXY` env vars point to `http://127.0.0.1:3128`.
//! 4. The gateway runs as the outermost entrypoint, wrapping the CA trust
//!    injection and the user command.
//!
//! Because there are no network interfaces, a process inside the container
//! cannot bypass the proxy by connecting to arbitrary IP addresses. All
//! outbound traffic must traverse the gateway and the host proxy.

use anyhow::Context as _;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::image::CreateImageOptions;
use bollard::models::HostConfig;
use bollard::Docker;
use futures_util::StreamExt;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Container configuration (intermediate representation)
// ---------------------------------------------------------------------------

/// Docker container configuration for the launch sandbox.
///
/// This is a testable intermediate representation between Strait's launch
/// settings and bollard's `Config` struct, enabling unit tests without Docker.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Docker image to use (e.g. `"node:20-slim"`).
    pub image: String,
    /// Command to execute inside the container.
    pub cmd: Vec<String>,
    /// Environment variables to set (e.g. `"HTTPS_PROXY=http://127.0.0.1:3128"`).
    /// All four proxy variants (HTTPS_PROXY, HTTP_PROXY, https_proxy, http_proxy) are set.
    pub env: Vec<String>,
    /// Bind-mount strings in Docker format: `"host_path:container_path:ro"` or `":rw"`.
    pub binds: Vec<String>,
    /// Whether to attach a TTY.
    pub tty: bool,
    /// Entrypoint override. Always set by `build_config` to the gateway-based
    /// entrypoint chain (gateway -> CA trust injection -> user command).
    pub entrypoint: Option<Vec<String>>,
    /// Whether Docker should auto-remove the container after it exits.
    ///
    /// Defaults to `true` in `build_config`. Set to `false` when you need
    /// to inspect the container after exit (e.g., to read the exit code
    /// reliably via `wait_container`).
    pub auto_remove: bool,
    /// Docker network mode. Set to `"none"` for network isolation.
    pub network_mode: Option<String>,
}

/// Default graceful shutdown timeout (seconds) before force-killing.
const DEFAULT_STOP_TIMEOUT_SECS: i64 = 10;

/// Path where the CA PEM is bind-mounted inside the container.
pub const CONTAINER_CA_PEM_PATH: &str = "/strait/ca.pem";

/// Path for the augmented CA bundle created at container startup.
pub const CONTAINER_CA_BUNDLE_PATH: &str = "/tmp/strait-ca-bundle.pem";

/// Path where the proxy Unix socket is bind-mounted inside the container.
pub const CONTAINER_PROXY_SOCKET_PATH: &str = "/strait/proxy.sock";

/// Path where the gateway binary is bind-mounted inside the container.
pub const CONTAINER_GATEWAY_PATH: &str = "/strait/gateway/strait-gateway";

/// Address the gateway listens on inside the container.
pub const GATEWAY_LISTEN_ADDR: &str = "127.0.0.1:3128";

/// Environment variables set inside the container so common HTTPS clients
/// (libcurl, Python `requests`, Node.js, Go's `crypto/x509`) trust the
/// session CA via the augmented bundle at [`CONTAINER_CA_BUNDLE_PATH`].
///
/// These are set only when the launch path provides a session CA. They
/// are intentionally container-local: the bundle file lives inside the
/// container's writable tmpfs and the host trust store is never touched.
pub const CONTAINER_TRUST_ENV_VARS: &[&str] =
    &["SSL_CERT_FILE", "NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE"];

/// Environment variables set inside the container so HTTP-aware tools
/// route through the gateway at [`GATEWAY_LISTEN_ADDR`] instead of the
/// missing host network. All four casings are set because different tools
/// check different variants.
pub const CONTAINER_PROXY_ENV_VARS: &[&str] =
    &["HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy"];

/// Build the container trust boundary diagnostic, suitable for printing at
/// launch startup or returning from `strait session info`.
///
/// The output is a fixed list of facts about how the container reaches the
/// proxy and how it trusts the session CA. None of it is host-specific or
/// session-specific, so it can be generated synchronously without touching
/// the running container.
///
/// Operators reading the diagnostic should be able to answer:
///
/// 1. Where is the augmented CA bundle inside the container?
/// 2. Which env vars point clients at that bundle?
/// 3. How does outbound HTTP traffic reach the host proxy?
/// 4. Is host-wide CA trust required? (Answer: no, it is explicitly not.)
pub fn container_trust_diagnostic_lines() -> Vec<String> {
    let proxy_url = format!("http://{GATEWAY_LISTEN_ADDR}");
    vec![
        "Trust boundary: container-local (no machine-wide CA install required).".to_string(),
        format!(
            "  CA source mount: {CONTAINER_CA_PEM_PATH} (read-only, removed when the session ends)"
        ),
        format!(
            "  Augmented CA bundle: {CONTAINER_CA_BUNDLE_PATH} (built by the entrypoint script at container start)"
        ),
        format!(
            "  Trust env vars: {} (all point at the augmented bundle)",
            CONTAINER_TRUST_ENV_VARS.join(", ")
        ),
        format!(
            "  Proxy env vars: {} (all set to {proxy_url})",
            CONTAINER_PROXY_ENV_VARS.join(", ")
        ),
        format!(
            "  Network: --network=none with traffic forced through {CONTAINER_GATEWAY_PATH} -> {CONTAINER_PROXY_SOCKET_PATH}"
        ),
    ]
}

/// Generate the shell entrypoint script that injects the Strait session CA
/// into the container's trust store at startup.
///
/// The script:
/// 1. Verifies the CA PEM file is bind-mounted at `/strait/ca.pem`
/// 2. Detects the system CA bundle (Debian, Alpine, RHEL/Fedora)
/// 3. Creates an augmented bundle combining system CAs + Strait CA
/// 4. Runs the original command via `exec "$@"`
///
/// Edge cases handled:
/// - **Alpine** uses `/etc/ssl/cert.pem` instead of `/etc/ssl/certs/ca-certificates.crt`
/// - **No system CA bundle**: falls back to using only the Strait CA PEM
/// - **CA PEM not mounted**: prints a clear error and exits with code 1
pub fn generate_ca_entrypoint_script() -> String {
    format!(
        r#"#!/bin/sh
set -e

# Verify CA PEM is bind-mounted
if [ ! -f {ca_pem} ]; then
  echo "strait: ERROR: CA certificate not found at {ca_pem}" >&2
  echo "strait: The CA PEM file must be bind-mounted into the container." >&2
  exit 1
fi

# Detect system CA bundle location (Debian, Alpine, RHEL/Fedora)
SYSTEM_CA=""
for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
  if [ -f "$f" ]; then
    SYSTEM_CA="$f"
    break
  fi
done

# Build augmented CA bundle
if [ -n "$SYSTEM_CA" ]; then
  cat "$SYSTEM_CA" {ca_pem} > {ca_bundle}
else
  cp {ca_pem} {ca_bundle}
fi

exec "$@"
"#,
        ca_pem = CONTAINER_CA_PEM_PATH,
        ca_bundle = CONTAINER_CA_BUNDLE_PATH,
    )
}

// ---------------------------------------------------------------------------
// Bind-mount path validation
// ---------------------------------------------------------------------------

/// Validate a filesystem path for use as a Docker bind mount.
///
/// Prevents directory traversal attacks where paths like `/project/../../etc/shadow`
/// could mount unintended host directories into the container.
///
/// Strategy:
/// 1. Path must be absolute
/// 2. If the path exists on disk: [`std::fs::canonicalize`] resolves symlinks and
///    `..` components, then the canonical path is verified to be under `base_dir`
/// 3. If the path does not exist: textual validation rejects `..` components and
///    verifies the path starts with `base_dir`
///
/// Returns the validated (possibly canonicalized) path on success.
pub fn validate_bind_mount_path(path: &str, base_dir: &std::path::Path) -> anyhow::Result<String> {
    let p = std::path::Path::new(path);

    if !p.is_absolute() {
        warn!(path = %path, "rejecting relative bind-mount path");
        anyhow::bail!("bind-mount path must be absolute: {path}");
    }

    // Canonicalize base_dir for reliable prefix checking.
    // Falls back to the raw path when the base doesn't exist (e.g. in tests).
    let canonical_base = std::fs::canonicalize(base_dir).unwrap_or_else(|_| base_dir.to_path_buf());

    // Try filesystem-level canonicalization first (resolves symlinks and ..)
    if let Ok(canonical) = std::fs::canonicalize(p) {
        if canonical.starts_with(&canonical_base) {
            return Ok(canonical.to_string_lossy().to_string());
        }
        warn!(
            path = %path,
            canonical = %canonical.display(),
            base_dir = %canonical_base.display(),
            "rejecting bind-mount path: resolves outside base directory"
        );
        anyhow::bail!(
            "bind-mount path resolves outside base directory: {} -> {} (base: {})",
            path,
            canonical.display(),
            canonical_base.display()
        );
    }

    // Path doesn't exist on disk — fall back to textual validation.
    for component in p.components() {
        if component == std::path::Component::ParentDir {
            warn!(path = %path, "rejecting bind-mount path: contains '..' component");
            anyhow::bail!("bind-mount path contains directory traversal (..): {path}");
        }
    }

    // Verify the path is textually under the base directory
    if !p.starts_with(&canonical_base) {
        warn!(
            path = %path,
            base_dir = %canonical_base.display(),
            "rejecting bind-mount path: outside base directory"
        );
        anyhow::bail!(
            "bind-mount path is outside base directory: {} (base: {})",
            path,
            canonical_base.display()
        );
    }

    Ok(path.to_string())
}

// ---------------------------------------------------------------------------
// ContainerManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of a Docker container using the bollard API.
///
/// Typical usage:
/// 1. `ContainerManager::new()` — connect to the Docker daemon
/// 2. `create_container(image, cmd, proxy_socket, gateway_binary, ca_pem, cwd)` — build and create
/// 3. `start_container()` — start with TTY attached
/// 4. `stop_container()` — graceful shutdown, then force kill
///
/// The container is auto-removed when stopped (Docker `AutoRemove` flag).
pub struct ContainerManager {
    docker: Docker,
    container_id: Option<String>,
    container_name: Option<String>,
}

impl ContainerManager {
    /// Connect to the local Docker daemon.
    ///
    /// Returns a clear error if Docker is not running or the socket is not found.
    pub fn new() -> anyhow::Result<Self> {
        let docker = Docker::connect_with_local_defaults().context(
            "failed to connect to Docker daemon — is Docker running? \
             Check with: docker info",
        )?;

        Ok(Self {
            docker,
            container_id: None,
            container_name: None,
        })
    }

    /// Build a `ContainerConfig` for the launch sandbox.
    ///
    /// Validates and bind-mounts the working directory, sets environment
    /// variables, and configures the gateway-based entrypoint chain.
    ///
    /// The container runs with `--network=none` for network isolation. The
    /// proxy Unix socket and gateway binary are bind-mounted into the
    /// container. The gateway listens on `127.0.0.1:3128` and forwards
    /// connections to the host proxy over the Unix socket.
    ///
    /// When `ca_pem_host_path` is provided, the CA PEM file is bind-mounted
    /// into the container and a wrapper entrypoint script injects it into
    /// the system CA bundle at startup. The entrypoint chain is:
    /// gateway -> CA trust injection -> user command.
    ///
    /// The proxy socket and gateway binary paths are trusted (internally
    /// generated) and not validated against the working directory.
    #[allow(clippy::too_many_arguments)]
    pub fn build_config(
        image: &str,
        cmd: &[String],
        proxy_socket_host_path: &std::path::Path,
        gateway_binary_host_path: &std::path::Path,
        ca_pem_host_path: Option<&std::path::Path>,
        working_dir_host_path: &std::path::Path,
        tty: bool,
    ) -> anyhow::Result<ContainerConfig> {
        let mut binds = Vec::new();
        let validated_working_dir = validate_bind_mount_path(
            &working_dir_host_path.to_string_lossy(),
            working_dir_host_path,
        )?;
        binds.push(format!(
            "{validated_working_dir}:{validated_working_dir}:rw"
        ));

        // Bind-mount proxy socket and gateway binary for network isolation.
        // The proxy socket connects the in-container gateway to the host proxy.
        // The gateway binary bridges TCP (127.0.0.1:3128) to the Unix socket.
        binds.push(format!(
            "{}:{}",
            proxy_socket_host_path.display(),
            CONTAINER_PROXY_SOCKET_PATH,
        ));
        binds.push(format!(
            "{}:{}:ro",
            gateway_binary_host_path.display(),
            CONTAINER_GATEWAY_PATH,
        ));

        // Build environment variables.
        // Proxy env vars point to the in-container gateway (127.0.0.1:3128).
        // All four variants are set because different tools check different
        // casings (e.g. curl checks http_proxy, Python checks HTTP_PROXY).
        let proxy_url = format!("http://{GATEWAY_LISTEN_ADDR}");
        let mut env: Vec<String> = CONTAINER_PROXY_ENV_VARS
            .iter()
            .map(|var| format!("{var}={proxy_url}"))
            .collect();

        // CA trust injection: bind-mount the CA PEM, set env vars
        let ca_script = if let Some(host_path) = ca_pem_host_path {
            binds.push(format!(
                "{}:{}:ro",
                host_path.display(),
                CONTAINER_CA_PEM_PATH,
            ));

            for var in CONTAINER_TRUST_ENV_VARS {
                env.push(format!("{var}={CONTAINER_CA_BUNDLE_PATH}"));
            }

            Some(generate_ca_entrypoint_script())
        } else {
            None
        };

        // Build entrypoint chain: gateway -> [CA trust injection ->] user command.
        // The gateway is always the outermost wrapper. It listens on
        // 127.0.0.1:3128, forwarding to the proxy socket, then spawns the
        // child command (everything after `--`).
        let mut entrypoint = vec![
            CONTAINER_GATEWAY_PATH.to_string(),
            "--socket".to_string(),
            CONTAINER_PROXY_SOCKET_PATH.to_string(),
            "--".to_string(),
        ];
        if let Some(script) = ca_script {
            entrypoint.extend([
                "/bin/sh".to_string(),
                "-c".to_string(),
                script,
                "--".to_string(),
            ]);
        }

        Ok(ContainerConfig {
            image: image.to_string(),
            cmd: cmd.to_vec(),
            env,
            binds,
            tty,
            entrypoint: Some(entrypoint),
            auto_remove: true,
            network_mode: Some("none".to_string()),
        })
    }

    /// Create a Docker container from launch settings.
    ///
    /// The working directory is bind-mounted read-write, the container runs
    /// with `--network=none`, and the gateway binary provides proxy access via
    /// the Unix socket.
    ///
    /// The working directory path is validated before any Docker API calls.
    ///
    /// When `ca_pem_host_path` is provided, the Strait session CA is
    /// injected into the container's trust store via a wrapper entrypoint.
    ///
    /// Returns clear errors for:
    /// - Bind-mount path traversal attempts
    /// - Docker daemon not running (connection failure)
    /// - Image not found (with pull suggestion)
    #[allow(clippy::too_many_arguments)]
    pub async fn create_container(
        &mut self,
        image: &str,
        cmd: &[String],
        proxy_socket_host_path: &std::path::Path,
        gateway_binary_host_path: &std::path::Path,
        ca_pem_host_path: Option<&std::path::Path>,
        working_dir_host_path: &std::path::Path,
        tty: bool,
    ) -> anyhow::Result<String> {
        let config = Self::build_config(
            image,
            cmd,
            proxy_socket_host_path,
            gateway_binary_host_path,
            ca_pem_host_path,
            working_dir_host_path,
            tty,
        )?;
        self.create_container_from_config(&config).await
    }

    /// Create a Docker container from a pre-built `ContainerConfig`.
    ///
    /// This is the lower-level method that actually calls the Docker API.
    /// Use this when you need to modify the config after `build_config`
    /// (e.g., to disable `auto_remove` for reliable exit code capture).
    ///
    /// If the image is not found locally, an automatic `docker pull` is
    /// attempted before retrying container creation.
    pub async fn create_container_from_config(
        &mut self,
        config: &ContainerConfig,
    ) -> anyhow::Result<String> {
        // Verify Docker connectivity first
        self.ping().await?;

        match self.try_create_container(config).await {
            Ok(id) => Ok(id),
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("No such image") || msg.contains("not found") {
                    // Attempt auto-pull, then retry
                    info!(image = %config.image, "image not found locally, pulling...");
                    eprintln!("Image '{}' not found locally — pulling...", config.image);
                    self.pull_image(&config.image).await?;
                    self.try_create_container(config).await
                } else {
                    Err(e)
                }
            }
        }
    }

    /// Attempt to create a Docker container (single try, no auto-pull).
    async fn try_create_container(&mut self, config: &ContainerConfig) -> anyhow::Result<String> {
        let container_name = format!("strait-{}", uuid::Uuid::new_v4());

        let host_config = HostConfig {
            binds: if config.binds.is_empty() {
                None
            } else {
                Some(config.binds.clone())
            },
            auto_remove: Some(config.auto_remove),
            network_mode: config.network_mode.clone(),
            ..Default::default()
        };

        let docker_config = Config {
            image: Some(config.image.clone()),
            cmd: Some(config.cmd.clone()),
            env: Some(config.env.clone()),
            tty: Some(config.tty),
            open_stdin: Some(config.tty),
            attach_stdin: Some(config.tty),
            attach_stdout: Some(true),
            attach_stderr: Some(true),
            host_config: Some(host_config),
            entrypoint: config.entrypoint.clone(),
            ..Default::default()
        };

        let options = CreateContainerOptions {
            name: container_name.clone(),
            platform: None,
        };

        let response = self
            .docker
            .create_container(Some(options), docker_config)
            .await
            .map_err(|e| {
                let msg = e.to_string();
                if msg.contains("No such image") || msg.contains("not found") {
                    anyhow::anyhow!(
                        "image '{}' not found — try pulling it first: docker pull {}",
                        config.image,
                        config.image,
                    )
                } else if msg.contains("connection refused")
                    || msg.contains("Cannot connect")
                    || msg.contains("socket")
                {
                    anyhow::anyhow!(
                        "cannot connect to Docker daemon — is Docker running? \
                         Check with: docker info"
                    )
                } else {
                    anyhow::anyhow!("failed to create container: {e}")
                }
            })?;

        info!(
            container_id = %response.id,
            container_name = %container_name,
            image = %config.image,
            "container created"
        );

        self.container_id = Some(response.id.clone());
        self.container_name = Some(container_name);

        Ok(response.id)
    }

    /// Pull a Docker image from the registry.
    ///
    /// Streams progress to the log and returns an error if the pull fails.
    async fn pull_image(&self, image: &str) -> anyhow::Result<()> {
        let options = Some(CreateImageOptions {
            from_image: image,
            ..Default::default()
        });

        let mut stream = self.docker.create_image(options, None, None);
        while let Some(result) = stream.next().await {
            match result {
                Ok(info) => {
                    if let Some(status) = &info.status {
                        debug!(image = %image, status = %status, "pull progress");
                    }
                }
                Err(e) => {
                    return Err(anyhow::anyhow!("failed to pull image '{}': {}", image, e));
                }
            }
        }
        info!(image = %image, "image pulled successfully");
        eprintln!("Image '{}' pulled successfully", image);
        Ok(())
    }

    /// Start the previously created container.
    ///
    /// The container must have been created with `create_container` first.
    pub async fn start_container(&self) -> anyhow::Result<()> {
        let name = self.container_name.as_deref().ok_or_else(|| {
            anyhow::anyhow!("no container to start — call create_container first")
        })?;

        self.docker
            .start_container(name, None::<StartContainerOptions<String>>)
            .await
            .context("failed to start container")?;

        info!(container_name = %name, "container started");
        Ok(())
    }

    /// Stop the container gracefully, then force-kill after timeout.
    ///
    /// Uses the default stop timeout of 10 seconds. The container is
    /// automatically removed (via `AutoRemove`) after stopping.
    pub async fn stop_container(&mut self) -> anyhow::Result<()> {
        let name = match self.container_name.as_deref() {
            Some(n) => n.to_string(),
            None => {
                debug!("stop_container called with no active container");
                return Ok(());
            }
        };

        let options = StopContainerOptions {
            t: DEFAULT_STOP_TIMEOUT_SECS,
        };

        match self.docker.stop_container(&name, Some(options)).await {
            Ok(()) => {
                info!(container_name = %name, "container stopped");
            }
            Err(e) => {
                let msg = e.to_string();
                // Container already stopped or removed — not an error
                if msg.contains("is not running") || msg.contains("No such container") {
                    warn!(container_name = %name, "container already stopped");
                } else {
                    return Err(anyhow::anyhow!("failed to stop container '{name}': {e}"));
                }
            }
        }

        self.container_id = None;
        self.container_name = None;
        Ok(())
    }

    /// Force-remove the container (used for cleanup on exit).
    ///
    /// This is a best-effort operation — errors are logged but not propagated,
    /// since this is typically called during shutdown.
    pub async fn remove_container(&mut self) {
        let name = match self.container_name.take() {
            Some(n) => n,
            None => return,
        };

        let options = RemoveContainerOptions {
            force: true,
            ..Default::default()
        };

        match self.docker.remove_container(&name, Some(options)).await {
            Ok(()) => {
                info!(container_name = %name, "container removed");
            }
            Err(e) => {
                warn!(container_name = %name, error = %e, "failed to remove container (best-effort)");
            }
        }

        self.container_id = None;
    }

    /// Return the container ID if a container has been created.
    pub fn container_id(&self) -> Option<&str> {
        self.container_id.as_deref()
    }

    /// Return the container name if a container has been created.
    pub fn container_name(&self) -> Option<&str> {
        self.container_name.as_deref()
    }

    /// Return a reference to the underlying Docker client.
    ///
    /// Used by the launch orchestrator for attach and wait operations.
    pub fn docker(&self) -> &Docker {
        &self.docker
    }

    /// Verify connectivity to the Docker daemon.
    ///
    /// Returns a clear error if Docker is not running or the socket is not found.
    /// Call this early in the workflow to fail fast before setting up other resources.
    pub async fn verify_connection(&self) -> anyhow::Result<()> {
        self.ping().await
    }

    /// Ping the Docker daemon to verify connectivity.
    async fn ping(&self) -> anyhow::Result<()> {
        self.docker.ping().await.map_err(|e| {
            let msg = e.to_string();
            if msg.contains("connection refused")
                || msg.contains("Cannot connect")
                || msg.contains("socket")
                || msg.contains("No such file")
            {
                anyhow::anyhow!(
                    "Docker daemon is not running — start Docker and try again. \
                     Check with: docker info"
                )
            } else {
                anyhow::anyhow!("failed to ping Docker daemon: {e}")
            }
        })?;
        Ok(())
    }
}

impl Drop for ContainerManager {
    fn drop(&mut self) {
        // Best-effort cleanup: if we still have a container, try to remove it.
        // We can't use async in Drop, so we try tokio::spawn first and fall
        // back to a synchronous `docker rm -f` via the CLI when the runtime
        // is shutting down (tokio::spawn would panic in that case).
        if let Some(name) = self.container_name.take() {
            if let Ok(_handle) = tokio::runtime::Handle::try_current() {
                let docker = self.docker.clone();
                let name_clone = name.clone();
                tokio::spawn(async move {
                    let options = RemoveContainerOptions {
                        force: true,
                        ..Default::default()
                    };
                    if let Err(e) = docker.remove_container(&name_clone, Some(options)).await {
                        warn!(container_name = %name_clone, error = %e, "drop cleanup: failed to remove container");
                    }
                });
            } else {
                // Runtime unavailable (shutting down) — synchronous CLI fallback
                // to prevent orphaned containers.
                if let Err(e) = std::process::Command::new("docker")
                    .args(["rm", "-f", &name])
                    .stdin(std::process::Stdio::null())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                {
                    eprintln!("drop cleanup: failed to remove container {name}: {e}");
                }
            }
            self.container_id = None;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_working_dir() -> &'static Path {
        Path::new("/project")
    }

    fn test_proxy_socket() -> &'static Path {
        Path::new("/tmp/test-proxy.sock")
    }

    fn test_gateway_binary() -> &'static Path {
        Path::new("/usr/local/bin/strait-gateway")
    }

    fn build_test_config(
        image: &str,
        cmd: &[String],
        ca_pem_host_path: Option<&Path>,
        working_dir: &Path,
    ) -> anyhow::Result<ContainerConfig> {
        ContainerManager::build_config(
            image,
            cmd,
            test_proxy_socket(),
            test_gateway_binary(),
            ca_pem_host_path,
            working_dir,
            true,
        )
    }

    #[test]
    fn network_mode_is_none() {
        let config = build_test_config("alpine", &[], None, test_working_dir()).unwrap();
        assert_eq!(config.network_mode.as_deref(), Some("none"));
    }

    #[test]
    fn proxy_socket_is_bind_mounted() {
        let config = build_test_config("alpine", &[], None, test_working_dir()).unwrap();
        assert!(config.binds.contains(&format!(
            "{}:{}",
            test_proxy_socket().display(),
            CONTAINER_PROXY_SOCKET_PATH,
        )));
    }

    #[test]
    fn gateway_binary_is_bind_mounted() {
        let config = build_test_config("alpine", &[], None, test_working_dir()).unwrap();
        assert!(config.binds.contains(&format!(
            "{}:{}:ro",
            test_gateway_binary().display(),
            CONTAINER_GATEWAY_PATH,
        )));
    }

    #[test]
    fn working_directory_is_bind_mounted_readwrite() {
        let config = build_test_config("node:20", &[], None, test_working_dir()).unwrap();
        assert!(config.binds.contains(&"/project:/project:rw".to_string()));
    }

    #[test]
    fn build_config_with_ca_adds_bind_mount_and_env() {
        let ca_path = Path::new("/tmp/test-ca.pem");
        let config = build_test_config("node:20", &[], Some(ca_path), test_working_dir()).unwrap();
        assert!(config.binds.contains(&format!(
            "{}:{}:ro",
            ca_path.display(),
            CONTAINER_CA_PEM_PATH
        )));
        for var in CONTAINER_TRUST_ENV_VARS {
            assert!(config
                .env
                .contains(&format!("{var}={CONTAINER_CA_BUNDLE_PATH}")));
        }
    }

    #[test]
    fn build_config_has_expected_bind_count() {
        let config = build_test_config("alpine", &[], None, test_working_dir()).unwrap();
        assert_eq!(config.binds.len(), 3, "cwd + proxy socket + gateway binary");
    }

    #[test]
    fn build_config_rejects_invalid_working_directory() {
        let result = build_test_config("node:20", &[], None, Path::new("/project/../../etc"));
        assert!(result.is_err());
    }

    #[test]
    fn trust_diagnostic_lines_describe_container_local_boundary() {
        let lines = container_trust_diagnostic_lines();
        assert!(lines.iter().any(|line| line.contains("container-local")));
        assert!(lines
            .iter()
            .any(|line| line.contains(CONTAINER_CA_PEM_PATH)));
        assert!(lines
            .iter()
            .any(|line| line.contains(CONTAINER_CA_BUNDLE_PATH)));
        assert!(lines.iter().any(|line| line.contains(GATEWAY_LISTEN_ADDR)));
        assert!(lines.iter().any(|line| line.contains("--network=none")));
    }

    #[test]
    fn ca_entrypoint_script_is_valid_shell() {
        let script = generate_ca_entrypoint_script();
        assert!(script.starts_with(
            "#!/bin/sh
"
        ));
        assert!(script.contains("set -e"));
        assert!(script.contains(CONTAINER_CA_PEM_PATH));
        assert!(script.contains(CONTAINER_CA_BUNDLE_PATH));
        assert!(script.contains("exec \"$@\""));
    }

    #[test]
    fn traversal_path_is_rejected() {
        let result =
            validate_bind_mount_path("/project/../../../etc/shadow", Path::new("/project"));
        assert!(result.is_err());
    }

    #[test]
    fn relative_path_is_rejected() {
        let result = validate_bind_mount_path("project/src", Path::new("/project"));
        assert!(result.is_err());
    }

    #[test]
    fn valid_existing_path_inside_base_is_accepted() {
        let temp = tempfile::TempDir::new().unwrap();
        let sub_dir = temp.path().join("subdir");
        std::fs::create_dir_all(&sub_dir).unwrap();

        let result = validate_bind_mount_path(&sub_dir.to_string_lossy(), temp.path()).unwrap();
        let canonical = std::fs::canonicalize(&sub_dir)
            .unwrap()
            .to_string_lossy()
            .to_string();
        assert_eq!(result, canonical);
    }
}
