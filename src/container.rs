//! Container lifecycle management using the bollard Docker API.
//!
//! Translates Cedar policy into Docker container configuration:
//! - `fs:read` policies map to read-only bind-mounts
//! - `fs:write` policies map to read-write bind-mounts
//! - `proc:exec` policies map to binaries available on the container PATH
//!
//! Network traffic routes through the host proxy via the `HTTPS_PROXY`
//! environment variable pointing to `host.docker.internal:<port>`.

use anyhow::Context as _;
use bollard::container::{
    Config, CreateContainerOptions, RemoveContainerOptions, StartContainerOptions,
    StopContainerOptions,
};
use bollard::models::HostConfig;
use bollard::Docker;
use tracing::{debug, info, warn};

// ---------------------------------------------------------------------------
// Policy types used as input
// ---------------------------------------------------------------------------

/// A single permission extracted from a Cedar policy for container configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerPermission {
    /// Read access to a filesystem path (maps to read-only bind-mount).
    FsRead(String),
    /// Write access to a filesystem path (maps to read-write bind-mount).
    FsWrite(String),
    /// Permission to execute a specific binary.
    ProcExec(String),
}

/// A collection of permissions that define a container's capabilities.
#[derive(Debug, Clone, Default)]
pub struct ContainerPolicy {
    /// Individual permissions extracted from Cedar policy.
    pub permissions: Vec<ContainerPermission>,
}

// ---------------------------------------------------------------------------
// Container configuration (intermediate representation)
// ---------------------------------------------------------------------------

/// Docker container configuration derived from Cedar policy.
///
/// This is a testable intermediate representation between Cedar policy
/// and bollard's `Config` struct, enabling unit tests without Docker.
#[derive(Debug, Clone)]
pub struct ContainerConfig {
    /// Docker image to use (e.g. `"node:20-slim"`).
    pub image: String,
    /// Command to execute inside the container.
    pub cmd: Vec<String>,
    /// Environment variables to set (e.g. `"HTTPS_PROXY=http://host.docker.internal:8080"`).
    pub env: Vec<String>,
    /// Bind-mount strings in Docker format: `"host_path:container_path:ro"` or `":rw"`.
    pub binds: Vec<String>,
    /// Whether to attach a TTY.
    pub tty: bool,
    /// Optional entrypoint override (e.g. for CA trust injection wrapper).
    pub entrypoint: Option<Vec<String>>,
}

/// Default graceful shutdown timeout (seconds) before force-killing.
const DEFAULT_STOP_TIMEOUT_SECS: i64 = 10;

/// Path where the CA PEM is bind-mounted inside the container.
const CONTAINER_CA_PEM_PATH: &str = "/strait/ca.pem";

/// Path for the augmented CA bundle created at container startup.
const CONTAINER_CA_BUNDLE_PATH: &str = "/tmp/strait-ca-bundle.pem";

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
// ContainerManager
// ---------------------------------------------------------------------------

/// Manages the lifecycle of a Docker container using the bollard API.
///
/// Typical usage:
/// 1. `ContainerManager::new()` — connect to the Docker daemon
/// 2. `create_container(policy, image, cmd, proxy_port, ca_pem)` — build and create
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

    /// Build a `ContainerConfig` from a Cedar-derived policy.
    ///
    /// This is a pure function (no Docker calls) that translates permissions
    /// into Docker bind-mounts, environment variables, and PATH entries.
    ///
    /// When `ca_pem_host_path` is provided, the CA PEM file is bind-mounted
    /// into the container and a wrapper entrypoint script injects it into
    /// the system CA bundle at startup.
    pub fn build_config(
        policy: &ContainerPolicy,
        image: &str,
        cmd: &[String],
        proxy_port: u16,
        ca_pem_host_path: Option<&std::path::Path>,
    ) -> ContainerConfig {
        let mut binds = Vec::new();
        let mut extra_path_dirs: Vec<String> = Vec::new();

        for perm in &policy.permissions {
            match perm {
                ContainerPermission::FsRead(path) => {
                    // host_path:container_path:ro
                    binds.push(format!("{path}:{path}:ro"));
                }
                ContainerPermission::FsWrite(path) => {
                    // host_path:container_path:rw
                    binds.push(format!("{path}:{path}:rw"));
                }
                ContainerPermission::ProcExec(binary) => {
                    // Derive the directory containing the binary and add to PATH.
                    // If the binary is a bare name (e.g. "git"), assume it lives
                    // in a standard location and add /usr/bin to PATH.
                    if let Some(dir) = std::path::Path::new(binary).parent() {
                        let dir_str = dir.to_string_lossy();
                        if !dir_str.is_empty() {
                            if !extra_path_dirs.contains(&dir_str.to_string()) {
                                extra_path_dirs.push(dir_str.to_string());
                            }
                        } else {
                            // Bare binary name — add standard locations
                            for std_dir in ["/usr/local/bin", "/usr/bin", "/bin"] {
                                if !extra_path_dirs.contains(&std_dir.to_string()) {
                                    extra_path_dirs.push(std_dir.to_string());
                                }
                            }
                        }
                    }
                }
            }
        }

        // Build environment variables
        let mut env = vec![format!(
            "HTTPS_PROXY=http://host.docker.internal:{proxy_port}"
        )];

        // Add PATH with extra directories for proc:exec binaries
        if !extra_path_dirs.is_empty() {
            let path_value = extra_path_dirs.join(":");
            env.push(format!("PATH={path_value}"));
        }

        // CA trust injection: bind-mount the CA PEM, set env vars, wrap entrypoint
        let entrypoint = if let Some(host_path) = ca_pem_host_path {
            binds.push(format!(
                "{}:{}:ro",
                host_path.display(),
                CONTAINER_CA_PEM_PATH,
            ));

            env.push(format!("SSL_CERT_FILE={CONTAINER_CA_BUNDLE_PATH}"));
            env.push(format!("NODE_EXTRA_CA_CERTS={CONTAINER_CA_BUNDLE_PATH}"));
            env.push(format!("REQUESTS_CA_BUNDLE={CONTAINER_CA_BUNDLE_PATH}"));

            let script = generate_ca_entrypoint_script();
            Some(vec![
                "/bin/sh".to_string(),
                "-c".to_string(),
                script,
                "--".to_string(),
            ])
        } else {
            None
        };

        ContainerConfig {
            image: image.to_string(),
            cmd: cmd.to_vec(),
            env,
            binds,
            tty: true,
            entrypoint,
        }
    }

    /// Create a Docker container from a Cedar-derived policy.
    ///
    /// Translates the policy into bind-mounts, environment variables, and
    /// command configuration. The container is configured with `AutoRemove`
    /// so it is cleaned up automatically when stopped.
    ///
    /// When `ca_pem_host_path` is provided, the Strait session CA is
    /// injected into the container's trust store via a wrapper entrypoint.
    ///
    /// Returns clear errors for:
    /// - Docker daemon not running (connection failure)
    /// - Image not found (with pull suggestion)
    pub async fn create_container(
        &mut self,
        policy: &ContainerPolicy,
        image: &str,
        cmd: &[String],
        proxy_port: u16,
        ca_pem_host_path: Option<&std::path::Path>,
    ) -> anyhow::Result<String> {
        let config = Self::build_config(policy, image, cmd, proxy_port, ca_pem_host_path);
        self.create_container_from_config(&config).await
    }

    /// Create a Docker container from a pre-built `ContainerConfig`.
    ///
    /// This is the lower-level method that actually calls the Docker API.
    async fn create_container_from_config(
        &mut self,
        config: &ContainerConfig,
    ) -> anyhow::Result<String> {
        // Verify Docker connectivity first
        self.ping().await?;

        let container_name = format!("strait-{}", uuid::Uuid::new_v4());

        let host_config = HostConfig {
            binds: if config.binds.is_empty() {
                None
            } else {
                Some(config.binds.clone())
            },
            auto_remove: Some(true),
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
        // We can't use async in Drop, so we spawn a blocking removal.
        if let Some(name) = self.container_name.take() {
            let docker = self.docker.clone();
            // Fire-and-forget cleanup task
            tokio::spawn(async move {
                let options = RemoveContainerOptions {
                    force: true,
                    ..Default::default()
                };
                if let Err(e) = docker.remove_container(&name, Some(options)).await {
                    warn!(container_name = %name, error = %e, "drop cleanup: failed to remove container");
                }
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_with(perms: Vec<ContainerPermission>) -> ContainerPolicy {
        ContainerPolicy { permissions: perms }
    }

    // -- Unit tests: Cedar policy → container config --------------------------

    #[test]
    fn fs_read_produces_readonly_bind_mount() {
        let policy = policy_with(vec![ContainerPermission::FsRead(
            "/project/src".to_string(),
        )]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert_eq!(config.binds.len(), 1);
        assert_eq!(config.binds[0], "/project/src:/project/src:ro");
    }

    #[test]
    fn fs_write_produces_readwrite_bind_mount() {
        let policy = policy_with(vec![ContainerPermission::FsWrite(
            "/project/out".to_string(),
        )]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert_eq!(config.binds.len(), 1);
        assert_eq!(config.binds[0], "/project/out:/project/out:rw");
    }

    #[test]
    fn mixed_fs_permissions_produce_correct_mounts() {
        let policy = policy_with(vec![
            ContainerPermission::FsRead("/project/src".to_string()),
            ContainerPermission::FsWrite("/project/out".to_string()),
            ContainerPermission::FsRead("/project/config".to_string()),
        ]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert_eq!(config.binds.len(), 3);
        assert_eq!(config.binds[0], "/project/src:/project/src:ro");
        assert_eq!(config.binds[1], "/project/out:/project/out:rw");
        assert_eq!(config.binds[2], "/project/config:/project/config:ro");
    }

    #[test]
    fn proc_exec_bare_binary_adds_standard_path_dirs() {
        let policy = policy_with(vec![ContainerPermission::ProcExec("git".to_string())]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        // Should have PATH with standard directories
        let path_env = config.env.iter().find(|e| e.starts_with("PATH="));
        assert!(path_env.is_some(), "should have PATH env var");
        let path_value = path_env.unwrap().strip_prefix("PATH=").unwrap();
        assert!(
            path_value.contains("/usr/local/bin"),
            "PATH should include /usr/local/bin: {path_value}"
        );
        assert!(
            path_value.contains("/usr/bin"),
            "PATH should include /usr/bin: {path_value}"
        );
        assert!(
            path_value.contains("/bin"),
            "PATH should include /bin: {path_value}"
        );
    }

    #[test]
    fn proc_exec_absolute_path_adds_parent_to_path() {
        let policy = policy_with(vec![ContainerPermission::ProcExec(
            "/usr/local/bin/node".to_string(),
        )]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        let path_env = config.env.iter().find(|e| e.starts_with("PATH="));
        assert!(path_env.is_some(), "should have PATH env var");
        let path_value = path_env.unwrap().strip_prefix("PATH=").unwrap();
        assert!(
            path_value.contains("/usr/local/bin"),
            "PATH should include parent dir: {path_value}"
        );
    }

    #[test]
    fn https_proxy_env_var_set_to_host() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert!(
            config
                .env
                .contains(&"HTTPS_PROXY=http://host.docker.internal:8080".to_string()),
            "should have HTTPS_PROXY env var: {:?}",
            config.env
        );
    }

    #[test]
    fn https_proxy_uses_configured_port() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "node:20", &[], 9999, None);

        assert!(
            config
                .env
                .contains(&"HTTPS_PROXY=http://host.docker.internal:9999".to_string()),
            "HTTPS_PROXY should use port 9999: {:?}",
            config.env
        );
    }

    #[test]
    fn config_includes_image_and_cmd() {
        let policy = policy_with(vec![]);
        let cmd = vec!["npm".to_string(), "test".to_string()];
        let config = ContainerManager::build_config(&policy, "node:20-slim", &cmd, 8080, None);

        assert_eq!(config.image, "node:20-slim");
        assert_eq!(config.cmd, vec!["npm", "test"]);
    }

    #[test]
    fn tty_enabled_by_default() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "alpine", &[], 8080, None);
        assert!(config.tty, "TTY should be enabled");
    }

    #[test]
    fn empty_policy_produces_no_binds() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "alpine", &[], 8080, None);
        assert!(config.binds.is_empty(), "empty policy should have no binds");
    }

    #[test]
    fn multiple_proc_exec_no_duplicate_path_dirs() {
        let policy = policy_with(vec![
            ContainerPermission::ProcExec("git".to_string()),
            ContainerPermission::ProcExec("curl".to_string()),
            ContainerPermission::ProcExec("node".to_string()),
        ]);

        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        let path_env = config.env.iter().find(|e| e.starts_with("PATH="));
        assert!(path_env.is_some());
        let path_value = path_env.unwrap().strip_prefix("PATH=").unwrap();

        // Count occurrences of /usr/bin — should appear only once
        let usr_bin_count = path_value.split(':').filter(|d| *d == "/usr/bin").count();
        assert_eq!(
            usr_bin_count, 1,
            "PATH should not have duplicate /usr/bin: {path_value}"
        );
    }

    #[test]
    fn full_policy_produces_complete_config() {
        let policy = policy_with(vec![
            ContainerPermission::FsRead("/project/src".to_string()),
            ContainerPermission::FsWrite("/project/out".to_string()),
            ContainerPermission::ProcExec("git".to_string()),
        ]);

        let cmd = vec!["bash".to_string(), "-c".to_string(), "npm test".to_string()];
        let config = ContainerManager::build_config(&policy, "node:20", &cmd, 8080, None);

        // Check binds
        assert_eq!(config.binds.len(), 2);
        assert!(config
            .binds
            .contains(&"/project/src:/project/src:ro".to_string()));
        assert!(config
            .binds
            .contains(&"/project/out:/project/out:rw".to_string()));

        // Check HTTPS_PROXY
        assert!(config
            .env
            .contains(&"HTTPS_PROXY=http://host.docker.internal:8080".to_string()));

        // Check PATH includes git directories
        let path_env = config.env.iter().find(|e| e.starts_with("PATH="));
        assert!(path_env.is_some());

        // Check image and cmd
        assert_eq!(config.image, "node:20");
        assert_eq!(config.cmd, vec!["bash", "-c", "npm test"]);

        // Check TTY
        assert!(config.tty);
    }

    // -- Unit tests: CA trust injection ----------------------------------------

    #[test]
    fn ca_entrypoint_script_is_valid_shell() {
        let script = generate_ca_entrypoint_script();

        // Starts with shebang
        assert!(
            script.starts_with("#!/bin/sh\n"),
            "script should start with shebang"
        );

        // Uses set -e for fail-fast
        assert!(script.contains("set -e"), "script should use set -e");

        // Contains error check for missing CA PEM
        assert!(
            script.contains("/strait/ca.pem"),
            "script should reference CA PEM path"
        );
        assert!(
            script.contains("ERROR"),
            "script should have error message for missing CA"
        );
        assert!(
            script.contains("exit 1"),
            "script should exit 1 on missing CA"
        );

        // Detects Debian CA bundle
        assert!(
            script.contains("/etc/ssl/certs/ca-certificates.crt"),
            "script should detect Debian CA bundle"
        );

        // Detects Alpine CA bundle
        assert!(
            script.contains("/etc/ssl/cert.pem"),
            "script should detect Alpine CA bundle"
        );

        // Detects RHEL/Fedora CA bundle
        assert!(
            script.contains("/etc/pki/tls/certs/ca-bundle.crt"),
            "script should detect RHEL CA bundle"
        );

        // Creates augmented bundle at known path
        assert!(
            script.contains("/tmp/strait-ca-bundle.pem"),
            "script should write augmented bundle"
        );

        // Falls back when no system bundle exists (cp instead of cat)
        assert!(
            script.contains("cp /strait/ca.pem"),
            "script should fallback to copying CA PEM when no system bundle"
        );

        // Ends with exec to run original command
        assert!(
            script.contains("exec \"$@\""),
            "script should exec original command"
        );
    }

    #[test]
    fn build_config_with_ca_adds_bind_mount() {
        let policy = policy_with(vec![]);
        let ca_path = std::path::Path::new("/tmp/test-ca.pem");
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, Some(ca_path));

        assert!(
            config
                .binds
                .contains(&"/tmp/test-ca.pem:/strait/ca.pem:ro".to_string()),
            "should bind-mount CA PEM: {:?}",
            config.binds
        );
    }

    #[test]
    fn build_config_with_ca_sets_trust_env_vars() {
        let policy = policy_with(vec![]);
        let ca_path = std::path::Path::new("/tmp/test-ca.pem");
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, Some(ca_path));

        assert!(
            config
                .env
                .contains(&"SSL_CERT_FILE=/tmp/strait-ca-bundle.pem".to_string()),
            "should set SSL_CERT_FILE: {:?}",
            config.env
        );
        assert!(
            config
                .env
                .contains(&"NODE_EXTRA_CA_CERTS=/tmp/strait-ca-bundle.pem".to_string()),
            "should set NODE_EXTRA_CA_CERTS: {:?}",
            config.env
        );
        assert!(
            config
                .env
                .contains(&"REQUESTS_CA_BUNDLE=/tmp/strait-ca-bundle.pem".to_string()),
            "should set REQUESTS_CA_BUNDLE: {:?}",
            config.env
        );
    }

    #[test]
    fn build_config_with_ca_sets_entrypoint() {
        let policy = policy_with(vec![]);
        let ca_path = std::path::Path::new("/tmp/test-ca.pem");
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, Some(ca_path));

        let ep = config.entrypoint.as_ref().expect("should have entrypoint");
        assert_eq!(ep[0], "/bin/sh");
        assert_eq!(ep[1], "-c");
        assert!(
            ep[2].contains("exec \"$@\""),
            "entrypoint script should exec original command"
        );
        assert_eq!(ep[3], "--", "entrypoint should end with -- separator");
    }

    #[test]
    fn build_config_without_ca_has_no_entrypoint() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert!(
            config.entrypoint.is_none(),
            "should not have entrypoint without CA"
        );
    }

    #[test]
    fn build_config_without_ca_has_no_trust_env_vars() {
        let policy = policy_with(vec![]);
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, None);

        assert!(
            !config.env.iter().any(|e| e.starts_with("SSL_CERT_FILE=")),
            "should not have SSL_CERT_FILE without CA"
        );
        assert!(
            !config
                .env
                .iter()
                .any(|e| e.starts_with("NODE_EXTRA_CA_CERTS=")),
            "should not have NODE_EXTRA_CA_CERTS without CA"
        );
        assert!(
            !config
                .env
                .iter()
                .any(|e| e.starts_with("REQUESTS_CA_BUNDLE=")),
            "should not have REQUESTS_CA_BUNDLE without CA"
        );
    }

    #[test]
    fn build_config_with_ca_and_policy_combines_binds() {
        let policy = policy_with(vec![
            ContainerPermission::FsRead("/project/src".to_string()),
            ContainerPermission::FsWrite("/project/out".to_string()),
        ]);
        let ca_path = std::path::Path::new("/tmp/test-ca.pem");
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, Some(ca_path));

        // Should have policy binds + CA bind
        assert_eq!(
            config.binds.len(),
            3,
            "should have 2 policy binds + 1 CA bind: {:?}",
            config.binds
        );
        assert!(config
            .binds
            .contains(&"/project/src:/project/src:ro".to_string()));
        assert!(config
            .binds
            .contains(&"/project/out:/project/out:rw".to_string()));
        assert!(config
            .binds
            .contains(&"/tmp/test-ca.pem:/strait/ca.pem:ro".to_string()));
    }

    #[test]
    fn build_config_with_ca_preserves_proxy_env() {
        let policy = policy_with(vec![]);
        let ca_path = std::path::Path::new("/tmp/test-ca.pem");
        let config = ContainerManager::build_config(&policy, "node:20", &[], 8080, Some(ca_path));

        assert!(
            config
                .env
                .contains(&"HTTPS_PROXY=http://host.docker.internal:8080".to_string()),
            "HTTPS_PROXY should still be set with CA injection: {:?}",
            config.env
        );
    }
}
