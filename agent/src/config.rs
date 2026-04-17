//! Startup configuration for `strait-agent`.
//!
//! This is the in-container agent's own minimal config loader. It is
//! intentionally independent from the host-side `strait.toml` parser in
//! `src/config.rs` -- the agent has a different config surface (proxy port,
//! agent user for privilege drop, iptables redirect ports, host control-plane
//! socket path) and must stay small so the in-container binary does not pick
//! up host-only dependencies.
//!
//! Loading order:
//!
//! 1. Start from built-in defaults (safe for "run inside a bare container
//!    with no config file").
//! 2. If a `strait-agent.toml` path is provided and exists, parse it and
//!    overlay its fields.
//! 3. Apply environment-variable overrides (prefix `STRAIT_AGENT_`).
//!
//! Env vars always win so operators can tune a baked image without
//! rewriting the config file.

use std::path::{Path, PathBuf};

use anyhow::{anyhow, Context as _};
use serde::Deserialize;

/// Default TCP port the in-container MITM proxy listens on.
///
/// Chosen outside the common web-server range so colocated development
/// servers don't clash with it. iptables REDIRECT rewrites 80/443 traffic
/// to this port regardless.
pub const DEFAULT_PROXY_PORT: u16 = 9443;

/// Default ports that the entrypoint should REDIRECT to the proxy.
pub const DEFAULT_REDIRECT_PORTS: &[u16] = &[80, 443];

/// Default Unix socket path for the host control plane.
pub const DEFAULT_HOST_SOCKET: &str = "/run/strait/host.sock";

/// Resolved, validated agent configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    /// TCP port the in-container MITM proxy listens on.
    pub proxy_port: u16,
    /// Unix user the entrypoint drops privileges to before exec'ing the
    /// agent command. `None` means "stay as the current user" -- useful
    /// for tests and not intended for production.
    pub agent_user: Option<String>,
    /// Ports the entrypoint should REDIRECT via iptables to the proxy port.
    pub redirect_ports: Vec<u16>,
    /// Path to the host control plane's Unix socket, mounted into the
    /// container.
    pub host_socket: PathBuf,
}

impl Default for AgentConfig {
    fn default() -> Self {
        Self {
            proxy_port: DEFAULT_PROXY_PORT,
            agent_user: None,
            redirect_ports: DEFAULT_REDIRECT_PORTS.to_vec(),
            host_socket: PathBuf::from(DEFAULT_HOST_SOCKET),
        }
    }
}

impl AgentConfig {
    /// Load configuration from an optional TOML file, then overlay
    /// environment-variable overrides.
    ///
    /// If `path` is `Some` and the file exists, the file is parsed on top
    /// of defaults. If `path` is `Some` but the file is missing, that is an
    /// error (the caller asked for a specific file and it wasn't there). If
    /// `path` is `None`, defaults are used as the starting point.
    pub fn load(path: Option<&Path>) -> anyhow::Result<Self> {
        let file = match path {
            Some(p) => Some(RawAgentConfig::from_path(p)?),
            None => None,
        };
        Self::from_parts(file, EnvSource::Process)
    }

    /// Load configuration treating a missing file the same as "no file" --
    /// useful for boot paths where the file is optional.
    pub fn load_optional(path: Option<&Path>) -> anyhow::Result<Self> {
        let file = match path {
            Some(p) if p.exists() => Some(RawAgentConfig::from_path(p)?),
            _ => None,
        };
        Self::from_parts(file, EnvSource::Process)
    }

    /// Testable core: take an already-parsed file (if any) and an env
    /// source, and produce a resolved config. Pulled out so unit tests can
    /// inject a fake environment instead of mutating the process env.
    fn from_parts(file: Option<RawAgentConfig>, env: EnvSource) -> anyhow::Result<Self> {
        let mut cfg = AgentConfig::default();

        if let Some(raw) = file {
            if let Some(proxy) = raw.proxy {
                if let Some(port) = proxy.port {
                    cfg.proxy_port = port;
                }
            }
            if let Some(entrypoint) = raw.entrypoint {
                if let Some(user) = entrypoint.agent_user {
                    cfg.agent_user = if user.is_empty() { None } else { Some(user) };
                }
                if let Some(ports) = entrypoint.redirect_ports {
                    cfg.redirect_ports = ports;
                }
            }
            if let Some(host) = raw.host {
                if let Some(sock) = host.socket_path {
                    cfg.host_socket = sock;
                }
            }
        }

        apply_env_overrides(&mut cfg, &env)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.proxy_port == 0 {
            anyhow::bail!("proxy.port must be non-zero");
        }
        if self.redirect_ports.is_empty() {
            anyhow::bail!("entrypoint.redirect_ports must not be empty");
        }
        for p in &self.redirect_ports {
            if *p == 0 {
                anyhow::bail!("entrypoint.redirect_ports entries must be non-zero");
            }
        }
        if self.host_socket.as_os_str().is_empty() {
            anyhow::bail!("host.socket_path must not be empty");
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Raw TOML shape
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct RawAgentConfig {
    proxy: Option<RawProxy>,
    entrypoint: Option<RawEntrypoint>,
    host: Option<RawHost>,
}

impl RawAgentConfig {
    fn from_path(path: &Path) -> anyhow::Result<Self> {
        let bytes = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read agent config at {}", path.display()))?;
        let raw: RawAgentConfig = toml::from_str(&bytes)
            .with_context(|| format!("failed to parse agent config at {}", path.display()))?;
        Ok(raw)
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProxy {
    port: Option<u16>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawEntrypoint {
    agent_user: Option<String>,
    redirect_ports: Option<Vec<u16>>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawHost {
    socket_path: Option<PathBuf>,
}

// ---------------------------------------------------------------------------
// Env overrides
// ---------------------------------------------------------------------------

/// Environment source indirection so tests can inject a fake env map
/// without touching the process-wide environment.
enum EnvSource {
    Process,
    #[cfg(test)]
    Map(std::collections::HashMap<String, String>),
}

impl EnvSource {
    fn get(&self, key: &str) -> Option<String> {
        match self {
            EnvSource::Process => std::env::var(key).ok(),
            #[cfg(test)]
            EnvSource::Map(m) => m.get(key).cloned(),
        }
    }
}

fn apply_env_overrides(cfg: &mut AgentConfig, env: &EnvSource) -> anyhow::Result<()> {
    if let Some(v) = env.get("STRAIT_AGENT_PROXY_PORT") {
        cfg.proxy_port = v
            .parse::<u16>()
            .map_err(|e| anyhow!("STRAIT_AGENT_PROXY_PORT: {e}"))?;
    }
    if let Some(v) = env.get("STRAIT_AGENT_AGENT_USER") {
        cfg.agent_user = if v.is_empty() { None } else { Some(v) };
    }
    if let Some(v) = env.get("STRAIT_AGENT_REDIRECT_PORTS") {
        let ports: Result<Vec<u16>, _> = v
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(str::parse::<u16>)
            .collect();
        cfg.redirect_ports = ports.map_err(|e| anyhow!("STRAIT_AGENT_REDIRECT_PORTS: {e}"))?;
    }
    if let Some(v) = env.get("STRAIT_AGENT_HOST_SOCKET") {
        cfg.host_socket = PathBuf::from(v);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn empty_env() -> EnvSource {
        EnvSource::Map(HashMap::new())
    }

    fn env(pairs: &[(&str, &str)]) -> EnvSource {
        EnvSource::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        )
    }

    #[test]
    fn defaults_produce_a_valid_config() {
        let cfg = AgentConfig::from_parts(None, empty_env()).unwrap();
        assert_eq!(cfg.proxy_port, DEFAULT_PROXY_PORT);
        assert_eq!(cfg.agent_user, None);
        assert_eq!(cfg.redirect_ports, vec![80, 443]);
        assert_eq!(cfg.host_socket, PathBuf::from(DEFAULT_HOST_SOCKET));
    }

    #[test]
    fn minimal_toml_overrides_defaults() {
        let toml_str = r#"
[proxy]
port = 18080

[entrypoint]
agent_user = "agent"
redirect_ports = [80, 443, 8080]

[host]
socket_path = "/tmp/strait-host.sock"
"#;
        let raw: RawAgentConfig = toml::from_str(toml_str).unwrap();
        let cfg = AgentConfig::from_parts(Some(raw), empty_env()).unwrap();
        assert_eq!(cfg.proxy_port, 18080);
        assert_eq!(cfg.agent_user.as_deref(), Some("agent"));
        assert_eq!(cfg.redirect_ports, vec![80, 443, 8080]);
        assert_eq!(cfg.host_socket, PathBuf::from("/tmp/strait-host.sock"));
    }

    #[test]
    fn empty_toml_sections_preserve_defaults() {
        // All sections optional; an empty file should behave like no file.
        let raw: RawAgentConfig = toml::from_str("").unwrap();
        let cfg = AgentConfig::from_parts(Some(raw), empty_env()).unwrap();
        assert_eq!(cfg, AgentConfig::default());
    }

    #[test]
    fn env_overrides_win_over_file() {
        let toml_str = r#"
[proxy]
port = 18080

[entrypoint]
agent_user = "agent"
redirect_ports = [80, 443]
"#;
        let raw: RawAgentConfig = toml::from_str(toml_str).unwrap();
        let cfg = AgentConfig::from_parts(
            Some(raw),
            env(&[
                ("STRAIT_AGENT_PROXY_PORT", "19000"),
                ("STRAIT_AGENT_AGENT_USER", "root"),
                ("STRAIT_AGENT_REDIRECT_PORTS", "80,443,8443"),
                ("STRAIT_AGENT_HOST_SOCKET", "/var/run/strait/host.sock"),
            ]),
        )
        .unwrap();
        assert_eq!(cfg.proxy_port, 19000);
        assert_eq!(cfg.agent_user.as_deref(), Some("root"));
        assert_eq!(cfg.redirect_ports, vec![80, 443, 8443]);
        assert_eq!(cfg.host_socket, PathBuf::from("/var/run/strait/host.sock"));
    }

    #[test]
    fn empty_agent_user_env_clears_the_field() {
        let raw: RawAgentConfig = toml::from_str(
            r#"
[entrypoint]
agent_user = "agent"
"#,
        )
        .unwrap();
        let cfg =
            AgentConfig::from_parts(Some(raw), env(&[("STRAIT_AGENT_AGENT_USER", "")])).unwrap();
        assert_eq!(cfg.agent_user, None);
    }

    #[test]
    fn invalid_port_env_is_rejected() {
        let err =
            AgentConfig::from_parts(None, env(&[("STRAIT_AGENT_PROXY_PORT", "not-a-number")]))
                .unwrap_err();
        assert!(err.to_string().contains("STRAIT_AGENT_PROXY_PORT"));
    }

    #[test]
    fn empty_redirect_ports_is_rejected() {
        let raw: RawAgentConfig = toml::from_str(
            r#"
[entrypoint]
redirect_ports = []
"#,
        )
        .unwrap();
        let err = AgentConfig::from_parts(Some(raw), empty_env()).unwrap_err();
        assert!(err.to_string().contains("redirect_ports"));
    }

    #[test]
    fn zero_proxy_port_is_rejected() {
        let err =
            AgentConfig::from_parts(None, env(&[("STRAIT_AGENT_PROXY_PORT", "0")])).unwrap_err();
        assert!(err.to_string().contains("proxy.port"));
    }

    #[test]
    fn unknown_fields_in_toml_are_rejected() {
        let err: Result<RawAgentConfig, _> = toml::from_str(
            r#"
[proxy]
port = 18080
unexpected = true
"#,
        );
        assert!(err.is_err(), "unknown field should fail to parse");
    }

    #[test]
    fn load_from_file_round_trips() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("strait-agent.toml");
        std::fs::write(
            &path,
            r#"
[proxy]
port = 12345

[entrypoint]
agent_user = "ci"
redirect_ports = [80, 443]

[host]
socket_path = "/tmp/host.sock"
"#,
        )
        .unwrap();
        let raw = RawAgentConfig::from_path(&path).unwrap();
        let cfg = AgentConfig::from_parts(Some(raw), empty_env()).unwrap();
        assert_eq!(cfg.proxy_port, 12345);
        assert_eq!(cfg.agent_user.as_deref(), Some("ci"));
    }

    #[test]
    fn load_optional_handles_missing_file() {
        // A path that does not exist should produce defaults, not an error.
        let path = Path::new("/definitely/not/a/real/path/strait-agent.toml");
        let cfg = AgentConfig::load_optional(Some(path)).unwrap();
        assert_eq!(cfg, AgentConfig::default());
    }

    #[test]
    fn comma_separated_redirect_ports_env_accepts_spaces() {
        let cfg = AgentConfig::from_parts(
            None,
            env(&[("STRAIT_AGENT_REDIRECT_PORTS", " 80 , 443 , 8443 ")]),
        )
        .unwrap();
        assert_eq!(cfg.redirect_ports, vec![80, 443, 8443]);
    }
}
