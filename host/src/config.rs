//! Host control plane configuration.
//!
//! Defaults cover a typical single-user host install; every field can be
//! overridden in `~/.config/strait/host.toml`. The loader merges defaults
//! with the TOML file: missing fields in the file fall back to defaults,
//! and a missing file is not an error (the host starts on defaults).

use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::Deserialize;

/// Default Unix socket path for container-side connections.
pub const DEFAULT_UNIX_SOCKET: &str = "/var/run/strait/host.sock";

/// Default TCP listener for the desktop app (loopback only).
pub const DEFAULT_TCP_LISTEN: &str = "127.0.0.1:3129";

/// Default permission bits for the Unix socket.
///
/// `0600` keeps the socket private to the user that owns the host process.
/// Containers running as that user on the same host can connect; nothing
/// else on the box can.
pub const DEFAULT_SOCKET_MODE: u32 = 0o600;

/// Resolved host configuration with defaults filled in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostConfig {
    /// Filesystem path of the Unix domain socket.
    pub unix_socket: PathBuf,
    /// TCP listener address.
    pub tcp_listen: SocketAddr,
    /// Permission bits for the Unix socket file.
    pub socket_mode: u32,
}

impl HostConfig {
    /// Returns the built-in defaults with no file on disk.
    pub fn defaults() -> Self {
        Self {
            unix_socket: PathBuf::from(DEFAULT_UNIX_SOCKET),
            tcp_listen: DEFAULT_TCP_LISTEN
                .parse()
                .expect("DEFAULT_TCP_LISTEN must be a valid SocketAddr"),
            socket_mode: DEFAULT_SOCKET_MODE,
        }
    }

    /// Load configuration, merging any values found in `path` on top of the
    /// built-in defaults. Returns the defaults unchanged if `path` does not
    /// exist. Any parse or type error is surfaced to the caller.
    pub fn load(path: &Path) -> Result<Self> {
        let mut cfg = Self::defaults();
        if !path.exists() {
            return Ok(cfg);
        }
        let txt = std::fs::read_to_string(path)
            .with_context(|| format!("reading host config {}", path.display()))?;
        cfg.merge_toml(&txt)
            .with_context(|| format!("parsing host config {}", path.display()))?;
        Ok(cfg)
    }

    /// Merge a TOML document on top of `self`. Exposed for tests so they can
    /// exercise the merge logic without touching the filesystem.
    pub fn merge_toml(&mut self, toml_text: &str) -> Result<()> {
        let file: HostConfigFile = toml::from_str(toml_text)?;
        if let Some(path) = file.unix_socket {
            self.unix_socket = path;
        }
        if let Some(addr) = file.tcp_listen {
            self.tcp_listen = addr
                .parse()
                .with_context(|| format!("invalid tcp_listen {addr}"))?;
        }
        if let Some(mode) = file.socket_mode {
            self.socket_mode = mode;
        }
        Ok(())
    }
}

/// On-disk shape of `host.toml`. All fields optional so callers can leave
/// anything they do not care about at the default.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct HostConfigFile {
    unix_socket: Option<PathBuf>,
    tcp_listen: Option<String>,
    socket_mode: Option<u32>,
}

/// Return the default path for `host.toml`. On Unix this is
/// `$HOME/.config/strait/host.toml`. If `$HOME` is not set (unusual), falls
/// back to `./host.toml` in the current working directory so the binary
/// still has something to report in `--help` and error messages.
pub fn default_config_path() -> PathBuf {
    match std::env::var_os("HOME") {
        Some(home) => PathBuf::from(home).join(".config/strait/host.toml"),
        None => PathBuf::from("host.toml"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_documented_values() {
        let cfg = HostConfig::defaults();
        assert_eq!(cfg.unix_socket, PathBuf::from(DEFAULT_UNIX_SOCKET));
        assert_eq!(
            cfg.tcp_listen,
            DEFAULT_TCP_LISTEN.parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.socket_mode, DEFAULT_SOCKET_MODE);
    }

    #[test]
    fn minimal_toml_overrides_single_field() {
        let mut cfg = HostConfig::defaults();
        cfg.merge_toml(r#"unix_socket = "/tmp/strait/host.sock""#)
            .unwrap();
        assert_eq!(cfg.unix_socket, PathBuf::from("/tmp/strait/host.sock"));
        // tcp_listen and socket_mode should remain at defaults.
        assert_eq!(
            cfg.tcp_listen,
            DEFAULT_TCP_LISTEN.parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.socket_mode, DEFAULT_SOCKET_MODE);
    }

    #[test]
    fn full_toml_overrides_every_field() {
        let mut cfg = HostConfig::defaults();
        cfg.merge_toml(
            r#"
            unix_socket = "/tmp/strait/custom.sock"
            tcp_listen = "127.0.0.1:9999"
            socket_mode = 0o640
            "#,
        )
        .unwrap();
        assert_eq!(cfg.unix_socket, PathBuf::from("/tmp/strait/custom.sock"));
        assert_eq!(
            cfg.tcp_listen,
            "127.0.0.1:9999".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.socket_mode, 0o640);
    }

    #[test]
    fn missing_file_returns_defaults() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("does-not-exist.toml");
        let cfg = HostConfig::load(&path).unwrap();
        assert_eq!(cfg, HostConfig::defaults());
    }

    #[test]
    fn load_reads_file_on_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("host.toml");
        std::fs::write(&path, r#"tcp_listen = "127.0.0.1:4141""#).unwrap();
        let cfg = HostConfig::load(&path).unwrap();
        assert_eq!(
            cfg.tcp_listen,
            "127.0.0.1:4141".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(cfg.unix_socket, PathBuf::from(DEFAULT_UNIX_SOCKET));
    }

    #[test]
    fn unknown_field_is_rejected() {
        let mut cfg = HostConfig::defaults();
        let err = cfg
            .merge_toml(r#"bogus = "value""#)
            .expect_err("unknown field should error");
        let msg = format!("{err:#}");
        assert!(msg.contains("bogus"), "unexpected error: {msg}");
    }

    #[test]
    fn invalid_tcp_listen_is_rejected() {
        let mut cfg = HostConfig::defaults();
        let err = cfg
            .merge_toml(r#"tcp_listen = "not-an-address""#)
            .expect_err("invalid tcp_listen should error");
        let msg = format!("{err:#}");
        assert!(msg.contains("tcp_listen"), "unexpected error: {msg}");
    }
}
