//! Entrypoint privilege-drop flow for `strait-agent entrypoint`.
//!
//! Invoked as PID 1 (or equivalent) inside the container with root
//! privileges and `CAP_NET_ADMIN`. The flow:
//!
//! 1. Verify we are root and that `CAP_NET_ADMIN` is effective.
//! 2. Resolve the configured agent user (uid, gid, supplementary groups).
//!    This happens before any iptables work so a bad `agent_user` fails
//!    fast and leaves the container's network untouched.
//! 3. Generate the session-local CA and write the cert + key to a known
//!    path the proxy will read (H-ICDP-3).
//! 4. Spawn the in-container proxy as a child process. The proxy continues
//!    to run as root after the entrypoint `exec`s the agent command.
//! 5. Install the `iptables` OUTPUT REDIRECT rules (see [`super::iptables`]).
//! 6. Install the session CA into the container's system trust store plus
//!    the language-specific env vars (`NODE_EXTRA_CA_CERTS`,
//!    `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`). See [`super::ca_trust`].
//!    The env vars are exported on the current process so `execvp`
//!    inherits them into the agent command.
//! 7. Drop privileges: `setgid` + `initgroups` + `setuid` to the agent
//!    user. Clear ambient and inheritable capabilities so the exec'd child
//!    cannot recover `CAP_NET_ADMIN`.
//! 8. `exec` the user-supplied command, replacing this process image.
//!
//! The full flow is Linux-only. On other platforms `run` short-circuits
//! with an error (the agent binary only ships inside Linux containers),
//! but the function signature stays cross-platform so the CLI wiring in
//! `main.rs` doesn't need a cfg gate.

use anyhow::Result;

use crate::config::AgentConfig;

/// Run the entrypoint flow.
///
/// On Linux this performs capability checks, spawns the proxy, installs
/// iptables rules, drops privileges, and `exec`s `command`. On success the
/// `exec` replaces the current process, so this function never returns
/// `Ok(())` in the happy path; any return value means something went
/// wrong before `exec`.
///
/// On non-Linux targets this returns an error immediately.
pub fn run(config: &AgentConfig, command: &[String]) -> Result<()> {
    linux::run(config, command)
}

#[cfg(target_os = "linux")]
mod linux {
    use std::ffi::{CString, OsString};
    use std::fs;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    use anyhow::{anyhow, bail, Context as _, Result};
    use caps::{CapSet, Capability};
    use nix::unistd::{execvp, initgroups, setgid, setuid, Gid, Uid, User};
    use tracing::{info, warn};

    use crate::ca::SessionCa;
    use crate::ca_trust;
    use crate::config::AgentConfig;
    use crate::iptables;

    /// Path the entrypoint writes the session CA cert PEM to.
    ///
    /// Must match the path the proxy loads at startup (H-ICDP-3). World
    /// readable: the agent user needs to verify server certs signed by
    /// this CA, and it is public-key material.
    pub(crate) const CA_CERT_OUT: &str = "/run/strait/ca.pem";
    /// Path the entrypoint writes the session CA private key to.
    ///
    /// Root-readable only: this is what the proxy uses to sign leaf
    /// certs. Leaking it to the agent user would let the agent forge
    /// TLS server certs for arbitrary hosts.
    pub(crate) const CA_KEY_OUT: &str = "/run/strait/ca.key";
    /// Directory that holds the two files above. Created 0755 so the
    /// agent user can read the cert but not list the key.
    const CA_DIR: &str = "/run/strait";

    pub fn run(config: &AgentConfig, command: &[String]) -> Result<()> {
        if command.is_empty() {
            bail!(
                "entrypoint requires a child command (use `--` to separate it from strait-agent flags)"
            );
        }

        ensure_root()?;
        ensure_cap_net_admin()?;

        let agent_user_name = config.agent_user.as_deref().ok_or_else(|| {
            anyhow!("config.agent_user is required for entrypoint privilege drop")
        })?;
        let agent = resolve_user(agent_user_name)?;
        info!(
            user = %agent_user_name,
            uid = agent.uid.as_raw(),
            gid = agent.gid.as_raw(),
            "resolved agent user"
        );

        // Generate the session CA *before* spawning the proxy so the PEM
        // + key are on disk by the time the proxy opens them. Doing this
        // before iptables also means a CA generation failure leaves the
        // container's network untouched.
        let ca = SessionCa::generate().context("generate session CA")?;
        let ca_cert_path = write_ca_material(&ca).context("persist session CA material")?;
        info!(
            cert_path = %ca_cert_path.display(),
            "generated session CA and wrote cert+key to /run/strait"
        );

        let proxy_exe = resolve_self_exe()?;
        let proxy_child = spawn_proxy(&proxy_exe, config, &ca_cert_path)?;
        info!(
            pid = proxy_child.id(),
            port = config.proxy_port,
            "spawned proxy subprocess"
        );
        // The proxy child is intentionally leaked: we want it to keep
        // running after the entrypoint `exec`s away. Dropping a `Child`
        // does not kill the process on Unix, but mem::forget makes intent
        // explicit in case that ever changes.
        std::mem::forget(proxy_child);

        iptables::install_redirect_rules(
            agent.uid.as_raw(),
            &config.redirect_ports,
            config.proxy_port,
        )
        .context("failed to install iptables redirect rules")?;
        info!(
            redirect_ports = ?config.redirect_ports,
            proxy_port = config.proxy_port,
            agent_uid = agent.uid.as_raw(),
            "installed iptables OUTPUT REDIRECT rules"
        );

        // Install the CA *after* iptables so a trust-store failure
        // doesn't leave the container with half a network boundary: the
        // iptables rules on their own still force traffic through the
        // proxy, they just produce cert errors in user-visible tools.
        let trust = ca_trust::install(&ca.cert_pem)
            .context("install session CA into container trust store")?;
        export_trust_env(&trust);
        info!(
            ca_pem_path = %trust.ca_pem_path.display(),
            env_vars = ?ca_trust::LANGUAGE_ENV_NAMES,
            "installed session CA trust and exported env vars for child"
        );

        drop_privileges(&agent)?;
        info!(
            uid = agent.uid.as_raw(),
            gid = agent.gid.as_raw(),
            "dropped privileges; exec'ing agent command"
        );

        exec_command(command)
    }

    struct ResolvedUser {
        name: String,
        uid: Uid,
        gid: Gid,
    }

    fn ensure_root() -> Result<()> {
        let euid = nix::unistd::geteuid();
        if !euid.is_root() {
            bail!(
                "strait-agent entrypoint must start as root (effective uid {} is not 0)",
                euid.as_raw()
            );
        }
        Ok(())
    }

    fn ensure_cap_net_admin() -> Result<()> {
        let effective = caps::read(None, CapSet::Effective)
            .context("failed to read effective capability set from /proc/self")?;
        if !effective.contains(&Capability::CAP_NET_ADMIN) {
            bail!(
                "CAP_NET_ADMIN is not in the effective capability set. \
                 Run the container with `--cap-add=NET_ADMIN`."
            );
        }
        Ok(())
    }

    fn resolve_user(name: &str) -> Result<ResolvedUser> {
        let user = User::from_name(name)
            .with_context(|| format!("failed to look up user {name:?}"))?
            .ok_or_else(|| {
                anyhow!("configured agent_user {name:?} does not exist on this system")
            })?;
        if user.uid.is_root() {
            bail!(
                "agent_user {name:?} resolves to uid 0; refusing to exec the agent command as root"
            );
        }
        Ok(ResolvedUser {
            name: user.name,
            uid: user.uid,
            gid: user.gid,
        })
    }

    fn resolve_self_exe() -> Result<PathBuf> {
        std::env::current_exe()
            .context("failed to resolve strait-agent binary path via current_exe")
    }

    fn spawn_proxy(proxy_exe: &Path, config: &AgentConfig, ca_cert_path: &Path) -> Result<Child> {
        let mut cmd = Command::new(proxy_exe);
        cmd.arg("proxy")
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        // Forward proxy-relevant config via env. The proxy reads the same
        // STRAIT_AGENT_* overrides as the entrypoint, so this guarantees
        // both halves agree on port + socket path regardless of how the
        // entrypoint was originally configured.
        cmd.env("STRAIT_AGENT_PROXY_PORT", config.proxy_port.to_string());
        cmd.env("STRAIT_AGENT_HOST_SOCKET", &config.host_socket);
        // The proxy loads the CA cert+key at startup (H-ICDP-3). We pin
        // the cert path via env so both halves stay in sync even if the
        // default path changes in a later revision.
        cmd.env("STRAIT_AGENT_CA_CERT_PATH", ca_cert_path);
        cmd.env(
            "STRAIT_AGENT_CA_KEY_PATH",
            Path::new(CA_KEY_OUT).as_os_str(),
        );

        cmd.spawn()
            .with_context(|| format!("failed to spawn proxy subprocess ({})", proxy_exe.display()))
    }

    /// Write the session CA cert and private key to `/run/strait`.
    ///
    /// - `/run/strait` is created as 0755 so the agent user can read the
    ///   cert file but cannot `ls` to discover the key name.
    /// - Cert file is 0644 -- public-key material, fine for the agent
    ///   user to read.
    /// - Key file is 0600 -- root-only, so a compromised agent process
    ///   cannot mint TLS server certs.
    fn write_ca_material(ca: &SessionCa) -> Result<PathBuf> {
        let dir = Path::new(CA_DIR);
        fs::create_dir_all(dir)
            .with_context(|| format!("create session CA directory {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("set permissions on {}", dir.display()))?;

        let cert = PathBuf::from(CA_CERT_OUT);
        fs::write(&cert, &ca.cert_pem)
            .with_context(|| format!("write CA cert PEM to {}", cert.display()))?;
        fs::set_permissions(&cert, fs::Permissions::from_mode(0o644))
            .with_context(|| format!("set permissions on {}", cert.display()))?;

        let key = PathBuf::from(CA_KEY_OUT);
        {
            let mut f = std::fs::OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(&key)
                .with_context(|| format!("open CA key file {}", key.display()))?;
            std::io::Write::write_all(&mut f, ca.key_pem.as_bytes())
                .with_context(|| format!("write CA key PEM to {}", key.display()))?;
        }
        // Defensive: even if the file pre-existed with loose perms, force
        // them back to 0600 now.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600))
            .with_context(|| format!("set permissions on {}", key.display()))?;

        Ok(cert)
    }

    /// Export the CA trust env vars on the current process so `execvp`
    /// inherits them into the agent command.
    ///
    /// This is the only `set_var` hop in the entrypoint -- all other
    /// config flows through spawn env, which is local to the child.
    fn export_trust_env(trust: &ca_trust::InstalledTrust) {
        for (key, value) in &trust.env {
            // SAFETY: std::env::set_var is !Send in some targets; this
            // runs before any threads are spawned (entrypoint is single-
            // threaded through here), so mutation is safe.
            std::env::set_var(key, value);
        }
    }

    fn drop_privileges(agent: &ResolvedUser) -> Result<()> {
        // Order matters: set primary gid first, then supplementary groups
        // (which requires root), finally setuid. After setuid there is no
        // way back to root.
        setgid(agent.gid).context("setgid failed")?;

        let name_c = CString::new(agent.name.as_bytes())
            .with_context(|| format!("agent user name {:?} contains a NUL byte", agent.name))?;
        initgroups(&name_c, agent.gid).context("initgroups failed")?;

        // Drop Ambient and Inheritable capability sets before setuid so
        // that even if the agent command is a file-capability binary, it
        // cannot regain CAP_NET_ADMIN. The bounding set is cleared on
        // setuid from root -> non-root automatically.
        if let Err(err) = caps::clear(None, CapSet::Ambient) {
            warn!(error = %err, "failed to clear ambient capability set (continuing)");
        }
        if let Err(err) = caps::clear(None, CapSet::Inheritable) {
            warn!(error = %err, "failed to clear inheritable capability set (continuing)");
        }

        setuid(agent.uid).context("setuid failed")?;

        // Paranoia check: on setuid root -> non-root the kernel clears
        // the effective set. Asserting it here turns that invariant into
        // a test-visible property.
        let effective = caps::read(None, CapSet::Effective)
            .context("failed to re-read effective capability set after setuid")?;
        if effective.contains(&Capability::CAP_NET_ADMIN) {
            bail!("CAP_NET_ADMIN is still effective after privilege drop; aborting");
        }
        Ok(())
    }

    fn exec_command(command: &[String]) -> Result<()> {
        let program = CString::new(OsString::from(&command[0]).as_bytes())
            .with_context(|| format!("command {:?} contains a NUL byte", command[0]))?;
        let argv: Vec<CString> = command
            .iter()
            .map(|a| {
                CString::new(OsString::from(a).as_bytes())
                    .with_context(|| format!("argv entry {a:?} contains a NUL byte"))
            })
            .collect::<Result<_>>()?;

        // execvp returns only on error.
        let err = execvp(&program, &argv).unwrap_err();
        Err(anyhow!("execvp({command:?}) failed: {err}"))
    }
}

#[cfg(not(target_os = "linux"))]
mod linux {
    use anyhow::{bail, Result};

    use crate::config::AgentConfig;

    pub fn run(_config: &AgentConfig, _command: &[String]) -> Result<()> {
        bail!(
            "`strait-agent entrypoint` is Linux-only. \
             The agent binary is meant to run inside a Linux container."
        )
    }
}
