//! Entrypoint privilege-drop flow for `strait-agent entrypoint`.
//!
//! Invoked as PID 1 (or equivalent) inside the container with root
//! privileges and `CAP_NET_ADMIN`. The flow:
//!
//! 1. Verify we are root and that `CAP_NET_ADMIN` is effective.
//! 2. Resolve the configured agent user (uid, gid, supplementary groups).
//!    This happens before any iptables work so a bad `agent_user` fails
//!    fast and leaves the container's network untouched.
//! 3. Spawn the in-container proxy as a child process. The proxy continues
//!    to run as root after the entrypoint `exec`s the agent command.
//! 4. Install the `iptables` OUTPUT REDIRECT rules (see [`super::iptables`]).
//! 5. Drop privileges: `setgid` + `initgroups` + `setuid` to the agent
//!    user. Clear ambient and inheritable capabilities so the exec'd child
//!    cannot recover `CAP_NET_ADMIN`.
//! 6. `exec` the user-supplied command, replacing this process image.
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
    use std::os::unix::ffi::OsStrExt;
    use std::path::{Path, PathBuf};
    use std::process::{Child, Command, Stdio};

    use anyhow::{anyhow, bail, Context as _, Result};
    use caps::{CapSet, Capability};
    use nix::unistd::{execvp, initgroups, setgid, setuid, Gid, Uid, User};
    use tracing::{info, warn};

    use crate::config::AgentConfig;
    use crate::iptables;

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

        let proxy_exe = resolve_self_exe()?;
        let proxy_child = spawn_proxy(&proxy_exe, config)?;
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

    fn spawn_proxy(proxy_exe: &Path, config: &AgentConfig) -> Result<Child> {
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

        cmd.spawn()
            .with_context(|| format!("failed to spawn proxy subprocess ({})", proxy_exe.display()))
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
