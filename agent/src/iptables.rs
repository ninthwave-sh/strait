//! Thin wrapper around the `iptables` binary for the entrypoint flow.
//!
//! The entrypoint installs a small, well-defined set of rules in the `nat`
//! table that redirect outbound TCP traffic from the agent user to the
//! in-container proxy:
//!
//! ```text
//! # In the nat OUTPUT chain:
//! # 1. Loopback is never redirected. The proxy itself talks to 127.0.0.1.
//! -A OUTPUT -o lo -j RETURN
//! # 2. Only traffic originating from the agent user's UID is redirected.
//! #    Root-owned traffic (the proxy and this entrypoint) is untouched,
//! #    so the proxy's upstream connections cannot loop back into itself.
//! -A OUTPUT -p tcp -m owner --uid-owner <agent_uid> --dport <port>
//!     -j REDIRECT --to-ports <proxy_port>
//! ```
//!
//! This module only knows how to *install* rules. The entrypoint is a
//! one-shot tool: we shell out to `iptables` once, then drop privileges.
//! Rule teardown is the container's responsibility (containers die, their
//! network namespace goes with them).
//!
//! Everything is Linux-only. The agent binary exists to run inside a Linux
//! container; the wrapper is gated so `cargo test` still builds on macOS.

#![cfg(target_os = "linux")]

use std::ffi::OsStr;
use std::process::Command;

use anyhow::{anyhow, Context as _, Result};

/// Path to the iptables binary. Overridable for tests via the
/// `STRAIT_AGENT_IPTABLES_BIN` environment variable -- handy when running
/// against `iptables-legacy` or a wrapper script.
const DEFAULT_IPTABLES: &str = "iptables";

fn iptables_bin() -> String {
    std::env::var("STRAIT_AGENT_IPTABLES_BIN").unwrap_or_else(|_| DEFAULT_IPTABLES.to_string())
}

/// Install OUTPUT REDIRECT rules for the configured ports.
///
/// `agent_uid` is the numeric UID of the user the entrypoint will exec the
/// agent command as. Only traffic owned by that UID is redirected, which
/// leaves the proxy's own upstream connections (running as root) alone.
///
/// This function is not idempotent by design. It is meant to be called
/// exactly once per container, before the entrypoint drops privileges.
/// Calling it twice will install duplicate rules; that is a caller bug.
pub fn install_redirect_rules(
    agent_uid: u32,
    redirect_ports: &[u16],
    proxy_port: u16,
) -> Result<()> {
    if redirect_ports.is_empty() {
        return Err(anyhow!("install_redirect_rules: redirect_ports is empty"));
    }
    if proxy_port == 0 {
        return Err(anyhow!(
            "install_redirect_rules: proxy_port must be non-zero"
        ));
    }

    // Loopback first. The proxy binds 127.0.0.1:<proxy_port> and anything the
    // proxy sends over loopback (healthchecks, self-connects) must not be
    // redirected again.
    run_iptables(&["-t", "nat", "-A", "OUTPUT", "-o", "lo", "-j", "RETURN"])
        .context("install iptables loopback RETURN rule")?;

    let uid_str = agent_uid.to_string();
    let proxy_str = proxy_port.to_string();

    for port in redirect_ports {
        let port_str = port.to_string();
        run_iptables(&[
            "-t",
            "nat",
            "-A",
            "OUTPUT",
            "-p",
            "tcp",
            "-m",
            "owner",
            "--uid-owner",
            &uid_str,
            "--dport",
            &port_str,
            "-j",
            "REDIRECT",
            "--to-ports",
            &proxy_str,
        ])
        .with_context(|| format!("install REDIRECT rule for dport {port}"))?;
    }
    Ok(())
}

fn run_iptables<S: AsRef<OsStr>>(args: &[S]) -> Result<()> {
    let bin = iptables_bin();
    let output = Command::new(&bin)
        .args(args)
        .output()
        .with_context(|| format!("failed to spawn {bin}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let printable_args: Vec<String> = args
            .iter()
            .map(|a| a.as_ref().to_string_lossy().into_owned())
            .collect();
        return Err(anyhow!(
            "{bin} {args:?} failed (status {status}): stdout={stdout:?} stderr={stderr:?}",
            args = printable_args,
            status = output.status,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_port_list() {
        let err = install_redirect_rules(1000, &[], 9443).unwrap_err();
        assert!(
            err.to_string().contains("redirect_ports is empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_zero_proxy_port() {
        let err = install_redirect_rules(1000, &[80, 443], 0).unwrap_err();
        assert!(
            err.to_string().contains("proxy_port"),
            "unexpected error: {err}"
        );
    }
}
