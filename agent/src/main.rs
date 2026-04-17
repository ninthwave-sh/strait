//! `strait-agent` -- in-container agent binary for strait.
//!
//! Two subcommands in one binary:
//!
//! - `entrypoint` -- runs as container PID 1 or equivalent. Will (in
//!   H-ICDP-2) verify `CAP_NET_ADMIN`, install iptables OUTPUT REDIRECT
//!   rules for the configured ports to the proxy port, then drop
//!   privileges to the configured agent user and exec the agent command.
//! - `proxy` -- MITM proxy. Will (in H-ICDP-3) host the pipeline moved
//!   out of the top-level crate's `src/mitm.rs`, using `SO_ORIGINAL_DST`
//!   to recover the intended destination after the REDIRECT.
//!
//! This skeleton only wires up clap, loads the startup config, prints
//! a stub message, and exits successfully. No iptables work, no socket
//! listening, no privilege drop.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use strait_agent::config::AgentConfig;

#[derive(Parser)]
#[command(
    name = "strait-agent",
    version,
    about = "In-container agent for strait: entrypoint wrapper and MITM proxy"
)]
struct Cli {
    /// Path to a `strait-agent.toml` file.
    ///
    /// Optional. When set, the file is parsed and overlaid on top of
    /// built-in defaults; environment variables (`STRAIT_AGENT_*`) win
    /// over both. When unset, defaults + env vars are used.
    #[arg(long, global = true, value_name = "PATH")]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Container entrypoint: install iptables rules, drop privileges, exec
    /// the agent command.
    ///
    /// Not implemented in this skeleton (H-ICDP-2). Currently prints the
    /// parsed config and exits.
    Entrypoint {
        /// Command (and args) to exec after privilege drop.
        ///
        /// Collected verbatim -- use `--` to separate the command from
        /// `strait-agent` flags (for example
        /// `strait-agent entrypoint -- claude-code "$@"`).
        #[arg(trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<String>,
    },
    /// In-container MITM proxy.
    ///
    /// Not implemented in this skeleton (H-ICDP-3). Currently prints the
    /// parsed config and exits.
    Proxy,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    // Basic tracing setup; the full pipeline is wired up in later items.
    let _ = tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_target(false)
        .try_init();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("strait-agent: {err:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> anyhow::Result<()> {
    let config = AgentConfig::load_optional(cli.config.as_deref())?;

    match cli.command {
        Commands::Entrypoint { command } => {
            println!("strait-agent: mode=entrypoint (skeleton; H-ICDP-2 fills this in)");
            println!("  proxy_port       = {}", config.proxy_port);
            println!(
                "  agent_user       = {}",
                config.agent_user.as_deref().unwrap_or("<unset>")
            );
            println!("  redirect_ports   = {:?}", config.redirect_ports);
            println!("  host_socket      = {}", config.host_socket.display());
            if command.is_empty() {
                println!("  child command    = <none>");
            } else {
                println!("  child command    = {command:?}");
            }
        }
        Commands::Proxy => {
            println!("strait-agent: mode=proxy (skeleton; H-ICDP-3 fills this in)");
            println!("  proxy_port       = {}", config.proxy_port);
            println!("  host_socket      = {}", config.host_socket.display());
        }
    }
    Ok(())
}
