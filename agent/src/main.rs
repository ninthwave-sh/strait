//! `strait-agent` -- in-container agent binary for strait.
//!
//! Two subcommands in one binary:
//!
//! - `entrypoint` -- runs as container PID 1 or equivalent. Verifies
//!   `CAP_NET_ADMIN`, spawns the proxy subprocess, installs iptables
//!   OUTPUT REDIRECT rules for the configured ports to the proxy port,
//!   drops privileges to the configured agent user, and `exec`s the
//!   agent command. See [`strait_agent::entrypoint`].
//! - `proxy` -- MITM proxy. Will (in H-ICDP-3) host the pipeline moved
//!   out of the top-level crate's `src/mitm.rs`, using `SO_ORIGINAL_DST`
//!   to recover the intended destination after the REDIRECT.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use strait_agent::config::AgentConfig;
use strait_agent::entrypoint;

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

    /// Override `entrypoint.agent_user` from the config file.
    ///
    /// Convenience for `--cap-add=NET_ADMIN` container invocations where
    /// the user is passed via docker-run args rather than a mounted
    /// config. Global so the same flag works with both subcommands.
    #[arg(long, global = true, value_name = "USER")]
    agent_user: Option<String>,

    /// Override `proxy.port` from the config file.
    #[arg(long, global = true, value_name = "PORT")]
    proxy_port: Option<u16>,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Container entrypoint: install iptables rules, drop privileges,
    /// and exec the agent command.
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
    let mut config = AgentConfig::load_optional(cli.config.as_deref())?;
    // CLI overrides win over env + file so operators can tune a single
    // invocation without editing the config file or exporting env vars.
    if let Some(user) = cli.agent_user {
        config.agent_user = if user.is_empty() { None } else { Some(user) };
    }
    if let Some(port) = cli.proxy_port {
        if port == 0 {
            anyhow::bail!("--proxy-port must be non-zero");
        }
        config.proxy_port = port;
    }

    match cli.command {
        Commands::Entrypoint { command } => entrypoint::run(&config, &command),
        Commands::Proxy => {
            println!("strait-agent: mode=proxy (skeleton; H-ICDP-3 fills this in)");
            println!("  proxy_port       = {}", config.proxy_port);
            println!("  host_socket      = {}", config.host_socket.display());
            Ok(())
        }
    }
}
