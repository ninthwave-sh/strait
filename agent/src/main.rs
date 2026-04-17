//! `strait-agent` -- in-container agent binary for strait.
//!
//! Two subcommands in one binary:
//!
//! - `entrypoint` -- runs as container PID 1 or equivalent. Verifies
//!   `CAP_NET_ADMIN`, spawns the proxy subprocess, installs iptables
//!   OUTPUT REDIRECT rules for the configured ports to the proxy port,
//!   drops privileges to the configured agent user, and `exec`s the
//!   agent command. See [`strait_agent::entrypoint`].
//! - `proxy` -- MITM proxy ported from the top-level crate's
//!   `src/mitm.rs`. Accepts REDIRECT'd TCP connections, recovers the
//!   original destination via `SO_ORIGINAL_DST`, terminates TLS with the
//!   session-local CA, evaluates Cedar policy, and forwards upstream.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use strait_agent::config::AgentConfig;
use strait_agent::entrypoint;
use strait_agent::observations::NoopSink;
use strait_agent::proxy::{self, PromptDenyClient, ProxyConfig};

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
    /// Accepts TCP connections rerouted by iptables REDIRECT, recovers
    /// the original destination via `SO_ORIGINAL_DST`, terminates TLS
    /// with the session-local CA, evaluates the Cedar policy, and
    /// forwards upstream.
    Proxy {
        /// Path to the Cedar policy file.
        #[arg(long, value_name = "PATH")]
        policy: PathBuf,
        /// Path to export the session CA cert (PEM) so the container
        /// entrypoint can inject it into the trust store before language
        /// runtimes start. The CA private key stays in process memory.
        #[arg(long, value_name = "PATH")]
        ca_cert: PathBuf,
    },
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
        Commands::Proxy { policy, ca_cert } => run_proxy(&config, policy, ca_cert),
    }
}

fn run_proxy(config: &AgentConfig, policy: PathBuf, ca_cert: PathBuf) -> anyhow::Result<()> {
    // Bind to all interfaces inside the container. iptables REDIRECT
    // rewrites the destination to (127.0.0.1, proxy_port), but binding
    // to 0.0.0.0 also works and matches what docker port-forwarding
    // tests expect.
    let listen_addr: SocketAddr = format!("0.0.0.0:{}", config.proxy_port)
        .parse()
        .expect("proxy port yields a valid sockaddr");
    let proxy_cfg = ProxyConfig {
        listen_addr,
        policy_path: policy,
        ca_cert_out: ca_cert,
        host_rpc: Arc::new(PromptDenyClient),
        // The observation streaming sink that ships events to the host
        // control plane lives in `strait_agent::observations` (M-HCP-5).
        // Wiring it into the CLI requires a running `strait-host` and a
        // registered session, which is tied up in H-HCP-6; until that
        // lands, the binary stays silent on observations by default.
        // Test harnesses and downstream orchestrators can build their
        // own `ProxyConfig` and inject a live `HostStreamingSink`.
        observation_sink: Arc::new(NoopSink),
        test_upstream_override: None,
        test_upstream_tls: None,
        max_body_size: 10 * 1024 * 1024,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(proxy::run(proxy_cfg))
}
