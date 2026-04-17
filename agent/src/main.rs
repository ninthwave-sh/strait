//! `strait-agent` -- in-container agent binary for strait.
//!
//! Two subcommands in one binary:
//!
//! - `entrypoint` -- runs as container PID 1 or equivalent. Will (in
//!   H-ICDP-2) verify `CAP_NET_ADMIN`, install iptables OUTPUT REDIRECT
//!   rules for the configured ports to the proxy port, then drop
//!   privileges to the configured agent user and exec the agent command.
//! - `proxy` -- MITM proxy ported from the top-level crate's
//!   `src/mitm.rs`. Accepts REDIRECT'd TCP connections, recovers the
//!   original destination via `SO_ORIGINAL_DST`, terminates TLS with the
//!   session-local CA, evaluates Cedar policy, and forwards upstream
//!   (H-ICDP-3).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use strait_agent::config::AgentConfig;
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
            Ok(())
        }
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
        test_upstream_override: None,
        test_upstream_tls: None,
        max_body_size: 10 * 1024 * 1024,
    };
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(proxy::run(proxy_cfg))
}
