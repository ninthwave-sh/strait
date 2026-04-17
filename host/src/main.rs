//! `strait-host` binary entry point.
//!
//! Runs as a long-lived host process that serves the container-side proxy
//! (Unix socket) and the desktop app (TCP loopback). This revision ships
//! the process skeleton only: listeners, config load, structured logging,
//! SIGHUP reload, and graceful SIGTERM. The real control-plane protocol
//! arrives in H-HCP-2.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use strait_host::config::{
    default_config_path, HostConfig, DEFAULT_SOCKET_MODE, DEFAULT_TCP_LISTEN, DEFAULT_UNIX_SOCKET,
};
use strait_host::listener::{serve, ShutdownSignal};

// ── CLI ──────────────────────────────────────────────────────────────

/// Long-form `--help` text. Keeps the documented defaults in one place so
/// they are visible to operators running `strait-host --help`.
const LONG_ABOUT: &str =
    concat!(
    "strait-host: long-lived host control plane process.\n\n",
    "Serves two listeners:\n",
    "  - Unix domain socket for in-container proxies (default: ",
    "/var/run/strait/host.sock", ", mode 0600)\n",
    "  - TCP loopback for the desktop app (default: ",
    "127.0.0.1:3129", ")\n\n",
    "Config is loaded from $HOME/.config/strait/host.toml by default. ",
    "Missing files and missing fields fall back to the documented defaults.\n\n",
    "Signals:\n",
    "  - SIGTERM / SIGINT: graceful shutdown. Listeners stop accepting and the process exits.\n",
    "  - SIGHUP: re-read the config file and log the new values. Listener ",
    "rebinding on reload is not implemented yet; restart to apply listener changes.\n",
);

#[derive(Parser, Debug)]
#[command(
    name = "strait-host",
    version,
    about = "Host control plane process for strait",
    long_about = LONG_ABOUT,
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Start the host control plane. Blocks until SIGTERM or SIGINT.
    Serve(ServeArgs),
}

#[derive(clap::Args, Debug)]
struct ServeArgs {
    /// Path to the host config file.
    ///
    /// Defaults to $HOME/.config/strait/host.toml. A missing file is not an
    /// error: the host starts on built-in defaults.
    #[arg(long, value_name = "PATH")]
    config: Option<PathBuf>,

    /// Override the Unix domain socket path.
    ///
    /// Default: /var/run/strait/host.sock (mode 0600, owned by the user
    /// that runs strait-host).
    #[arg(long, value_name = "PATH")]
    unix_socket: Option<PathBuf>,

    /// Override the TCP listener address.
    ///
    /// Default: 127.0.0.1:3129. Bind to loopback unless you know what you
    /// are doing; the protocol is not designed for untrusted networks.
    #[arg(long, value_name = "ADDR")]
    tcp_listen: Option<String>,

    /// Log format: "json" (default) or "text".
    #[arg(long, value_name = "FMT", default_value = "json")]
    log_format: String,
}

// ── Entry point ──────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Serve(args) => match run_serve(args).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("strait-host: {e:#}");
                ExitCode::from(1)
            }
        },
    }
}

async fn run_serve(args: ServeArgs) -> Result<()> {
    init_tracing(&args.log_format)?;

    let config_path = args.config.unwrap_or_else(default_config_path);
    info!(
        target: "strait_host",
        path = %config_path.display(),
        "loading config",
    );
    let mut cfg = HostConfig::load(&config_path)
        .with_context(|| format!("loading config {}", config_path.display()))?;

    if let Some(p) = args.unix_socket {
        cfg.unix_socket = p;
    }
    if let Some(a) = args.tcp_listen {
        cfg.tcp_listen = a
            .parse()
            .with_context(|| format!("invalid --tcp-listen {a}"))?;
    }

    info!(
        target: "strait_host",
        unix_socket = %cfg.unix_socket.display(),
        tcp_listen = %cfg.tcp_listen,
        socket_mode = format!("0o{:o}", cfg.socket_mode),
        default_unix = DEFAULT_UNIX_SOCKET,
        default_tcp = DEFAULT_TCP_LISTEN,
        default_mode = format!("0o{:o}", DEFAULT_SOCKET_MODE),
        "configured",
    );

    let shutdown = ShutdownSignal::new();
    let current_cfg = Arc::new(Mutex::new(cfg.clone()));

    // SIGTERM / SIGINT → trigger shutdown.
    spawn_shutdown_listener(shutdown.clone());

    // SIGHUP → reload config from disk. Listener rebinding is intentionally
    // out of scope for H-HCP-1; the reload updates the in-memory snapshot
    // so operators can confirm the file parses, and logs the new values.
    spawn_sighup_listener(config_path.clone(), current_cfg.clone());

    // Run the listeners until shutdown.
    serve(&cfg, shutdown.clone()).await?;
    info!(target: "strait_host", "shutdown complete");
    Ok(())
}

// ── Signal handlers ──────────────────────────────────────────────────

#[cfg(unix)]
fn spawn_shutdown_listener(shutdown: ShutdownSignal) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sigterm = match signal(SignalKind::terminate()) {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "strait_host", error = %e, "failed to install SIGTERM handler");
                return;
            }
        };
        let mut sigint = match signal(SignalKind::interrupt()) {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "strait_host", error = %e, "failed to install SIGINT handler");
                return;
            }
        };
        tokio::select! {
            _ = sigterm.recv() => {
                info!(target: "strait_host", signal = "SIGTERM", "shutdown requested");
            }
            _ = sigint.recv() => {
                info!(target: "strait_host", signal = "SIGINT", "shutdown requested");
            }
        }
        shutdown.trigger();
    });
}

#[cfg(not(unix))]
fn spawn_shutdown_listener(shutdown: ShutdownSignal) {
    tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        info!(target: "strait_host", signal = "CTRL_C", "shutdown requested");
        shutdown.trigger();
    });
}

#[cfg(unix)]
fn spawn_sighup_listener(path: PathBuf, current: Arc<Mutex<HostConfig>>) {
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                warn!(target: "strait_host", error = %e, "failed to install SIGHUP handler");
                return;
            }
        };
        while sighup.recv().await.is_some() {
            match HostConfig::load(&path) {
                Ok(new_cfg) => {
                    let mut guard = current.lock().await;
                    let prev = guard.clone();
                    *guard = new_cfg.clone();
                    if prev != new_cfg {
                        info!(
                            target: "strait_host",
                            unix_socket = %new_cfg.unix_socket.display(),
                            tcp_listen = %new_cfg.tcp_listen,
                            "config reloaded",
                        );
                    } else {
                        info!(target: "strait_host", "config reloaded (no changes)");
                    }
                }
                Err(e) => {
                    error!(
                        target: "strait_host",
                        path = %path.display(),
                        error = %e,
                        "config reload failed",
                    );
                }
            }
        }
    });
}

#[cfg(not(unix))]
fn spawn_sighup_listener(_path: PathBuf, _current: Arc<Mutex<HostConfig>>) {
    // No-op on non-unix. strait-host only supports unix hosts.
}

// ── Tracing ──────────────────────────────────────────────────────────

fn init_tracing(fmt: &str) -> Result<()> {
    use tracing_subscriber::{fmt as tfmt, EnvFilter};

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,strait_host=info"));

    match fmt {
        "json" => {
            let subscriber = tfmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .json()
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .context("installing tracing subscriber")?;
        }
        "text" => {
            let subscriber = tfmt()
                .with_env_filter(filter)
                .with_writer(std::io::stderr)
                .finish();
            tracing::subscriber::set_global_default(subscriber)
                .context("installing tracing subscriber")?;
        }
        other => {
            anyhow::bail!("unknown --log-format {other:?} (expected \"json\" or \"text\")");
        }
    }
    Ok(())
}
