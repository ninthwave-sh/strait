use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::Context as _;
use clap::{ArgGroup, Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{info, warn};

use strait::config;
use strait::control::{self, ControlServiceOptions, ManagedSessionOptions, TcpTlsOptions};
use strait::credentials::CredentialStore;
use strait::generate;
use strait::observe::ObservationStream;
use strait::templates;
use strait::watch;

#[cfg(unix)]
use strait::config::sighup_reload_task;
use strait::config::{git_policy_poll_task, ProxyContext, StraitConfig};
#[cfg(unix)]
use strait::container::container_trust_diagnostic_lines;
#[cfg(unix)]
use strait::launch::{
    LaunchPolicyMutationResult, LaunchSessionMetadata, LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE,
};
use strait::mitm::handle_connection;

#[derive(Parser)]
#[command(
    name = "strait",
    version,
    about = "Container-scoped MITM policy platform for AI agents"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum TemplateAction {
    /// List all available policy templates.
    List,
    /// Apply a template — write .cedar + .cedarschema files.
    Apply {
        /// Template name (e.g. "github-org-readonly").
        name: String,

        /// Output directory for the generated files.
        ///
        /// If omitted, both files are printed to stdout.
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum SessionAction {
    /// List active strait runtime sessions discovered through the local registry.
    List,

    /// Inspect a running strait session through the control API.
    Info {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },

    /// Watch the live observation stream for a running strait session.
    Watch {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },

    /// Reload policy from the session's configured source.
    ///
    /// Live updates apply to network policy only. Filesystem or process
    /// policy changes require relaunch.
    ReloadPolicy {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },

    /// Replace the active policy with the contents of a Cedar policy file.
    ///
    /// Live updates apply to network policy only. Filesystem or process
    /// policy changes require relaunch.
    ReplacePolicy {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,

        /// Path to the Cedar policy file to apply.
        #[arg(value_name = "POLICY_FILE")]
        policy: PathBuf,
    },

    /// Persist a blocked request as durable Cedar policy and reload it live.
    PersistDecision {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,

        /// Blocked-request identifier from the observation stream.
        #[arg(value_name = "BLOCKED_ID")]
        blocked_id: String,
    },

    /// Stop a running strait session through the control API.
    Stop {
        /// Session ID to target.
        ///
        /// If omitted, targets the newest active session.
        #[arg(long, value_name = "ID")]
        session: Option<String>,
    },
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum ServiceAction {
    /// Start the gRPC control service.
    #[command(after_help = "\
The control service listens on a Unix domain socket locally and can also\
listen on mTLS-authenticated TCP for remote operators.\
\nIf you provide one of --observe, --warn, or --policy plus a command after\
`--`, the service will launch and own that session while still publishing the\
existing control socket and observation socket contracts.")]
    Start {
        /// Unix socket path for the local gRPC control service.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,

        /// Optional remote listen address for mTLS-authenticated gRPC.
        #[arg(long, value_name = "ADDR")]
        tcp_listen: Option<SocketAddr>,

        /// PEM-encoded server certificate for remote TLS.
        #[arg(long, value_name = "FILE")]
        tls_cert: Option<PathBuf>,

        /// PEM-encoded server private key for remote TLS.
        #[arg(long, value_name = "FILE")]
        tls_key: Option<PathBuf>,

        /// PEM-encoded client CA bundle for remote mTLS.
        #[arg(long, value_name = "FILE")]
        tls_client_ca: Option<PathBuf>,

        /// Launch a managed session in observe mode.
        #[arg(long)]
        observe: bool,

        /// Launch a managed session in warn mode with the supplied policy.
        #[arg(long, value_name = "POLICY_FILE")]
        warn: Option<PathBuf>,

        /// Launch a managed session in enforce mode with the supplied policy.
        #[arg(long, value_name = "POLICY_FILE")]
        policy: Option<PathBuf>,

        /// Container image for the managed session.
        #[arg(long, value_name = "IMAGE")]
        image: Option<String>,

        /// Observation log path for the managed session.
        #[arg(long, value_name = "FILE")]
        output: Option<PathBuf>,

        /// Additional environment variable for the managed session.
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Additional bind mount for the managed session.
        #[arg(long, value_name = "HOST:CONTAINER[:ro|rw]")]
        mount: Vec<String>,

        /// Managed session command. Pass after `--`.
        #[arg(
            value_name = "COMMAND",
            trailing_var_arg = true,
            allow_hyphen_values = true
        )]
        command: Vec<String>,
    },

    /// Show control service status and published sessions.
    Status {
        /// Unix socket path for the local gRPC control service.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },

    /// Stop a running gRPC control service.
    Stop {
        /// Unix socket path for the local gRPC control service.
        #[arg(long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTPS proxy for standalone integrations.
    #[command(after_help = "\
TLS TRUST:
  strait generates a session-local CA certificate on each startup.
  The CA cert PEM is written to the path specified by `ca_cert_path` in strait.toml.
  Configure your client to trust it:

    curl --cacert /tmp/strait-ca.pem --proxy http://127.0.0.1:<port> https://api.github.com/user

  Or concatenate with the system CA bundle:
    cat /tmp/strait-ca.pem >> /path/to/ca-bundle.crt
    SSL_CERT_FILE=/path/to/ca-bundle.crt HTTPS_PROXY=127.0.0.1:<port> curl https://api.github.com/user")]
    Proxy {
        /// Path to the strait.toml configuration file.
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,
    },

    /// Generate Cedar policy from an observation log.
    ///
    /// Reads a JSONL observation file and produces a Cedar policy file + schema
    /// covering all observed activity. Dynamic path segments (UUIDs, long numbers,
    /// SHA hashes) are collapsed to wildcards with annotation comments.
    Generate {
        /// Path to the observation JSONL file.
        observations: PathBuf,

        /// Output path for the Cedar policy file.
        #[arg(short, long, default_value = "policy.cedar")]
        output: PathBuf,

        /// Output path for the Cedar schema file.
        #[arg(long, default_value = "policy.cedarschema")]
        schema: PathBuf,
    },

    /// Test a Cedar policy against an observation log.
    ///
    /// Replays every event in the observation log against the specified Cedar
    /// policy and reports mismatches. Exits 0 when all evaluable events match,
    /// 1 when any mismatch is found.
    Test {
        /// Replay mode: evaluate observations against a policy.
        #[arg(long)]
        replay: PathBuf,

        /// Path to the Cedar policy file.
        #[arg(long)]
        policy: PathBuf,

        /// Agent identity (Cedar principal) to use during evaluation.
        ///
        /// Defaults to "agent" if not specified. Use this to test policies that
        /// reference specific principals (e.g. `principal == Agent::"worker"`).
        #[arg(long)]
        agent: Option<String>,
    },

    /// Watch live observation events from the newest running strait session.
    ///
    /// Compatibility alias for `strait session watch`.
    /// Connects to the live stream for the newest published session
    /// and renders a colored real-time stream of agent activity. Falls back
    /// to legacy socket discovery when no session is published. Auto-reconnects
    /// if the stream disconnects. Exits cleanly on Ctrl+C.
    Watch {
        /// Path to the observation Unix socket.
        ///
        /// If omitted, auto-discovers the newest published session and
        /// falls back to legacy `/tmp/strait-*.sock` discovery.
        #[arg(short, long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },

    /// Explain a Cedar policy in plain English.
    ///
    /// Reads a Cedar policy file and prints a human-readable summary of what
    /// the policy allows and denies. Groups rules by action namespace (http,
    /// fs, proc) so non-Cedar-experts can review generated policies.
    Explain {
        /// Path to the Cedar policy file.
        #[arg(value_name = "POLICY_FILE")]
        policy: PathBuf,
    },

    /// Manage built-in Cedar policy templates.
    ///
    /// List available templates or apply one to get a starting Cedar policy
    /// and schema for common access patterns (GitHub orgs, AWS S3, etc.).
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },

    /// Manage running strait sessions over the local control API.
    #[command(after_help = "\
LIVE POLICY UPDATES:
  Live updates apply to network policy only.
  Filesystem or process policy changes require relaunch.")]
    Session {
        #[command(subcommand)]
        action: SessionAction,
    },

    /// Manage the background gRPC control service.
    Service {
        #[command(subcommand)]
        action: ServiceAction,
    },

    /// Launch a command in a sandboxed container with Cedar policy enforcement.
    ///
    /// Runs the specified command inside a container with filesystem and network
    /// access controlled by Cedar policies. Three modes:
    ///
    /// - `--observe`: observe mode (allow all, record activity)
    /// - `--warn <policy.cedar>`: evaluate policy, allow all, log violations as warnings
    /// - `--policy <policy.cedar>`: enforce policy, deny disallowed access
    ///
    /// Network traffic routes through the built-in proxy. Filesystem access is
    /// controlled via bind-mount restrictions derived from Cedar `fs:` policies.
    #[command(
        group(ArgGroup::new("mode").required(true).args(["observe", "warn", "policy"])),
        after_help = "\
SESSION MANAGEMENT:
  strait launch prints a session ID once the session is ready.
  Use `strait session info|watch|reload-policy|replace-policy|stop`
  to manage that running session.

LIVE POLICY UPDATES:
  Live updates apply to network policy only.
  Filesystem or process policy changes require relaunch."
    )]
    Launch {
        /// Run in observation mode: allow all activity, record to JSONL.
        ///
        /// All filesystem and network access is permitted. Activity is recorded
        /// to an observation log for later policy generation with `strait generate`.
        #[arg(long)]
        observe: bool,

        /// Evaluate Cedar policy but allow all access, logging violations as warnings.
        ///
        /// Container bind-mounts are restricted to paths permitted by `fs:` policies.
        /// Network connections to disallowed hosts are logged as warnings but not blocked.
        #[arg(long, value_name = "POLICY_FILE")]
        warn: Option<PathBuf>,

        /// Enforce Cedar policy: deny disallowed filesystem and network access.
        ///
        /// Container bind-mounts are restricted to paths permitted by `fs:` policies.
        /// Network connections to disallowed hosts are blocked with HTTP 403.
        #[arg(long, value_name = "POLICY_FILE")]
        policy: Option<PathBuf>,

        /// Path to a strait.toml configuration file.
        ///
        /// When provided, the credential store and MITM host list from the config
        /// are used by the launch proxy. This enables credential injection in
        /// container mode -- the agent never sees the real API key.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,

        /// Docker image to use for the container.
        ///
        /// Defaults to ubuntu:24.04 when omitted.
        #[arg(long)]
        image: Option<String>,

        /// Output path for the observation JSONL file.
        #[arg(long, default_value = "observations.jsonl")]
        output: PathBuf,

        /// Disable TTY allocation in the container.
        ///
        /// By default, the container runs with a pseudo-TTY attached. Use this
        /// flag when stdin is not a terminal (e.g., CI pipelines, headless
        /// adapters, background processes).
        #[arg(long)]
        no_tty: bool,

        /// Set environment variables in the container (repeatable).
        #[arg(long, value_name = "KEY=VALUE")]
        env: Vec<String>,

        /// Additional bind mounts in Docker format (repeatable).
        ///
        /// Accepts `HOST:CONTAINER` or `HOST:CONTAINER:MODE` where MODE is
        /// `ro` or `rw` (defaults to `rw`). These mounts are operator-specified
        /// and bypass Cedar policy validation -- use them for trusted paths
        /// outside the project directory (e.g., `~/.claude/:/root/.claude/:ro`).
        #[arg(long, value_name = "HOST:CONTAINER[:MODE]")]
        mount: Vec<String>,

        /// The command and arguments to run inside the container.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Compare two Cedar policy files and show permission-level differences.
    ///
    /// Not a text diff — a semantic diff showing which permissions were
    /// added, removed, or left unchanged. Useful for reviewing policy
    /// changes during code review.
    ///
    /// Exits with code 0 when no changes are found, code 1 when
    /// permissions differ (like `git diff`).
    Diff {
        /// Path to the old (baseline) Cedar policy file.
        old: PathBuf,

        /// Path to the new (changed) Cedar policy file.
        new: PathBuf,
    },

    /// Initialize Cedar policies by observing live traffic.
    ///
    /// Starts the proxy in observation mode: all MITM'd requests are allowed
    /// (no policy enforcement), credentials are injected, and every request is
    /// recorded. After the observation period expires, a starter Cedar policy
    /// and schema covering all observed activity are generated.
    ///
    /// Dynamic path segments (UUIDs, long numeric IDs, SHA hashes) are
    /// automatically collapsed to wildcards with annotation comments.
    Init {
        /// Duration to observe traffic (e.g. "5m", "30s", "1h").
        #[arg(long, value_name = "DURATION")]
        observe: String,

        /// Path to the strait.toml configuration file.
        ///
        /// The `[policy]` section is ignored in observation mode.
        #[arg(short, long, value_name = "FILE")]
        config: PathBuf,

        /// Output directory for generated .cedar and .cedarschema files.
        ///
        /// If omitted, both files are printed to stdout.
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,
    },
}

/// Initialize the tracing subscriber with JSON output to stderr.
///
/// Called once at startup. Commands that produce no tracing events see no
/// output — the subscriber is effectively a no-op for non-proxy commands.
fn init_tracing() {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    strait::ensure_rustls_crypto_provider();
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            observations,
            output,
            schema,
        } => {
            generate::generate(&observations, &output, &schema)?;
        }
        Commands::Explain { policy } => {
            let summary = strait::explain::explain(&policy)?;
            print!("{summary}");
        }
        Commands::Template { action } => match action {
            TemplateAction::List => {
                templates::list();
            }
            TemplateAction::Apply { name, output_dir } => {
                templates::apply(&name, output_dir.as_deref())?;
            }
        },
        Commands::Test {
            replay,
            policy,
            agent,
        } => {
            let result = strait::replay::replay(&replay, &policy, agent.as_deref())?;
            let exit_code = strait::replay::print_results(&result);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Commands::Watch { socket } => {
            watch::run(socket).await?;
        }
        Commands::Session { action } => {
            run_session_command(action).await?;
        }
        Commands::Service { action } => {
            run_service_command(action).await?;
        }
        Commands::Proxy { config } => {
            run_proxy(config).await?;
        }
        Commands::Launch {
            observe,
            warn,
            policy,
            config,
            image,
            output,
            no_tty,
            env,
            mount,
            command,
        } => {
            init_tracing();

            // Load credential store and MITM hosts from config if provided.
            let (credential_store, mitm_hosts) = if let Some(ref config_path) = config {
                let cfg = StraitConfig::load(config_path)?;
                info!(path = %config_path.display(), "launch config loaded");

                let cred_store = if cfg.credential.is_empty() {
                    None
                } else {
                    let store = CredentialStore::from_entries(&cfg.credential)?;
                    info!(
                        count = cfg.credential.len(),
                        "credentials loaded from config"
                    );
                    Some(Arc::new(store))
                };

                (cred_store, cfg.mitm.hosts.clone())
            } else {
                (None, Vec::new())
            };

            let resolved_image = image.unwrap_or_else(|| "ubuntu:24.04".to_string());

            // clap's ArgGroup "mode" guarantees exactly one of these is set.
            let tty = !no_tty;
            let extra_mounts = strait::launch::parse_extra_mounts(&mount)?;
            let exit_code = if let Some(policy_path) = policy {
                // Enforce mode: deny disallowed access
                strait::launch::run_launch_with_policy(
                    strait::launch::EnforcementMode::Enforce,
                    &policy_path,
                    command,
                    Some(&resolved_image),
                    Some(output),
                    credential_store,
                    mitm_hosts,
                    env,
                    extra_mounts,
                    tty,
                )
                .await?
            } else if let Some(warn_path) = warn {
                // Warn mode: allow all, log violations
                strait::launch::run_launch_with_policy(
                    strait::launch::EnforcementMode::Warn,
                    &warn_path,
                    command,
                    Some(&resolved_image),
                    Some(output),
                    credential_store,
                    mitm_hosts,
                    env,
                    extra_mounts,
                    tty,
                )
                .await?
            } else {
                // Observe mode: allow all, record activity
                debug_assert!(observe);
                strait::launch::run_launch_observe(
                    command,
                    Some(&resolved_image),
                    Some(output),
                    credential_store,
                    mitm_hosts,
                    env,
                    extra_mounts,
                    tty,
                )
                .await?
            };
            std::process::exit(exit_code);
        }
        Commands::Diff { old, new } => {
            let result = strait::diff::diff(&old, &new)?;
            print!("{result}");
            if result.has_changes() {
                std::process::exit(1);
            }
        }
        Commands::Init {
            observe: duration_str,
            config,
            output_dir,
        } => {
            run_observe(config, &duration_str, output_dir).await?;
        }
    }

    Ok(())
}

#[cfg(unix)]
async fn run_session_command(action: SessionAction) -> anyhow::Result<()> {
    match action {
        SessionAction::List => {
            let sessions = inspect_running_sessions().await?;
            print!("{}", format_session_list(&sessions));
        }
        SessionAction::Info { session } => {
            let session = resolve_target_session(session.as_deref()).await?;
            print!("{}", format_session_info(&session));
        }
        SessionAction::Watch { session } => {
            watch::run_session(session).await?;
        }
        SessionAction::ReloadPolicy { session } => {
            let session = resolve_target_session(session.as_deref()).await?;
            let update =
                strait::launch::request_launch_policy_reload(&session.control_socket_path).await?;
            report_policy_update("Policy reload", &session, &update)?;
        }
        SessionAction::ReplacePolicy { session, policy } => {
            let session = resolve_target_session(session.as_deref()).await?;
            let policy_text = std::fs::read_to_string(&policy)
                .with_context(|| format!("failed to read policy file '{}'", policy.display()))?;
            let update = strait::launch::request_launch_policy_replace(
                &session.control_socket_path,
                policy_text,
            )
            .await?;
            report_policy_update("Policy replace", &session, &update)?;
        }
        SessionAction::PersistDecision {
            session,
            blocked_id,
        } => {
            let session = resolve_target_session(session.as_deref()).await?;
            let outcome = strait::launch::request_launch_decision_persist(
                &session.control_socket_path,
                &blocked_id,
            )
            .await?;
            println!(
                "Persisted {} for session {}.",
                outcome.match_key, session.session_id
            );
            println!("{LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE}");
        }
        SessionAction::Stop { session } => {
            let session = resolve_target_session(session.as_deref()).await?;
            strait::launch::request_launch_session_stop(&session.control_socket_path).await?;
            println!("Stop requested for session {}.", session.session_id);
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn run_session_command(_action: SessionAction) -> anyhow::Result<()> {
    anyhow::bail!("session commands are only supported on Unix platforms")
}

#[cfg(unix)]
async fn run_service_command(action: ServiceAction) -> anyhow::Result<()> {
    match action {
        ServiceAction::Start {
            socket,
            tcp_listen,
            tls_cert,
            tls_key,
            tls_client_ca,
            observe,
            warn,
            policy,
            image,
            output,
            env,
            mount,
            command,
        } => {
            let socket_path = socket.unwrap_or_else(control::default_service_socket_path);
            let managed_session = ManagedSessionOptions {
                observe,
                warn,
                policy,
                image,
                output,
                env,
                mount,
                command,
            };
            let tcp_tls = match (tcp_listen, tls_cert, tls_key, tls_client_ca) {
                (None, None, None, None) => None,
                (Some(listen_addr), Some(cert_path), Some(key_path), Some(client_ca_path)) => {
                    Some(TcpTlsOptions {
                        listen_addr,
                        cert_path,
                        key_path,
                        client_ca_path,
                    })
                }
                _ => anyhow::bail!(
                    "remote TLS requires --tcp-listen, --tls-cert, --tls-key, and --tls-client-ca together"
                ),
            };

            init_tracing();
            eprintln!("Control service socket: {}", socket_path.display());
            if let Some(remote) = &tcp_tls {
                eprintln!("Remote control endpoint: {}", remote.listen_addr);
            }

            control::run_control_service(ControlServiceOptions {
                socket_path,
                tcp_tls,
                managed_session,
            })
            .await?;
        }
        ServiceAction::Status { socket } => {
            let socket_path = socket.unwrap_or_else(control::default_service_socket_path);
            let status = control::query_service_status(&socket_path).await?;
            println!("Control service: running");
            println!("Local endpoint: {}", status.local_endpoint.address);
            if let Some(remote_endpoint) = status.remote_endpoint {
                println!("Remote endpoint: {}", remote_endpoint.address);
            }
            println!("Sessions: {}", status.sessions.len());
            for session in status.sessions {
                println!("- {} ({})", session.session_id, session.mode);
            }
        }
        ServiceAction::Stop { socket } => {
            let socket_path = socket.unwrap_or_else(control::default_service_socket_path);
            control::request_service_stop(&socket_path).await?;
            println!(
                "Stop requested for control service at {}.",
                socket_path.display()
            );
        }
    }

    Ok(())
}

#[cfg(not(unix))]
async fn run_service_command(_action: ServiceAction) -> anyhow::Result<()> {
    anyhow::bail!("control service commands are only supported on Unix platforms")
}

#[cfg(unix)]
async fn inspect_running_sessions() -> anyhow::Result<Vec<LaunchSessionMetadata>> {
    let mut sessions = Vec::new();
    for candidate in strait::launch::list_launch_sessions()? {
        match strait::launch::request_launch_session_info(&candidate.control_socket_path).await {
            Ok(session) => sessions.push(session),
            Err(error) => warn!(
                session_id = %candidate.session_id,
                error = %error,
                "skipping launch session that could not be queried"
            ),
        }
    }
    sessions.sort_by(|left, right| left.session_id.cmp(&right.session_id));
    Ok(sessions)
}

#[cfg(unix)]
fn session_registry_candidates_newest_first(
    sessions: impl IntoIterator<Item = LaunchSessionMetadata>,
) -> Vec<LaunchSessionMetadata> {
    let mut sessions: Vec<_> = sessions.into_iter().collect();
    sessions.sort_by(|left, right| {
        std::fs::metadata(&right.control_socket_path)
            .ok()
            .and_then(|metadata| metadata.modified().ok())
            .cmp(
                &std::fs::metadata(&left.control_socket_path)
                    .ok()
                    .and_then(|metadata| metadata.modified().ok()),
            )
            .then_with(|| right.session_id.cmp(&left.session_id))
    });
    sessions
}

#[cfg(unix)]
async fn resolve_default_target_session(
    sessions: Vec<LaunchSessionMetadata>,
) -> anyhow::Result<LaunchSessionMetadata> {
    if sessions.is_empty() {
        anyhow::bail!(
            "no active strait sessions found; start one with `strait proxy --config ...` or `strait launch ...`"
        );
    }

    for candidate in session_registry_candidates_newest_first(sessions) {
        match strait::launch::request_launch_session_info(&candidate.control_socket_path).await {
            Ok(session) => return Ok(session),
            Err(error) => warn!(
                session_id = %candidate.session_id,
                error = %error,
                "skipping launch session that could not be queried while resolving default target"
            ),
        }
    }

    anyhow::bail!(
        "no active strait sessions found; start one with `strait proxy --config ...` or `strait launch ...`"
    );
}

#[cfg(unix)]
async fn resolve_target_session(session_id: Option<&str>) -> anyhow::Result<LaunchSessionMetadata> {
    let discovered = if let Some(session_id) = session_id {
        strait::launch::list_launch_sessions()?
            .into_iter()
            .find(|session| session.session_id == session_id)
            .with_context(|| format!("no active strait session found for '{session_id}'"))?
    } else {
        return resolve_default_target_session(strait::launch::list_launch_sessions()?).await;
    };

    strait::launch::request_launch_session_info(&discovered.control_socket_path)
        .await
        .with_context(|| {
            format!(
                "failed to query session '{}' over the control API",
                discovered.session_id
            )
        })
}

#[cfg(unix)]
fn format_session_list(sessions: &[LaunchSessionMetadata]) -> String {
    if sessions.is_empty() {
        return "No active strait sessions.\n".to_string();
    }

    let mut lines = vec![format!(
        "{:<36}  {:<8}  {}",
        "SESSION ID", "MODE", "CONTAINER"
    )];
    for session in sessions {
        let container = session
            .container_name
            .as_deref()
            .or(session.container_id.as_deref())
            .unwrap_or("-");
        lines.push(format!(
            "{:<36}  {:<8}  {}",
            session.session_id, session.mode, container
        ));
    }
    format!("{}\n", lines.join("\n"))
}

#[cfg(unix)]
fn format_session_info(session: &LaunchSessionMetadata) -> String {
    let mut output = format!(
        "\
Session ID: {}
Mode: {}
Control socket: {}
Observation socket: {}
",
        session.session_id,
        session.mode,
        session.control_socket_path.display(),
        session.observation.path.display(),
    );

    if let Some(container_id) = session.container_id.as_deref() {
        output.push_str(&format!("Container ID: {}\n", container_id));
    }
    if let Some(container_name) = session.container_name.as_deref() {
        output.push_str(&format!("Container name: {}\n", container_name));
    }

    output.push_str(&format!(
        "Policy updates: {}\n",
        LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE
    ));

    // The container trust boundary only applies to launched sessions that
    // actually own a container. Standalone `strait proxy` sessions rely on
    // whatever host trust the pointing client already has, and none of the
    // diagnostic lines ("/strait/ca.pem", "--network=none", gateway socket)
    // describe how they actually operate. Emitting the diagnostic for those
    // sessions would be actively misleading.
    if session.container_id.is_some() || session.container_name.is_some() {
        for line in container_trust_diagnostic_lines() {
            output.push_str(&line);
            output.push('\n');
        }
    }

    output
}

#[cfg(unix)]
fn report_policy_update(
    action: &str,
    session: &LaunchSessionMetadata,
    update: &LaunchPolicyMutationResult,
) -> anyhow::Result<()> {
    if update.applied {
        println!("{action} applied live for session {}.", session.session_id);
        println!("{LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE}");
        return Ok(());
    }

    let domains = update.restart_required_domains.join(", ");
    anyhow::bail!(
        "{action} requires relaunch for {domains} policy changes in session {}. {LIVE_POLICY_UPDATE_BOUNDARY_MESSAGE}",
        session.session_id
    )
}

/// Shared proxy startup: write CA cert, bind listener, print port.
///
/// Both `run_proxy` and `run_observe` perform the same startup sequence after
/// building their respective `ProxyContext`. This helper eliminates that
/// duplication.
async fn bind_proxy_listener(
    config: &StraitConfig,
    ctx: &ProxyContext,
) -> anyhow::Result<TcpListener> {
    // Write CA cert PEM to configured path
    std::fs::write(&config.ca_cert_path, &ctx.session_ca.ca_cert_pem)?;
    info!(path = %config.ca_cert_path.display(), "CA cert written");

    let listen_addr: SocketAddr = format!("{}:{}", config.listen.address, config.listen.port)
        .parse()
        .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    info!(port = local_addr.port(), "strait listening");

    // Print port to stderr for programmatic consumption
    eprintln!("PORT={}", local_addr.port());

    Ok(listener)
}

/// Run the HTTPS proxy server.
async fn run_proxy(config_path: PathBuf) -> anyhow::Result<()> {
    init_tracing();

    // Load configuration
    let config = StraitConfig::load(&config_path)?;
    info!(path = %config_path.display(), "configuration loaded");

    // Build shared proxy context with a live observation stream so external
    // control surfaces can attach to standalone proxy sessions.
    let mut ctx = ProxyContext::from_config(&config)?;
    let obs_stream = ObservationStream::new();
    ctx.observation_stream = Some(obs_stream.clone());
    let ctx = Arc::new(ctx);

    #[cfg(unix)]
    let runtime_session = {
        let mode_label = format!("proxy-{}", ctx.enforcement_mode);
        let session =
            strait::launch::RuntimeSession::start(mode_label, ctx.clone(), &obs_stream).await?;
        let metadata = session.metadata().await;
        eprintln!("Session ID={}", metadata.session_id);
        eprintln!("CONTROL_SOCKET={}", metadata.control_socket_path.display());
        eprintln!("OBSERVATION_SOCKET={}", metadata.observation.path.display());
        session
    };

    let listener = bind_proxy_listener(&config, &ctx).await?;

    // Start git policy poll task if configured
    if ctx.git_policy.is_some() {
        let poll_ctx = ctx.clone();
        tokio::spawn(async move {
            git_policy_poll_task(poll_ctx).await;
        });
    }

    // Start health check server if configured
    if let Some(ref health_config) = config.health {
        let health_ctx = ctx.clone();
        let health_port = health_config.port;
        tokio::spawn(async move {
            strait::health::start_health_server(health_port, health_ctx).await;
        });
    }

    // Start SIGHUP reload handler (Unix only — covers Linux and macOS)
    #[cfg(unix)]
    if ctx.policy_engine.is_some() {
        let sighup_ctx = ctx.clone();
        tokio::spawn(async move {
            sighup_reload_task(sighup_ctx).await;
        });
    }

    #[cfg(unix)]
    let mut stop_rx = runtime_session.stop_receiver();

    loop {
        #[cfg(unix)]
        {
            tokio::select! {
                changed = stop_rx.changed() => {
                    match changed {
                        Ok(()) if *stop_rx.borrow() => {
                            info!("proxy session stop requested over control API");
                            break;
                        }
                        Ok(()) => continue,
                        Err(_) => break,
                    }
                }
                accepted = listener.accept() => {
                    let (client, peer) = accepted?;
                    let ctx = ctx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(client, peer, &ctx).await {
                            warn!(error = %e, "connection error");
                        }
                    });
                }
            }
        }

        #[cfg(not(unix))]
        {
            let (client, peer) = listener.accept().await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(client, peer, &ctx).await {
                    warn!(error = %e, "connection error");
                }
            });
        }
    }

    Ok(())
}

/// Run the proxy in observation mode for a fixed duration, then generate policy.
///
/// This is the implementation of `strait init --observe <duration>`. It:
/// 1. Loads config but ignores the `[policy]` section (no enforcement).
/// 2. Starts the proxy with an `ObservationStream` that records to a temp JSONL file.
/// 3. Accepts connections for `duration`, logging all MITM'd requests.
/// 4. Generates a Cedar policy + schema from the observation log.
/// 5. Writes to `--output-dir` or prints to stdout.
async fn run_observe(
    config_path: PathBuf,
    duration_str: &str,
    output_dir: Option<PathBuf>,
) -> anyhow::Result<()> {
    use strait::observe::{parse_duration, ObservationStream};

    let duration = parse_duration(duration_str)?;

    init_tracing();

    // Load configuration, ignoring the policy section
    let mut config = config::StraitConfig::load(&config_path)?;
    config.policy = None;
    info!(
        path = %config_path.display(),
        "configuration loaded (observation mode — policy enforcement disabled)"
    );

    // Create observation stream with JSONL persistence
    let temp_dir = tempfile::TempDir::new()?;
    let obs_log_path = temp_dir.path().join("observations.jsonl");
    let mut obs_stream = ObservationStream::new();
    obs_stream.persist_to_file(&obs_log_path)?;
    info!(path = %obs_log_path.display(), "observation log created");

    // Build proxy context (no policy engine)
    let mut ctx = config::ProxyContext::from_config(&config)?;
    ctx.observation_stream = Some(obs_stream);
    let ctx = Arc::new(ctx);

    let listener = bind_proxy_listener(&config, &ctx).await?;
    eprintln!(
        "Observation mode: recording traffic for {}. Send requests through the proxy.",
        duration_str
    );

    // Run the proxy for the specified duration
    let accept_loop = async {
        loop {
            let (client, peer) = listener.accept().await?;
            let ctx = ctx.clone();
            tokio::spawn(async move {
                if let Err(e) = handle_connection(client, peer, &ctx).await {
                    warn!(error = %e, "connection error");
                }
            });
        }
        // Type annotation for the async block to satisfy the compiler
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };

    tokio::select! {
        result = accept_loop => {
            result?;
        }
        _ = tokio::time::sleep(duration) => {
            info!("observation period complete");
        }
    }

    // Give in-flight requests a moment to complete
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    // Drop the context to flush the observation stream
    drop(ctx);

    eprintln!("Observation complete. Generating policy...");

    // Generate policy from observations
    match generate::generate_from_file(&obs_log_path)? {
        Some((policy_text, schema_text, wildcard_count)) => {
            if let Some(ref dir) = output_dir {
                std::fs::create_dir_all(dir)?;
                let policy_path = dir.join("policy.cedar");
                let schema_path = dir.join("policy.cedarschema");
                std::fs::write(&policy_path, &policy_text)?;
                std::fs::write(&schema_path, &schema_text)?;
                eprintln!("Policy written to {}", policy_path.display());
                eprintln!("Schema written to {}", schema_path.display());
            } else {
                // Print to stdout
                println!("# policy.cedar");
                print!("{policy_text}");
                println!();
                println!("# policy.cedarschema");
                print!("{schema_text}");
            }

            if wildcard_count > 0 {
                eprintln!(
                    "{wildcard_count} path segments collapsed to wildcards — review carefully"
                );
            }
        }
        None => {
            eprintln!("No actionable requests observed during the observation period.");
            eprintln!("Make sure your application sends requests through the proxy.");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    #[cfg(unix)]
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    #[cfg(unix)]
    use tokio::net::UnixListener;

    fn render_help(command: &mut clap::Command) -> String {
        let mut buf = Vec::new();
        command.write_long_help(&mut buf).unwrap();
        String::from_utf8(buf).unwrap()
    }

    #[test]
    fn test_cli_debug_assert() {
        // Verify the CLI definition is internally consistent (catches clap bugs early).
        Cli::command().debug_assert();
    }

    #[test]
    fn test_proxy_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "proxy", "--config", "strait.toml"]).unwrap();
        match cli.command {
            Commands::Proxy { config } => {
                assert_eq!(config.to_str().unwrap(), "strait.toml");
            }
            _ => panic!("expected Proxy subcommand"),
        }
    }

    #[test]
    fn test_launch_requires_mode_flag() {
        // launch without --observe, --warn, or --policy must fail (ArgGroup "mode" is required)
        let result = Cli::try_parse_from(["strait", "launch", "node", "server.js"]);
        assert!(
            result.is_err(),
            "launch without a mode flag should be rejected"
        );
    }

    #[test]
    fn test_launch_observe_flag_parses() {
        let cli = Cli::try_parse_from(["strait", "launch", "--observe", "echo", "hello"]).unwrap();
        match cli.command {
            Commands::Launch {
                observe, command, ..
            } => {
                assert!(observe, "observe should be true");
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_format_session_info_handles_proxy_sessions_without_container_metadata() {
        let info = format_session_info(&LaunchSessionMetadata {
            version: 1,
            session_id: "session-123".to_string(),
            mode: "proxy-enforce".to_string(),
            decision_timeout_secs: 30,
            control_socket_path: PathBuf::from("/tmp/control.sock"),
            observation: strait::launch::ObservationHandle {
                transport: "unix_socket".to_string(),
                path: PathBuf::from("/tmp/observe.sock"),
            },
            container_id: None,
            container_name: None,
        });

        assert!(info.contains("Mode: proxy-enforce"));
        assert!(!info.contains("Container ID:"));
        assert!(!info.contains("Container name:"));

        // Proxy sessions do not inject CA into a container, do not use
        // --network=none, and do not route through the gateway. Emitting the
        // container trust diagnostic for them would be actively misleading.
        assert!(
            !info.contains("Trust boundary"),
            "proxy session info must not advertise the container trust boundary: {info}"
        );
        assert!(
            !info.contains("/strait/ca.pem"),
            "proxy session info must not reference container-only paths: {info}"
        );
        assert!(
            !info.contains("--network=none"),
            "proxy session info must not reference container-only network config: {info}"
        );
    }

    #[test]
    fn test_format_session_info_includes_container_trust_boundary_diagnostic() {
        let info = format_session_info(&LaunchSessionMetadata {
            version: 1,
            session_id: "session-456".to_string(),
            mode: "launch-enforce".to_string(),
            decision_timeout_secs: 30,
            control_socket_path: PathBuf::from("/tmp/control.sock"),
            observation: strait::launch::ObservationHandle {
                transport: "unix_socket".to_string(),
                path: PathBuf::from("/tmp/observe.sock"),
            },
            container_id: Some("abc123".to_string()),
            container_name: Some("strait-session-456".to_string()),
        });

        // Core session fields remain.
        assert!(info.contains("Session ID: session-456"));
        assert!(info.contains("Container ID: abc123"));
        assert!(info.contains("Container name: strait-session-456"));

        // Trust boundary diagnostics must be visible to operators so they can
        // debug a failed launch without reaching for host-wide workarounds.
        assert!(
            info.contains("Trust boundary"),
            "expected trust boundary diagnostic, got: {info}"
        );
        assert!(
            info.contains("container-local"),
            "expected container-local framing, got: {info}"
        );
        assert!(
            info.contains("no machine-wide CA install required"),
            "expected the no-machine-wide disclaimer, got: {info}"
        );
        assert!(
            info.contains("/tmp/strait-ca-bundle.pem"),
            "expected augmented bundle path, got: {info}"
        );
        assert!(
            info.contains("SSL_CERT_FILE"),
            "expected SSL_CERT_FILE in trust env vars, got: {info}"
        );
        assert!(
            info.contains("HTTPS_PROXY"),
            "expected HTTPS_PROXY in proxy env vars, got: {info}"
        );
        assert!(
            info.contains("--network=none"),
            "expected --network=none in diagnostic, got: {info}"
        );
    }

    #[test]
    fn test_launch_with_image_and_output_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--image",
            "ubuntu:24.04",
            "--output",
            "/tmp/obs.jsonl",
            "npm",
            "test",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch {
                observe,
                warn,
                policy,
                image,
                output,
                env,
                command,
                ..
            } => {
                assert!(observe);
                assert!(warn.is_none());
                assert!(policy.is_none());
                assert_eq!(image.as_deref(), Some("ubuntu:24.04"));
                assert_eq!(output.to_str().unwrap(), "/tmp/obs.jsonl");
                assert!(env.is_empty());
                assert_eq!(command, vec!["npm", "test"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_generate_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "generate",
            "observations.jsonl",
            "--output",
            "policy.cedar",
        ])
        .unwrap();
        matches!(cli.command, Commands::Generate { .. });
    }

    #[test]
    fn test_test_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "test",
            "--replay",
            "observations.jsonl",
            "--policy",
            "policy.cedar",
        ])
        .unwrap();
        matches!(cli.command, Commands::Test { .. });
    }

    #[test]
    fn test_watch_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "watch"]).unwrap();
        matches!(cli.command, Commands::Watch { .. });
    }

    #[test]
    fn test_session_list_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "session", "list"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::List,
            } => {}
            _ => panic!("expected Session::List subcommand"),
        }
    }

    #[test]
    fn test_session_info_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["strait", "session", "info", "--session", "session-123"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::Info { session },
            } => {
                assert_eq!(session.as_deref(), Some("session-123"));
            }
            _ => panic!("expected Session::Info subcommand"),
        }
    }

    #[test]
    fn test_session_watch_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "session", "watch"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::Watch { session },
            } => {
                assert!(session.is_none(), "session should default to newest");
            }
            _ => panic!("expected Session::Watch subcommand"),
        }
    }

    #[test]
    fn test_session_reload_policy_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "session",
            "reload-policy",
            "--session",
            "session-123",
        ])
        .unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::ReloadPolicy { session },
            } => {
                assert_eq!(session.as_deref(), Some("session-123"));
            }
            _ => panic!("expected Session::ReloadPolicy subcommand"),
        }
    }

    #[test]
    fn test_session_replace_policy_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "session",
            "replace-policy",
            "--session",
            "session-123",
            "policy.cedar",
        ])
        .unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::ReplacePolicy { session, policy },
            } => {
                assert_eq!(session.as_deref(), Some("session-123"));
                assert_eq!(policy.to_str().unwrap(), "policy.cedar");
            }
            _ => panic!("expected Session::ReplacePolicy subcommand"),
        }
    }

    #[test]
    fn test_session_stop_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["strait", "session", "stop", "--session", "session-123"]).unwrap();
        match cli.command {
            Commands::Session {
                action: SessionAction::Stop { session },
            } => {
                assert_eq!(session.as_deref(), Some("session-123"));
            }
            _ => panic!("expected Session::Stop subcommand"),
        }
    }

    #[test]
    fn test_session_persist_decision_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "session",
            "persist-decision",
            "--session",
            "session-123",
            "blocked-456",
        ])
        .unwrap();
        match cli.command {
            Commands::Session {
                action:
                    SessionAction::PersistDecision {
                        session,
                        blocked_id,
                    },
            } => {
                assert_eq!(session.as_deref(), Some("session-123"));
                assert_eq!(blocked_id, "blocked-456");
            }
            _ => panic!("expected Session::PersistDecision subcommand"),
        }
    }

    #[test]
    fn test_service_start_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "service",
            "start",
            "--socket",
            "/tmp/strait-control.sock",
            "--observe",
            "--image",
            "ubuntu:24.04",
            "--output",
            "/tmp/service-observations.jsonl",
            "--mount",
            "/tmp/fixture:/fixture:ro",
            "--",
            "sh",
            "-lc",
            "sleep 60",
        ])
        .unwrap();

        match cli.command {
            Commands::Service {
                action:
                    ServiceAction::Start {
                        socket,
                        observe,
                        image,
                        output,
                        mount,
                        command,
                        ..
                    },
            } => {
                assert_eq!(
                    socket.unwrap().to_str().unwrap(),
                    "/tmp/strait-control.sock"
                );
                assert!(observe);
                assert_eq!(image.as_deref(), Some("ubuntu:24.04"));
                assert_eq!(
                    output.unwrap().to_str().unwrap(),
                    "/tmp/service-observations.jsonl"
                );
                assert_eq!(mount, vec!["/tmp/fixture:/fixture:ro"]);
                assert_eq!(command, vec!["sh", "-lc", "sleep 60"]);
            }
            _ => panic!("expected Service::Start subcommand"),
        }
    }

    #[test]
    fn test_service_status_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "service",
            "status",
            "--socket",
            "/tmp/strait.sock",
        ])
        .unwrap();

        match cli.command {
            Commands::Service {
                action: ServiceAction::Status { socket },
            } => {
                assert_eq!(socket.unwrap().to_str().unwrap(), "/tmp/strait.sock");
            }
            _ => panic!("expected Service::Status subcommand"),
        }
    }

    #[test]
    fn test_service_stop_subcommand_parses() {
        let cli =
            Cli::try_parse_from(["strait", "service", "stop", "--socket", "/tmp/strait.sock"])
                .unwrap();

        match cli.command {
            Commands::Service {
                action: ServiceAction::Stop { socket },
            } => {
                assert_eq!(socket.unwrap().to_str().unwrap(), "/tmp/strait.sock");
            }
            _ => panic!("expected Service::Stop subcommand"),
        }
    }

    #[test]
    fn test_help_lists_all_subcommands() {
        let cmd = Cli::command();
        let subcommand_names: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();

        assert!(
            subcommand_names.contains(&"proxy"),
            "missing 'proxy' subcommand"
        );
        assert!(
            subcommand_names.contains(&"launch"),
            "missing 'launch' subcommand"
        );
        assert!(
            subcommand_names.contains(&"generate"),
            "missing 'generate' subcommand"
        );
        assert!(
            subcommand_names.contains(&"test"),
            "missing 'test' subcommand"
        );
        assert!(
            subcommand_names.contains(&"watch"),
            "missing 'watch' subcommand"
        );
        assert!(
            subcommand_names.contains(&"explain"),
            "missing 'explain' subcommand"
        );
        assert!(
            subcommand_names.contains(&"diff"),
            "missing 'diff' subcommand"
        );
        assert!(
            subcommand_names.contains(&"session"),
            "missing 'session' subcommand"
        );
        assert!(
            subcommand_names.contains(&"service"),
            "missing 'service' subcommand"
        );
    }

    #[test]
    fn test_session_help_mentions_live_update_boundary() {
        let mut cmd = Cli::command();
        let session = cmd.find_subcommand_mut("session").unwrap();
        let help = render_help(session);

        assert!(
            help.contains("Live updates apply to network policy only."),
            "session help should describe the live update boundary: {help}"
        );
        assert!(
            help.contains("Filesystem or process policy changes require relaunch."),
            "session help should mention relaunch for fs/proc changes: {help}"
        );
    }

    #[test]
    fn test_launch_help_mentions_session_management_and_live_update_boundary() {
        let mut cmd = Cli::command();
        let launch = cmd.find_subcommand_mut("launch").unwrap();
        let help = render_help(launch);

        assert!(
            help.contains("Use `strait session info|watch|reload-policy|replace-policy|stop`"),
            "launch help should point operators at session commands: {help}"
        );
        assert!(
            help.contains("Live updates apply to network policy only."),
            "launch help should describe the live update boundary: {help}"
        );
    }

    #[test]
    fn test_service_help_mentions_grpc_and_remote_support() {
        let mut cmd = Cli::command();
        let service = cmd.find_subcommand_mut("service").unwrap();
        let help = render_help(service);

        assert!(
            help.contains("background gRPC control service"),
            "service help should describe the gRPC control plane: {help}"
        );
        assert!(
            help.contains("start"),
            "service help should list the start subcommand: {help}"
        );
        assert!(
            help.contains("status"),
            "service help should list the status subcommand: {help}"
        );
        assert!(
            help.contains("stop"),
            "service help should list the stop subcommand: {help}"
        );
    }

    #[cfg(unix)]
    async fn spawn_session_info_server(
        socket_path: &std::path::Path,
        session: LaunchSessionMetadata,
    ) -> tokio::task::JoinHandle<()> {
        if let Some(parent) = socket_path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        if socket_path.exists() {
            std::fs::remove_file(socket_path).unwrap();
        }
        let listener = UnixListener::bind(socket_path).unwrap();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (read_half, mut write_half) = tokio::io::split(stream);
                let mut reader = tokio::io::BufReader::new(read_half);
                let mut request = String::new();
                let bytes = reader.read_line(&mut request).await.unwrap();
                if bytes == 0 {
                    continue;
                }

                let response = strait::launch::LaunchControlResponse {
                    version: strait::launch::SESSION_CONTROL_PROTOCOL_VERSION,
                    ok: true,
                    result: Some(strait::launch::LaunchControlResult::SessionInfo {
                        session: session.clone(),
                    }),
                    error: None,
                };
                let response_line = serde_json::to_string(&response).unwrap();
                write_half
                    .write_all(response_line.as_bytes())
                    .await
                    .unwrap();
                write_half.write_all(b"\n").await.unwrap();
                write_half.flush().await.unwrap();
            }
        })
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn default_session_resolution_skips_newer_stale_registry_entries() {
        let temp_dir = tempfile::tempdir().unwrap();
        let live_socket = temp_dir.path().join("live.sock");
        let stale_socket = temp_dir.path().join("stale.sock");

        let live_session = LaunchSessionMetadata {
            version: strait::launch::SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: "live-session".to_string(),
            mode: "observe".to_string(),
            decision_timeout_secs: 30,
            control_socket_path: live_socket.clone(),
            observation: strait::launch::ObservationHandle {
                transport: "unix_socket".to_string(),
                path: temp_dir.path().join("live-observe.sock"),
            },
            container_id: None,
            container_name: None,
        };

        let server = spawn_session_info_server(&live_socket, live_session.clone()).await;

        tokio::time::sleep(std::time::Duration::from_millis(20)).await;

        let stale_listener = UnixListener::bind(&stale_socket).unwrap();
        drop(stale_listener);

        let stale_session = LaunchSessionMetadata {
            version: strait::launch::SESSION_CONTROL_PROTOCOL_VERSION,
            session_id: "stale-session".to_string(),
            mode: "observe".to_string(),
            decision_timeout_secs: 30,
            control_socket_path: stale_socket,
            observation: strait::launch::ObservationHandle {
                transport: "unix_socket".to_string(),
                path: temp_dir.path().join("stale-observe.sock"),
            },
            container_id: None,
            container_name: None,
        };

        let resolved = resolve_default_target_session(vec![live_session.clone(), stale_session])
            .await
            .unwrap();
        assert_eq!(resolved.session_id, live_session.session_id);

        server.abort();
        let _ = tokio::fs::remove_file(&live_socket).await;
    }

    #[test]
    fn test_explain_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "explain", "policy.cedar"]).unwrap();
        match cli.command {
            Commands::Explain { policy } => {
                assert_eq!(policy.to_str().unwrap(), "policy.cedar");
            }
            _ => panic!("expected Explain subcommand"),
        }
    }

    #[test]
    fn test_diff_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "diff", "old.cedar", "new.cedar"]).unwrap();
        match cli.command {
            Commands::Diff { old, new } => {
                assert_eq!(old.to_str().unwrap(), "old.cedar");
                assert_eq!(new.to_str().unwrap(), "new.cedar");
            }
            _ => panic!("expected Diff subcommand"),
        }
    }

    #[test]
    fn test_launch_warn_flag_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--warn",
            "policy.cedar",
            "echo",
            "hello",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch {
                observe,
                warn,
                policy,
                command,
                ..
            } => {
                assert!(!observe, "observe should be false");
                assert_eq!(warn.unwrap().to_str().unwrap(), "policy.cedar");
                assert!(policy.is_none(), "policy should be None");
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_policy_flag_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--policy",
            "policy.cedar",
            "npm",
            "test",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch {
                observe,
                warn,
                policy,
                command,
                ..
            } => {
                assert!(!observe, "observe should be false");
                assert!(warn.is_none(), "warn should be None");
                assert_eq!(policy.unwrap().to_str().unwrap(), "policy.cedar");
                assert_eq!(command, vec!["npm", "test"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_observe_and_warn_conflict() {
        let result = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--warn",
            "policy.cedar",
            "echo",
            "hello",
        ]);
        assert!(result.is_err(), "--observe and --warn should conflict");
    }

    #[test]
    fn test_launch_observe_and_policy_conflict() {
        let result = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--policy",
            "policy.cedar",
            "echo",
            "hello",
        ]);
        assert!(result.is_err(), "--observe and --policy should conflict");
    }

    #[test]
    fn test_launch_env_flag_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--env",
            "FOO=bar",
            "--env",
            "BAZ=qux",
            "echo",
            "hello",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch { env, command, .. } => {
                assert_eq!(env, vec!["FOO=bar", "BAZ=qux"]);
                assert_eq!(command, vec!["echo", "hello"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_env_flag_with_equals_in_value() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--env",
            "FOO=bar=baz",
            "echo",
            "hello",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch { env, .. } => {
                assert_eq!(env, vec!["FOO=bar=baz"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_no_tty_flag() {
        let cli =
            Cli::try_parse_from(["strait", "launch", "--observe", "--no-tty", "echo", "hello"])
                .unwrap();
        match cli.command {
            Commands::Launch { no_tty, .. } => {
                assert!(no_tty, "--no-tty flag should be true");
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_tty_default() {
        let cli = Cli::try_parse_from(["strait", "launch", "--observe", "echo", "hello"]).unwrap();
        match cli.command {
            Commands::Launch { no_tty, .. } => {
                assert!(!no_tty, "--no-tty should default to false");
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_warn_and_policy_conflict() {
        let result = Cli::try_parse_from([
            "strait",
            "launch",
            "--warn",
            "warn.cedar",
            "--policy",
            "policy.cedar",
            "echo",
            "hello",
        ]);
        assert!(result.is_err(), "--warn and --policy should conflict");
    }

    #[test]
    fn test_launch_config_flag_with_observe() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "--config",
            "strait.toml",
            "echo",
            "ok",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch {
                observe,
                config,
                command,
                ..
            } => {
                assert!(observe);
                assert_eq!(config.unwrap().to_str().unwrap(), "strait.toml");
                assert_eq!(command, vec!["echo", "ok"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_config_flag_with_policy() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--policy",
            "policy.cedar",
            "--config",
            "strait.toml",
            "echo",
            "ok",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch { policy, config, .. } => {
                assert_eq!(policy.unwrap().to_str().unwrap(), "policy.cedar");
                assert_eq!(config.unwrap().to_str().unwrap(), "strait.toml");
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_config_short_flag() {
        let cli = Cli::try_parse_from([
            "strait",
            "launch",
            "--observe",
            "-c",
            "strait.toml",
            "echo",
            "ok",
        ])
        .unwrap();
        match cli.command {
            Commands::Launch { config, .. } => {
                assert_eq!(config.unwrap().to_str().unwrap(), "strait.toml");
            }
            _ => panic!("expected Launch subcommand"),
        }
    }

    #[test]
    fn test_launch_without_config_flag() {
        let cli = Cli::try_parse_from(["strait", "launch", "--observe", "echo", "ok"]).unwrap();
        match cli.command {
            Commands::Launch { config, .. } => {
                assert!(config.is_none());
            }
            _ => panic!("expected Launch subcommand"),
        }
    }
}
