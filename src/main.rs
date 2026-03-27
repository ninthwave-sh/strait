use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use strait::config;
use strait::generate;
use strait::templates;
use strait::watch;

#[cfg(unix)]
use strait::config::sighup_reload_task;
use strait::config::{git_policy_poll_task, ProxyContext, StraitConfig};
use strait::mitm::{handle_mitm, should_mitm};

#[derive(Parser)]
#[command(
    name = "strait",
    version,
    about = "HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging"
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
enum Commands {
    /// Start the HTTPS proxy.
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
    },

    /// Watch live observation events from a running strait session.
    ///
    /// Connects to the Unix socket observation server and renders a colored
    /// real-time stream of agent activity. Auto-reconnects if the socket
    /// disconnects. Exits cleanly on Ctrl+C.
    Watch {
        /// Path to the observation Unix socket.
        ///
        /// If omitted, auto-discovers by looking for /tmp/strait-*.sock.
        #[arg(short, long, value_name = "PATH")]
        socket: Option<PathBuf>,
    },

    /// Manage built-in Cedar policy templates.
    ///
    /// List available templates or apply one to get a starting Cedar policy
    /// and schema for common access patterns (GitHub orgs, AWS S3, etc.).
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },

    /// Launch a command in a sandboxed container with Cedar policy enforcement.
    ///
    /// Runs the specified command inside a container with filesystem and network
    /// access controlled by Cedar policies. Three modes:
    ///
    /// - `--observe`: observe mode (allow all, record activity)
    /// - `--warn`: evaluate policy, allow all, log violations as warnings (future)
    /// - `--policy`: enforce policy, deny disallowed access (future)
    ///
    /// Network traffic routes through the built-in proxy. Filesystem access is
    /// controlled via bind-mount restrictions derived from Cedar `fs:` policies.
    Launch {
        /// Run in observation mode: allow all activity, record to JSONL.
        ///
        /// All filesystem and network access is permitted. Activity is recorded
        /// to an observation log for later policy generation with `strait generate`.
        #[arg(long)]
        observe: bool,

        /// Docker image to use for the container.
        #[arg(long, default_value = "alpine:latest")]
        image: String,

        /// Output path for the observation JSONL file.
        #[arg(long, default_value = "observations.jsonl")]
        output: PathBuf,

        /// The command and arguments to run inside the container.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Generate {
            observations,
            output,
            schema,
        } => {
            generate::generate(&observations, &output, &schema)?;
        }
        Commands::Template { action } => match action {
            TemplateAction::List => {
                templates::list();
            }
            TemplateAction::Apply { name, output_dir } => {
                templates::apply(&name, output_dir.as_deref())?;
            }
        },
        Commands::Test { replay, policy } => {
            let result = strait::replay::replay(&replay, &policy)?;
            let exit_code = strait::replay::print_results(&result);
            if exit_code != 0 {
                std::process::exit(exit_code);
            }
        }
        Commands::Watch { socket } => {
            watch::run(socket).await?;
        }
        Commands::Proxy { config } => {
            run_proxy(config).await?;
        }
        Commands::Launch {
            observe,
            image,
            output,
            command,
        } => {
            if !observe {
                eprintln!("strait launch requires --observe (enforce mode not yet implemented)");
                eprintln!("Usage: strait launch --observe <command> [args...]");
                std::process::exit(1);
            }

            tracing_subscriber::fmt()
                .json()
                .with_target(false)
                .with_writer(std::io::stderr)
                .init();

            let exit_code =
                strait::launch::run_launch_observe(command, Some(&image), Some(output)).await?;
            std::process::exit(exit_code);
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

/// Run the HTTPS proxy server.
async fn run_proxy(config_path: PathBuf) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    // Load configuration
    let config = StraitConfig::load(&config_path)?;
    info!(path = %config_path.display(), "configuration loaded");

    // Build shared proxy context
    let ctx = Arc::new(ProxyContext::from_config(&config)?);

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

    loop {
        let (client, peer) = listener.accept().await?;
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, peer, &ctx).await {
                warn!(error = %e, "connection error");
            }
        });
    }
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

    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

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

    // Write CA cert PEM
    std::fs::write(&config.ca_cert_path, &ctx.session_ca.ca_cert_pem)?;
    info!(path = %config.ca_cert_path.display(), "CA cert written");

    let listen_addr: std::net::SocketAddr =
        format!("{}:{}", config.listen.address, config.listen.port)
            .parse()
            .map_err(|e| anyhow::anyhow!("invalid listen address: {e}"))?;

    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    info!(
        port = local_addr.port(),
        "strait listening (observation mode)"
    );

    // Print port to stderr for programmatic consumption
    eprintln!("PORT={}", local_addr.port());
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

/// Handle a single client connection.
///
/// For CONNECT requests: check if the target host should be MITM'd.
/// - Inspected hosts: terminate TLS, evaluate Cedar policies, forward or deny.
/// - All other hosts: transparent TCP tunnel (no decryption).
async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    ctx: &ProxyContext,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut buf_client = BufReader::new(&mut client);
    let mut request_line = String::new();
    buf_client.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }

    let method = parts[0];
    let target = parts[1];

    if method.eq_ignore_ascii_case("CONNECT") {
        // Parse host:port from CONNECT target
        let (host, port) = parse_connect_target(target)?;

        // Drain remaining headers (up to empty line)
        loop {
            let mut line = String::new();
            buf_client.read_line(&mut line).await?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Drop the BufReader so we get back sole ownership of client
        drop(buf_client);

        if should_mitm(&host, &ctx.mitm_hosts) {
            // MITM path: send 200, then terminate TLS with session CA
            info!(
                host = host.as_str(),
                port = port,
                peer = %peer,
                "CONNECT: MITM path"
            );

            // Send 200 Connection Established before starting TLS handshake
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            // Hand off to MITM handler
            handle_mitm(client, &host, port, ctx).await?;
        } else {
            // Passthrough path: transparent TCP tunnel
            let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;

            // Log passthrough event
            ctx.audit_logger.log_passthrough(&host, port);

            info!(
                host = host.as_str(),
                port = port,
                peer = %peer,
                "CONNECT: passthrough (no MITM)"
            );

            // Send 200 Connection Established
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            // Tunnel bytes bidirectionally
            let _ = copy_bidirectional(&mut client, &mut upstream).await;
        }
    }

    Ok(())
}

fn parse_connect_target(target: &str) -> anyhow::Result<(String, u16)> {
    if let Some((host, port_str)) = target.rsplit_once(':') {
        let port: u16 = port_str.parse()?;
        Ok((host.to_string(), port))
    } else {
        Ok((target.to_string(), 443))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_parse_connect_target_with_port() {
        let (host, port) = parse_connect_target("api.github.com:443").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_target_without_port() {
        let (host, port) = parse_connect_target("api.github.com").unwrap();
        assert_eq!(host, "api.github.com");
        assert_eq!(port, 443);
    }

    #[test]
    fn test_parse_connect_target_custom_port() {
        let (host, port) = parse_connect_target("example.com:8080").unwrap();
        assert_eq!(host, "example.com");
        assert_eq!(port, 8080);
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
    fn test_launch_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "launch", "node", "server.js"]).unwrap();
        match cli.command {
            Commands::Launch { command, .. } => {
                assert_eq!(command, vec!["node", "server.js"]);
            }
            _ => panic!("expected Launch subcommand"),
        }
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
                image,
                output,
                command,
            } => {
                assert!(observe);
                assert_eq!(image, "ubuntu:24.04");
                assert_eq!(output.to_str().unwrap(), "/tmp/obs.jsonl");
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
    }
}
