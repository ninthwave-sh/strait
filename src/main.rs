use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::net::TcpListener;
use tracing::{info, warn};

use strait::config;
use strait::generate;
use strait::observe::ObservationStream;
use strait::presets;
use strait::templates;

#[cfg(unix)]
use strait::config::sighup_reload_task;
use strait::config::{git_policy_poll_task, ProxyContext, StraitConfig};
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
enum PresetAction {
    /// List built-in launch presets.
    List,
    /// Apply a preset -- write devcontainer.json + strait.toml + policy.cedar.
    Apply {
        /// Preset name (e.g. "claude-code-devcontainer").
        name: String,

        /// Output directory for the generated files.
        #[arg(value_name = "DIR")]
        output_dir: PathBuf,
    },
}

#[derive(Subcommand)]
enum Commands {
    /// Start the HTTPS proxy for standalone integrations.
    ///
    /// strait generates a session-local CA certificate on each startup. The
    /// CA cert PEM is written to the path specified by `ca_cert_path` in
    /// strait.toml. Configure your client to trust it before routing
    /// traffic through the proxy.
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

    /// Explain a Cedar policy in plain English.
    ///
    /// Reads a Cedar policy file and prints a human-readable summary of what
    /// the policy allows and denies. Groups rules by action namespace so
    /// non-Cedar experts can review generated policies.
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

    /// Manage built-in devcontainer presets.
    ///
    /// A preset bundles a devcontainer.json, a strait.toml, and a starter
    /// Cedar policy for a supported first-run flow. Container lifecycle is
    /// the user's responsibility -- run the devcontainer with your tool of
    /// choice after applying the preset.
    Preset {
        #[command(subcommand)]
        action: PresetAction,
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
        Commands::Preset { action } => match action {
            PresetAction::List => {
                presets::print_list();
            }
            PresetAction::Apply { name, output_dir } => {
                presets::apply(&name, &output_dir)?;
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
        Commands::Proxy { config } => {
            run_proxy(config).await?;
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
    ctx.observation_stream = Some(obs_stream);
    let ctx = Arc::new(ctx);

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
    fn test_preset_list_subcommand_parses() {
        let cli = Cli::try_parse_from(["strait", "preset", "list"]).unwrap();
        match cli.command {
            Commands::Preset { action } => match action {
                PresetAction::List => {}
                PresetAction::Apply { .. } => panic!("expected PresetAction::List"),
            },
            _ => panic!("expected Preset subcommand"),
        }
    }

    #[test]
    fn test_preset_apply_subcommand_parses() {
        let cli = Cli::try_parse_from([
            "strait",
            "preset",
            "apply",
            "claude-code-devcontainer",
            "./my-agent",
        ])
        .unwrap();
        match cli.command {
            Commands::Preset { action } => match action {
                PresetAction::Apply { name, output_dir } => {
                    assert_eq!(name, "claude-code-devcontainer");
                    assert_eq!(output_dir.to_str().unwrap(), "./my-agent");
                }
                PresetAction::List => panic!("expected PresetAction::Apply"),
            },
            _ => panic!("expected Preset subcommand"),
        }
    }

    #[test]
    fn test_preset_apply_requires_name_and_output_dir() {
        assert!(Cli::try_parse_from(["strait", "preset", "apply"]).is_err());
        assert!(
            Cli::try_parse_from(["strait", "preset", "apply", "claude-code-devcontainer"]).is_err()
        );
    }

    #[test]
    fn test_help_lists_supported_subcommands() {
        let cmd = Cli::command();
        let subcommand_names: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();

        for expected in [
            "proxy", "generate", "test", "explain", "diff", "init", "template", "preset",
        ] {
            assert!(
                subcommand_names.contains(&expected),
                "missing expected subcommand '{expected}' in {subcommand_names:?}"
            );
        }
    }

    #[test]
    fn test_launch_subcommand_is_removed() {
        // The host-side `strait launch` orchestrator was removed in H-ICDP-5.
        // Container lifecycle is now the user's responsibility (devcontainer
        // feature, sandcastle, or direct docker run). Guard against a reviewer
        // accidentally reintroducing the subcommand.
        let cmd = Cli::command();
        let names: Vec<&str> = cmd.get_subcommands().map(|s| s.get_name()).collect();
        for retired in ["launch", "session", "service", "watch"] {
            assert!(
                !names.contains(&retired),
                "retired subcommand '{retired}' has reappeared: {names:?}"
            );
        }

        // And the CLI should reject them rather than silently accepting.
        for retired in ["launch", "session", "service", "watch"] {
            assert!(
                Cli::try_parse_from(["strait", retired]).is_err(),
                "`strait {retired}` should not parse"
            );
        }
    }

    #[test]
    fn test_preset_help_does_not_reference_launch() {
        // `strait launch` is gone. Make sure preset help text does not
        // suggest it as a follow-up command.
        let mut cmd = Cli::command();
        let preset = cmd
            .find_subcommand_mut("preset")
            .expect("preset subcommand exists");
        let help = render_help(preset);
        assert!(
            !help.contains("strait launch"),
            "preset help should not reference the retired launch command: {help}"
        );
    }
}
