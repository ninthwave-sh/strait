mod audit;
mod ca;
pub mod config;
pub mod container;
pub mod credentials;
pub mod generate;
mod health;
mod mitm;
pub mod observe;
pub mod policy;
pub mod sigv4;
pub mod templates;

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::config::{ProxyContext, StraitConfig};
use crate::mitm::{handle_mitm, should_mitm};

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

    /// List or apply built-in Cedar policy templates.
    ///
    /// Templates provide ready-to-use Cedar policies for common access
    /// patterns (GitHub, AWS S3). Each includes a policy file and a
    /// matching Cedar schema.
    Template {
        #[command(subcommand)]
        action: TemplateAction,
    },
}

#[derive(Subcommand)]
enum TemplateAction {
    /// List available built-in policy templates.
    List,

    /// Copy a built-in template to disk or print to stdout.
    Apply {
        /// Name of the template to apply.
        name: String,

        /// Write .cedar and .cedarschema files to this directory.
        /// If omitted, both are printed to stdout.
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
        Commands::Proxy { config } => {
            run_proxy(config).await?;
        }
        Commands::Template { action } => {
            run_template_command(action)?;
        }
    }

    Ok(())
}

/// Run a `strait template` subcommand (list or apply).
fn run_template_command(action: TemplateAction) -> anyhow::Result<()> {
    match action {
        TemplateAction::List => {
            let templates = crate::templates::list();
            for t in templates {
                println!("  {:<30} {}", t.name, t.description);
            }
            Ok(())
        }
        TemplateAction::Apply { name, output_dir } => {
            crate::templates::apply(&name, output_dir.as_deref())
        }
    }
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

    // Start health check server if configured
    if let Some(ref health_config) = config.health {
        let health_ctx = ctx.clone();
        let health_port = health_config.port;
        tokio::spawn(async move {
            health::start_health_server(health_port, health_ctx).await;
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
}
