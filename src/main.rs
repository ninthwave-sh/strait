use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use clap::{Parser, Subcommand};
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use strait::ca::SessionCa;
use strait::config::{ProxyContext, StraitConfig};
use strait::health;
use strait::mitm::{handle_mitm, should_mitm};
use strait::observe;
use strait::observe::ObservationLog;

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

    /// Initialize Cedar policy from observed live traffic.
    ///
    /// Starts a transparent MITM proxy that records all requests for the
    /// specified duration, then generates a permissive Cedar policy and
    /// schema from the observed traffic patterns.
    Init {
        /// Observe traffic for this duration, then generate policy.
        /// Accepts human-readable durations: 30s, 5m, 1h.
        #[arg(long)]
        observe: String,

        /// Write generated .cedar and .cedarschema files to this directory.
        /// If omitted, both are printed to stdout.
        #[arg(long, value_name = "DIR")]
        output_dir: Option<PathBuf>,

        /// Path to strait.toml for credential injection during observation.
        #[arg(short, long, value_name = "FILE")]
        config: Option<PathBuf>,
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
            strait::generate::generate(&observations, &output, &schema)?;
        }
        Commands::Proxy { config } => {
            run_proxy(config).await?;
        }
        Commands::Init {
            observe: observe_duration,
            output_dir,
            config,
        } => {
            run_observe_mode(&observe_duration, output_dir.as_deref(), config.as_deref()).await?;
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

/// Run observation mode: transparent MITM proxy that records traffic, then
/// generates a Cedar policy and schema after the specified duration.
async fn run_observe_mode(
    duration_str: &str,
    output_dir: Option<&std::path::Path>,
    config_path: Option<&std::path::Path>,
) -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let duration = observe::parse_duration(duration_str)?;

    // Optionally load config for credentials and MITM host list
    let config = match config_path {
        Some(path) => {
            let c = StraitConfig::load(path)?;
            info!(path = %path.display(), "configuration loaded for observation");
            Some(c)
        }
        None => None,
    };

    // Generate a session CA for MITM
    let session_ca = Arc::new(SessionCa::generate()?);
    info!("session CA generated for observation mode");

    // Write CA cert to a temp file so the user can trust it
    let ca_cert_path = config
        .as_ref()
        .map(|c| c.ca_cert_path.clone())
        .unwrap_or_else(|| std::env::temp_dir().join("strait-observe-ca.pem"));
    std::fs::write(&ca_cert_path, &session_ca.ca_cert_pem)?;
    eprintln!("CA_CERT={}", ca_cert_path.display());

    // Build credential store if config provides credentials
    let credential_store = match &config {
        Some(c) if !c.credential.is_empty() => {
            let store = strait::credentials::CredentialStore::from_entries(&c.credential)?;
            info!(
                count = c.credential.len(),
                "credentials loaded for observation"
            );
            Some(Arc::new(store))
        }
        _ => None,
    };

    // Determine MITM hosts (from config, or empty = MITM all CONNECT targets)
    let mitm_hosts: Vec<String> = config
        .as_ref()
        .map(|c| c.mitm.hosts.clone())
        .unwrap_or_default();

    let listen_addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let listener = TcpListener::bind(listen_addr).await?;
    let local_addr = listener.local_addr()?;
    eprintln!("PORT={}", local_addr.port());
    eprintln!(
        "strait observe mode listening on {} for {}",
        local_addr, duration_str
    );
    eprintln!(
        "Configure your client: HTTPS_PROXY=http://127.0.0.1:{}",
        local_addr.port()
    );

    let observation_log = Arc::new(ObservationLog::new());

    // Accept connections until the duration expires
    tokio::select! {
        _ = tokio::time::sleep(duration) => {
            eprintln!("\nObservation period complete ({duration_str}).");
        }
        _ = async {
            loop {
                match listener.accept().await {
                    Ok((client, peer)) => {
                        let ca = session_ca.clone();
                        let log = observation_log.clone();
                        let creds = credential_store.clone();
                        let hosts = mitm_hosts.clone();
                        tokio::spawn(async move {
                            if let Err(e) = handle_observe_connection(
                                client, peer, &ca, &log, creds.as_deref(), &hosts,
                            ).await {
                                warn!(error = %e, "observe connection error");
                            }
                        });
                    }
                    Err(e) => {
                        warn!(error = %e, "accept error");
                    }
                }
            }
        } => {}
    }

    // Generate and output the policy + schema
    let request_count = observation_log.len();
    eprintln!("Recorded {request_count} requests.");

    if request_count == 0 {
        eprintln!("No requests observed. No policy generated.");
        return Ok(());
    }

    let policy = observation_log.generate_policy();
    let schema = observation_log.generate_schema();

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir)?;
        let policy_path = dir.join("policy.cedar");
        let schema_path = dir.join("policy.cedarschema");
        std::fs::write(&policy_path, &policy)?;
        std::fs::write(&schema_path, &schema)?;
        eprintln!("Written: {}", policy_path.display());
        eprintln!("Written: {}", schema_path.display());
    } else {
        println!("--- policy.cedar ---");
        println!("{policy}");
        println!();
        println!("--- policy.cedarschema ---");
        println!("{schema}");
    }

    Ok(())
}

/// Handle a single connection in observation mode.
///
/// In observation mode, all CONNECT targets are MITM'd (or only configured
/// hosts if a config was provided). Requests are recorded to the observation
/// log and forwarded upstream without policy enforcement.
async fn handle_observe_connection(
    mut client: TcpStream,
    _peer: SocketAddr,
    session_ca: &SessionCa,
    log: &ObservationLog,
    credential_store: Option<&strait::credentials::CredentialStore>,
    mitm_hosts: &[String],
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

    if !method.eq_ignore_ascii_case("CONNECT") {
        return Ok(());
    }

    let (host, port) = parse_connect_target(target)?;

    // Drain remaining headers
    loop {
        let mut line = String::new();
        buf_client.read_line(&mut line).await?;
        if line.trim().is_empty() {
            break;
        }
    }
    drop(buf_client);

    // In observation mode: MITM all hosts if no config, or only configured hosts
    let should_observe = mitm_hosts.is_empty() || mitm_hosts.iter().any(|h| h == &host);

    if !should_observe {
        // Passthrough: transparent tunnel without observation
        let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        let _ = copy_bidirectional(&mut client, &mut upstream).await;
        return Ok(());
    }

    // Send 200 Connection Established
    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await?;

    // Generate leaf cert and accept TLS from client
    let (cert_chain, key) = session_ca.issue_leaf_cert(&host)?;
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)?;
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let mut tls_client = acceptor.accept(client).await?;

    // Read the inner HTTP request
    let mut buf_reader = BufReader::new(&mut tls_client);
    let mut inner_request_line = String::new();
    buf_reader.read_line(&mut inner_request_line).await?;
    let inner_request_line = inner_request_line.trim().to_string();

    let inner_parts: Vec<&str> = inner_request_line.split_whitespace().collect();
    if inner_parts.len() < 2 {
        return Ok(());
    }
    let inner_method = inner_parts[0].to_string();
    let inner_path = inner_parts[1].to_string();

    // Read headers
    let mut headers: Vec<(String, String)> = Vec::new();
    loop {
        let mut line = String::new();
        buf_reader.read_line(&mut line).await?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            headers.push((name.trim().to_string(), value.trim().to_string()));
        }
    }

    // Record to observation log
    log.record(&inner_method, &host, &inner_path);
    info!(
        method = inner_method.as_str(),
        host = host.as_str(),
        path = inner_path.as_str(),
        "observed request"
    );

    // Read body if present
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    let body: Option<Vec<u8>> = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut buf).await?;
        Some(buf)
    } else {
        None
    };

    // Optionally inject credentials
    if let Some(store) = credential_store {
        if let Some(cred) = store.get(&host) {
            if let Some(new_headers) =
                cred.inject(&inner_method, &inner_path, &headers, body.as_deref())
            {
                for (name, _) in &new_headers {
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
                headers.extend(new_headers);
            }
        }
    }

    // Force Connection: close
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
    headers.push(("Connection".to_string(), "close".to_string()));

    // Connect to upstream via TLS and forward the request
    let upstream_tcp = TcpStream::connect(format!("{host}:{port}")).await?;
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.clone())?;
    let mut tls_upstream = connector.connect(server_name, upstream_tcp).await?;

    // Reconstruct and forward the request
    let mut request_bytes = format!("{inner_method} {inner_path} HTTP/1.1\r\n");
    for (name, value) in &headers {
        request_bytes.push_str(&format!("{name}: {value}\r\n"));
    }
    request_bytes.push_str("\r\n");
    tls_upstream.write_all(request_bytes.as_bytes()).await?;

    if let Some(ref body_bytes) = body {
        tls_upstream.write_all(body_bytes).await?;
    }

    // Relay response back to client
    let buf = buf_reader.buffer().to_vec();
    let tls_client_inner = buf_reader.into_inner();
    if !buf.is_empty() {
        tls_upstream.write_all(&buf).await?;
    }

    let (mut client_read, mut client_write) = tokio::io::split(tls_client_inner);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(tls_upstream);

    tokio::select! {
        result = tokio::io::copy(&mut upstream_read, &mut client_write) => {
            let _ = result;
            let _ = client_write.shutdown().await;
            let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        }
        result = tokio::io::copy(&mut client_read, &mut upstream_write) => {
            let _ = result;
            let _ = upstream_write.shutdown().await;
            let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
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
