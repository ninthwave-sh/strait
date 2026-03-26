mod ca;
mod mitm;

use std::net::SocketAddr;
use std::path::PathBuf;

use clap::Parser;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

use crate::ca::SessionCa;
use crate::mitm::{handle_mitm, should_mitm};

#[derive(Parser)]
#[command(
    name = "strait",
    version,
    about = "HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging",
    after_help = "\
TLS TRUST:
  strait generates a session-local CA certificate on each startup.
  To trust it, pass --ca-cert-path to write the PEM, then configure your client:

    curl --cacert /tmp/strait-ca.pem --proxy http://127.0.0.1:<port> https://api.github.com/user

  Or concatenate with the system CA bundle:
    cat /tmp/strait-ca.pem >> /path/to/ca-bundle.crt
    SSL_CERT_FILE=/path/to/ca-bundle.crt HTTPS_PROXY=127.0.0.1:<port> curl https://api.github.com/user"
)]
struct Cli {
    /// Port to listen on (0 for ephemeral)
    #[arg(short, long, default_value = "0")]
    port: u16,

    /// Path to write the session CA certificate PEM.
    /// If not specified, the CA cert PEM is printed to stdout.
    #[arg(long, value_name = "PATH")]
    ca_cert_path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    // Generate session CA
    let session_ca = SessionCa::generate()?;
    info!("session CA generated");

    // Export CA cert PEM
    if let Some(ref path) = cli.ca_cert_path {
        std::fs::write(path, &session_ca.ca_cert_pem)?;
        info!(path = %path.display(), "CA cert written");
    } else {
        // Print to stdout so caller can capture it
        print!("{}", session_ca.ca_cert_pem);
    }

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], cli.port))).await?;
    let local_addr = listener.local_addr()?;
    info!(port = local_addr.port(), "strait listening");

    // Print port to stderr (stdout may have the CA cert)
    eprintln!("PORT={}", local_addr.port());

    loop {
        let (client, peer) = listener.accept().await?;
        let ca = session_ca.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, peer, &ca).await {
                warn!(error = %e, "connection error");
            }
        });
    }
}

/// Handle a single client connection.
///
/// For CONNECT requests: check if the target host should be MITM'd.
/// - Inspected hosts: terminate TLS, read inner HTTP, forward upstream.
/// - All other hosts: transparent TCP tunnel (no decryption).
async fn handle_connection(
    mut client: TcpStream,
    peer: SocketAddr,
    ca: &SessionCa,
) -> anyhow::Result<()> {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    let mut buf_client = BufReader::new(&mut client);
    let mut request_line = String::new();
    buf_client.read_line(&mut request_line).await?;

    let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
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

        if should_mitm(&host) {
            // MITM path: send 200, then terminate TLS with session CA
            let ts =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let event = serde_json::json!({
                "ts": ts,
                "type": "connect",
                "peer": peer.to_string(),
                "host": host,
                "port": port,
                "mitm": true
            });
            eprintln!("{}", serde_json::to_string(&event)?);

            // Send 200 Connection Established before starting TLS handshake
            client
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await?;

            // Hand off to MITM handler
            handle_mitm(client, &host, port, ca, &peer).await?;
        } else {
            // Passthrough path: transparent TCP tunnel
            let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;

            let ts =
                chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
            let event = serde_json::json!({
                "ts": ts,
                "type": "connect",
                "peer": peer.to_string(),
                "host": host,
                "port": port,
                "mitm": false
            });
            eprintln!("{}", serde_json::to_string(&event)?);

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
