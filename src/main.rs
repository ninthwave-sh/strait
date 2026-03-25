use std::net::SocketAddr;

use clap::Parser;
use tokio::io::copy_bidirectional;
use tokio::net::{TcpListener, TcpStream};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "strait", version, about = "HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging")]
struct Cli {
    /// Port to listen on (0 for ephemeral)
    #[arg(short, long, default_value = "0")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], cli.port))).await?;
    let local_addr = listener.local_addr()?;
    info!(port = local_addr.port(), "strait listening");

    // Print port to stdout for callers to parse
    println!("{}", local_addr.port());

    loop {
        let (client, peer) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = handle_connection(client, peer).await {
                warn!(error = %e, "connection error");
            }
        });
    }
}

/// Handle a single client connection.
///
/// For now: read the CONNECT line, establish upstream TCP, tunnel bytes.
/// Future: selective MITM, Cedar policy evaluation, and credential injection.
async fn handle_connection(mut client: TcpStream, peer: SocketAddr) -> anyhow::Result<()> {
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

        // Establish upstream connection
        let mut upstream = TcpStream::connect(format!("{host}:{port}")).await?;

        let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
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
