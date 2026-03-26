//! Selective MITM: terminate TLS for inspected hosts, passthrough for others.
//!
//! When the CONNECT target is an inspected host (e.g. api.github.com), the proxy
//! generates a per-host certificate signed by the session CA, terminates TLS,
//! reads the inner HTTP request, and forwards it upstream. For all other hosts
//! the connection is tunneled transparently without any decryption.

use std::sync::Arc;

use anyhow::Context;
use rustls::ServerConfig;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::info;

use crate::ca::SessionCa;

/// Set of hostnames that should be MITM'd for policy inspection.
const INSPECTED_HOSTS: &[&str] = &["api.github.com"];

/// Returns true if the given host should be MITM'd.
pub fn should_mitm(host: &str) -> bool {
    INSPECTED_HOSTS.contains(&host)
}

/// Perform MITM on the client connection.
///
/// 1. Accept TLS from the client using a leaf cert for `host`.
/// 2. Read the inner HTTP request (method, path, headers).
/// 3. Establish a real TLS connection to the upstream.
/// 4. Forward the request and relay the response.
pub async fn handle_mitm(
    client: TcpStream,
    host: &str,
    port: u16,
    ca: &SessionCa,
    peer: &std::net::SocketAddr,
) -> anyhow::Result<()> {
    // Generate a leaf certificate for this host
    let (cert_chain, key) = ca
        .issue_leaf_cert(host)
        .context("failed to issue leaf cert")?;

    // Build server TLS config (we act as server to the client)
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build server TLS config")?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS from the client
    let mut tls_client = acceptor
        .accept(client)
        .await
        .context("TLS accept from client failed")?;

    // Read the inner HTTP request
    let mut buf_reader = BufReader::new(&mut tls_client);

    // Read request line
    let mut request_line = String::new();
    buf_reader.read_line(&mut request_line).await?;
    let request_line = request_line.trim().to_string();

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        anyhow::bail!("invalid HTTP request line: {}", request_line);
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();

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

    // Log the inner HTTP request (this is the key MITM visibility)
    let ts = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    let header_map: serde_json::Value = headers
        .iter()
        .map(|(k, v)| (k.clone(), serde_json::Value::String(v.clone())))
        .collect::<serde_json::Map<String, serde_json::Value>>()
        .into();

    let event = serde_json::json!({
        "ts": ts,
        "type": "mitm_request",
        "peer": peer.to_string(),
        "host": host,
        "method": method,
        "path": path,
        "headers": header_map,
        "mitm": true
    });
    info!(
        host = host,
        method = method.as_str(),
        path = path.as_str(),
        "MITM: inner HTTP request visible"
    );
    eprintln!("{}", serde_json::to_string(&event)?);

    // Build the upstream request to forward
    // Connect to upstream with real TLS
    let upstream_tcp = TcpStream::connect(format!("{host}:{port}")).await?;

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
    let mut tls_upstream = connector.connect(server_name, upstream_tcp).await?;

    // Reconstruct and forward the request
    let mut request_bytes = format!("{method} {path} HTTP/1.1\r\n");
    for (name, value) in &headers {
        request_bytes.push_str(&format!("{name}: {value}\r\n"));
    }
    request_bytes.push_str("\r\n");
    tls_upstream.write_all(request_bytes.as_bytes()).await?;

    // Read content body if Content-Length present
    let content_length: Option<usize> = headers
        .iter()
        .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
        .and_then(|(_, v)| v.parse().ok());

    if let Some(len) = content_length {
        let mut body = vec![0u8; len];
        tokio::io::AsyncReadExt::read_exact(&mut buf_reader, &mut body).await?;
        tls_upstream.write_all(&body).await?;
    }

    // Relay the response back: bidirectional copy
    // Drop the BufReader wrapper to get back the inner stream
    // We need to handle buffered data + remaining stream
    let buf = buf_reader.buffer().to_vec();
    let tls_client_inner = buf_reader.into_inner();

    // Write any buffered data to upstream
    if !buf.is_empty() {
        tls_upstream.write_all(&buf).await?;
    }

    // Bidirectional relay: when one direction finishes (e.g. upstream sends
    // response and closes), shut down the other direction so the peer sees EOF.
    let (mut client_read, mut client_write) = tokio::io::split(tls_client_inner);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(tls_upstream);

    tokio::select! {
        result = tokio::io::copy(&mut upstream_read, &mut client_write) => {
            // Upstream finished sending (response complete). Shut down client write.
            let _ = result;
            let _ = client_write.shutdown().await;
            // Drain remaining client data to upstream
            let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        }
        result = tokio::io::copy(&mut client_read, &mut upstream_write) => {
            // Client finished sending. Shut down upstream write.
            let _ = result;
            let _ = upstream_write.shutdown().await;
            // Drain remaining upstream data to client
            let _ = tokio::io::copy(&mut upstream_read, &mut client_write).await;
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn github_api_is_inspected() {
        assert!(should_mitm("api.github.com"));
    }

    #[test]
    fn other_hosts_are_not_inspected() {
        assert!(!should_mitm("example.com"));
        assert!(!should_mitm("google.com"));
        assert!(!should_mitm("github.com"));
    }
}
