//! Selective MITM: terminate TLS for inspected hosts, passthrough for others.
//!
//! When the CONNECT target is an inspected host (e.g. api.github.com), the proxy
//! generates a per-host certificate signed by the session CA, terminates TLS,
//! reads the inner HTTP request, evaluates it against Cedar policies, and
//! either returns a 403 or forwards it upstream with credential injection.
//! For all other hosts the connection is tunneled transparently without any decryption.

use std::sync::Arc;
use std::time::Instant;

use anyhow::Context;
use rustls::ServerConfig;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::ProxyContext;
use crate::credentials::CredentialStore;

/// Returns true if the given host should be MITM'd.
pub fn should_mitm(host: &str, mitm_hosts: &[String]) -> bool {
    mitm_hosts.iter().any(|h| h == host)
}

/// Perform MITM on the client connection with HTTP/1.1 keep-alive.
///
/// After the initial TLS handshake, the proxy loops over sequential HTTP
/// requests on the same connection:
///
/// 1. Read the inner HTTP request (method, path, headers, body).
/// 2. Evaluate against Cedar policies (if a policy engine is provided).
/// 3. On DENY, return HTTP 403 and continue the loop.
/// 4. On ALLOW (or no policy engine), inject credentials, forward upstream,
///    read the response, and relay it back to the client.
///
/// The loop exits when:
/// - The client sends `Connection: close`.
/// - EOF on the client connection.
/// - The upstream sends `Connection: close` in its response.
/// - The configurable idle timeout fires (default 30 s).
/// - An unrecoverable error occurs (e.g. 413 Payload Too Large).
pub async fn handle_mitm(
    client: TcpStream,
    host: &str,
    port: u16,
    ctx: &ProxyContext,
) -> anyhow::Result<()> {
    // Generate a leaf certificate for this host
    let (cert_chain, key) = ctx
        .session_ca
        .issue_leaf_cert(host)
        .context("failed to issue leaf cert")?;

    // Build server TLS config (we act as server to the client)
    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, key)
        .context("failed to build server TLS config")?;

    let acceptor = TlsAcceptor::from(Arc::new(server_config));

    // Accept TLS from the client
    let tls_client = acceptor
        .accept(client)
        .await
        .context("TLS accept from client failed")?;

    // Split into independent read/write halves for the keep-alive loop.
    let (read_half, mut write_half) = tokio::io::split(tls_client);
    let mut buf_reader = BufReader::new(read_half);

    loop {
        // --- Read the next HTTP request (with idle timeout) ---
        let mut request_line = String::new();
        let read_result = tokio::time::timeout(
            ctx.keepalive_timeout,
            buf_reader.read_line(&mut request_line),
        )
        .await;

        match read_result {
            Err(_) => {
                // Idle timeout — close connection cleanly
                info!(
                    host = host,
                    "keep-alive idle timeout, closing MITM connection"
                );
                break;
            }
            Ok(Ok(0)) => {
                // EOF — client closed the connection
                break;
            }
            Ok(Err(e)) => {
                return Err(e.into());
            }
            Ok(Ok(_)) => {
                // Got data — continue processing
            }
        }

        let request_line = request_line.trim().to_string();
        let parts: Vec<&str> = request_line.split_whitespace().collect();
        if parts.len() < 2 {
            anyhow::bail!("invalid HTTP request line: {}", request_line);
        }
        let method = parts[0].to_string();
        let path = parts[1].to_string();

        // Read headers
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut client_wants_close = false;
        loop {
            let mut line = String::new();
            buf_reader.read_line(&mut line).await?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                break;
            }
            if let Some((name, value)) = trimmed.split_once(':') {
                let name = name.trim().to_string();
                let value = value.trim().to_string();
                if name.eq_ignore_ascii_case("connection") && value.eq_ignore_ascii_case("close") {
                    client_wants_close = true;
                }
                headers.push((name, value));
            }
        }

        // --- Body buffering ---
        // Read the request body *before* credential injection so that signing
        // schemes (e.g. SigV4) have access to the body hash. Requests without
        // Content-Length pass None; oversized bodies are rejected with 413.
        let content_length: Option<usize> = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("content-length"))
            .and_then(|(_, v)| v.parse().ok());

        let body: Option<Vec<u8>> = if let Some(len) = content_length {
            if len > ctx.max_body_size {
                let response = build_payload_too_large_response(len, ctx.max_body_size);
                write_half.write_all(response.as_bytes()).await?;
                write_half.flush().await?;
                // 413 includes Connection: close — cannot skip the unread body
                break;
            }
            let mut buf = vec![0u8; len];
            AsyncReadExt::read_exact(&mut buf_reader, &mut buf).await?;
            Some(buf)
        } else {
            None
        };

        // --- Agent identity extraction ---
        // Extract the agent identity from the configured header. If absent, use the
        // configured default (e.g. "anonymous"). Always strip the identity header
        // from outbound requests to prevent spoofing upstream.
        let identity_header = &ctx.identity_header;
        let agent_id = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(identity_header))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| ctx.identity_default.clone());

        // Strip the identity header before forwarding upstream
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(identity_header));

        // Start timing policy evaluation
        let eval_start = Instant::now();

        let policy_guard = ctx.policy_engine.as_ref().map(|swap| swap.load());
        let credentials = ctx.credential_store.as_deref();
        let audit = &ctx.audit_logger;

        // --- Policy evaluation ---
        let mut denied = false;

        if let Some(ref engine) = policy_guard {
            let action = format!("http:{method}");
            let decision = engine.evaluate(host, &action, &path, &headers, &agent_id)?;

            let policy_display = if decision.policy_names.is_empty() {
                "default-deny".to_string()
            } else {
                decision.policy_names.join(", ")
            };

            if !decision.allowed {
                // Build a human-readable denial reason. If the matching policy has
                // a @reason("...") annotation, use that; otherwise use a generic format.
                let denial_reason = if !decision.policy_reasons.is_empty() {
                    decision.policy_reasons.join("; ")
                } else {
                    format!(
                        "Request denied by policy '{}': {} {} on {}",
                        policy_display, method, path, host
                    )
                };

                // Log DENY audit event — no credential injected
                audit.log_decision(
                    host,
                    port,
                    &method,
                    &path,
                    &agent_id,
                    "deny",
                    &decision.policy_names,
                    false,
                    Some(&denial_reason),
                    eval_start,
                );

                warn!(
                    host = host,
                    method = method.as_str(),
                    path = path.as_str(),
                    agent = agent_id.as_str(),
                    policy = policy_display.as_str(),
                    "DENY: request blocked by Cedar policy"
                );

                // Return 403 with structured JSON body
                let body_json =
                    crate::policy::deny_response_body(host, &method, &path, &decision.policy_names);
                let body_bytes = serde_json::to_string(&body_json)?;
                let response = build_deny_response(&body_bytes);
                write_half.write_all(response.as_bytes()).await?;
                write_half.flush().await?;

                denied = true;
            } else {
                // ALLOW path — check for credential injection
                let credential_injected = inject_credential(
                    host,
                    &method,
                    &path,
                    &mut headers,
                    body.as_deref(),
                    credentials,
                );

                // Log ALLOW audit event
                audit.log_decision(
                    host,
                    port,
                    &method,
                    &path,
                    &agent_id,
                    "allow",
                    &decision.policy_names,
                    credential_injected,
                    None,
                    eval_start,
                );

                info!(
                    host = host,
                    method = method.as_str(),
                    path = path.as_str(),
                    agent = agent_id.as_str(),
                    policy = policy_display.as_str(),
                    credential_injected = credential_injected,
                    "ALLOW: request permitted by Cedar policy"
                );
            }
        } else {
            // No policy engine — allow by default, still inject credentials
            let credential_injected = inject_credential(
                host,
                &method,
                &path,
                &mut headers,
                body.as_deref(),
                credentials,
            );

            audit.log_decision(
                host,
                port,
                &method,
                &path,
                &agent_id,
                "allow",
                &["no-policy".to_string()],
                credential_injected,
                None,
                eval_start,
            );

            info!(
                host = host,
                method = method.as_str(),
                path = path.as_str(),
                agent = agent_id.as_str(),
                credential_injected = credential_injected,
                "ALLOW: no policy engine configured"
            );
        }

        if denied {
            // After deny, continue the loop unless client requested close
            if client_wants_close {
                break;
            }
            continue;
        }

        // --- Forward to upstream ---
        let upstream_tcp = TcpStream::connect(format!("{host}:{port}")).await?;

        let mut root_store = rustls::RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())?;
        let tls_upstream = connector.connect(server_name, upstream_tcp).await?;

        let (upstream_read, mut upstream_write) = tokio::io::split(tls_upstream);

        // Reconstruct and forward the request (headers now include injected credentials)
        let mut request_bytes = format!("{method} {path} HTTP/1.1\r\n");
        for (name, value) in &headers {
            request_bytes.push_str(&format!("{name}: {value}\r\n"));
        }
        request_bytes.push_str("\r\n");
        upstream_write.write_all(request_bytes.as_bytes()).await?;

        // Write the buffered body (already read before credential injection)
        if let Some(ref body_bytes) = body {
            upstream_write.write_all(body_bytes).await?;
        }
        upstream_write.flush().await?;

        // Read the upstream response and relay it back to the client
        let mut upstream_reader = BufReader::new(upstream_read);
        let response_info =
            relay_upstream_response(&method, &mut upstream_reader, &mut write_half).await?;

        // Check exit conditions
        if client_wants_close || response_info.upstream_wants_close {
            break;
        }
    }

    // Shut down the client TLS connection
    let _ = write_half.shutdown().await;
    Ok(())
}

/// Metadata extracted from a relayed upstream HTTP response.
struct ResponseInfo {
    /// True if the upstream sent `Connection: close` or the body was
    /// framed by connection close (no Content-Length, no chunked).
    upstream_wants_close: bool,
}

/// Read an HTTP response from `upstream` and forward it to `client`.
///
/// Handles Content-Length, Transfer-Encoding: chunked, and read-until-EOF
/// body framing. Returns metadata about the response for keep-alive decisions.
async fn relay_upstream_response<R, W>(
    request_method: &str,
    upstream: &mut BufReader<R>,
    client: &mut W,
) -> anyhow::Result<ResponseInfo>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    // Read and forward status line
    let mut status_line = String::new();
    upstream.read_line(&mut status_line).await?;
    client.write_all(status_line.as_bytes()).await?;

    // Parse status code for body-framing decisions
    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    // Read and forward headers, extracting framing info
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut connection_close = false;

    loop {
        let mut line = String::new();
        upstream.read_line(&mut line).await?;
        client.write_all(line.as_bytes()).await?;

        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }

        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse().ok();
            } else if key.eq_ignore_ascii_case("transfer-encoding") {
                chunked = val.to_ascii_lowercase().contains("chunked");
            } else if key.eq_ignore_ascii_case("connection") {
                connection_close = val.eq_ignore_ascii_case("close");
            }
        }
    }

    // Determine if this response carries a body.
    // 1xx, 204, 304 never have a body; HEAD responses omit the body.
    let has_body = !matches!(status_code, 100..=199 | 204 | 304)
        && !request_method.eq_ignore_ascii_case("HEAD");

    if has_body {
        if let Some(len) = content_length {
            // Fixed-length body
            let mut remaining = len;
            let mut buf = vec![0u8; 8192];
            while remaining > 0 {
                let to_read = buf.len().min(remaining);
                let n = AsyncReadExt::read(upstream, &mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
                remaining -= n;
            }
        } else if chunked {
            // Chunked transfer encoding
            loop {
                // Read chunk size line
                let mut chunk_line = String::new();
                upstream.read_line(&mut chunk_line).await?;
                client.write_all(chunk_line.as_bytes()).await?;

                let size_str = chunk_line.trim().split(';').next().unwrap_or("0");
                let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);

                if chunk_size == 0 {
                    // Terminal chunk — read and forward trailers + final CRLF
                    loop {
                        let mut trailer = String::new();
                        upstream.read_line(&mut trailer).await?;
                        client.write_all(trailer.as_bytes()).await?;
                        if trailer.trim().is_empty() {
                            break;
                        }
                    }
                    break;
                }

                // Read chunk data
                let mut remaining = chunk_size;
                let mut buf = vec![0u8; 8192];
                while remaining > 0 {
                    let to_read = buf.len().min(remaining);
                    let n = AsyncReadExt::read(upstream, &mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    client.write_all(&buf[..n]).await?;
                    remaining -= n;
                }
                // Read and forward the trailing \r\n after chunk data
                let mut crlf = [0u8; 2];
                AsyncReadExt::read_exact(upstream, &mut crlf).await?;
                client.write_all(&crlf).await?;
            }
        } else {
            // No Content-Length, no chunked: read until upstream closes (EOF)
            let mut buf = vec![0u8; 8192];
            loop {
                let n = AsyncReadExt::read(upstream, &mut buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
            }
            // Connection is closed by definition
            connection_close = true;
        }
    }

    client.flush().await?;

    Ok(ResponseInfo {
        upstream_wants_close: connection_close,
    })
}

/// Build the HTTP 413 Payload Too Large response string.
///
/// Returned when a request's Content-Length exceeds the configured maximum
/// body size for MITM buffering.
fn build_payload_too_large_response(content_length: usize, max_body_size: usize) -> String {
    let body = serde_json::json!({
        "error": "payload_too_large",
        "message": format!(
            "Request body size ({content_length} bytes) exceeds maximum allowed ({max_body_size} bytes)"
        ),
        "content_length": content_length,
        "max_body_size": max_body_size,
    });
    let body_bytes = serde_json::to_string(&body).expect("JSON serialization cannot fail");
    format!(
        "HTTP/1.1 413 Payload Too Large\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
\r\n\
{}",
        body_bytes.len(),
        body_bytes
    )
}

/// Build the HTTP 403 deny response string from a JSON body.
///
/// The response includes properly formatted HTTP/1.1 headers with no leading
/// whitespace and a Content-Length that exactly matches the body byte length.
/// No `Connection: close` is included — the keep-alive loop continues after
/// a deny, allowing the client to retry or send a different request.
fn build_deny_response(body_bytes: &str) -> String {
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
\r\n\
{}",
        body_bytes.len(),
        body_bytes
    )
}

/// Inject credential headers if one is configured for the target host.
///
/// Delegates to the [`Credential::inject`] trait method, which allows each
/// credential type to compute its own headers. Bearer tokens return a static
/// header/value; future types (e.g. SigV4) can inspect the full request.
///
/// Returns true if a credential was injected.
fn inject_credential(
    host: &str,
    method: &str,
    path: &str,
    headers: &mut Vec<(String, String)>,
    body: Option<&[u8]>,
    credentials: Option<&CredentialStore>,
) -> bool {
    if let Some(store) = credentials {
        if let Some(cred) = store.get(host) {
            if let Some(new_headers) = cred.inject(method, path, headers, body) {
                // Remove any existing headers that match the injected names (case-insensitive)
                for (name, _) in &new_headers {
                    headers.retain(|(k, _)| !k.eq_ignore_ascii_case(name));
                }
                headers.extend(new_headers);
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CredentialEntryConfig;

    #[test]
    fn github_api_is_inspected() {
        let hosts = vec!["api.github.com".to_string()];
        assert!(should_mitm("api.github.com", &hosts));
    }

    #[test]
    fn other_hosts_are_not_inspected() {
        let hosts = vec!["api.github.com".to_string()];
        assert!(!should_mitm("example.com", &hosts));
        assert!(!should_mitm("google.com", &hosts));
        assert!(!should_mitm("github.com", &hosts));
    }

    #[test]
    fn empty_mitm_hosts_means_no_inspection() {
        let hosts: Vec<String> = vec![];
        assert!(!should_mitm("api.github.com", &hosts));
        assert!(!should_mitm("example.com", &hosts));
    }

    #[test]
    fn inject_credential_adds_header() {
        std::env::set_var("STRAIT_TEST_INJECT_1", "ghp_inject_test");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "token ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_INJECT_1".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        let injected = inject_credential(
            "api.github.com",
            "GET",
            "/repos",
            &mut headers,
            None,
            Some(&store),
        );
        assert!(injected, "credential should be injected");

        let auth = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(auth.is_some(), "Authorization header should be present");
        assert_eq!(auth.unwrap().1, "token ghp_inject_test");

        std::env::remove_var("STRAIT_TEST_INJECT_1");
    }

    #[test]
    fn inject_credential_replaces_existing_header() {
        std::env::set_var("STRAIT_TEST_INJECT_2", "ghp_new_token");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "token ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_INJECT_2".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Authorization".to_string(), "token old_value".to_string()),
        ];

        let injected = inject_credential(
            "api.github.com",
            "GET",
            "/",
            &mut headers,
            None,
            Some(&store),
        );
        assert!(injected);

        // Should only have one Authorization header
        let auth_count = headers.iter().filter(|(k, _)| k == "Authorization").count();
        assert_eq!(
            auth_count, 1,
            "should have exactly one Authorization header"
        );

        let auth = headers.iter().find(|(k, _)| k == "Authorization").unwrap();
        assert_eq!(auth.1, "token ghp_new_token");

        std::env::remove_var("STRAIT_TEST_INJECT_2");
    }

    #[test]
    fn inject_credential_no_store_returns_false() {
        let mut headers = vec![("Host".to_string(), "api.github.com".to_string())];
        let injected = inject_credential("api.github.com", "GET", "/", &mut headers, None, None);
        assert!(!injected);
    }

    #[test]
    fn deny_response_has_no_leading_whitespace_in_headers() {
        let body = r#"{"error":"policy_denied"}"#;
        let response = build_deny_response(body);

        // Split into lines by \r\n
        let lines: Vec<&str> = response.split("\r\n").collect();

        // Status line
        assert_eq!(lines[0], "HTTP/1.1 403 Forbidden");

        // Header lines should not have leading whitespace
        assert_eq!(lines[1], "Content-Type: application/json");
        assert_eq!(lines[2], format!("Content-Length: {}", body.len()));

        // No Connection: close — keep-alive loop continues after deny

        // Empty line separating headers from body
        assert_eq!(lines[3], "");

        // Body
        assert_eq!(lines[4], body);
    }

    #[test]
    fn deny_response_content_length_matches_body() {
        let body_json = serde_json::json!({
            "error": "policy_denied",
            "message": "Request denied by Cedar policy: test-policy",
            "host": "api.github.com",
            "method": "DELETE",
            "path": "/repos/org/repo",
            "policy": "test-policy"
        });
        let body_bytes = serde_json::to_string(&body_json).unwrap();
        let response = build_deny_response(&body_bytes);

        // Extract Content-Length header value
        let content_length_line = response
            .split("\r\n")
            .find(|line| line.starts_with("Content-Length:"))
            .expect("Content-Length header must be present");
        let claimed_length: usize = content_length_line
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse()
            .unwrap();

        // Extract actual body (everything after \r\n\r\n)
        let body_start = response.find("\r\n\r\n").unwrap() + 4;
        let actual_body = &response[body_start..];

        assert_eq!(
            claimed_length,
            actual_body.len(),
            "Content-Length ({}) must match actual body length ({})",
            claimed_length,
            actual_body.len()
        );
        assert_eq!(actual_body, body_bytes);
    }

    #[test]
    fn inject_credential_unknown_host_returns_false() {
        std::env::set_var("STRAIT_TEST_INJECT_3", "test");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "token ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_INJECT_3".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let mut headers = vec![("Host".to_string(), "example.com".to_string())];

        let injected =
            inject_credential("example.com", "GET", "/", &mut headers, None, Some(&store));
        assert!(
            !injected,
            "no credential should be injected for unknown host"
        );

        std::env::remove_var("STRAIT_TEST_INJECT_3");
    }

    // --- Agent identity extraction tests ---

    /// Helper: extract agent_id from headers using the same logic as handle_mitm.
    fn extract_agent_id(
        headers: &[(String, String)],
        identity_header: &str,
        identity_default: &str,
    ) -> String {
        headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(identity_header))
            .map(|(_, v)| v.clone())
            .unwrap_or_else(|| identity_default.to_string())
    }

    /// Helper: strip identity header from headers.
    fn strip_identity_header(headers: &mut Vec<(String, String)>, identity_header: &str) {
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case(identity_header));
    }

    #[test]
    fn agent_identity_extracted_from_header() {
        let headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("X-Strait-Agent".to_string(), "ci-bot".to_string()),
        ];

        let agent = extract_agent_id(&headers, "X-Strait-Agent", "anonymous");
        assert_eq!(agent, "ci-bot");
    }

    #[test]
    fn missing_identity_header_uses_default() {
        let headers = vec![("Host".to_string(), "api.github.com".to_string())];

        let agent = extract_agent_id(&headers, "X-Strait-Agent", "anonymous");
        assert_eq!(agent, "anonymous");
    }

    #[test]
    fn identity_header_stripped_from_forwarded_request() {
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("X-Strait-Agent".to_string(), "ci-bot".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        strip_identity_header(&mut headers, "X-Strait-Agent");

        assert!(
            !headers.iter().any(|(k, _)| k == "X-Strait-Agent"),
            "identity header should be stripped"
        );
        assert_eq!(headers.len(), 2, "only non-identity headers should remain");
    }

    #[test]
    fn identity_header_case_insensitive() {
        let headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("x-strait-agent".to_string(), "ci-bot".to_string()),
        ];

        let agent = extract_agent_id(&headers, "X-Strait-Agent", "anonymous");
        assert_eq!(agent, "ci-bot", "case-insensitive header match");
    }

    // --- Keep-alive: Connection header pass-through tests ---

    #[test]
    fn connection_header_not_injected_on_outbound() {
        // Verify that handle_mitm no longer force-injects Connection: close.
        // The client's Connection header should be forwarded as-is.
        let headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        // No Connection header present — none should be added
        let conn = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"));
        assert!(conn.is_none(), "Connection: close should not be injected");
    }

    #[test]
    fn client_keepalive_header_preserved() {
        let headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];

        // Connection: keep-alive from client should be preserved (not replaced)
        let conn = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .unwrap();
        assert_eq!(
            conn.1, "keep-alive",
            "client keep-alive should be preserved, not overwritten"
        );
    }

    #[test]
    fn deny_response_has_no_connection_close() {
        let body = r#"{"error":"policy_denied"}"#;
        let response = build_deny_response(body);
        assert!(
            !response.contains("Connection: close"),
            "deny response should not include Connection: close"
        );
    }

    // --- Body buffering tests ---

    #[test]
    fn inject_credential_receives_body_for_post() {
        std::env::set_var("STRAIT_TEST_BODY_1", "ghp_body_test");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "token ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_BODY_1".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Content-Length".to_string(), "13".to_string()),
        ];
        let body = b"hello, world!";

        let injected = inject_credential(
            "api.github.com",
            "POST",
            "/repos",
            &mut headers,
            Some(body),
            Some(&store),
        );
        assert!(injected, "credential should be injected with body present");

        let auth = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(auth.is_some());
        assert_eq!(auth.unwrap().1, "token ghp_body_test");

        std::env::remove_var("STRAIT_TEST_BODY_1");
    }

    #[test]
    fn inject_credential_receives_none_for_get() {
        std::env::set_var("STRAIT_TEST_BODY_2", "ghp_get_test");

        let entries = vec![CredentialEntryConfig {
            host: Some("api.github.com".to_string()),
            host_pattern: None,
            header: "Authorization".to_string(),
            value_prefix: "token ".to_string(),
            source: "env".to_string(),
            env_var: Some("STRAIT_TEST_BODY_2".to_string()),
            credential_type: "bearer".to_string(),
            access_key_id_var: None,
            secret_access_key_var: None,
            session_token_var: None,
        }];

        let store = CredentialStore::from_entries(&entries).unwrap();
        let mut headers = vec![("Host".to_string(), "api.github.com".to_string())];

        let injected = inject_credential(
            "api.github.com",
            "GET",
            "/repos",
            &mut headers,
            None,
            Some(&store),
        );
        assert!(injected, "credential should be injected even without body");

        let auth = headers.iter().find(|(k, _)| k == "Authorization");
        assert!(auth.is_some());
        assert_eq!(auth.unwrap().1, "token ghp_get_test");

        std::env::remove_var("STRAIT_TEST_BODY_2");
    }

    #[test]
    fn payload_too_large_response_format() {
        let response = build_payload_too_large_response(20_000_000, 10_485_760);

        // Should be a proper HTTP 413 response
        let lines: Vec<&str> = response.split("\r\n").collect();
        assert_eq!(lines[0], "HTTP/1.1 413 Payload Too Large");
        assert_eq!(lines[1], "Content-Type: application/json");
        assert!(lines[2].starts_with("Content-Length: "));
        assert_eq!(lines[3], "Connection: close");
        assert_eq!(lines[4], "");

        // Body should contain the error details
        let body_start = response.find("\r\n\r\n").unwrap() + 4;
        let body = &response[body_start..];
        let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
        assert_eq!(parsed["error"], "payload_too_large");
        assert_eq!(parsed["content_length"], 20_000_000);
        assert_eq!(parsed["max_body_size"], 10_485_760);
    }

    #[test]
    fn payload_too_large_content_length_matches_body() {
        let response = build_payload_too_large_response(50_000_000, 10_000_000);

        let content_length_line = response
            .split("\r\n")
            .find(|line| line.starts_with("Content-Length:"))
            .expect("Content-Length header must be present");
        let claimed_length: usize = content_length_line
            .strip_prefix("Content-Length: ")
            .unwrap()
            .parse()
            .unwrap();

        let body_start = response.find("\r\n\r\n").unwrap() + 4;
        let actual_body = &response[body_start..];

        assert_eq!(
            claimed_length,
            actual_body.len(),
            "Content-Length ({}) must match actual body length ({})",
            claimed_length,
            actual_body.len()
        );
    }
}
