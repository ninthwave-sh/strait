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
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio_rustls::TlsAcceptor;
use tracing::{info, warn};

use crate::config::ProxyContext;
use crate::credentials::CredentialStore;

/// Returns true if the given host should be MITM'd.
pub fn should_mitm(host: &str, mitm_hosts: &[String]) -> bool {
    mitm_hosts.iter().any(|h| h == host)
}

/// Perform MITM on the client connection.
///
/// 1. Accept TLS from the client using a leaf cert for `host`.
/// 2. Read the inner HTTP request (method, path, headers).
/// 3. Evaluate against Cedar policies (if a policy engine is provided).
/// 4. On DENY, return HTTP 403 with structured JSON body. No credential injected.
/// 5. On ALLOW (or no policy engine), inject credentials and forward upstream.
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

    let policy = ctx.policy_engine.as_deref();
    let credentials = ctx.credential_store.as_deref();
    let audit = &ctx.audit_logger;

    // Evaluate Cedar policy (if configured)
    if let Some(engine) = policy {
        let decision = engine.evaluate(host, &method, &path, &headers, &agent_id)?;

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

            // Log DENY audit event -- no credential injected
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
            let body =
                crate::policy::deny_response_body(host, &method, &path, &decision.policy_names);
            let body_bytes = serde_json::to_string(&body)?;
            let response = build_deny_response(&body_bytes);

            let tls_client_inner = buf_reader.into_inner();
            tls_client_inner.write_all(response.as_bytes()).await?;
            tls_client_inner.shutdown().await?;
            return Ok(());
        }

        // ALLOW path -- check for credential injection
        let credential_injected =
            inject_credential(host, &method, &path, &mut headers, None, credentials);

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
    } else {
        // No policy engine -- allow by default, still inject credentials
        let credential_injected =
            inject_credential(host, &method, &path, &mut headers, None, credentials);

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

    // --- Connection: close ---
    // Inject or replace Connection header with "close" on all forwarded requests
    // to force one-request-per-connection semantics (v0.1 keep-alive mitigation).
    headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
    headers.push(("Connection".to_string(), "close".to_string()));

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

    // Reconstruct and forward the request (headers now include injected credentials)
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

/// Build the HTTP 403 deny response string from a JSON body.
///
/// The response includes properly formatted HTTP/1.1 headers with no leading
/// whitespace and a Content-Length that exactly matches the body byte length.
fn build_deny_response(body_bytes: &str) -> String {
    format!(
        "HTTP/1.1 403 Forbidden\r\n\
Content-Type: application/json\r\n\
Content-Length: {}\r\n\
Connection: close\r\n\
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
        assert_eq!(lines[3], "Connection: close");

        // Empty line separating headers from body
        assert_eq!(lines[4], "");

        // Body
        assert_eq!(lines[5], body);
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

    // --- Connection: close tests ---

    #[test]
    fn connection_close_injected_into_headers() {
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Accept".to_string(), "application/json".to_string()),
        ];

        // Simulate the Connection: close injection logic from handle_mitm
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
        headers.push(("Connection".to_string(), "close".to_string()));

        let conn = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"));
        assert!(conn.is_some(), "Connection header should be present");
        assert_eq!(conn.unwrap().1, "close");
    }

    #[test]
    fn connection_close_replaces_existing_keepalive() {
        let mut headers = vec![
            ("Host".to_string(), "api.github.com".to_string()),
            ("Connection".to_string(), "keep-alive".to_string()),
        ];

        // Simulate the Connection: close injection logic
        headers.retain(|(k, _)| !k.eq_ignore_ascii_case("connection"));
        headers.push(("Connection".to_string(), "close".to_string()));

        let conn_count = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .count();
        assert_eq!(conn_count, 1, "should have exactly one Connection header");

        let conn = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("connection"))
            .unwrap();
        assert_eq!(conn.1, "close");
    }
}
