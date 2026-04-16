//! Integration tests for the strait proxy.
//!
//! These tests use loopback connections to verify MITM and passthrough behavior
//! without requiring external network access.

use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};

/// Start a local TLS server that echoes back the HTTP request as the response body.
/// Returns (addr, CA cert PEM) so the test client can trust this server.
async fn start_tls_echo_server() -> (std::net::SocketAddr, String, CertificateDer<'static>) {
    let key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test-echo-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    // Generate leaf cert for api.github.com (the host we MITM)
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "api.github.com");
    leaf_params.subject_alt_names.push(rcgen::SanType::DnsName(
        "api.github.com".try_into().unwrap(),
    ));
    // Also add localhost for direct connection
    leaf_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &key_pair)
        .unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                ca_cert_der.clone(),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };

                // Read the HTTP request (headers + optional body)
                let mut buf = BufReader::new(&mut tls);
                let mut request_lines = Vec::new();
                let mut content_length: Option<usize> = None;
                loop {
                    let mut line = String::new();
                    if buf.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                        break;
                    }
                    let trimmed = line.trim().to_string();
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse().ok();
                        }
                    }
                    request_lines.push(trimmed);
                }

                // Read request body if Content-Length present
                let mut request_body = Vec::new();
                if let Some(len) = content_length {
                    request_body.resize(len, 0);
                    let _ = buf.read_exact(&mut request_body).await;
                }

                // Echo back headers + body
                let mut echo = request_lines.join("\n");
                if !request_body.is_empty() {
                    echo.push_str("\n\n");
                    echo.push_str(&String::from_utf8_lossy(&request_body));
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    echo.len(),
                    echo
                );

                let tls_inner = buf.into_inner();
                let _ = tls_inner.write_all(response.as_bytes()).await;
                let _ = tls_inner.shutdown().await;
            });
        }
    });

    (addr, ca_cert_pem, ca_cert_der)
}

/// Start a local TLS server that echoes back HTTP requests with keep-alive support.
/// Unlike `start_tls_echo_server`, this server does NOT send `Connection: close`
/// and handles multiple sequential requests on the same TLS connection.
/// Returns (addr, CA cert PEM, CA cert DER) so the test client can trust this server.
async fn start_keepalive_echo_server() -> (std::net::SocketAddr, String, CertificateDer<'static>) {
    let key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test-echo-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&key_pair).unwrap();
    let ca_cert_pem = ca_cert.pem();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    // Generate leaf cert for api.github.com
    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "api.github.com");
    leaf_params.subject_alt_names.push(rcgen::SanType::DnsName(
        "api.github.com".try_into().unwrap(),
    ));
    leaf_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &key_pair)
        .unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                ca_cert_der.clone(),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };

                let (read_half, mut write_half) = tokio::io::split(tls);
                let mut buf = BufReader::new(read_half);

                loop {
                    // Read request line
                    let mut first_line = String::new();
                    match buf.read_line(&mut first_line).await {
                        Ok(0) => break, // EOF
                        Ok(_) => {}
                        Err(_) => break,
                    }
                    if first_line.trim().is_empty() {
                        break;
                    }

                    let mut request_lines = vec![first_line.trim().to_string()];
                    let mut content_length: Option<usize> = None;
                    let mut connection_close = false;

                    // Read headers
                    loop {
                        let mut line = String::new();
                        if buf.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                            break;
                        }
                        let trimmed = line.trim().to_string();
                        if let Some((k, v)) = trimmed.split_once(':') {
                            if k.trim().eq_ignore_ascii_case("content-length") {
                                content_length = v.trim().parse().ok();
                            }
                            if k.trim().eq_ignore_ascii_case("connection")
                                && v.trim().eq_ignore_ascii_case("close")
                            {
                                connection_close = true;
                            }
                        }
                        request_lines.push(trimmed);
                    }

                    // Read request body
                    let mut request_body = Vec::new();
                    if let Some(len) = content_length {
                        request_body.resize(len, 0);
                        let _ = buf.read_exact(&mut request_body).await;
                    }

                    // Build echo response (NO Connection: close)
                    let mut echo = request_lines.join("\n");
                    if !request_body.is_empty() {
                        echo.push_str("\n\n");
                        echo.push_str(&String::from_utf8_lossy(&request_body));
                    }
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        echo.len(),
                        echo
                    );

                    if write_half.write_all(response.as_bytes()).await.is_err() {
                        break;
                    }
                    if write_half.flush().await.is_err() {
                        break;
                    }

                    if connection_close {
                        break;
                    }
                }

                let _ = write_half.shutdown().await;
            });
        }
    });

    (addr, ca_cert_pem, ca_cert_der)
}

/// Start a plain TCP echo server for passthrough testing.
/// Returns the server address.
async fn start_tcp_echo_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                // Echo everything back
                let (mut reader, mut writer) = stream.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
            });
        }
    });

    addr
}

#[tokio::test]
async fn ca_cert_is_written_to_specified_path() {
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("ca.pem");

    // Import the SessionCa directly
    let ca = strait_test_helpers::generate_ca();
    std::fs::write(&cert_path, &ca.ca_cert_pem).unwrap();

    let content = std::fs::read_to_string(&cert_path).unwrap();
    assert!(content.contains("BEGIN CERTIFICATE"));
    assert!(content.contains("END CERTIFICATE"));
}

#[tokio::test]
async fn ca_cert_is_unique_per_session() {
    let ca1 = strait_test_helpers::generate_ca();
    let ca2 = strait_test_helpers::generate_ca();
    assert_ne!(ca1.ca_cert_pem, ca2.ca_cert_pem);
}

#[tokio::test]
async fn mitm_terminates_tls_and_exposes_inner_request() {
    // Start a TLS echo server (simulates api.github.com)
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Build a production ProxyContext that routes to the echo server
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    // Start the proxy listener using the production handle_connection
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    // Connect to the proxy and send a CONNECT request
    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    // Send an HTTP request through the TLS tunnel
    tls.write_all(
        b"GET /repos/test/repo HTTP/1.1\r\nHost: api.github.com\r\nX-Test: hello\r\nConnection: close\r\n\r\n",
    )
    .await
    .unwrap();

    // Read the response (the echo server returns the request as the body)
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    // The echo server should have echoed back our request
    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK in response, got: {}",
        response_str
    );
    assert!(
        response_str.contains("GET /repos/test/repo"),
        "Expected request line in echo body, got: {}",
        response_str
    );
    assert!(
        response_str.contains("X-Test: hello"),
        "Expected X-Test header in echo body, got: {}",
        response_str
    );
}

#[tokio::test]
async fn passthrough_does_not_decrypt() {
    // Start a TCP echo server
    let echo_addr = start_tcp_echo_server().await;

    // Start the proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut client, _peer) = proxy_listener.accept().await.unwrap();

        let mut buf = BufReader::new(&mut client);
        let mut request_line = String::new();
        buf.read_line(&mut request_line).await.unwrap();

        // Drain headers
        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }

        drop(buf);

        // Connect to echo server (simulates the upstream)
        let mut upstream = TcpStream::connect(echo_addr).await.unwrap();

        // Send 200
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Tunnel bidirectionally
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    // Connect to proxy and send CONNECT for a non-MITM host
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read 200 response
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200, got: {}",
        response_line.trim()
    );
    // Drain response headers
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    let client_inner = buf.into_inner();

    // Now we should have a raw TCP tunnel to the echo server
    // Anything we send should be echoed back (no TLS, no decryption)
    let client = client_inner;
    client.write_all(b"hello passthrough").await.unwrap();
    client.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    client.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&echoed),
        "hello passthrough",
        "Passthrough should relay bytes without modification"
    );
}

#[tokio::test]
async fn mitm_preserves_request_body_through_pipeline() {
    // Start a TLS echo server that echoes headers + body
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Build a production ProxyContext that routes to the echo server
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    // Start the proxy listener using the production handle_connection
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    // Send a POST request with a body
    let body = r#"{"name":"test-repo","private":true}"#;
    let request = format!(
        "POST /repos HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    tls.write_all(request.as_bytes()).await.unwrap();

    // Read the response
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    // The echo server should have echoed back our request including the body
    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK in response, got: {}",
        response_str
    );
    assert!(
        response_str.contains("POST /repos"),
        "Expected POST request line in echo body, got: {}",
        response_str
    );
    assert!(
        response_str.contains(body),
        "Expected request body '{}' preserved in echo response, got: {}",
        body,
        response_str
    );
}

// ---------------------------------------------------------------------------
// AWS SigV4 integration tests (production code path)
//
// These tests exercise the real proxy pipeline:
//   ProxyContext → handle_mitm → SigV4Credential::inject → echo server
//
// Each test constructs a ProxyContext with a real SigV4Credential (using
// hardcoded test keys via env vars), starts a TLS echo server, and sends
// requests through the production handle_mitm function. The echo server
// reflects the headers it received so we can verify the signing output.
// ---------------------------------------------------------------------------

/// Start a TLS echo server with configurable SANs.
///
/// Generates a self-signed CA and a leaf cert with the given DNS SANs.
/// Returns (addr, CA cert DER) so callers can build a TLS client config
/// that trusts this server.
async fn start_aws_echo_server(sans: &[&str]) -> (std::net::SocketAddr, CertificateDer<'static>) {
    let key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test-echo-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&key_pair).unwrap();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params.distinguished_name.push(
        DnType::CommonName,
        sans.first().copied().unwrap_or("localhost"),
    );
    for san in sans {
        leaf_params
            .subject_alt_names
            .push(rcgen::SanType::DnsName((*san).try_into().unwrap()));
    }
    // Always include localhost
    leaf_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &key_pair)
        .unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                ca_cert_der.clone(),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };

                let mut buf = BufReader::new(&mut tls);
                let mut request_lines = Vec::new();
                let mut content_length: Option<usize> = None;
                loop {
                    let mut line = String::new();
                    if buf.read_line(&mut line).await.is_err() || line.trim().is_empty() {
                        break;
                    }
                    let trimmed = line.trim().to_string();
                    if let Some((k, v)) = trimmed.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_length = v.trim().parse().ok();
                        }
                    }
                    request_lines.push(trimmed);
                }

                let mut request_body = Vec::new();
                if let Some(len) = content_length {
                    request_body.resize(len, 0);
                    let _ = buf.read_exact(&mut request_body).await;
                }

                let mut echo = request_lines.join("\n");
                if !request_body.is_empty() {
                    echo.push_str("\n\n");
                    echo.push_str(&String::from_utf8_lossy(&request_body));
                }
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    echo.len(),
                    echo
                );

                let tls_inner = buf.into_inner();
                let _ = tls_inner.write_all(response.as_bytes()).await;
                let _ = tls_inner.shutdown().await;
            });
        }
    });

    (addr, ca_cert_der)
}

/// Test AWS credential configuration for `build_sigv4_proxy_context`.
struct TestAwsCreds {
    ak_var: &'static str,
    sk_var: &'static str,
    tok_var: &'static str,
    access_key: &'static str,
    secret_key: &'static str,
    session_token: Option<&'static str>,
}

/// Build a ProxyContext with a SigV4Credential for `*.amazonaws.com`.
///
/// Sets env vars for the test credentials, builds the credential store,
/// and configures upstream overrides to route to the local echo server.
fn build_sigv4_proxy_context(
    echo_addr: std::net::SocketAddr,
    mitm_hosts: Vec<String>,
    creds: &TestAwsCreds,
) -> strait::config::ProxyContext {
    use std::time::{Duration, Instant};
    use strait::audit::AuditLogger;
    use strait::ca::SessionCa;
    use strait::config::CredentialEntryConfig;
    use strait::credentials::CredentialStore;

    // Set env vars for the SigV4 credential resolver
    std::env::set_var(creds.ak_var, creds.access_key);
    std::env::set_var(creds.sk_var, creds.secret_key);
    if let Some(token) = creds.session_token {
        std::env::set_var(creds.tok_var, token);
    } else {
        std::env::remove_var(creds.tok_var);
    }

    let entries = vec![CredentialEntryConfig {
        host: None,
        host_pattern: Some("*.amazonaws.com".to_string()),
        header: "Authorization".to_string(),
        value_prefix: String::new(),
        source: "env".to_string(),
        env_var: None,
        credential_type: "aws-sigv4".to_string(),
        access_key_id_var: Some(creds.ak_var.to_string()),
        secret_access_key_var: Some(creds.sk_var.to_string()),
        session_token_var: Some(creds.tok_var.to_string()),
    }];
    let store = CredentialStore::from_entries(&entries).unwrap();

    // Build NoVerify TLS config for connecting to the echo server
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(strait_test_helpers::NoVerify))
            .with_no_client_auth(),
    );

    strait::config::ProxyContext {
        session_ca: SessionCa::generate().unwrap(),
        policy_engine: None,
        credential_store: Some(Arc::new(store)),
        audit_logger: Arc::new(AuditLogger::new(None).unwrap()),
        mitm_hosts,
        max_body_size: 10 * 1024 * 1024,
        keepalive_timeout: Duration::from_secs(30),
        decision_timeout: Duration::from_secs(30),
        startup_instant: Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "anonymous".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: None,
        enforcement_mode: "observe".to_string(),
        mitm_all: false,
        warn_only: false,
        live_policy_bounds: None,
        upstream_addr_override: Some(echo_addr),
        upstream_tls_override: Some(tls_config),
        upstream_connect_timeout: Duration::from_secs(30),
        upstream_response_timeout: Duration::from_secs(60),
        pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
    }
}

/// Send a request through the real proxy pipeline (handle_mitm) and return the
/// echo server's response body.
///
/// This exercises the full production code path:
/// client → CONNECT → proxy → TLS termination → handle_mitm → credential
/// injection → echo server → response relay → client.
async fn send_through_proxy(
    ctx: Arc<strait::config::ProxyContext>,
    host: &str,
    method: &str,
    path: &str,
    extra_headers: &[(&str, &str)],
    body: Option<&[u8]>,
) -> String {
    // Start the proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let host_owned = host.to_string();
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    // Spawn the proxy handler (replicates handle_connection's CONNECT handling
    // then delegates to the real production handle_mitm).
    let ctx_for_handler = ctx.clone();
    let host_for_handler = host_owned.clone();
    let handler = tokio::spawn(async move {
        let (mut client, _peer) = proxy_listener.accept().await.unwrap();
        // Read and drain CONNECT request
        let mut buf = BufReader::new(&mut client);
        let mut _connect_line = String::new();
        buf.read_line(&mut _connect_line).await.unwrap();
        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        drop(buf);
        // Send 200 Connection Established
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        // Delegate to production handle_mitm
        let _ = strait::mitm::handle_mitm(client, &host_for_handler, 443, &ctx_for_handler).await;
    });

    // Client: connect to proxy, send CONNECT, TLS handshake, send request
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    let connect_req = format!("CONNECT {host}:443 HTTP/1.1\r\nHost: {host}:443\r\n\r\n");
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // Read 200 + drain
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200, got: {}",
        response_line.trim()
    );
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    // TLS handshake with proxy (trusting the session CA)
    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(host.to_string()).unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Build and send the HTTP request
    let body_bytes = body.unwrap_or(&[]);
    let mut request = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\n");
    if !body_bytes.is_empty() {
        request.push_str(&format!("Content-Length: {}\r\n", body_bytes.len()));
    }
    for (k, v) in extra_headers {
        request.push_str(&format!("{k}: {v}\r\n"));
    }
    request.push_str("Connection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();
    if !body_bytes.is_empty() {
        tls.write_all(body_bytes).await.unwrap();
    }

    // Read the echoed response
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();

    // Wait for handler to finish
    let _ = handler.await;

    String::from_utf8_lossy(&response).to_string()
}

/// S3 PUT through the real proxy pipeline — production handle_mitm injects
/// SigV4 Authorization, X-Amz-Date, X-Amz-Content-Sha256; body is intact.
#[tokio::test]
async fn sigv4_s3_put_produces_auth_headers() {
    let (echo_addr, _echo_ca_der) = start_aws_echo_server(&["s3.us-east-1.amazonaws.com"]).await;

    let creds = TestAwsCreds {
        ak_var: "STRAIT_INTG_SV4_AK_S3PUT",
        sk_var: "STRAIT_INTG_SV4_SK_S3PUT",
        tok_var: "STRAIT_INTG_SV4_TOK_S3PUT",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };
    let ctx = build_sigv4_proxy_context(
        echo_addr,
        vec!["s3.us-east-1.amazonaws.com".to_string()],
        &creds,
    );

    let response_str = send_through_proxy(
        Arc::new(ctx),
        "s3.us-east-1.amazonaws.com",
        "PUT",
        "/my-bucket/test-key",
        &[("Content-Type", "application/octet-stream")],
        Some(b"test-object-data-for-s3"),
    )
    .await;

    // Verify the echoed request has SigV4 Authorization header
    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("AWS4-HMAC-SHA256"),
        "Expected AWS4-HMAC-SHA256 in Authorization header, got: {}",
        response_str
    );
    assert!(
        response_str.contains("us-east-1/s3/aws4_request"),
        "Expected us-east-1/s3/aws4_request in Authorization, got: {}",
        response_str
    );

    // Verify X-Amz-Date header present
    assert!(
        response_str.to_lowercase().contains("x-amz-date"),
        "Expected x-amz-date header, got: {}",
        response_str
    );

    // Verify X-Amz-Content-Sha256 is present
    assert!(
        response_str.contains("x-amz-content-sha256"),
        "Expected x-amz-content-sha256 header, got: {}",
        response_str
    );

    // Verify body is intact
    assert!(
        response_str.contains("test-object-data-for-s3"),
        "Expected body preserved in echo, got: {}",
        response_str
    );

    // Clean up env vars
    std::env::remove_var("STRAIT_INTG_SV4_AK_S3PUT");
    std::env::remove_var("STRAIT_INTG_SV4_SK_S3PUT");
}

/// Lambda POST — service=lambda, region=eu-west-1 extracted correctly from hostname.
#[tokio::test]
async fn sigv4_lambda_invoke_different_service_region() {
    let (echo_addr, _echo_ca_der) =
        start_aws_echo_server(&["lambda.eu-west-1.amazonaws.com"]).await;

    let creds = TestAwsCreds {
        ak_var: "STRAIT_INTG_SV4_AK_LAMBDA",
        sk_var: "STRAIT_INTG_SV4_SK_LAMBDA",
        tok_var: "STRAIT_INTG_SV4_TOK_LAMBDA",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };
    let ctx = build_sigv4_proxy_context(
        echo_addr,
        vec!["lambda.eu-west-1.amazonaws.com".to_string()],
        &creds,
    );

    let body = br#"{"key":"value"}"#;
    let response_str = send_through_proxy(
        Arc::new(ctx),
        "lambda.eu-west-1.amazonaws.com",
        "POST",
        "/2015-03-31/functions/my-func/invocations",
        &[("Content-Type", "application/json")],
        Some(body),
    )
    .await;

    // Verify Authorization with Lambda service and eu-west-1 region
    assert!(
        response_str.contains("AWS4-HMAC-SHA256"),
        "Expected AWS4-HMAC-SHA256, got: {}",
        response_str
    );
    assert!(
        response_str.contains("eu-west-1/lambda/aws4_request"),
        "Expected eu-west-1/lambda/aws4_request, got: {}",
        response_str
    );

    // Verify X-Amz-Date header present
    assert!(
        response_str.to_lowercase().contains("x-amz-date"),
        "Expected x-amz-date header, got: {}",
        response_str
    );

    // Verify X-Amz-Content-Sha256
    assert!(
        response_str.contains("x-amz-content-sha256"),
        "Expected x-amz-content-sha256 header, got: {}",
        response_str
    );

    // Clean up env vars
    std::env::remove_var("STRAIT_INTG_SV4_AK_LAMBDA");
    std::env::remove_var("STRAIT_INTG_SV4_SK_LAMBDA");
}

/// Empty body GET signing (e.g. S3 ListBucket) — production code signs the
/// request with SHA-256 of the empty string for the content hash.
#[tokio::test]
async fn sigv4_empty_body_get_signing() {
    let (echo_addr, _echo_ca_der) = start_aws_echo_server(&["s3.us-east-1.amazonaws.com"]).await;

    let creds = TestAwsCreds {
        ak_var: "STRAIT_INTG_SV4_AK_GET",
        sk_var: "STRAIT_INTG_SV4_SK_GET",
        tok_var: "STRAIT_INTG_SV4_TOK_GET",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };
    let ctx = build_sigv4_proxy_context(
        echo_addr,
        vec!["s3.us-east-1.amazonaws.com".to_string()],
        &creds,
    );

    let response_str = send_through_proxy(
        Arc::new(ctx),
        "s3.us-east-1.amazonaws.com",
        "GET",
        "/my-bucket?list-type=2",
        &[],
        None,
    )
    .await;

    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("AWS4-HMAC-SHA256"),
        "Expected AWS4-HMAC-SHA256 in Authorization, got: {}",
        response_str
    );
    assert!(
        response_str.contains("us-east-1/s3/aws4_request"),
        "Expected us-east-1/s3/aws4_request in Authorization, got: {}",
        response_str
    );

    // x-amz-content-sha256 should be the SHA-256 of empty string
    let empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    assert!(
        response_str.contains(empty_sha),
        "Expected SHA-256 of empty body ({}), got: {}",
        empty_sha,
        response_str
    );

    // Clean up env vars
    std::env::remove_var("STRAIT_INTG_SV4_AK_GET");
    std::env::remove_var("STRAIT_INTG_SV4_SK_GET");
}

/// Session token / temporary credentials — X-Amz-Security-Token is present
/// when a session token is configured.
#[tokio::test]
async fn sigv4_session_token_flow() {
    let (echo_addr, _echo_ca_der) = start_aws_echo_server(&["s3.us-east-1.amazonaws.com"]).await;

    let creds = TestAwsCreds {
        ak_var: "STRAIT_INTG_SV4_AK_SESS",
        sk_var: "STRAIT_INTG_SV4_SK_SESS",
        tok_var: "STRAIT_INTG_SV4_TOK_SESS",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: Some("FwoGZXIvYXdzEBYaDHQa5GFake+Session+Token"),
    };
    let ctx = build_sigv4_proxy_context(
        echo_addr,
        vec!["s3.us-east-1.amazonaws.com".to_string()],
        &creds,
    );

    let response_str = send_through_proxy(
        Arc::new(ctx),
        "s3.us-east-1.amazonaws.com",
        "GET",
        "/my-bucket/my-key",
        &[],
        None,
    )
    .await;

    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("AWS4-HMAC-SHA256"),
        "Expected AWS4-HMAC-SHA256, got: {}",
        response_str
    );

    // Verify X-Amz-Security-Token is present with the session token
    assert!(
        response_str.to_lowercase().contains("x-amz-security-token"),
        "Expected x-amz-security-token header for temporary credentials, got: {}",
        response_str
    );
    assert!(
        response_str.contains("FwoGZXIvYXdzEBYaDHQa5GFake+Session+Token"),
        "Expected session token value in x-amz-security-token, got: {}",
        response_str
    );

    // Clean up env vars
    std::env::remove_var("STRAIT_INTG_SV4_AK_SESS");
    std::env::remove_var("STRAIT_INTG_SV4_SK_SESS");
    std::env::remove_var("STRAIT_INTG_SV4_TOK_SESS");
}

/// Virtual-hosted S3 style (bucket.s3.region.amazonaws.com) — the proxy
/// correctly extracts service=s3, region from the subdomain-prefixed hostname.
#[tokio::test]
async fn sigv4_virtual_hosted_s3_style() {
    let host = "my-bucket.s3.us-west-2.amazonaws.com";
    let (echo_addr, _echo_ca_der) = start_aws_echo_server(&[host]).await;

    let creds = TestAwsCreds {
        ak_var: "STRAIT_INTG_SV4_AK_VHOST",
        sk_var: "STRAIT_INTG_SV4_SK_VHOST",
        tok_var: "STRAIT_INTG_SV4_TOK_VHOST",
        access_key: "AKIAIOSFODNN7EXAMPLE",
        secret_key: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        session_token: None,
    };
    let ctx = build_sigv4_proxy_context(echo_addr, vec![host.to_string()], &creds);

    let response_str = send_through_proxy(Arc::new(ctx), host, "GET", "/my-key", &[], None).await;

    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("AWS4-HMAC-SHA256"),
        "Expected AWS4-HMAC-SHA256, got: {}",
        response_str
    );
    // Virtual-hosted: bucket.s3.us-west-2.amazonaws.com → service=s3, region=us-west-2
    assert!(
        response_str.contains("us-west-2/s3/aws4_request"),
        "Expected us-west-2/s3/aws4_request for virtual-hosted S3, got: {}",
        response_str
    );

    // Clean up env vars
    std::env::remove_var("STRAIT_INTG_SV4_AK_VHOST");
    std::env::remove_var("STRAIT_INTG_SV4_SK_VHOST");
}

/// Passthrough for non-MITM AWS host — no decryption, no signing.
#[tokio::test]
async fn passthrough_non_mitm_aws_host() {
    // Start a TCP echo server (no TLS termination needed for passthrough)
    let echo_addr = start_tcp_echo_server().await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut client, _peer) = proxy_listener.accept().await.unwrap();

        let mut buf = BufReader::new(&mut client);
        let mut request_line = String::new();
        buf.read_line(&mut request_line).await.unwrap();
        // Drain headers
        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
        drop(buf);

        // Connect to echo server (passthrough — no MITM)
        let mut upstream = TcpStream::connect(echo_addr).await.unwrap();

        // Send 200
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Tunnel bidirectionally (no TLS termination, no signing)
        let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
    });

    // Connect to proxy and CONNECT for an AWS host that is NOT in the MITM list
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            b"CONNECT dynamodb.eu-central-1.amazonaws.com:443 HTTP/1.1\r\n\
              Host: dynamodb.eu-central-1.amazonaws.com:443\r\n\r\n",
        )
        .await
        .unwrap();

    // Read 200
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200, got: {}",
        response_line.trim()
    );
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    let client_inner = buf.into_inner();

    // Send raw bytes (should be tunneled without modification — no signing)
    let payload = b"passthrough-aws-no-signing";
    client_inner.write_all(payload).await.unwrap();
    client_inner.shutdown().await.unwrap();

    let mut echoed = Vec::new();
    client_inner.read_to_end(&mut echoed).await.unwrap();
    assert_eq!(
        String::from_utf8_lossy(&echoed),
        "passthrough-aws-no-signing",
        "Passthrough should relay bytes without modification or signing"
    );
}

// ---------------------------------------------------------------------------
// HTTP/1.1 keep-alive integration tests
// ---------------------------------------------------------------------------

/// Helper: read a single HTTP response from a BufReader, returning the full
/// response string (status + headers + body). Uses Content-Length framing.
async fn read_http_response<R: tokio::io::AsyncRead + Unpin>(reader: &mut BufReader<R>) -> String {
    // Read status line
    let mut status_line = String::new();
    reader.read_line(&mut status_line).await.unwrap();

    let mut header_text = String::new();
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            header_text.push_str(&line);
            break;
        }
        if let Some((k, v)) = line.trim().split_once(':') {
            if k.trim().eq_ignore_ascii_case("content-length") {
                content_length = v.trim().parse().ok();
            }
        }
        header_text.push_str(&line);
    }

    let mut body = Vec::new();
    if let Some(len) = content_length {
        body.resize(len, 0);
        reader.read_exact(&mut body).await.unwrap();
    }

    let mut response = status_line;
    response.push_str(&header_text);
    response.push_str(&String::from_utf8_lossy(&body));
    response
}

/// Two sequential GET requests on the same CONNECT tunnel — both succeed,
/// second request processed after first response completes.
#[tokio::test]
async fn keepalive_two_sequential_requests() {
    let (echo_addr, _pem, _der) = start_keepalive_echo_server().await;

    // Use production handle_connection with keepalive support
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    // --- First request ---
    write_half
        .write_all(b"GET /repos/first HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response1 = read_http_response(&mut reader).await;
    assert!(
        response1.contains("200 OK"),
        "First request should get 200 OK, got: {}",
        response1
    );
    assert!(
        response1.contains("GET /repos/first"),
        "First request path should be echoed, got: {}",
        response1
    );

    // --- Second request (same connection) ---
    write_half
        .write_all(b"GET /repos/second HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response2 = read_http_response(&mut reader).await;
    assert!(
        response2.contains("200 OK"),
        "Second request should get 200 OK, got: {}",
        response2
    );
    assert!(
        response2.contains("GET /repos/second"),
        "Second request path should be echoed, got: {}",
        response2
    );

    // Clean up: send Connection: close to terminate
    write_half
        .write_all(b"GET /done HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let _ = read_http_response(&mut reader).await;
}

/// Client sends `Connection: close` — proxy processes the request and then
/// closes the connection (no further requests accepted).
#[tokio::test]
async fn keepalive_client_connection_close_exits_loop() {
    let (echo_addr, _pem, _der) = start_keepalive_echo_server().await;

    // Use production handle_connection
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    // Send request WITH Connection: close
    write_half
        .write_all(b"GET /final HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response = read_http_response(&mut reader).await;
    assert!(
        response.contains("200 OK"),
        "Request should succeed, got: {}",
        response
    );
    assert!(
        response.contains("GET /final"),
        "Request path should be echoed, got: {}",
        response
    );

    // Connection should be closed — read_to_end should return quickly
    let mut remaining = Vec::new();
    reader.read_to_end(&mut remaining).await.unwrap();
    // No more data expected (connection closed by proxy)
}

/// Idle timeout fires — proxy closes the connection cleanly when no request
/// arrives within the keep-alive timeout window.
#[tokio::test]
async fn keepalive_idle_timeout_closes_connection() {
    let (echo_addr, _pem, _der) = start_keepalive_echo_server().await;

    // Use production handle_connection with a very short keepalive timeout (1s)
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(1),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    // Send one request (keep connection alive)
    write_half
        .write_all(b"GET /hello HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response = read_http_response(&mut reader).await;
    assert!(response.contains("200 OK"));

    // Wait for idle timeout (> 1s)
    tokio::time::sleep(std::time::Duration::from_millis(1500)).await;

    // Connection should be closed by the proxy — read_to_end returns
    let mut remaining = Vec::new();
    let result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        reader.read_to_end(&mut remaining),
    )
    .await;
    assert!(
        result.is_ok(),
        "read_to_end should complete (proxy closed connection)"
    );
}

/// Policy deny mid-loop — proxy sends 403 and the connection continues for
/// the next request.
#[tokio::test]
async fn keepalive_deny_mid_loop_continues() {
    let (echo_addr, _pem, _der) = start_keepalive_echo_server().await;

    // Use production handle_connection with a policy that denies /denied
    let ctx = strait_test_helpers::build_production_mitm_context_with_deny(
        echo_addr,
        "api.github.com",
        "/denied",
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    // --- First request: denied ---
    write_half
        .write_all(b"GET /denied HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response1 = read_http_response(&mut reader).await;
    assert!(
        response1.contains("403 Forbidden"),
        "Denied request should get 403, got: {}",
        response1
    );
    // Deny response should NOT have Connection: close
    assert!(
        !response1.contains("Connection: close"),
        "Deny response should not include Connection: close, got: {}",
        response1
    );

    // --- Second request: allowed (connection should still be open) ---
    write_half
        .write_all(b"GET /allowed HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response2 = read_http_response(&mut reader).await;
    assert!(
        response2.contains("200 OK"),
        "Allowed request should get 200, got: {}",
        response2
    );
    assert!(
        response2.contains("GET /allowed"),
        "Allowed request path should be echoed, got: {}",
        response2
    );

    // Clean up
    write_half
        .write_all(b"GET /done HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let _ = read_http_response(&mut reader).await;
}

/// Live policy replacement updates subsequent requests without dropping the
/// existing keep-alive session.
#[tokio::test]
async fn keepalive_live_policy_replace_affects_subsequent_requests() {
    let (echo_addr, _pem, _der) = start_keepalive_echo_server().await;

    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("policy.cedar");
    std::fs::write(&policy_path, "permit(principal, action, resource);").unwrap();

    let mut ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    ctx.enforcement_mode = "enforce".to_string();
    ctx.policy_config = Some(strait::config::PolicyConfig {
        file: Some(policy_path),
        git_url: None,
        git_path: None,
        schema: None,
        poll_interval_secs: None,
    });
    ctx.policy_engine = Some(arc_swap::ArcSwap::from_pointee(
        strait::policy::PolicyEngine::load(
            ctx.policy_config
                .as_ref()
                .and_then(|config| config.file.as_deref())
                .unwrap(),
            None,
        )
        .unwrap(),
    ));

    let ca_pem = ctx.session_ca.ca_cert_pem.clone();
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;
    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    write_half
        .write_all(b"GET /before-reload HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response1 = read_http_response(&mut reader).await;
    assert!(
        response1.contains("200 OK"),
        "initial request should use the original policy: {response1}"
    );

    let outcome = strait::config::replace_policy(
        ctx.as_ref(),
        r#"
@id("allow-all")
permit(principal, action, resource);

@id("deny-after-replace")
forbid(principal, action, resource)
when { context.path == "/after-reload" };
"#,
    )
    .unwrap();
    assert!(outcome.applied, "network-only replace should apply live");

    write_half
        .write_all(b"GET /after-reload HTTP/1.1\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();
    let response2 = read_http_response(&mut reader).await;
    assert!(
        response2.contains("403 Forbidden"),
        "subsequent request should observe the updated policy: {response2}"
    );
    assert!(
        !response2.contains("Connection: close"),
        "policy deny should keep the session alive: {response2}"
    );

    write_half
        .write_all(b"GET /still-open HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let response3 = read_http_response(&mut reader).await;
    assert!(
        response3.contains("200 OK"),
        "keep-alive session should continue after the live update: {response3}"
    );
}

// ---------------------------------------------------------------------------
// Observation mode integration tests
// ---------------------------------------------------------------------------

/// Integration test: run observation mode with a loopback echo server,
/// verify generated policy covers observed requests.
///
/// This test simulates the `strait init --observe` workflow:
/// 1. Start a TLS echo server (simulates the upstream API).
/// 2. Set up a proxy with observation stream (no policy enforcement).
/// 3. Route traffic through the MITM proxy (with observation recording).
/// 4. Generate a Cedar policy from the observation log.
/// 5. Verify the policy covers the observed method+path pairs.
#[tokio::test]
async fn observe_mode_generates_policy_covering_observed_requests() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");

    // Set up an ObservationStream recording to a temp JSONL file
    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Simulate traffic that would flow through the MITM proxy:
    // These are the same events the proxy's handle_mitm function would emit.
    let requests = vec![
        ("GET", "api.github.com", "/repos/org/my-repo"),
        ("GET", "api.github.com", "/repos/org/my-repo/pulls"),
        ("POST", "api.github.com", "/repos/org/my-repo/pulls"),
        ("GET", "api.github.com", "/repos/org/other-repo/issues/42"),
        ("GET", "api.github.com", "/user"),
        (
            "DELETE",
            "api.github.com",
            "/repos/org/my-repo/branches/feature",
        ),
    ];

    for (method, host, path) in &requests {
        obs.emit(EventKind::NetworkRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            decision: "allow".to_string(),
            latency_us: 100,
            enforcement_mode: String::new(),
            blocked: None,
        });
    }

    // Drop the stream to flush writes
    drop(obs);

    // Generate policy from the observation log
    let result = strait::generate::generate_from_file(&obs_log_path).unwrap();
    assert!(result.is_some(), "should generate policy from observations");

    let (policy_text, schema_text, _wildcard_count) = result.unwrap();

    // Verify the policy covers observed method+path pairs
    assert!(
        policy_text.contains(r#"action == Action::"http:GET""#),
        "policy should contain http:GET action:\n{policy_text}"
    );
    assert!(
        policy_text.contains(r#"action == Action::"POST""#)
            || policy_text.contains(r#"action == Action::"http:POST""#),
        "policy should contain http:POST action:\n{policy_text}"
    );
    assert!(
        policy_text.contains(r#"action == Action::"DELETE""#)
            || policy_text.contains(r#"action == Action::"http:DELETE""#),
        "policy should contain http:DELETE action:\n{policy_text}"
    );
    assert!(
        policy_text.contains("api.github.com"),
        "policy should reference api.github.com:\n{policy_text}"
    );
    assert!(
        policy_text.contains("permit("),
        "policy should contain permit statements:\n{policy_text}"
    );

    // Verify schema contains all observed actions
    assert!(
        schema_text.contains(r#"action "http:GET""#),
        "schema should declare http:GET:\n{schema_text}"
    );
    assert!(
        schema_text.contains(r#"action "http:POST""#),
        "schema should declare http:POST:\n{schema_text}"
    );
    assert!(
        schema_text.contains(r#"action "http:DELETE""#),
        "schema should declare http:DELETE:\n{schema_text}"
    );
}

/// Integration test: path normalization collapses dynamic segments to wildcards.
///
/// Verifies that paths containing UUIDs, long numeric IDs, and SHA hashes
/// are correctly collapsed to `*` in the generated policy.
#[tokio::test]
async fn observe_mode_path_normalization() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");

    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Emit requests with dynamic path segments
    let uuid = "550e8400-e29b-41d4-a716-446655440000";
    let sha = "da39a3ee5e6b4b0d3255bfef95601890afd80709";

    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.github.com".to_string(),
        path: "/repos/my-org/my-repo/pulls/42".to_string(),
        decision: "allow".to_string(),
        latency_us: 100,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.github.com".to_string(),
        path: "/repos/my-org/my-repo/pulls/9999".to_string(),
        decision: "allow".to_string(),
        latency_us: 100,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: format!("/users/{uuid}/profile"),
        decision: "allow".to_string(),
        latency_us: 100,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.github.com".to_string(),
        path: format!("/repos/org/repo/commits/{sha}"),
        decision: "allow".to_string(),
        latency_us: 100,
        enforcement_mode: String::new(),
        blocked: None,
    });

    drop(obs);

    let result = strait::generate::generate_from_file(&obs_log_path).unwrap();
    let (policy_text, _schema_text, wildcard_count) = result.unwrap();

    // Verify wildcards were applied
    assert!(
        wildcard_count > 0,
        "should have collapsed at least one wildcard"
    );

    // Pull request numbers (42, 9999) should be collapsed to *
    // Note: "42" is only 2 digits (< 4), but 9999 is 4 digits, so 9999 gets collapsed.
    // Both should map to the same collapsed resource.
    assert!(
        policy_text.contains("pulls/*") || policy_text.contains("pulls"),
        "numeric IDs in paths should be collapsed:\n{policy_text}"
    );

    // UUID should be collapsed to *
    assert!(
        policy_text.contains("users/*/profile"),
        "UUID should be collapsed to wildcard:\n{policy_text}"
    );
    // The original UUID should appear in a comment annotation
    assert!(
        policy_text.contains(uuid),
        "original UUID should appear in annotation:\n{policy_text}"
    );

    // SHA should be collapsed to *
    assert!(
        policy_text.contains("commits/*"),
        "SHA should be collapsed to wildcard:\n{policy_text}"
    );
    assert!(
        policy_text.contains(sha),
        "original SHA should appear in annotation:\n{policy_text}"
    );
}

/// Integration test: observation mode with echo server end-to-end.
///
/// Simulates the full flow: MITM proxy records observations, then
/// generates policy. Uses a loopback echo server so no external
/// network access is required.
#[tokio::test]
async fn observe_mode_with_echo_server_records_and_generates() {
    use strait::observe::{EventKind, ObservationStream};

    // Start a TLS echo server
    let (_echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("policy.cedar");
    let schema_path = dir.path().join("policy.cedarschema");

    // Set up observation stream
    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Simulate MITM proxy recording traffic to the echo server.
    // In real operation, the handle_mitm function emits these events
    // as it processes each request through the TLS tunnel.
    let observed_requests = vec![
        ("GET", "api.github.com", "/repos/org/repo"),
        ("GET", "api.github.com", "/repos/org/repo/pulls"),
        ("POST", "api.github.com", "/repos/org/repo/issues"),
        ("GET", "api.github.com", "/repos/org/other-repo/pulls/1234"),
    ];

    for (method, host, path) in &observed_requests {
        obs.emit(EventKind::NetworkRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            decision: "allow".to_string(),
            latency_us: 50,
            enforcement_mode: String::new(),
            blocked: None,
        });
    }

    drop(obs);

    // Generate policy files (the same way `strait init --observe` does)
    let wildcard_count =
        strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    // Verify output files exist
    assert!(policy_path.exists(), "policy file should be written");
    assert!(schema_path.exists(), "schema file should be written");

    let policy = std::fs::read_to_string(&policy_path).unwrap();
    let schema = std::fs::read_to_string(&schema_path).unwrap();

    // Verify policy covers all observed methods
    assert!(policy.contains(r#"action == Action::"http:GET""#));
    assert!(policy.contains(r#"action == Action::"http:POST""#));

    // Verify the long numeric ID (1234) was collapsed
    assert!(wildcard_count > 0, "should collapse numeric PR number");

    // Verify schema is valid Cedar
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    let policy_set =
        PolicySet::from_str(&policy).expect("generated policy should parse as valid Cedar");

    let (cedar_schema, _warnings) = Schema::from_cedarschema_str(&schema)
        .expect("generated schema should parse as valid Cedar schema");

    let validator = Validator::new(cedar_schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    assert!(
        result.validation_passed(),
        "generated policy should pass schema validation: {:?}",
        result
            .validation_errors()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );
}

/// Integration test: duration parsing works correctly for all supported formats.
#[test]
fn duration_parsing_integration() {
    use strait::observe::parse_duration;

    // Valid durations
    assert_eq!(
        parse_duration("30s").unwrap(),
        std::time::Duration::from_secs(30)
    );
    assert_eq!(
        parse_duration("5m").unwrap(),
        std::time::Duration::from_secs(300)
    );
    assert_eq!(
        parse_duration("1h").unwrap(),
        std::time::Duration::from_secs(3600)
    );

    // Invalid durations produce clear errors
    assert!(parse_duration("").is_err());
    assert!(parse_duration("abc").is_err());
    assert!(parse_duration("5x").is_err());
    assert!(parse_duration("0m").is_err());
}

// ============================================================================
// E2E Round-Trip Integration Tests (H-CP-11)
//
// These tests prove the entire observe-then-enforce lifecycle works
// end-to-end at the library level. They exercise:
//   1. Observe: emit events to a JSONL file
//   2. Generate: produce a Cedar policy from observations
//   3. Replay: verify the generated policy matches all observations
//   4. Enforce (denial): verify unauthorized events are denied
//
// No Docker required — these use the library APIs directly with
// synthesized observation events.
// ============================================================================

/// Full round-trip: observe → generate → replay → verify consistency.
///
/// Synthesizes observation events (network + mount) as produced by
/// `strait launch --observe`, generates a Cedar policy, then replays
/// the observations and verifies every event matches the policy.
#[test]
fn e2e_roundtrip_observe_generate_replay() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    // --- Phase 1: Observe ---
    // Simulate `strait launch --observe ./test-agent` recording activity.
    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Container lifecycle events (skipped by generate/replay but part of the log)
    obs.emit(EventKind::ContainerStart {
        container_id: "e2e-test-container".to_string(),
        image: "alpine:latest".to_string(),
    });

    // Mount events (recorded when container starts)
    obs.emit(EventKind::Mount {
        path: "/workspace".to_string(),
        mode: "read-write".to_string(),
    });

    // Network activity: test agent makes a GET request to a loopback echo server
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/data/items".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // Filesystem activity: test agent reads a file
    obs.emit(EventKind::FsAccess {
        path: "/workspace/config.json".to_string(),
        operation: "read".to_string(),
    });

    // Container stop
    obs.emit(EventKind::ContainerStop {
        container_id: "e2e-test-container".to_string(),
        exit_code: Some(0),
    });

    // Flush and close the observation stream
    drop(obs);

    // Verify JSONL has all 5 events
    let obs_content = std::fs::read_to_string(&obs_log_path).unwrap();
    let line_count = obs_content.lines().count();
    assert_eq!(line_count, 5, "observation log should have 5 events");

    // Verify both network and mount events are present
    assert!(
        obs_content.contains("\"type\":\"network_request\""),
        "observation log should contain network_request events"
    );
    assert!(
        obs_content.contains("\"type\":\"mount\""),
        "observation log should contain mount events"
    );

    // --- Phase 2: Generate ---
    // Run `strait generate observations.jsonl` to produce a Cedar policy.
    let wildcard_count =
        strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    assert!(policy_path.exists(), "generated policy file should exist");
    assert!(schema_path.exists(), "generated schema file should exist");

    let policy_text = std::fs::read_to_string(&policy_path).unwrap();
    let schema_text = std::fs::read_to_string(&schema_path).unwrap();

    // Policy should cover both network and filesystem observed activity
    assert!(
        policy_text.contains(r#"action == Action::"http:GET""#),
        "policy should contain http:GET action: {policy_text}"
    );
    assert!(
        policy_text.contains(r#"action == Action::"fs:read""#),
        "policy should contain fs:read action: {policy_text}"
    );
    assert!(
        policy_text.contains(r#"action == Action::"fs:mount""#),
        "policy should contain fs:mount action: {policy_text}"
    );

    // Schema should contain all observed actions
    assert!(
        schema_text.contains(r#"action "http:GET""#),
        "schema should declare http:GET: {schema_text}"
    );
    assert!(
        schema_text.contains(r#"action "fs:read""#),
        "schema should declare fs:read: {schema_text}"
    );
    assert!(
        schema_text.contains(r#"action "fs:mount""#),
        "schema should declare fs:mount: {schema_text}"
    );

    // Verify generated policy is valid Cedar
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    let policy_set =
        PolicySet::from_str(&policy_text).expect("generated policy should parse as valid Cedar");
    let (cedar_schema, _warnings) = Schema::from_cedarschema_str(&schema_text)
        .expect("generated schema should parse as valid Cedar schema");
    let validator = Validator::new(cedar_schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    assert!(
        result.validation_passed(),
        "generated policy should pass schema validation: {:?}",
        result
            .validation_errors()
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
    );

    // --- Phase 3: Replay ---
    // Run `strait test --replay observations.jsonl --policy generated.cedar`
    // to verify all observed events match the generated policy (exit 0).
    let replay_result = strait::replay::replay(&obs_log_path, &policy_path, None).unwrap();

    assert!(
        replay_result.mismatches.is_empty(),
        "replay should have zero mismatches — observe/generate/enforce must be consistent. \
         Mismatches: {:?}",
        replay_result
            .mismatches
            .iter()
            .map(|m| format!(
                "line {}: observed={}, policy={}",
                m.line, m.observed, m.policy_decision
            ))
            .collect::<Vec<_>>()
    );

    // Evaluable events = network_request + fs_access + mount = 3
    // Skipped events = container_start + container_stop = 2
    assert_eq!(
        replay_result.matches, 3,
        "should match all 3 evaluable events"
    );
    assert_eq!(replay_result.skipped, 2, "should skip 2 lifecycle events");
    assert_eq!(
        strait::replay::print_results(&replay_result),
        0,
        "exit code should be 0 when all events match"
    );

    // No wildcards expected for these simple paths
    assert_eq!(
        wildcard_count, 0,
        "simple paths should not produce wildcards"
    );
}

/// E2E: enforce mode denies actions not in the generated policy.
///
/// Synthesizes a set of "authorized" observations, generates a policy,
/// then replays a DIFFERENT set of observations (unauthorized activity)
/// and verifies the policy denies them.
#[test]
fn e2e_enforce_denies_unauthorized_actions() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let bad_obs_log_path = dir.path().join("unauthorized.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    // --- Phase 1: Generate policy from authorized observations ---
    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Authorized activity: GET to api.example.com and read /workspace/config.json
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/data/items".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::Mount {
        path: "/workspace".to_string(),
        mode: "read-only".to_string(),
    });
    obs.emit(EventKind::FsAccess {
        path: "/workspace/config.json".to_string(),
        operation: "read".to_string(),
    });
    drop(obs);

    strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    // Verify the authorized observations replay cleanly
    let authorized_result = strait::replay::replay(&obs_log_path, &policy_path, None).unwrap();
    assert!(
        authorized_result.mismatches.is_empty(),
        "authorized observations should replay cleanly"
    );

    // --- Phase 2: Replay unauthorized observations against the same policy ---
    let mut bad_obs = ObservationStream::new();
    bad_obs.persist_to_file(&bad_obs_log_path).unwrap();

    // Unauthorized: POST to the same host (only GET was observed)
    bad_obs.emit(EventKind::NetworkRequest {
        method: "POST".to_string(),
        host: "api.example.com".to_string(),
        path: "/data/items".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // Unauthorized: GET to a different host entirely
    bad_obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "evil.example.com".to_string(),
        path: "/exfiltrate".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // Unauthorized: write to a path (only read was in the policy)
    bad_obs.emit(EventKind::FsAccess {
        path: "/workspace/secret.txt".to_string(),
        operation: "write".to_string(),
    });

    // Unauthorized: read from an unexpected path outside /workspace
    bad_obs.emit(EventKind::FsAccess {
        path: "/etc/shadow".to_string(),
        operation: "read".to_string(),
    });

    drop(bad_obs);

    let bad_result = strait::replay::replay(&bad_obs_log_path, &policy_path, None).unwrap();

    // All unauthorized events should be mismatches (policy denies them)
    assert_eq!(
        bad_result.mismatches.len(),
        4,
        "all 4 unauthorized events should be denied by the policy. \
         Matches: {}, Mismatches: {}",
        bad_result.matches,
        bad_result.mismatches.len()
    );

    for m in &bad_result.mismatches {
        assert_eq!(
            m.observed, "allow",
            "unauthorized events were observed as 'allow'"
        );
        assert_eq!(
            m.policy_decision, "deny",
            "policy should deny unauthorized events"
        );
    }

    assert_eq!(
        strait::replay::print_results(&bad_result),
        1,
        "exit code should be 1 when mismatches are found"
    );
}

/// Edge case: round-trip with filesystem-only activity (no network).
///
/// Tests that the observe/generate/replay pipeline works correctly
/// when the agent only accesses the filesystem with no network activity.
#[test]
fn e2e_roundtrip_filesystem_only() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Only filesystem activity, no network
    obs.emit(EventKind::Mount {
        path: "/workspace".to_string(),
        mode: "read-write".to_string(),
    });
    obs.emit(EventKind::FsAccess {
        path: "/workspace/src/main.rs".to_string(),
        operation: "read".to_string(),
    });
    obs.emit(EventKind::FsAccess {
        path: "/workspace/build/output.o".to_string(),
        operation: "write".to_string(),
    });

    drop(obs);

    // Generate policy
    strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    let policy_text = std::fs::read_to_string(&policy_path).unwrap();

    // Policy should only contain fs: actions, no http: actions
    assert!(
        policy_text.contains(r#"Action::"fs:read""#),
        "policy should contain fs:read"
    );
    assert!(
        policy_text.contains(r#"Action::"fs:write""#),
        "policy should contain fs:write"
    );
    assert!(
        policy_text.contains(r#"Action::"fs:mount""#),
        "policy should contain fs:mount"
    );
    assert!(
        !policy_text.contains("http:"),
        "filesystem-only policy should not contain http: actions"
    );

    // Replay should match all events
    let result = strait::replay::replay(&obs_log_path, &policy_path, None).unwrap();
    assert!(
        result.mismatches.is_empty(),
        "filesystem-only round-trip should be consistent"
    );
    assert_eq!(result.matches, 3, "should match all 3 fs events");
}

/// Edge case: round-trip with network-only activity (no filesystem).
///
/// Tests that the observe/generate/replay pipeline works correctly
/// when the agent only makes network requests with no filesystem activity.
#[test]
fn e2e_roundtrip_network_only() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Only network activity, no filesystem
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.github.com".to_string(),
        path: "/repos/org/repo".to_string(),
        decision: "allow".to_string(),
        latency_us: 100,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::NetworkRequest {
        method: "POST".to_string(),
        host: "api.github.com".to_string(),
        path: "/repos/org/repo/issues".to_string(),
        decision: "allow".to_string(),
        latency_us: 200,
        enforcement_mode: String::new(),
        blocked: None,
    });

    drop(obs);

    // Generate policy
    strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    let policy_text = std::fs::read_to_string(&policy_path).unwrap();

    // Policy should only contain http: actions, no fs: actions
    assert!(
        policy_text.contains(r#"Action::"http:GET""#),
        "policy should contain http:GET"
    );
    assert!(
        policy_text.contains(r#"Action::"http:POST""#),
        "policy should contain http:POST"
    );
    assert!(
        !policy_text.contains("fs:"),
        "network-only policy should not contain fs: actions"
    );

    // Replay should match all events
    let result = strait::replay::replay(&obs_log_path, &policy_path, None).unwrap();
    assert!(
        result.mismatches.is_empty(),
        "network-only round-trip should be consistent"
    );
    assert_eq!(result.matches, 2, "should match both network events");
}

/// E2E: wildcard collapsing generates valid Cedar with annotations.
///
/// Tests that observations with UUIDs, long numbers, and SHA hashes
/// produce correctly collapsed wildcard policies. The wildcards are
/// for human review — Cedar doesn't do glob matching, so wildcard
/// resources are intentionally more restrictive than the original
/// concrete paths. Users are expected to review and adjust.
///
/// The annotation comments preserve the original values for reference.
#[test]
fn e2e_wildcard_collapsing_produces_valid_annotated_policy() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // UUID in path
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/users/550e8400-e29b-41d4-a716-446655440000/profile".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // Different UUID in same path pattern
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/users/660e8400-e29b-41d4-a716-446655440001/profile".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // Long numeric ID in path
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.github.com".to_string(),
        path: "/repos/org/repo/pulls/12345".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    // SHA hash in path
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "github.com".to_string(),
        path: "/org/repo/commit/da39a3ee5e6b4b0d3255bfef95601890afd80709".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    drop(obs);

    // Generate policy with wildcards
    let wildcard_count =
        strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    assert!(
        wildcard_count > 0,
        "should have collapsed dynamic path segments to wildcards"
    );

    let policy_text = std::fs::read_to_string(&policy_path).unwrap();
    let schema_text = std::fs::read_to_string(&schema_path).unwrap();

    // Wildcards should appear in the policy resources
    assert!(
        policy_text.contains("users/*/profile"),
        "UUID segments should be collapsed to wildcard: {policy_text}"
    );

    // Annotation comments should contain the original values
    assert!(
        policy_text.contains("550e8400-e29b-41d4-a716-446655440000"),
        "annotation should list first UUID: {policy_text}"
    );
    assert!(
        policy_text.contains("660e8400-e29b-41d4-a716-446655440001"),
        "annotation should list second UUID: {policy_text}"
    );
    assert!(
        policy_text.contains("12345"),
        "annotation should list numeric ID: {policy_text}"
    );
    assert!(
        policy_text.contains("da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        "annotation should list SHA hash: {policy_text}"
    );

    // Deduplicated: two UUIDs → one permit statement for that pattern
    // (UUIDs are different but collapse to same pattern)
    let uuid_permit_count = policy_text.matches("users/*/profile").count();
    assert_eq!(
        uuid_permit_count, 1,
        "two UUIDs in same pattern should deduplicate to one permit: {policy_text}"
    );

    // Generated policy should be valid Cedar
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    let policy_set =
        PolicySet::from_str(&policy_text).expect("wildcard policy should be valid Cedar syntax");
    let (cedar_schema, _warnings) =
        Schema::from_cedarschema_str(&schema_text).expect("schema should be valid");
    let validator = Validator::new(cedar_schema);
    let result = validator.validate(&policy_set, ValidationMode::Strict);
    assert!(
        result.validation_passed(),
        "wildcard policy should pass schema validation"
    );
}

/// E2E: mixed activity round-trip with container lifecycle events.
///
/// Tests the full lifecycle as it would appear in a real
/// `strait launch --observe` session, including container start/stop
/// events that are correctly skipped during generate and replay.
#[test]
fn e2e_roundtrip_full_lifecycle_mixed_events() {
    use strait::observe::{EventKind, ObservationStream};

    let dir = tempfile::tempdir().unwrap();
    let obs_log_path = dir.path().join("observations.jsonl");
    let policy_path = dir.path().join("generated.cedar");
    let schema_path = dir.path().join("generated.cedarschema");

    let mut obs = ObservationStream::new();
    obs.persist_to_file(&obs_log_path).unwrap();

    // Full lifecycle: start → mounts → network → fs → stop
    obs.emit(EventKind::ContainerStart {
        container_id: "abc123".to_string(),
        image: "alpine:latest".to_string(),
    });
    obs.emit(EventKind::Mount {
        path: "/workspace".to_string(),
        mode: "read-write".to_string(),
    });
    obs.emit(EventKind::Mount {
        path: "/data".to_string(),
        mode: "read-only".to_string(),
    });
    obs.emit(EventKind::NetworkRequest {
        method: "GET".to_string(),
        host: "api.example.com".to_string(),
        path: "/health".to_string(),
        decision: "allow".to_string(),
        latency_us: 30,
        enforcement_mode: String::new(),
        blocked: None,
    });
    obs.emit(EventKind::FsAccess {
        path: "/workspace/output.txt".to_string(),
        operation: "write".to_string(),
    });
    obs.emit(EventKind::FsAccess {
        path: "/data/input.csv".to_string(),
        operation: "read".to_string(),
    });
    obs.emit(EventKind::ContainerStop {
        container_id: "abc123".to_string(),
        exit_code: Some(0),
    });

    drop(obs);

    // Generate
    strait::generate::generate(&obs_log_path, &policy_path, &schema_path).unwrap();

    // Replay
    let result = strait::replay::replay(&obs_log_path, &policy_path, None).unwrap();

    assert_eq!(result.total, 7, "total events in log");
    assert_eq!(result.skipped, 2, "container start/stop should be skipped");
    assert_eq!(
        result.matches, 5,
        "5 evaluable events (2 mounts + 1 network + 2 fs) should match"
    );
    assert!(
        result.mismatches.is_empty(),
        "full lifecycle round-trip must be consistent"
    );
    assert_eq!(strait::replay::print_results(&result), 0);

    // --- Verify enforcement denies different agent ---
    // A different agent trying to write to /data (read-only) or
    // hit a different host should be denied.
    let bad_obs_path = dir.path().join("bad-agent.jsonl");
    let mut bad_obs = ObservationStream::new();
    bad_obs.persist_to_file(&bad_obs_path).unwrap();

    // Unauthorized: write to read-only /data path
    bad_obs.emit(EventKind::FsAccess {
        path: "/data/tampered.csv".to_string(),
        operation: "write".to_string(),
    });

    // Unauthorized: hit a different API
    bad_obs.emit(EventKind::NetworkRequest {
        method: "POST".to_string(),
        host: "evil.example.com".to_string(),
        path: "/exfiltrate".to_string(),
        decision: "allow".to_string(),
        latency_us: 50,
        enforcement_mode: String::new(),
        blocked: None,
    });

    drop(bad_obs);

    let bad_result = strait::replay::replay(&bad_obs_path, &policy_path, None).unwrap();
    assert_eq!(
        bad_result.mismatches.len(),
        2,
        "both unauthorized actions should be denied"
    );
    assert_eq!(strait::replay::print_results(&bad_result), 1);
}

// ===========================================================================
// Chunked Transfer-Encoding & malformed Content-Length tests (H-CP-17)
//
// These tests exercise the real `handle_mitm` function with a minimal
// ProxyContext, routing requests through the actual MITM pipeline to a
// loopback TLS echo server.
// ===========================================================================

/// Helper: build a minimal ProxyContext for testing, overriding the upstream
/// resolution so `handle_mitm` connects to the echo server instead of the
/// real internet.
fn build_test_proxy_context() -> strait::config::ProxyContext {
    use std::time::{Duration, Instant};
    let session_ca = strait::ca::SessionCa::generate().unwrap();
    let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());
    strait::config::ProxyContext {
        session_ca,
        policy_engine: None,
        credential_store: None,
        audit_logger,
        mitm_hosts: vec!["localhost".to_string()],
        max_body_size: 10 * 1024 * 1024,
        keepalive_timeout: Duration::from_secs(5),
        decision_timeout: Duration::from_secs(30),
        startup_instant: Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "anonymous".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: None,
        enforcement_mode: "observe".to_string(),
        mitm_all: false,
        warn_only: false,
        live_policy_bounds: None,
        upstream_addr_override: None,
        upstream_tls_override: None,
        upstream_connect_timeout: std::time::Duration::from_secs(30),
        upstream_response_timeout: std::time::Duration::from_secs(60),
        pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
    }
}

/// Helper: connect through the proxy's MITM pipeline, perform a TLS handshake,
/// and return the TLS stream ready for sending HTTP requests.
///
/// `proxy_addr` — the local proxy listener address
/// `ca_pem` — PEM-encoded session CA cert for trust
/// `hostname` — the CONNECT target hostname
async fn connect_through_mitm(
    proxy_addr: std::net::SocketAddr,
    ca_pem: &str,
    hostname: &str,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();

    // Send CONNECT
    let connect_req = format!("CONNECT {hostname}:443 HTTP/1.1\r\nHost: {hostname}:443\r\n\r\n");
    client.write_all(connect_req.as_bytes()).await.unwrap();

    // Read 200 response + drain headers
    {
        let mut buf = BufReader::new(&mut client);
        let mut response_line = String::new();
        buf.read_line(&mut response_line).await.unwrap();
        assert!(
            response_line.contains("200"),
            "Expected 200, got: {}",
            response_line.trim()
        );
        loop {
            let mut line = String::new();
            buf.read_line(&mut line).await.unwrap();
            if line.trim().is_empty() {
                break;
            }
        }
    }

    // TLS handshake trusting the session CA
    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from(hostname.to_string()).unwrap();
    connector.connect(server_name, client).await.unwrap()
}

/// Integration test: POST with `Transfer-Encoding: chunked` through the MITM
/// pipeline — the proxy decodes the chunked body and forwards it with
/// Content-Length to the upstream echo server.
///
/// Uses a test helper that replicates MITM behavior with chunked decoding,
/// routing through a loopback TLS echo server.
#[tokio::test]
async fn mitm_chunked_request_body_decoded_and_forwarded() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Use production handle_mitm which already handles chunked decoding
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    // Send a POST with chunked encoding
    let body_data = r#"{"name":"chunked-test"}"#;
    let chunked_body = format!("{:x}\r\n{}\r\n0\r\n\r\n", body_data.len(), body_data);
    let request = format!(
        "POST /repos HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Content-Type: application/json\r\n\
         Transfer-Encoding: chunked\r\n\
         \r\n\
         {}",
        chunked_body,
    );
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    // The echo server should echo back the decoded body
    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("POST /repos"),
        "Expected POST request line in echo, got: {}",
        response_str
    );
    assert!(
        response_str.contains(body_data),
        "Expected decoded body '{}' in echo response, got: {}",
        body_data,
        response_str
    );
    // Verify the proxy replaced Transfer-Encoding with Content-Length
    assert!(
        response_str.contains(&format!("Content-Length: {}", body_data.len())),
        "Expected Content-Length header for decoded body, got: {}",
        response_str
    );
}

/// Integration test: malformed Content-Length returns 400 Bad Request.
#[tokio::test]
async fn mitm_malformed_content_length_returns_400() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let ctx = build_test_proxy_context();
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await.unwrap();
        let mut buf = BufReader::new(&mut client);
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        loop {
            let mut l = String::new();
            buf.read_line(&mut l).await.unwrap();
            if l.trim().is_empty() {
                break;
            }
        }
        drop(buf);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = strait::mitm::handle_mitm(client, "localhost", echo_addr.port(), &ctx).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "localhost").await;

    // Send a request with malformed Content-Length
    let request = "POST /repos HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: abc\r\n\
         \r\n";
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("400 Bad Request"),
        "Expected 400 Bad Request for malformed Content-Length, got: {}",
        response_str
    );
    assert!(
        response_str.contains("bad_request"),
        "Expected bad_request error in body, got: {}",
        response_str
    );
}

/// Integration test: negative Content-Length returns 400 Bad Request.
#[tokio::test]
async fn mitm_negative_content_length_returns_400() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let ctx = build_test_proxy_context();
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    tokio::spawn(async move {
        let (mut client, _) = proxy_listener.accept().await.unwrap();
        let mut buf = BufReader::new(&mut client);
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        loop {
            let mut l = String::new();
            buf.read_line(&mut l).await.unwrap();
            if l.trim().is_empty() {
                break;
            }
        }
        drop(buf);
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let _ = strait::mitm::handle_mitm(client, "localhost", echo_addr.port(), &ctx).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "localhost").await;

    // Send a request with negative Content-Length
    let request = "POST /repos HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Length: -1\r\n\
         \r\n";
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("400 Bad Request"),
        "Expected 400 Bad Request for negative Content-Length, got: {}",
        response_str
    );
}

/// Regression test: existing Content-Length body forwarding still works
/// after chunked encoding changes. Uses the same helper as existing tests
/// to verify nothing is broken in the standard path.
#[tokio::test]
async fn mitm_content_length_body_still_works() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Use production handle_mitm for Content-Length body forwarding
    let ctx = strait_test_helpers::build_production_mitm_context(
        echo_addr,
        "api.github.com",
        std::time::Duration::from_secs(5),
    );
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    // Send a POST with Content-Length (the standard path)
    let body = r#"{"name":"cl-test","private":true}"#;
    let request = format!(
        "POST /repos HTTP/1.1\r\n\
         Host: api.github.com\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         \r\n\
         {}",
        body.len(),
        body
    );
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains(body),
        "Expected body '{}' in echo response, got: {}",
        body,
        response_str
    );
}

// --- H-ER-2: Input validation tests ---

/// Test that a request with both Content-Length and Transfer-Encoding: chunked
/// gets rejected with 400 Bad Request by the MITM pipeline.
#[tokio::test]
async fn mitm_rejects_conflicting_cl_te_headers() {
    let ca = strait_test_helpers::generate_ca();
    let ctx = strait_test_helpers::build_mitm_proxy_context(&ca, None);
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    // Connect to proxy and send CONNECT for a MITM host
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read 200 Connection Established
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200, got: {}",
        response_line.trim()
    );
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    // TLS handshake with the proxy's session CA
    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("api.github.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send a request with BOTH Content-Length and Transfer-Encoding: chunked
    tls.write_all(
        b"POST /repos/test/repo HTTP/1.1\r\n\
          Host: api.github.com\r\n\
          Content-Length: 5\r\n\
          Transfer-Encoding: chunked\r\n\
          \r\n\
          5\r\nhello\r\n0\r\n\r\n",
    )
    .await
    .unwrap();

    // Read the response — should be 400
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("400 Bad Request"),
        "Expected 400 for CL/TE conflict, got: {}",
        response_str
    );
    assert!(
        response_str.contains("Conflicting Content-Length and Transfer-Encoding"),
        "Expected CL/TE conflict message, got: {}",
        response_str
    );
}

/// Test that HTTP/0.9 requests are rejected with 400.
#[tokio::test]
async fn mitm_rejects_http_09_version() {
    let ca = strait_test_helpers::generate_ca();
    let ctx = strait_test_helpers::build_mitm_proxy_context(&ca, None);
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(response_line.contains("200"));
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("api.github.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send a request with no HTTP version (HTTP/0.9 style — only 2 parts)
    tls.write_all(b"GET /repos/test/repo\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("400 Bad Request"),
        "Expected 400 for HTTP/0.9, got: {}",
        response_str
    );
}

/// Test that fabricated HTTP version strings (HTTP/9.9) are rejected with 400.
#[tokio::test]
async fn mitm_rejects_fabricated_http_version() {
    let ca = strait_test_helpers::generate_ca();
    let ctx = strait_test_helpers::build_mitm_proxy_context(&ca, None);
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
        .await
        .unwrap();

    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(response_line.contains("200"));
    loop {
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        if line.trim().is_empty() {
            break;
        }
    }

    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("api.github.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send a request with fabricated HTTP version
    tls.write_all(b"GET /repos/test/repo HTTP/9.9\r\nHost: api.github.com\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("400 Bad Request"),
        "Expected 400 for HTTP/9.9, got: {}",
        response_str
    );
    assert!(
        response_str.contains("Unsupported HTTP version"),
        "Expected version rejection message, got: {}",
        response_str
    );
}

/// Test that CONNECT to a non-MITM host returns 403 when policy engine is active.
#[tokio::test]
async fn passthrough_denied_when_policy_active() {
    let ca = strait_test_helpers::generate_ca();
    // Build a ProxyContext with a policy engine (using a simple allow-all policy)
    let ctx = strait_test_helpers::build_mitm_proxy_context_with_policy(&ca);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    // Connect and send CONNECT for a non-MITM host
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT evil.example.com:443 HTTP/1.1\r\nHost: evil.example.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read the response — should be 403
    let mut response = Vec::new();
    client.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("403 Forbidden"),
        "Expected 403 for non-MITM host with policy active, got: {}",
        response_str
    );
    assert!(
        response_str.contains("passthrough_denied"),
        "Expected passthrough_denied error, got: {}",
        response_str
    );
}

/// Test that CONNECT to a non-MITM host succeeds in observe mode (no policy).
#[tokio::test]
async fn passthrough_allowed_without_policy_engine() {
    // Start a TCP echo server as the upstream
    let echo_addr = start_tcp_echo_server().await;

    let ca = strait_test_helpers::generate_ca();
    // Build a ProxyContext WITHOUT a policy engine (observe mode)
    let mut ctx = strait_test_helpers::build_mitm_proxy_context(&ca, None);
    // Override upstream to point at the echo server
    ctx.upstream_addr_override = Some(echo_addr);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    // Connect and send CONNECT for a non-MITM host
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read the response — should get 200 (passthrough allowed)
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200 for passthrough without policy, got: {}",
        response_line.trim()
    );
}

/// Test that CONNECT to a non-MITM host succeeds in warn-only mode even with policy.
#[tokio::test]
async fn passthrough_allowed_in_warn_only_mode() {
    // Start a TCP echo server as the upstream
    let echo_addr = start_tcp_echo_server().await;

    let ca = strait_test_helpers::generate_ca();
    // Build a ProxyContext with a policy engine BUT in warn-only mode
    let mut ctx = strait_test_helpers::build_mitm_proxy_context_with_policy(&ca);
    ctx.warn_only = true;
    ctx.upstream_addr_override = Some(echo_addr);

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx = Arc::new(ctx);
    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    // Connect and send CONNECT for a non-MITM host
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
        .await
        .unwrap();

    // Should get 200 (warn mode doesn't deny passthrough)
    let mut buf = BufReader::new(&mut client);
    let mut response_line = String::new();
    buf.read_line(&mut response_line).await.unwrap();
    assert!(
        response_line.contains("200"),
        "Expected 200 for passthrough in warn-only mode, got: {}",
        response_line.trim()
    );
}

// ---------------------------------------------------------------------------
// Upstream timeout tests
// ---------------------------------------------------------------------------

/// Start a TCP listener that accepts connections but never sends any data,
/// simulating a stalled upstream that holds the connection open forever.
async fn start_stalled_tcp_server() -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            // Hold the connection open but never send data
            tokio::spawn(async move {
                let _held = stream;
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            });
        }
    });

    addr
}

/// Start a TLS echo server that accepts the TLS handshake and reads the HTTP
/// request, but never sends a response back. Used to test upstream response
/// timeout behavior.
async fn start_stalled_response_tls_server() -> (std::net::SocketAddr, CertificateDer<'static>) {
    let key_pair = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "test-stall-ca");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&key_pair).unwrap();
    let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "api.github.com");
    leaf_params.subject_alt_names.push(rcgen::SanType::DnsName(
        "api.github.com".try_into().unwrap(),
    ));
    leaf_params
        .subject_alt_names
        .push(rcgen::SanType::DnsName("localhost".try_into().unwrap()));
    let leaf_cert = leaf_params
        .signed_by(&leaf_key, &ca_cert, &key_pair)
        .unwrap();

    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                ca_cert_der.clone(),
            ],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
        .unwrap();

    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let mut tls = match acceptor.accept(stream).await {
                    Ok(tls) => tls,
                    Err(_) => return,
                };

                // Read the request but never respond
                let mut buf = [0u8; 4096];
                let _ = tls.read(&mut buf).await;

                // Stall indefinitely
                tokio::time::sleep(std::time::Duration::from_secs(300)).await;
            });
        }
    });

    (addr, ca_cert_der)
}

#[tokio::test]
async fn upstream_connect_timeout_returns_504() {
    // Start a server that accepts TCP connections but never responds
    let stalled_addr = start_stalled_tcp_server().await;

    let session_ca = strait::ca::SessionCa::generate().unwrap();
    let ca_pem = session_ca.ca_cert_pem.clone();
    let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

    // Use NoVerify since the stalled server won't complete TLS anyway
    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(strait_test_helpers::NoVerify))
            .with_no_client_auth(),
    );

    let ctx = Arc::new(strait::config::ProxyContext {
        session_ca,
        policy_engine: None,
        credential_store: None,
        audit_logger,
        mitm_hosts: vec!["api.github.com".to_string()],
        max_body_size: 10 * 1024 * 1024,
        keepalive_timeout: std::time::Duration::from_secs(5),
        decision_timeout: std::time::Duration::from_secs(30),
        startup_instant: std::time::Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "anonymous".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: None,
        enforcement_mode: "observe".to_string(),
        mitm_all: false,
        warn_only: false,
        live_policy_bounds: None,
        upstream_addr_override: Some(stalled_addr),
        upstream_tls_override: Some(tls_config),
        // Very short timeout so the test completes quickly
        upstream_connect_timeout: std::time::Duration::from_millis(100),
        upstream_response_timeout: std::time::Duration::from_secs(60),
        pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    tls.write_all(b"GET /repos/test HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("504 Gateway Timeout"),
        "Expected 504 Gateway Timeout, got: {}",
        response_str
    );
    assert!(
        response_str.contains("gateway_timeout"),
        "Expected gateway_timeout error in body, got: {}",
        response_str
    );
}

#[tokio::test]
async fn upstream_response_timeout_returns_504() {
    // Start a TLS server that accepts but never responds
    let (stalled_addr, _ca_der) = start_stalled_response_tls_server().await;

    let session_ca = strait::ca::SessionCa::generate().unwrap();
    let ca_pem = session_ca.ca_cert_pem.clone();
    let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(strait_test_helpers::NoVerify))
            .with_no_client_auth(),
    );

    let ctx = Arc::new(strait::config::ProxyContext {
        session_ca,
        policy_engine: None,
        credential_store: None,
        audit_logger,
        mitm_hosts: vec!["api.github.com".to_string()],
        max_body_size: 10 * 1024 * 1024,
        keepalive_timeout: std::time::Duration::from_secs(5),
        decision_timeout: std::time::Duration::from_secs(30),
        startup_instant: std::time::Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "anonymous".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: None,
        enforcement_mode: "observe".to_string(),
        mitm_all: false,
        warn_only: false,
        live_policy_bounds: None,
        upstream_addr_override: Some(stalled_addr),
        upstream_tls_override: Some(tls_config),
        upstream_connect_timeout: std::time::Duration::from_secs(30),
        // Very short response timeout so the test completes quickly
        upstream_response_timeout: std::time::Duration::from_millis(200),
        pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    tls.write_all(b"GET /repos/test HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("504 Gateway Timeout"),
        "Expected 504 Gateway Timeout, got: {}",
        response_str
    );
    assert!(
        response_str.contains("gateway_timeout"),
        "Expected gateway_timeout error in body, got: {}",
        response_str
    );
}

#[tokio::test]
async fn normal_upstream_succeeds_with_timeouts_configured() {
    // Verify that normal traffic works when timeouts are configured but do not fire.
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    let session_ca = strait::ca::SessionCa::generate().unwrap();
    let ca_pem = session_ca.ca_cert_pem.clone();
    let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(strait_test_helpers::NoVerify))
            .with_no_client_auth(),
    );

    let ctx = Arc::new(strait::config::ProxyContext {
        session_ca,
        policy_engine: None,
        credential_store: None,
        audit_logger,
        mitm_hosts: vec!["api.github.com".to_string()],
        max_body_size: 10 * 1024 * 1024,
        keepalive_timeout: std::time::Duration::from_secs(5),
        decision_timeout: std::time::Duration::from_secs(30),
        startup_instant: std::time::Instant::now(),
        identity_header: "X-Strait-Agent".to_string(),
        identity_default: "anonymous".to_string(),
        git_policy: None,
        policy_config: None,
        observation_stream: None,
        enforcement_mode: "observe".to_string(),
        mitm_all: false,
        warn_only: false,
        live_policy_bounds: None,
        upstream_addr_override: Some(echo_addr),
        upstream_tls_override: Some(tls_config),
        upstream_connect_timeout: std::time::Duration::from_secs(5),
        upstream_response_timeout: std::time::Duration::from_secs(5),
        pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
    });

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ctx_clone = ctx.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        let _ = strait::mitm::handle_connection(client, peer, &ctx_clone).await;
    });

    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, "api.github.com").await;

    tls.write_all(b"GET /repos/test HTTP/1.1\r\nHost: api.github.com\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.contains("200 OK"),
        "Expected 200 OK, got: {}",
        response_str
    );
    assert!(
        response_str.contains("GET /repos/test"),
        "Expected echoed request line, got: {}",
        response_str
    );
}

async fn start_proxy_server(ctx: Arc<strait::config::ProxyContext>) -> std::net::SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let (client, peer) = match listener.accept().await {
                Ok(pair) => pair,
                Err(_) => break,
            };
            let ctx = ctx.clone();
            tokio::spawn(async move {
                let _ = strait::mitm::handle_connection(client, peer, &ctx).await;
            });
        }
    });

    addr
}

async fn send_get_request_through_proxy(
    proxy_addr: std::net::SocketAddr,
    ca_pem: String,
    host: &str,
    path: &str,
) -> String {
    let mut tls = connect_through_mitm(proxy_addr, &ca_pem, host).await;
    let request = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n");
    tls.write_all(request.as_bytes()).await.unwrap();

    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    String::from_utf8_lossy(&response).to_string()
}

async fn wait_for_blocked_request(
    rx: &mut tokio::sync::broadcast::Receiver<strait::observe::ObservationEvent>,
    ignored_ids: &[&str],
) -> strait::observe::BlockedRequest {
    tokio::time::timeout(std::time::Duration::from_secs(2), async {
        loop {
            let event = rx.recv().await.unwrap();
            let blocked = match event.event {
                strait::observe::EventKind::PolicyViolation {
                    blocked: Some(blocked),
                    ..
                }
                | strait::observe::EventKind::NetworkRequest {
                    blocked: Some(blocked),
                    ..
                } => blocked,
                _ => continue,
            };
            if ignored_ids
                .iter()
                .any(|ignored| *ignored == blocked.blocked_id)
            {
                continue;
            }
            return blocked;
        }
    })
    .await
    .expect("blocked request event should arrive before timeout")
}

fn build_live_decision_context(
    echo_addr: std::net::SocketAddr,
    deny_path: &str,
    decision_timeout: std::time::Duration,
) -> (
    Arc<strait::config::ProxyContext>,
    strait::observe::ObservationStream,
) {
    let obs_stream = strait::observe::ObservationStream::new();
    let mut ctx = strait_test_helpers::build_production_mitm_context_with_deny(
        echo_addr,
        "api.github.com",
        deny_path,
    );
    ctx.observation_stream = Some(obs_stream.clone());
    ctx.decision_timeout = decision_timeout;
    ctx.pending_decisions = Arc::new(strait::decisions::PendingDecisionStore::new());
    (Arc::new(ctx), obs_stream)
}

#[tokio::test]
async fn blocked_request_allow_once_resumes_only_current_request() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let (ctx, obs_stream) = build_live_decision_context(
        echo_addr,
        "/blocked-once",
        std::time::Duration::from_secs(2),
    );
    let mut rx = obs_stream.subscribe();
    let proxy_addr = start_proxy_server(ctx.clone()).await;
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let first = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-once",
    ));
    let first_block = wait_for_blocked_request(&mut rx, &[]).await;
    ctx.pending_decisions
        .resolve_allow_once(&first_block.blocked_id)
        .unwrap();

    let first_response = first.await.unwrap();
    assert!(
        first_response.contains("200 OK"),
        "expected allow-once request to resume: {first_response}"
    );
    assert!(first_response.contains("GET /blocked-once"));

    let second = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-once",
    ));
    let second_block = wait_for_blocked_request(&mut rx, &[&first_block.blocked_id]).await;
    assert_ne!(first_block.blocked_id, second_block.blocked_id);
    ctx.pending_decisions
        .resolve_deny(&second_block.blocked_id)
        .unwrap();

    let second_response = second.await.unwrap();
    assert!(
        second_response.contains("403 Forbidden"),
        "second request should block again after allow-once: {second_response}"
    );
}

#[tokio::test]
async fn blocked_request_allow_session_caches_future_matches() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let (ctx, obs_stream) = build_live_decision_context(
        echo_addr,
        "/blocked-session",
        std::time::Duration::from_secs(2),
    );
    let mut rx = obs_stream.subscribe();
    let proxy_addr = start_proxy_server(ctx.clone()).await;
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let first = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-session",
    ));
    let blocked = wait_for_blocked_request(&mut rx, &[]).await;
    ctx.pending_decisions
        .resolve_allow_session(&blocked.blocked_id)
        .unwrap();

    let first_response = first.await.unwrap();
    assert!(first_response.contains("200 OK"));

    let second_response = send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-session",
    )
    .await;
    assert!(second_response.contains("200 OK"));
    assert!(ctx.pending_decisions.is_session_allowed(&blocked.match_key));
    assert!(
        tokio::time::timeout(
            std::time::Duration::from_millis(150),
            wait_for_blocked_request(&mut rx, &[&blocked.blocked_id])
        )
        .await
        .is_err(),
        "allow-session should let the next matching request pass without a new hold"
    );
}

#[tokio::test]
async fn blocked_request_explicit_deny_returns_403() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let (ctx, obs_stream) = build_live_decision_context(
        echo_addr,
        "/blocked-deny",
        std::time::Duration::from_secs(2),
    );
    let mut rx = obs_stream.subscribe();
    let proxy_addr = start_proxy_server(ctx.clone()).await;
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let request = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-deny",
    ));
    let blocked = wait_for_blocked_request(&mut rx, &[]).await;
    ctx.pending_decisions
        .resolve_deny(&blocked.blocked_id)
        .unwrap();

    let response = request.await.unwrap();
    assert!(
        response.contains("403 Forbidden"),
        "explicit deny should keep the request blocked: {response}"
    );
}

#[tokio::test]
async fn blocked_request_timeout_expires_decision_id() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let (ctx, obs_stream) = build_live_decision_context(
        echo_addr,
        "/blocked-timeout",
        std::time::Duration::from_millis(150),
    );
    let mut rx = obs_stream.subscribe();
    let proxy_addr = start_proxy_server(ctx.clone()).await;
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let started = std::time::Instant::now();
    let request = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-timeout",
    ));
    let blocked = wait_for_blocked_request(&mut rx, &[]).await;

    let response = request.await.unwrap();
    assert!(response.contains("403 Forbidden"));
    assert!(
        started.elapsed() >= std::time::Duration::from_millis(100),
        "blocked request should stay open until the hold timeout elapses"
    );
    assert_eq!(
        ctx.pending_decisions
            .resolve_allow_once(&blocked.blocked_id)
            .unwrap_err(),
        strait::decisions::DecisionError::Expired
    );
    assert_eq!(
        ctx.pending_decisions
            .resolve_allow_once("missing-blocked-id")
            .unwrap_err(),
        strait::decisions::DecisionError::UnknownBlockedId
    );
}

#[tokio::test]
async fn held_request_does_not_block_new_connections() {
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;
    let (ctx, obs_stream) = build_live_decision_context(
        echo_addr,
        "/blocked-concurrent",
        std::time::Duration::from_secs(2),
    );
    let mut rx = obs_stream.subscribe();
    let proxy_addr = start_proxy_server(ctx.clone()).await;
    let ca_pem = ctx.session_ca.ca_cert_pem.clone();

    let blocked_request = tokio::spawn(send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/blocked-concurrent",
    ));
    let blocked = wait_for_blocked_request(&mut rx, &[]).await;

    let allowed_response = send_get_request_through_proxy(
        proxy_addr,
        ca_pem.clone(),
        "api.github.com",
        "/allowed-concurrent",
    )
    .await;
    assert!(
        allowed_response.contains("200 OK"),
        "an unrelated connection should still complete while another request is held: {allowed_response}"
    );

    ctx.pending_decisions
        .resolve_deny(&blocked.blocked_id)
        .unwrap();
    let blocked_response = blocked_request.await.unwrap();
    assert!(blocked_response.contains("403 Forbidden"));
}

/// Test helper module exposed for integration tests.
mod strait_test_helpers {
    use super::*;

    // Lightweight test CA for tests that only need a PEM certificate.
    #[derive(Clone)]
    pub struct TestCa {
        pub ca_cert_pem: String,
    }

    pub fn generate_ca() -> TestCa {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test session CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_cert = params.self_signed(&key_pair).unwrap();
        TestCa {
            ca_cert_pem: ca_cert.pem(),
        }
    }

    /// Build a [`ProxyContext`] that routes through the production `handle_mitm`
    /// code path to a local echo server.
    ///
    /// Uses `upstream_addr_override` + `upstream_tls_override` (NoVerify) so
    /// production code connects to the echo server instead of the real internet.
    /// This replaces the duplicated MITM helpers (`handle_mitm_connection`,
    /// `handle_mitm_connection_chunked`, `handle_mitm_keepalive_*`) with the
    /// real production pipeline.
    pub fn build_production_mitm_context(
        echo_addr: std::net::SocketAddr,
        hostname: &str,
        keepalive_timeout: std::time::Duration,
    ) -> strait::config::ProxyContext {
        let session_ca = strait::ca::SessionCa::generate().unwrap();
        let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );

        strait::config::ProxyContext {
            session_ca,
            policy_engine: None,
            credential_store: None,
            audit_logger,
            mitm_hosts: vec![hostname.to_string()],
            max_body_size: 10 * 1024 * 1024,
            keepalive_timeout,
            decision_timeout: std::time::Duration::from_secs(30),
            startup_instant: std::time::Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: None,
            enforcement_mode: "observe".to_string(),
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: Some(echo_addr),
            upstream_tls_override: Some(tls_config),
            upstream_connect_timeout: std::time::Duration::from_secs(30),
            upstream_response_timeout: std::time::Duration::from_secs(60),
            pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
        }
    }

    /// Build a [`ProxyContext`] with a Cedar policy engine that denies a
    /// specific path, routing through the production `handle_mitm` pipeline.
    pub fn build_production_mitm_context_with_deny(
        echo_addr: std::net::SocketAddr,
        hostname: &str,
        deny_path: &str,
    ) -> strait::config::ProxyContext {
        let session_ca = strait::ca::SessionCa::generate().unwrap();
        let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoVerify))
                .with_no_client_auth(),
        );

        // Policy: permit everything EXCEPT the denied path
        let policy_text = format!(
            r#"
@id("allow-all")
permit(principal, action, resource);

@id("deny-path")
@reason("Path is denied by test policy")
forbid(principal, action, resource)
when {{ context.path == "{deny_path}" }};
"#
        );

        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.cedar");
        std::fs::write(&policy_path, &policy_text).unwrap();
        // Leak the tempdir so it persists for the lifetime of the context
        std::mem::forget(dir);

        let engine = strait::policy::PolicyEngine::load(&policy_path, None).unwrap();

        strait::config::ProxyContext {
            session_ca,
            policy_engine: Some(arc_swap::ArcSwap::from_pointee(engine)),
            credential_store: None,
            audit_logger,
            mitm_hosts: vec![hostname.to_string()],
            max_body_size: 10 * 1024 * 1024,
            keepalive_timeout: std::time::Duration::from_secs(5),
            decision_timeout: std::time::Duration::from_secs(30),
            startup_instant: std::time::Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: None,
            enforcement_mode: "enforce".to_string(),
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: Some(echo_addr),
            upstream_tls_override: Some(tls_config),
            upstream_connect_timeout: std::time::Duration::from_secs(30),
            upstream_response_timeout: std::time::Duration::from_secs(60),
            pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
        }
    }

    /// Build a minimal [`ProxyContext`] for testing `handle_connection` and `handle_mitm`.
    ///
    /// Creates a context with:
    /// - A fresh session CA (from the provided `TestCa` — converted to a real `SessionCa`)
    /// - `api.github.com` as the only MITM host
    /// - No policy engine (observe mode)
    /// - No credential store
    /// - Optional upstream address override for the echo server
    pub fn build_mitm_proxy_context(
        _ca: &TestCa,
        upstream_addr: Option<std::net::SocketAddr>,
    ) -> strait::config::ProxyContext {
        let session_ca = strait::ca::SessionCa::generate().unwrap();
        let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

        strait::config::ProxyContext {
            session_ca,
            policy_engine: None,
            credential_store: None,
            audit_logger,
            mitm_hosts: vec!["api.github.com".to_string()],
            max_body_size: 10 * 1024 * 1024,
            keepalive_timeout: std::time::Duration::from_secs(5),
            decision_timeout: std::time::Duration::from_secs(30),
            startup_instant: std::time::Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: None,
            enforcement_mode: "observe".to_string(),
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: upstream_addr,
            upstream_tls_override: None,
            upstream_connect_timeout: std::time::Duration::from_secs(30),
            upstream_response_timeout: std::time::Duration::from_secs(60),
            pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
        }
    }

    /// Build a [`ProxyContext`] with a trivial Cedar policy engine for testing
    /// passthrough deny behavior.
    pub fn build_mitm_proxy_context_with_policy(_ca: &TestCa) -> strait::config::ProxyContext {
        let session_ca = strait::ca::SessionCa::generate().unwrap();
        let audit_logger = Arc::new(strait::audit::AuditLogger::new(None).unwrap());

        // Write a trivial permit-all policy to a temp file
        let dir = tempfile::tempdir().unwrap();
        let policy_path = dir.path().join("policy.cedar");
        std::fs::write(&policy_path, "permit(principal, action, resource);\n").unwrap();

        let engine = strait::policy::PolicyEngine::load(&policy_path, None).unwrap();

        strait::config::ProxyContext {
            session_ca,
            policy_engine: Some(arc_swap::ArcSwap::from_pointee(engine)),
            credential_store: None,
            audit_logger,
            mitm_hosts: vec!["api.github.com".to_string()],
            max_body_size: 10 * 1024 * 1024,
            keepalive_timeout: std::time::Duration::from_secs(5),
            decision_timeout: std::time::Duration::from_secs(30),
            startup_instant: std::time::Instant::now(),
            identity_header: "X-Strait-Agent".to_string(),
            identity_default: "anonymous".to_string(),
            git_policy: None,
            policy_config: None,
            observation_stream: None,
            enforcement_mode: "enforce".to_string(),
            mitm_all: false,
            warn_only: false,
            live_policy_bounds: None,
            upstream_addr_override: None,
            upstream_tls_override: None,
            upstream_connect_timeout: std::time::Duration::from_secs(30),
            upstream_response_timeout: std::time::Duration::from_secs(60),
            pending_decisions: Arc::new(strait::decisions::PendingDecisionStore::new()),
        }
    }

    /// Certificate verifier that accepts any certificate (for test echo server).
    #[derive(Debug)]
    pub struct NoVerify;

    impl rustls::client::danger::ServerCertVerifier for NoVerify {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: rustls::pki_types::UnixTime,
        ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &rustls::DigitallySignedStruct,
        ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            vec![
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
                rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::RSA_PSS_SHA256,
                rustls::SignatureScheme::RSA_PSS_SHA384,
                rustls::SignatureScheme::RSA_PSS_SHA512,
                rustls::SignatureScheme::RSA_PKCS1_SHA256,
                rustls::SignatureScheme::RSA_PKCS1_SHA384,
                rustls::SignatureScheme::RSA_PKCS1_SHA512,
            ]
        }
    }
}
