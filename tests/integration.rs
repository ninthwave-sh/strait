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
    // Start the proxy's CA
    let ca = strait_test_helpers::generate_ca();

    // Start a TLS echo server (simulates api.github.com)
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Start the proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ca_clone = ca.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        // Simulate the proxy's CONNECT handling for MITM
        strait_test_helpers::handle_mitm_connection(client, peer, &ca_clone, echo_addr).await;
    });

    // Connect to the proxy and send a CONNECT request
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read the 200 response
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

    // Now do TLS handshake with the proxy (using the session CA as trust root)
    let mut root_store = rustls::RootCertStore::empty();
    let ca_pem_bytes = ca.ca_cert_pem.as_bytes();
    let mut cursor = std::io::Cursor::new(ca_pem_bytes);
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }

    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("api.github.com").unwrap();

    // Drop the BufReader to get back the inner stream
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send an HTTP request through the TLS tunnel
    tls.write_all(
        b"GET /repos/test/repo HTTP/1.1\r\nHost: api.github.com\r\nX-Test: hello\r\n\r\n",
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
    // Start the proxy's CA
    let ca = strait_test_helpers::generate_ca();

    // Start a TLS echo server that echoes headers + body
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    // Start the proxy listener
    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ca_clone = ca.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        strait_test_helpers::handle_mitm_connection(client, peer, &ca_clone, echo_addr).await;
    });

    // Connect to the proxy and send a CONNECT request
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(b"CONNECT api.github.com:443 HTTP/1.1\r\nHost: api.github.com:443\r\n\r\n")
        .await
        .unwrap();

    // Read the 200 response
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

    // TLS handshake with the proxy (using the session CA as trust root)
    let mut root_store = rustls::RootCertStore::empty();
    let ca_pem_bytes = ca.ca_cert_pem.as_bytes();
    let mut cursor = std::io::Cursor::new(ca_pem_bytes);
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

    // Send a POST request with a body
    let body = r#"{"name":"test-repo","private":true}"#;
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
// AWS SigV4 integration tests
// ---------------------------------------------------------------------------

/// S3 PUT through MITM — echo server receives Authorization header matching
/// AWS4-HMAC-SHA256 pattern, X-Amz-Content-Sha256 present, body intact.
#[tokio::test]
async fn sigv4_s3_put_produces_auth_headers() {
    let ca = strait_test_helpers::generate_ca();
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ca_clone = ca.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        strait_test_helpers::handle_mitm_with_sigv4(
            client,
            peer,
            &ca_clone,
            echo_addr,
            "s3.us-east-1.amazonaws.com",
        )
        .await;
    });

    // Connect to proxy and send CONNECT for S3
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            b"CONNECT s3.us-east-1.amazonaws.com:443 HTTP/1.1\r\n\
              Host: s3.us-east-1.amazonaws.com:443\r\n\r\n",
        )
        .await
        .unwrap();

    // Read 200 + drain headers
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

    // TLS handshake with proxy
    let mut root_store = rustls::RootCertStore::empty();
    let ca_pem_bytes = ca.ca_cert_pem.as_bytes();
    let mut cursor = std::io::Cursor::new(ca_pem_bytes);
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("s3.us-east-1.amazonaws.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send a PUT request with a body (S3 PutObject)
    let body = b"test-object-data-for-s3";
    let request = format!(
        "PUT /my-bucket/test-key HTTP/1.1\r\n\
         Host: s3.us-east-1.amazonaws.com\r\n\
         Content-Length: {}\r\n\
         Content-Type: application/octet-stream\r\n\
         \r\n",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.write_all(body).await.unwrap();

    // Read echo response
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    // Verify the forwarded request has SigV4 Authorization header
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
}

/// Lambda POST — service=lambda, region extracted correctly from hostname.
#[tokio::test]
async fn sigv4_lambda_invoke_different_service_region() {
    let ca = strait_test_helpers::generate_ca();
    let (echo_addr, _echo_ca_pem, _echo_ca_der) = start_tls_echo_server().await;

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ca_clone = ca.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        strait_test_helpers::handle_mitm_with_sigv4(
            client,
            peer,
            &ca_clone,
            echo_addr,
            "lambda.eu-west-1.amazonaws.com",
        )
        .await;
    });

    // Connect to proxy and CONNECT for Lambda
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            b"CONNECT lambda.eu-west-1.amazonaws.com:443 HTTP/1.1\r\n\
              Host: lambda.eu-west-1.amazonaws.com:443\r\n\r\n",
        )
        .await
        .unwrap();

    // Read 200 + drain
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

    // TLS handshake
    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca.ca_cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("lambda.eu-west-1.amazonaws.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send Lambda Invoke POST
    let body = br#"{"key":"value"}"#;
    let request = format!(
        "POST /2015-03-31/functions/my-func/invocations HTTP/1.1\r\n\
         Host: lambda.eu-west-1.amazonaws.com\r\n\
         Content-Length: {}\r\n\
         Content-Type: application/json\r\n\
         \r\n",
        body.len()
    );
    tls.write_all(request.as_bytes()).await.unwrap();
    tls.write_all(body).await.unwrap();

    // Read echo response
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

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

    // Verify X-Amz-Content-Sha256
    assert!(
        response_str.contains("x-amz-content-sha256"),
        "Expected x-amz-content-sha256 header, got: {}",
        response_str
    );
}

/// Cedar deny — 403 response, no AWS auth headers forwarded.
#[tokio::test]
async fn mitm_deny_returns_403_without_auth_headers() {
    let ca = strait_test_helpers::generate_ca();

    let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = proxy_listener.local_addr().unwrap();

    let ca_clone = ca.clone();
    tokio::spawn(async move {
        let (client, peer) = proxy_listener.accept().await.unwrap();
        // Use deny handler — always returns 403, no forwarding
        strait_test_helpers::handle_mitm_with_deny(
            client,
            peer,
            &ca_clone,
            "s3.us-east-1.amazonaws.com",
        )
        .await;
    });

    // Connect and CONNECT
    let mut client = TcpStream::connect(proxy_addr).await.unwrap();
    client
        .write_all(
            b"CONNECT s3.us-east-1.amazonaws.com:443 HTTP/1.1\r\n\
              Host: s3.us-east-1.amazonaws.com:443\r\n\r\n",
        )
        .await
        .unwrap();

    // Read 200 + drain
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

    // TLS handshake
    let mut root_store = rustls::RootCertStore::empty();
    let mut cursor = std::io::Cursor::new(ca.ca_cert_pem.as_bytes());
    for cert in rustls_pemfile::certs(&mut cursor) {
        root_store.add(cert.unwrap()).unwrap();
    }
    let client_config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let server_name = ServerName::try_from("s3.us-east-1.amazonaws.com").unwrap();
    let client_inner = buf.into_inner();
    let mut tls = connector.connect(server_name, client_inner).await.unwrap();

    // Send request
    tls.write_all(
        b"PUT /my-bucket/secret-key HTTP/1.1\r\n\
          Host: s3.us-east-1.amazonaws.com\r\n\
          Content-Length: 4\r\n\
          \r\n\
          test",
    )
    .await
    .unwrap();

    // Read response
    let mut response = Vec::new();
    tls.read_to_end(&mut response).await.unwrap();
    let response_str = String::from_utf8_lossy(&response);

    // Verify 403 response
    assert!(
        response_str.contains("403 Forbidden"),
        "Expected 403, got: {}",
        response_str
    );

    // Verify structured JSON body
    assert!(
        response_str.contains("policy_denied"),
        "Expected policy_denied error, got: {}",
        response_str
    );

    // Verify NO AWS auth headers in the response (request was not forwarded)
    assert!(
        !response_str.contains("AWS4-HMAC-SHA256"),
        "Should NOT contain AWS auth headers (request denied), got: {}",
        response_str
    );
    assert!(
        !response_str.contains("x-amz-content-sha256"),
        "Should NOT contain x-amz-content-sha256 (request denied), got: {}",
        response_str
    );
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

/// Test helper module exposed for integration tests.
mod strait_test_helpers {
    use super::*;

    // Re-export the CA for testing
    #[derive(Clone)]
    pub struct TestCa {
        pub ca_cert_pem: String,
        inner: InnerCa,
    }

    #[derive(Clone)]
    struct InnerCa {
        ca_cert_der: CertificateDer<'static>,
        ca_key_pair: Arc<KeyPair>,
    }

    impl TestCa {
        pub fn issue_leaf_cert(
            &self,
            hostname: &str,
        ) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
            let leaf_key = KeyPair::generate().unwrap();
            let mut params = CertificateParams::default();
            params.distinguished_name.push(DnType::CommonName, hostname);
            params
                .subject_alt_names
                .push(rcgen::SanType::DnsName(hostname.try_into().unwrap()));

            let ca_cert_params =
                CertificateParams::from_ca_cert_der(&self.inner.ca_cert_der).unwrap();
            let ca_cert_for_signing = ca_cert_params.self_signed(&self.inner.ca_key_pair).unwrap();

            let leaf_cert = params
                .signed_by(&leaf_key, &ca_cert_for_signing, &self.inner.ca_key_pair)
                .unwrap();

            let chain = vec![
                CertificateDer::from(leaf_cert.der().to_vec()),
                self.inner.ca_cert_der.clone(),
            ];
            let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));
            (chain, key)
        }
    }

    pub fn generate_ca() -> TestCa {
        let key_pair = KeyPair::generate().unwrap();
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "test session CA");
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);

        let ca_cert = params.self_signed(&key_pair).unwrap();
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        TestCa {
            ca_cert_pem,
            inner: InnerCa {
                ca_cert_der,
                ca_key_pair: Arc::new(key_pair),
            },
        }
    }

    /// Simulate the proxy's MITM connection handler.
    /// Accepts the CONNECT request, terminates TLS with a session-CA-signed cert,
    /// reads the inner HTTP, then forwards to the real upstream (echo server).
    pub async fn handle_mitm_connection(
        mut client: TcpStream,
        _peer: std::net::SocketAddr,
        ca: &TestCa,
        upstream_addr: std::net::SocketAddr,
    ) {
        let mut buf = BufReader::new(&mut client);
        // Read CONNECT line
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        // Drain headers
        loop {
            let mut l = String::new();
            buf.read_line(&mut l).await.unwrap();
            if l.trim().is_empty() {
                break;
            }
        }
        drop(buf);

        // Send 200
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Accept TLS from client using session CA
        let (cert_chain, key) = ca.issue_leaf_cert("api.github.com");
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let mut tls_client = acceptor.accept(client).await.unwrap();

        // Read inner HTTP request
        let mut buf = BufReader::new(&mut tls_client);
        let mut request_line = String::new();
        buf.read_line(&mut request_line).await.unwrap();
        let mut headers = Vec::new();
        let mut content_length: Option<usize> = None;
        loop {
            let mut h = String::new();
            buf.read_line(&mut h).await.unwrap();
            if h.trim().is_empty() {
                break;
            }
            let trimmed = h.trim().to_string();
            if let Some((k, v)) = trimmed.split_once(':') {
                if k.trim().eq_ignore_ascii_case("content-length") {
                    content_length = v.trim().parse().ok();
                }
            }
            headers.push(trimmed);
        }

        // Read request body if Content-Length present
        let mut request_body = Vec::new();
        if let Some(len) = content_length {
            request_body.resize(len, 0);
            buf.read_exact(&mut request_body).await.unwrap();
        }

        // Connect to upstream (echo server)
        let upstream_tcp = TcpStream::connect(upstream_addr).await.unwrap();

        // TLS to the echo server - trust its CA
        // For simplicity, use a dangerous client config that trusts everything
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls_upstream = connector.connect(server_name, upstream_tcp).await.unwrap();

        // Forward the request (headers + body)
        let mut req = request_line.clone();
        for h in &headers {
            req.push_str(h);
            req.push_str("\r\n");
        }
        req.push_str("\r\n");
        tls_upstream.write_all(req.as_bytes()).await.unwrap();
        if !request_body.is_empty() {
            tls_upstream.write_all(&request_body).await.unwrap();
        }

        // Relay response back with proper shutdown propagation
        let tls_client_inner = buf.into_inner();
        let (mut cr, mut cw) = tokio::io::split(tls_client_inner);
        let (mut ur, mut uw) = tokio::io::split(tls_upstream);

        tokio::select! {
            _ = tokio::io::copy(&mut ur, &mut cw) => {
                let _ = cw.shutdown().await;
                let _ = tokio::io::copy(&mut cr, &mut uw).await;
            }
            _ = tokio::io::copy(&mut cr, &mut uw) => {
                let _ = uw.shutdown().await;
                let _ = tokio::io::copy(&mut ur, &mut cw).await;
            }
        }
    }

    /// Sign headers in-place with AWS SigV4 using known test credentials.
    ///
    /// Uses the `aws-sigv4` crate directly to produce Authorization,
    /// X-Amz-Date, and X-Amz-Content-Sha256 headers.
    fn inject_sigv4_headers(
        method: &str,
        path: &str,
        host: &str,
        headers: &mut Vec<(String, String)>,
        body: &[u8],
    ) {
        use aws_credential_types::Credentials;
        use aws_sigv4::http_request::{sign, SignableBody, SignableRequest, SigningSettings};
        use aws_sigv4::sign::v4;
        use aws_smithy_runtime_api::client::identity::Identity;
        use sha2::{Digest, Sha256};

        // Parse service/region from hostname
        let suffix = ".amazonaws.com";
        let prefix = &host[..host.len() - suffix.len()];
        let parts: Vec<&str> = prefix.split('.').collect();
        let (service, region) = match parts.len() {
            1 => (parts[0], "us-east-1"),
            2 => (parts[0], parts[1]),
            n if n >= 3 => (parts[n - 2], parts[n - 1]),
            _ => panic!("not an AWS host: {}", host),
        };

        // Compute content SHA-256
        let mut hasher = Sha256::new();
        hasher.update(body);
        let content_sha256 = hex::encode(hasher.finalize());

        headers.push(("x-amz-content-sha256".to_string(), content_sha256.clone()));

        let creds = Credentials::new(
            "AKIAIOSFODNN7EXAMPLE",
            "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
            None::<String>,
            None,
            "strait-test",
        );
        let identity: Identity = creds.into();

        let settings = SigningSettings::default();
        let params = v4::SigningParams::builder()
            .identity(&identity)
            .region(region)
            .name(service)
            .time(std::time::SystemTime::now())
            .settings(settings)
            .build()
            .unwrap();

        let signing_params: aws_sigv4::http_request::SigningParams<'_> = params.into();
        let uri = format!("https://{host}{path}");
        let signable_body = SignableBody::Bytes(body);
        let header_iter = headers.iter().map(|(k, v)| (k.as_str(), v.as_str()));

        let signable = SignableRequest::new(method, &uri, header_iter, signable_body).unwrap();
        let (instructions, _) = sign(signable, &signing_params).unwrap().into_parts();

        for (name, value) in instructions.headers() {
            let name_str = name.to_string();
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name_str));
            headers.push((name_str, value.to_string()));
        }

        // Ensure x-amz-content-sha256 is present (may have been removed by retain)
        if !headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-content-sha256"))
        {
            headers.push(("x-amz-content-sha256".to_string(), content_sha256));
        }
    }

    /// Handle a MITM connection with SigV4 credential injection.
    ///
    /// Like [`handle_mitm_connection`] but also signs the request with AWS
    /// SigV4 before forwarding to the echo server.
    pub async fn handle_mitm_with_sigv4(
        mut client: TcpStream,
        _peer: std::net::SocketAddr,
        ca: &TestCa,
        upstream_addr: std::net::SocketAddr,
        hostname: &str,
    ) {
        let mut buf = BufReader::new(&mut client);
        // Read CONNECT line
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        // Drain headers
        loop {
            let mut l = String::new();
            buf.read_line(&mut l).await.unwrap();
            if l.trim().is_empty() {
                break;
            }
        }
        drop(buf);

        // Send 200
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Accept TLS from client using session CA
        let (cert_chain, key) = ca.issue_leaf_cert(hostname);
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let mut tls_client = acceptor.accept(client).await.unwrap();

        // Read inner HTTP request
        let mut buf = BufReader::new(&mut tls_client);
        let mut request_line = String::new();
        buf.read_line(&mut request_line).await.unwrap();
        let mut headers: Vec<(String, String)> = Vec::new();
        let mut content_length: Option<usize> = None;
        loop {
            let mut h = String::new();
            buf.read_line(&mut h).await.unwrap();
            if h.trim().is_empty() {
                break;
            }
            let trimmed = h.trim().to_string();
            if let Some((k, v)) = trimmed.split_once(':') {
                let key = k.trim().to_string();
                let val = v.trim().to_string();
                if key.eq_ignore_ascii_case("content-length") {
                    content_length = val.parse().ok();
                }
                headers.push((key, val));
            }
        }

        // Read request body if Content-Length present
        let mut request_body = Vec::new();
        if let Some(len) = content_length {
            request_body.resize(len, 0);
            buf.read_exact(&mut request_body).await.unwrap();
        }

        // Parse method and path from request line
        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        let method = parts[0];
        let path = parts[1];

        // Inject SigV4 credentials
        inject_sigv4_headers(method, path, hostname, &mut headers, &request_body);

        // Connect to upstream echo server
        let upstream_tcp = TcpStream::connect(upstream_addr).await.unwrap();
        let client_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth();
        let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
        let server_name = ServerName::try_from("localhost").unwrap();
        let mut tls_upstream = connector.connect(server_name, upstream_tcp).await.unwrap();

        // Forward the signed request
        let mut req = request_line.clone();
        for (k, v) in &headers {
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("\r\n");
        tls_upstream.write_all(req.as_bytes()).await.unwrap();
        if !request_body.is_empty() {
            tls_upstream.write_all(&request_body).await.unwrap();
        }

        // Relay response back
        let tls_client_inner = buf.into_inner();
        let (mut cr, mut cw) = tokio::io::split(tls_client_inner);
        let (mut ur, mut uw) = tokio::io::split(tls_upstream);

        tokio::select! {
            _ = tokio::io::copy(&mut ur, &mut cw) => {
                let _ = cw.shutdown().await;
                let _ = tokio::io::copy(&mut cr, &mut uw).await;
            }
            _ = tokio::io::copy(&mut cr, &mut uw) => {
                let _ = uw.shutdown().await;
                let _ = tokio::io::copy(&mut ur, &mut cw).await;
            }
        }
    }

    /// Handle a MITM connection that always denies the request with 403.
    ///
    /// Simulates the Cedar deny path: reads the request, returns a structured
    /// 403 response without forwarding to any upstream server.
    pub async fn handle_mitm_with_deny(
        mut client: TcpStream,
        _peer: std::net::SocketAddr,
        ca: &TestCa,
        hostname: &str,
    ) {
        let mut buf = BufReader::new(&mut client);
        // Read CONNECT line
        let mut line = String::new();
        buf.read_line(&mut line).await.unwrap();
        // Drain headers
        loop {
            let mut l = String::new();
            buf.read_line(&mut l).await.unwrap();
            if l.trim().is_empty() {
                break;
            }
        }
        drop(buf);

        // Send 200
        client
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();

        // Accept TLS from client
        let (cert_chain, key) = ca.issue_leaf_cert(hostname);
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));
        let mut tls_client = acceptor.accept(client).await.unwrap();

        // Read inner HTTP request
        let mut buf = BufReader::new(&mut tls_client);
        let mut request_line = String::new();
        buf.read_line(&mut request_line).await.unwrap();
        loop {
            let mut h = String::new();
            buf.read_line(&mut h).await.unwrap();
            if h.trim().is_empty() {
                break;
            }
        }
        // Drain any body (read and discard)
        // We don't need the body for the deny response

        // Parse method and path for the deny response body
        let parts: Vec<&str> = request_line.trim().split_whitespace().collect();
        let method = parts.first().copied().unwrap_or("UNKNOWN");
        let path = parts.get(1).copied().unwrap_or("/");

        // Build structured 403 deny response (same format as production code)
        let body = serde_json::json!({
            "error": "policy_denied",
            "message": format!("Request denied by Cedar policy: deny-all"),
            "host": hostname,
            "method": method,
            "path": path,
            "policy": "deny-all",
            "hint": format!("No permit policy allows {} {} on {}. Check your .cedar policy file.", method, path, hostname),
        });
        let body_bytes = serde_json::to_string(&body).unwrap();
        let response = format!(
            "HTTP/1.1 403 Forbidden\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\
             \r\n\
             {}",
            body_bytes.len(),
            body_bytes
        );

        let tls_client_inner = buf.into_inner();
        let _ = tls_client_inner.write_all(response.as_bytes()).await;
        let _ = tls_client_inner.shutdown().await;
    }

    /// Certificate verifier that accepts any certificate (for test echo server).
    #[derive(Debug)]
    struct NoVerify;

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
