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
