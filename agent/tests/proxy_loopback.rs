//! Loopback integration test for `strait-agent proxy`.
//!
//! Simulates a REDIRECT'd TCP connection without actually calling out to
//! iptables: the test client TCP-connects directly to the proxy's listen
//! address. The proxy discovers the upstream through a test-only override
//! (since `SO_ORIGINAL_DST` would fail on a loopback socket that was
//! never routed through netfilter) and forwards to a local TLS echo
//! server. Reuses the `NoVerify` verifier pattern from
//! `tests/integration.rs` so the echo server's self-signed cert is
//! accepted for upstream connects.

use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Once};

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, SanType};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, ServerConfig};
use strait_agent::proxy::{self, AllowAllClient, HostRpcClient};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

fn ensure_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

/// Start a loopback TLS echo server that returns an HTTP 200 with the
/// exact request line as the body. Uses self-signed certs for
/// `api.github.com` (the hostname the client will SNI).
async fn start_tls_echo_server() -> SocketAddr {
    ensure_crypto_provider();

    let ca_key = KeyPair::generate().unwrap();
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "loopback-echo-ca");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    let ca_cert = ca_params.self_signed(&ca_key).unwrap();

    let leaf_key = KeyPair::generate().unwrap();
    let mut leaf_params = CertificateParams::default();
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "api.github.com");
    leaf_params
        .subject_alt_names
        .push(SanType::DnsName("api.github.com".try_into().unwrap()));
    leaf_params
        .subject_alt_names
        .push(SanType::DnsName("localhost".try_into().unwrap()));
    let leaf_cert = leaf_params.signed_by(&leaf_key, &ca_cert, &ca_key).unwrap();

    let chain = vec![
        CertificateDer::from(leaf_cert.der().to_vec()),
        CertificateDer::from(ca_cert.der().to_vec()),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

    let server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server_config));

    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    tokio::spawn(async move {
        loop {
            let Ok((tcp, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let tls = match acceptor.accept(tcp).await {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let (mut read, mut write) = tokio::io::split(tls);

                // Read request line + drain headers until blank line.
                let mut buf = Vec::with_capacity(512);
                let mut tmp = [0u8; 512];
                loop {
                    let n = match read.read(&mut tmp).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => n,
                    };
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let request_line = std::str::from_utf8(&buf)
                    .unwrap_or("<invalid utf8>")
                    .lines()
                    .next()
                    .unwrap_or("<no request line>")
                    .to_string();

                let body = format!("echoed: {request_line}");
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = write.write_all(response.as_bytes()).await;
                let _ = write.shutdown().await;
            });
        }
    });

    addr
}

/// Build a rustls `ClientConfig` that accepts any server cert. Mirrors
/// the `NoVerify` pattern from `tests/integration.rs` but vendored here
/// so the agent-crate test doesn't depend on top-level test helpers.
fn no_verify_client_config() -> Arc<ClientConfig> {
    ensure_crypto_provider();
    Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    )
}

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

/// Write a minimal allow-everything Cedar policy to a tempfile. Broad
/// enough that every `http:METHOD` action against every host passes. The
/// real security surface is exercised by the `src/policy.rs` tests --
/// here we only need to prove the proxy reaches the "allowed" branch and
/// forwards upstream.
fn write_allow_all_policy(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("allow-all.cedar");
    // The policy has to reference an Agent, Action, and Resource so the
    // authorizer's type inference is happy.
    std::fs::write(&path, r#"permit(principal, action, resource);"#).unwrap();
    path
}

/// Write a deny-all Cedar policy. Used to exercise the DENY branch.
fn write_deny_policy(dir: &std::path::Path) -> std::path::PathBuf {
    let path = dir.join("deny.cedar");
    // No permits — Cedar's default is deny, but we keep the file
    // non-empty so the policy loader doesn't reject it as trivially
    // malformed.
    std::fs::write(
        &path,
        r#"// intentional no-permit policy; Cedar's default is deny.
forbid(principal, action, resource);"#,
    )
    .unwrap();
    path
}

async fn spawn_proxy(
    policy_path: std::path::PathBuf,
    ca_cert_out: std::path::PathBuf,
    upstream_addr: SocketAddr,
    host_rpc: Arc<dyn HostRpcClient>,
) -> SocketAddr {
    let state = proxy::build_state(
        policy_path,
        ca_cert_out,
        host_rpc,
        Arc::new(strait_agent::observations::NoopSink),
        // Loopback tests exercise allow/deny only, not credential
        // injection. The no-op injector keeps the request unmodified
        // so the echo-server assertions still apply.
        Arc::new(strait_agent::credential_injector::NoopCredentialInjector),
        Some(upstream_addr),
        Some(no_verify_client_config()),
        10 * 1024 * 1024,
    )
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = proxy::accept_loop(listener, Arc::new(state)).await;
    });
    addr
}

/// Full loopback round trip: client TCP-connects to the proxy, does TLS
/// with `api.github.com` as the SNI, sends `GET /`, and expects the echo
/// server's response to come back.
#[tokio::test]
async fn proxy_completes_round_trip_on_allow() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_allow_all_policy(tmp.path());
    let ca_out = tmp.path().join("ca.pem");

    let echo_addr = start_tls_echo_server().await;
    let proxy_addr = spawn_proxy(policy, ca_out.clone(), echo_addr, Arc::new(AllowAllClient)).await;

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(no_verify_client_config());
    let server_name = ServerName::try_from("api.github.com").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let request =
        b"GET /repos HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/json\r\n\r\n";
    tls.write_all(request).await.unwrap();
    tls.flush().await.unwrap();

    let mut response = Vec::new();
    read_to_end_with_timeout(&mut tls, &mut response).await;
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.starts_with("HTTP/1.1 200 OK"),
        "expected 200 OK from echo server, got: {response_str}"
    );
    assert!(
        response_str.contains("echoed: GET /repos HTTP/1.1"),
        "expected echoed request line in body, got: {response_str}"
    );

    // The CA cert file is also written out as a side-effect of building
    // the state: the entrypoint (H-ICDP-4) relies on this file existing
    // at `--ca-cert`, so verify the shape now.
    let ca_pem = std::fs::read_to_string(&ca_out).unwrap();
    assert!(ca_pem.contains("BEGIN CERTIFICATE"));
    assert!(ca_pem.contains("END CERTIFICATE"));
}

/// Cedar policy denies the request and the placeholder host RPC also
/// denies -- client should receive HTTP 403 with a JSON body.
#[tokio::test]
async fn proxy_returns_403_when_policy_denies() {
    let tmp = tempfile::tempdir().unwrap();
    let policy = write_deny_policy(tmp.path());
    let ca_out = tmp.path().join("ca.pem");

    let echo_addr = start_tls_echo_server().await;
    let proxy_addr =
        spawn_proxy(policy, ca_out, echo_addr, Arc::new(proxy::PromptDenyClient)).await;

    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let connector = tokio_rustls::TlsConnector::from(no_verify_client_config());
    let server_name = ServerName::try_from("api.github.com").unwrap();
    let mut tls = connector.connect(server_name, tcp).await.unwrap();

    let request = b"DELETE /repos/x HTTP/1.1\r\nHost: api.github.com\r\n\r\n";
    tls.write_all(request).await.unwrap();
    tls.flush().await.unwrap();

    let mut response = Vec::new();
    read_to_end_with_timeout(&mut tls, &mut response).await;
    let response_str = String::from_utf8_lossy(&response);

    assert!(
        response_str.starts_with("HTTP/1.1 403 Forbidden"),
        "expected 403 Forbidden from proxy, got: {response_str}"
    );
    // Body should be JSON with "error": "policy_denied".
    let body_start = response_str.find("\r\n\r\n").unwrap() + 4;
    let body = &response_str[body_start..];
    let parsed: serde_json::Value = serde_json::from_str(body).unwrap();
    assert_eq!(parsed["error"], "policy_denied");
}

/// Helper: read from a TLS stream with a bounded timeout so test
/// failures don't hang CI. Returns whatever bytes arrived.
async fn read_to_end_with_timeout<R: AsyncReadExt + Unpin>(stream: &mut R, buf: &mut Vec<u8>) {
    let read = async {
        let mut tmp = [0u8; 4096];
        loop {
            match stream.read(&mut tmp).await {
                Ok(0) => return Ok::<_, io::Error>(()),
                Ok(n) => buf.extend_from_slice(&tmp[..n]),
                Err(e) => return Err(e),
            }
        }
    };
    let _ = tokio::time::timeout(std::time::Duration::from_secs(5), read).await;
}
