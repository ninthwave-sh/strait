//! Test-only fixture that drives a real CONNECT + TLS + HTTP GET through the
//! in-container Strait gateway and reports line-oriented JSON events.

use anyhow::Context;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use serde::Serialize;
use std::env;
use std::io::{self, BufRead, Write};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

const PROBE_STEP_TIMEOUT: Duration = Duration::from_secs(15);

#[derive(Debug)]
struct ProbeConfig {
    host: String,
    port: u16,
    path: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ReadyEvent {
    event: &'static str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ProbeEvent<'a> {
    event: &'static str,
    status: &'a str,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
struct ExitEvent {
    event: &'static str,
    code: i32,
}

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
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

fn emit<T: Serialize>(event: &T) -> anyhow::Result<()> {
    let mut stdout = io::stdout().lock();
    serde_json::to_writer(&mut stdout, event).context("failed to serialize live policy probe")?;
    writeln!(stdout).context("failed to write live policy probe line")?;
    stdout
        .flush()
        .context("failed to flush live policy probe line")
}

fn parse_args() -> anyhow::Result<ProbeConfig> {
    let mut host = None;
    let mut port = None;
    let mut path = "/probe".to_string();

    let mut args = env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--host" => host = args.next(),
            "--port" => {
                let value = args.next().context("missing value for --port")?;
                port = Some(value.parse().context("invalid --port value")?);
            }
            "--path" => path = args.next().context("missing value for --path")?,
            other => anyhow::bail!("unexpected argument: {other}"),
        }
    }

    Ok(ProbeConfig {
        host: host.context("missing required --host")?,
        port: port.context("missing required --port")?,
        path,
    })
}

async fn read_connect_response(
    mut reader: BufReader<TcpStream>,
) -> anyhow::Result<(u16, TcpStream)> {
    let mut status_line = String::new();
    let bytes = reader
        .read_line(&mut status_line)
        .await
        .context("failed to read CONNECT status line")?;
    anyhow::ensure!(bytes > 0, "proxy closed before CONNECT response");

    loop {
        let mut line = String::new();
        let bytes = reader
            .read_line(&mut line)
            .await
            .context("failed to read CONNECT headers")?;
        anyhow::ensure!(bytes > 0, "proxy closed while reading CONNECT headers");
        if line.trim().is_empty() {
            break;
        }
    }

    let status = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|value| value.parse().ok())
        .unwrap_or(0);
    Ok((status, reader.into_inner()))
}

async fn perform_probe(config: &ProbeConfig) -> String {
    let proxy_addr: SocketAddr = "127.0.0.1:3128".parse().unwrap();
    let stream =
        match tokio::time::timeout(PROBE_STEP_TIMEOUT, TcpStream::connect(proxy_addr)).await {
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => return "proxy_connect_error".to_string(),
            Err(_) => return "proxy_connect_timeout".to_string(),
        };

    let mut reader = BufReader::new(stream);
    let connect_request = format!(
        "CONNECT {}:{} HTTP/1.1\r\nHost: {}:{}\r\n\r\n",
        config.host, config.port, config.host, config.port
    );

    if reader
        .get_mut()
        .write_all(connect_request.as_bytes())
        .await
        .is_err()
    {
        return "proxy_write_error".to_string();
    }

    let (connect_status, stream) =
        match tokio::time::timeout(PROBE_STEP_TIMEOUT, read_connect_response(reader)).await {
            Ok(Ok(result)) => result,
            Ok(Err(_)) => return "connect_response_error".to_string(),
            Err(_) => return "connect_response_timeout".to_string(),
        };

    if connect_status != 200 {
        return connect_status.to_string();
    }

    let tls_config = Arc::new(
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(tls_config);
    let server_name = match ServerName::try_from(config.host.clone()) {
        Ok(name) => name,
        Err(_) => return "invalid_server_name".to_string(),
    };

    let mut tls = match tokio::time::timeout(
        PROBE_STEP_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    {
        Ok(Ok(tls)) => tls,
        Ok(Err(_)) => return "tls_handshake_error".to_string(),
        Err(_) => return "tls_handshake_timeout".to_string(),
    };

    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
        config.path, config.host
    );
    if tls.write_all(request.as_bytes()).await.is_err() {
        return "request_write_error".to_string();
    }
    if tls.flush().await.is_err() {
        return "request_flush_error".to_string();
    }

    let mut tls_reader = BufReader::new(tls);
    let mut status_line = String::new();
    match tokio::time::timeout(PROBE_STEP_TIMEOUT, tls_reader.read_line(&mut status_line)).await {
        Ok(Ok(0)) => "upstream_error".to_string(),
        Ok(Ok(_)) => status_line
            .split_whitespace()
            .nth(1)
            .map(ToOwned::to_owned)
            .unwrap_or_else(|| "other".to_string()),
        Ok(Err(_)) => "upstream_error".to_string(),
        Err(_) => "upstream_timeout".to_string(),
    }
}

fn main() -> anyhow::Result<()> {
    strait::ensure_rustls_crypto_provider();
    let config = parse_args()?;
    let runtime = tokio::runtime::Runtime::new().context("failed to build tokio runtime")?;

    emit(&ReadyEvent { event: "ready" })?;

    for line in io::stdin().lock().lines() {
        let line = line.context("failed to read fixture stdin")?;
        match line.trim() {
            "probe" => {
                let status = runtime.block_on(perform_probe(&config));
                emit(&ProbeEvent {
                    event: "probe",
                    status: &status,
                })?;
            }
            "exit" => {
                emit(&ExitEvent {
                    event: "exit",
                    code: 0,
                })?;
                return Ok(());
            }
            _ => {}
        }
    }

    emit(&ExitEvent {
        event: "exit",
        code: 0,
    })?;
    Ok(())
}
