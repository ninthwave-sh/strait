//! In-container MITM proxy pipeline.
//!
//! Ported from the top-level crate's `src/mitm.rs`, with one structural change:
//! the proxy no longer receives HTTP `CONNECT` requests from a client that
//! was configured with `HTTPS_PROXY`. Instead, it accepts TCP connections
//! that were rerouted by iptables `-j REDIRECT` and recovers the original
//! destination via `SO_ORIGINAL_DST` (see [`super::so_original_dst`]).
//!
//! ## Shape of the pipeline
//!
//! 1. Accept a TCP connection on the proxy port.
//! 2. Recover the pre-DNAT destination (`(ip, port)`) from the kernel.
//! 3. Peek the TLS ClientHello to extract the SNI hostname — that is the
//!    host the Cedar policy is scoped by.
//! 4. Terminate TLS with a leaf cert for `sni_host`, signed by the
//!    session-local CA generated at startup.
//! 5. Read one HTTP request (method, path, headers, body).
//! 6. Evaluate the Cedar policy; on allow, forward to the original
//!    destination over real upstream TLS and relay the response back.
//!    On deny, call the placeholder host-control-plane RPC client
//!    (currently always returns `Deny`) and answer with HTTP 403.
//!
//! ## What is intentionally missing in this step
//!
//! Credential injection, live-decision hold-and-resume, observation-event
//! streaming, HTTP/1.1 keep-alive across multiple requests, and chunked
//! request-body decoding are all implemented in the host-side
//! `src/mitm.rs`. This port covers the allow/deny round trip needed by the
//! in-container proxy acceptance criteria; the richer behaviour will come
//! back in later work items as the host control plane lands
//! (`H-HCP-*`).

use std::future::Future;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::pin::Pin;
use std::sync::Arc;

use anyhow::Context as _;
use rustls::server::Acceptor;
use rustls::ClientConfig;
use strait::ca::SessionCa;
use strait::observe::{EventKind, ObservationEvent};
use strait::policy::PolicyEngine;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::{LazyConfigAcceptor, TlsConnector};
use tracing::{info, warn};

use crate::credential_injector::{CredentialInjector, CredentialOutcome, NoopCredentialInjector};
use crate::observations::{NoopSink, ObservationSink};

/// Placeholder host-control-plane RPC verdict.
///
/// H-HCP-4 replaces this with a real gRPC call into `strait-host` that
/// either asks a user for a decision or answers from a persisted rule
/// cache. Until then, the only outcome is `Deny` — matching the design
/// doc's "prompt -> deny" placeholder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostRpcVerdict {
    /// The host decided to allow the request (and, in the real flow,
    /// would hand back any credential to inject). Never produced by the
    /// default client.
    Allow,
    /// The host decided to deny the request.
    Deny,
}

/// Pinned future returned by host RPC clients.
pub type HostRpcFuture<'a> = Pin<Box<dyn Future<Output = HostRpcVerdict> + Send + 'a>>;

/// Host-control-plane client abstraction.
///
/// The default implementation ([`PromptDenyClient`]) always returns
/// [`HostRpcVerdict::Deny`] so every policy-denied request terminates in
/// an HTTP 403. Tests can provide an [`AllowAllClient`] to exercise the
/// forward-upstream path once the policy already granted allow, or to
/// inject an override decision.
///
/// Implemented as a trait with a `BoxFuture`-returning method rather than
/// `async fn` in trait so we can hold `Arc<dyn HostRpcClient>` without
/// pulling the `async-trait` crate into the agent's dep graph.
pub trait HostRpcClient: Send + Sync {
    /// Ask the host whether to override a policy-denied request.
    fn review_blocked<'a>(
        &'a self,
        host: &'a str,
        method: &'a str,
        path: &'a str,
    ) -> HostRpcFuture<'a>;
}

/// Default host client: always returns [`HostRpcVerdict::Deny`].
///
/// Matches the design doc's "prompt -> deny" placeholder. Any request
/// whose Cedar decision is `deny` terminates in HTTP 403 and is logged.
pub struct PromptDenyClient;

impl HostRpcClient for PromptDenyClient {
    fn review_blocked<'a>(
        &'a self,
        _host: &'a str,
        _method: &'a str,
        _path: &'a str,
    ) -> HostRpcFuture<'a> {
        Box::pin(async { HostRpcVerdict::Deny })
    }
}

/// Testing-only host client: always returns [`HostRpcVerdict::Allow`].
///
/// Only intended for integration tests that exercise the "deny by policy,
/// overridden by the host" branch.
#[doc(hidden)]
pub struct AllowAllClient;

impl HostRpcClient for AllowAllClient {
    fn review_blocked<'a>(
        &'a self,
        _host: &'a str,
        _method: &'a str,
        _path: &'a str,
    ) -> HostRpcFuture<'a> {
        Box::pin(async { HostRpcVerdict::Allow })
    }
}

/// Configuration for a single `strait-agent proxy` run.
pub struct ProxyConfig {
    /// TCP address the proxy binds to. iptables REDIRECT sends all
    /// port-80/443 traffic to this address.
    pub listen_addr: SocketAddr,
    /// Cedar policy file (`--policy`).
    pub policy_path: PathBuf,
    /// Where to export the CA cert PEM so the entrypoint (or test) can
    /// inject it into the container's trust store. The CA key stays in
    /// process memory only.
    pub ca_cert_out: PathBuf,
    /// Host-control-plane RPC client. Defaults to [`PromptDenyClient`].
    pub host_rpc: Arc<dyn HostRpcClient>,
    /// Observation sink the proxy reports each handled request to. Defaults
    /// to [`NoopSink`] so the proxy works correctly without a host. In
    /// production, wire a [`crate::observations::HostStreamingSink`] that
    /// forwards events to `strait-host`.
    pub observation_sink: Arc<dyn ObservationSink>,
    /// Credential fetcher the proxy consults on every allowed outbound.
    /// Defaults to [`NoopCredentialInjector`], which returns "no
    /// credential" and causes the proxy to forward requests unmodified.
    /// Production builds wire in [`crate::RpcCredentialInjector`] after
    /// a successful `RegisterContainer`.
    pub credential_injector: Arc<dyn CredentialInjector>,
    /// Test-only override: when `Some`, the proxy dials this address
    /// instead of the one recovered from `SO_ORIGINAL_DST`. Production
    /// code leaves this `None`.
    pub test_upstream_override: Option<SocketAddr>,
    /// Test-only override: when `Some`, the proxy uses this TLS client
    /// config for upstream connects (typically a `NoVerify` verifier for
    /// self-signed echo servers).
    pub test_upstream_tls: Option<Arc<ClientConfig>>,
    /// Maximum request body size the proxy will buffer before forwarding.
    pub max_body_size: usize,
}

impl ProxyConfig {
    /// Build a default `ProxyConfig` with the placeholder RPC client and
    /// the no-op credential injector.
    pub fn new(listen_addr: SocketAddr, policy_path: PathBuf, ca_cert_out: PathBuf) -> Self {
        Self {
            listen_addr,
            policy_path,
            ca_cert_out,
            host_rpc: Arc::new(PromptDenyClient),
            observation_sink: Arc::new(NoopSink),
            credential_injector: Arc::new(NoopCredentialInjector),
            test_upstream_override: None,
            test_upstream_tls: None,
            max_body_size: 10 * 1024 * 1024,
        }
    }
}

/// Shared per-connection state. Built once and cloned into each spawned
/// handler via `Arc`.
pub struct ProxyState {
    pub session_ca: SessionCa,
    pub policy: PolicyEngine,
    pub host_rpc: Arc<dyn HostRpcClient>,
    pub observation_sink: Arc<dyn ObservationSink>,
    pub credential_injector: Arc<dyn CredentialInjector>,
    pub test_upstream_override: Option<SocketAddr>,
    pub test_upstream_tls: Option<Arc<ClientConfig>>,
    pub max_body_size: usize,
}

/// Boot the in-container proxy: load policy, generate session CA, bind
/// the listener, and accept forever. Returns only on fatal I/O errors.
pub async fn run(cfg: ProxyConfig) -> anyhow::Result<()> {
    let state = Arc::new(build_state(
        cfg.policy_path.clone(),
        cfg.ca_cert_out.clone(),
        cfg.host_rpc.clone(),
        cfg.observation_sink.clone(),
        cfg.credential_injector.clone(),
        cfg.test_upstream_override,
        cfg.test_upstream_tls.clone(),
        cfg.max_body_size,
    )?);

    let listener = TcpListener::bind(cfg.listen_addr)
        .await
        .with_context(|| format!("failed to bind proxy to {}", cfg.listen_addr))?;
    let bound = listener.local_addr()?;
    info!(addr = %bound, "strait-agent proxy listening");

    accept_loop(listener, state).await
}

/// Build the shared proxy state outside of `run` so tests can construct
/// the pieces individually (custom listener, injected RPC client).
#[allow(clippy::too_many_arguments)]
pub fn build_state(
    policy_path: PathBuf,
    ca_cert_out: PathBuf,
    host_rpc: Arc<dyn HostRpcClient>,
    observation_sink: Arc<dyn ObservationSink>,
    credential_injector: Arc<dyn CredentialInjector>,
    test_upstream_override: Option<SocketAddr>,
    test_upstream_tls: Option<Arc<ClientConfig>>,
    max_body_size: usize,
) -> anyhow::Result<ProxyState> {
    strait::ensure_rustls_crypto_provider();

    let policy = PolicyEngine::load(&policy_path, None)
        .with_context(|| format!("failed to load Cedar policy from {}", policy_path.display()))?;
    let session_ca = SessionCa::generate().context("failed to generate session CA")?;

    // Export the CA cert so the container entrypoint (H-ICDP-4) can plant
    // it into the trust store before language runtimes start.
    std::fs::write(&ca_cert_out, session_ca.ca_cert_pem.as_bytes())
        .with_context(|| format!("failed to write CA cert to {}", ca_cert_out.display()))?;
    info!(path = %ca_cert_out.display(), "exported session CA cert");

    Ok(ProxyState {
        session_ca,
        policy,
        host_rpc,
        observation_sink,
        credential_injector,
        test_upstream_override,
        test_upstream_tls,
        max_body_size,
    })
}

/// Accept loop extracted so tests can feed a pre-bound listener (random
/// port on 127.0.0.1) without duplicating the listener-setup logic.
pub async fn accept_loop(listener: TcpListener, state: Arc<ProxyState>) -> anyhow::Result<()> {
    loop {
        let (conn, peer) = listener.accept().await?;
        let state = Arc::clone(&state);
        tokio::spawn(async move {
            if let Err(err) = handle_connection(conn, peer, state).await {
                warn!(peer = %peer, error = %err, "connection handler failed");
            }
        });
    }
}

/// Handle a single REDIRECT'd TCP connection end-to-end.
///
/// Split out of `run` so tests can drive the handler directly against a
/// pair of in-memory TCP streams (see `tests/proxy_loopback.rs`).
pub async fn handle_connection(
    conn: TcpStream,
    peer: SocketAddr,
    state: Arc<ProxyState>,
) -> anyhow::Result<()> {
    // Recover the original destination. On Linux with real iptables this
    // comes from `SO_ORIGINAL_DST`; under test we fall back to the
    // injected override so loopback tests don't have to set up netfilter.
    let original_dst = resolve_original_dst(&conn, state.test_upstream_override)?;

    // Peek the ClientHello so we know which host the Cedar policy is
    // scoped to and which leaf cert to issue.
    let acceptor = LazyConfigAcceptor::new(Acceptor::default(), conn);
    let handshake = acceptor
        .await
        .context("TLS ClientHello read failed (no ClientHello or malformed)")?;
    let sni_host = handshake
        .client_hello()
        .server_name()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("client omitted SNI; refusing MITM"))?;

    info!(
        peer = %peer,
        original_dst = %original_dst,
        sni = %sni_host,
        "accepted REDIRECT'd connection"
    );

    let server_config = build_server_config(&state.session_ca, &sni_host)
        .context("failed to build server TLS config")?;
    let tls = handshake
        .into_stream(Arc::new(server_config))
        .await
        .context("TLS accept from client failed")?;

    forward_one_request(tls, &sni_host, original_dst, state).await
}

/// Recover the original destination of an accepted connection.
///
/// On Linux this reads `SO_ORIGINAL_DST`. If that fails and the caller
/// provided a `test_upstream_override`, use that instead — the loopback
/// test suite can't install iptables rules, so it runs with the override
/// set. If neither works, fail loudly: a proxy that silently forwards to
/// the wrong address is the worst kind of bug.
fn resolve_original_dst(
    conn: &TcpStream,
    override_: Option<SocketAddr>,
) -> anyhow::Result<SocketAddr> {
    use std::os::unix::io::AsRawFd as _;

    match super::so_original_dst::get_original_dst(conn.as_raw_fd()) {
        Ok(addr) => Ok(addr),
        Err(err) => {
            if let Some(o) = override_ {
                return Ok(o);
            }
            Err(anyhow::anyhow!(
                "SO_ORIGINAL_DST lookup failed and no test override set: {err}"
            ))
        }
    }
}

/// Build a rustls `ServerConfig` that presents a leaf cert for `sni_host`,
/// signed by the session CA.
fn build_server_config(
    session_ca: &SessionCa,
    sni_host: &str,
) -> anyhow::Result<rustls::ServerConfig> {
    let (chain, key) = session_ca
        .issue_leaf_cert(sni_host)
        .context("failed to issue leaf cert for SNI host")?;
    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain, key)
        .context("rustls rejected the session-signed leaf cert")
}

/// Read one HTTP/1.x request from the TLS client, evaluate the policy,
/// forward to the upstream if allowed, and relay the response back.
///
/// This intentionally does *not* loop over keep-alive: the smallest thing
/// that satisfies the work item's acceptance criterion is a single round
/// trip. Keep-alive plus credential injection plus the full observe/decide
/// event stream come back as later items.
async fn forward_one_request<S>(
    tls: S,
    sni_host: &str,
    original_dst: SocketAddr,
    state: Arc<ProxyState>,
) -> anyhow::Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (read_half, mut write_half) = tokio::io::split(tls);
    let mut reader = BufReader::new(read_half);

    let request_start = std::time::Instant::now();
    let request = match read_http_request(&mut reader, state.max_body_size).await? {
        Some(req) => req,
        None => {
            // EOF before any request — client opened and closed the TLS
            // connection. Nothing to forward.
            return Ok(());
        }
    };

    // Cedar scopes http: actions by method. The ported pipeline in
    // `src/mitm.rs` uses the exact same action format, so the same policy
    // files keep working.
    let action = format!("http:{}", request.method);
    let decision = state
        .policy
        .evaluate(
            sni_host,
            &action,
            &request.path,
            &request.headers,
            "anonymous",
        )
        .context("policy evaluation failed")?;

    let allowed = if decision.allowed {
        info!(
            host = %sni_host,
            method = %request.method,
            path = %request.path,
            "ALLOW: Cedar policy permitted request"
        );
        true
    } else {
        // Placeholder RPC: by default this always returns Deny. The real
        // host control plane (H-HCP-*) will ask the user, and may return
        // Allow with an injected credential.
        let verdict = state
            .host_rpc
            .review_blocked(sni_host, &request.method, &request.path)
            .await;
        match verdict {
            HostRpcVerdict::Allow => {
                info!(
                    host = %sni_host,
                    method = %request.method,
                    path = %request.path,
                    "ALLOW: host RPC overrode policy denial"
                );
                true
            }
            HostRpcVerdict::Deny => {
                warn!(
                    host = %sni_host,
                    method = %request.method,
                    path = %request.path,
                    policy = ?decision.policy_names,
                    "DENY: Cedar policy denied and host RPC did not override"
                );
                false
            }
        }
    };

    if !allowed {
        emit_network_observation(
            &state.observation_sink,
            sni_host,
            &request.method,
            &request.path,
            "deny",
            request_start,
        );
        let body = strait::policy::deny_response_body(
            sni_host,
            &request.method,
            &request.path,
            &decision.policy_names,
        );
        let body_bytes = serde_json::to_string(&body)?;
        write_half
            .write_all(build_deny_response(&body_bytes).as_bytes())
            .await?;
        write_half.flush().await?;
        let _ = write_half.shutdown().await;
        return Ok(());
    }

    // Event is emitted as soon as the verdict is known so downstream
    // consumers (desktop UI, watch CLIs) see the decision regardless of
    // whether the upstream eventually fails mid-forward.
    emit_network_observation(
        &state.observation_sink,
        sni_host,
        &request.method,
        &request.path,
        "allow",
        request_start,
    );

    // Credential injection. The policy allowed the request, so we
    // round-trip to the host for whatever secret material this specific
    // outbound needs. The agent never caches; every allowed request
    // calls `FetchCredential` fresh. On RPC failure the injector fails
    // open (returns `None`), which the proxy applies below.
    let injection = state
        .credential_injector
        .fetch(
            sni_host,
            &action,
            &request.method,
            &request.path,
            &request.headers,
            request.body.as_deref(),
        )
        .await
        .context("credential injector failed")?;

    // Effective outbound method/path/headers after applying the
    // credential outcome. `Signed` rewrites method and URL; `Header`
    // replaces any same-named header; `None` leaves everything alone.
    let (effective_method, effective_path, effective_headers) =
        apply_credential(&request, sni_host, injection);

    // Forward upstream. In tests we dial the echo-server address and use
    // a NoVerify client config; in production we dial `original_dst` with
    // a webpki-roots-backed client config.
    let upstream_addr = state.test_upstream_override.unwrap_or(original_dst);
    let tls_config = match state.test_upstream_tls.clone() {
        Some(cfg) => cfg,
        None => default_upstream_tls_config(),
    };

    let upstream_tcp = TcpStream::connect(upstream_addr)
        .await
        .with_context(|| format!("failed to dial upstream {upstream_addr}"))?;
    let connector = TlsConnector::from(tls_config);
    let server_name = rustls::pki_types::ServerName::try_from(sni_host.to_string())
        .map_err(|e| anyhow::anyhow!("bad SNI hostname: {e}"))?;
    let upstream_tls = connector
        .connect(server_name, upstream_tcp)
        .await
        .with_context(|| format!("upstream TLS connect to {sni_host} failed"))?;

    let (upstream_read, mut upstream_write) = tokio::io::split(upstream_tls);

    // Reconstruct the request line + headers + body and write it to the
    // upstream. Format matches the ported pipeline in src/mitm.rs so the
    // shape is familiar to anyone reviewing both.
    let mut forwarded = format!("{effective_method} {effective_path} HTTP/1.1\r\n");
    for (name, value) in &effective_headers {
        forwarded.push_str(&format!("{name}: {value}\r\n"));
    }
    forwarded.push_str("\r\n");
    upstream_write.write_all(forwarded.as_bytes()).await?;
    if let Some(ref body) = request.body {
        upstream_write.write_all(body).await?;
    }
    upstream_write.flush().await?;

    let mut upstream_reader = BufReader::new(upstream_read);
    relay_upstream_response(&request.method, &mut upstream_reader, &mut write_half).await?;
    let _ = write_half.shutdown().await;
    Ok(())
}

/// Ship a `NetworkRequest` observation up to the configured sink.
///
/// Lives here (rather than inline) so the decision side and the
/// forwarded-allow side can share the exact same payload shape. The
/// timestamp uses the common RFC3339 millisecond format produced by
/// `src/observe.rs` so downstream tooling does not need to handle two
/// variants.
fn emit_network_observation(
    sink: &Arc<dyn ObservationSink>,
    host: &str,
    method: &str,
    path: &str,
    decision: &str,
    start: std::time::Instant,
) {
    let latency_us = start.elapsed().as_micros().min(u64::MAX as u128) as u64;
    let event = ObservationEvent {
        version: strait::observe::SCHEMA_VERSION,
        timestamp: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        session: None,
        event: EventKind::NetworkRequest {
            method: method.to_string(),
            host: host.to_string(),
            path: path.to_string(),
            decision: decision.to_string(),
            latency_us,
            enforcement_mode: String::new(),
            blocked: None,
        },
    };
    sink.emit(event);
}

/// Apply a [`CredentialOutcome`] to the parsed request, producing the
/// method, path, and header set the proxy should send upstream.
///
/// Pulled out of `forward_one_request` so the unit tests can exercise
/// the edit logic without standing up a TLS server.
fn apply_credential(
    request: &ParsedRequest,
    sni_host: &str,
    outcome: CredentialOutcome,
) -> (String, String, Vec<(String, String)>) {
    match outcome {
        CredentialOutcome::None => (
            request.method.clone(),
            request.path.clone(),
            request.headers.clone(),
        ),
        CredentialOutcome::Header { name, value } => {
            let mut headers = request.headers.clone();
            headers.retain(|(k, _)| !k.eq_ignore_ascii_case(&name));
            headers.push((name, value));
            (request.method.clone(), request.path.clone(), headers)
        }
        CredentialOutcome::Signed {
            method,
            url,
            headers,
        } => {
            // Extract the path (+ query) from the signed URL. Host-side
            // signing built this URL as `https://<sni>{path}`, so we
            // strip the `https://<sni>` prefix if present. If the URL is
            // unexpected we fall back to the original path rather than
            // dropping the request -- the signature was built over the
            // canonical URI, so either value round-trips to the same
            // upstream, and mismatches surface as a 403 from AWS.
            let path = url
                .strip_prefix(&format!("https://{sni_host}"))
                .map(str::to_string)
                .unwrap_or_else(|| request.path.clone());
            (method, path, headers)
        }
    }
}

fn default_upstream_tls_config() -> Arc<ClientConfig> {
    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    Arc::new(
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth(),
    )
}

/// Parsed inbound HTTP request.
#[derive(Debug)]
struct ParsedRequest {
    method: String,
    path: String,
    headers: Vec<(String, String)>,
    body: Option<Vec<u8>>,
}

/// Read one HTTP/1.x request from the client-facing TLS stream.
///
/// Simplification relative to `src/mitm.rs`: no chunked transfer-encoding
/// support (yet), only Content-Length. Anything else is forwarded as "no
/// body" — adequate for the first round trip, to be extended in a later
/// item when chunked upload clients land in the in-container proxy.
async fn read_http_request<R>(
    reader: &mut BufReader<R>,
    max_body_size: usize,
) -> anyhow::Result<Option<ParsedRequest>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let mut request_line = String::new();
    let n = reader.read_line(&mut request_line).await?;
    if n == 0 {
        return Ok(None); // EOF before any bytes
    }

    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 3 {
        anyhow::bail!(
            "malformed HTTP request line: {:?}",
            request_line.trim_end_matches(['\r', '\n'])
        );
    }
    let method = parts[0].to_string();
    let path = parts[1].to_string();
    let version = parts[2];
    if version != "HTTP/1.0" && version != "HTTP/1.1" {
        anyhow::bail!("unsupported HTTP version: {version}");
    }

    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: Option<usize> = None;
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).await?;
        if read == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            break;
        }
        if let Some((name, value)) = trimmed.split_once(':') {
            let name = name.trim().to_string();
            let value = value.trim().to_string();
            if name.eq_ignore_ascii_case("content-length") {
                content_length = value.parse().ok();
            }
            headers.push((name, value));
        }
    }

    let body = match content_length {
        Some(len) if len > max_body_size => {
            anyhow::bail!("request body {len} bytes exceeds max {max_body_size}");
        }
        Some(len) if len > 0 => {
            let mut buf = vec![0u8; len];
            reader.read_exact(&mut buf).await?;
            Some(buf)
        }
        _ => None,
    };

    Ok(Some(ParsedRequest {
        method,
        path,
        headers,
        body,
    }))
}

/// Relay an upstream response back to the client. Supports Content-Length
/// and read-until-EOF framing; chunked Transfer-Encoding is forwarded as a
/// raw stream.
async fn relay_upstream_response<R, W>(
    request_method: &str,
    upstream: &mut BufReader<R>,
    client: &mut W,
) -> anyhow::Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut status_line = String::new();
    upstream.read_line(&mut status_line).await?;
    client.write_all(status_line.as_bytes()).await?;

    let status_code: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(200);

    let mut content_length: Option<usize> = None;
    let mut chunked = false;
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
            }
        }
    }

    let has_body = !matches!(status_code, 100..=199 | 204 | 304)
        && !request_method.eq_ignore_ascii_case("HEAD");

    if has_body {
        if let Some(len) = content_length {
            let mut remaining = len;
            let mut buf = [0u8; 8192];
            while remaining > 0 {
                let to_read = buf.len().min(remaining);
                let n = upstream.read(&mut buf[..to_read]).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
                remaining -= n;
            }
        } else if chunked {
            // Forward chunked body byte-for-byte until terminal chunk.
            loop {
                let mut chunk_line = String::new();
                upstream.read_line(&mut chunk_line).await?;
                client.write_all(chunk_line.as_bytes()).await?;
                let size_str = chunk_line.trim().split(';').next().unwrap_or("0");
                let chunk_size = usize::from_str_radix(size_str, 16).unwrap_or(0);
                if chunk_size == 0 {
                    // Terminal chunk — relay trailers + final CRLF
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
                let mut remaining = chunk_size;
                let mut buf = [0u8; 8192];
                while remaining > 0 {
                    let to_read = buf.len().min(remaining);
                    let n = upstream.read(&mut buf[..to_read]).await?;
                    if n == 0 {
                        break;
                    }
                    client.write_all(&buf[..n]).await?;
                    remaining -= n;
                }
                let mut crlf = [0u8; 2];
                upstream.read_exact(&mut crlf).await?;
                client.write_all(&crlf).await?;
            }
        } else {
            // No content-length, no chunked — read until EOF.
            let mut buf = [0u8; 8192];
            loop {
                let n = upstream.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                client.write_all(&buf[..n]).await?;
            }
        }
    }

    client.flush().await?;
    Ok(())
}

/// Build an HTTP 403 deny response string from a JSON body. Keeps a
/// `Connection: close` header because, unlike the host-side pipeline,
/// we do not run a keep-alive loop yet.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deny_response_is_well_formed_403() {
        let body = r#"{"error":"policy_denied"}"#;
        let resp = build_deny_response(body);
        let lines: Vec<&str> = resp.split("\r\n").collect();
        assert_eq!(lines[0], "HTTP/1.1 403 Forbidden");
        assert_eq!(lines[1], "Content-Type: application/json");
        assert_eq!(lines[2], format!("Content-Length: {}", body.len()));
        assert_eq!(lines[3], "Connection: close");
        assert_eq!(lines[4], "");
        assert_eq!(lines[5], body);
    }

    #[test]
    fn deny_response_content_length_matches_body() {
        let body = r#"{"error":"policy_denied","reason":"test"}"#;
        let resp = build_deny_response(body);
        let body_start = resp.find("\r\n\r\n").unwrap() + 4;
        assert_eq!(&resp[body_start..], body);
    }

    #[tokio::test]
    async fn prompt_deny_client_always_denies() {
        let client = PromptDenyClient;
        let verdict = client.review_blocked("api.github.com", "GET", "/").await;
        assert_eq!(verdict, HostRpcVerdict::Deny);
    }

    #[tokio::test]
    async fn allow_all_client_always_allows() {
        let client = AllowAllClient;
        let verdict = client.review_blocked("api.github.com", "GET", "/").await;
        assert_eq!(verdict, HostRpcVerdict::Allow);
    }

    #[tokio::test]
    async fn read_http_request_parses_get_with_headers() {
        let input =
            b"GET /repos HTTP/1.1\r\nHost: api.github.com\r\nAccept: application/json\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let parsed = read_http_request(&mut reader, 1024).await.unwrap().unwrap();
        assert_eq!(parsed.method, "GET");
        assert_eq!(parsed.path, "/repos");
        assert_eq!(parsed.headers.len(), 2);
        assert_eq!(parsed.headers[0].0, "Host");
        assert!(parsed.body.is_none());
    }

    #[tokio::test]
    async fn read_http_request_reads_content_length_body() {
        let input = b"POST /submit HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello";
        let mut reader = BufReader::new(&input[..]);
        let parsed = read_http_request(&mut reader, 1024).await.unwrap().unwrap();
        assert_eq!(parsed.method, "POST");
        assert_eq!(parsed.body.as_deref(), Some(&b"hello"[..]));
    }

    #[tokio::test]
    async fn read_http_request_rejects_oversize_body() {
        let input = b"POST / HTTP/1.1\r\nContent-Length: 100\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let err = read_http_request(&mut reader, 10).await.unwrap_err();
        assert!(err.to_string().contains("exceeds max"));
    }

    #[tokio::test]
    async fn read_http_request_returns_none_on_eof() {
        let input: &[u8] = b"";
        let mut reader = BufReader::new(input);
        let parsed = read_http_request(&mut reader, 1024).await.unwrap();
        assert!(parsed.is_none());
    }

    #[tokio::test]
    async fn read_http_request_rejects_unknown_http_version() {
        let input = b"GET / HTTP/3.0\r\n\r\n";
        let mut reader = BufReader::new(&input[..]);
        let err = read_http_request(&mut reader, 1024).await.unwrap_err();
        assert!(err.to_string().contains("unsupported HTTP version"));
    }

    // ── apply_credential tests ────────────────────────────────────────

    fn parsed_request_fixture() -> ParsedRequest {
        ParsedRequest {
            method: "GET".to_string(),
            path: "/repos".to_string(),
            headers: vec![
                ("Host".to_string(), "api.github.com".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ],
            body: None,
        }
    }

    #[test]
    fn apply_credential_none_leaves_request_unchanged() {
        let req = parsed_request_fixture();
        let (method, path, headers) =
            apply_credential(&req, "api.github.com", CredentialOutcome::None);
        assert_eq!(method, "GET");
        assert_eq!(path, "/repos");
        assert_eq!(headers, req.headers);
    }

    #[test]
    fn apply_credential_header_adds_authorization_when_absent() {
        let req = parsed_request_fixture();
        let out = CredentialOutcome::Header {
            name: "Authorization".to_string(),
            value: "token gh_abc".to_string(),
        };
        let (method, path, headers) = apply_credential(&req, "api.github.com", out);
        assert_eq!(method, "GET");
        assert_eq!(path, "/repos");
        // Original two headers remain, Authorization is appended.
        assert_eq!(headers.len(), 3);
        let auth = headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .unwrap();
        assert_eq!(auth.1, "token gh_abc");
    }

    #[test]
    fn apply_credential_header_replaces_existing_same_name_case_insensitive() {
        let mut req = parsed_request_fixture();
        // Client set their own Authorization header; the credential
        // injector must stomp on it so the container can't leak an
        // ambient secret.
        req.headers
            .push(("authorization".to_string(), "leaked".to_string()));
        let out = CredentialOutcome::Header {
            name: "Authorization".to_string(),
            value: "token gh_abc".to_string(),
        };
        let (_, _, headers) = apply_credential(&req, "api.github.com", out);
        let auth_values: Vec<&String> = headers
            .iter()
            .filter(|(k, _)| k.eq_ignore_ascii_case("authorization"))
            .map(|(_, v)| v)
            .collect();
        assert_eq!(auth_values.len(), 1, "duplicate Authorization headers");
        assert_eq!(auth_values[0], "token gh_abc");
    }

    #[test]
    fn apply_credential_signed_rewrites_method_path_headers() {
        let req = parsed_request_fixture();
        let out = CredentialOutcome::Signed {
            method: "GET".to_string(),
            url: "https://s3.us-east-1.amazonaws.com/bucket/key".to_string(),
            headers: vec![
                ("Host".to_string(), "s3.us-east-1.amazonaws.com".to_string()),
                (
                    "Authorization".to_string(),
                    "AWS4-HMAC-SHA256 ...".to_string(),
                ),
                ("X-Amz-Date".to_string(), "20240115T120000Z".to_string()),
            ],
        };
        let (method, path, headers) = apply_credential(&req, "s3.us-east-1.amazonaws.com", out);
        assert_eq!(method, "GET");
        assert_eq!(path, "/bucket/key");
        assert_eq!(headers.len(), 3);
        assert!(headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("x-amz-date")));
        // Original Accept header is gone -- signed request is authoritative.
        assert!(!headers
            .iter()
            .any(|(k, _)| k.eq_ignore_ascii_case("accept")));
    }

    #[test]
    fn apply_credential_signed_falls_back_to_request_path_on_bad_url() {
        let req = parsed_request_fixture();
        let out = CredentialOutcome::Signed {
            method: "GET".to_string(),
            // URL doesn't match the SNI host -- fall back to the
            // pre-signed path rather than shipping a nonsensical URL.
            url: "https://other-host.example/whatever".to_string(),
            headers: vec![],
        };
        let (_, path, _) = apply_credential(&req, "s3.us-east-1.amazonaws.com", out);
        assert_eq!(path, "/repos");
    }
}
