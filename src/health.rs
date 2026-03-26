//! Health check HTTP endpoint.
//!
//! When `[health]` is configured in `strait.toml`, a lightweight HTTP server
//! binds to `127.0.0.1:<port>` and serves a JSON status response. The endpoint
//! reads from `Arc<ProxyContext>` — all state is immutable after startup, so no
//! locks are needed.
//!
//! If the health port is already in use at startup, a warning is logged and the
//! proxy continues without the health check.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use serde::Serialize;
use tokio::net::TcpListener;
use tracing::{info, warn};

use crate::config::ProxyContext;

/// JSON response body for the health endpoint.
#[derive(Debug, Serialize)]
pub struct HealthResponse {
    pub status: &'static str,
    pub session_id: String,
    pub uptime_seconds: u64,
    pub policy_loaded: bool,
    pub credentials_loaded: bool,
    pub mitm_hosts: Vec<String>,
}

/// Build a [`HealthResponse`] from the current [`ProxyContext`].
pub fn build_health_response(ctx: &ProxyContext) -> HealthResponse {
    HealthResponse {
        status: "healthy",
        session_id: ctx.audit_logger.session_id().to_string(),
        uptime_seconds: ctx.startup_instant.elapsed().as_secs(),
        policy_loaded: ctx.policy_engine.is_some(),
        credentials_loaded: ctx.credential_store.is_some(),
        mitm_hosts: ctx.mitm_hosts.clone(),
    }
}

/// Handle an incoming HTTP request on the health endpoint.
///
/// Returns `200 OK` with the JSON health status for any path.
async fn handle_health(
    ctx: Arc<ProxyContext>,
    _req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    let health = build_health_response(&ctx);
    let body = serde_json::to_string(&health).unwrap_or_else(|_| r#"{"status":"error"}"#.into());

    let response = Response::builder()
        .status(200)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap();

    Ok(response)
}

/// Start the health check HTTP server.
///
/// Binds to `127.0.0.1:<port>` and serves the health JSON response. If the port
/// is already in use, logs a warning and returns without crashing the proxy.
pub async fn start_health_server(port: u16, ctx: Arc<ProxyContext>) {
    let addr = SocketAddr::from(([127, 0, 0, 1], port));

    let listener = match TcpListener::bind(addr).await {
        Ok(l) => l,
        Err(e) => {
            warn!(port = port, error = %e, "health check port already in use, continuing without health endpoint");
            return;
        }
    };

    let local_addr = listener.local_addr().unwrap_or(addr);
    info!(port = local_addr.port(), "health check endpoint listening");

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "health check accept error");
                continue;
            }
        };

        let ctx = ctx.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let service = service_fn(move |req| {
                let ctx = ctx.clone();
                handle_health(ctx, req)
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                warn!(error = %e, "health check connection error");
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyContext, StraitConfig};
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_config(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    fn make_ctx(toml: &str) -> Arc<ProxyContext> {
        let f = write_config(toml);
        let config = StraitConfig::load(f.path()).unwrap();
        Arc::new(ProxyContext::from_config(&config).unwrap())
    }

    #[test]
    fn health_response_has_correct_json_fields() {
        let ctx = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
hosts = ["api.github.com"]
"#,
        );

        let health = build_health_response(&ctx);
        let json = serde_json::to_value(&health).unwrap();

        assert_eq!(json["status"], "healthy");
        assert!(json["session_id"].is_string());
        assert!(!json["session_id"].as_str().unwrap().is_empty());
        assert!(json["uptime_seconds"].is_u64());
        assert_eq!(json["policy_loaded"], false);
        assert_eq!(json["credentials_loaded"], false);
        assert_eq!(json["mitm_hosts"], serde_json::json!(["api.github.com"]));
    }

    #[test]
    fn policy_loaded_reflects_policy_engine() {
        // Without policy
        let ctx_no_policy = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let health = build_health_response(&ctx_no_policy);
        assert!(!health.policy_loaded);

        // With policy — need a valid Cedar policy file
        let mut policy_file = NamedTempFile::new().unwrap();
        policy_file
            .write_all(b"permit(principal, action, resource);")
            .unwrap();
        policy_file.flush().unwrap();

        let config_toml = format!(
            r#"
ca_cert_path = "/tmp/ca.pem"

[policy]
path = "{}"
"#,
            policy_file.path().display()
        );
        let ctx_with_policy = make_ctx(&config_toml);
        let health = build_health_response(&ctx_with_policy);
        assert!(health.policy_loaded);
    }

    #[test]
    fn credentials_loaded_reflects_credential_store() {
        // Without credentials
        let ctx_no_creds = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let health = build_health_response(&ctx_no_creds);
        assert!(!health.credentials_loaded);

        // With credentials
        std::env::set_var("STRAIT_HEALTH_TEST_TOKEN", "test-token");
        let ctx_with_creds = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "STRAIT_HEALTH_TEST_TOKEN"
"#,
        );
        let health = build_health_response(&ctx_with_creds);
        assert!(health.credentials_loaded);
        std::env::remove_var("STRAIT_HEALTH_TEST_TOKEN");
    }

    #[test]
    fn mitm_hosts_matches_configured_hosts() {
        let ctx_empty = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let health = build_health_response(&ctx_empty);
        assert!(health.mitm_hosts.is_empty());

        let ctx_hosts = make_ctx(
            r#"
ca_cert_path = "/tmp/ca.pem"

[mitm]
hosts = ["api.github.com", "api.stripe.com"]
"#,
        );
        let health = build_health_response(&ctx_hosts);
        assert_eq!(health.mitm_hosts, vec!["api.github.com", "api.stripe.com"]);
    }

    #[test]
    fn health_check_disabled_when_health_section_omitted() {
        let f = write_config(
            r#"
ca_cert_path = "/tmp/ca.pem"
"#,
        );
        let config = StraitConfig::load(f.path()).unwrap();
        assert!(config.health.is_none());
    }
}
