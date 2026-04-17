//! gRPC client for the host control plane.
//!
//! The in-container agent connects to `strait-host` over a Unix domain
//! socket that the container runtime bind-mounts from the host. Tonic's
//! `Endpoint` type is designed around TCP URIs, so we build a `Channel`
//! by supplying a custom connector that opens a `UnixStream` and wraps it
//! in the `hyper_util::rt::TokioIo` adapter required by tonic 0.12's
//! hyper-1 transport.
//!
//! This module is deliberately thin; the protocol types themselves live in
//! the shared `strait-proto` crate.

use std::path::{Path, PathBuf};

use hyper_util::rt::TokioIo;
use strait_proto::v1::strait_host_client::StraitHostClient;
use tokio::net::UnixStream;
use tonic::transport::{Channel, Endpoint, Uri};
use tower::service_fn;

/// Client handle for the strait host control plane.
pub type HostClient = StraitHostClient<Channel>;

/// Errors surfaced by [`connect_unix`].
#[derive(Debug)]
pub enum HostClientError {
    /// The synthesised endpoint URI failed to parse. Indicates a bug, not
    /// an operator-facing problem; we keep it as a variant so the type can
    /// absorb future URI-construction paths (e.g. abstract sockets).
    Endpoint(tonic::codegen::http::uri::InvalidUri),
    /// The underlying tonic transport could not establish the channel. The
    /// most common cause is a missing or permission-denied socket path.
    Transport(tonic::transport::Error),
}

impl std::fmt::Display for HostClientError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Endpoint(e) => write!(f, "invalid endpoint uri: {e}"),
            Self::Transport(e) => write!(f, "grpc transport error: {e}"),
        }
    }
}

impl std::error::Error for HostClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Endpoint(e) => Some(e),
            Self::Transport(e) => Some(e),
        }
    }
}

impl From<tonic::codegen::http::uri::InvalidUri> for HostClientError {
    fn from(e: tonic::codegen::http::uri::InvalidUri) -> Self {
        Self::Endpoint(e)
    }
}

impl From<tonic::transport::Error> for HostClientError {
    fn from(e: tonic::transport::Error) -> Self {
        Self::Transport(e)
    }
}

/// Connect to a strait-host over a Unix domain socket.
///
/// The host URI is a synthetic `http://strait-host.local` placeholder; tonic
/// requires some URI so it can derive the HTTP authority, but the actual
/// bytes go over the Unix socket the connector opens. The returned channel
/// is lazily connected: the first RPC performs the handshake.
pub async fn connect_unix(socket_path: impl AsRef<Path>) -> Result<HostClient, HostClientError> {
    let path: PathBuf = socket_path.as_ref().to_path_buf();
    let endpoint = Endpoint::try_from("http://strait-host.local")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_: Uri| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(&path).await?;
                Ok::<_, std::io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(HostClient::new(channel))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The connector module is async; this test exercises the error path so
    /// we know `HostClientError` renders a sensible message when the socket
    /// does not exist.
    #[tokio::test]
    async fn connect_reports_missing_socket() {
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("does-not-exist.sock");
        let err = connect_unix(&sock).await.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.to_lowercase().contains("transport"),
            "unexpected error: {msg}"
        );
    }
}
