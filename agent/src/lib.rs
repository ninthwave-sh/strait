//! Library surface for `strait-agent`.
//!
//! The shipping artifact is the `strait-agent` binary (`src/main.rs`).
//! Logic that deserves unit tests (and code paths exercised by the
//! integration tests under `agent/tests/`) lives here so it can be
//! exercised without spawning a process.
//!
//! Current contents:
//!
//! - [`config`]: startup config loader (`strait-agent.toml` + env-var
//!   overrides). Independent from the host-side `strait.toml` parser in
//!   the top-level `strait` crate -- the agent has a different, smaller
//!   config surface (proxy port, agent user, iptables redirect ports,
//!   host control-plane socket path).
//! - [`so_original_dst`]: recover the pre-DNAT destination of a
//!   REDIRECT'd TCP connection via `getsockopt(SO_ORIGINAL_DST)` on
//!   Linux, plus a pure sockaddr parser that is cross-platform testable.
//! - [`proxy`]: the in-container MITM proxy pipeline, ported from the
//!   top-level crate's `src/mitm.rs` with the SO_ORIGINAL_DST entry path
//!   as the new way to learn the original destination. Exposes
//!   [`proxy::run`] for the binary and [`proxy::handle_connection`] for
//!   integration tests.
//! - [`host_client`]: gRPC client for the host control plane. Connects
//!   over the bind-mounted Unix domain socket shared with `strait-host`.
//! - [`entrypoint`]: container entrypoint flow (`strait-agent entrypoint`).
//!   Verifies `CAP_NET_ADMIN`, spawns the proxy subprocess, installs the
//!   `iptables` OUTPUT REDIRECT rules, drops privileges to the configured
//!   agent user, and `exec`s the agent command. Linux-only at runtime;
//!   the module compiles cross-platform but `run()` errors on non-Linux.
//! - [`iptables`]: thin wrapper around the `iptables` binary used by
//!   [`entrypoint`]. Linux-only (the module is gated out on other
//!   platforms).
//!
//! Future phase (H-ICDP-4) will fill in container-side CA trust injection.

pub mod config;
pub mod credential_injector;
pub mod decision_client;
pub mod entrypoint;
pub mod host_client;
#[cfg(target_os = "linux")]
pub mod iptables;
pub mod observations;
pub mod proxy;
pub mod so_original_dst;

pub use config::AgentConfig;
pub use credential_injector::{
    CredentialInjector, CredentialOutcome, NoopCredentialInjector, RpcCredentialInjector,
};
pub use decision_client::{HostDecisionClient, DEFAULT_CALL_TIMEOUT};
pub use host_client::{connect_unix, HostClient, HostClientError};
pub use observations::{HostStreamingSink, NoopSink, ObservationSink};
