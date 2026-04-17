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
//!
//! Future phases (H-ICDP-2, H-ICDP-4) will fill in the entrypoint
//! privilege-drop flow and container-side CA trust injection.

pub mod config;
pub mod proxy;
pub mod so_original_dst;

pub use config::AgentConfig;
