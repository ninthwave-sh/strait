//! Library surface for `strait-agent`.
//!
//! The shipping artifact is the `strait-agent` binary (`src/main.rs`).
//! Logic that deserves unit tests lives here so it can be exercised
//! without spawning a process.
//!
//! Current contents:
//!
//! - [`config`]: startup config loader (`strait-agent.toml` + env-var
//!   overrides). Independent from the host-side `strait.toml` parser in
//!   the top-level `strait` crate -- the agent has a different, smaller
//!   config surface (proxy port, agent user, iptables redirect ports,
//!   host control-plane socket path).
//!
//! Future phases (H-ICDP-2, H-ICDP-3, H-ICDP-4) will fill in the
//! entrypoint privilege-drop flow and the MITM proxy pipeline.

pub mod config;

pub use config::AgentConfig;
