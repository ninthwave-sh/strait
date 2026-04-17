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
//! - [`entrypoint`]: container entrypoint flow (`strait-agent entrypoint`).
//!   Verifies `CAP_NET_ADMIN`, spawns the proxy subprocess, installs the
//!   `iptables` OUTPUT REDIRECT rules, drops privileges to the configured
//!   agent user, and `exec`s the agent command. Linux-only at runtime;
//!   the module compiles cross-platform but `run()` errors on non-Linux.
//! - [`iptables`]: thin wrapper around the `iptables` binary used by
//!   [`entrypoint`]. Linux-only (the module is gated out on other
//!   platforms).
//!
//! Future phase (H-ICDP-3) will fill in the MITM proxy pipeline.

pub mod config;
pub mod entrypoint;
#[cfg(target_os = "linux")]
pub mod iptables;

pub use config::AgentConfig;
