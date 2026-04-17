//! strait-host: host control plane process for strait.
//!
//! The host binary is long-lived; it owns the rule store, credential store,
//! decision queue, and desktop UI RPC. This crate exposes the listener and
//! configuration primitives so integration tests can drive them without
//! spawning a subprocess.
//!
//! Protocol definitions (gRPC, frame shapes, message types) live in the
//! sibling H-HCP-2 work item; this crate intentionally ships only the
//! process skeleton: config loading, listener wiring, logging, and
//! graceful shutdown.

pub mod config;
pub mod listener;

pub use config::{
    default_config_path, HostConfig, DEFAULT_SOCKET_MODE, DEFAULT_TCP_LISTEN, DEFAULT_UNIX_SOCKET,
};
pub use listener::{serve, ShutdownSignal};
