//! strait-host: host control plane process for strait.
//!
//! The host binary is long-lived; it owns the rule store, credential store,
//! decision queue, and desktop UI RPC. This crate exposes the listener,
//! configuration primitives, decision queue, persisted rule store, and
//! gRPC service so integration tests can drive them without spawning a
//! subprocess.
//!
//! The wire protocol types live in the sibling `strait-proto` crate; this
//! crate provides the server-side implementation and the listener wiring.

pub mod config;
pub mod decisions;
pub mod grpc;
pub mod listener;
pub mod migrations;
pub mod rule_store;

pub use config::{
    default_config_path, default_rules_db_path, HostConfig, DEFAULT_RULES_DB_RELATIVE,
    DEFAULT_SOCKET_MODE, DEFAULT_TCP_LISTEN, DEFAULT_UNIX_SOCKET,
};
pub use decisions::{DecisionError, DecisionQueue, HoldInfo, PendingSummary, DEFAULT_HOLD_TIMEOUT};
pub use grpc::{ResolveError, StraitHostService};
pub use listener::{serve, serve_with_service, ShutdownSignal};
pub use rule_store::{Rule, RuleAction, RuleChange, RuleDuration, RuleStore};
