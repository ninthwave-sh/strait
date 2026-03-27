//! strait — HTTPS proxy with Cedar policy evaluation, credential injection,
//! and audit logging.
//!
//! This library crate re-exports all modules for integration testing and
//! the binary entry point in `main.rs`.

pub mod audit;
pub mod ca;
pub mod config;
pub mod credentials;
pub mod generate;
pub mod health;
pub mod mitm;
pub mod observe;
pub mod policy;
pub mod sigv4;
