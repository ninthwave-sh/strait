//! strait — container-scoped MITM proxy with Cedar policy over network,
//! filesystem, and process access.
//!
//! This library crate re-exports the public modules used by the `strait`
//! binary and by integration tests.

use std::sync::Once;

pub mod audit;
pub mod ca;
pub mod config;
pub mod container;
pub mod control;
pub mod credentials;
pub mod decisions;
pub mod diff;
pub mod explain;
pub mod generate;
pub mod health;
pub mod launch;
pub mod mitm;
pub mod observe;
pub mod policy;
pub mod replay;
pub mod sigv4;
pub mod templates;
pub mod watch;

pub fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
