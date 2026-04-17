//! strait — container-scoped MITM proxy with Cedar policy over network,
//! filesystem, and process access.
//!
//! This library crate re-exports the public modules used by the `strait`
//! binary and by integration tests.

use std::sync::Once;

pub mod audit;
pub mod ca;
pub mod config;
pub mod decisions;
pub mod diff;
pub mod explain;
pub mod generate;
pub mod health;
pub mod mitm;
pub mod observe;
pub mod policy;
pub mod presets;
pub mod replay;
pub mod templates;

// The credential store (including AWS SigV4 signing) now lives in the
// `strait-host` crate. Re-export the modules here so existing callers in
// this crate's host-side code (`src/mitm.rs`, `src/config.rs`,
// `src/policy.rs`) keep compiling via `crate::credentials` /
// `crate::sigv4` during the in-container rewrite transition. Future
// work removes those host-side call sites and the re-export becomes
// unused.
pub use strait_host::credentials;
pub use strait_host::sigv4;

pub fn ensure_rustls_crypto_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
