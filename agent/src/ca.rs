//! Session-local CA certificate generation for the in-container agent.
//!
//! Each container lifetime gets a fresh CA key pair generated on entrypoint
//! startup. The CA is written to a known in-container path so the proxy can
//! load it (H-ICDP-3) and so the entrypoint can inject it into the system
//! trust store (see [`super::ca_trust`]).
//!
//! This is a separate, minimal copy of the host-side `src/ca.rs` generator
//! so the agent crate stays independent of the top-level crate's MITM
//! dependencies. When H-ICDP-3 moves the MITM pipeline into the agent crate
//! this module will grow a leaf-cert cache; for now it is deliberately just
//! "generate a CA and emit PEM".
//!
//! The CA is *session-local* -- lifetime 24 hours, regenerated on every
//! container start, never written to the host. It is only meaningful inside
//! the running container's trust boundary.

use anyhow::{Context as _, Result};
use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use time::{Duration, OffsetDateTime};

/// A freshly generated session CA.
pub struct SessionCa {
    /// CA certificate in PEM form. Safe to write world-readable.
    pub cert_pem: String,
    /// CA private key in PEM form. Readable only by the proxy process
    /// (root inside the container).
    pub key_pem: String,
}

impl SessionCa {
    /// Generate a new session CA with a fresh key pair.
    ///
    /// The CA is valid for 24 hours. The entrypoint regenerates on every
    /// start so a long-lived container that outlives the validity window
    /// is an explicit non-goal -- restart the container to rotate.
    pub fn generate() -> Result<Self> {
        let key_pair = KeyPair::generate().context("generate CA key pair")?;

        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "strait session CA");
        params
            .distinguished_name
            .push(DnType::OrganizationName, "strait");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::hours(24);

        let ca_cert = params.self_signed(&key_pair).context("self-sign CA")?;
        Ok(Self {
            cert_pem: ca_cert.pem(),
            key_pem: key_pair.serialize_pem(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_produces_pem_encoded_cert_and_key() {
        let ca = SessionCa::generate().unwrap();
        assert!(
            ca.cert_pem.contains("BEGIN CERTIFICATE"),
            "cert PEM should have BEGIN CERTIFICATE header: {}",
            ca.cert_pem
        );
        assert!(
            ca.cert_pem.contains("END CERTIFICATE"),
            "cert PEM should have END CERTIFICATE footer"
        );
        assert!(
            ca.key_pem.contains("PRIVATE KEY"),
            "key PEM should carry a private-key header: {}",
            ca.key_pem
        );
    }

    #[test]
    fn each_generate_call_produces_a_distinct_ca() {
        let a = SessionCa::generate().unwrap();
        let b = SessionCa::generate().unwrap();
        assert_ne!(
            a.cert_pem, b.cert_pem,
            "session CAs should be unique across generations"
        );
        assert_ne!(a.key_pem, b.key_pem);
    }
}
