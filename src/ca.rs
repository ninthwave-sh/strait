//! Session-local CA certificate generation.
//!
//! Each proxy session generates a fresh CA key pair. The CA cert is exported
//! as PEM so the caller can inject it into the sandbox's trust store. Per-host
//! leaf certificates are signed by this CA on demand during MITM.

use rcgen::{BasicConstraints, CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::sync::Arc;
use time::{Duration, OffsetDateTime};

/// Holds the session CA certificate and key pair.
#[derive(Clone)]
pub struct SessionCa {
    pub ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    ca_key_pair: Arc<KeyPair>,
}

impl SessionCa {
    /// Generate a new session CA with a fresh key pair.
    pub fn generate() -> anyhow::Result<Self> {
        let key_pair = KeyPair::generate()?;

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

        let ca_cert = params.self_signed(&key_pair)?;
        let ca_cert_pem = ca_cert.pem();
        let ca_cert_der = CertificateDer::from(ca_cert.der().to_vec());

        Ok(Self {
            ca_cert_pem,
            ca_cert_der,
            ca_key_pair: Arc::new(key_pair),
        })
    }

    /// Generate a leaf certificate for the given hostname, signed by this CA.
    pub fn issue_leaf_cert(
        &self,
        hostname: &str,
    ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        let leaf_key = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(hostname.try_into()?));
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::hours(24);

        let ca_cert_params = CertificateParams::from_ca_cert_der(&self.ca_cert_der)?;
        let ca_cert_for_signing = ca_cert_params.self_signed(&self.ca_key_pair)?;

        let leaf_cert = params.signed_by(&leaf_key, &ca_cert_for_signing, &self.ca_key_pair)?;

        let chain = vec![
            CertificateDer::from(leaf_cert.der().to_vec()),
            self.ca_cert_der.clone(),
        ];

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        Ok((chain, key_der))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_generates_valid_pem() {
        let ca = SessionCa::generate().unwrap();
        assert!(ca.ca_cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(ca.ca_cert_pem.contains("END CERTIFICATE"));
    }

    #[test]
    fn ca_is_unique_per_call() {
        let ca1 = SessionCa::generate().unwrap();
        let ca2 = SessionCa::generate().unwrap();
        assert_ne!(ca1.ca_cert_pem, ca2.ca_cert_pem);
    }

    #[test]
    fn issue_leaf_cert_for_host() {
        let ca = SessionCa::generate().unwrap();
        let (chain, _key) = ca.issue_leaf_cert("api.github.com").unwrap();
        assert_eq!(chain.len(), 2); // leaf + CA
    }
}
