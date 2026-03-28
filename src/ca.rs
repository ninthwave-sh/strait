//! Session-local CA certificate generation.
//!
//! Each proxy session generates a fresh CA key pair. The CA cert is exported
//! as PEM so the caller can inject it into the sandbox's trust store. Per-host
//! leaf certificates are signed by this CA on demand during MITM.
//!
//! Leaf certificates are cached per-hostname to avoid expensive RSA key
//! generation on every CONNECT request. Cache entries expire after 1 hour
//! (well within the 24-hour CA lifetime).

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration as StdDuration, Instant};
use time::{Duration, OffsetDateTime};

/// Cache TTL for leaf certificates (1 hour).
const LEAF_CERT_CACHE_TTL: StdDuration = StdDuration::from_secs(3600);

/// Cached leaf certificate entry.
struct CachedLeafCert {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
    expires_at: Instant,
}

/// Holds the session CA certificate, key pair, and leaf certificate cache.
///
/// The leaf cache is shared across clones (via `Arc`) so all connection
/// handlers within a session benefit from cached certs.
#[derive(Clone)]
pub struct SessionCa {
    pub ca_cert_pem: String,
    ca_cert_der: CertificateDer<'static>,
    ca_key_pair: Arc<KeyPair>,
    leaf_cache: Arc<RwLock<HashMap<String, CachedLeafCert>>>,
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
            leaf_cache: Arc::new(RwLock::new(HashMap::new())),
        })
    }

    /// Issue a leaf certificate for the given hostname, signed by this CA.
    ///
    /// Returns a cached cert if one exists and has not expired; otherwise
    /// generates a fresh keypair and cert, caches it, and returns it.
    pub fn issue_leaf_cert(
        &self,
        hostname: &str,
    ) -> anyhow::Result<(Vec<CertificateDer<'static>>, PrivateKeyDer<'static>)> {
        // Fast path: return cached cert under read lock.
        {
            let cache = self.leaf_cache.read().expect("leaf cache lock poisoned");
            if let Some(entry) = cache.get(hostname) {
                if entry.expires_at > Instant::now() {
                    return Ok((entry.chain.clone(), entry.key.clone_key()));
                }
            }
        }

        // Cache miss or expired — generate a new leaf cert.
        let leaf_key = KeyPair::generate()?;

        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, hostname);
        params
            .subject_alt_names
            .push(rcgen::SanType::DnsName(hostname.try_into()?));
        params.not_before = OffsetDateTime::now_utc() - Duration::minutes(5);
        params.not_after = OffsetDateTime::now_utc() + Duration::hours(24);
        params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

        let ca_cert_params = CertificateParams::from_ca_cert_der(&self.ca_cert_der)?;
        let ca_cert_for_signing = ca_cert_params.self_signed(&self.ca_key_pair)?;

        let leaf_cert = params.signed_by(&leaf_key, &ca_cert_for_signing, &self.ca_key_pair)?;

        let chain = vec![
            CertificateDer::from(leaf_cert.der().to_vec()),
            self.ca_cert_der.clone(),
        ];

        let key_der = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der()));

        // Insert into cache under write lock.
        {
            let mut cache = self.leaf_cache.write().expect("leaf cache lock poisoned");
            cache.insert(
                hostname.to_string(),
                CachedLeafCert {
                    chain: chain.clone(),
                    key: key_der.clone_key(),
                    expires_at: Instant::now() + LEAF_CERT_CACHE_TTL,
                },
            );
        }

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

    #[test]
    fn cached_leaf_cert_returns_same_bytes() {
        let ca = SessionCa::generate().unwrap();
        let (chain1, key1) = ca.issue_leaf_cert("api.github.com").unwrap();
        let (chain2, key2) = ca.issue_leaf_cert("api.github.com").unwrap();

        // Second call must return the exact same DER bytes (cache hit).
        assert_eq!(chain1[0].as_ref(), chain2[0].as_ref());
        assert_eq!(chain1[1].as_ref(), chain2[1].as_ref());
        assert_eq!(key1, key2);
    }

    #[test]
    fn leaf_cert_includes_server_auth_eku() {
        let ca = SessionCa::generate().unwrap();
        let (chain, _key) = ca.issue_leaf_cert("api.github.com").unwrap();

        // id-kp-serverAuth OID: 1.3.6.1.5.5.7.3.1
        // DER-encoded OID value bytes (after tag+length): 2B 06 01 05 05 07 03 01
        let server_auth_oid = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];
        let leaf_der = chain[0].as_ref();
        let found = leaf_der
            .windows(server_auth_oid.len())
            .any(|w| w == server_auth_oid);
        assert!(
            found,
            "leaf certificate DER should contain id-kp-serverAuth OID"
        );
    }

    #[test]
    fn different_host_generates_different_cert() {
        let ca = SessionCa::generate().unwrap();
        let (chain_gh, _) = ca.issue_leaf_cert("api.github.com").unwrap();
        let (chain_gl, _) = ca.issue_leaf_cert("gitlab.com").unwrap();

        // Leaf certs for different hosts must differ.
        assert_ne!(chain_gh[0].as_ref(), chain_gl[0].as_ref());
        // CA cert (second in chain) is shared.
        assert_eq!(chain_gh[1].as_ref(), chain_gl[1].as_ref());
    }

    #[test]
    fn expired_cache_entry_triggers_regeneration() {
        let ca = SessionCa::generate().unwrap();
        let (chain1, _) = ca.issue_leaf_cert("api.github.com").unwrap();

        // Force the cache entry to be expired.
        {
            let mut cache = ca.leaf_cache.write().unwrap();
            if let Some(entry) = cache.get_mut("api.github.com") {
                entry.expires_at = Instant::now() - StdDuration::from_secs(1);
            }
        }

        let (chain2, _) = ca.issue_leaf_cert("api.github.com").unwrap();

        // Expired entry must trigger a fresh cert (different DER bytes
        // because a new keypair is generated).
        assert_ne!(chain2[0].as_ref(), chain1[0].as_ref());
    }
}
