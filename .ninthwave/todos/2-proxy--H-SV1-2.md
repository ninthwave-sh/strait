# Feat: Per-host leaf certificate cache (H-SV1-2)

**Priority:** High
**Source:** Strait v0.1 eng review — outside voice finding #6
**Depends on:** None
**Domain:** proxy

Add a per-host leaf certificate cache to `SessionCa`. Currently `issue_leaf_cert()` generates a fresh RSA keypair and signs a new certificate on every CONNECT request. With `Connection: close` forcing one-request-per-connection, this means expensive asymmetric key generation on every API call. Cache leaf certs in a `RwLock<HashMap<String, CachedLeafCert>>` where each entry holds the cert chain, private key, and an expiry timestamp. Certs are valid for 24 hours (matching the CA), so a 1-hour cache TTL is safe.

**Test plan:**
- Unit test: first call for a host generates a cert, second call returns the cached cert (same DER bytes)
- Unit test: cache miss for a different hostname generates a new cert
- Unit test: expired cache entry triggers regeneration
- Verify existing `issue_leaf_cert` tests still pass

Acceptance: `issue_leaf_cert("api.github.com")` called twice returns the same cert chain without generating a new keypair. Cache entries expire after 1 hour. Thread-safe via `RwLock`.

Key files: `src/ca.rs`
