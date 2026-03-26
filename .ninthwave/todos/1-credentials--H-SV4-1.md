# Refactor: Credential trait abstraction (H-SV4-1)

**Priority:** High
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** None
**Domain:** credentials

Extract a `Credential` trait from the existing bearer token injection. The trait's `inject` method takes method, path, headers, and an optional body slice — enabling signing-based credentials like SigV4. `BearerCredential` becomes the first impl. `CredentialStore` holds `Box<dyn Credential + Send + Sync>` keyed by host. Config gains a `type` field (defaulting to `"bearer"` for backward compat). The `inject_credential` function in mitm.rs calls the trait method instead of directly reading header/value.

**Test plan:**
- Unit tests for trait dispatch: store returns correct impl type per host
- BearerCredential roundtrip: same behavior as current `ResolvedCredential` (header replacement, prefix, case-insensitive)
- Config parsing: `type = "bearer"` explicit and omitted (default) both produce BearerCredential
- Existing integration tests pass unchanged (bearer path is unmodified behavior)

Acceptance: `Credential` trait defined with `fn inject(&self, method: &str, path: &str, headers: &[(String, String)], body: Option<&[u8]>) -> Option<Vec<(String, String)>>`. `BearerCredential` implements it. `CredentialStore::get` returns `&dyn Credential`. All 93 existing tests pass. `cargo clippy --all-features` clean.

Key files: `src/credentials.rs`, `src/mitm.rs`, `src/config.rs`
