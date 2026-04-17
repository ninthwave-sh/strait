# Feat: In-container CA trust injection (H-ICDP-4)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 1
**Depends on:** H-ICDP-2
**Domain:** in-container-data-plane
**Lineage:** d12d72f2-3855-4d39-b646-beff69e9d717

Move CA trust injection fully inside the container. At entrypoint, after the proxy is up but before dropping to the agent user, write the session-local CA to the system trust stores and to common language-specific stores. Targets: `/etc/ssl/certs/ca-certificates.crt` (Debian/Ubuntu via `update-ca-certificates`), `/etc/pki/ca-trust/source/anchors/` (Fedora/RHEL via `update-ca-trust`), Node's `NODE_EXTRA_CA_CERTS`, Python's `REQUESTS_CA_BUNDLE`, and Go's `SSL_CERT_FILE`. Fallbacks in place when distro tools are missing.

**Test plan:**
- Docker integration test on Debian-based image: after entrypoint, `curl https://<host>` through the proxy succeeds; the CA is listed in `/etc/ssl/certs/ca-certificates.crt`.
- Docker integration test on a minimal image without `update-ca-certificates`: fallback directly appends to `/etc/ssl/certs/ca-certificates.crt` and `curl` still succeeds.
- Env export test: `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE` are present in the child process environment.

Acceptance: In a Debian-based and a Fedora-based container, an HTTPS request via the proxy is trusted by `curl`, `python -c "import requests; ..."`, and `node -e "require('https').get(...)"`. If neither `update-ca-certificates` nor `update-ca-trust` is available, the fallback path still produces a working trust store and the entrypoint logs a warning.

Key files: `agent/src/ca_trust.rs`, `agent/src/entrypoint.rs`, `agent/tests/ca_trust_integration.rs`
