# Feat: CA trust injection into container (M-CP-5)

**Priority:** Medium
**Source:** v0.3 container platform plan (eng review decision)
**Depends on:** H-CP-4
**Domain:** container

Inject the Strait session CA certificate into the container's system CA bundle at container start. The entrypoint script copies the container's existing CA bundle, appends Strait's CA PEM, and writes to a temp location. Environment variables (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS, REQUESTS_CA_BUNDLE) point to the augmented bundle.

Approach: bind-mount the CA PEM file into the container, then use a wrapper entrypoint that runs:
1. `cat /etc/ssl/certs/ca-certificates.crt /strait/ca.pem > /tmp/ca-bundle.pem` (or equivalent for the container's distro)
2. `export SSL_CERT_FILE=/tmp/ca-bundle.pem`
3. `exec "$@"` (run the user's original command)

**Test plan:**
- Unit test: entrypoint script generation produces valid shell script
- Integration test (requires Docker): start container with CA injection, verify `curl --silent https://httpbin.org/get` through the proxy succeeds (CA trusted)
- Edge case: container has no /etc/ssl/certs/ (Alpine uses /etc/ssl/cert.pem) -- detect and adapt
- Edge case: CA PEM file not bind-mounted -- clear error at container start

Acceptance: HTTPS requests from inside the container through the Strait proxy succeed without certificate errors. Works on Debian-based and Alpine-based container images.

Key files: `src/container.rs` (extend)
