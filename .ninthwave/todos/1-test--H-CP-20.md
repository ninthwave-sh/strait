# Fix: SigV4 integration tests must exercise production code path (H-CP-20)

**Priority:** High
**Source:** design review of PR #18
**Depends on:** -
**Domain:** test

The SigV4 integration tests in `tests/integration.rs` use custom test helpers (`inject_sigv4_headers`, `handle_mitm_with_sigv4`) that duplicate the production MITM and signing logic. They test the test helper, not the production code. If the production `SigV4Credential` or `handle_mitm` has a bug, these tests won't catch it.

Required:
- Rewrite SigV4 integration tests to send requests through the actual proxy pipeline (like the bearer credential integration tests do)
- Configure a `ProxyContext` with a real `SigV4Credential` (using test AWS keys from env)
- Verify the upstream echo server receives correctly signed requests
- Remove or demote the test-helper-based tests to unit tests

Also add missing coverage:
- Empty body GET signing (e.g., S3 ListBucket)
- Session token / temporary credentials flow
- Virtual-hosted S3 style (`bucket.s3.region.amazonaws.com`)

**Test plan:**
- Integration tests use real ProxyContext → handle_connection → handle_mitm → SigV4Credential::inject → echo server
- Verify Authorization header, X-Amz-Date, X-Amz-Content-Sha256 on the echoed request

Key files: `tests/integration.rs` (SigV4 test section)
