# Test: Integration tests and AWS examples (M-SV4-6)

**Priority:** Medium
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** H-SV4-5, M-SV4-4
**Domain:** testing

Add loopback integration tests for the full SigV4 MITM flow and example Cedar policies for AWS services. Integration tests: (1) signed S3 PUT — verify Authorization and X-Amz-Content-Sha256 headers present and well-formed in forwarded request, (2) signed Lambda invoke — verify different service/region in signature, (3) deny path — Cedar policy denies request, no signing occurs, 403 returned. Example files: `examples/aws.cedar` with permit/forbid rules using `aws_service` and `aws_region` context, `examples/aws.cedarschema` with AWS context attributes, updated `examples/strait.toml` showing AWS credential config alongside existing GitHub config.

**Test plan:**
- Integration test: S3 PUT through MITM — echo server receives Authorization header matching `AWS4-HMAC-SHA256` pattern, X-Amz-Content-Sha256 present, body intact
- Integration test: Lambda POST — service=lambda, region extracted correctly from hostname
- Integration test: Cedar deny — 403 response, no AWS auth headers in forwarded request (request not forwarded)
- Integration test: passthrough for non-MITM AWS hosts — no decryption, no signing
- Manual review: example Cedar policies are valid (`cedar validate` against schema)

Acceptance: 3+ new integration tests pass. Example AWS Cedar policy validates against example schema. `examples/strait.toml` demonstrates AWS + GitHub credential coexistence. All existing tests pass.

Key files: `tests/integration.rs`, `examples/aws.cedar`, `examples/aws.cedarschema`, `examples/strait.toml`
