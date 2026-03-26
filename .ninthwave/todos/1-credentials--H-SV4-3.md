# Refactor: MITM body buffering (H-SV4-3)

**Priority:** High
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** H-SV4-1
**Domain:** credentials

Restructure the MITM pipeline to read the request body *before* credential injection. Currently the body is read after headers are reconstructed for upstream. SigV4 signing requires the body hash as input to the signature. Buffer the body in memory when Content-Length is present (with a configurable max size, default 10MB). Pass `Option<&[u8]>` body to the `Credential::inject` trait method. Bearer injection ignores the body (unchanged behavior). Requests without Content-Length pass `None`.

**Test plan:**
- Unit test: body buffered correctly for POST/PUT with Content-Length
- Unit test: GET request with no body passes `None` to inject
- Unit test: oversized body (exceeds max) returns 413 error, not forwarded
- Integration test: body content preserved through MITM pipeline (echo server returns same body)
- Existing integration tests pass (passthrough and MITM without body unchanged)

Acceptance: MITM pipeline reads body before calling `Credential::inject`. Body available as `Option<&[u8]>` in the inject call. Oversized bodies rejected with HTTP 413. All existing tests pass. No behavior change for bearer credentials.

Key files: `src/mitm.rs`
