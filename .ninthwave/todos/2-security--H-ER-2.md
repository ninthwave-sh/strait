# Fix: MITM request parsing -- CL/TE, HTTP version, passthrough deny (H-ER-2)

**Priority:** High
**Source:** ER-4 Findings 1-3, ER-8 Finding 4
**Depends on:** None
**Domain:** security

The MITM pipeline has three input validation gaps: (1) conflicting Content-Length and Transfer-Encoding headers are silently resolved instead of rejected per RFC 9112, (2) the HTTP request line doesn't validate the version token, and (3) the passthrough path forwards CONNECT to any host without validation, making the proxy an open relay. Fix by returning 400 for CL/TE conflicts, validating HTTP/1.0 or HTTP/1.1 version tokens, and denying passthrough to non-MITM hosts when a policy engine is active (one config lookup on mitm_hosts, no Cedar evals). Emit warn!() tracing for each new rejection type.

**Test plan:**
- Test that a request with both Content-Length and Transfer-Encoding: chunked returns 400 Bad Request
- Test that HTTP/0.9 and fabricated version strings (HTTP/9.9) return 400
- Test that CONNECT to a non-MITM host returns 403 when policy engine is active
- Test that CONNECT to a non-MITM host succeeds in observe mode (no policy)

Acceptance: CL/TE conflicts rejected with 400. HTTP version validated. Passthrough denied for non-MITM hosts when policy active. All rejections logged with structured tracing.

Key files: `src/mitm.rs`
