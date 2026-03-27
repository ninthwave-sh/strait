# Fix: Handle chunked Transfer-Encoding in MITM pipeline (H-CP-17)

**Priority:** High
**Source:** design review of PRs #1, #16, #22
**Depends on:** -
**Domain:** mitm

The MITM handler only reads request bodies when `Content-Length` is present. Requests with `Transfer-Encoding: chunked` (no Content-Length) get `body = None`, and the unread chunked data remains in the stream. In keep-alive mode, this corrupts subsequent request parsing — the chunked body bytes are interpreted as the next HTTP request line.

Three options:
- A) Decode chunked encoding into a buffered body (full support)
- B) Reject chunked requests with 411 Length Required (explicit rejection)
- C) Force `Connection: close` after a chunked request (prevent corruption)

Option A is ideal. Option B is acceptable for v0.2 — the GitHub API and AWS SDK both use Content-Length. Option C is the minimum to prevent silent corruption.

Also fix: malformed `Content-Length` (e.g., `abc`, `-1`) should return 400 Bad Request, not silently treat as no body.

**Test plan:**
- Integration test: POST with `Transfer-Encoding: chunked` through proxy — verify body arrives at upstream (option A) or clean error (option B)
- Integration test: malformed `Content-Length` returns 400
- Regression: existing Content-Length body forwarding still works

Key files: `src/mitm.rs` (body reading logic around line 136-154)
