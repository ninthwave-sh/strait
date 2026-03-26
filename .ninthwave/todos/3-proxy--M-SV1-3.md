# Fix: HTTP response formatting bug in MITM deny path (M-SV1-3)

**Priority:** Medium
**Source:** Strait v0.1 eng review — code quality issue #3
**Depends on:** None
**Domain:** proxy

The `format!` macro at `mitm.rs:136-145` uses line continuation (`\`) that preserves leading whitespace from indentation. This means HTTP 403 response headers get extra spaces prepended (e.g., `     Content-Type: application/json`) and the body gets leading spaces, making Content-Length incorrect. Fix by removing the indentation from continuation lines or using a different string building approach.

**Test plan:**
- Unit test: construct a deny response and verify no leading whitespace in headers or body
- Unit test: verify Content-Length matches actual body byte length
- Verify existing integration tests still pass

Acceptance: The 403 deny response has correctly formatted HTTP headers with no leading whitespace. Content-Length matches the body size exactly.

Key files: `src/mitm.rs`
