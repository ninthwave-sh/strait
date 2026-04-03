# Fix: Upstream connection and response timeouts (H-MITM-1)

**Priority:** High
**Source:** ER-4.5
**Depends on:** None
**Domain:** mitm-pipeline
**Lineage:** 06bbe3b8-986c-4c74-8f9b-ba6f7eb08be8

Add configurable timeouts around upstream connection establishment and response handling in the MITM pipeline so slow upstream APIs do not hold client connections forever. The proxy should use `tokio::time::timeout` for the upstream connect and response phases, expose defaults through config, and return HTTP 504 when either timeout fires.

**Test plan:**
- Add config coverage for upstream connect and response timeout settings and their defaults.
- Add MITM tests that force a stalled upstream connect or response path and verify the proxy returns HTTP 504.
- Verify normal upstream traffic still succeeds when the timeouts do not fire.

Acceptance: The MITM pipeline enforces configurable upstream connection and response timeouts, and timeout failures return HTTP 504 instead of hanging indefinitely.

Key files: `src/config.rs`, `src/mitm.rs`, `tests/integration.rs`
