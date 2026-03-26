# Feat: HTTP/1.1 keep-alive request loop in handle_mitm (H-V2-3)

**Priority:** High
**Source:** v0.2 roadmap — replace Connection: close mitigation
**Depends on:** None
**Domain:** mitm

Replace the current one-request-per-MITM-connection workaround (injecting `Connection: close`) with a proper HTTP/1.1 request loop in `handle_mitm`. After sending the upstream response back to the client, read the next request from the same TLS connection and repeat. The loop exits when: (a) the client sends `Connection: close`, (b) EOF on the client connection, (c) the upstream sends `Connection: close` in its response, or (d) a configurable idle timeout fires (default 30s, `[mitm].keepalive_timeout_secs`).

Remove the `Connection: close` injection from `handle_mitm` and from the 403/deny response builders. Update all tests that assert `Connection: close` is present — they should now assert it is NOT present (or only present when the upstream sends it).

**Implementation notes:**
- The existing bidirectional relay after the first response must be removed; it was a workaround for the one-request model.
- Request body buffering (already implemented for SigV4) must work correctly in a loop — reset buffer state between requests.
- Pipelining (multiple requests in flight) is NOT required — sequential request/response is sufficient.

**Test plan:**
- Two sequential requests on the same CONNECT tunnel → both succeed, second request processed after first response
- `Connection: close` from client → loop exits after that response
- Idle timeout fires → connection closed cleanly
- Policy deny mid-loop → 403 sent, loop continues (or exits per connection-close)
- All existing MITM integration tests pass with `Connection: close` assertions updated

Acceptance: `cargo test --all-features` passes. `cargo clippy` clean. No `Connection: close` injection on outbound requests. Benchmarks show measurable latency improvement on repeated requests to the same host.

Key files: `src/mitm.rs`, `src/config.rs` (keepalive_timeout_secs field), `tests/integration.rs`
