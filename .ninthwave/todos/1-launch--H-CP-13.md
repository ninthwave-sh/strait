# Fix: Replace CONNECT-only proxy in `launch --observe` with full MITM (H-CP-13)

**Priority:** Critical
**Source:** design review of H-CP-7 (PR #36)
**Depends on:** -
**Domain:** launch

The `strait launch --observe` orchestrator (PR #36) implemented a lightweight CONNECT-tunneling proxy that only records host+port. It should use the existing MITM proxy from `mitm.rs` — the same approach `strait init --observe` (PR #33) uses — so observation logs capture full HTTP method, URL path, headers, and decision.

Current behavior in `launch.rs`:
- `run_proxy_loop()` / `handle_proxy_connection()` — separate CONNECT-only proxy
- Records: `method: "CONNECT", host, path: "", decision: "passthrough"`
- Useless for policy generation (no request detail)

Required behavior:
- Reuse `handle_connection` / `handle_mitm` from `main.rs`/`mitm.rs`
- Build a `ProxyContext` with policy=None (observe mode) and an `ObservationStream` attached
- MITM all connections (no `should_mitm()` check in observe mode — observe everything)
- Records: `method: "GET", host: "api.github.com", path: "/repos/org/repo", decision: "allow"`

Also delete the duplicate proxy code from `launch.rs` — there should be one proxy implementation, not two.

**Test plan:**
- Integration test: `launch --observe` with a container that makes an HTTP GET, verify observation JSONL contains full method + path (not just CONNECT)
- Unit test: verify proxy context is built with policy=None and observation stream attached
- Regression: existing `init --observe` tests still pass

Key files: `src/launch.rs` (remove duplicate proxy, wire existing proxy), `src/main.rs` (extract shared proxy setup if needed)
