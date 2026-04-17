# Refactor: Move MITM pipeline into strait-agent proxy (H-ICDP-3)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 1
**Depends on:** H-ICDP-1
**Domain:** in-container-data-plane
**Lineage:** 02a6a409-7f87-41aa-ac39-5b90a11eba76

Lift the existing MITM pipeline from `src/mitm.rs` into `agent/src/proxy.rs` as the implementation of `strait-agent proxy`. The new proxy accepts connections that were REDIRECTed by iptables, reads the original destination via `SO_ORIGINAL_DST` (Linux), performs TLS termination with the session-local CA, evaluates Cedar policy, and forwards upstream. Policy evaluation and Cedar code stay where they are; only the pipeline move and the SO_ORIGINAL_DST entry path are new. Placeholder host-control-plane RPC client returns "prompt -> deny" until H-HCP-* lands.

**Test plan:**
- Unit test: `SO_ORIGINAL_DST` parser returns the expected address for a canned sockopt payload.
- Loopback integration test: a TLS echo server plus `strait-agent proxy`, with a client TCP-connected to the proxy port, completes a round trip after TLS termination (reuses the `NoVerify` cert verifier pattern from `tests/integration.rs`).
- Regression: existing policy eval tests under `src/policy.rs` continue to pass.

Acceptance: `strait-agent proxy --policy policy.cedar --ca-cert /tmp/strait-ca.pem` accepts a REDIRECTed TCP connection (simulated in tests via direct connect), recovers the original destination, terminates TLS, evaluates the Cedar rule, and forwards to the upstream. The old `src/mitm.rs` still exists at this point for reference but is not wired into `strait-agent`.

Key files: `agent/src/proxy.rs`, `agent/src/so_original_dst.rs`, `agent/tests/proxy_loopback.rs`, `src/mitm.rs` (source of truth to port)
