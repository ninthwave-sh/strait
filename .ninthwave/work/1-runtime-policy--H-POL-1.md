# Feat: Add live network policy reload and replace through the session API (H-POL-1)

**Priority:** High
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** H-SES-1
**Domain:** runtime-policy
**Lineage:** 1c3b256c-0639-4cd0-9f8e-43e2131072a2
**Requires manual review:** true

Wire the new session control plane to the existing `ArcSwap` policy engine so network policy can be reloaded or replaced during a running session. Keep the runtime contract explicit: only new network requests see the updated policy, while filesystem mounts and proc allowlists remain restart-bound. Route both SIGHUP and session API updates through the same mutation path so reload behavior cannot drift.

**Test plan:**
- Add unit tests for policy reload and replace handlers, including invalid policy failures
- Add integration tests proving new requests observe the updated network policy while existing sessions stay up
- Verify unsupported live fs or proc mutations return a structured restart-required response

Acceptance: A running session supports `policy.reload` and `policy.replace` through the session API and applies valid network policy updates atomically to subsequent requests. Invalid updates leave the previous policy active and return a structured error. Attempts to live-update fs or proc enforcement return an explicit restart-required response.

Key files: `src/config.rs`, `src/launch.rs`, `src/policy.rs`
