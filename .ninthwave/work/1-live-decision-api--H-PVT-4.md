# Feat: Add live decision actions for blocked requests (H-PVT-4)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-3
**Domain:** live-decision-api
**Lineage:** 9b8098b1-de48-4a9d-af06-d0263cf292b2
**Requires manual review:** true

Add control-plane methods that let a client deny, allow once, or allow for session against a specific blocked-request ID without restarting the proxy. The runtime must track pending decisions, unblock or fail the waiting request path, and fall back cleanly to block-and-retry when true hold-and-resume is unavailable on the chosen proxy backend.

**Test plan:**
- Add control-protocol tests for the new methods and payload validation in the session or daemon control module
- Add integration coverage in `tests/integration.rs` for allow-once, allow-session, explicit deny, and expired or unknown decision IDs
- Verify block-and-retry fallback returns consistent state when a request cannot be held open

Acceptance: External clients can resolve a blocked request through the local control API, and repeated matching requests honor the selected once or session semantics for the active runtime.

Key files: `src/mitm.rs`, `src/main.rs`, `src/launch.rs`, `tests/integration.rs`
