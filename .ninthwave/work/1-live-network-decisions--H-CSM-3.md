# Feat: Add live decision actions for container-backed sessions (H-CSM-3)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-CSM-2
**Domain:** live-network-decisions
**Lineage:** d1bbae5b-fa0e-47c2-ae07-3e823a2b4f92
**Requires manual review:** true

Add control-plane methods that let a client deny, allow once, or allow for session against a specific blocked-request ID without restarting the launched container session. The runtime must track pending decisions, unblock or fail the waiting request path, and fall back cleanly to block-and-retry when true hold-and-resume is unavailable.

**Test plan:**
- Add control-protocol tests for the new decision methods and payload validation in the launch session control module
- Add integration coverage in `tests/integration.rs` for allow-once, allow-session, explicit deny, and expired or unknown decision IDs
- Verify block-and-retry fallback returns consistent state when a request cannot be held open through the live decision path

Acceptance: External clients can resolve a blocked request through the local control API, and repeated matching requests honor the selected once or session semantics for the active container-backed session.

Key files: `src/launch.rs`, `src/main.rs`, `src/mitm.rs`, `tests/integration.rs`
