# Feat: Add blocked-request explanations and minimal exception suggestions (H-PVT-3)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-2
**Domain:** network-policy-engine
**Lineage:** 21e58efb-77d5-4049-a768-2028d9044b40
**Requires manual review:** true

Extend the network pipeline so a denied request produces a stable blocked-request ID, a normalized match key, a concrete explanation of why the request failed, and the smallest candidate exception that could unblock it. Update the observation and watch surfaces to carry the network-first payload that a desktop client needs instead of the older container-centric event assumptions.

**Test plan:**
- Add unit tests for suggestion synthesis in `src/policy.rs` across host-only, method-plus-host, and path-scoped cases
- Add serialization tests in `src/observe.rs` for the new blocked-request event payload and backwards-compatible decoding rules
- Verify `src/watch.rs` renders blocked-request details, including ambiguous-suggestion and no-suggestion cases

Acceptance: Blocked network requests emit parseable events that identify the request, explain the block, and provide a concrete once or session or persist suggestion payload for later decision actions.

Key files: `src/policy.rs`, `src/observe.rs`, `src/watch.rs`, `src/mitm.rs`
