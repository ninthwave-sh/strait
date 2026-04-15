# Feat: Emit blocked-request explanations and candidate exceptions (H-CSM-2)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-CSM-1
**Domain:** blocked-request-intel
**Lineage:** f5560bfe-a077-4f16-8f06-9c86ec0c84e6
**Requires manual review:** true

Extend the network event model so a denied request produces a stable blocked-request ID, a normalized match key, a clear explanation of why it failed, and the smallest candidate exception that could unblock it. Keep the payload aligned with the existing observation stream and `watch` UX so the later desktop client can consume the same semantics instead of inventing a second model.

**Test plan:**
- Add unit tests for suggestion synthesis in `src/policy.rs` across host-only, method-plus-host, and path-scoped cases
- Add serialization coverage in `src/observe.rs` for the richer blocked-request event payload and backwards-compatible decoding
- Verify `src/watch.rs` renders blocked-request details, including ambiguous-suggestion and no-suggestion cases

Acceptance: Blocked network requests emit parseable events that identify the request, explain the block, and provide a concrete once, session, or persist candidate exception payload.

Key files: `src/policy.rs`, `src/observe.rs`, `src/watch.rs`, `src/mitm.rs`
