# Refactor: Lock the container trust boundary and launch contract (H-CSM-1)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** None
**Domain:** container-trust-boundary
**Lineage:** c9da5bc7-dfe5-4f15-ba50-37f54ec7f49d
**Requires manual review:** true

Turn the current container-scoped CA injection and `--network=none` gateway path into an explicit, tested product contract. The launch path should make it obvious that trust lives inside the container only, that no machine-wide CA install is required for the primary runtime, and that the published session metadata is sufficient for later control-plane clients and operator debugging.

**Test plan:**
- Add launch integration coverage that the container receives the augmented CA bundle and trust env vars from `src/container.rs`
- Verify `src/launch.rs` and `src/main.rs` surface the session metadata and trust diagnostics needed to debug a failed launch
- Cover failure cases for missing gateway binary, unreadable CA bundle, and launch paths that would otherwise suggest host-wide trust workarounds

Acceptance: `strait launch` has a documented and tested container-only trust boundary, emits actionable diagnostics, and does not require a machine-wide CA installation for the supported flow.

Key files: `src/container.rs`, `src/launch.rs`, `src/main.rs`, `README.md`, `tests/launch_integration.rs`
