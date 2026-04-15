# Refactor: Narrow the product surface to network-only control plane (H-PVT-2)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-1
**Domain:** product-surface
**Lineage:** 2103126c-915c-4f95-9e91-d7ef2b0b9946

Reshape the repo around the pivot so the public runtime story is a network-only proxy and control plane, not container sandboxing or unified `fs:` and `proc:` policy. Remove or quarantine legacy product surfaces in CLI help, README text, architecture docs, and module exports so phase 1 stops presenting two competing products. Keep only the legacy compatibility that is still required to avoid breaking in-flight code.

**Test plan:**
- Update CLI parsing and help-text tests in `src/main.rs` for the new primary runtime story
- Run documentation-facing smoke checks by verifying every quick-start path in `README.md` points at proxy or daemon flows, not container launch flows
- Build and test after module or command removal to catch stale exports and dead code references

Acceptance: The repo has one clear phase-1 story: network policy proxy plus control plane. Legacy container or fs or proc surfaces are removed or clearly marked non-product internals across code and docs.

Key files: `src/main.rs`, `src/lib.rs`, `README.md`, `src/launch.rs`, `src/container.rs`, `docs/designs/unified-agent-policy-platform.md`
