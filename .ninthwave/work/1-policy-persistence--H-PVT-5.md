# Feat: Persist approved exceptions as durable network policy (H-PVT-5)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-4
**Domain:** policy-persistence
**Lineage:** bec7e8d1-8634-4a4f-b7c6-46fe126549f4
**Requires manual review:** true

Implement the persist action that turns an approved suggestion into durable network policy text, writes it to the configured policy source, and reapplies the updated rules without tearing down the session. Persisted output should be minimal, deterministic, and reviewable so users can see exactly what changed and avoid accumulating duplicate or overly broad rules.

**Test plan:**
- Add policy writer tests that ensure method or host or path suggestions serialize to the smallest stable Cedar rule
- Add reload tests proving network-only updates apply live while non-network edits still report restart-required output
- Cover duplicate-rule and broader-existing-rule cases so persist does not create redundant policy entries

Acceptance: Choosing persist writes a minimal network rule, reloads it into the running proxy, and leaves the next session pre-authorized for the same traffic without duplicate-rule churn.

Key files: `src/policy.rs`, `src/config.rs`, `src/main.rs`, `src/launch.rs`, `tests/integration.rs`
