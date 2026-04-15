# Feat: Persist approved network exceptions as durable Cedar policy (H-CSM-4)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-CSM-3
**Domain:** durable-network-policy
**Lineage:** 02c72478-94fb-48ec-85ab-fe010647e14a
**Requires manual review:** true

Implement the persist action that turns an approved suggestion into durable network policy text, writes it to the configured policy source, and reapplies the updated network rules without tearing down the running session. Persisted output should stay minimal, deterministic, and reviewable so users can see exactly what changed and avoid duplicate or overly broad rules.

**Test plan:**
- Add policy writer tests that ensure method, host, and path suggestions serialize to the smallest stable Cedar rule
- Add reload tests proving network-only updates apply live while non-network edits still report restart-required output
- Cover duplicate-rule and broader-existing-rule cases so persist does not create redundant policy entries

Acceptance: Choosing persist writes a minimal network rule, reloads it into the running session, and leaves the next launched session pre-authorized for the same traffic without duplicate-rule churn.

Key files: `src/policy.rs`, `src/config.rs`, `src/launch.rs`, `src/main.rs`, `tests/integration.rs`
