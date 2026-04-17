# Refactor: Preset library in host control plane (M-ONB-2)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 4
**Depends on:** H-HCP-3
**Domain:** onboarding
**Lineage:** 07e9b85f-0d25-4057-a026-498f185b430d

Move preset Cedar policies (existing `src/presets.rs` and `src/templates.rs` entries) into the host control plane as server-side defaults. Any newly registered container can opt in to a preset by id via its feature config or a desktop-shell action. Presets become first-class rules in the store with the `preset:<id>` marker so they are distinguishable from user-authored rules.

**Test plan:**
- Unit test: loading the bundled preset library registers the expected rule set in the store.
- Integration test: container A opts into `preset:github-read`; `StreamRules` delivers the preset's rules to A only.
- Edge case: preset updated across a version bump -- existing containers keep their pinned version unless explicitly upgraded.

Acceptance: Presets live in `strait-host` and are applied per-session via opt-in. The current preset library (GitHub, AWS, container sandbox) reaches parity in the new home. The desktop shell exposes a preset picker during onboarding (depends on M-ONB-1 for UI placement).

Key files: `host/src/presets.rs`, `host/src/templates.rs`, `host/tests/presets_integration.rs`, `src/presets.rs` (delete after move), `src/templates.rs` (delete after move)
