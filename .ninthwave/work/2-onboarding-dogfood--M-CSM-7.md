# Feat: Polish onboarding, launch presets, and dogfood flow (M-CSM-7)

**Priority:** Medium
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** M-CSM-6
**Domain:** onboarding-dogfood
**Lineage:** b383a0d3-62cc-4278-bdf7-8b93f8810674

Finish the phase-1 experience by wiring first-run onboarding around the container trust boundary, adding preset-driven launch ergonomics inspired by the best parts of `nono`, and documenting one dogfood path that proves the product works without machine-wide trust. The result should make the architectural win legible to users: owned boundary, no host CA install, live request decisions, and repeatable operator setup.

**Test plan:**
- Run a manual end-to-end flow: launch a supported agent or fixture through `strait launch`, block a request, act from the desktop control plane, and verify the session unblocks
- Add automated smoke coverage for trust-path reporting, preset expansion, and onboarding helpers in the supported launch path
- Verify persisted rules survive control-service restart and apply to the next launched session with no manual policy edits

Acceptance: A new user can launch a supported container-backed session, rely on container-only CA trust, receive a blocked-request prompt, approve the minimal exception from the control-plane flow, and repeat the same request in a new session using the persisted rule.

Key files: `README.md`, `examples/`, `src/ca.rs`, `src/main.rs`, `desktop/`
