# Feat: Polish onboarding, launch presets, and devcontainer dogfood flow (M-CSM-7)

**Priority:** Medium
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`); amended per `docs/designs/devcontainer-strategy.md`
**Depends on:** M-CSM-6, M-DC-5
**Domain:** onboarding-dogfood
**Lineage:** b383a0d3-62cc-4278-bdf7-8b93f8810674

Finish the phase-1 experience by wiring first-run onboarding around the container trust boundary with devcontainer.json as the canonical launch path, adding preset-driven launch ergonomics (borrowing the operator-ergonomics lessons from `nono`), and documenting one dogfood path that proves the product works without machine-wide trust. The result should make the architectural win legible to users: owned boundary, no host CA install, live request decisions, and repeatable operator setup driven from devcontainer.json. The L-DC-7 devcontainer feature is the distribution story; this item is the launch-ergonomics story for users running `strait launch --devcontainer <path>` directly.

**Test plan:**
- Run a manual end-to-end flow: `strait launch --devcontainer` against a supported agent fixture, block a request, act from the desktop control plane, and verify the session unblocks
- Add automated smoke coverage for trust-path reporting, preset expansion, and onboarding helpers in the devcontainer launch path
- Verify persisted rules survive control-service restart and apply to the next launched devcontainer session with no manual policy edits

Acceptance: A new user clones an example repo with a devcontainer.json, runs `strait launch --devcontainer`, gets a session-local CA trusted only inside the container, receives a blocked-request prompt, approves the minimal exception from the control-plane flow, and repeats the same request in a new session using the persisted rule. No machine-wide trust install at any point.

Key files: `README.md`, `examples/`, `src/ca.rs`, `src/main.rs`, `desktop/`
