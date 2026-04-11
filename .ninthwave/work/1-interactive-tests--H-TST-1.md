# Test: Prove interactive passthrough, resize, and live policy mutation end to end (H-TST-1)

**Priority:** High
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** H-TUI-1, H-TUI-2, H-SES-1, H-POL-1, M-OBS-1
**Domain:** interactive-tests
**Lineage:** 763f1a9f-99c1-483b-a3d9-3c9141ec2855

Use the mock TUI app and the session API to add Docker-backed end-to-end coverage for interactive passthrough, resize propagation, and mid-session network policy updates. These tests should prove the supported contract for internal dogfooding without introducing a dependency on a real agent harness. Keep failures attributable to a single subsystem -- TTY handling, control plane, observation delivery, or policy swap.

**Test plan:**
- Add end-to-end tests for input and output round-trip through a running interactive session
- Add end-to-end tests for initial terminal sizing, live resize propagation, and terminal cleanup
- Add end-to-end tests for valid and invalid live network policy updates during a running session

Acceptance: Integration coverage proves interactive input and output passthrough, initial terminal sizing, live resize propagation, runtime network policy mutation, and terminal cleanup after exit. Tests fail if a session loses TTY semantics or applies an invalid live policy update incorrectly. The suite is stable enough to gate regressions in the interactive contract.

Key files: `tests/launch_integration.rs`, `tests/integration.rs`, `tests/fixtures`
