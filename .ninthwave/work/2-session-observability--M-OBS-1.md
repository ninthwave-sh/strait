# Feat: Make observation delivery session-aware and emit runtime mutation events (M-OBS-1)

**Priority:** Medium
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** H-SES-1, H-TUI-1, H-POL-1
**Domain:** session-observability
**Lineage:** ec8aea1c-b2c3-4fb9-afd7-93327f313b26

Make live observation delivery a session resource instead of relying only on ad hoc socket discovery. Add auditable runtime events for control-plane mutations, starting with `policy_reloaded` and `tty_resized`, and include enough session context for downstream controllers to distinguish concurrent runs. Preserve JSONL persistence and existing watch behavior while defining the canonical live stream around the session API.

**Test plan:**
- Add unit tests for new event serialization and backward-compatible parsing
- Add integration tests for session-based stream attachment and multi-consumer delivery
- Verify `policy_reloaded` and `tty_resized` events are emitted when those actions occur

Acceptance: Observation consumers can attach through a running session and receive activity plus runtime mutation events tagged with session context. `policy_reloaded` and `tty_resized` events are emitted when those actions occur. JSONL persistence and current watch rendering continue to work without regression.

Key files: `src/observe.rs`, `src/watch.rs`, `src/launch.rs`
