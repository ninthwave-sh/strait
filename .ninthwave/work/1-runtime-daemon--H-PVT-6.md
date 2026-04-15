# Feat: Introduce a local daemon for desktop-facing runtime control (H-PVT-6)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-5
**Domain:** runtime-daemon
**Lineage:** fa6bd6ae-624f-4d25-b531-757f995e6928

Add a backgroundable daemon or control-service mode that owns proxy sessions and exposes a stable local IPC surface for desktop clients instead of requiring users to keep a foreground terminal open. The daemon should manage session lifecycle, discovery, and shutdown cleanly across restarts while reusing the same decision and observation contracts established in earlier pivot work.

**Test plan:**
- Add CLI tests in `src/main.rs` for daemon start or status or stop parsing and help text
- Add integration coverage for daemon startup, session publication, and reconnect from a second local client process
- Verify stale socket and registry cleanup on unclean exit followed by fresh startup

Acceptance: A local daemon can start and own a proxy session, publish it for other local clients, and stop cleanly without depending on the legacy launch-oriented container path.

Key files: `src/main.rs`, `src/launch.rs`, `src/observe.rs`, `README.md`
