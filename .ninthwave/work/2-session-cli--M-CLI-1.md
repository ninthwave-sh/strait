# Feat: Add session management CLI commands over the control API (M-CLI-1)

**Priority:** Medium
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** H-SES-1, H-POL-1, M-OBS-1
**Domain:** session-cli
**Lineage:** dc6bda8c-3dd3-40e1-ac7b-218ad4b50133

Add session-oriented CLI commands that talk to the control API instead of duplicating runtime logic in bespoke flags or signals. The CLI should cover listing sessions, inspecting a session, attaching to its live stream, reloading or replacing policy, and stopping a session. Keep `watch` backward compatible while making session-targeted flows the default operator path.

**Test plan:**
- Add CLI parsing tests for the new `strait session` subcommands
- Add integration tests that exercise the control API through the CLI surface
- Verify help text and error messages describe live-update boundaries clearly

Acceptance: Operators can target a running session with `strait session list`, `info`, `watch`, `reload-policy`, `replace-policy`, and `stop`. These commands use the control API rather than bespoke side channels. Launch output and CLI help explain that live updates apply to network policy only and that fs or proc changes require relaunch.

Key files: `src/main.rs`, `src/watch.rs`, `src/launch.rs`
