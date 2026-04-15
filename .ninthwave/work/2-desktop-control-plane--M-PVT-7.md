# Feat: Build the first desktop control plane shell (M-PVT-7)

**Priority:** Medium
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-PVT-6
**Domain:** desktop-control-plane
**Lineage:** 50c028f5-863e-4498-9e01-7ccf25c7b151

Create the first desktop shell with tray or menu presence, a session list, a blocked-request feed, a request detail view, and actions for deny, allow once, allow for session, and persist. Reuse the daemon IPC contract directly so the app stays a thin control surface instead of inventing a second backend protocol.

**Test plan:**
- Add app-level tests for rendering session lists and blocked-request cards from fixture IPC payloads
- Verify each decision action calls the correct daemon method and updates optimistic or error state in the UI
- Run manual smoke checks on macOS and one non-macOS target for tray presence, event streaming, and reconnect after daemon restart

Acceptance: Users can see live blocked requests in a desktop shell, inspect why each one was blocked, and trigger all four decision actions without touching the terminal.

Key files: `desktop/`, `src/main.rs`, `README.md`
