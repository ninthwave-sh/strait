# Feat: Build the first desktop control plane shell (M-CSM-6)

**Priority:** Medium
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-CSM-5
**Domain:** desktop-control-plane
**Lineage:** 3745ab34-ee4f-4ce9-a4c5-3c2b9ef9fb7f

Create the first desktop shell with tray or menu presence, a session list, a blocked-request feed, a request detail view, and actions for deny, allow once, allow for session, and persist. Reuse the local control service directly so the app stays a thin control surface over the container-backed runtime instead of inventing a second protocol.

**Test plan:**
- Add app-level tests for rendering session lists and blocked-request cards from fixture IPC payloads
- Verify each decision action calls the correct control-service method and updates optimistic or error state in the UI
- Run manual smoke checks on macOS and one non-macOS target for tray presence, event streaming, and reconnect after service restart

Acceptance: Users can see live blocked requests in a desktop shell, inspect why each one was blocked, and trigger all four decision actions for a running container-backed session without touching the launch terminal.

Key files: `desktop/`, `src/main.rs`, `README.md`
