# Feat: Desktop shell multi-container session registry (M-HCP-7)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** H-HCP-2, H-HCP-3
**Domain:** host-control-plane
**Lineage:** 9f83c7ad-1f1f-462b-a3bb-77c2637adad3

Extend the Electron desktop shell (M-CSM-6) to handle multiple concurrent container sessions. Adds a left-rail session list showing each registered container with its label, uptime, and a pending-decision badge. Decision alerts carry the originating session id and activate the right pane for that session. Replaces the single-session assumption in the existing shell.

**Test plan:**
- E2E test: start two fake agents pointed at the host; both appear in the rail; clicking each swaps the detail pane.
- E2E test: decision alert raised for session B while session A is focused jumps focus to session B or surfaces a clear badge (choose and document).
- Visual regression: tray icon reflects total pending decisions across sessions.

Acceptance: Desktop shell handles N concurrent sessions with clear separation. Pending decisions are never cross-wired between sessions. Tray menu lists sessions and exposes quick-resume for the most recent pending decision. Docs updated to explain multi-session UX.

Key files: `desktop/src/renderer/sessions.tsx`, `desktop/src/main/ipc.ts`, `desktop/src/main/tray.ts`, `docs/desktop-shell.md` (if present; add otherwise)
