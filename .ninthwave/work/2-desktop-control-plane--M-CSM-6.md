# Feat: Build the first desktop control plane shell (M-CSM-6)

**Priority:** Medium
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`); amended per prior-art analysis 2026-04-16
**Depends on:** H-CSM-5
**Domain:** desktop-control-plane
**Lineage:** 3745ab34-ee4f-4ce9-a4c5-3c2b9ef9fb7f

Create the first desktop shell with system tray presence, a session list, a blocked-request feed, a request detail view, and actions for deny, allow once, allow for session, and persist. Connect to the gRPC control service from H-CSM-5 so the app stays a thin control surface over the container-backed runtime. Key UX patterns to implement:

- **Hold-controlled alerts:** Each blocked-request notification controls a live held request. The alert shows a countdown timer matching the hold timeout from H-CSM-3. The user's decision (block/allow + duration) is sent via `SubmitDecision` and directly determines whether the held request proceeds.
- **Duration on decision:** Every decision prompt offers once / session / persist / custom TTL -- not just action.
- **Related-request batching:** When multiple requests to the same host are blocked while one alert is shown, batch them into a single decision rather than spamming separate alerts. After the user decides, apply the decision to all batched requests.
- **System tray / status bar:** Light-touch menu bar presence with quick-access menu: session list, enable/disable toggle, preferences. Does not take over the dock.

Framework: Tauri is the recommended fit (Rust backend aligns with strait, web frontend for cross-platform, native tray support via tauri-plugin-positioner). Electron is the fallback if Tauri proves insufficient for tray or notification UX. Framework choice is finalized during implementation, not prescribed.

**Test plan:**
- Add app-level tests for rendering session lists and blocked-request cards from fixture gRPC payloads
- Verify each decision action calls the correct gRPC method and updates optimistic or error state in the UI
- Add batching test: two blocked requests to the same host collapse into one alert; deciding on one resolves both
- Add countdown test: alert shows remaining hold time and auto-closes with deny on expiry
- Run manual smoke checks on macOS and one non-macOS target for tray presence, event streaming, and reconnect after service restart

Acceptance: Users can see live blocked requests in a desktop shell, inspect why each one was blocked (Cedar explanation, request details), and trigger all four decision actions with duration for a running container-backed session without touching the launch terminal. Related requests to the same host batch into a single decision. The alert shows a countdown timer matching the held request timeout.

Key files: `desktop/`, `proto/control.proto`, `README.md`
