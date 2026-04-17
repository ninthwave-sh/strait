# Desktop shell: multi-session UX

The Strait desktop shell is the operator-facing UI for the host control
plane. A single host runs many containers, so the shell must handle
multiple concurrent agent sessions side-by-side. This document describes
how the shell renders that inventory, routes decision prompts, and keeps
the tray icon honest about what is awaiting attention.

## Layout

```
 +-----------------+----------------------------+-----------------+
 | Sessions rail   | Blocked requests (active)  | Request detail  |
 |                 |                            |                 |
 | - alpha  (2)    | api.github.com   0:42      | GET /repos/...  |
 | > beta   [1]    | <allow / deny buttons>     | Cedar suggestion|
 | - gamma         |                            | Raw event JSON  |
 +-----------------+----------------------------+-----------------+
```

The left rail lists every session currently registered with the host
control plane. Each row shows:

- **Label** -- the container's name, falling back to the session id when
  a sandbox does not provide a friendly name.
- **Mode** -- `enforce`, `warn`, or `observe`, propagated from the host.
- **Uptime** -- wall-clock age since the desktop first observed the
  session. The control-service proto currently has no `registered_at`
  field, so the shell keeps this clock in the main-process
  `ControlPlane`; restarting the desktop resets the clock for every
  visible session.
- **Pending decision badge** -- a numeric pill that shows how many
  blocked requests are awaiting a decision on that session. The badge
  pulses amber when the pending prompt landed while a **different**
  session was focused (see "Alerts never cross-wire" below).

The middle pane shows the blocked-request batches belonging to the
currently focused session only. Switching sessions swaps the middle and
right panes; it never mixes prompts from two sessions.

## Alerts never cross-wire

When a new `BlockedRequestEvent` streams in for a session that is not
currently focused, the shell does **not** steal focus. Instead, it:

1. Leaves the middle pane bound to whatever session the operator was
   looking at (so they can finish what they were doing without losing
   their place).
2. Flags the background session's rail row as **alerted** -- an amber
   outline plus an amber pending badge -- so the operator can see at a
   glance that another container needs attention.
3. Increments the tray tooltip's total pending count and flips the tray
   icon to its "needs attention" variant (an orange dot on top of the
   base glyph).

The operator regains focus on the alerted session in exactly one of the
following ways:

- Click the session row in the rail.
- Click the session entry in the tray's "Sessions" submenu.
- Click the tray's "Resume latest pending decision" entry, which jumps
  to the session id and blocked id of the most recently observed
  pending prompt across every session.

Each of these paths funnels through a single main-process action --
`focusSession(sessionId, blockedId?)` -- which shows the window and
dispatches a `desktop:focus-session` IPC event to the renderer. The
renderer handles it by activating the session and, when a blocked id is
supplied, selecting that batch in the middle pane.

### Why a badge instead of auto-focus

Auto-focusing on a new prompt would yank the operator out of a decision
they are already making. The acceptance criterion for M-HCP-7 required
choosing between "jump focus" and "surface a clear badge"; we picked
badge. The badge remains sticky until the operator explicitly focuses
the session, which means background alerts cannot get silently absorbed
by whichever session happened to be focused when the request arrived.

## Tray surface

The tray menu always exposes:

- **Open Strait Desktop** -- shows the main window.
- **Resume latest pending decision (N)** -- the quick-resume entry.
  Disabled and renamed to "No pending decisions" when N is zero.
- **Sessions** -- a submenu listing every registered session. Each
  entry's label is `${container_label} · ${N} pending` when there is at
  least one pending prompt on that session, otherwise just
  `${container_label}`. Clicking an entry focuses that session.
- **Enable control plane** -- checkbox, forwards to
  `ControlPlane.setEnabled`.
- **Preferences**, **Quit** -- standard chrome.

The tray tooltip is regenerated on every state-change event and reads
`Strait Desktop · N session(s) · M pending decision(s)`. The icon is
regenerated at the same cadence; it flips to the "needs attention"
variant when `M > 0` and back to the base glyph when every session is
green.

## Module layout

The renderer-side code lives under `desktop/src/`:

- `App.tsx` owns the top-level state (active session, alerted set,
  selected batch) and orchestrates the panels.
- `Sessions.tsx` exports the `SessionRail` component and helpers
  (`sessionLabel`, `formatUptime`).
- `bridge.ts` declares the `DesktopBridge` surface, including the new
  `onFocusSession` channel.

The main-process side lives under `desktop/electron/`:

- `main.ts` -- window lifecycle and wiring.
- `tray.ts` -- `SessionTray` plus the pure helpers used by tests
  (`buildTrayMenuTemplate`, `buildTrayTooltip`, `deriveSessionCounts`,
  `trayIconImage`).
- `ipc.ts` -- renderer-facing IPC registration and the shared
  `FOCUS_SESSION_CHANNEL` constant.
- `controlClient.ts` -- tracks `firstSeenAtUnixMs` per session and
  `getMostRecentPending()` for the tray quick-resume entry.

## Testing

`desktop/src/__tests__/app.test.tsx` covers multi-session rendering:

- Two sessions appear in the rail with their container labels.
- Clicking a different session swaps the middle pane.
- A new prompt for an unfocused session raises a pending-count badge
  without stealing focus.
- `onFocusSession` requests from the bridge activate the requested
  session.

`desktop/src/__tests__/tray.test.ts` covers the tray helpers with a
mocked `electron` module, so the pure template builder runs in a vanilla
Node environment:

- Pending-count aggregation across sessions.
- Tooltip text for connected and disconnected cases.
- Session submenu labels with per-session counts.
- Quick-resume dispatch of the most recent pending decision.
