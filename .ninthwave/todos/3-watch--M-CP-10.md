# Feat: `strait watch` colored viewer (M-CP-10)

**Priority:** Medium
**Source:** v0.3 container platform plan
**Depends on:** M-CP-6
**Domain:** watch

Implement `strait watch` that connects to the Unix socket observation server and renders a colored real-time stream of agent activity. Each event is formatted as a single line with color-coding:

- Green: allowed actions
- Red: denied actions
- Yellow: warned actions (would be denied in enforce mode)
- Cyan: container lifecycle events (start, stop, mount)
- Dim: passthrough events (no policy evaluation)

Format: `[timestamp] [ACTION] resource -- decision (latency)`

Example output:
```
[14:32:01] http:GET  api.github.com/repos/org/repo -- allow (0.3ms)
[14:32:01] fs:read   /project/src/main.rs          -- allow
[14:32:02] http:DELETE api.github.com/repos/org/repo -- DENY (policy: no-delete)
[14:32:02] proc:exec  git                           -- allow
```

Auto-reconnects if the socket disconnects (agent restarted). Exits cleanly on Ctrl+C.

**Test plan:**
- Unit test: each event type produces correctly colored output
- Unit test: connection to Unix socket and event rendering
- Unit test: socket disconnect triggers reconnect attempt
- Edge case: socket does not exist yet -- wait and retry with message "Waiting for strait launch..."
- Edge case: very long resource paths -- truncate to terminal width

Acceptance: `strait watch` connects to the observation socket and displays colored events in real-time. Works alongside a running `strait launch` session in a separate terminal.

Key files: `src/watch.rs` (NEW)
