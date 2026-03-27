# Feat: Unix socket observation server (M-CP-6)

**Priority:** Medium
**Source:** v0.3 container platform plan
**Depends on:** H-CP-3
**Domain:** observe

Add a Unix socket server to the observation stream. The server listens at `/tmp/strait-<pid>.sock` and streams JSONL events to any connected client. Multiple clients can connect simultaneously (each gets a broadcast receiver). Stale sockets from prior runs are auto-cleaned.

This enables `strait watch` (M-CP-10) to connect from a separate terminal and display live events.

**Test plan:**
- Unit test: Unix socket server starts and accepts connections
- Unit test: events emitted to observation stream appear on connected socket client
- Unit test: multiple simultaneous clients each receive all events
- Unit test: client disconnect does not crash the server or affect other clients
- Edge case: stale socket file from prior run -- auto-remove before bind
- Edge case: /tmp not writable -- fall back to XDG_RUNTIME_DIR or current directory

Acceptance: `ObservationStream::start_socket_server()` creates a Unix socket. Connected clients receive JSONL events in real-time. Stale sockets are cleaned up automatically.

Key files: `src/observe.rs` (extend)
