# Fix: Observation pipeline -- passthrough events + socket resilience (M-ER-8)

**Priority:** Medium
**Source:** ER-5 Findings 1-3, 7
**Depends on:** H-ER-4 (benefits from)
**Domain:** observation

Passthrough connections emit audit events but not observation events, making them invisible to `strait watch` and `strait generate`. The discover_socket function only searches /tmp but the socket may be in XDG_RUNTIME_DIR. The socket accept loop breaks permanently on any error (EMFILE, ENOMEM). The enforcement_mode field is always empty in NetworkRequest events. Fix by emitting observation events for passthrough connections (host/port only, no method/path since the tunnel is encrypted), mirroring the socket search order from resolve_socket_dir in discover_socket, logging and continuing on transient accept errors, and threading enforcement_mode through ProxyContext.

**Test plan:**
- Test that a passthrough connection produces an observation event with host and port
- Test that discover_socket finds a socket in a non-/tmp directory (mock XDG_RUNTIME_DIR)
- Test that a transient accept error (simulated) logs a warning but doesn't break the accept loop
- Test that enforcement_mode is populated in NetworkRequest events

Acceptance: Passthrough connections visible in observation stream. Socket discovery mirrors resolve_socket_dir. Accept loop resilient to transient errors. enforcement_mode populated.

Key files: `src/mitm.rs`, `src/observe.rs`, `src/watch.rs`
