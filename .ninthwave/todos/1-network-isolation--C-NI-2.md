# Feature: Unix socket listener in proxy (C-NI-2)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** None
**Domain:** network-isolation

Add a Unix socket listener to the proxy's accept loop in launch mode. When
`strait launch` starts the proxy, it should create a temporary Unix socket
file (e.g., in a tempdir) and spawn an accept loop that feeds incoming
connections into the existing `handle_connection()` function -- the same
path TCP connections take.

The Unix socket path must be communicated to the container config builder
so it can be bind-mounted. The TCP listener should remain for standalone
`strait proxy` mode (no changes to that code path).

**Test plan:**
- Integration test: create a Unix socket listener, connect to it, send an HTTP CONNECT request, verify the proxy handles it identically to a TCP connection
- Test that the socket file is created in a tempdir and cleaned up on shutdown
- Verify standalone `strait proxy` mode is unaffected (no Unix socket created)

Acceptance: `run_mitm_proxy_loop` (or equivalent) accepts connections from both
TCP and Unix socket simultaneously; the socket path is returned/available for
container bind-mount configuration.

Key files: `src/launch.rs`, `src/mitm.rs`
