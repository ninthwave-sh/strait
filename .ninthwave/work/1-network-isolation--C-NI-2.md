# Feature: Unix socket listener in proxy (C-NI-2)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** None
**Domain:** network-isolation
**Lineage:** 8d2db633-fbf2-4a51-b968-37fca2da159c

Add a Unix socket listener to the launch-mode proxy so container traffic can reach the host proxy without a host TCP port. `strait launch` should create a temporary socket path, serve both TCP and Unix socket connections through the same `handle_connection()` path, and expose the socket path for container bind-mount configuration. Standalone `strait proxy` behavior should stay unchanged.

**Test plan:**
- Add an integration test that connects over the Unix socket, sends an HTTP CONNECT request, and verifies the existing proxy handling path is reused.
- Verify the socket file is created in a temp directory and cleaned up on shutdown.
- Verify standalone `strait proxy` mode still only uses its TCP listener.

Acceptance: Launch mode serves both TCP and Unix socket connections through the same proxy loop, and the Unix socket path is available to container setup.

Key files: `src/launch.rs`, `src/mitm.rs`
