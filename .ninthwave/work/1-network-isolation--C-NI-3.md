# Feature: Network-isolated container config with gateway mounts (C-NI-3)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-1, C-NI-2
**Domain:** network-isolation
**Lineage:** 76660a0c-e13e-4f77-bf45-32cf582f9cf5

Update container creation so `strait launch` enforces network isolation instead of relying on cooperative proxy env vars alone. The container config should use `network_mode: none`, bind-mount the proxy Unix socket and gateway binary, point `HTTPS_PROXY` at the in-container gateway, and run the gateway ahead of the CA trust wrapper and user command.

**Test plan:**
- Update `build_config` unit tests to assert `network_mode` is `none`, the proxy socket and gateway binary are bind-mounted, and proxy env vars point to `127.0.0.1:3128`.
- Verify the generated entrypoint chain starts with the gateway and still preserves CA trust injection plus the user command.
- Run the existing launch/container test coverage to confirm observe, warn, and enforce configs still build correctly.

Acceptance: Container config uses `--network=none`, mounts the proxy socket and gateway binary, and launches the gateway-based entrypoint chain in all launch modes.

Key files: `src/container.rs`, `src/launch.rs`
