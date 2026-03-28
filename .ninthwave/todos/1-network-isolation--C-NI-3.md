# Feature: Container config --network=none + bind-mounts (C-NI-3)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-1, C-NI-2
**Domain:** network-isolation

Update `build_config()` and `try_create_container()` to enforce network
isolation. The container must start with `network_mode: "none"` (zero network
interfaces except loopback). The proxy Unix socket and gateway binary are
bind-mounted in. The entrypoint chain becomes: gateway binary (starts TCP
forwarder, spawns child) -> CA trust wrapper -> user command.

Changes to `build_config`:
- Accept socket path and gateway binary path instead of (or in addition to) proxy port
- Add bind-mounts: socket at `/strait/proxy.sock`, gateway at `/strait/gateway`
- Set `HTTPS_PROXY=http://127.0.0.1:3128` (points to gateway inside container)
- Update entrypoint to run gateway as the init process

Changes to `try_create_container`:
- Set `network_mode: Some("none".to_string())` in HostConfig

Changes to `launch.rs`:
- Pass Unix socket path and gateway binary path to `build_config`

**Test plan:**
- Update existing `build_config` unit tests: verify network_mode is "none", verify socket and gateway bind-mounts are present, verify HTTPS_PROXY points to 127.0.0.1:3128
- Test entrypoint chain: gateway binary path is first in entrypoint, followed by CA trust wrapper, followed by user command
- Verify observe/warn/enforce modes all produce correct container configs
- Test that standalone proxy mode (`strait proxy`) is unaffected

Acceptance: `build_config` produces a container config with `--network=none`,
bind-mounted socket + gateway, and correct entrypoint chain. All existing
container unit tests updated and passing.

Key files: `src/container.rs`, `src/launch.rs`
