# Feat: Container management with bollard (H-CP-4)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** H-CP-2
**Domain:** container

Add container lifecycle management using the `bollard` crate (Rust Docker API bindings). Create containers from Cedar policy: translate `fs:read` policies to read-only bind-mounts, `fs:write` to read-write mounts, `proc:exec` policies to available binaries in the container image.

The container runs the user's command with full TTY support. Network traffic routes through the host proxy via `HTTPS_PROXY` environment variable pointing to `host.docker.internal:<port>`.

Key behaviors:
- `create_container(policy, image, cmd)` -- translate Cedar policy to Docker container config
- `start_container()` -- start with TTY attached
- `stop_container()` -- graceful shutdown, then force kill after timeout
- Auto-cleanup on Strait exit (remove container)

**Test plan:**
- Unit test: Cedar policy with `fs:read` on `/project/src` produces container config with read-only bind-mount
- Unit test: Cedar policy with `fs:write` on `/project/out` produces read-write bind-mount
- Unit test: Cedar policy with `proc:exec` on `git` includes git in container PATH
- Unit test: container config includes HTTPS_PROXY env var pointing to host
- Integration test (requires Docker): create container, verify bind-mounts exist inside, stop and remove
- Edge case: Docker daemon not running -- clear error message before any container operations
- Edge case: image not found -- clear error with pull suggestion

Acceptance: `ContainerManager` struct using bollard that creates, starts, and stops containers. Cedar `fs:` policies map to bind-mounts. Container has HTTPS_PROXY set. Clean error messages for Docker-not-found and image-not-found.

Key files: `src/container.rs` (NEW), `Cargo.toml` (add bollard dependency)
