# Feat: Host binary mounting via proc:exec policies (H-DF-2)

**Priority:** High
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** None
**Domain:** dogfood
**Lineage:** b4abef7c-c331-43fc-848c-1c098b461919

Currently `ContainerPermission::ProcExec` only modifies the PATH environment variable -- it assumes binaries are pre-installed in the container image. Instead, when a Cedar `proc:exec` policy permits a binary (e.g., `proc::git`, `proc::claude`), `strait launch` should resolve it on the host via PATH lookup and bind-mount it read-only into the container. This eliminates the need for custom Dockerfiles in most cases -- use a base image like `ubuntu:24.04` and mount what you need.

Implementation:

1. Add `resolve_host_binary(name: &str) -> Option<PathBuf>` that searches the host PATH for the binary (like `which`). Already a pattern in `resolve_gateway_binary()`.

2. Add `extract_proc_permissions()` in `src/policy.rs` (parallel to existing `extract_fs_permissions()`). Parse Cedar policy to find all `proc:exec` permit rules and return `Vec<ContainerPermission::ProcExec>`.

3. In `build_config()` (`src/container.rs`), for each `ProcExec(binary)`:
   - Resolve on host via `resolve_host_binary`
   - If found: bind-mount `{host_path}:/usr/local/bin/{binary_name}:ro`
   - If not found: warn and skip (don't fail the launch)
   - Build PATH from mounted locations + standard dirs (`/usr/local/bin:/usr/bin:/bin`)

4. Call `extract_proc_permissions()` in `src/launch.rs` for warn/enforce modes (observe mode already gives full access).

Handle shared library dependencies pragmatically: mount the binary only. If the binary is dynamically linked and the container lacks its libraries, it will fail at runtime with a clear error. This is acceptable -- users can either use a richer base image or add `fs:read` policies to mount library directories.

**Test plan:**
- Unit test `resolve_host_binary` with a known binary (e.g., "sh") and a nonexistent binary
- Unit test `extract_proc_permissions` with a Cedar policy containing proc:exec rules
- Unit test `build_config` with ProcExec permissions: verify bind-mount entries and PATH env var
- Integration test: launch container with proc:exec policy for `ls`, verify `ls` runs inside container from a base image that lacks it (or verify the mount exists)
- Test that missing host binary logs a warning but doesn't fail the launch

Acceptance: `strait launch --policy policy.cedar` with a `proc:exec` rule for a host binary (e.g., `git`) mounts that binary into the container and the binary is executable inside the container. Missing binaries produce a warning, not an error. PATH inside the container includes mount locations. `cargo test --all-features` passes. `cargo clippy --all-features -- -D warnings` clean.

Key files: `src/container.rs:288-411`, `src/policy.rs:354-378`, `src/launch.rs:528-560`, `tests/launch_integration.rs`
