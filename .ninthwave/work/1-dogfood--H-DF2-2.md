# Feat: Add --mount flag for operator bind mounts (H-DF2-2)

**Priority:** High
**Source:** Dogfooding review -- need to mount ~/.claude/ for OAuth auth, outside Cedar policy scope
**Depends on:** None
**Domain:** dogfood
**Lineage:** b1ab6a63-a4dd-44ad-8a8f-7c4e008bcf53

Cedar `fs:read`/`fs:write` policies are for controlling agent access -- they validate paths under `base_dir` to prevent traversal. But operators need to mount trusted paths outside the project directory (e.g., `~/.claude/` for Claude Code OAuth config, or tool config directories).

Add a `--mount` repeatable flag to `strait launch` that accepts Docker bind-mount syntax: `--mount /host/path:/container/path:ro`. These mounts bypass Cedar validation because they are operator-specified, not agent-requested.

Implementation:
1. Add `#[arg(long, value_name = "HOST:CONTAINER:MODE")] mount: Vec<String>` to the Launch command in `src/main.rs`
2. Thread through `run_launch_observe()` and `run_launch_with_policy()` in `src/launch.rs`
3. In `build_config()` or after it returns, append the extra mounts to `ContainerConfig.binds`
4. Validate format (must have at least host:container, mode defaults to `rw`) but do NOT validate against `base_dir`

This enables mounting `~/.claude/:/root/.claude/:rw` for OAuth auth without modifying Cedar policies.

**Test plan:**
- Unit test: `--mount /foo:/bar:ro` produces bind entry `"/foo:/bar:ro"` in config
- Unit test: `--mount /foo:/bar` defaults to rw
- Unit test: invalid format (no colon) produces a clear error
- Unit test: multiple `--mount` flags all appear in binds
- `cargo test --all-features` passes

Acceptance: `strait launch --mount /host:/container:ro --observe -- echo hello` creates a container with the specified bind mount. Multiple `--mount` flags work. Mount paths are not validated against `base_dir`. Invalid format produces a clear error message.

Key files: `src/main.rs:153-198`, `src/launch.rs:257-264,441-450`, `src/container.rs`
