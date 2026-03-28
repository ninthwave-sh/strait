# Feature: Add --env flag to strait launch (C-RL-1)

**Priority:** Critical
**Source:** v0.1.0 release -- Claude Code container testing
**Depends on:** None
**Domain:** release-launch

Add a repeatable `--env KEY=VALUE` argument to `strait launch` so users can
pass environment variables into the container. This is required for passing
`ANTHROPIC_API_KEY` and similar secrets to agents running inside containers.

The `ContainerConfig` struct already supports an `env: Vec<String>` field.
The CLI just needs to expose it and thread it through the launch functions.

Changes:

1. `src/main.rs` -- Add `#[arg(long, value_name = "KEY=VALUE")]` field
   `env: Vec<String>` to the `Launch` variant. Pass it through to both
   `run_launch_observe()` and `run_launch_with_policy()`.

2. `src/launch.rs` -- Add `extra_env: Vec<String>` parameter to both
   `run_launch_observe()` and `run_launch_with_policy()`. After
   `ContainerManager::build_config()` returns, append `extra_env` entries
   to `config.env`.

3. CLI tests in `src/main.rs` -- Add parsing tests for `--env FOO=bar`,
   multiple `--env` flags, and `--env` with `=` in the value.

**Test plan:**
- Unit test: CLI parsing accepts `--env FOO=bar --env BAZ=qux` alongside other launch flags
- Unit test: CLI parsing accepts values with `=` signs (e.g., `--env FOO=bar=baz`)
- Integration test: `strait launch --observe --env FOO=bar --image alpine:latest -- env` and verify FOO=bar appears in container output

Acceptance: `strait launch --observe --env ANTHROPIC_API_KEY=test --image alpine:latest -- env`
prints `ANTHROPIC_API_KEY=test` in its output. Existing tests still pass.

Key files: `src/main.rs`, `src/launch.rs`
