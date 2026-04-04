# Feat: Add --no-tty flag to strait launch (H-DF-3)

**Priority:** High
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** None
**Domain:** dogfood
**Lineage:** 371d80b1-ff69-41fa-a517-b20eb87c80df

`src/container.rs:406` hardcodes `tty: true` in `build_config()`. This causes container creation to fail when stdin is not a terminal (e.g., ninthwave's headless adapter, CI pipelines, background processes). Add a `--no-tty` flag to `strait launch` that disables TTY allocation, stdin open, and stdin attach.

Implementation -- follow the existing flag threading pattern (same as `--env`, `--image`):

1. Add `#[arg(long)] no_tty: bool` to the `Launch` variant in `src/main.rs` (around line 153)
2. Pass `!no_tty` as a `tty: bool` parameter through the match arms to the launch functions
3. Add `tty: bool` parameter to `run_launch_observe()` and `run_launch_with_policy()` signatures in `src/launch.rs`
4. Add `tty: bool` parameter to `build_config()` in `src/container.rs`, replacing the hardcoded `true` at line 406
5. The bollard `Config` at line 503-505 already reads from `config.tty` for `tty`, `open_stdin`, and `attach_stdin` -- no changes needed there

The existing `setup_raw_terminal()` in `src/launch.rs:930` already handles non-TTY stdin gracefully (returns None when stdin is not a terminal), so no changes needed in terminal setup.

**Test plan:**
- Update existing unit test `tty_enabled_by_default` in `src/container.rs` to test both `tty: true` and `tty: false` paths through `build_config`
- Verify `build_config` with `tty: false` produces `ContainerConfig { tty: false, ... }`
- Integration test: `strait launch --no-tty --observe -- echo hello` completes successfully without TTY
- Verify `cargo test --all-features` passes

Acceptance: `strait launch --no-tty --observe -- echo hello` runs successfully without a TTY. The container is created with `tty=false`, `open_stdin=false`, `attach_stdin=false`. Default behavior (no flag) still allocates a TTY. All existing tests pass.

Key files: `src/main.rs:153-198`, `src/launch.rs:257-264,441-450`, `src/container.rs:288-411,485-511`
