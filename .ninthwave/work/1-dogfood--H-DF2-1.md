# Fix: Skip host binary mounting on macOS (H-DF2-1)

**Priority:** High
**Source:** Dogfooding review -- H-DF-2 mounts Mach-O binaries into Linux containers on macOS
**Depends on:** None
**Domain:** dogfood
**Lineage:** 062abe91-46b2-4cd8-8c93-3a60ca8637c1

H-DF-2 added host binary mounting via proc:exec policies. On macOS hosts, the resolved binaries are Mach-O format and cannot execute inside Linux containers. The feature silently produces non-functional bind-mounts.

Fix `build_config()` in `src/container.rs` to detect the host OS at compile time (`cfg!(target_os = "macos")`). When on macOS, skip the `resolve_host_binary` + bind-mount step for `ProcExec` permissions and log a warning: "host binary mounting skipped on macOS (Mach-O binaries cannot run in Linux containers)". The PATH setup should still happen so container-installed binaries work.

On Linux, the current behavior is correct and should not change.

**Test plan:**
- Add unit test with `cfg!(target_os)` conditional assertions: on macOS, `build_config` with ProcExec should produce no binary bind-mounts but still set PATH. On Linux, existing behavior preserved.
- Verify existing `proc_exec_host_binary_bind_mounted` test is gated to Linux only
- `cargo test --all-features` passes on macOS
- `cargo clippy --all-features -- -D warnings` clean

Acceptance: On macOS, `strait launch` with proc:exec policies does not attempt to mount host binaries. A warning is logged. PATH is still set for container-installed binaries. On Linux, host binary mounting works as before. All tests pass on both platforms.

Key files: `src/container.rs:344-370`
