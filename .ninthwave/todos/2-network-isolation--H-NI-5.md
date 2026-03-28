# Feature: Gateway binary resolution at runtime (H-NI-5)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-3, H-NI-4
**Domain:** network-isolation

Add logic to `launch.rs` to locate the correct gateway binary for the target
container architecture at runtime. The binary could be:
- Adjacent to the `strait` binary (shipped together in release archives)
- In a well-known path (e.g., `~/.strait/bin/`)
- In the cargo target directory (development mode)

The resolver must detect the container's target architecture (x86_64 vs
aarch64) since the host and container architectures may differ. If the
gateway binary is not found, `strait launch` should fail with a clear error
message explaining how to obtain it.

**Test plan:**
- Unit test: resolver finds gateway binary adjacent to current executable
- Unit test: resolver returns clear error when binary is missing
- Unit test: architecture detection returns correct target for the container runtime
- Test development mode: resolver finds binary in `target/` directory

Acceptance: `strait launch` locates the gateway binary automatically in both
installed and development scenarios. Missing binary produces an actionable
error message.

Key files: `src/launch.rs`
