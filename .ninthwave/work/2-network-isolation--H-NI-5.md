# Feature: Gateway binary resolution at runtime (H-NI-5)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-3, H-NI-4
**Domain:** network-isolation
**Lineage:** d42b2dc5-8821-4ef7-843a-530363f2e2ce

Teach `strait launch` how to locate the correct gateway binary for the target container architecture at runtime. The resolver should support installed and development layouts, detect the container architecture, and return a clear actionable error when the binary is missing.

**Test plan:**
- Add unit tests for gateway lookup adjacent to the current executable and in development target directories.
- Add a missing-binary test that verifies the error message explains how to obtain the gateway binary.
- Verify architecture detection picks the correct gateway artifact for the container runtime.

Acceptance: `strait launch` automatically resolves the correct gateway binary in common installed and development environments, and missing binaries fail with a clear error.

Key files: `src/launch.rs`
