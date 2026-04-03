# Feature: Integration tests for enforced network isolation (H-NI-6)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-3
**Domain:** network-isolation
**Lineage:** 8fc2b68f-fee8-45e2-a988-c9af190f78c6

Add Docker-based integration tests that exercise the new gateway-backed `--network=none` launch path end to end. The tests should verify the happy-path proxy flow, direct network bypass failure, mode-specific behavior, and gateway exit-code cleanup using the same Docker-aware pattern already used in `tests/launch_integration.rs`.

**Test plan:**
- Add integration tests that verify proxied HTTPS requests succeed through the gateway while direct outbound TCP attempts fail.
- Cover observe and enforce behavior on the Unix-socket proxy path.
- Verify the gateway exits cleanly and propagates the container command exit code.

Acceptance: Launch integration tests cover the enforced network-isolation path end to end and skip cleanly when Docker is unavailable.

Key files: `tests/launch_integration.rs`
