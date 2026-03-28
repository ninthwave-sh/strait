# Feature: Integration tests for enforced network isolation (H-NI-6)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-3
**Domain:** network-isolation

Add Docker-based integration tests that verify enforced network isolation
works end-to-end. These tests require Docker and follow the existing pattern
in `tests/launch_integration.rs`.

Test scenarios:
- Container with --network=none can make HTTPS requests through the proxy
  via the gateway (the happy path works)
- Direct TCP connections from the container to external IPs fail (no network
  interfaces available)
- All three modes (observe, warn, enforce) work with the new isolation model
- Container exit codes propagate correctly through the gateway

**Test plan:**
- Test: `strait launch --observe -- curl https://api.github.com` succeeds via proxy
- Test: `strait launch --observe -- sh -c 'nc -z 1.1.1.1 443'` fails (no network)
- Test: observe mode records observations from Unix socket proxy path
- Test: enforce mode blocks denied requests via Unix socket proxy path
- Verify gateway process exits cleanly when container command finishes

Acceptance: All new integration tests pass with Docker available. Tests are
skipped (not failed) when Docker is unavailable, matching existing pattern.

Key files: `tests/launch_integration.rs`
