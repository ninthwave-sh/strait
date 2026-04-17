# Test: Invariants for in-container data plane (M-ICDP-6)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` architecture invariants 1-3
**Depends on:** H-ICDP-2, H-ICDP-3, H-ICDP-4
**Domain:** in-container-data-plane
**Lineage:** 8cca6f45-1eb2-4a33-b54d-2bde2a1a643f

Add a Docker-based integration test suite that proves the three security invariants for the in-container data plane: (1) the agent user cannot read or connect to the host socket or modify iptables rules, (2) a tool that does not honor `HTTPS_PROXY` still has its traffic routed through the proxy, (3) the agent user cannot signal the proxy process. Runs in CI via the existing build job's Docker support.

**Test plan:**
- Invariant 1: as agent user, `cat /run/strait/host.sock` -> permission denied; `iptables -L` -> permission denied; `iptables -F` -> permission denied.
- Invariant 2: run a Node `fetch` or raw `nc -z upstream 443` with `HTTPS_PROXY` unset and confirm the proxy audited the request.
- Invariant 3: as agent user, `kill -9 <proxy_pid>` returns EPERM; proxy stays up.
- Each invariant runs as a separate `#[test]` in `agent/tests/invariants.rs` and short-circuits early on setup failures.

Acceptance: All three invariants pass in CI on a Debian-based test image. Each test prints the exact shell command it ran and the exit code on failure. The suite is wired into the existing workflow so it runs on every PR.

Key files: `agent/tests/invariants.rs`, `.github/workflows/ci.yml`, `agent/tests/fixtures/`
