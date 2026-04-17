# Feat: Entrypoint privilege-drop flow (H-ICDP-2)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 1
**Depends on:** H-ICDP-1
**Domain:** in-container-data-plane
**Lineage:** 57430294-d776-4117-bbc5-2bfa1e6bade0
**Requires manual review:** true

Implement `strait-agent entrypoint -- <cmd>`: as root, verify `CAP_NET_ADMIN`, spawn the proxy subprocess bound to `127.0.0.1:<proxy_port>`, install iptables `OUTPUT REDIRECT` rules for the configured ports (default 80, 443) to the proxy port, then `setuid`+`setgid` to the configured agent user and `exec` the user command. Drops `CAP_NET_ADMIN` from the agent command's environment. This is a trust-boundary item; touches privilege handling and is flagged for manual review.

**Test plan:**
- Docker-based integration test: run a container with `strait-agent entrypoint -- /bin/true` and assert exit 0, iptables rules present, proxy PID running as root.
- Integration test: confirm the agent command runs as the configured non-root user (`id -u` in the exec'd command is not 0).
- Edge case: container without `CAP_NET_ADMIN` -- entrypoint exits non-zero with a clear diagnostic.
- Edge case: misconfigured `agent_user` (does not exist) -- entrypoint fails before touching iptables.

Acceptance: In a Linux container launched with `--cap-add=NET_ADMIN`, `strait-agent entrypoint --agent-user node --proxy-port 3128 -- id -u` prints a non-zero UID while iptables OUTPUT redirection is installed, the proxy process is running as root, and `CAP_NET_ADMIN` is no longer effective in the child. Missing capability or missing user fails fast with an actionable error.

Key files: `agent/src/entrypoint.rs`, `agent/src/iptables.rs`, `agent/tests/entrypoint_integration.rs`
