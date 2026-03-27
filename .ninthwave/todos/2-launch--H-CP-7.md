# Feat: `strait launch` orchestrator (H-CP-7)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** H-CP-1, H-CP-4, M-CP-5, M-CP-6
**Domain:** launch

Implement the `strait launch` subcommand that orchestrates the proxy, container, and observation stream into a unified workflow. Three modes:

- `strait launch --observe ./agent` -- no policy enforcement, log all activity
- `strait launch --warn policy.cedar ./agent` -- evaluate policy, log violations as warnings, never block
- `strait launch --policy policy.cedar ./agent` -- enforce policy (deny = container doesn't get the mount / proxy returns 403)

Startup sequence:
1. Load Cedar policy (if --warn or --policy)
2. Start Strait proxy on host (random available port)
3. Write session CA to temp file
4. Create container with bind-mounts from policy, HTTPS_PROXY pointing to host proxy, CA trust injection
5. Start observation stream (JSONL file + Unix socket)
6. Start container with TTY attached
7. Wait for agent exit
8. Stop proxy, clean up container and temp files

Agent gets full terminal control (TTY passthrough for interactive TUI sessions).

**Test plan:**
- Integration test (requires Docker): `launch --observe` with a test agent that makes one HTTP request and reads one file, verify observation JSONL contains both events
- Integration test: `launch --policy` with a restrictive policy, verify agent can only access permitted mounts and API endpoints
- Integration test: `launch --warn` with same restrictive policy, verify agent succeeds but warnings are logged
- Edge case: agent exits immediately (bad command) -- clean error with exit code
- Edge case: agent is killed by signal (Ctrl+C) -- clean container shutdown
- Edge case: policy file invalid -- fail fast before starting container

Acceptance: `strait launch --observe echo hello` runs in a container, produces observation JSONL, exits cleanly. All three modes (observe/warn/policy) work correctly.

Key files: `src/launch.rs` (NEW), `src/main.rs` (wire up subcommand)
