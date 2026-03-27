# Feat: `strait launch --observe` basic orchestrator (H-CP-7a)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** H-CP-1, H-CP-4, M-CP-5, M-CP-6
**Domain:** launch

Implement the `strait launch --observe` subcommand that orchestrates proxy, container, and observation into a unified observe-mode workflow. This is the foundation that H-CP-7b adds enforcement modes on top of.

Startup sequence:
1. Start Strait proxy on host (random available port)
2. Write session CA to temp file
3. Create container with bind-mounts (all paths read-write in observe mode -- no policy restricts)
4. Inject CA into container's system bundle (via M-CP-5 entrypoint)
5. Set HTTPS_PROXY in container pointing to host proxy
6. Start observation stream (JSONL file + Unix socket via H-CP-3/M-CP-6)
7. Migrate proxy audit events to ObservationStream (replace AuditLogger callers)
8. Start container with TTY attached
9. Wait for agent exit
10. Stop proxy, clean up container, close observation stream

Agent gets full terminal control (TTY passthrough for interactive TUI sessions).

**Test plan:**
- Integration test (requires Docker): `launch --observe echo hello` runs in container, produces observation JSONL, exits cleanly
- Integration test: observation JSONL contains network events from proxy AND container lifecycle events
- Edge case: agent exits immediately (bad command) -- clean error with exit code
- Edge case: agent killed by signal (Ctrl+C) -- clean container shutdown and temp file cleanup
- Edge case: Docker not running -- clear error before any operations

Acceptance: `strait launch --observe echo hello` runs in a container, produces observation JSONL with both network and container events, exits cleanly. TTY passthrough works for interactive agents.

Key files: `src/launch.rs` (NEW), `src/main.rs` (wire subcommand), `src/audit.rs` (migrate callers to ObservationStream)
