# Feat: Introduce a local control service for container-backed sessions (H-CSM-5)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** H-CSM-4
**Domain:** session-control-service
**Lineage:** aeb200ea-314d-49c6-b942-d51bbefe3626

Add a backgroundable local control service that owns primary `strait` sessions and exposes a stable IPC surface for future desktop clients instead of requiring users to keep one foreground terminal alive forever. Reuse the existing session registry, control socket, and observation stream model so the service is an orchestration layer on top of the current runtime, not a second backend.

**Test plan:**
- Add CLI tests in `src/main.rs` for service start, status, and stop parsing and help text
- Add integration coverage for service startup, published session discovery, and reconnect from a second local client process
- Verify stale socket and registry cleanup on unclean exit followed by a fresh startup

Acceptance: A local service can start and own a container-backed Strait session, publish it for other local clients, and stop cleanly while preserving the existing session control and observation contracts.

Key files: `src/main.rs`, `src/launch.rs`, `src/observe.rs`, `README.md`
