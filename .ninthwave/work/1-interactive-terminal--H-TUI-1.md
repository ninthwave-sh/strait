# Feat: Add container TTY resize propagation and terminal lifecycle hardening (H-TUI-1)

**Priority:** High
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** None
**Domain:** interactive-terminal
**Lineage:** 0406519a-af5b-4b5e-b631-32400811804a

Extend `strait launch` so a containerized interactive app receives the host terminal size at startup and subsequent resize updates while the session is running. Keep raw-mode setup and cleanup reliable across normal exit, Ctrl+C, SIGTERM, and failed attach paths. Scope this item to TTY correctness in the launch path, not the session API.

**Test plan:**
- Add unit tests for terminal size helpers and guard cleanup behavior
- Add launch-level tests that verify startup rows and columns and live resize propagation
- Verify non-TTY sessions do not attempt raw mode or resize forwarding

Acceptance: Interactive launch sessions set initial terminal size from the host terminal, propagate host resize events to the running container TTY, and restore host terminal settings on exit or interruption. Non-TTY launch sessions continue to work without resize handling. New automated coverage proves startup sizing, resize delivery, and cleanup paths.

Key files: `src/launch.rs`, `src/container.rs`, `tests/launch_integration.rs`
