# Feat: Add mock TUI app and PTY-backed test utilities (H-TUI-2)

**Priority:** High
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** None
**Domain:** interactive-terminal
**Lineage:** fdab85da-9363-4122-8d63-31cb1f87c8ba

Add a tiny test-only interactive program that reports whether stdin and stdout are TTYs, prints the current window size, redraws on resize, echoes deterministic input, and exits on a simple command. Add PTY-backed test helpers that can drive input, read output, and trigger resizes from integration tests. Keep the app independent from real agent harnesses so the interactive contract is testable and deterministic.

**Test plan:**
- Add unit tests for the mock TUI output format and exit behavior where practical
- Add helper tests that verify PTY setup, input delivery, and resize triggering
- Run repeated local executions to confirm the helpers are stable and not timing-fragile

Acceptance: The repo contains a reusable mock TUI app and PTY-backed test helpers that can assert TTY presence, observe redraw output, send input, and trigger resizes without a real agent harness. The helpers are deterministic enough to support integration coverage for interactive passthrough. The mock app has a documented contract for the tests that consume it.

Key files: `tests/fixtures`, `tests/launch_integration.rs`, `Cargo.toml`
