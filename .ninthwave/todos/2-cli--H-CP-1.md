# Refactor: CLI subcommand restructure (H-CP-1)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** v0.2 items (H-V2-1, H-V2-3, M-V2-2, M-V2-4, L-V2-5)
**Domain:** cli

Move the current proxy behavior under a `strait proxy` subcommand and add the subcommand framework for `launch`, `generate`, `test`, and `watch`. The existing `strait --config` invocation becomes `strait proxy --config`. Add placeholder subcommands that print "not yet implemented" for the v0.3 commands.

This is a breaking change to the CLI interface. Pre-v1, zero external users.

**Test plan:**
- Unit test: `strait proxy --config` parses correctly and starts proxy (existing integration tests adapted)
- Unit test: `strait launch`, `strait generate`, `strait test --replay`, `strait watch` subcommands parse without errors
- Verify: `strait --help` shows all subcommands with descriptions

Acceptance: `strait proxy --config strait.toml` starts the proxy identically to current `strait --config strait.toml`. All new subcommands are registered in clap.

Key files: `src/main.rs`
