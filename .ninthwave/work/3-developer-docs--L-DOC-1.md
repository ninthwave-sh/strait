# Docs: Document interactive sessions, control API, and live-update boundaries (L-DOC-1)

**Priority:** Low
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** M-CLI-1, H-TST-1
**Domain:** developer-docs
**Lineage:** 6e6476f9-ccda-484e-bc78-92b03455e25a

Update operator and developer docs to describe the interactive session model, the local control API, and the hard boundary between live network policy updates and restart-bound fs or proc enforcement. Include a documented mock-TUI smoke flow for macOS-first dogfooding and make session-targeted commands the primary examples. Keep the docs aligned with the actual runtime events and CLI names shipped by the implementation.

**Test plan:**
- Review README and command help for consistency with implemented session commands
- Verify the documented mock-TUI smoke flow works on a developer machine
- Check that no example implies unsupported live fs or proc mutation

Acceptance: Docs explain how to launch an interactive session, inspect or mutate it live, watch runtime events, and understand which policy changes require relaunch. Manual smoke steps for mock TUI passthrough and resize are documented. No doc example relies on unsupported live fs or proc mutation.

Key files: `README.md`, `docs/designs/unified-agent-policy-platform.md`, `src/main.rs`
