# Feat: SIGHUP policy reload (M-V2-2)

**Priority:** Medium
**Source:** v0.2 roadmap — hot-reload without restart
**Depends on:** H-V2-1 (requires ArcSwap<PolicyEngine> in ProxyContext)
**Domain:** config

Wire up `SIGHUP` to trigger an immediate policy reload from the configured source (file or git). The signal handler sets an atomic flag; the main loop (or a dedicated reload task) detects the flag, re-reads the policy file (or re-fetches from git), validates the schema if configured, and atomically swaps `ProxyContext.policy` via `ArcSwap`. Log the reload result (success or error with reason) as a structured tracing event. On reload error, keep the previous policy in place and log the failure — do not crash.

**Test plan:**
- Send SIGHUP to a running strait process → policy reloads, new policy takes effect on next request
- SIGHUP with invalid policy file → old policy retained, error logged, process stays up
- SIGHUP with schema validation failure → old policy retained, error logged
- No SIGHUP → policy unchanged

Acceptance: Signal handling confirmed on Linux and macOS (tokio signal or nix crate). `cargo test` passes. Integration test sends SIGHUP and verifies behavior without external network access.

Key files: `src/main.rs` (signal handling), `src/config.rs` (reload logic), `src/policy.rs`
