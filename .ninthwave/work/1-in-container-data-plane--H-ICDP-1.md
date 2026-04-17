# Feat: strait-agent crate skeleton (H-ICDP-1)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 1
**Depends on:** None
**Domain:** in-container-data-plane
**Lineage:** 08c999c1-5137-4252-b951-8c017a5811a6

Introduce a new workspace crate `strait-agent` that will become the shipping in-container binary. It exposes two subcommands: `entrypoint` (privilege-drop wrapper, filled in by H-ICDP-2) and `proxy` (MITM proxy, filled in by H-ICDP-3). This item only stands up the crate, the clap-based subcommand skeleton, a shared startup config loader, and the workspace wiring. No behavior yet beyond printing mode and parsed config.

**Test plan:**
- Unit test: `strait-agent entrypoint --help` and `strait-agent proxy --help` return usage without error.
- Unit test: startup config loader parses a minimal `strait-agent.toml` plus env-var overrides.
- Workspace build: `cargo build -p strait-agent` succeeds; `cargo test --workspace` still passes.

Acceptance: `cargo build --release -p strait-agent` produces a working binary with `entrypoint` and `proxy` subcommands. The crate lives under `agent/` and is a member of the top-level `[workspace]`. Shared config loader (dev-independent from `src/config.rs`) has unit tests. No runtime behavior beyond stub messages; neither subcommand yet installs iptables or serves traffic.

Key files: `agent/Cargo.toml`, `agent/src/main.rs`, `agent/src/config.rs`, `Cargo.toml`
