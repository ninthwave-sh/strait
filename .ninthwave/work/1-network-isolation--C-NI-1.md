# Feature: Cargo workspace and gateway binary crate (C-NI-1)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** None
**Domain:** network-isolation
**Lineage:** 1e63eb03-ac1b-4e4c-8b97-7118c4403003

Convert the single-crate repo into a Cargo workspace and add a small `gateway/` crate that runs inside containers. The gateway should listen on `127.0.0.1:3128`, forward traffic to the host proxy over a Unix socket, manage the child command, and exit with the child's exit code. Keep the crate dependency-light so it can cross-compile to a small static musl binary.

**Test plan:**
- Add `gateway/` unit tests that forward TCP traffic through a Unix socket echo server and verify round-trip data.
- Verify child-process exit code propagation and signal forwarding in `gateway` tests.
- Run `cargo build -p strait-gateway` and `cargo test -p strait-gateway`.

Acceptance: The repo builds as a workspace, `strait-gateway` can run standalone with a Unix socket target, and gateway tests cover forwarding plus child-process lifecycle behavior.

Key files: `Cargo.toml`, `gateway/Cargo.toml`, `gateway/src/main.rs`
