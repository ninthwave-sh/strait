# Feature: Cargo workspace + gateway binary crate (C-NI-1)

**Priority:** Critical
**Source:** v0.4 network isolation investigation
**Depends on:** None
**Domain:** network-isolation

Convert the single-crate repo to a Cargo workspace and add a `gateway/` crate
that implements a TCP-to-Unix-socket forwarder. The gateway binary runs inside
containers as an init wrapper: it listens on TCP 127.0.0.1:3128, forwards each
connection to a Unix socket (the host proxy), manages a child process (the
user's command), and exits with the child's exit code.

The gateway must be a separate crate with minimal dependencies (tokio, libc)
so it cross-compiles to a small static musl binary (~1-2MB) without pulling
in cedar-policy, bollard, etc.

**Test plan:**
- Unit tests in `gateway/` for TCP-to-Unix-socket forwarding (create a Unix socket echo server, connect via the gateway, verify round-trip)
- Test child process management: gateway spawns a child, child exits 0 -> gateway exits 0; child exits 1 -> gateway exits 1
- Test signal forwarding: SIGTERM to gateway propagates to child
- Verify `cargo build -p strait-gateway` succeeds independently

Acceptance: `cargo test -p strait-gateway` passes; binary runs standalone with
`strait-gateway --socket /path/to/sock -- echo hello` and forwards traffic
while running the child process.

Key files: `Cargo.toml` (workspace), `gateway/Cargo.toml`, `gateway/src/main.rs`
