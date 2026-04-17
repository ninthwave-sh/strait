# Feat: strait-host process skeleton (H-HCP-1)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** None
**Domain:** host-control-plane
**Lineage:** 4627e6f4-4fb7-49ff-b746-eb0d51f27687

Introduce a new workspace crate `strait-host` that runs as a long-lived process on the host. It listens on a Unix domain socket (default `/var/run/strait/host.sock`, permissions `0600`, owned by the current user) for container-side connections and on a TCP port (default `127.0.0.1:3129`) for the desktop app. Loads config from `~/.config/strait/host.toml`. This item is wiring only: process skeleton, listeners, logging, config loader, graceful shutdown. Protocol definition lives in H-HCP-2.

**Test plan:**
- Unit test: config loader merges defaults with a minimal `host.toml`.
- Integration test: start `strait-host`, connect to the Unix socket and the TCP port, send a no-op `Heartbeat` frame (stubbed), confirm both accept.
- Integration test: SIGTERM triggers graceful shutdown of both listeners within 2 seconds.

Acceptance: `strait-host serve` starts, logs listener endpoints, accepts connections on both sockets, reloads config on SIGHUP, and exits cleanly on SIGTERM. Default socket path and config path are documented in `strait-host --help`. Workspace `cargo test` passes.

Key files: `host/Cargo.toml`, `host/src/main.rs`, `host/src/config.rs`, `host/src/listener.rs`, `Cargo.toml`
