# Feat: Introduce a gRPC control service for container-backed sessions (H-CSM-5)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`); amended per prior-art analysis 2026-04-16
**Depends on:** H-CSM-4
**Domain:** session-control-service
**Lineage:** aeb200ea-314d-49c6-b942-d51bbefe3626

Add a backgroundable control service that owns primary `strait` sessions and exposes a gRPC API for desktop clients and remote operators. The service listens on a Unix domain socket locally and optionally on TLS-authenticated TCP for remote scenarios (Codespaces, remote VMs where the proxy runs on Linux and the desktop client is on macOS). The gRPC service definition should include: `StreamBlockedRequests` (server-streaming blocked-request events to client), `SubmitDecision` (client sends deny/allow-once/allow-session/persist for a blocked-request ID), `ListSessions`, `GetSessionStatus`, and `Subscribe` (bidirectional streaming for live session events and status changes). Reuse the existing session registry, control socket, and observation stream model so the service is an orchestration layer on top of the current runtime, not a second backend. The proto definition and service contract must not assume localhost -- design remote-capable from the start even if the first implementation only exposes the local Unix socket.

**Test plan:**
- Add CLI tests in `src/main.rs` for service start, status, and stop parsing and help text
- Add integration coverage for service startup, published session discovery, and reconnect from a second local client process
- Add gRPC health check and subscribe/disconnect cycle test
- Add remote-TLS handshake test with mTLS or token auth (can be behind a feature flag if TLS deps are heavy)
- Verify stale socket and registry cleanup on unclean exit followed by a fresh startup

Acceptance: A control service can start and own a container-backed strait session, publish it for other local clients via gRPC over Unix socket, and stop cleanly while preserving the existing session control and observation contracts. The proto definition is remote-capable (no localhost assumptions). A desktop client can connect, stream blocked requests, and submit decisions.

Key files: `src/main.rs`, `src/launch.rs`, `src/observe.rs`, `proto/control.proto` (new), `README.md`
