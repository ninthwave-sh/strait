# Feat: Host control plane gRPC protocol (H-HCP-2)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** H-HCP-1
**Domain:** host-control-plane
**Lineage:** ae7a4ca4-1c34-47aa-8eb3-14773fe1ddc6

Define the gRPC protocol between `strait-agent` (in container) and `strait-host` (on host) and between `strait-host` and the desktop shell. RPCs: `RegisterContainer`, `SubmitDecision` (hold-and-resume, used for every prompt), `FetchCredential` (returns computed header value or SigV4-signed request), `StreamRules` (server-streaming rule changes to registered containers), `StreamObservations` (client-streaming observations from containers to host), `Heartbeat`. Protos committed, generated code vendored, shared crate `strait-proto` holds generated types.

**Test plan:**
- Round-trip test: serialize and deserialize every message type; no wire-format surprises.
- Integration test: `strait-host` stub that echoes `SubmitDecision` requests; fake client sends one, waits for verdict, closes stream on timeout.
- Schema test: `prost-build` compiles cleanly; no reserved-field collisions.

Acceptance: `proto/strait_host.proto` compiles via `prost-build` in a new `strait-proto` workspace crate. `strait-host` serves all six RPCs with minimal stubs (return `Unimplemented` where real logic lives in later items). Integration test covers at least one round-trip per RPC. `strait-agent` has a gRPC client module that connects over the bind-mounted Unix socket.

Key files: `proto/strait_host.proto`, `proto/Cargo.toml`, `host/src/grpc.rs`, `agent/src/host_client.rs`
