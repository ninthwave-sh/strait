# Project plan: in-container data plane rewrite

**Created:** 2026-04-17
**Status:** DRAFT
**Relates to:** `docs/designs/devcontainer-strategy.md`

This document plans the work to move strait from its current host-side
proxy + in-container gateway architecture to an in-container data plane
with a host-side control plane. It is the actionable companion to the
strategy doc; work items seeded here feed `.ninthwave/work/`.

## Goals

- No HTTPS_PROXY dependency. All in-container outbound TCP flows redirect
  to the local proxy via iptables REDIRECT.
- One host control plane serves many containers.
- Credentials stay on the host; the in-container proxy injects them on
  allow but never persists them inside the container.
- The devcontainer feature install is a single block in devcontainer.json.
- `strait launch` is removed.

## Non-goals for this phase

- eBPF-based interception. iptables is enough for v1.
- Windows host support. Linux and macOS hosts only. Containers always
  run Linux.
- Per-container proxy isolation beyond the root-vs-agent-user split
  inside the container.

## Scope changes relative to current codebase

### Removed

- `src/launch.rs` and the `strait launch` CLI subcommand.
- `src/container.rs` Docker/Podman lifecycle logic. Container lifecycle
  is the user's responsibility (devcontainer feature, sandcastle, direct
  docker run). Anything still needed for integration tests moves under
  `tests/support/`.
- Host-side MITM proxy process. The `src/mitm.rs` pipeline moves into
  the in-container agent binary; no host-side copy remains.
- Gateway binary as a separate role. The `gateway` crate becomes
  `strait-agent` -- in-container proxy, entrypoint wrapper, and control-
  plane client in one shipped binary.
- `--network=none` + Unix-socket data-path gateway. The container gets
  real Linux networking; iptables handles redirection.
- `HTTPS_PROXY` env injection in `src/container.rs`. Not applicable to
  the new model and actively harmful (it signals a bypass surface).

### Retained

- Cedar policy engine (`src/policy.rs`). Unchanged.
- MITM pipeline (`src/mitm.rs`) and session-local CA (`src/ca.rs`). Move
  from host to in-container agent.
- Observation pipeline (`src/observe.rs`) and generation (`src/generate.rs`).
  The observation stream moves from host-local JSONL + socket to
  "container -> host control plane -> desktop UI."
- Audit log format. Writes happen in the host control plane.
- Credential store (`src/credentials.rs`, `src/sigv4.rs`) -- moves into
  the host control plane. In-container proxy requests a credential only
  on allow, via the host RPC, and injects it into the outbound request.
- Desktop control plane (M-CSM-6). Retargeted at the host control plane.

### New components

- `strait-host` -- long-lived host process. Owns rule store, decisions,
  credentials, audit, desktop-facing gRPC API, and a container registry.
- `strait-agent` -- shipping in-container binary. Modes:
  - `entrypoint` -- installs iptables rules, drops privileges, execs
    the agent command.
  - `proxy` -- the MITM proxy process started by the entrypoint.
  - (one binary, two modes, so the devcontainer feature ships one file.)
- Control-plane gRPC protocol (`proto/strait_host.proto`). Covers
  container registration, decision requests, credential requests,
  observation streaming, rule subscription, and heartbeat.
- Devcontainer feature manifest (`features/strait/devcontainer-feature.json`)
  and install script.

## Architecture invariants

These must hold after the rewrite. Each is a testable property:

1. The agent user inside the container has no read or connect permission
   on `/run/strait/host.sock` and no write permission on the proxy's
   iptables rules.
2. Setting `HTTPS_PROXY=` or `unset HTTPS_PROXY` inside the container
   does not change what the agent can reach. The integration tests must
   cover this with a tool that does not honor proxy env vars (for example
   a raw `nc` or a Node `fetch` without proxy wiring).
3. Killing the proxy inside the container as the agent user fails.
   Signal 9 from the agent user to the proxy pid returns EPERM.
4. The host control plane can register two or more containers
   simultaneously and route each decision back to the correct session.
5. Credentials never touch the container filesystem. The in-container
   proxy receives them over gRPC and holds them only in memory for the
   lifetime of the outbound request.

## Work-item outline

Priorities use the ninthwave scheme (`C`=critical, `H`=high, `M`=medium,
`L`=low). IDs use feature codes `ICDP` (in-container data plane) and
`HCP` (host control plane).

### Phase 1: in-container data plane

- **H-ICDP-1** -- `strait-agent` binary skeleton. Workspace crate,
  `entrypoint` and `proxy` subcommands, shared startup config loader.
  Unblocks the rest of Phase 1. Key files: `agent/` new crate,
  `Cargo.toml` workspace members.
- **H-ICDP-2** -- Entrypoint privilege-drop flow. As root: verify
  `CAP_NET_ADMIN`, install iptables OUTPUT REDIRECT for 80/443 to the
  proxy port, then `setuid` to the configured agent user and exec the
  agent command. Tested with a docker-based integration test.
- **H-ICDP-3** -- Move MITM pipeline from `src/mitm.rs` into the proxy
  subcommand. Use `SO_ORIGINAL_DST` to recover the intended destination
  after REDIRECT. Retain the hudsucker pipeline and session-local CA.
- **H-ICDP-4** -- CA trust injection inside container entrypoint. Update
  `/etc/ssl/certs/ca-certificates.crt`, `/etc/pki/ca-trust/...`, and
  common language-specific trust stores (Node, Python). No host-side
  involvement.
- **H-ICDP-5** -- Delete `src/launch.rs`, `src/container.rs`, the
  `launch` CLI subcommand, and the host-side proxy bootstrap in
  `src/main.rs`. Remove `bollard` from top-level dependencies. Move the
  few things integration tests still need to `tests/support/`.
- **M-ICDP-6** -- Integration test matrix for invariants 1, 2, and 3
  in the invariants list above. Runs in Docker in CI.

### Phase 2: host control plane

- **H-HCP-1** -- `strait-host` process skeleton. Long-lived, listens on
  a Unix socket (default `/var/run/strait/host.sock`) plus a TCP gRPC
  port for the desktop app. Config at `~/.config/strait/host.toml`.
- **H-HCP-2** -- gRPC protocol definition: `RegisterContainer`,
  `SubmitDecision` (hold-and-resume), `FetchCredential`, `StreamRules`,
  `StreamObservations`, `Heartbeat`. Proto file committed, generated
  code vendored.
- **H-HCP-3** -- Rule store. Persistent (sqlite or sled, decide during
  implementation). Multi-container aware -- rules carry a session scope
  plus a default scope that applies to all containers.
- **H-HCP-4** -- Credential store. Moves logic from `src/credentials.rs`
  and `src/sigv4.rs` out of the in-container proxy and behind the host
  RPC. On allow, the in-container proxy calls `FetchCredential(host,
  action)`; the host returns the computed Authorization header value (or
  signs a SigV4 request) for that single outbound call.
- **M-HCP-5** -- Host control plane observation stream. In-container
  proxy pushes observations upstream; host persists and broadcasts to
  subscribed desktop sessions.
- **H-HCP-6** -- Retarget existing H-CSM-3 (hold-and-resume) and
  H-CSM-4 (persist action) from the retired local control service to
  the new host control plane. These work items are already decided in
  `.ninthwave/decisions/`; update them to reference `strait-host` RPCs.
- **M-HCP-7** -- Multi-container session registry in the desktop shell
  (M-CSM-6). Side pane lists active containers; decision alerts show
  the originating session.

### Phase 3: install surface

- **H-INST-1** -- Devcontainer feature at `features/strait/`. Ships the
  `strait-agent` binary, entrypoint wrapper, and a post-create hook
  that validates CAP_NET_ADMIN availability.
- **H-INST-2** -- Published image at `ghcr.io/ninthwave-io/strait`. CI
  workflow updated to build and push on release tags.
- **M-INST-3** -- Bring-your-own-sandbox docs. Document the entrypoint
  pattern, CAP_NET_ADMIN requirement, and socket mount. Include a
  working sandcastle example.
- **M-INST-4** -- Host install paths. Homebrew cask for macOS,
  tarball-with-install-script for Linux, plus a `brew install strait`
  shortcut that wires up the host control plane as a launchd service.

### Phase 4: onboarding and presets

- **M-ONB-1** -- Rescope M-CSM-7 onboarding around the devcontainer
  feature. First session starts by adding the feature block; desktop
  app detects the first registered container and walks through observe
  -> generate -> persist.
- **M-ONB-2** -- Preset library lives in the host control plane. Any
  registered container can opt in to a preset by id. Existing preset
  work from M-CSM-7 becomes server-side defaults.
- **L-ONB-3** -- First-run quickstart tutorial in the desktop app.
  Covers starting the host, adding the feature to an existing devcontainer
  project, running an agent, observing a session, and persisting a rule.

## Dependencies

```
H-ICDP-1 ---- H-ICDP-2 ---- H-ICDP-3 ---- H-ICDP-5
                  \             \
                   H-ICDP-4      \
                                  M-ICDP-6

H-HCP-1 ---- H-HCP-2 ---- H-HCP-3 ---- H-HCP-6 (retargeted H-CSM-3,4)
                   \           \
                    H-HCP-4     M-HCP-5 ---- M-HCP-7

H-ICDP-3 (proxy) + H-HCP-4 (credential RPC) unblock real credential flow
H-HCP-6 needs H-ICDP-3 so the in-container proxy can issue SubmitDecision
H-INST-1 needs H-ICDP-* and H-HCP-* both at "integration-ready"
```

## Test strategy

- Existing loopback integration tests (`tests/integration.rs`) migrate
  to target the in-container proxy, not a host-side one. Tests can run
  `strait-agent proxy` directly against a loopback TCP+TLS echo server,
  without starting a container.
- Docker-based integration tests (replacing `tests/launch_integration.rs`)
  build a minimal image, run `strait-agent entrypoint --` with
  a simple agent command, and exercise the four invariants above.
- Host control plane gets its own tests under `host/tests/` covering
  multi-container registration, decision routing, and credential RPC.

## Risks and open questions

- **CAP_NET_ADMIN acceptance.** Some hardened sandboxes reject adding
  capabilities. Mitigation: document which sandboxes support it;
  sandcastle's Docker and Podman providers do; Vercel Sandbox may not
  (to verify during H-INST-3). If a sandbox cannot grant CAP_NET_ADMIN
  at startup, strait does not fit there -- that is an explicit tradeoff
  of the transparency-first model.
- **macOS desktop host.** Running the host control plane as a launchd
  service is straightforward, but the host-mounted socket must survive
  the Docker Desktop / OrbStack VM boundary. To verify during H-INST-4.
- **Credential round-trip latency.** Every allow-on-first-sight incurs
  an extra gRPC hop to the host. Mitigation: `FetchCredential` can
  bundle with `SubmitDecision` so the verdict and credential come back
  in the same response.
- **Backwards-facing docs.** Every reference to `strait launch`,
  `--network=none`, and the in-container gateway needs updating. Docs
  sweep is part of each phase, not a trailing cleanup.
