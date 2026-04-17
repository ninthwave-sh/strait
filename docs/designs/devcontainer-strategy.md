# Strategy: strait as a sandbox-native network policy layer

**Last updated:** 2026-04-17
**Status:** APPROVED
**Supersedes:** previous revision (2026-04-16)

## Context

The April 2026 refocus committed strait to network policy for containerized AI
agents. This revision locks in three decisions that were still open:

1. Where the data plane (proxy + interception) lives.
2. How in-container tools reach the proxy.
3. What the primary install surface is.

The trigger was a closer read of three reference implementations that share
the problem space: `agentic-devcontainer` (opensnitch-in-container), `opensnitch`
(Linux application firewall), and `LuLu` (macOS outbound firewall). Every one
of them intercepts traffic at the kernel or system-extension layer and treats
the proxy-env-var convention as insufficient on its own.

That read changes strait's architecture in one important way: the proxy moves
into the container and relies on iptables REDIRECT for transparency, while
the control plane stays on the host and fans out across many containers.

## Thesis

Strait is the live, granular network policy layer for AI agent sandboxes.
The thing it sells is the UX and the granularity -- observe-then-enforce,
live allow/deny with session and persist durations, rules scoped by HTTP
method and path and agent identity. "The agent cannot bypass it" is expected
baseline, not the headline.

Two design laws follow from that:

1. **No bypass paths.** The proxy is not reachable only by a polite
   `HTTPS_PROXY` environment variable. Every outbound TCP flow from the
   agent is forced through the proxy by the kernel, regardless of whether
   the tool making the request cooperates.
2. **Granularity down to the request.** Cedar rules address HTTP method,
   host, path, and agent identity. That requires HTTP-layer inspection,
   which means keeping MITM. Connection-level (SNI-only) enforcement is
   rejected as a viable option; it collapses the rule surface that makes
   the product distinctive.

## Architecture

```
Host                                     Container (Linux namespace)
+---------------------------------+     +----------------------------------+
| strait-host (control plane)     |     | strait-agent (data plane)        |
|                                 |     |                                  |
|  - Rule store                   |<--->|  - MITM proxy (root)             |
|  - Decisions (allow/deny/persist| uds |  - iptables REDIRECT entrypoint  |
|  - Credential store             |     |  - Registers with host on start  |
|  - Desktop UI                   |     |                                  |
|  - Multi-container registry     |     |   (agent runs as non-root user;  |
|                                 |     |    cannot touch proxy or rules)  |
+---------------------------------+     +----------------------------------+
         ^                                         ^
         |  one host <-> many containers           |
         |                                         |
         +------- Unix socket, root-only in -------+
```

### Data plane: inside the container

The proxy runs inside the container as root. At entrypoint:

1. The entrypoint starts as root.
2. It installs iptables rules that `REDIRECT` all outbound TCP (default:
   ports 80, 443, plus configured extras) to `127.0.0.1:<proxy_port>`.
3. It starts the strait MITM proxy bound to that port, owned by root.
4. It drops to the configured non-root user and `exec`s the agent command.

The agent never runs as root and cannot modify iptables, cannot kill the
proxy, and cannot read the proxy's config or its socket to the host. The
CA trust bundle, policy files, and the host-facing Unix socket are all
read-only bind mounts owned by root inside the container.

The trust boundary is recast from "container vs host" to "proxy-as-root
vs agent-as-user, inside the same namespace." That is weaker than full
namespace isolation, but it is the right boundary for this product: the
threat model is a prompt-injected agent that the user is intentionally
running, not a malicious container trying to break out.

### Control plane: on the host, always

The host runs a long-lived `strait-host` process. It owns:

- The rule store and the audit log.
- Decision flow -- when an in-container proxy sees a new request, it asks
  the host for a verdict. The host holds the request (hold-and-resume),
  surfaces the decision to the desktop UI, and responds with allow, deny,
  allow-once, allow-session, or persist.
- The credential store. On allow, the host supplies the credential that
  the in-container proxy injects into the outbound request. Credentials
  never exist on disk inside the container.
- The container registry. Multiple containers connect to the same host
  control plane. The UI surfaces per-session panes, not per-host views.
- The desktop shell (the existing M-CSM-6 Electron app).

This is the piece that makes strait fit orchestration layers like
`sandcastle`. A host strait-host can serve many agent sandboxes in
parallel -- the sandboxes are provisioned by whatever orchestrator the
user prefers, and strait is the policy layer they share.

### Host <-> container transport

A Unix domain socket is bind-mounted from host into container at
`/run/strait/host.sock`. Inside the container it is owned by `root:root`
with mode `0600`. The agent user has no read or connect permission.

The in-container proxy opens the socket on startup, registers the
container's session id, and keeps a long-lived gRPC channel to the host
control plane. Every new Cedar evaluation that returns "prompt" (no cached
verdict) rides that channel as a `SubmitDecision` RPC.

### Interception mechanism

iptables REDIRECT is the primary mechanism. Requirements:

- Container must have `CAP_NET_ADMIN` at entrypoint time so it can install
  the rules. The capability is dropped before the agent user takes over.
- Works on Linux. On macOS, users run Docker Desktop or OrbStack, both of
  which run a Linux VM; the container runs under Linux kernel semantics,
  so REDIRECT works there too.
- The proxy reads the original destination via `SO_ORIGINAL_DST` on the
  redirected TCP connection, then MITM-terminates TLS using the session-
  local CA.

eBPF-based socket redirection is in scope as a future mechanism, not a
v1 requirement. iptables REDIRECT is well understood, ubiquitous, and
enough for the wedge.

### What this is not

- Not a connection-level firewall. strait MITMs. Users who want only
  SNI-level decisions should use one of the reference implementations.
- Not a container orchestrator. strait does not launch containers any
  more. `strait launch` is removed as a user-facing command.
- Not Linux-kernel-only. The host control plane runs on macOS and Linux;
  the data plane runs inside a Linux container regardless of host OS.
- Not privileged on the host. The control plane is a normal user process.
  Only the in-container data plane needs `CAP_NET_ADMIN`, and only at
  startup.

## Install surface

### Primary: devcontainer feature

Most users adopt strait by adding a block to `devcontainer.json`:

```json
"features": {
  "ghcr.io/ninthwave-io/strait": {
    "host": "unix:///var/run/strait/host.sock",
    "agent_user": "node",
    "policy": "policy.cedar"
  }
}
```

The feature ships the in-container `strait-agent` binary, an entrypoint
wrapper that installs iptables rules and drops privileges, and the
read-only mount of the session CA.

The host strait-host process must already be running; the feature does
not start it. Installing the host control plane is a one-time action
(Homebrew cask on macOS, apt or binary install on Linux).

### Secondary: bring-your-own-sandbox

For users who are not on devcontainer -- orchestrators like sandcastle,
hand-rolled Docker setups, Podman rootless, CI runners -- strait is a
small static binary plus a documented entrypoint pattern:

```
1. Copy strait-agent into your image.
2. Make your entrypoint run: strait-agent entrypoint -- <your cmd>
3. Grant CAP_NET_ADMIN at startup (drop it in the wrapper).
4. Bind-mount /var/run/strait/host.sock from host.
```

This is the surface that lets strait plug into any agent sandbox. The
contract with the host control plane is the gRPC protocol on the
bind-mounted socket; everything above that is the user's concern.

### Removed: `strait launch`

The CLI command that currently launches containers and wires up a host-
side proxy is removed in this phase. It conflates container orchestration
with policy, and carrying it forward means carrying the host-side proxy
path -- which is exactly the architecture being removed. Users who need
to launch containers will use their existing tooling (docker, podman,
compose, devcontainer CLI, sandcastle).

## Migration posture

Clean cut, pre-v1, no deprecation window. Strait is pre-users. The work
items below delete the old data plane rather than flagging it.

## Phasing

### Phase 0 (this document)

Lock the thesis: proxy inside container, iptables REDIRECT for
transparency, control plane on host, devcontainer feature as primary
install, `strait launch` removed.

### Phase 1: in-container data plane

- Replace the host-side proxy + in-container gateway with a single
  in-container `strait-agent` binary that embeds the MITM proxy and
  the iptables-setting entrypoint.
- Collapse the current `gateway` crate into `strait-agent`; it becomes
  the shipping in-container binary.
- Delete `src/launch.rs` and the `strait launch` CLI command. Move any
  still-needed logic into the host control plane.
- Rewrite container-side bring-up to use iptables REDIRECT instead of
  `HTTPS_PROXY` env vars.
- Drop `--network=none` + Unix-socket gateway. The container gets real
  Linux networking; the kernel redirects everything through the proxy.

### Phase 2: host control plane

- Introduce `strait-host`, a long-lived process with a gRPC API.
- Move the rule store, decision flow, and credential store behind that
  API. Audit log becomes a tail of decisions from the host.
- Retarget the existing control protocol (H-CSM-3 hold-and-resume,
  H-CSM-4 persist action) at the host control plane rather than a
  per-container local service.
- Rescope H-CSM-5 from "local control service" to "host control service
  with multi-container session management."
- Desktop control plane (M-CSM-6) connects to `strait-host` instead of
  a single in-container daemon.

### Phase 3: devcontainer feature + bring-your-own-sandbox

- Publish `ghcr.io/ninthwave-io/strait` as a devcontainer feature.
- Entrypoint wrapper installs iptables rules, starts proxy as root,
  drops to `remoteUser` before `exec`ing the agent command.
- Document the bring-your-own-sandbox install path with a working
  sandcastle example.
- Retire the existing `examples/claude-code/` flow in favor of a
  devcontainer.json example that uses the feature.

### Phase 4: onboarding and presets

- Rescope M-CSM-7 onboarding around "first session through the
  devcontainer feature" rather than `strait launch`.
- Host control plane gets an install flow (Homebrew cask on macOS,
  systemd service on Linux, or run-from-terminal for dogfood).
- Presets become host-side defaults that any newly registered container
  can adopt.

## What stays from previous revisions

- Cedar policy engine, HTTP-only action model, observe-then-enforce
  workflow.
- Session-local CA and TLS termination.
- Credential broker. Moves from in-proxy to host control plane; injected
  by the in-container proxy using a credential handed down over the
  host socket on allow.
- Desktop control plane as the primary client surface. Not a VS Code
  extension. Users ship agents across many IDEs and many sandboxes.
- No fs or proc Cedar domains. Devcontainer owns filesystem shape;
  strait stays scoped to network.
- No backwards compat with the host-side-proxy architecture. Removed.

## What this closes

Two open questions the previous revision left behind:

1. **How do in-container tools find the proxy without `HTTPS_PROXY`?**
   Answer: they do not find it. The kernel redirects every outbound
   TCP flow through the proxy. Tools that ignore `HTTPS_PROXY` cannot
   bypass strait; tools that honor it do not need to set it.
2. **How does one strait deployment serve many sandboxes?**
   Answer: the host control plane is the coordination point. Each
   sandbox registers its session on startup over the host-mounted
   socket and lives in the multi-container session view of the
   desktop UI.

## References

- `docs/devcontainer.md` -- public-facing comparison with Claude Code's
  reference devcontainer. Needs rewrite after Phase 1 lands.
- `docs/designs/in-container-rewrite.md` -- detailed project plan and
  work-item outline for Phases 1 through 4.
- `.ninthwave/decisions/` -- decision logs for individual work items.
