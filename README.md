# strait

> **Early development.** Strait is pre-v1, under active development, and not yet distributed or stable. APIs, config formats, and CLI flags will change. Not recommended for production use.

Policy platform for AI agents. Strait uses a container-scoped MITM proxy plus Cedar policy over network, filesystem, and process access. That owned runtime boundary is deliberate: request-level visibility without machine-wide CA trust needs a boundary we control.

## The problem

Security teams need to answer one question: *what should this agent be allowed to do?* But today's tools split that answer across separate network proxies, filesystem sandboxes, and process monitors, each with its own policy format and its own blind spots.

Strait unifies all three under Cedar. Observe what an agent actually does, auto-generate a policy from that behavior, then enforce it.

We explored a host-scoped pivot after looking closely at `nono`. The learning was useful, but it reinforced the original architecture: if you want MITM-level request control across everything the agent does, without mandating machine-wide CA trust, you need a runtime boundary you own. For Strait, that boundary is still the container.

## How it works

```
  ┌──────────────────────────────────────────────────────┐
  │          Container (Docker/Podman/OrbStack)          │
  │                                                      │
  │  ┌──────────────┐     ┌──────────────────────┐       │
  │  │ AI Agent     │────▶│ Strait Proxy (MITM)  │──▶ API│
  │  │ (your cmd)   │     │ Cedar eval + creds   │       │
  │  │ [full TTY]   │     └──────────────────────┘       │
  │  └──────────────┘                                    │
  │                                                      │
  │  Filesystem from Cedar policy:                       │
  │    fs:read  /project/src  -> read-only mount         │
  │    fs:write /project/out  -> read-write mount        │
  │    (no policy = not mounted = invisible)             │
  └──────────────────────┬───────────────────────────────┘
                         │ observations
  ┌──────────────────────▼───────────────────────────────┐
  │  Strait Host Process                                 │
  │   - Container lifecycle management                   │
  │   - Local control API (session.info/watch.attach)    │
  │   - Observation stream (Unix socket + JSONL)         │
  │   - strait session watch - colored live event viewer │
  │   - strait generate - Cedar policy from observations │
  │   - strait test --replay - policy verification       │
  └──────────────────────────────────────────────────────┘
```

Cedar policies control three domains:

- **Network** - HTTPS MITM proxy with request-level policy (`http:GET`, `http:POST`, `http:DELETE`). Credential injection on allow. The agent never sees real API tokens.
- **Filesystem** - Cedar `fs:read` / `fs:write` rules translate to container bind-mounts. No rule = not mounted = invisible to the agent.
- **Process** - Cedar `proc:exec` rules control which binaries are available in the container.

Standalone proxy sessions still exist as a secondary mode for debugging and integrations, and they publish the same session control surfaces. They are useful infrastructure, but they are not the primary product wedge.

## Quick start

### Launch an interactive session

```bash
strait launch --observe -- ./my-agent
```

`strait launch` starts the agent in a container, prints a stable session ID, and publishes two local Unix sockets:

- a control socket used by `strait session info|reload-policy|replace-policy|stop`
- an observation socket used by `strait session watch`

In a second terminal, target the running session directly:

```bash
strait session list
strait session info --session <SESSION_ID>
strait session watch --session <SESSION_ID>
```

`strait session info` reports the session ID, mode, control socket, observation socket, and container identity when present. `strait session watch` renders the live event stream for that session, including lifecycle events such as `container:start`, live control-plane events such as `policy:reload`, and PTY resize events such as `tty:resize`.

The older `strait watch` command remains as a compatibility alias, but session-targeted commands are the primary interface for live launch management.

### Understand the live-update boundary

Live policy mutation is available through the local control API:

```bash
strait session reload-policy --session <SESSION_ID>
strait session replace-policy --session <SESSION_ID> ./policy.cedar
```

These commands only apply network policy changes live. Filesystem (`fs:`) or process (`proc:`) changes still require a relaunch because those domains are enforced by container mounts and executable availability at container start.

Supported live loop:

1. Update HTTP rules in `policy.cedar`.
2. Run `strait session replace-policy --session <SESSION_ID> ./policy.cedar`.
3. Keep the same interactive session running while new network decisions take effect.

Restart-bound loop:

1. Add or remove `fs:` or `proc:` permissions.
2. Relaunch with `strait launch --warn ...` or `strait launch --policy ...`.
3. Do not expect `reload-policy` or `replace-policy` to mutate mounts or available binaries in place.

### Observe what an agent does

```bash
strait launch --observe -- ./my-agent
```

Observe mode allows everything, records activity to `observations.jsonl`, and still publishes the same session control surfaces for inspection and watch.

### Generate a policy from observations

```bash
strait generate observations.jsonl
```

Produces `policy.cedar` covering exactly what the agent did. Dynamic path segments (UUIDs, hashes) are collapsed to wildcards automatically.

### Review the policy

```bash
strait explain policy.cedar
```

Human-readable summary of what the policy allows and denies.

### Enforce the policy

```bash
strait launch --policy policy.cedar -- ./my-agent
```

Same agent, same container, now with enforcement. Known actions succeed. Novel actions get denied.

### Progressive enforcement

```
  OBSERVE ──▶ GENERATE ──▶ WARN ──▶ ENFORCE
     │                       │         │
     │  (no policy,          │  (log   │  (block
     │   log everything)     │  what   │   violations)
     │                       │  would  │
     │                       │  block) │
```

Use `--warn` as an intermediate step: it loads the policy and logs violations without blocking.

```bash
strait launch --warn policy.cedar -- ./my-agent
```

### Mock-TUI smoke flow (macOS-first, with gateway prerequisite)

This repo ships a deterministic PTY fixture for local dogfooding. A repo-local `strait launch` also needs a Linux `strait-gateway` binary for the container architecture. On macOS, the host-native gateway binary is Mach-O and cannot run inside the Linux container, so build the Linux gateway first.

Common targets:

- Apple Silicon Docker/OrbStack defaulting to arm64 containers: `aarch64-unknown-linux-musl`
- Intel Docker Desktop or amd64 containers: `x86_64-unknown-linux-musl`

From the repo root:

```bash
cargo build --bin strait --bin mock-tui-fixture
cargo zigbuild --release --package strait-gateway --target <linux-target>
target/debug/strait launch \
  --observe \
  --image ubuntu:24.04 \
  --output /tmp/mock-tui-observations.jsonl \
  -- "$(pwd)/target/debug/mock-tui-fixture"
```

`strait launch` discovers the cross-built gateway from the normal Cargo target layout, so the `cargo zigbuild` artifact is the required prerequisite for this repo-local smoke flow.

Then validate the interactive path manually:

1. Copy the printed `Session ID` from the launch terminal.
2. In a second terminal, run `target/debug/strait session info --session <SESSION_ID>` and confirm the control and observation sockets are published.
3. In that second terminal, run `target/debug/strait session watch --session <SESSION_ID>`.
4. Back in the launch terminal, type `through-strait` and press Enter. The fixture should echo an `input` event and the watch terminal should continue streaming the same session.
5. Resize the launch terminal window. The fixture should redraw and the watch terminal should show a `tty:resize` event with the new `COLSxROWS` and `signal` as the source.
6. Type `exit` to end the fixture cleanly.

What to verify:

- session watch stays attached to the targeted session for the whole interaction
- passthrough PTY I/O works end to end
- resize is visible as a runtime event
- the observation log at `/tmp/mock-tui-observations.jsonl` contains `container_start`, `container_stop`, and `tty_resized`

## Cedar policies

A single `.cedar` file governs all three domains:

```cedar
// Network: allow GET on org repos, inject credentials automatically
@id("read-repos")
permit(
  principal == Agent::"worker",
  action == Action::"http:GET",
  resource in Resource::"api.github.com/repos/our-org"
);

// Filesystem: read-only mount of project source
@id("read-source")
permit(
  principal,
  action == Action::"fs:read",
  resource in Resource::"fs::/project/src"
);

// Process: allow git binary
@id("allow-git")
permit(
  principal,
  action == Action::"proc:exec",
  resource == Resource::"proc::git"
);

// Hard deny: no pushes to main
@id("deny-push-main")
@reason("Direct pushes to main are prohibited; use pull requests")
forbid(
  principal,
  action == Action::"http:POST",
  resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
```

Default disposition is **deny**. Only actions with a matching `permit` are allowed. `forbid` policies override `permit` for hard guardrails.

## Credential injection

Credentials live in `strait.toml`, not in the agent's environment. The proxy injects them into allowed requests only.

```toml
# GitHub — bearer token
[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "GITHUB_TOKEN"

# AWS — SigV4 request signing
[[credential]]
host_pattern = "*.amazonaws.com"
type = "aws-sigv4"
source = "env"
```

The agent never sees real secrets. If a request is denied by policy, credentials are not injected. This prevents exfiltration via prompt injection.

## Standalone proxy mode

Strait also runs as a standalone HTTPS proxy without containers, for debugging, local integrations, or experimentation with the policy and observation surfaces:

```bash
strait proxy --config strait.toml
```

Features in proxy mode today: MITM with Cedar policy evaluation, credential injection (bearer + AWS SigV4), live session control sockets, observation streaming, structured JSON audit logging, health check endpoint, SIGHUP policy hot-reload, and git-hosted policies with automatic polling.

This mode shares the same session publication and watch surfaces as the primary `strait` runtime, but it is not the primary enforcement story because host trust and subprocess coverage vary by client.

## Policy tooling

```bash
strait template list                              # list built-in starter policies
strait template apply github-org-readonly          # apply a template
strait session list                                # list active Strait sessions
strait session info --session <id>                 # inspect one running session
strait session watch --session <id>                # stream live events for one session
strait session reload-policy --session <id>        # reload network policy in place
strait session replace-policy --session <id> policy.cedar  # replace network policy in place
strait session stop --session <id>                 # stop one running session
strait explain policy.cedar                        # human-readable summary
strait diff old-policy.cedar new-policy.cedar      # semantic permission diff
strait test --replay observations.jsonl --policy policy.cedar  # verify policy
strait watch                                       # compatibility alias for newest session
```

## Use cases

- **Agent sandboxing** - run AI agents with least-privilege access to APIs, files, and tools
- **CI/CD pipelines** - govern what builds can fetch and write, with auditable records
- **Compliance** - immutable audit trail of every API call and file access
- **Credential isolation** - policy-governed API access without sharing secrets

## Known limitations

- **Network enforcement requires a container runtime** — containers run with `--network=none` (no network interfaces). Traffic reaches the proxy through a gateway binary that communicates over a bind-mounted Unix socket. Direct TCP bypass is not possible inside the container, but the enforcement only applies when running under `strait launch`.
- **Filesystem and process enforcement rely on container isolation** — standard container security model.
- **Live mutation stops at the network boundary** — `strait session reload-policy` and `strait session replace-policy` can update HTTP policy live, but filesystem mounts and available executables are fixed for the lifetime of the launched container.

## Install

```bash
cargo install strait    # from source
```

## License

Apache-2.0
