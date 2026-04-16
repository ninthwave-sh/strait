# strait

> **Early development.** Strait is pre-v1, under active development, and not yet distributed or stable. APIs, config formats, and CLI flags will change. Not recommended for production use.

strait is the network policy layer for devcontainers. Replace your iptables allowlist with a Cedar policy engine, live request-level decisions, and a desktop control plane.

Strait uses a container-scoped MITM proxy and Cedar to control outbound HTTP access from a devcontainer-style runtime. That owned runtime boundary is deliberate: request-level visibility without machine-wide CA trust needs a boundary we control.

## The problem

Security teams need to answer one question: *what should this agent be allowed to do over the network?* The devcontainer spec already answers image, mounts, users, and editor settings. What it does not answer is request-level egress policy for the agent running inside it.

Strait replaces coarse iptables allowlists with Cedar. Observe what an agent actually does, generate a network policy from that behavior, then enforce it.

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

Cedar policies control network egress:

- **Network** - HTTPS MITM proxy with request-level policy (`http:GET`, `http:POST`, `http:DELETE`). Credential injection happens on allow. The agent never sees real API tokens.
- **Identity-aware rules** - Use Cedar to scope requests by method, host, path, and agent identity instead of maintaining a shell-script allowlist.
- **Devcontainer fit** - Keep image build, mounts, users, and editor settings in `devcontainer.json`. Use strait for outbound HTTP policy.

Standalone proxy sessions still exist as a secondary mode for debugging and integrations, and they publish the same session control surfaces. They are useful infrastructure, but the primary product story is devcontainers plus request-level network policy.

## Trust boundary

Strait's trust boundary is **container-local**. No machine-wide CA install is required for the primary `strait launch` runtime.

What happens at launch:

1. A session-local CA is generated on the host and written to a private temporary file, then bind-mounted read-only into the container at `/strait/ca.pem`. Nothing is added to the host's system trust store.
2. An entrypoint script inside the container concatenates the image's system CA bundle (Debian, Alpine, or RHEL layout -- whichever the image ships) with the session CA and writes the result to `/tmp/strait-ca-bundle.pem`. If the CA source is unreadable the entrypoint fails loudly instead of falling back to host-wide trust.
3. The container's trust env vars (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`) are all pointed at the augmented bundle, so OpenSSL, Node, and Python-based agents pick up the session CA automatically.
4. The container's proxy env vars (`HTTPS_PROXY`, `HTTP_PROXY`, `https_proxy`, `http_proxy`) are all pointed at the in-container gateway at `http://127.0.0.1:3128`.
5. The container runs with `--network=none`. The only network path off the container is through the bind-mounted Unix socket that the `strait-gateway` binary forwards to the host proxy. Direct TCP bypass is not possible.

When the session ends, the bind-mounted CA and the container are removed. The host's system trust store is untouched, and there is no step in the supported launch flow that tells an operator to install the CA anywhere on the host.

`strait launch` and `strait session info` both print this trust boundary diagnostic when a session starts or is inspected, so it is always visible when debugging a failed launch.

Standalone proxy mode (`strait proxy`) does **not** share this container-local guarantee: that mode depends on the host's trust configuration for whichever client points at it. See [Standalone proxy mode](#standalone-proxy-mode) for the tradeoff.

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

These commands apply network policy changes live for the running session.

Supported live loop:

1. Update HTTP rules in `policy.cedar`.
2. Run `strait session replace-policy --session <SESSION_ID> ./policy.cedar`.
3. Keep the same interactive session running while new network decisions take effect.

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

A single `.cedar` file governs outbound HTTP policy:

```cedar
// Allow read access to org repos, inject credentials automatically
@id("read-repos")
permit(
  principal == Agent::"worker",
  action == Action::"http:GET",
  resource in Resource::"api.github.com/repos/our-org"
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

## Docs and examples

- [Devcontainer comparison](docs/devcontainer.md) - where strait fits relative to the devcontainer spec and Claude Code's `init-firewall.sh` setup
- [Devcontainer strategy](docs/designs/devcontainer-strategy.md) - architecture rationale for the network-only devcontainer framing
- [Claude Code example](examples/claude-code/README.md) - run Claude Code inside a strait-managed container

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

- **Devcontainer network policy** - replace shell-script firewall rules with Cedar policy for outbound HTTP access
- **CI/CD pipelines** - govern what builds and agents can call over the network, with auditable records
- **Compliance** - immutable audit trail of every API call
- **Credential isolation** - policy-governed API access without sharing secrets

## Known limitations

- **Network enforcement requires a container runtime** - containers run with `--network=none` (no network interfaces). Traffic reaches the proxy through a gateway binary that communicates over a bind-mounted Unix socket. Direct TCP bypass is not possible inside the container, but the enforcement only applies when running under `strait launch`.
- **Trust is container-local, not host-wide** - the session CA is only injected inside the container. Standalone `strait proxy` sessions rely on whatever trust configuration the pointing client already has; only `strait launch` gives you the "no machine-wide CA install" guarantee.
- **Devcontainer config stays outside strait** - image build, mounts, users, editor settings, and lifecycle hooks still belong in `devcontainer.json`.
- **Policy scope is network-only** - strait does not add separate Cedar rules for filesystem mounts or executable availability.

## Install

```bash
cargo install strait    # from source
```

## License

Apache-2.0
