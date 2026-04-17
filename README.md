# strait

> **Early development.** Strait is pre-v1, under active development, and not yet distributed or stable. APIs, config formats, and CLI flags will change. Not recommended for production use.

strait is the network policy layer for devcontainers. It pairs a container-scoped MITM proxy with a Cedar policy engine, request-level decisions, and (soon) a desktop control plane.

The host-side launcher has been retired. strait no longer orchestrates Docker or Podman itself. Container lifecycle is your responsibility: use the devcontainer feature (landing in a later phase), sandcastle, direct `docker run`, or any other devcontainer-compatible tool. strait provides the policy, the proxy, and the tooling that sits on top.

## The problem

Security teams need to answer one question: *what should this agent be allowed to do over the network?* The devcontainer spec already answers image, mounts, users, and editor settings. What it does not answer is request-level egress policy for the agent running inside it.

Strait replaces coarse iptables allowlists with Cedar. Observe what an agent actually does, generate a network policy from that behavior, then enforce it.

## Architecture at a glance

```
  ┌───────────────────────────────────────────────────────┐
  │              Container (your devcontainer)            │
  │                                                       │
  │  ┌──────────────┐     ┌──────────────────────┐        │
  │  │ Agent        │────▶│ strait-agent proxy   │──▶ API │
  │  │ (your cmd)   │     │ MITM + Cedar eval    │        │
  │  └──────────────┘     └──────────────────────┘        │
  └──────────────────────────┬────────────────────────────┘
                             │ gRPC
  ┌──────────────────────────▼────────────────────────────┐
  │  strait-host (long-lived host process)                │
  │   - Rule store, decisions, credentials, audit         │
  │   - Desktop-facing gRPC API                           │
  └───────────────────────────────────────────────────────┘
```

Phase 1 of the rewrite has landed or is landing the in-container data plane (`strait-agent`). Phase 2 is landing the host control plane (`strait-host`). The top-level `strait` binary in this crate still ships the proxy, Cedar policy tooling, and preset scaffolding.

Cedar policies control network egress:

- **Network** - HTTPS MITM proxy with request-level policy (`http:GET`, `http:POST`, `http:DELETE`). Credential injection happens on allow. The agent never sees real API tokens.
- **Identity-aware rules** - Use Cedar to scope requests by method, host, path, and agent identity instead of maintaining a shell-script allowlist.
- **Devcontainer fit** - Keep image build, mounts, users, and editor settings in `devcontainer.json`. Use strait for outbound HTTP policy.

## Trust boundary

Strait's trust boundary is **container-local**. No machine-wide CA install is required. A session-local CA is generated at startup and trusted only inside the container that owns the session. When the session ends, the CA is gone.

## Quick start

### 1. Scaffold a devcontainer with a starter policy

```bash
strait preset list
strait preset apply claude-code-devcontainer ./my-agent
```

This writes `.devcontainer/devcontainer.json`, `strait.toml`, and a starter `policy.cedar` into `./my-agent`. Open the directory in your devcontainer tool of choice.

See [`examples/claude-code-devcontainer/README.md`](examples/claude-code-devcontainer/README.md) for the full walkthrough.

### 2. Run the standalone proxy (optional)

Outside a devcontainer, the standalone proxy mode is useful for local integrations and debugging:

```bash
strait proxy --config strait.toml
```

The proxy runs the MITM pipeline, evaluates Cedar policy on every request, injects credentials on allowed requests, and streams observations. This mode depends on the pointing client's trust configuration — it does not share the container-local guarantee above.

### 3. Observe what an agent does

```bash
strait init --observe 5m --config strait.toml --output-dir ./policy-draft
```

Starts the proxy in observation mode for five minutes, then generates `policy.cedar` and `policy.cedarschema` from the recorded traffic. Dynamic path segments (UUIDs, hashes) are collapsed to wildcards automatically.

### 4. Review the policy

```bash
strait explain policy.cedar
```

Human-readable summary of what the policy allows and denies.

### 5. Verify the policy against observations

```bash
strait test --replay observations.jsonl --policy policy.cedar
```

Replays every recorded event against the policy and reports mismatches. Exits non-zero if the policy would have denied something the agent actually did.

### 6. Diff two policies

```bash
strait diff old-policy.cedar new-policy.cedar
```

Semantic diff showing added, removed, and unchanged permissions. Useful during code review.

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

## Docs and examples

- [Devcontainer comparison](docs/devcontainer.md) - where strait fits relative to the devcontainer spec
- [Devcontainer strategy](docs/designs/devcontainer-strategy.md) - architecture rationale for the network-only devcontainer framing
- [In-container rewrite](docs/designs/in-container-rewrite.md) - active migration plan from the host-side launcher to the in-container data plane
- [Claude Code devcontainer dogfood](examples/claude-code-devcontainer/README.md) - the bundled `claude-code-devcontainer` preset

## Policy tooling

```bash
strait preset list                                  # list bundled devcontainer presets
strait preset apply claude-code-devcontainer <dir>  # extract a preset's files into <dir>
strait template list                                # list built-in starter policies
strait template apply github-org-readonly           # apply a template
strait init --observe 5m --config strait.toml       # observe for 5m, generate a policy
strait generate observations.jsonl                  # generate policy from an existing log
strait explain policy.cedar                         # human-readable summary
strait diff old-policy.cedar new-policy.cedar       # semantic permission diff
strait test --replay observations.jsonl --policy policy.cedar  # verify policy
strait proxy --config strait.toml                   # run the standalone HTTPS proxy
```

## Use cases

- **Devcontainer network policy** - replace shell-script firewall rules with Cedar policy for outbound HTTP access
- **CI/CD pipelines** - govern what builds and agents can call over the network, with auditable records
- **Compliance** - immutable audit trail of every API call
- **Credential isolation** - policy-governed API access without sharing secrets

## Known limitations

- **No host-side container orchestration** - `strait launch` has been retired. Run your devcontainer with any devcontainer-compatible tool; the in-container `strait-agent` (landing in the ongoing rewrite) will provide enforcement inside the container.
- **Trust is container-local** - the session CA is only trusted inside the container. Standalone `strait proxy` sessions rely on whatever trust configuration the pointing client has.
- **Devcontainer config stays outside strait** - image build, mounts, users, editor settings, and lifecycle hooks still belong in `devcontainer.json`.
- **Policy scope is network-only** - strait controls outbound HTTP. Filesystem and process rules are out of scope.

## Install

```bash
cargo install strait    # from source
```

### Devcontainer feature

Strait is published as a devcontainer feature at
`ghcr.io/ninthwave-io/strait`. Reference it from your
`.devcontainer/devcontainer.json` to install the in-container agent
without cloning this repository. Multi-arch binaries (`linux/amd64` and
`linux/arm64`) are shipped; the install script picks the right one at
build time based on the container architecture.

```jsonc
{
    "image": "mcr.microsoft.com/devcontainers/base:debian",
    "remoteUser": "vscode",
    "features": {
        "ghcr.io/ninthwave-io/strait:0.1": {
            "agent_user": "vscode",
            "proxy_port": "9443"
        }
    }
}
```

See [`features/strait/README.md`](features/strait/README.md) for the
full option list, the required `CAP_NET_ADMIN` capability, and the
host control-plane socket mount.

## License

Apache-2.0
