# strait

Policy platform for AI agents. One Cedar policy governs network access, filesystem isolation, and process control. The agent never sees real credentials.

## The problem

Security teams need to answer one question: *what should this agent be allowed to do?* But today's tools split that answer across separate network proxies, filesystem sandboxes, and process monitors — each with its own policy format and its own blind spots.

Strait unifies all three under Cedar. Observe what an agent actually does, auto-generate a policy from that behavior, then enforce it.

## How it works

```
  ┌──────────────────────────────────────────────────────┐
  │           Container (Docker/Podman/OrbStack)          │
  │                                                       │
  │  ┌──────────────┐     ┌─────────────────────┐       │
  │  │ AI Agent     │────▶│ Strait Proxy (MITM) │──▶ API│
  │  │ (your cmd)   │     │ Cedar eval + creds   │       │
  │  │ [full TTY]   │     └─────────────────────┘       │
  │  └──────────────┘                                    │
  │                                                       │
  │  Filesystem from Cedar policy:                       │
  │    fs:read  /project/src  → read-only mount          │
  │    fs:write /project/out  → read-write mount         │
  │    (no policy = not mounted = invisible)             │
  └──────────────────────┬──────────────────────────────┘
                         │ observations
  ┌──────────────────────▼──────────────────────────────┐
  │  Strait Host Process                                 │
  │   • Container lifecycle management                   │
  │   • Observation stream (Unix socket + JSONL)         │
  │   • strait watch — colored live event viewer         │
  │   • strait generate — Cedar policy from observations │
  │   • strait test --replay — policy verification       │
  └─────────────────────────────────────────────────────┘
```

Cedar policies control three domains:

- **Network** — HTTPS MITM proxy with request-level policy (`http:GET`, `http:POST`, `http:DELETE`). Credential injection on allow. The agent never sees real API tokens.
- **Filesystem** — Cedar `fs:read` / `fs:write` rules translate to container bind-mounts. No rule = not mounted = invisible to the agent.
- **Process** — Cedar `proc:exec` rules control which binaries are available in the container.

## Quick start

### Observe what an agent does

```bash
strait launch --observe -- ./my-agent
```

Runs your command in a container, allows everything, records all activity to `observations.jsonl`.

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

Strait also runs as a standalone HTTPS proxy without containers, for cases where you want policy enforcement and credential injection on network traffic only:

```bash
strait proxy --config strait.toml
```

Features in proxy mode: MITM with Cedar policy evaluation, credential injection (bearer + AWS SigV4), structured JSON audit logging, health check endpoint, SIGHUP policy hot-reload, git-hosted policies with automatic polling.

## Policy tooling

```bash
strait template list                              # list built-in starter policies
strait template apply github-org-readonly          # apply a template
strait explain policy.cedar                        # human-readable summary
strait diff old-policy.cedar new-policy.cedar      # semantic permission diff
strait test --replay observations.jsonl --policy policy.cedar  # verify policy
strait watch                                       # live colored event stream
```

## Use cases

- **Agent sandboxing** — run AI agents with least-privilege access to APIs, files, and tools
- **CI/CD pipelines** — govern what builds can fetch and write, with auditable records
- **Compliance** — immutable audit trail of every API call and file access
- **Credential isolation** — policy-governed API access without sharing secrets

## Known limitations

- **Network enforcement is cooperative** — the container routes traffic through the proxy via `HTTPS_PROXY`. A determined agent could bypass this. This is defense-in-depth, not a hard boundary.
- **Filesystem and process enforcement rely on container isolation** — standard container security model.

## Install

```bash
cargo install strait    # from source
```

## License

MIT
