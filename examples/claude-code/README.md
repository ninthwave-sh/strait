# Claude Code in a strait container

Run Claude Code inside a sandboxed container with policy enforcement,
credential injection, and audit logging.

If you are starting from Claude Code's reference devcontainer, read
[`docs/devcontainer.md`](../../docs/devcontainer.md) first. It explains how
the reference `init-firewall.sh` setup maps onto strait and why you should
remove that firewall script once strait is in place.

Two auth models are supported:

1. **Max subscription (OAuth)** -- primary path. Anthropic traffic passes
   through as a tunnel. OAuth tokens from `~/.claude/` are mounted into
   the container.
2. **API key** -- secondary path. Anthropic traffic is MITM'd and the
   `x-api-key` header is injected by the proxy.

In both cases, GitHub and npm credentials are injected by the proxy and
never exposed to the agent.

## Devcontainer feature (recommended)

The `.devcontainer/devcontainer.json` in this directory uses the strait
devcontainer feature (`ghcr.io/ninthwave-io/strait`). This is the
simplest path: add the feature to your devcontainer.json, set two host
environment variables, and the container connects to your host-side
strait proxy automatically.

### Quick start

1. Start strait on the host:

   ```bash
   strait service start
   strait launch --observe --output /tmp/observations.jsonl -- sleep infinity
   ```

2. Set the host environment variables to point at the running session:

   ```bash
   export STRAIT_PROXY_SOCKET=/path/to/session/proxy.sock
   export STRAIT_CA_PEM=/path/to/session/ca.pem
   ```

3. Open this directory in VS Code or any devcontainer-compatible tool.
   The feature installs the gateway, configures CA trust, and routes
   all outbound traffic through the host proxy.

The proxy runs on the host. The container has no direct network access
to the proxy credentials. The gateway binary inside the container
forwards TCP connections over a bind-mounted Unix socket to the host
proxy.

## Prerequisites

- Docker (or OrbStack / Podman)
- `GITHUB_TOKEN` environment variable
- `strait` binary on your PATH (`cargo install --path .` from the repo root)
- Claude Code Max subscription (or `ANTHROPIC_API_KEY` for API key auth)

## How it works

The example has two files:

| File | Purpose |
|------|---------|
| `strait.toml` | Config: MITM hosts, credential sources, container spec, audit |
| `policy.cedar` | Cedar policy: HTTP access, filesystem mounts, binary execution |

The `[container]` section in `strait.toml` tells strait to auto-build a
Docker image with the right packages installed:

```toml
[container]
base_image = "ubuntu:24.04"
apt = ["git", "curl", "ca-certificates"]
npm = ["@anthropic-ai/claude-code"]
```

strait generates a Dockerfile, builds the image, and caches it by content
hash. No manual `docker build` step needed.

The `proc:exec` rules in `policy.cedar` tell strait which host binaries
to bind-mount into the container:

```cedar
@id("allow-exec-claude")
permit(
    principal == Agent::"claude-code",
    action == Action::"proc:exec",
    resource == Resource::"proc::claude"
);
```

When strait sees this rule, it finds `claude` on your host PATH, resolves
its absolute path, and bind-mounts it read-only into the container at
`/usr/local/bin/claude`. Same for `git` and `node`.

## Quick start (Max subscription)

Mount your Claude credentials into the container. Anthropic traffic passes
through without MITM -- the proxy only intercepts GitHub and npm traffic
for credential injection.

```bash
strait launch --policy examples/claude-code/policy.cedar \
  --config examples/claude-code/strait.toml \
  --mount ~/.claude/:/root/.claude/:rw \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

The `--mount` flag makes your OAuth tokens available inside the container.
The `--env` flag creates an empty placeholder -- the real token is injected
by the proxy after policy evaluation.

## Quick start (API key)

If you have an Anthropic API key instead of a Max subscription, add
Anthropic to the MITM hosts and credential injection config.

Add to `strait.toml`:

```toml
[mitm]
hosts = [
    "api.anthropic.com",
    "api.github.com",
    "registry.npmjs.org",
]

# Add this credential block:
[[credential]]
host = "api.anthropic.com"
header = "x-api-key"
source = "env"
env_var = "ANTHROPIC_API_KEY"
```

Add to `policy.cedar`:

```cedar
@id("allow-anthropic-api")
permit(
    principal == Agent::"claude-code",
    action in [Action::"http:GET", Action::"http:POST"],
    resource in Resource::"api.anthropic.com"
);
```

Then launch without the `--mount` flag:

```bash
strait launch --policy examples/claude-code/policy.cedar \
  --config examples/claude-code/strait.toml \
  --env "ANTHROPIC_API_KEY=" \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

## Observe-then-enforce workflow

If you prefer to discover what Claude Code needs before writing a policy,
use the observe/generate/warn/enforce workflow.

### 1. Observe

Run with no policy. All traffic is allowed and recorded.

```bash
strait launch --observe \
  --output observations.jsonl \
  --mount ~/.claude/:/root/.claude/:rw \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

Review what happened:

```bash
strait watch observations.jsonl
```

### 2. Generate a policy

```bash
strait generate observations.jsonl > policy.cedar
```

Edit the generated policy to match your needs. Add `proc:exec` rules for
any host binaries the agent should have access to:

```cedar
@id("allow-exec-git")
permit(
    principal == Agent::"claude-code",
    action == Action::"proc:exec",
    resource == Resource::"proc::git"
);
```

Inspect the full policy:

```bash
strait explain policy.cedar
```

### 3. Warn

Evaluate the policy but allow all traffic. Violations are logged as warnings.

```bash
strait launch --warn policy.cedar \
  --config examples/claude-code/strait.toml \
  --output observations.jsonl \
  --mount ~/.claude/:/root/.claude/:rw \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

Check for violations:

```bash
cat /tmp/strait-audit.jsonl | grep '"decision":"deny"'
```

### 4. Enforce

Deny requests that violate the policy. Credentials are injected only on
allowed requests.

```bash
strait launch --policy policy.cedar \
  --config examples/claude-code/strait.toml \
  --output observations.jsonl \
  --mount ~/.claude/:/root/.claude/:rw \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

Blocked requests return HTTP 403 to the agent. The audit log at
`/tmp/strait-audit.jsonl` records every decision.

## MITM hosts

The `strait.toml` config intercepts these endpoints:

| Host | Purpose |
|------|---------|
| `api.github.com` | Repo operations, PRs, issues |
| `registry.npmjs.org` | npm package metadata |

Traffic to hosts not in this list -- including `api.anthropic.com`,
`statsig.anthropic.com`, and `sentry.io` -- passes through as a plain
CONNECT tunnel (no TLS termination, no policy evaluation). This is the
right default for Max/OAuth users: Anthropic traffic carries its own
OAuth token and does not need credential injection.

## What is isolated

- **GitHub token**: injected by the proxy on allowed requests only.
  The agent inside the container has an empty `GITHUB_TOKEN` placeholder.
- **npm token**: same injection model for private package access.
- **Anthropic credentials**: for Max users, OAuth tokens live in the
  mounted `~/.claude/` directory. The proxy does not touch Anthropic
  traffic. For API key users, the proxy injects `x-api-key` and the
  agent never sees the real key.
- **Filesystem**: only the project directory is mounted (per Cedar policy).
- **Network**: all traffic routes through the proxy for audit logging.
