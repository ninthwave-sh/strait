# Claude Code in a strait container

Run Claude Code inside a sandboxed container with policy enforcement,
credential injection, and audit logging. No custom Docker build needed.

strait reads `proc:exec` rules from your Cedar policy and automatically
mounts host binaries (`claude`, `git`, `node`) into the container. You
write a policy, point strait at a base image, and go.

## Prerequisites

- Docker (or OrbStack / Podman)
- `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` environment variables
- `strait` binary on your PATH (`cargo install --path .` from the repo root)
- `claude` CLI installed on the host (`npm install -g @anthropic-ai/claude-code`)
- `git` and `node` on the host PATH

## How it works

The example has three files:

| File | Purpose |
|------|---------|
| `strait.toml` | Config: MITM hosts, credential sources, audit settings |
| `policy.cedar` | Cedar policy: HTTP access, filesystem mounts, binary execution |
| `Dockerfile` | Minimal base image (`ubuntu:24.04` + `ca-certificates`) |

The key insight is `proc:exec` rules in `policy.cedar`:

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
`/usr/local/bin/claude`. Same for `git` and `node`. No Dockerfile changes
needed when you add a new tool. Just add a `proc:exec` rule.

## Quick start

Build the minimal base image (one-time):

```bash
docker build -t claude-code-sandbox examples/claude-code/
```

Then run Claude Code through strait:

```bash
strait launch --policy examples/claude-code/policy.cedar \
  --config examples/claude-code/strait.toml \
  --image claude-code-sandbox \
  --env "ANTHROPIC_API_KEY=" \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

The `--env` flags create empty placeholders inside the container. The real
keys stay on the host and are injected by the proxy after policy evaluation.

## Observe-then-enforce workflow

If you prefer to discover what Claude Code needs before writing a policy,
use the observe/generate/warn/enforce workflow.

### 1. Observe

Run with no policy. All traffic is allowed and recorded.

```bash
strait launch --observe \
  --image claude-code-sandbox \
  --output observations.jsonl \
  --env "ANTHROPIC_API_KEY=" \
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
  --image claude-code-sandbox \
  --output observations.jsonl \
  --env "ANTHROPIC_API_KEY=" \
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
  --image claude-code-sandbox \
  --output observations.jsonl \
  --env "ANTHROPIC_API_KEY=" \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

Blocked requests return HTTP 403 to the agent. The audit log at
`/tmp/strait-audit.jsonl` records every decision.

## MITM hosts

The `strait.toml` config intercepts these endpoints:

| Host | Purpose |
|------|---------|
| `api.anthropic.com` | Chat completions, tool use |
| `api.github.com` | Repo operations, PRs, issues |
| `statsig.anthropic.com` | Feature flags, usage telemetry |
| `sentry.io` | Error reporting |
| `registry.npmjs.org` | npm package metadata |

Traffic to hosts not in this list passes through as a plain CONNECT tunnel
(no TLS termination, no policy evaluation, no credential injection).

If Claude Code hits additional endpoints during your usage, add them to
`[mitm] hosts` in `strait.toml` and add corresponding `permit` rules in
your Cedar policy. Run in observe mode first to discover what is needed.
