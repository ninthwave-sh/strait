# Claude Code in a strait container

Run Claude Code inside a sandboxed container with API credential injection,
policy enforcement, and audit logging.

## Prerequisites

- Docker (or OrbStack / Podman)
- `ANTHROPIC_API_KEY` and `GITHUB_TOKEN` environment variables
- `strait` binary on your PATH (`cargo install --path .` from the repo root)

## Build the image

```bash
docker build -t claude-code-sandbox examples/claude-code/
```

## 1. Observe mode

Run Claude Code with no policy. All traffic is allowed and recorded.

```bash
strait launch --observe \
  --image claude-code-sandbox \
  --output observations.jsonl \
  --env "ANTHROPIC_API_KEY=" \
  --env "GITHUB_TOKEN=" \
  -- claude --print "list my GitHub repos"
```

The `--env` flags create empty placeholders inside the container. The real
keys stay on the host and are injected by the proxy after policy evaluation.

Review what happened:

```bash
strait watch observations.jsonl
```

## 2. Generate a policy

```bash
strait generate observations.jsonl > policy.cedar
```

Edit the generated policy to match your needs, then inspect it:

```bash
strait explain policy.cedar
```

## 3. Warn mode

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

Check the audit log for any policy violations:

```bash
cat /tmp/strait-audit.jsonl | grep '"decision":"deny"'
```

## 4. Enforce mode

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
