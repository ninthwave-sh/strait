# Claude Code devcontainer dogfood

This example is the phase-1 first-run path. It wires the container trust
boundary, devcontainer.json, the strait control plane, and the desktop
shell into one repeatable flow.

## What you get

- `.devcontainer/devcontainer.json` drives the container environment.
- `strait.toml` configures MITM hosts and credential injection.
- `policy.cedar` is the starting network policy (GitHub + npm).
- `strait launch --devcontainer` launches the container, injects the
  session CA, and holds blocked requests for a live decision.

No machine-wide CA install happens at any point. The session CA lives
inside the container and is removed when the session ends.

## Prerequisites

- Docker (or Podman / OrbStack)
- The `strait` binary on your PATH
- The control service running so the desktop shell can attach
  (`strait service start --socket /tmp/strait-control.sock`)
- The desktop shell connected (`cd desktop && npm run shell`)

## Run it

From the example directory:

```bash
strait launch \
  --devcontainer .devcontainer/devcontainer.json \
  --config strait.toml \
  --policy policy.cedar \
  -- curl -fsS https://api.github.com/zen
```

Or apply this preset into a scratch directory and launch from there:

```bash
strait preset apply claude-code-devcontainer ./my-agent
cd my-agent
strait launch \
  --devcontainer .devcontainer/devcontainer.json \
  --config strait.toml \
  --policy policy.cedar \
  -- curl -fsS https://api.github.com/zen
```

## Dogfood walkthrough

1. **Trust boundary**: `strait launch` prints the trust boundary
   diagnostic at startup. The session CA only lives inside the
   container (`/strait/ca.pem`), the augmented bundle is built at
   entrypoint (`/tmp/strait-ca-bundle.pem`), and traffic exits through
   the gateway on `--network=none`.
2. **Blocked request**: run a request that is not allowed by the
   starter policy, for example `curl -fsS https://example.com` from
   inside the container. strait holds the request and emits a
   `blocked_request` observation event.
3. **Live decision**: in the desktop shell, pick the batch for
   `example.com` and click "Persist". The control plane calls
   `session persist-decision`, which writes a new permit rule into
   `policy.cedar` atomically and hot-reloads the session.
4. **Restart loop**: stop the session (`strait session stop`) and
   launch it again with the same policy file. Repeat the same
   `curl` -- the persisted rule applies immediately without any
   manual policy edits.

## Files

| Path | Purpose |
| --- | --- |
| `.devcontainer/devcontainer.json` | Image, user, workspace, env |
| `strait.toml` | MITM hosts, credential injection, audit |
| `policy.cedar` | Starter Cedar policy for outbound HTTP |
