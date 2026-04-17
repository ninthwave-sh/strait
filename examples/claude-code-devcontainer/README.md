# Claude Code devcontainer dogfood

This example is the phase-1 first-run path. It wires the container trust
boundary, `devcontainer.json`, and a starter Cedar policy into one
repeatable flow.

## What you get

- `.devcontainer/devcontainer.json` drives the container environment.
- `strait.toml` configures MITM hosts and credential injection.
- `policy.cedar` is the starting network policy (GitHub + npm).
- The in-container `strait-agent` proxy (phase 1 of the ongoing rewrite)
  enforces policy inside the container. The host-side `strait launch`
  orchestrator has been retired -- container lifecycle is handled by
  your devcontainer tooling.

No machine-wide CA install happens at any point. The session CA lives
inside the container and is removed when the session ends.

## Prerequisites

- Docker (or Podman / OrbStack)
- The `strait` binary on your PATH (for policy tooling and scaffolding)
- A devcontainer-compatible runner: VS Code Dev Containers, the
  devcontainer CLI, sandcastle, or direct `docker run` using the
  `.devcontainer/devcontainer.json` in this example

## Scaffold it

Apply the preset into a scratch directory so you have an editable copy:

```bash
strait preset apply claude-code-devcontainer ./my-agent
cd my-agent
```

## Run it

Open the extracted directory with your devcontainer tool of choice:

- VS Code: "Dev Containers: Reopen in Container"
- devcontainer CLI: `devcontainer up --workspace-folder .`
- Direct Docker: build from `.devcontainer/devcontainer.json` and
  run the resulting image with `strait.toml` + `policy.cedar`
  available inside the container

Once inside the container, the in-container proxy enforces policy on
every outbound HTTP request. Allowed requests get credentials injected
by the proxy; denied requests return HTTP 403 to the agent.

## Dogfood walkthrough

1. **Trust boundary**: the session CA only lives inside the container
   (`/strait/ca.pem`). The augmented bundle is built at entrypoint
   (`/tmp/strait-ca-bundle.pem`). No host-side CA install.
2. **Blocked request**: run a request that is not allowed by the
   starter policy, for example `curl -fsS https://example.com` from
   inside the container. strait denies the request and records a
   `blocked_request` observation event.
3. **Edit the policy**: add a permit rule for the host in question and
   save `policy.cedar`. The in-container proxy picks up the update.
4. **Restart loop**: rerun the same request -- the new rule applies
   without any manual CA install or host-side orchestration.

Once the host control plane (`strait-host`, landing in phase 2) is
available, blocked requests will surface in the desktop shell as live
decisions, and persisted rules will flow back to the container over
gRPC instead of requiring a file edit.

## Files

| Path | Purpose |
| --- | --- |
| `.devcontainer/devcontainer.json` | Image, user, workspace, env |
| `strait.toml` | MITM hosts, credential injection, audit |
| `policy.cedar` | Starter Cedar policy for outbound HTTP |
