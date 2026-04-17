# strait devcontainer feature

Routes all outbound TCP inside a devcontainer through a Cedar-policy-gated
MITM proxy. No `HTTPS_PROXY` dependency: `iptables` REDIRECT rewrites
ports 80 and 443 from the agent user to the in-container proxy.

## Reference the feature by id

The feature is published as an OCI artifact at
`ghcr.io/ninthwave-io/strait` on every `v*` tag (see
[`.github/workflows/release-feature.yml`](../../.github/workflows/release-feature.yml)).
Consumers pin a version and reference it from their `devcontainer.json`
without cloning this repository:

```jsonc
{
    "image": "mcr.microsoft.com/devcontainers/base:debian",
    "remoteUser": "vscode",
    "features": {
        "ghcr.io/ninthwave-io/strait:0.1": {
            "agent_user": "vscode",
            "proxy_port": "9443",
            "host": "/run/strait/host.sock",
            "policy": "/workspaces/my-repo/.strait/policy.cedar"
        }
    }
}
```

Both `linux/amd64` and `linux/arm64` are shipped; the install script
picks the matching binary via `uname -m` inside the builder container,
so Apple Silicon hosts automatically get the arm64 artifact.

### Using the in-repo sources

For local development on the feature itself, the same options work
against the in-repo path. `install.sh` falls back to a sibling
`strait-agent` binary when no per-arch binary is present.

```jsonc
{
    "image": "mcr.microsoft.com/devcontainers/base:debian",
    "remoteUser": "vscode",
    "features": {
        "./features/strait": {
            "agent_user": "vscode",
            "proxy_port": "9443",
            "host": "/run/strait/host.sock",
            "policy": "/workspaces/my-repo/.strait/policy.cedar"
        }
    }
}
```

When the container starts, the feature's entrypoint wraps the user's
start command with `strait-agent entrypoint`, which:

1. Verifies `CAP_NET_ADMIN` is effective.
2. Spawns the in-container MITM proxy as root on `proxy_port`.
3. Installs iptables OUTPUT REDIRECT rules for ports 80 and 443 from the
   configured `agent_user` to `proxy_port`.
4. Drops privileges to `agent_user` and execs the user's command.

The proxy keeps running as root; `agent_user` has no permission to kill
it or rewrite the iptables rules.

## Options

| Option        | Default                   | Description                                                               |
| ------------- | ------------------------- | ------------------------------------------------------------------------- |
| `host`        | `/run/strait/host.sock`   | In-container path where the host control plane Unix socket is mounted.    |
| `agent_user`  | `vscode`                  | Unix user the entrypoint drops privileges to before exec'ing the command. |
| `policy`      | `/etc/strait/policy.cedar`| Cedar policy file path inside the container.                              |
| `proxy_port`  | `9443`                    | TCP port the in-container proxy listens on (iptables REDIRECT target).    |

Options become environment variables the install script reads at build
time, then get baked into `/etc/strait/strait-agent.toml`.

## Requirements

- **Linux container.** The in-container agent is Linux-only.
- **CAP_NET_ADMIN.** The feature declares `capAdd: [NET_ADMIN]`, which
  devcontainer runtimes honor. Non-devcontainer runtimes (for example
  `docker run` invoked by hand) must pass `--cap-add=NET_ADMIN` too.
- **iptables.** Installed by the feature on Debian/Ubuntu/Alpine/RHEL
  base images. Bring-your-own on other distros.
- **An `agent_user`.** Must already exist in the base image. The
  `common-utils` feature installs a `vscode` user by default, so
  `common-utils` is listed in `installsAfter`.

## What this feature does not do

- It does not start the host control plane. The host process
  (`strait-host`) runs on the developer workstation; see
  `docs/designs/in-container-rewrite.md`. The `host` option only tells
  the in-container agent where the host socket is mounted.
- It does not mount the host socket. Users add a mount in their own
  `devcontainer.json` (mounting `${localEnv:STRAIT_HOST_SOCKET}` to the
  `host` path).

## Debugging

- `strait feature: CAP_NET_ADMIN not effective at build time` in build
  logs is normal. The runtime check is authoritative.
- Entrypoint failing with `CAP_NET_ADMIN is not in the effective
  capability set`: your runtime is dropping the capability. Add
  `--cap-add=NET_ADMIN` or enable the feature.
- Entrypoint failing with `agent_user ... does not exist`: the user
  specified in the option is not present in the base image. Either
  change `agent_user`, or add a step that creates the user before this
  feature runs (`installsAfter`).

## See also

- `docs/designs/in-container-rewrite.md` -- architecture of the
  in-container data plane and host control plane.
- `agent/` -- the `strait-agent` crate (entrypoint + proxy).
