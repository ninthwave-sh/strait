# Bring your own sandbox

The [devcontainer feature](../features/strait/README.md) is the shortest path
into strait, but `strait-agent` is a plain Linux binary and the contract with
`strait-host` is a Unix socket. That means you can wire strait into any
sandbox that can:

1. Copy a binary into an image.
2. Run that binary as the container entrypoint, as root, with `CAP_NET_ADMIN`.
3. Bind-mount a host Unix socket to a known path inside the container.

If your orchestrator or CI runner clears those three bars, strait fits. This
guide walks through the steps for a hand-rolled Dockerfile, then shows the
same pattern through [sandcastle](https://github.com/vercel-labs/sandcastle)'s
Docker provider. Podman and a sandcastle-driven Vercel Sandbox attempt are
covered at the end.

See also: [`docs/designs/devcontainer-strategy.md`](designs/devcontainer-strategy.md)
for the architecture, and
[`docs/designs/in-container-rewrite.md`](designs/in-container-rewrite.md)
Phase 3 for the install-surface plan this doc lives under.

## What you are wiring up

The in-container side of a strait session is:

- `strait-agent entrypoint -- <your cmd>` runs as root at container start.
- It verifies `CAP_NET_ADMIN`, spawns the MITM proxy, installs iptables
  `OUTPUT REDIRECT` rules for ports 80 and 443 so all outbound TCP from the
  configured agent user lands on the proxy, then `setuid`s to the agent user
  and `exec`s your command.
- The proxy keeps a long-lived gRPC channel to the host over
  `/run/strait/host.sock` (or wherever you mount it). Every policy decision
  rides that channel.

On the host side, `strait-host serve` has to be running and listening on the
Unix socket before the container starts. This guide does not cover installing
the host -- see [M-INST-4 host install paths](designs/in-container-rewrite.md#phase-3-install-surface)
when that work lands; for now run `strait-host serve` from a terminal or a
user-level systemd/launchd service on the developer workstation.

## Prerequisites

- **Host.** `strait-host serve` is running and its Unix socket path (default
  `/var/run/strait/host.sock`) is known. Export it so examples can pick it up:

  ```sh
  export STRAIT_HOST_SOCKET=/var/run/strait/host.sock
  ```

- **strait-agent binary for your target arch.** Either:
  - Pull from the published image `ghcr.io/ninthwave-io/strait` (see
    [H-INST-2](designs/in-container-rewrite.md#phase-3-install-surface)), or
  - Build locally: `cargo build --release -p strait-agent`, which drops
    `target/release/strait-agent` on your workstation. Use `cross` or a
    matching `--target` if the container arch differs from the host arch.

- **Sandbox runtime.** Docker, Podman, or a sandbox orchestrator that
  supports adding Linux capabilities at container start. See
  [Sandbox support matrix](#sandbox-support-matrix) below.

## Hand-rolled Dockerfile

The minimum viable image is an agent user, the `strait-agent` binary, a
thin entrypoint wrapper, and the `iptables` package.

### 1. `Dockerfile`

Copy `strait-agent` in from a build context. The build script in
[`examples/sandcastle/Dockerfile`](../examples/sandcastle/Dockerfile) shows
the same shape wrapped for sandcastle; the snippet below is the no-frills
version:

```dockerfile
FROM debian:bookworm-slim

# Agent runs as this non-root user. strait-agent enforces that the agent
# user is not uid 0 before exec'ing the command.
ARG AGENT_USER=agent
RUN useradd --create-home --shell /bin/bash "${AGENT_USER}"

# iptables is the interception mechanism. strait-agent shells out to it
# at entrypoint time; the image must have it installed.
RUN apt-get update \
 && apt-get install -y --no-install-recommends iptables ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# Copy strait-agent from the build context. Pre-build with
# `cargo build --release -p strait-agent` (or a cross-compiled build
# targeting the container arch) and place the binary next to this
# Dockerfile as `strait-agent`.
COPY strait-agent /usr/local/bin/strait-agent
RUN chmod 0755 /usr/local/bin/strait-agent

# Tell strait-agent which user to drop to and where the host socket
# lives. These override any config file; they are the only settings the
# agent needs to run.
ENV STRAIT_AGENT_AGENT_USER=${AGENT_USER} \
    STRAIT_AGENT_HOST_SOCKET=/run/strait/host.sock \
    STRAIT_AGENT_PROXY_PORT=9443

# Entrypoint wrapper. strait-agent does the privilege drop; this script
# exists only so the image's default CMD can stay as a normal shell.
COPY entrypoint.sh /usr/local/bin/strait-entrypoint
RUN chmod 0755 /usr/local/bin/strait-entrypoint

ENTRYPOINT ["/usr/local/bin/strait-entrypoint"]
CMD ["/bin/bash"]
```

### 2. `entrypoint.sh`

The wrapper is a three-line shim that hands control to `strait-agent`:

```sh
#!/bin/sh
set -e

# If the container was started with no command (plain `docker run
# -it <image>`), fall back to a login shell so the operator still has
# somewhere to type.
if [ "$#" -eq 0 ]; then
    set -- /bin/bash -l
fi

exec /usr/local/bin/strait-agent entrypoint -- "$@"
```

Mark it executable in the build context (`chmod +x entrypoint.sh`). The
wrapper does **not** run `setuid` itself -- `strait-agent entrypoint` handles
that after it installs the iptables rules.

### 3. Run it

Build the image, then run it with `--cap-add=NET_ADMIN`, a bind mount to the
host socket, and whatever agent command you want to sandbox:

```sh
docker build -t strait-sandbox .

docker run --rm -it \
  --cap-add=NET_ADMIN \
  -v "${STRAIT_HOST_SOCKET}:/run/strait/host.sock:ro" \
  strait-sandbox \
  curl -sS https://api.github.com/meta
```

Quick verification:

- `strait-host` logs a `register_container` entry for the new session id.
- `curl` either completes (if policy allows `api.github.com`) or is denied
  by the proxy (HTTP 403 from strait with a reason header). Either way, the
  decision went through strait.
- Setting `HTTPS_PROXY=` or `unset HTTPS_PROXY` inside the container does
  not change the outcome: iptables is redirecting the traffic, not a proxy
  environment variable.

### Common snags

- `strait-agent entrypoint must start as root`: you passed `--user` on the
  `docker run` line. Remove it; strait-agent drops to `${AGENT_USER}` itself.
- `CAP_NET_ADMIN is not in the effective capability set`: `--cap-add=NET_ADMIN`
  was missing, or the runtime silently dropped it. Some sandboxes require
  both `--cap-add=NET_ADMIN` *and* a non-default `--security-opt` to keep the
  capability; see the matrix below.
- Host socket errors (`Connection refused`, `No such file`): `strait-host
  serve` is not running, the path on the host does not exist, or the bind
  mount path inside the container does not match `STRAIT_AGENT_HOST_SOCKET`.

## Sandcastle

[Sandcastle](https://github.com/vercel-labs/sandcastle) is a TypeScript
library that normalizes sandbox providers (Docker, Podman, Vercel Sandbox)
behind a single API. The strait contract -- `CAP_NET_ADMIN`, a bind mount,
and the image shown above -- plugs directly into sandcastle's Docker
provider.

The runnable version lives under [`examples/sandcastle/`](../examples/sandcastle/).
The shape is:

```ts
import { Sandbox } from "sandcastle";

const host = process.env.STRAIT_HOST_SOCKET ?? "/var/run/strait/host.sock";

const sandbox = await Sandbox.create({
  provider: "docker",
  image: "strait-sandbox:latest",
  capabilities: ["NET_ADMIN"],
  mounts: [
    {
      type: "bind",
      source: host,
      target: "/run/strait/host.sock",
      readOnly: true,
    },
  ],
});

const result = await sandbox.exec([
  "curl",
  "-sS",
  "https://api.github.com/meta",
]);

console.log(result.stdout);
await sandbox.dispose();
```

Points to notice:

- The `image` is the one built in [`examples/sandcastle/Dockerfile`](../examples/sandcastle/Dockerfile).
  It is the hand-rolled image above, trimmed to Node tooling.
- `capabilities: ["NET_ADMIN"]` is sandcastle's spelling of
  `--cap-add=NET_ADMIN`. Equivalent to passing `--cap-add=NET_ADMIN` to
  `docker run`; sandcastle's Podman provider maps it the same way.
- The bind-mount is read-only on purpose. The in-container proxy only needs
  `connect(2)` access; nothing in the container should be able to modify
  the host socket file.
- The command is whatever you want the agent to execute. strait sees every
  outbound HTTP request it makes.

### Running the example

From the repo root, with `strait-host serve` already running:

```sh
cargo build --release -p strait-agent
cp target/release/strait-agent examples/sandcastle/strait-agent
docker build -t strait-sandbox examples/sandcastle/

cd examples/sandcastle/
npm install
npm run start
```

Expected output: a JSON blob from `api.github.com/meta` (or a strait deny
message, depending on your policy), plus a `register_container` log line
from `strait-host`.

## Sandbox support matrix

| Sandbox          | CAP_NET_ADMIN at entrypoint? | Tested status                         |
| ---------------- | ---------------------------- | ------------------------------------- |
| Docker           | Yes (`--cap-add=NET_ADMIN`)  | Works. Primary supported path.        |
| Podman           | Yes (`--cap-add=NET_ADMIN`)  | Works. Rootless Podman needs the `netavark` plugin and an entry for `NET_ADMIN` under `containers.conf` `capabilities` default. Rootful Podman works unchanged. |
| OrbStack         | Yes (Docker API compatible)  | Works. Same flags as Docker.          |
| Docker Desktop   | Yes                          | Works. macOS hosts use the bundled LinuxKit VM, so iptables REDIRECT applies inside the VM as normal. |
| Vercel Sandbox   | Unknown                      | **Unverified** as of 2026-04-17 -- see below. |

If your sandbox cannot grant `CAP_NET_ADMIN` at startup, strait does not
fit. That is an explicit tradeoff of the transparency-first model -- see
[`docs/designs/devcontainer-strategy.md`](designs/devcontainer-strategy.md)
("Not privileged on the host"). Connection-level (SNI-only) enforcement is
rejected; request-level granularity is the product.

### Vercel Sandbox status

Vercel Sandbox is sandcastle's remote-execution provider. As of 2026-04-17
it is **not verified** with strait. The open question is whether the
provider honors `capabilities: ["NET_ADMIN"]` or silently drops it the way
hosted FaaS runtimes typically do.

The smoke test is identical to the Docker one in [`examples/sandcastle/`](../examples/sandcastle/);
switch `provider: "docker"` to `provider: "vercel"` and re-run. Three
outcomes are possible:

1. **`CAP_NET_ADMIN is not in the effective capability set`** from
   `strait-agent`. The provider accepted the capability field but the
   platform stripped it. strait does not fit; use a Docker or Podman
   sandbox instead.
2. **Image pull or upload failure.** Vercel Sandbox cannot reach the image.
   Push the image to a registry the provider can pull from, or follow the
   provider's documented upload flow.
3. **Success.** Log `register_container` on the host, move this row to
   "Works" in the matrix, and we are done.

Until someone records the result, treat Vercel Sandbox as unsupported. Open
a friction log entry under `.ninthwave/friction/` if you hit (1) with a
specific error message; that pins down the platform story for the install
surface work that follows.

## Troubleshooting summary

| Symptom                                           | Likely cause                                        | Fix                                                             |
| ------------------------------------------------- | --------------------------------------------------- | --------------------------------------------------------------- |
| `entrypoint must start as root`                   | Container started with `--user` or `USER` in image  | Let strait drop privileges; remove the `--user` override        |
| `CAP_NET_ADMIN is not in the effective capability set` | Capability not granted or silently dropped    | Add `--cap-add=NET_ADMIN`; check sandbox-specific docs          |
| `failed to install iptables redirect rules`       | `iptables` missing in the image                     | Install it in the Dockerfile (`apt-get install iptables`)       |
| `configured agent_user ... does not exist`        | The user named in `STRAIT_AGENT_AGENT_USER` is not in `/etc/passwd` | `useradd` it in the Dockerfile, or use an existing user         |
| `connect(/run/strait/host.sock): No such file`    | Host socket not mounted or `strait-host` not running | `strait-host serve` on host; verify bind-mount paths match       |
| Requests succeed but no decisions in `strait-host` | Container bypassed the proxy (iptables not applied) | Confirm entrypoint is `strait-agent entrypoint --`, not the raw agent command |
