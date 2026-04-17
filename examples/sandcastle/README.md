# sandcastle + strait example

Runnable companion to [`docs/bring-your-own-sandbox.md`](../../docs/bring-your-own-sandbox.md).
Uses [sandcastle](https://github.com/vercel-labs/sandcastle) to start a
container with `CAP_NET_ADMIN` and a bind-mounted host socket, so every
outbound request inside the container flows through `strait-host`.

## Files

| File            | Purpose                                                              |
| --------------- | -------------------------------------------------------------------- |
| `Dockerfile`    | Minimal Debian image with `iptables`, `curl`, a non-root agent user, and the `strait-agent` binary. |
| `entrypoint.sh` | Image entrypoint: execs `strait-agent entrypoint -- "$@"`.           |
| `main.ts`       | sandcastle driver: creates the sandbox, runs `curl`, disposes.       |
| `package.json`  | `tsx` + `sandcastle` deps so `npm run start` works.                  |

## Prerequisites

- `strait-host serve` running on your workstation. Note its socket path
  (default `/var/run/strait/host.sock`) and export it:

  ```sh
  export STRAIT_HOST_SOCKET=/var/run/strait/host.sock
  ```

- A Linux build of `strait-agent` matching the container arch. From the
  repo root:

  ```sh
  cargo build --release -p strait-agent
  cp target/release/strait-agent examples/sandcastle/strait-agent
  ```

  On an Apple Silicon host running an `arm64` container, a native `cargo
  build` is enough. If the container is `linux/amd64` and you are on
  macOS, use `cross` or a matching `--target` to cross-compile.

- Node 20+ and a sandbox runtime (Docker Desktop, OrbStack, or Podman).

## Build the image

```sh
cd examples/sandcastle
docker build -t strait-sandbox .
```

`docker build` copies the `strait-agent` binary from the build context
into the image at `/usr/local/bin/strait-agent`.

## Run the example

Still from `examples/sandcastle/`:

```sh
npm install
npm run start
```

`main.ts` asks sandcastle for a Docker sandbox with `CAP_NET_ADMIN`, binds
`$STRAIT_HOST_SOCKET` to `/run/strait/host.sock` read-only, and execs
`curl -sS https://api.github.com/meta` inside the container.

Expected signals:

- `strait-host` logs a `register_container` entry for the new session.
- Every outbound request from the container shows up as an observation or
  a decision on the host (depending on your rules).
- If your policy allows `api.github.com`, `curl` prints a JSON meta
  response. If not, strait returns a deny response and `curl` surfaces a
  non-2xx status.

## Alternate providers

sandcastle supports multiple providers behind one API. Override
`STRAIT_SANDBOX_PROVIDER` to try each:

```sh
STRAIT_SANDBOX_PROVIDER=podman npm run start
STRAIT_SANDBOX_PROVIDER=vercel npm run start
```

- **Docker / OrbStack / Docker Desktop.** Works. Primary supported path.
- **Podman.** Works. Rootless Podman needs `NET_ADMIN` in the default
  capabilities list under `containers.conf`; rootful Podman needs no
  config changes. See the matrix in
  [`docs/bring-your-own-sandbox.md`](../../docs/bring-your-own-sandbox.md#sandbox-support-matrix).
- **Vercel Sandbox.** Unverified as of 2026-04-17. Run the example with
  `STRAIT_SANDBOX_PROVIDER=vercel` and record the result in
  `.ninthwave/friction/` (with the exact error if any) so the support
  matrix can be updated.

## Troubleshooting

See the troubleshooting table in
[`docs/bring-your-own-sandbox.md`](../../docs/bring-your-own-sandbox.md#troubleshooting-summary).
The short version:

- `entrypoint must start as root` -> remove `--user` overrides; strait
  drops privileges itself.
- `CAP_NET_ADMIN is not in the effective capability set` -> the provider
  stripped the capability; see the support matrix.
- `connect(/run/strait/host.sock)` errors -> `strait-host` is not
  running, or `STRAIT_HOST_SOCKET` does not point at the host socket.
