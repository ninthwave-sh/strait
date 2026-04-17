/**
 * examples/sandcastle/main.ts
 *
 * Minimal sandcastle example that runs an outbound HTTP request through
 * strait. Companion to docs/bring-your-own-sandbox.md.
 *
 * Prerequisites (see README.md):
 *   - `strait-host serve` is running on the workstation
 *   - STRAIT_HOST_SOCKET points at the host's Unix socket
 *   - `strait-sandbox:latest` image has been built from the sibling
 *     Dockerfile with a strait-agent binary copied into the build context
 *
 * Run:
 *   npm install
 *   npm run start
 */
import { Sandbox } from "sandcastle";

async function main() {
  const hostSocket = process.env.STRAIT_HOST_SOCKET ?? "/var/run/strait/host.sock";
  const image = process.env.STRAIT_SANDBOX_IMAGE ?? "strait-sandbox:latest";

  // Providers: "docker" (primary, tested), "podman" (tested), "vercel"
  // (unverified -- see docs/bring-your-own-sandbox.md).
  const provider = (process.env.STRAIT_SANDBOX_PROVIDER ?? "docker") as
    | "docker"
    | "podman"
    | "vercel";

  const sandbox = await Sandbox.create({
    provider,
    image,
    // CAP_NET_ADMIN is the only capability strait-agent needs. It is held
    // by the entrypoint long enough to install iptables rules, then
    // cleared from the ambient and inheritable sets before exec.
    capabilities: ["NET_ADMIN"],
    // Read-only bind mount: the in-container proxy only needs
    // connect(2) on the socket. Nothing in the container should be able
    // to modify the host-side socket file.
    mounts: [
      {
        type: "bind",
        source: hostSocket,
        target: "/run/strait/host.sock",
        readOnly: true,
      },
    ],
  });

  try {
    // Any command that makes an outbound HTTP request exercises the
    // policy path. strait sees the request, asks the host for a
    // decision, and either forwards or denies it.
    const result = await sandbox.exec([
      "curl",
      "-sS",
      "https://api.github.com/meta",
    ]);

    console.log("exit:", result.exitCode);
    console.log("stdout:", result.stdout);
    if (result.stderr) {
      console.error("stderr:", result.stderr);
    }
  } finally {
    await sandbox.dispose();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
