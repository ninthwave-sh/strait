# Strait and devcontainers

Strait is the network policy layer for devcontainers. Keep `devcontainer.json` for image build, tools, mounts, users, and editor settings. Use strait for outbound network policy.

This doc is the public companion to [`docs/designs/devcontainer-strategy.md`](designs/devcontainer-strategy.md). It explains where strait fits relative to the [Development Containers spec](https://containers.dev/) and Claude Code's [reference devcontainer](https://code.claude.com/docs/en/devcontainer).

## Start here: incompatibilities and migration calls

If you are starting from Claude Code's reference devcontainer, make these decisions first:

| `devcontainer.json` field | Strait position | What to do |
| --- | --- | --- |
| `forwardPorts` | Rejected by strait's network model | Remove it. Strait runs containers with `--network=none`, so inbound port forwarding does not fit the model. If the agent needs outbound API access, express that as Cedar policy instead. |
| `runArgs` that add privilege, such as `--privileged`, `--cap-add=NET_ADMIN`, `--cap-add=NET_RAW`, or `--network=host` | Rejected | Remove them. These flags let the container bypass the gateway and proxy path that strait depends on. |
| `privileged: true` / `capAdd` | Rejected | Remove them for the same reason. Strait needs a non-privileged container boundary. |
| `mounts` | Not a strait policy feature | Keep them in `devcontainer.json`. Devcontainer owns filesystem shape; strait does not translate mounts into Cedar rules. |

Once strait is in place, remove `init-firewall.sh` and the `postStartCommand` that calls it. Keeping both works against the point of the migration: the iptables script is less expressive, requires extra container privileges, and duplicates the network policy job that strait is taking over.

## Where strait fits

The two tools answer different questions:

| Question | Tool |
| --- | --- |
| What image, features, mounts, env vars, and editor settings does this project need? | `devcontainer.json` |
| What outbound HTTP requests should this agent be allowed to make? | strait |

That means strait is not a replacement for the devcontainer spec. It is the replacement for the firewall layer that Claude Code currently adds on top of a devcontainer.

## What Claude Code's `init-firewall.sh` actually does

Claude Code's reference container uses a `postStartCommand` that runs `sudo /usr/local/bin/init-firewall.sh`. The current script does four important things:

1. Requires elevated container networking privileges with `--cap-add=NET_ADMIN` and `--cap-add=NET_RAW`.
2. Flushes iptables state, restores Docker DNS rules for `127.0.0.11`, then allows DNS, localhost, SSH, and host-network traffic.
3. Resolves GitHub metadata and a fixed domain allowlist (`registry.npmjs.org`, `api.anthropic.com`, `sentry.io`, `statsig.anthropic.com`, `statsig.com`, Visual Studio Code endpoints), loads those IPs into an ipset, then defaults `INPUT`, `FORWARD`, and `OUTPUT` to `DROP`.
4. Verifies the result by checking that `https://example.com` is blocked while `https://api.github.com` is still reachable.

That setup is a good baseline, but it stays at the firewall layer:

- policy is edited in a shell script
- permissions are domain or IP scoped
- changes usually mean editing the script and restarting the container
- there is no request-level allow/deny decision by method, path, or identity

## Claude Code iptables vs strait

| Concern | Claude Code reference (`init-firewall.sh`) | Strait |
| --- | --- | --- |
| Environment contract | `devcontainer.json` + Dockerfile | `devcontainer.json` stays the environment contract |
| Network rule source | Shell script that writes iptables/ipset rules | `policy.cedar` plus `strait.toml` |
| Permission granularity | Domain and IP allowlist | HTTP method, host, path, and agent identity |
| Privilege model | Needs extra container capabilities to edit firewall state | Keeps the proxy on the host and the container on `--network=none` |
| Change loop | Edit shell script, rebuild or restart container | Observe, generate, review, then reload or relaunch with policy |
| Audit trail | Firewall verification and container logs | Structured audit log and live session surfaces |
| Recommendation | Good status quo for a simple allowlist | Prefer strait when you need request-level network policy. Remove `init-firewall.sh` once strait is in place. |

## Real config shapes

The examples below use real shapes from the Claude Code reference devcontainer and the current `examples/claude-code/` strait example. They are trimmed for relevance, but they are not placeholders.

Read them side by side like this:

| Claude Code reference | Strait equivalent |
| --- | --- |
| `postStartCommand: "sudo /usr/local/bin/init-firewall.sh"` | `strait launch --policy ... --config ...` with Cedar rules for outbound requests |
| `runArgs: ["--cap-add=NET_ADMIN", "--cap-add=NET_RAW"]` | No privileged networking flags |
| `mounts`, `workspaceMount`, `workspaceFolder`, `remoteUser`, `containerEnv` | Stay in `devcontainer.json` |
| Domain/IP allowlist in shell | Request-level allowlist in Cedar |

### Claude Code reference `devcontainer.json`

This is the shape Claude Code uses today to install the firewall and keep the workspace mounted in the container:

```json
{
  "name": "Claude Code Sandbox",
  "build": {
    "dockerfile": "Dockerfile",
    "args": {
      "TZ": "${localEnv:TZ:America/Los_Angeles}",
      "CLAUDE_CODE_VERSION": "latest",
      "GIT_DELTA_VERSION": "0.18.2",
      "ZSH_IN_DOCKER_VERSION": "1.2.0"
    }
  },
  "runArgs": [
    "--cap-add=NET_ADMIN",
    "--cap-add=NET_RAW"
  ],
  "remoteUser": "node",
  "mounts": [
    "source=claude-code-bashhistory-${devcontainerId},target=/commandhistory,type=volume",
    "source=claude-code-config-${devcontainerId},target=/home/node/.claude,type=volume"
  ],
  "containerEnv": {
    "NODE_OPTIONS": "--max-old-space-size=4096",
    "CLAUDE_CONFIG_DIR": "/home/node/.claude",
    "POWERLEVEL9K_DISABLE_GITSTATUS": "true"
  },
  "workspaceMount": "source=${localWorkspaceFolder},target=/workspace,type=bind,consistency=delegated",
  "workspaceFolder": "/workspace",
  "postStartCommand": "sudo /usr/local/bin/init-firewall.sh",
  "waitFor": "postStartCommand"
}
```

### Equivalent strait config

With strait, the environment still belongs in `devcontainer.json`, but the network configuration moves out of `init-firewall.sh`. The closest working example in this repo is `examples/claude-code/strait.toml`:

```toml
ca_cert_path = "/tmp/strait-ca.pem"

[mitm]
hosts = [
    "api.github.com",
    "registry.npmjs.org",
]

[[credential]]
host = "api.github.com"
header = "Authorization"
value_prefix = "token "
source = "env"
env_var = "GITHUB_TOKEN"

[[credential]]
host = "registry.npmjs.org"
header = "Authorization"
value_prefix = "Bearer "
source = "env"
env_var = "NPM_TOKEN"

[container]
base_image = "ubuntu:24.04"
apt = ["git", "curl", "ca-certificates"]
npm = ["@anthropic-ai/claude-code"]

[identity]
header = "X-Strait-Agent"
default = "claude-code"

[audit]
log_path = "/tmp/strait-audit.jsonl"
```

And the network allowlist itself moves into Cedar policy:

```cedar
@id("allow-github-api")
permit(
    principal == Agent::"claude-code",
    action in [Action::"http:GET", Action::"http:POST", Action::"http:PATCH"],
    resource in Resource::"api.github.com"
);

@id("allow-npm-registry")
permit(
    principal == Agent::"claude-code",
    action == Action::"http:GET",
    resource in Resource::"registry.npmjs.org"
);

@id("deny-repo-delete")
@reason("Repository deletion is too destructive for agent access")
forbid(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos"
);
```

The important difference is not the file format. It is the control surface:

- Claude Code's reference puts network policy in `init-firewall.sh`
- strait puts network policy in Cedar, keeps credentials out of the agent environment, and publishes audit data for every decision

## Migration checklist

If you already have a Claude Code style devcontainer, the intended migration is:

1. Keep your devcontainer image, `remoteUser`, mounts, and editor settings.
2. Delete `postStartCommand: "sudo /usr/local/bin/init-firewall.sh"`.
3. Delete privileged networking `runArgs`.
4. Add `strait.toml` and `policy.cedar`.
5. Launch the agent through strait.

Today, the closest repo example is [`examples/claude-code/README.md`](../examples/claude-code/README.md). The planned `--devcontainer` reader is described in [`docs/designs/devcontainer-strategy.md`](designs/devcontainer-strategy.md).

## Recommendation

Use devcontainers for the environment. Use strait for network policy. Once strait is in place, remove `init-firewall.sh`.
