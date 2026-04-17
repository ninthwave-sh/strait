# Getting started

This is the first-run walkthrough for strait. It mirrors the tour the
desktop shell shows on a fresh install. The goal is one coherent path:
add the devcontainer feature to an existing project, open it, answer
the first few prompts, and leave with a persisted Cedar rule.

## What you need

- The `strait` and `strait-host` binaries installed on the workstation
  that runs your devcontainers. See the install paths in the main
  [`README.md`](../README.md) (`brew install ninthwave-io/tap/strait`
  on macOS, the tarball installer on Linux).
- A project that already uses devcontainers -- any devcontainer-
  compatible runner will do (VS Code Dev Containers, the devcontainer
  CLI, sandcastle, plain `docker run` against the devcontainer
  definition).
- Docker Desktop, OrbStack, Podman, or another runtime that can grant
  `CAP_NET_ADMIN` at container start. The
  [bring-your-own-sandbox guide](bring-your-own-sandbox.md#sandbox-support-matrix)
  has the matrix.

## 1. Start the host control plane

The host control plane (`strait-host`) is a long-lived process on your
workstation. Nothing in the desktop or in your containers works until
it is running.

On macOS, after `brew install`:

```sh
brew services start strait
```

On Linux, after the tarball install:

```sh
systemctl --user start strait-host.service
```

Either path brings up the Unix socket the devcontainer feature will
mount into your container (`/var/run/strait/host.sock` by default).

Open the desktop shell at this point. If the host is up, the status
strip shows **Connected**. If it is not, the shell's first-run tour
opens on the **Start the host control plane** step and waits for the
socket to appear. No stack traces, no "Disconnected: UNAVAILABLE:
connect ENOENT ..." raw error at the top of the window -- the tour
tells you what to do and the rest of the shell stays quiet until the
socket comes up.

## 2. Add the devcontainer feature to your project

Edit your project's `.devcontainer/devcontainer.json`. Add the strait
feature and a bind mount for the host socket:

```jsonc
{
  "image": "mcr.microsoft.com/devcontainers/base:debian",
  "remoteUser": "vscode",
  "features": {
    "ghcr.io/ninthwave-io/strait:0.1": {
      "agent_user": "vscode",
      "policy": "/workspaces/${localWorkspaceFolderBasename}/.strait/policy.cedar"
    }
  },
  "mounts": [
    "source=${localEnv:STRAIT_HOST_SOCKET:/var/run/strait/host.sock},target=/run/strait/host.sock,type=bind,readonly"
  ]
}
```

No `--privileged` and no `--network=host` are needed. The feature
declares `capAdd: [NET_ADMIN]` itself, so devcontainer runtimes grant
the capability without your needing to add `runArgs`.

If you want a turnkey starting point, the bundled preset writes a
complete `.devcontainer/devcontainer.json`, `strait.toml`, and
`policy.cedar` into a scratch directory:

```sh
strait preset apply claude-code-devcontainer ./my-agent
```

Then reopen the directory in your devcontainer runner.

## 3. Observe

Reopen your project in its container. The feature's entrypoint
verifies `CAP_NET_ADMIN`, installs iptables REDIRECT rules for ports
80 and 443 from the `agent_user`, and hands off to whatever the
container normally runs.

The desktop shell picks up the new session on its next poll. The
rail adds a row for your container; the onboarding tour pins that
row as **Pinned** so you can tell at a glance which container the
walkthrough is narrating. Run whatever the agent normally does
(`curl`, `npm install`, an editor calling an API -- whatever surfaces
real outbound HTTP traffic).

Every first-sight host raises a blocked-request prompt that the host
holds open while it waits for a decision.

## 4. Decide

The middle pane of the desktop shell shows the pending prompts for
the pinned session. For each one you have four immediate choices:

- **Deny** -- the request is rejected. If the agent retries, the
  prompt comes back.
- **Allow once** -- the current request goes through. The next
  request to the same host raises a fresh prompt.
- **Allow for session** -- every request to the same host is allowed
  for the life of this container session. Cedar rule is not written
  to disk.
- **Allow for...** -- same as session, but bounded by an explicit TTL
  (in seconds).

If you are not sure what the agent is trying to do, Allow once is
safe: the agent keeps working, and you see the next request before
committing to a durable rule.

## 5. Persist

Once you are sure a host is legitimate for this policy, click
**Persist** on the prompt. That writes a Cedar rule into the host
rule store. The next session on the same policy scope picks it up
automatically; you will not see the prompt again.

The onboarding tour advances to a **You persisted your first rule**
card as soon as the persist succeeds. That is the finish line: close
the tour, keep working. The shell stamps a completion timestamp into
local storage, so the tutorial stays hidden the next time you open
the desktop app. You will not be re-prompted on a returning install.

## Keyboard navigation and resuming the tour

The first-run tutorial is keyboard-accessible from top to bottom:

- **Tab / Shift+Tab** move between interactive controls: Previous
  step, Next step, Focus pinned container, and Skip tour.
- **Arrow keys**, **Home**, and **End** walk through the step list
  once it is focused. The currently active step is annotated with
  `aria-current="step"` for screen readers, and the keyboard-focused
  step is tracked via `aria-activedescendant`.
- **Skip tour** hides the overlay without dismissing it permanently.
  The header shows a **Reopen tour** button that brings the walk-
  through back at whichever step the shell state is on; the tour is
  resumable, not one-shot.
- After a persisted rule the header button renames itself to
  **Replay tour**. The tour will not reappear unsolicited, but you
  can review it any time without clearing your rule store.

If you never start the tour at all, nothing blocks real usage. The
blocked-request prompts, session rail, and decision buttons all work
with the overlay hidden.

## Health checks and common snags

The desktop shell's first-run tour doubles as a health check. If
something is wrong, the tour points at the step to fix:

- **Host missing.** `strait-host` is not running or the socket path
  is wrong. The shell sits on the first step and the status strip
  stays red. Start the host; the shell reconnects on its next poll.
- **No sessions yet.** The host is up but no container has
  registered. Confirm the devcontainer feature is referenced in
  `.devcontainer/devcontainer.json`, the host socket is bind-mounted
  into the container, and your runtime grants `CAP_NET_ADMIN`.
- **Session registered, no prompts.** The agent has not made any
  outbound HTTP calls yet. Either the agent is idle, or the traffic
  is going over a protocol strait does not intercept (plain TCP, not
  HTTP). Trigger a known-outbound action (`curl https://api.github.com/meta`)
  to confirm the pipeline.
- **Prompts appear but persist does nothing.** Check that
  `strait-host` has write access to its rule-store directory and
  that the policy file referenced by the feature option points at a
  writable path. The host logs an error per failed persist.

If you hit something that is not on this list, open a friction log
entry under `.ninthwave/friction/` with the exact error text. That is
how new snags get into the fix-it loop.

## Where to go next

- [Devcontainer feature reference](../features/strait/README.md) --
  the full option list for the strait feature.
- [Bring your own sandbox](bring-your-own-sandbox.md) -- wiring
  strait into a hand-rolled Dockerfile or a non-devcontainer runner.
- [Devcontainer comparison](devcontainer.md) -- where strait fits
  relative to the devcontainer spec.
- [Architecture](designs/in-container-rewrite.md) -- the design
  rationale for the in-container data plane and host control plane.
