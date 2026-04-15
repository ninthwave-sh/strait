# Strategy: strait and the devcontainer standard

## Context

The refocus plan (`.opencode/plans/1776234011325-kind-engine.md`) commits strait to a container-scoped trust boundary as the product's moat: session-local CA inside the container only, all egress forced through a proxy, Cedar policy covering network + fs + proc in one model. Phase-1 work items (H-CSM-3..7) are about turning that boundary into a usable permission workflow: blocked-request explanations, live deny/allow-once/allow-session/persist decisions, a local control service, and a desktop control plane.

Meanwhile, Microsoft's devcontainer spec (https://containers.dev/) is the established format for "what does my project need to run in a container?" The Claude Code docs (https://code.claude.com/docs/en/devcontainer) bless a reference devcontainer setup with an iptables-based firewall (domain allowlist via `init-firewall.sh`) as the sanctioned way to sandbox an agent in a container.

That is the wedge. Devcontainer plus iptables answers part of the problem; strait answers the harder part. This document locks the position: strait sits inside the devcontainer ecosystem rather than parallel to it, and narrows its product surface to network egress.

## Thesis

strait should be compatible with devcontainer, not a competitor to it. In the devcontainer world, strait should narrow to network egress as its primary concern.

The two specs answer different questions:

| Question | Answer |
|---|---|
| What image, tools, env, and mounts does my project need? | devcontainer.json |
| What is my project allowed to do over the network once it runs? | strait |

Devcontainer owns the environment contract. strait owns the network permission contract. The integration goal is that a user with an existing `.devcontainer/devcontainer.json` can adopt strait without rewriting their config, and a user adopting strait can publish a devcontainer.json that works in VS Code, Codespaces, and GitHub without ceremony.

### Narrowing to network-only (inside devcontainer)

The current unified-policy framing (`http:` + `fs:` + `proc:`) duplicates work the container boundary already does:

- Filesystem access is determined by the devcontainer image, `mounts`, and `workspaceFolder`. If `/secrets` is not mounted there is nothing to authorize. If it is mounted, Cedar `fs:read` rules are a second layer over a first layer the user already configured.
- Process execution is determined by the image. If `curl` is not installed there is nothing to authorize. Cedar `proc:exec` rules are again a second layer.
- Network egress is genuinely different. TLS hides egress from the host kernel. The devcontainer spec has no native story for network policy. Claude Code's reference setup bolts on iptables (domain-granular, coarse, restart-to-edit).

Network egress is the exfiltration vector that matters and the one the container boundary does not solve. So in the devcontainer world, strait's value is concentrated on network policy, and the other two domains are dropped.

### What this simplifies

- Templates and onboarding: one domain to teach, not three.
- Observation and generation: only HTTP requests need capture and wildcard-collapsing.
- Policy mental model: "what APIs can this agent reach?" is a question users already ask; "what files can this agent read?" is a question the container already answers.
- Config surface: `[container]` ImageSpec in `src/config.rs` goes away. devcontainer.json is the image source.
- Pitch: "Cedar-powered network policy for devcontainers, with a desktop control plane" is sharper than "unified agent policy platform" for an audience that already bought the container model.

### What stays

- MITM pipeline, session-local CA, `--network=none` plus Unix-socket gateway, credential injection: all the hard and distinctive infra.
- Control plane (H-CSM-3, H-CSM-4, H-CSM-5), desktop shell (M-CSM-6), onboarding (M-CSM-7): unchanged. Every Phase-1 work item is already network-focused.
- Cedar policy engine: still the right tool for expressive network rules (method, host, path, identity). Narrower entity model, same engine.

### What goes

- `fs:` and `proc:` Cedar domains are dropped. The devcontainer already answers those questions. Carrying a parallel enforcement layer costs complexity with no marginal value inside the target audience.
- Codebase consequences: fs/proc actions removed from the entity schema in `src/policy.rs`; the mount-derivation pipeline that reads `fs:` rules and turns them into bind mounts is deleted; templates, examples, and docs that reference these domains are removed or rewritten.
- Generation, observation, and replay narrow to HTTP only. No fs or exec tracing, no mount inference.
- Standalone `strait launch` without a devcontainer still works (proxy plus MITM plus network-none boundary are intact), but it requires a user-provided image and the user is responsible for the image's fs/proc shape. strait does not layer anything on top.

### Positioning consequence

Claude Code's iptables firewall is the status quo; strait replaces it with a policy engine, an observe workflow, live decisions, and a desktop UX. Everything else in the devcontainer config (image, features, lifecycle hooks, editor customizations, mounts) is unaffected and stays the user's problem, expressed in devcontainer.json.

## What strait can honor from devcontainer.json

Fields that map cleanly onto strait's model:

- `image` / `build.dockerfile` / `build.context`: replaces the ad-hoc `[container].base_image` / `apt` / `npm` / `pip` generation in `src/config.rs`. Devcontainer builds become the canonical image source.
- `containerEnv`: merged with strait's session-specific env (proxy socket path, CA bundle path) at entrypoint.
- `postCreateCommand` / `onCreateCommand`: chained after strait's CA trust injection, before the agent command.
- `remoteUser`: strait learns to run the agent as a non-root user.
- `workspaceFolder`: replaces the hardcoded `/workspace`.
- `features`: strait itself can ship as a feature (`ghcr.io/ninthwave-io/strait`) so users add one block to enable it.

## What strait's security model rejects or translates

Under the narrowed thesis, mounts become the user's problem (expressed in devcontainer.json), not strait's. What remains:

- `forwardPorts`: strait uses `--network=none` plus a Unix-socket gateway. Inbound ports can't be forwarded directly. Two options: translate into a Cedar `http:` allow rule for outbound equivalents, or warn and ignore with a clear message about the network model.
- `mounts`: honored as-is. devcontainer.json owns the filesystem story. strait only inspects mounts to surface them in diagnostics ("this agent has read access to /secrets because your devcontainer.json mounts it"). No Cedar `fs:` rules required.
- `runArgs` / `capAdd` / `privileged`: reject privileged requests with a clear error. strait's network isolation depends on non-privileged containers with `--network=none`; `--privileged` would let the agent bypass both.

Principle: devcontainer describes environment; strait enforces network egress. strait intervenes only where the container boundary is blind (TLS-terminated egress) and delegates everywhere else.

## What to learn from Claude Code's devcontainer

What Claude Code does well that strait should match or exceed:

- Zero-config first run. The user clones a repo, opens in VS Code, and it Just Works. strait's `generate` plus `--observe` workflow is more powerful but higher ceremony. Presets (M-CSM-7 onboarding) should close that gap.
- Legible threat model. The docs are explicit about what the firewall does and does not prevent. strait's onboarding copy needs the same discipline.
- One-file config. Users edit `init-firewall.sh` directly. strait's equivalent is Cedar policy; the desktop control plane (M-CSM-6) and `persist` action (H-CSM-4) are what make that editable without shell scripts.

Where Claude Code's model falls short and where strait's wedge is real:

- iptables is domain-granular, not request-granular. No per-path, per-method, per-identity rules.
- No observe-then-enforce workflow. Users guess at allowlist entries and iterate by breaking the agent.
- No live decisions. A blocked request means restart the container with edited firewall rules.
- No audit trail beyond iptables logs.
- No desktop UX. Everything happens in a terminal.

Every one of those gaps maps onto an already-planned strait work item. Devcontainer compatibility is not new scope; it is repackaging the Phase-1 roadmap for an audience that already lives in devcontainer.json.

## Recommended phasing

Phase 0: this document. Lock the thesis and the positioning.

Phase 1: public comparison doc (`docs/devcontainer.md`). Explains where strait fits relative to devcontainer. Walks through the Claude Code iptables setup and shows the equivalent strait setup side by side. Documents incompatibilities (forwardPorts, privileged runArgs) up front.

Phase 2: narrow the codebase to network-only (drop `fs:` / `proc:` Cedar domains and the mount-derivation pipeline); add a devcontainer.json reader; wire `strait launch --devcontainer <path>` through the existing launch flow; rewrite user-facing docs (README, CLAUDE.md, unified-agent-policy-platform design) for the narrower framing.

Phase 3: ship as a devcontainer feature (`ghcr.io/ninthwave-io/strait`) so users add one block to their devcontainer.json and get strait plus proxy plus desktop-pairing out of the box. Depends on the local control service (H-CSM-5) being stable.

## Positioning

One-sentence product claim, post-compat and post-narrowing:

> strait is the network policy layer for devcontainers. Replace your iptables allowlist with a Cedar policy engine, live request-level decisions, and a desktop control plane.

This framing:

1. Names the thing strait replaces (iptables plus init-firewall.sh).
2. Names the audience (anyone running Claude Code or VS Code in a devcontainer).
3. Does not require users to learn a new runtime or abandon their existing config.
4. Scopes the promise. "Network policy" is legibly smaller than "unified agent policy platform," which trades surface area for credibility.

## Decisions

1. Desktop control plane stays the primary client surface. Not a VS Code extension. Users are moving away from VS Code, and devcontainers run outside VS Code (Codespaces, JetBrains, CLI, headless). Tying strait's UX to VS Code would narrow the audience in the wrong direction. The desktop shell (M-CSM-6) remains the Phase-1 target.
2. Host-side proxy stays on the host, always. If strait ships as a devcontainer feature, the feature registers the container with an already-running host-side strait daemon; it does not run the proxy inside the container. Running the proxy inside would expose it to tampering by whatever is executing inside the container. The entire trust boundary exists to prevent that.
3. Recommend removing iptables when adopting strait. Both can coexist without harm, but the comparison doc takes a clear position: once strait is in place, iptables plus init-firewall.sh is redundant and strictly less expressive. Remove it.
4. Clean cut on fs/proc. No backwards compat, no migration path, no legacy references. strait is pre-v1, pre-launch, pre-users. The narrowing is a decisive rewrite: fs/proc actions are removed from the entity schema, parsers, templates, and docs. No deprecation warnings. No migration tool. No "legacy" mentions in the codebase or README.
