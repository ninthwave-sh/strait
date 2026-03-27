# Design: Unified Agent Policy Platform

**Date:** 2026-03-27
**Status:** APPROVED
**Branch:** main

## Problem Statement

AI agents need fine-grained control over their capabilities — not just "can this agent reach api.github.com?" but "can this agent DELETE branches?" and "can this agent write to /etc?". Current solutions split this into separate tools: network proxies for API access, kernel sandboxes for filesystem isolation, container runtimes for process isolation. Each tool has its own policy format, its own observation model, and its own enforcement mechanism.

Security teams face "policy paralysis" — they can't write effective policies because they don't understand agent behavior. They need to observe what agents actually do, then generate policies from that observation.

## Insight

Everyone builds sandboxing and network policy as separate tools because they come from different traditions (OS security vs API authorization). But the security engineer asks ONE question: "what should this agent be allowed to do?" That question doesn't care whether the answer involves a filesystem rule, a network rule, or a process rule. A unified Cedar policy covering all three is the right abstraction.

## Solution

Strait evolves from an HTTPS policy proxy into a unified agent policy platform. A single Cedar policy governs filesystem access (via container bind-mounts), network access (via HTTPS MITM proxy with credential injection), and process access (via container image configuration). The observe-then-enforce workflow solves policy paralysis.

## Architecture

```
  ┌─────────────────────────────────────────────────────────┐
  │              Container (Docker/Podman/OrbStack)           │
  │                                                          │
  │  ┌──────────────┐     ┌──────────────────────┐         │
  │  │ AI Agent     │────▶│ Strait Proxy (MITM)  │──▶ API  │
  │  │ (user cmd)   │     │ Cedar eval + creds    │         │
  │  │ [full TTY]   │     └──────────────────────┘         │
  │  └──────────────┘                                      │
  │                                                          │
  │  Bind-mounts from Cedar policy:                         │
  │    fs:read  /project/src → read-only mount              │
  │    fs:write /project/out → read-write mount             │
  │    (no policy = not mounted = invisible)                │
  └───────────────────────┬─────────────────────────────────┘
                          │ observation stream
  ┌───────────────────────▼─────────────────────────────────┐
  │ Strait Host Process                                      │
  │  - Container lifecycle (docker/podman CLI or API)        │
  │  - Observation: proxy audit stream (network events)      │
  │  - `strait watch` colored output via Unix socket         │
  │  - `strait generate` policy from observations            │
  │  - `strait test --replay` verification                   │
  └─────────────────────────────────────────────────────────┘
```

### Why Containers

Container-based sandboxing (Docker, Podman, OrbStack) was chosen over kernel-level approaches (Seatbelt, Landlock, Endpoint Security Framework) for several reasons:

- **Ships cross-platform immediately** — macOS and Linux, no special OS permissions
- **No vendor-specific entitlements** — no Apple Developer entitlement approval process
- **Proven isolation model** — container runtimes are battle-tested for process and filesystem isolation
- **Ubiquitous tooling** — Docker/Podman are already installed on most developer machines
- **Container IS the sandbox** — bind-mounts enforce filesystem access, PID namespace isolates processes, network routes through the proxy

Kernel-level approaches (Seatbelt, Endpoint Security Framework) were evaluated and rejected for v0.3. They offer lower overhead but require platform-specific entitlements, have inconsistent observation APIs (some block silently with no events), and don't work cross-platform. They remain a future option if performance demands it.

### How Cedar Policy Maps to Enforcement

Cedar policy gets "compiled" into two enforcement mechanisms:

1. **Container config** — bind-mounts (filesystem access), available binaries (process exec), network routing (through proxy)
2. **Proxy rules** — request-level allow/deny, credential injection, API-level policy

```cedar
// Filesystem: translates to read-only bind-mount of /project/src
permit(principal, action == Action::"fs:read",
  resource in Resource::"fs::/project/src");

// Network: evaluated by Strait proxy at request time
permit(principal, action == Action::"http:GET",
  resource in Resource::"net::api.github.com/repos");

// Process: translates to binary available in container image
permit(principal, action == Action::"proc:exec",
  resource == Resource::"proc::git");
```

### Cedar Entity Model (namespaced)

```
Action::"http:GET"     Action::"fs:read"      Action::"proc:exec"
Action::"http:POST"    Action::"fs:write"     Action::"proc:fork"
Action::"http:DELETE"   Action::"fs:create"    Action::"proc:signal"

Resource::"net::api.github.com/repos/*"
Resource::"fs::/project/src"
Resource::"proc::git"
```

Breaking change from v0.1 entity model (`Action::"GET"` → `Action::"http:GET"`). Migration at v0.2→v0.3 boundary.

### Differentiators

What makes Strait's approach unique:

1. **HTTPS MITM with request-level policy** — not just connection-level monitoring, but semantic API policy ("allow GET /repos but deny DELETE /branches")
2. **Credential injection** — agents never see real secrets. The proxy holds credentials and injects them only on policy-allow. Prevents exfiltration via prompt injection.
3. **Observe-then-enforce workflow** — `strait launch --observe` captures all activity, `strait generate` produces a Cedar policy, `strait test --replay` verifies it. Zero-to-policy in minutes.
4. **Unified Cedar policy** — one policy language for filesystem, process, and network access. No separate config files for each enforcement layer.

## CLI Architecture (v0.3)

```
strait proxy --config strait.toml                              # existing HTTPS proxy mode
strait launch --observe ./agent                                # container + observe all activity
strait launch --warn policy.cedar ./agent                      # container + log what would be blocked
strait launch --policy policy.cedar ./agent                    # container + enforce policy
strait generate observations.jsonl                             # generate Cedar policy from observations
strait test --replay observations.jsonl --policy policy.cedar  # verify policy
strait watch                                                   # connect to Unix socket, render colored events
```

### I/O Architecture

- Agent gets full terminal control via container TTY (interactive TUI support — Claude Code, vim, etc.)
- Observations stream to Unix socket (`/tmp/strait-<pid>.sock`)
- `strait watch` connects to socket for live colored output in a second terminal
- Observation events also persisted to JSONL file for `strait generate` and `strait test`

### Progressive Enforcement

```
  OBSERVE ──► GENERATE ──► WARN ──► ENFORCE
     │                       │         │
     │  (no policy,          │  (log   │  (block
     │   log everything)     │  what   │   violations)
     │                       │  would  │
     │                       │  block) │
     └───────────────────────┴─────────┘
              policy lifecycle
```

## Phased Roadmap

### v0.2 — Proxy Improvements (current entity model)

Ship on existing `Action::"GET"` entity model. Work items in `.ninthwave/todos/`:
- Git-hosted Cedar policies with hot-reload (H-V2-1)
- HTTP/1.1 keep-alive request loop (H-V2-3)
- SIGHUP policy reload (M-V2-2)
- `strait init --observe` network traffic observation (M-V2-4)
- Policy templates for GitHub and AWS (L-V2-5)

### v0.3 — Container Platform (entity model migration)

Breaking change: entity model gains `http:`, `fs:`, `proc:` namespaces.
- `strait launch` CLI with container management
- Entity model migration
- Container bind-mounts from Cedar filesystem policy
- Unified observation stream (proxy audit + container events) via Unix socket
- `strait generate` — Cedar policy from observation data
- `strait test --replay` — verify policy against observed traffic
- `strait watch` — colored real-time observation viewer
- Progressive enforcement: `--observe` / `--warn` / `--policy` modes

### v0.4+ — Future

- `strait explain` — human-readable policy summaries
- `strait diff` — semantic policy diffing
- strait.sh managed platform (separate repo)

## Open Questions

1. **Policy generation heuristics** — how to collapse path segments that look like IDs (UUIDs, numeric) into wildcards without false positives? Conservative approach: only collapse well-known patterns (UUID v4, pure numeric >3 digits, 40-char hex).
2. **Container image strategy** — ship a default image with common agent tools, or require users to specify their own? Leaning toward: default image + `--image` override.
3. **Observation volume** — a real agent session can produce thousands of file access + network events. How to keep generated policies readable? Leaning toward: group by path prefix, collapse similar patterns, annotate with counts.

## Success Criteria

1. `strait launch --observe ./agent` runs an agent in a container, observes all activity, and produces a JSONL observation log
2. `strait generate` produces a valid Cedar policy from the observation log that covers all observed activity
3. `strait launch --policy generated.cedar ./agent` re-runs the agent with enforcement — all previously-observed actions succeed, novel actions are denied
4. `strait test --replay` confirms the generated policy matches observations
5. The HTTPS MITM proxy (credential injection, API-level policy) works with the container (proxy on host, container routes traffic through it)
6. Cross-platform: works on macOS (Docker/OrbStack) and Linux (Docker/Podman)

## Engineering Decisions (from eng review)

1. **Container API:** `bollard` crate (Rust Docker API bindings) for container lifecycle management. Not shelling out to `docker` CLI.
2. **Proxy location:** Proxy runs on HOST, not inside container. Container routes traffic via `HTTPS_PROXY=host.docker.internal:<port>`. Stronger isolation — agent can't tamper with proxy.
3. **CA trust:** Append Strait's session CA to the container's system CA bundle at container start via entrypoint script. Works with all HTTP clients regardless of env var support.
4. **Round-trip E2E test:** Blocking CI test: observe → generate → enforce → verify. Must pass before v0.3 ships.

## GSTACK REVIEW REPORT

| Review | Trigger | Why | Runs | Status | Findings |
|--------|---------|-----|------|--------|----------|
| CEO Review | `/plan-ceo-review` | Scope & strategy | 2 | CLEAR | 8 proposals, 8 accepted, 0 deferred. Pivoted from ESF to containers after outside voice. |
| Outside Voice | Claude subagent | Structural blind spots | 2 | ISSUES_FOUND | 10 findings, triggered ESF→container pivot |
| Eng Review | `/plan-eng-review` | Architecture & tests (required) | 2 | CLEAR | 2 issues (proxy location, CA trust), 1 critical gap (false wildcard), 35 test paths mapped |
| Design Review | `/plan-design-review` | UI/UX gaps | 0 | — | — |

**ENG REVIEW DECISIONS:**
- bollard crate for Docker API (not CLI shelling)
- Proxy on host, container routes traffic through it
- CA trust via system bundle append at container start
- Round-trip E2E test as v0.3 shipping gate
- 3 parallel worktree lanes for implementation

**VERDICT:** CEO + ENG CLEARED — ready to implement. v0.2 proxy improvements first, then v0.3 container platform.
