# Design: Network Policy for Devcontainers

**Date:** 2026-03-27
**Status:** APPROVED
**Branch:** main

## Status

This path is kept as a compatibility pointer for older links. The current product framing lives in these documents:

- [`../devcontainer.md`](../devcontainer.md) — user-facing comparison and migration guide
- [`devcontainer-strategy.md`](devcontainer-strategy.md) — architecture rationale and positioning

## Current product story

Strait sits beside the devcontainer spec instead of competing with it.

| Question | Owner |
| --- | --- |
| What image, tools, mounts, users, and editor settings does this project need? | `devcontainer.json` |
| What outbound HTTP requests should this agent be allowed to make? | strait |

In that model:

- Cedar policy covers outbound HTTP requests
- The proxy enforces request-level rules by method, host, path, and agent identity
- Credential injection happens only on allowed requests
- The observe, generate, warn, and enforce loop stays the main operator workflow

## Architecture summary

```
  ┌─────────────────────────────────────────────────────────┐
  │              Container (Docker/Podman/OrbStack)        │
  │                                                         │
  │  ┌──────────────┐     ┌──────────────────────┐         │
  │  │ AI Agent     │────▶│ Strait Proxy (MITM)  │──▶ API  │
  │  │ (user cmd)   │     │ Cedar eval + creds   │         │
  │  │ [full TTY]   │     └──────────────────────┘         │
  │  └──────────────┘                                      │
  └───────────────────────┬────────────────────────────────┘
                          │ observation stream
  ┌───────────────────────▼────────────────────────────────┐
  │ Strait Host Process                                     │
  │  - Container lifecycle                                  │
  │  - Local control API (`session.info`, `policy.replace`) │
  │  - Observation stream (JSONL + attach socket)           │
  │  - `strait session watch` for one session               │
  │  - `strait generate` policy from observations           │
  │  - `strait test --replay` verification                  │
  └────────────────────────────────────────────────────────┘
```

## Cedar model

```cedar
@id("allow-github-read")
permit(
  principal == Agent::"worker",
  action == Action::"http:GET",
  resource in Resource::"api.github.com/repos/our-org"
);

@id("deny-main-push")
forbid(
  principal,
  action == Action::"http:POST",
  resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
```

## Why this file changed

The broader pre-refocus design has been retired in favor of the devcontainer strategy. The current claim is simpler: keep `devcontainer.json` for environment shape and use strait for outbound network policy.
