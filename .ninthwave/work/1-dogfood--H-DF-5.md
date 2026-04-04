# Docs: Update Claude Code example for config-driven setup (H-DF-5)

**Priority:** High
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** H-DF-2
**Domain:** dogfood
**Lineage:** 80038816-7232-4d7a-84b3-c97dc5525a12

With host binary mounting (H-DF-2), the Claude Code example no longer needs a custom Dockerfile that installs `git` and `claude`. Update `examples/claude-code/` to demonstrate config-driven setup: use a base image (`ubuntu:24.04` or `node:20-slim`) and mount host tools via Cedar `proc:exec` policies.

Changes:
1. Simplify or remove the custom Dockerfile -- show that a base image works when binaries are mounted from the host
2. Update `strait.toml` MITM hosts to include endpoints Claude Code actually hits beyond `api.anthropic.com` and `api.github.com` (discover during dogfooding, but likely: `statsig.anthropic.com`, `sentry.io`, `registry.npmjs.org`)
3. Update `README.md` to show the config-driven workflow: write a Cedar policy with `proc:exec` for `claude`, `git`, `node`, and `strait launch` mounts them automatically
4. Add a sample Cedar policy file showing the complete Claude Code access pattern (fs:read/write for project dir, http: for API endpoints, proc:exec for tools)

**Test plan:**
- Manual review -- follow the updated README instructions end-to-end
- Verify the example `strait.toml` parses correctly (referenced MITM hosts are valid)
- Verify the sample Cedar policy is valid Cedar syntax

Acceptance: `examples/claude-code/README.md` documents config-driven setup without requiring a custom Docker build. The example includes a sample Cedar policy with proc:exec rules. MITM hosts list covers the endpoints Claude Code actually needs. A user can follow the README and run Claude Code inside strait using only a base image + config.

Key files: `examples/claude-code/README.md`, `examples/claude-code/strait.toml`, `examples/claude-code/Dockerfile`
