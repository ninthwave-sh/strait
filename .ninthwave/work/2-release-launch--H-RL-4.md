# Feature: Claude Code example config and Dockerfile (H-RL-4)

**Priority:** High
**Source:** v0.1.0 release -- real agent testing
**Depends on:** C-RL-1, C-RL-2
**Domain:** release-launch

Create an `examples/claude-code/` directory with everything needed to run
Claude Code inside a strait container: a Dockerfile, a strait.toml config,
and a README with step-by-step instructions.

**Dockerfile** (`examples/claude-code/Dockerfile`):
- Base image: `node:20-slim`
- Install git (needed by Claude Code for repo operations)
- Install `@anthropic-ai/claude-code` globally via npm
- Keep image minimal -- no dev dependencies

**Config** (`examples/claude-code/strait.toml`):
- MITM hosts: `api.anthropic.com`, `api.github.com`
- Credential injection for `x-api-key` header on `api.anthropic.com` (from `ANTHROPIC_API_KEY` env var)
- Credential injection for `Authorization` header on `api.github.com` (from `GITHUB_TOKEN` env var)
- Audit logging to `/tmp/strait-audit.jsonl`
- Identity header: `X-Strait-Agent: claude-code`

**README** (`examples/claude-code/README.md`):
- Prerequisites (Docker, API keys, cargo build)
- Build image command
- Observe pass: `strait launch --observe --image ... --env ... -- claude "task"`
- Generate + explain policy
- Warn mode with config
- Enforce mode with credential injection
- Keep it short and command-focused

**Test plan:**
- `docker build -t claude-code-sandbox examples/claude-code/` succeeds
- Config parses: `strait proxy --config examples/claude-code/strait.toml` starts without error (Ctrl-C after startup)
- Manual review: README instructions are complete and accurate

Acceptance: `docker build` produces a working image. Config loads without
errors. README covers the full observe-generate-warn-enforce workflow.

Key files: `examples/claude-code/Dockerfile`, `examples/claude-code/strait.toml`, `examples/claude-code/README.md`
