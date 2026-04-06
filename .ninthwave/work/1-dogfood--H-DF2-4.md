# Docs: Update Claude Code example for Max subscription (H-DF2-4)

**Priority:** High
**Source:** Dogfooding review -- example assumes API key auth, not OAuth
**Depends on:** H-DF2-2, H-DF2-3
**Domain:** dogfood
**Lineage:** 2f95aa19-df53-41fd-b11c-f585525a33fc

The current Claude Code example assumes API key auth (MITM + inject x-api-key on api.anthropic.com). Claude Code Max uses OAuth tokens stored in `~/.claude/.credentials.json`. The example needs to support both auth models, with the Max/OAuth approach as the primary path.

Changes:

1. Update `examples/claude-code/strait.toml`:
   - Remove `api.anthropic.com` from `[mitm] hosts` (passthrough for OAuth)
   - Remove the Anthropic credential injection entry
   - Keep GitHub credential injection (security-sensitive)
   - Add npm credential injection for registry.npmjs.org (if NPM_TOKEN is set)
   - Add a `[container]` section specifying apt packages (git, curl, ca-certificates) and npm packages (@anthropic-ai/claude-code) so the auto-build feature handles image creation

2. Update `examples/claude-code/README.md`:
   - Primary path: Max subscription with OAuth (mount `~/.claude/`, passthrough Anthropic traffic)
   - Secondary path: API key with credential injection (for users with API keys)
   - Show `--mount ~/.claude/:/root/.claude/:rw` for OAuth auth
   - Explain that Anthropic traffic passes through as a tunnel (no inspection needed)
   - Focus the security narrative on GitHub/npm/AWS credential isolation

3. Update `examples/claude-code/policy.cedar`:
   - Remove or comment the Anthropic API permit rules (not needed for passthrough traffic)
   - Keep GitHub, filesystem, and process rules
   - Add npm registry permit rules

4. Simplify the Dockerfile to just `FROM ubuntu:24.04` + `ca-certificates` since auto-build handles tool installation. Or remove it entirely if auto-build replaces it.

**Test plan:**
- Manual review -- follow updated README end-to-end with Max subscription
- Verify strait.toml parses correctly with `[container]` section
- Verify policy.cedar is valid Cedar syntax

Acceptance: A Claude Code Max user can follow the example README and run Claude Code inside strait without an API key. Anthropic traffic passes through without MITM. GitHub credentials are injected by the proxy. The `[container]` config auto-builds an image with Claude Code installed.

Key files: `examples/claude-code/strait.toml`, `examples/claude-code/README.md`, `examples/claude-code/policy.cedar`, `examples/claude-code/Dockerfile`
