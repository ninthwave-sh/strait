# Feat: Claude Code policy template (M-DF-6)

**Priority:** Medium
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** H-DF-5
**Domain:** dogfood
**Lineage:** d6bf1f70-4d88-4a07-a443-df0cbb4794a2

After dogfooding validates what Claude Code actually needs, add a `claude-code` template to strait's built-in template system. This gives users a one-command starting point: `strait template apply claude-code`.

The template should cover Claude Code's actual API surface discovered during dogfooding:
- `http:GET` / `http:POST` to `api.anthropic.com` (Claude API)
- `http:GET` / `http:POST` / `http:DELETE` to `api.github.com` (GitHub API, scoped to org)
- `fs:read` / `fs:write` for the project directory
- `fs:read` for system libraries and tool directories
- `proc:exec` for `claude`, `git`, `node`, and common dev tools
- Hard deny for destructive operations (e.g., force-push to main)

Add the template file at `templates/claude-code.cedar` and register it in `src/templates.rs` alongside the existing 5 templates (github-org-readonly, github-org-contributor, aws-s3-readonly, aws-s3-readwrite, container-sandbox).

**Test plan:**
- Verify `strait template list` includes `claude-code`
- Verify `strait template apply claude-code` outputs valid Cedar that parses without errors
- Unit test in `src/templates.rs` for the new template entry
- Verify the template Cedar validates against the schema in `templates/strait.cedarschema`

Acceptance: `strait template list` shows `claude-code`. `strait template apply claude-code` produces valid Cedar covering Claude Code's API surface. The template includes comments explaining each policy rule. `cargo test --all-features` passes.

Key files: `templates/claude-code.cedar`, `src/templates.rs`
