# Feat: Update Claude Code policy template for OAuth model (M-DF2-5)

**Priority:** Medium
**Source:** Dogfooding review -- M-DF-6 template assumed API key auth
**Depends on:** H-DF2-4
**Domain:** dogfood
**Lineage:** 92c772a7-4fce-4416-bf41-21340e648757

The `claude-code` policy template from M-DF-6 includes Anthropic API permit rules. For Max/OAuth users, Anthropic traffic is passthrough (not MITM'd), so these rules are unused. The template should reflect the common case: OAuth auth for Anthropic, credential injection for GitHub/npm/AWS.

Changes to `templates/claude-code.cedar`:
- Move Anthropic API permit rules into a clearly commented "API key users only" section, or remove them and add a comment explaining passthrough
- Add npm registry rules (http:GET for registry.npmjs.org)
- Keep GitHub and filesystem rules as-is
- Update the header comment to explain the OAuth vs API key distinction

Also update the behavioral tests in `src/templates.rs` to match the new template content.

**Test plan:**
- Verify `strait template apply claude-code` produces valid Cedar
- Update behavioral tests for any changed/removed rules
- `cargo test --all-features` passes

Acceptance: `claude-code` template reflects OAuth-first model. Comments explain when Anthropic API rules are needed (API key users) vs not (Max users). Template validates against the Cedar schema. Tests pass.

Key files: `templates/claude-code.cedar`, `src/templates.rs`
