# Docs: Fix stale network enforcement documentation (H-DF-1)

**Priority:** High
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** None
**Domain:** dogfood
**Lineage:** bb4530d3-b21e-4ead-b04a-fc57685902b5

README.md line 191 still says "Network enforcement is currently cooperative" and promises v0.4 will fix it. This is wrong -- containers already run with `--network=none` and the gateway binary routes traffic through a Unix socket. CLAUDE.md line 54 similarly says "Cooperative network enforcement." Both need to reflect reality: network isolation is enforced, not cooperative.

**Test plan:**
- Manual review -- verify README.md "Known limitations" section accurately describes `--network=none` + gateway enforcement
- Verify CLAUDE.md key design decisions section matches current behavior
- `cargo clippy --all-features -- -D warnings` still passes (no code changes)

Acceptance: README.md no longer mentions cooperative enforcement or "v0.4 will enforce." CLAUDE.md key design decisions accurately describe enforced network isolation via `--network=none` + gateway. The "Known limitations" section in README reflects actual current limitations, not solved ones.

Key files: `README.md:189-192`, `CLAUDE.md:54`
