# Chore: Release metadata polish (H-RL-3)

**Priority:** High
**Source:** v0.1.0 release preparation
**Depends on:** None
**Domain:** release-launch

Bundle of small metadata and documentation fixes for the v0.1.0 release.

**Description updates** -- The CLI `about` string, Cargo.toml description, and
Homebrew formula description all say "HTTPS proxy with Cedar policy evaluation,
credential injection, and audit logging" which describes the v0.2 proxy-only
era. Update all three to reflect the v0.3 container platform scope. Use
something like: "Policy platform for AI agents - Cedar policy over network,
filesystem, and process access".

Files:
- `Cargo.toml` line 5 -- update `description`
- `src/main.rs` line 23 -- update `about` string
- `Formula/strait.rb` line 2 -- update `desc`

**License fix** -- `Formula/strait.rb` line 4 says `license "MIT"` but the
project is Apache-2.0. Fix to `license "Apache-2.0"`.

**CLAUDE.md style convention** -- Add a bullet under Conventions: "No AI slop
signals in user-facing text (em dashes, flowery language). Keep prose direct
and plain."

**CHANGELOG.md** -- Create initial release changelog listing v0.1.0 features.
Keep it factual and concise. Use ASCII only (hyphens not em dashes).

**Test plan:**
- Manual review: verify descriptions match across all three locations
- `cargo clippy --all-features -- -D warnings` still passes
- `cargo test` still passes (CLI parsing tests may reference help text)

Acceptance: `strait --help` shows updated description. `Formula/strait.rb`
has correct license. CHANGELOG.md exists. CLAUDE.md has style convention.

Key files: `Cargo.toml`, `src/main.rs`, `Formula/strait.rb`, `CLAUDE.md`, `CHANGELOG.md`
