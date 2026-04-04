# Docs: Bump to v0.2.0 and update CHANGELOG (H-DF-4)

**Priority:** High
**Source:** Plan: Dogfood Strait with Claude Code
**Depends on:** H-DF-1
**Domain:** dogfood
**Lineage:** d01f5607-8601-4737-b1b9-2066b4a5a95a

Cargo.toml still says `version = "0.1.0"` despite shipping network isolation (6 PRs: C-NI-1 through H-NI-6) and the MITM timeout feature (H-MITM-1). Bump to 0.2.0 and add a CHANGELOG section documenting what shipped since v0.1.0.

Changes to document in v0.2.0 CHANGELOG:
- Network isolation: containers run with `--network=none`, traffic routes through gateway binary over Unix socket to host proxy
- Gateway binary: statically-linked musl binary, auto-detected for x86_64/aarch64
- CI musl cross-compilation for gateway
- Upstream connect and response timeouts (H-MITM-1)
- `--env` flag for `strait launch`
- `--config` flag for `strait launch` (credential injection in container mode)

**Test plan:**
- Manual review -- verify CHANGELOG entries are accurate and match merged PRs
- `cargo clippy --all-features -- -D warnings` still passes
- Verify `Cargo.toml` version field is `0.2.0`

Acceptance: `Cargo.toml` version is `0.2.0`. `CHANGELOG.md` has a v0.2.0 section listing network isolation, gateway binary, timeouts, and new CLI flags. No code changes beyond version bump.

Key files: `Cargo.toml:7`, `CHANGELOG.md`
