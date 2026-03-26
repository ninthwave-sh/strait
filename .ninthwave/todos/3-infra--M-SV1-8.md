# Feat: GitHub Releases workflow (M-SV1-8)

**Priority:** Medium
**Source:** Strait v0.1 design — deliverable 7
**Depends on:** None
**Domain:** infra

Add a GitHub Actions release workflow triggered by `v*` tags. The existing `ci.yml` already builds cross-platform release binaries (x86_64/aarch64 for Linux and macOS) but doesn't publish them. The new `release.yml` workflow:

1. Triggers on `push` of tags matching `v*`
2. Runs the same cross-platform build matrix as CI
3. Uploads the 4 binaries (linux-x86_64, linux-aarch64, darwin-x86_64, darwin-aarch64) as GitHub Release assets
4. Auto-generates release notes from commits since the last tag
5. Names binaries as `strait-<target>` (e.g., `strait-x86_64-unknown-linux-gnu`)

**Test plan:**
- Manual review: verify workflow YAML is valid GitHub Actions syntax
- Verify the build matrix matches `ci.yml` targets
- Verify binary naming convention matches GitHub Release conventions

Acceptance: Pushing a `v0.1.0` tag triggers the workflow, builds 4 binaries, and creates a GitHub Release with all artifacts attached. Users can download `strait-<target>` from the release page.

Key files: `.github/workflows/release.yml` (new)
