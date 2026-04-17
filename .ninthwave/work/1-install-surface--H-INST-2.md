# Feat: Publish devcontainer feature to ghcr (H-INST-2)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 3
**Depends on:** H-INST-1
**Domain:** install-surface
**Lineage:** 48f5e48a-a887-45a0-9a6f-6128a27a041a

Publish the devcontainer feature at `ghcr.io/ninthwave-io/strait` so users can reference it by id without cloning the repo. Add a release workflow that builds the feature (and its bundled `strait-agent` binary for both linux/amd64 and linux/arm64) and pushes to ghcr on tags matching `v*`. Verify pull-and-run in a smoke test job using a fresh tag candidate.

**Test plan:**
- Dry-run the publish workflow on a branch; confirm the OCI artifact layout matches the devcontainers spec.
- Smoke test: after publish, an external project referencing `ghcr.io/ninthwave-io/strait:<tag>` in its `devcontainer.json` builds and boots.
- Edge case: arch mismatch (Apple Silicon pulling arm64 binary) picks the right artifact.

Acceptance: On `v*` tag push, a GitHub Actions workflow builds and publishes the feature to `ghcr.io/ninthwave-io/strait` with multi-arch binaries. The workflow includes a post-publish smoke test that consumes the published feature. Public `devcontainer.json` snippet in `README.md` references the ghcr id.

Key files: `.github/workflows/release-feature.yml`, `features/strait/devcontainer-feature.json`, `README.md`
