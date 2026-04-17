# Feat: Devcontainer feature for strait (H-INST-1)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 3
**Depends on:** H-ICDP-2, H-ICDP-3, H-ICDP-4, H-HCP-2
**Domain:** install-surface
**Lineage:** 1315b7be-4a9c-4689-b876-e223803d9fd7

Ship strait as a devcontainer feature. Creates `features/strait/` with `devcontainer-feature.json`, `install.sh`, and the `strait-agent` binary bundled at install time. Configures entrypoint wrapping so the user's `remoteUser` runs under `strait-agent entrypoint`. Feature options: `host` (socket URL), `agent_user`, `policy`, `proxy_port`. Install script validates `CAP_NET_ADMIN` availability at container build or first-run. Builds current repo release binary; publishing to ghcr is H-INST-2.

**Test plan:**
- Integration test: spin up a container from a minimal `devcontainer.json` that enables the feature; confirm entrypoint wraps the user command; confirm iptables rules installed.
- Test: feature options flow through to the entrypoint (custom `agent_user`, custom `proxy_port`).
- Error path: container built without `CAP_NET_ADMIN` fails with an actionable message that links to the relevant docs.

Acceptance: A `devcontainer.json` with the local feature path enabled boots a container that routes all outbound TCP through the bundled proxy. Options are honored. CI runs the feature integration test. The feature is self-contained (no external fetches at install time beyond fetching the pinned binary URL in H-INST-2).

Key files: `features/strait/devcontainer-feature.json`, `features/strait/install.sh`, `features/strait/README.md`, `.github/workflows/feature-test.yml`
