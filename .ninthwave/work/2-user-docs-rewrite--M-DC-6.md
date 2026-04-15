# Docs: Rewrite user-facing docs for network-only and devcontainer framing (M-DC-6)

**Priority:** Medium
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), Phase 2
**Depends on:** H-DC-3
**Domain:** user-docs-rewrite
**Lineage:** 2decca98-c9ca-4d50-bea1-b3c31861be16

Rewrite the user-facing documentation to reflect the network-only narrative and devcontainer positioning. `README.md` leads with "network policy layer for devcontainers"; drops fs/proc examples; points to the new `docs/devcontainer.md` comparison doc and to `docs/designs/devcontainer-strategy.md` for architecture rationale. `CLAUDE.md` updates the architecture summary to remove the `fs:`/`proc:` entity model language and frames Cedar policy as network-only. `docs/designs/unified-agent-policy-platform.md` is retitled and rewritten to reflect the narrower scope, or replaced with a pointer to the strategy doc.

**Test plan:**
- Manual review: documents read cold to a new user and tell a consistent story
- Verify every example in `README.md` and `CLAUDE.md` uses only `http:` Cedar actions
- Verify no references to `fs:read`, `fs:write`, `proc:exec`, or "unified agent policy platform" remain in user-facing docs
- Verify internal links between `README.md`, `docs/devcontainer.md`, and `docs/designs/devcontainer-strategy.md` resolve

Acceptance: `README.md`, `CLAUDE.md`, and `docs/designs/unified-agent-policy-platform.md` (or its successor) present a consistent network-policy-for-devcontainers story. No fs/proc Cedar examples remain. The one-sentence product claim from the strategy doc appears verbatim in `README.md`. All cross-links resolve.

Key files: `README.md`, `CLAUDE.md`, `docs/designs/unified-agent-policy-platform.md`, `templates/README.md`
