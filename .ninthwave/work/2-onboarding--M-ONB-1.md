# Refactor: Rescope M-CSM-7 onboarding around devcontainer feature (M-ONB-1)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 4; supersedes onboarding flow that assumed `strait launch`
**Depends on:** H-INST-1, H-HCP-6, M-HCP-7
**Domain:** onboarding
**Lineage:** 574f6fcd-53f3-41ad-baff-906d9f480fd5

Rework the onboarding flow so the first session starts by adding the devcontainer feature to an existing project. The desktop shell detects the first registered container, pins that container in the session rail, and walks through observe -> generate -> persist. Replaces any onboarding copy or logic that referenced the removed `strait launch` command.

**Test plan:**
- Manual walkthrough: fresh install of desktop app and host service; add feature to a sample project; first session triggers the onboarding overlay with a clear next step at each stage.
- Regression: existing M-CSM-7 preset library still works (see M-ONB-2 for host-side move).
- Edge case: user has the feature installed but no `strait-host` running -> onboarding surfaces an install prompt, not a stack trace.

Acceptance: Onboarding path is coherent end-to-end for "add the feature, open the project, answer the prompts, leave with a persisted rule." No references to `strait launch` remain in onboarding UI, copy, or docs. Health checks gracefully guide the user when the host is missing.

Key files: `desktop/src/renderer/onboarding.tsx`, `desktop/src/renderer/sessions.tsx`, `docs/getting-started.md`
