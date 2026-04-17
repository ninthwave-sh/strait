# Feat: First-run quickstart tutorial (L-ONB-3)

**Priority:** Low
**Source:** `docs/designs/in-container-rewrite.md` Phase 4
**Depends on:** M-ONB-1, M-ONB-2
**Domain:** onboarding
**Lineage:** 29672681-3247-4237-953c-d9c4df3e5fc9

Add a first-run tutorial in the desktop app that covers the full golden path: install the host service, add the feature to an existing devcontainer project, run an agent, observe a session, persist a rule. Skippable. Resumable. Tracks completion per install so a returning user is not re-prompted.

**Test plan:**
- E2E test: fresh install reaches the tutorial overlay; completing each step advances; skip dismisses for the install lifetime.
- Regression: running a session without starting the tutorial still works (the tutorial is not blocking).
- Accessibility: keyboard navigation covers every step.

Acceptance: First-run tutorial exists, is keyboard-accessible, skippable, resumable, and does not block real usage. Completion state persists across app restarts. Docs cover the same path in text form.

Key files: `desktop/src/renderer/tutorial.tsx`, `desktop/src/main/tutorial-state.ts`, `docs/getting-started.md`
