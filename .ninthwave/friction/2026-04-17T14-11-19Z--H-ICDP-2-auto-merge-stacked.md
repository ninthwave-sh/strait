item: H-ICDP-2
date: 2026-04-17T14:11:19Z
severity: medium
description: |
  In auto mode, the orchestrator should only auto-merge PRs targeting the
  default/main branch. Stacked PRs (PRs with --base set to another
  ninthwave/* branch, such as this PR #120 which was stacked on top of
  H-ICDP-1) should wait until they are retargeted to main before the
  auto-merge gate is considered.

  Auto-merging a stacked PR into its dependency branch collapses the stack
  prematurely and makes review harder (the reviewer loses the clean
  per-item diff). The correct behavior is: the implementer opens the PR
  against its base branch for clean review, the dependency merges to main,
  GitHub retargets the child PR to main, and only then does the
  auto-merge/review-complete gate fire.

  Suggested fix: in the orchestrator daemon's merge decision, skip the
  merge step (but keep review/CI polling) when the PR's base is not the
  repo's default branch.
