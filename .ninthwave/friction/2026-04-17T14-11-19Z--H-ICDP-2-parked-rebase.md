item: H-ICDP-2
date: 2026-04-17T14:11:19Z
severity: medium
description: |
  PR #120 developed merge conflicts after its dependency (H-ICDP-1)
  landed, but the orchestrator did not send a rebase request to this
  worker. The work item was marked as "parked" in orchestrator state, and
  the parked status appears to suppress the normal
  base-branch-advanced -> rebase-request flow.

  Expected behavior: when the base branch of a stacked PR advances (for
  example, because the dependency merged and the PR was retargeted from
  ninthwave/H-ICDP-1 to main), the orchestrator should dispatch a rebase
  nudge to the worker regardless of parked/active status, because the PR
  is now blocked on a merge conflict that only the worker or rebaser can
  resolve.

  The human reviewer had to manually flag "this has conflicts / needs
  rebasing" on the PR to get the rebase to happen. Suggested fix: in the
  orchestrator daemon's rebase dispatcher, treat "PR has conflicts" or
  "base branch advanced" as a dispatch trigger independent of the work
  item's parked/active flag.
