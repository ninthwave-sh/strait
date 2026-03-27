# Feat: `strait explain policy.cedar` (M-V4-1)

**Priority:** medium
**Source:** CEO plan review — delight opportunity
**Depends on:** none
**Domain:** cli

Add `strait explain <policy-file>` subcommand that prints a human-readable English summary of what a Cedar policy allows and denies. Walks the policy set, groups by action namespace (http, fs, proc), and produces plain-English descriptions.

**Example output:**
```
This policy allows:
  - Read files under /project/src
  - Read and write files under /project/out
  - GET requests to api.github.com/repos/*
  - Execute git, npm, node

This policy denies:
  - All DELETE requests
  - Execute rm, dd, chmod
  - Write to /etc, /usr
```

**Why:** Lowers the barrier for non-Cedar-experts to review generated policies. Security engineers who don't know Cedar syntax can still understand what a policy does.

**Effort:** S (CC: ~30 min)

Key files: `src/explain.rs` (NEW), `src/main.rs` (new subcommand)
