# Feat: `strait diff old.cedar new.cedar` (P2-V4-2)

**Priority:** P2
**Source:** CEO plan review — delight opportunity
**Depends on:** v0.3 namespaced entity model
**Domain:** cli

Add `strait diff <old-policy> <new-policy>` subcommand that shows permission-level differences between two Cedar policy files. Not a text diff — a semantic diff showing what access changed.

**Example output:**
```
Added:
  + fs:write on /project/out (new write access)
  + http:POST on api.github.com/repos/*/pulls (can now create PRs)

Removed:
  - http:DELETE on api.github.com/repos/* (can no longer delete)

Unchanged:
  = fs:read on /project/src
  = http:GET on api.github.com/repos/*
```

**Why:** Critical for code review of policy changes. When a generated policy is modified by a security engineer, `strait diff` shows exactly what permissions changed — like `git diff` for access control.

**Effort:** S (CC: ~30 min)

Key files: `src/diff.rs` (NEW), `src/main.rs` (new subcommand)
