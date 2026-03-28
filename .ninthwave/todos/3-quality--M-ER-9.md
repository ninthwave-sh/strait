# Refactor: Code deduplication -- context builders + read_observations + evaluate_proc (M-ER-9)

**Priority:** Medium
**Source:** ER-2 Findings 3-4, 7; ER-6 Finding 8; CEO review (evaluate_proc moved here)
**Depends on:** H-ER-4
**Domain:** quality

Context-building logic is duplicated between policy.rs (inline in evaluate) and replay.rs (build_http_context, build_fs_context, build_proc_context, build_mount_context). The read_observations function is duplicated between generate.rs and replay.rs. The proc:fork and proc:signal action entities are created but never used. Fix by extracting shared context builders as public functions in policy.rs, moving read_observations to observe.rs as the canonical implementation, adding evaluate_proc method to PolicyEngine (needed for replay completeness, no live caller yet), and removing unused proc:fork/proc:signal entity creation.

**Test plan:**
- Test that the shared HTTP context builder produces the same output as the previous inline version
- Test that the shared read_observations function works from both generate and replay paths
- Test that evaluate_proc produces a valid PolicyDecision for a proc:exec action
- Verify that proc:fork and proc:signal entities are no longer created

Acceptance: Single context builder implementation shared by policy.rs and replay.rs. Single read_observations in observe.rs. evaluate_proc method added. Dead entities removed.

Key files: `src/policy.rs`, `src/replay.rs`, `src/generate.rs`, `src/observe.rs`
