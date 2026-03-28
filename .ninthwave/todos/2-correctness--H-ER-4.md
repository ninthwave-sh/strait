# Fix: Replay correctness -- fs context + warn decision (H-ER-4)

**Priority:** High
**Source:** ER-6 Findings 2-3, ER-2 Finding 5, ER-8 Finding 7
**Depends on:** None
**Domain:** correctness

The evaluate_fs function in policy.rs uses Context::empty() while replay builds context with path and operation attributes. This means Cedar policies with `when { context.path like ... }` conditions on filesystem actions work in replay but fail in live enforcement. Additionally, replay treats "warn" observations as denials when they should be counted as allowed (warn mode always allows the request). Fix by adding path and operation context to evaluate_fs (matching replay's build_fs_context), and adding "warn" to the observed_allowed set in replay.

**Test plan:**
- Test that a Cedar fs policy with `when { context.path like "/project/*" }` matches in live evaluate_fs
- Test that replay and live evaluate_fs produce the same decision for the same policy + input
- Test that "warn" decision is counted as allowed in replay results
- Test that "deny" decision is still counted as denied in replay

Acceptance: evaluate_fs populates context with path and operation. Replay treats warn as allowed. Replay and live produce consistent results for fs policies.

Key files: `src/policy.rs`, `src/replay.rs`
