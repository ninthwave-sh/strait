# Fix: Generated policy resource prefix mismatch (H-CP-15)

**Priority:** High
**Source:** design review of H-CP-8 (PR #24)
**Depends on:** -
**Domain:** generate

`strait generate` produces policies with `net::` prefixed resources (e.g., `Resource::"net::api.github.com/repos/org/repo"`) but the runtime policy evaluator in `policy.rs` creates entities without the prefix (`Resource::"api.github.com/repos/org/repo"`). Generated policies won't match at runtime.

Either:
- A) Remove the `net::` prefix from generate output (match current runtime), or
- B) Add the `net::` prefix to runtime entity construction (match generate output)

Option A is simpler and doesn't break existing user policies. Option B is more consistent with the namespaced action model (`http:GET`, `fs:read`) but is a breaking change for existing policies.

**Test plan:**
- Generate a policy from an observation log, then replay it with `strait test --replay` — all events should match
- Verify generated policy works with `strait proxy` (end-to-end)

Key files: `src/generate.rs` (resource prefix), `src/policy.rs` (entity construction)
