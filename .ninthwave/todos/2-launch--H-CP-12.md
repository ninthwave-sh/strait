# Feat: `strait launch --warn` and `--policy` enforcement modes (H-CP-12)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** H-CP-7
**Domain:** launch

Add enforcement modes on top of the observe-mode orchestrator:

- `strait launch --warn policy.cedar ./agent` -- evaluate Cedar policy at container creation time (restrict bind-mounts) and at proxy request time, but ALWAYS allow. Log violations as warnings in the observation stream.
- `strait launch --policy policy.cedar ./agent` -- enforce policy. Container only gets mounts permitted by Cedar fs: policies. Proxy denies requests not permitted by Cedar http: policies.

Key behaviors:
- Policy loaded and validated at startup (fail fast if invalid, before container creation)
- Cedar fs: policies translated to bind-mounts (read-only/read-write) via CP-4's container config builder
- Cedar http: policies evaluated by proxy at request time (existing flow, now with namespaced actions)
- Warn mode: same container config as enforce but proxy logs warnings instead of 403s
- Observation stream marks events with enforcement mode (observe/warn/enforce)

**Test plan:**
- Integration test: `launch --policy` with restrictive policy, verify agent can only access permitted mounts
- Integration test: `launch --policy` with network deny, verify proxy returns 403
- Integration test: `launch --warn` with same restrictive policy, verify agent succeeds but warnings logged
- Edge case: policy file invalid -- fail fast before starting container with clear error
- Edge case: policy blocks a required mount -- agent sees ENOENT for missing path, observation logs the denial reason

Acceptance: All three modes (observe/warn/policy) work correctly. Policy enforcement restricts bind-mounts and proxy decisions. Warn mode is non-blocking with logged violations.

Key files: `src/launch.rs` (extend)
