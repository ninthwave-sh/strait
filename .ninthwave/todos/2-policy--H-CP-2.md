# Refactor: Entity model namespace migration (H-CP-2)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** None
**Domain:** policy

Migrate the Cedar entity model from flat actions (`Action::"GET"`) to namespaced actions (`Action::"http:GET"`). Generalize `PolicyEngine::evaluate()` to accept a domain-agnostic action string rather than HTTP-specific method. Add entity builders for `fs:` and `proc:` namespaces.

Breaking change: existing `.cedar` policy files must update `Action::"GET"` to `Action::"http:GET"`. Add a startup check that detects old-format actions and prints a clear migration error.

Entity model:
- `Action::"http:GET"`, `Action::"http:POST"`, `Action::"http:DELETE"`, etc.
- `Action::"fs:read"`, `Action::"fs:write"`, `Action::"fs:create"`, `Action::"fs:delete"`
- `Action::"proc:exec"`, `Action::"proc:fork"`, `Action::"proc:signal"`
- `Resource::"net::host/path"` (network), `Resource::"fs::/path"` (filesystem), `Resource::"proc::command"` (process)

**Test plan:**
- Unit test: `Action::"http:GET"` entity construction produces correct Cedar EntityUid
- Unit test: `Action::"fs:read"` and `Action::"proc:exec"` entity construction
- Unit test: `Resource::"fs::/project/src"` hierarchy builds parent chain (fs::/project)
- Unit test: old-format policy (Action::"GET") triggers clear migration error at startup
- Integration test: update existing cedar test policies to use namespaced actions, verify evaluation still works

Acceptance: All existing tests pass with updated entity model. Old-format policies produce a clear error message directing users to update. New `fs:` and `proc:` entity builders exist and are tested.

Key files: `src/policy.rs`, `tests/integration.rs`, Cedar policy test fixtures
