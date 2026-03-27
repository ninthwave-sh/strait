# ER-2: Policy Engine Review

**Date:** 2026-03-27
**Module:** src/policy.rs (583 lines of production code, 1339 lines of tests)

## Summary

The Cedar policy engine is well-architected and production-ready for its
current scope. The entity model correctly implements `http:`, `fs:`, and
`proc:` namespaces with proper hierarchy construction. Path hierarchies
enable wildcard-like matching via Cedar's `in` operator, and `forbid`
rules correctly override `permit` (Cedar's native semantics). The
ArcSwap-based hot-reload is atomic and safe — in-flight requests hold
the old Arc until completion. Schema validation is optional and
correctly gated. Test coverage is excellent (60+ tests covering
hierarchy descent, agent identity, schema validation, AWS context,
old-format migration, and example file validation).

The most actionable findings are: header-to-context injection can
overwrite built-in context keys like `host` and `path` (security),
`escape_cedar_string` doesn't escape newlines or other control
characters (security), no `evaluate_proc` method exists despite
`build_proc_entities` being public (missing API), and significant
context-building logic is duplicated between `policy.rs` and
`replay.rs` (quality).

## Findings

### 1. [SECURITY] Header values can overwrite built-in context attributes — HIGH

**File:** `src/policy.rs:136-187`

Headers are lowercased and appended to the context via
`context_pairs.extend(header_pairs)` *after* the built-in keys (`host`,
`path`, `method`, `aws_service`, `aws_region`) are added. If a request
contains a header named `host`, `path`, or `method`, the Cedar
`Context::from_pairs()` call receives duplicate keys.

The behavior with duplicate keys in `Context::from_pairs()` is
implementation-defined by the Cedar SDK — it may use the first or last
value, or error. If the last value wins, a crafted request with a
`path: /admin` header could change `context.path` from its true value,
causing a `when { context.path like ... }` condition to evaluate against
attacker-controlled input. This could bypass a `forbid` rule that
matches on `context.path`.

**Suggested fix:** Filter headers before extending context, removing any
header whose lowercased name collides with a reserved context key:
```rust
let reserved = ["host", "path", "method", "aws_service", "aws_region"];
let header_pairs: Vec<_> = headers
    .iter()
    .filter(|(k, _)| !reserved.contains(&k.to_lowercase().as_str()))
    .map(|(k, v)| { /* ... */ })
    .collect();
```

Or prefix all header context keys (e.g., `header:content-type`) to
namespace them away from built-in attributes.

### 2. [SECURITY] `escape_cedar_string` only escapes backslash and double-quote — MEDIUM

**File:** `src/policy.rs:580-582`

The escape function handles `\` and `"` but not newlines (`\n`, `\r`),
tabs (`\t`), or other control characters. While Cedar's
`RestrictedExpression::from_str()` parser may reject raw control
characters in string literals (causing an `unwrap()` panic), this is a
defense-in-depth gap. If a header value or path contains a newline and
the parser doesn't reject it, it could break the Cedar expression
structure.

The `unwrap()` calls on `RestrictedExpression::from_str()` throughout
`evaluate()` (lines 142, 151, 156, 161, 175, 182) would panic on
malformed inputs rather than returning an error.

**Suggested fix:** Escape control characters and propagate parse errors:
```rust
pub(crate) fn escape_cedar_string(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => write!(out, "\\u{{{:04x}}}", c as u32).unwrap(),
            c => out.push(c),
        }
    }
    out
}
```

Also replace `.unwrap()` calls with `.map_err()` to return proper
errors instead of panicking on crafted input.

### 3. [MISSING] No `evaluate_proc` method on `PolicyEngine` — MEDIUM

**File:** `src/policy.rs:541-577`

`build_proc_entities()` is `pub` and constructs entities for `proc:exec`,
`proc:fork`, and `proc:signal` actions. But unlike `evaluate()` (HTTP)
and `evaluate_fs()` (filesystem), there is no corresponding
`evaluate_proc()` method on `PolicyEngine`. Callers (like `replay.rs`)
must manually construct the request, principal, action, resource, and
context — duplicating the evaluation pattern.

The `replay.rs` module works around this by implementing its own
`cedar_evaluate()` helper function that reimplements the core
authorization flow. This creates a maintenance risk: changes to the
evaluation pattern in `PolicyEngine` may not be reflected in `replay.rs`.

**Suggested fix:** Add `evaluate_proc()` to `PolicyEngine`, mirroring
the pattern of `evaluate_fs()`:
```rust
pub fn evaluate_proc(
    &self,
    command: &str,
    action: &str,
    agent_id: &str,
) -> anyhow::Result<PolicyDecision> { /* ... */ }
```

### 4. [QUALITY] Context-building logic duplicated between policy.rs and replay.rs — MEDIUM

**File:** `src/policy.rs:135-190`, `src/replay.rs:404-439`

The HTTP context construction (host, path, method, AWS attributes) is
implemented twice: once in `PolicyEngine::evaluate()` and once in
`replay.rs::build_http_context()`. The replay module's comment (line
403) explicitly notes "This mirrors the context construction in
`PolicyEngine::evaluate()`." Similarly, `build_fs_context()` and
`build_proc_context()` in `replay.rs` duplicate what should be shared
logic.

If the context schema evolves (e.g., adding a `query_string` attribute
or new AWS fields), both locations must be updated in sync.

**Suggested fix:** Extract context builders into `policy.rs` as public
functions (`build_http_context`, `build_fs_context`, `build_proc_context`)
and call them from both `PolicyEngine::evaluate*()` and `replay.rs`.

### 5. [QUALITY] `evaluate_fs` uses `Context::empty()` unlike HTTP evaluate — MEDIUM

**File:** `src/policy.rs:260`

`evaluate_fs()` passes `Context::empty()` to the Cedar request, while
`evaluate()` (HTTP) populates a rich context with host, path, method,
and headers. This means Cedar policies for filesystem operations cannot
use `when { context.path ... }` conditions — the context has no `path`
attribute even though the path is available.

The `replay.rs` module builds a proper fs context with `path` and
`operation` attributes (line 445-459), but `PolicyEngine::evaluate_fs()`
does not. This inconsistency means policies validated via replay
evaluation may behave differently than live `evaluate_fs()` calls.

**Suggested fix:** Build an fs context in `evaluate_fs()` with at
minimum `path` and `action` attributes:
```rust
let context_pairs = vec![
    ("path".to_string(), RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(path))).unwrap()),
    ("operation".to_string(), RestrictedExpression::from_str(&format!("\"{}\"", escape_cedar_string(action))).unwrap()),
];
let context = Context::from_pairs(context_pairs)?;
```

### 6. [DESIGN] `is_host_permitted` has O(7) evaluation overhead per host check — LOW

**File:** `src/policy.rs:294-303`

`is_host_permitted()` evaluates each of 7 HTTP methods (GET, POST, PUT,
PATCH, DELETE, HEAD, OPTIONS) against the host's root resource until one
succeeds. Each evaluation builds the full entity hierarchy and context.
This is called per CONNECT request to decide whether to MITM the
connection.

For the current use case (small number of configured MITM hosts), this
is fine. But as the entity model grows, this could be optimized by:
1. Short-circuiting on GET first (most common permissive policy)
2. Caching host-permitted results (they change only on policy reload)
3. Using a dedicated `http:CONNECT` action entity

**No immediate action needed** — this is a future optimization note.

### 7. [DESIGN] `proc:fork` and `proc:signal` action entities are unused — LOW

**File:** `src/policy.rs:567`

`build_proc_entities()` creates action entities for `proc:exec`,
`proc:fork`, and `proc:signal`, but only `proc:exec` is used anywhere
in the codebase (`watch.rs:183`, `generate.rs:181`, `replay.rs:302`).
The `proc:fork` and `proc:signal` actions are spec'd in the module
doc but have no callers and no observation events that produce them.

This is acceptable for forward-looking API design, but the unused
actions should be documented as reserved/planned to avoid confusion.

### 8. [QUALITY] Entity hierarchy construction allocates per-request — LOW

**File:** `src/policy.rs:359-426`

Every call to `build_http_entity_hierarchy()` allocates a new `Vec` of
`Entity` objects, `HashSet`s for parent relationships, and multiple
`String`s for resource IDs. For high-throughput scenarios, this
per-request allocation could become a bottleneck.

Cedar's `Entities` type is immutable once constructed, so caching is
difficult for the resource hierarchy (which varies per path). However,
the action entities (7 HTTP methods) and the agent entity are identical
across requests and could be pre-built once per policy load.

**No immediate action needed** — the current approach is correct and
clear. Profile before optimizing.

### 9. [QUALITY] `check_old_format_actions` uses naive string matching — LOW

**File:** `src/policy.rs:434-457`

The migration check searches for `Action::"GET"` in the raw policy text
using `String::contains()`. This could false-positive on:
- Cedar comments: `// Action::"GET" was the old format`
- String literals: `@reason("Use Action::\"GET\" instead")`

In practice, false positives would only produce an incorrect migration
error (not a security issue), and the user would see a clear error
message explaining what to change. The check runs once at load time
so there's no performance concern.

**No action needed** — the current approach is good enough for a
migration helper. It could be made more precise with regex matching
against non-comment, non-string contexts, but the cost/benefit ratio
doesn't justify it.

### 10. [QUALITY] `deny_response_body` duplicates policy display logic — LOW

**File:** `src/policy.rs:585-608`

The "default-deny" fallback string and `policy_names.join(", ")` pattern
is implemented both in `deny_response_body()` and in
`src/mitm.rs:335-339`. Both locations independently compute
`policy_display` from the same `policy_names` slice.

**Suggested fix:** Have `deny_response_body` accept the pre-computed
display string, or have the MITM module use `deny_response_body` as
the single source of truth for the display format.

### 11. [QUALITY] Schema only validates HTTP actions, not fs: or proc: — LOW

**File:** `examples/github.cedarschema`

The example schema declares only HTTP actions (`http:GET`, `http:POST`,
etc.) but the entity model also supports `fs:read`, `fs:write`,
`fs:create`, `fs:delete`, `fs:mount`, `proc:exec`, `proc:fork`, and
`proc:signal`. Policies using fs: or proc: actions would fail schema
validation in strict mode.

This is correct for the GitHub-specific schema, but there's no
comprehensive schema that covers all strait action types. A user
writing a policy combining HTTP and filesystem rules would need to
either skip schema validation or maintain their own schema.

**Suggested fix:** Consider shipping a `strait.cedarschema` that covers
the full entity model (all namespaces), in addition to the
domain-specific example schemas.

### 12. [DESIGN] `PolicyDecision` doesn't distinguish forbid from default-deny — LOW

**File:** `src/policy.rs:30-38`

`PolicyDecision.allowed` is `false` for both explicit `forbid` and
default-deny (no matching permit). The `policy_names` field is empty
for default-deny and populated for explicit forbid, but this requires
callers to check both fields to distinguish the two cases.

For audit purposes, knowing whether a denial came from an explicit
`forbid` (policy actively blocked it) vs. default-deny (no policy
covers it) is valuable. Cedar's `Response` provides this information
via `diagnostics().errors()` (for forbid) vs. empty reason set
(for default-deny), which is partially captured but not surfaced.

**No immediate action needed** — the current approach works and the
audit log includes enough information. This is an enhancement for
richer audit trail semantics.

## Key Question Answers

**Is the entity hierarchy deep enough for real-world path patterns?**

Yes. The hierarchy correctly splits URL paths into segments, creating a
parent chain from the most specific to the host root. For
`/repos/org/repo/pulls/123`, five resource entities are created with
proper `in` relationships. This supports Cedar's `in` operator for
subtree matching, which is the primary pattern for REST API access
control. The depth is bounded only by the URL path length.

For filesystem paths, the hierarchy correctly walks from leaf to root
(`fs::/project/src` -> `fs::/project` -> `fs::/`). The `fs::` prefix
namespace prevents collision with HTTP resources.

For process operations, the hierarchy is flat (single resource per
command), which is appropriate — process names don't have a natural
hierarchical structure.

**How does the policy engine handle `forbid` rules — do they correctly
override `permit`?**

Yes. Cedar's native semantics guarantee that `forbid` always overrides
`permit`, regardless of policy ordering. The implementation correctly
delegates to `Authorizer::is_authorized()` without any custom override
logic. The test suite explicitly verifies this: the `deny-push-main`
forbid in the example policy correctly blocks POST to
`/repos/our-org/my-repo/git/refs/heads/main` even though the
`create-prs` permit covers POST to org repos.

The `diagnostics().reason()` iterator correctly reports which policies
contributed to the decision, and `@reason` annotations are collected
for human-readable denial messages in the audit log.

**Are there action types that should exist but don't (e.g., `http:PATCH`,
`http:OPTIONS`)?**

All seven standard HTTP methods are covered: GET, POST, PUT, PATCH,
DELETE, HEAD, OPTIONS. There is no `http:CONNECT` action (CONNECT
decisions are handled by `is_host_permitted` rather than individual
method evaluation).

For filesystem: `fs:read`, `fs:write`, `fs:create`, `fs:delete` are
declared as entity actions, plus `fs:mount` is used in replay/generate
but not declared in `build_fs_entities`. This is a minor inconsistency —
`fs:mount` works because Cedar evaluates against the provided entities,
and replay builds its own entity set.

For process: `proc:exec`, `proc:fork`, `proc:signal` are declared but
only `proc:exec` has callers. This is forward-looking API design for
v0.3's container platform.

**Does the namespaced model correctly handle the v0.1->v0.3 migration?**

Yes. The `check_old_format_actions()` function detects pre-v0.3
un-namespaced actions (e.g., `Action::"GET"`) and returns a clear error
with migration instructions showing the old and new format for each
detected action. The check runs before Cedar parsing, so users get
the migration message rather than a confusing Cedar parse error.

The migration is one-way and mandatory — there's no compatibility mode
that accepts both formats. This is the right choice for a pre-v1 tool
where breaking changes are acceptable.

## Checklist Results

- [x] **Cedar entity model** — `http:`, `fs:`, `proc:` namespaces correctly
  implemented. Entity type names (`Agent`, `Resource`, `Action`) are
  consistent. Resource IDs use clear prefixes (`fs::`, `proc::`) to
  prevent namespace collision.
- [x] **Entity hierarchy** — Path hierarchies correctly built for HTTP
  (host + path segments) and filesystem (leaf to root) domains. Parent
  relationships use Cedar's `in` operator. Process resources are flat
  (correct for the domain).
- [x] **Policy evaluation** — Allow/deny decisions correct for all tested
  edge cases. Forbid correctly overrides permit. Default-deny works.
  Agent identity correctly scopes policies to specific principals.
  **Note:** Header-to-context injection vulnerability (Finding 1).
- [x] **Policy loading** — File parsing with clear error messages. Schema
  validation optional and correct. Old-format migration detection with
  actionable error messages.
- [x] **SIGHUP reload** — Atomic via ArcSwap. Bad policies don't break
  running proxy (error logged, previous policy retained). Reload runs
  on blocking pool to avoid blocking the async runtime. Both file and
  git modes supported.
- [~] **Performance** — Entity construction per-request is allocation-heavy
  but correct. No caching of action/agent entities. `is_host_permitted`
  does 7 evaluations per check. Acceptable for current scale.
- [~] **Error handling** — Policy load errors are well-handled. **Note:**
  `unwrap()` calls on `RestrictedExpression::from_str()` could panic
  on crafted input with control characters (Finding 2).
- [~] **Security** — Default-deny is correct. Forbid overrides permit.
  **Note:** Header values can overwrite context attributes (Finding 1),
  and escape function is incomplete (Finding 2).
