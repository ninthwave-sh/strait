# ER-6: Generation & Replay Review

**Date:** 2026-03-28
**Modules:** src/generate.rs (742 lines), src/replay.rs (1246 lines)

## Summary

The generation and replay modules form the observe-then-enforce workflow:
`generate` reads a JSONL observation log and synthesizes Cedar policy + schema
files; `replay` evaluates an observation log against an existing policy to
verify coverage. Both are well-structured with clear public APIs, thorough
tests (35+ tests total), and good error messages with line numbers for parse
failures.

The most critical finding is that **wildcard-collapsed policies are
non-functional** (Finding 1). When `generate` collapses dynamic path
segments (UUIDs, long numerics, SHAs) to `*`, it produces entity IDs
like `Resource::"host/users/*/posts"`. Cedar treats `*` as a literal
character in entity IDs, not a glob — so these rules never match any
request during live enforcement. The generated policy is syntactically
valid Cedar and passes schema validation, but the wildcard rules are
semantically dead. A user who deploys a generated policy with collapsed
paths will get unexpected denials with no indication of why.

The second major finding is a **replay context mismatch for filesystem
operations** (Finding 2). The live policy engine (`evaluate_fs`) evaluates
fs actions with `Context::empty()`, but replay constructs a context with
`path` and `operation` attributes. A policy using `when { context.path
like "/workspace/*" }` on an fs action would match in replay but fail
in live enforcement. This breaks replay's core invariant: that it
reproduces live enforcement decisions.

Additional findings include: replay misclassifies "warn" observations as
denials (Finding 3); generate produces permits for denied observations,
making generated policies overly permissive (Finding 4); replay cannot
reproduce header-based policy conditions because observations don't
capture headers (Finding 5); and duplicated `read_observations` code
between the two modules (Finding 8).

Test coverage is strong: `generate.rs` tests cover UUID/SHA/numeric
detection, resource collapsing, deduplication, empty input, container
event filtering, Cedar parse+validate round-trips, and wildcard annotation
comments. `replay.rs` tests cover match/mismatch exit codes, context
conditions (host, path, method, AWS), agent identity, fs/proc/mount event
evaluation, passthrough handling, error messages for corrupt and missing
files, and blank line tolerance. However, no test validates that a
generated policy produces correct decisions when evaluated against real
requests — the generation tests verify text output, not functional
correctness.

## Findings

### 1. [BUG] Generated wildcard policies are non-functional — Cedar treats `*` as literal — HIGH

**File:** `src/generate.rs:268-297`, `src/generate.rs:197-218`

When `collapse_resource` replaces a dynamic segment with `*`, the
generated policy produces rules like:

```cedar
permit(
  principal,
  action == Action::"http:GET",
  resource in Resource::"api.example.com/users/*/posts"
);
```

During live enforcement, a request to `/users/550e8400-.../posts` builds
this entity hierarchy:

- `Resource::"api.example.com/users/550e8400-.../posts"` → parent
- `Resource::"api.example.com/users/550e8400-..."` → parent
- `Resource::"api.example.com/users"` → parent
- `Resource::"api.example.com"`

The Cedar `in` operator checks if the request's resource entity is equal
to or a descendant of the specified entity. But
`Resource::"api.example.com/users/*/posts"` is never in the hierarchy —
the `*` is a literal character in the entity ID, not a wildcard. The
rule silently never matches.

**Impact:** Any rule with a collapsed wildcard segment is dead code.
Users who deploy generated policies with wildcards get unexpected denials.
The policy is syntactically valid (passes `PolicySet::from_str` and
schema validation), so there is no error signal.

The `uuid_collapsed_with_annotation_comment` test (line 503) verifies
the policy text contains `*` but does not test that the policy actually
permits matching requests — so the functional breakage is untested.

**Suggested fix:** Two options, in order of preference:

1. **Use context conditions instead of entity wildcards.** For collapsed
   paths, generate a broader entity match with a `when` clause:
   ```cedar
   // * at segment 2 was: 550e8400-..., 660e8400-...
   permit(
     principal,
     action == Action::"http:GET",
     resource in Resource::"api.example.com/users"
   ) when { context.path like "/users/*/posts" };
   ```
   Cedar's `like` operator supports `*` wildcards. This is both
   functional and precise.

2. **Truncate to the parent above the wildcard.** Generate the rule at
   the deepest non-wildcard ancestor:
   ```cedar
   // collapsed: users/*/posts → users (review for over-breadth)
   permit(
     principal,
     action == Action::"http:GET",
     resource in Resource::"api.example.com/users"
   );
   ```
   This is simpler but overly broad — it permits all paths under
   `/users`, not just `/users/*/posts`.

Option 1 is better because it preserves the path-level specificity while
using a Cedar feature that actually supports wildcards.

### 2. [BUG] Replay context mismatch for filesystem operations — HIGH

**File:** `src/replay.rs:445-459` vs `src/policy.rs:260-261`

The live `evaluate_fs` method evaluates fs actions with an empty context:

```rust
// policy.rs:260-261
let context = Context::empty();
let request = Request::new(principal, action_uid, resource, context, None)
```

But replay's `build_fs_context` constructs a context with `path` and
`operation` attributes:

```rust
// replay.rs:446-456
let pairs: Vec<(String, RestrictedExpression)> = vec![
    ("path".to_string(), ...),
    ("operation".to_string(), ...),
];
```

**Impact:** A policy like this evaluates differently in live vs. replay:

```cedar
permit(
  principal,
  action == Action::"fs:read",
  resource in Resource::"fs::/"
) when { context.path like "/workspace/*" };
```

- **Live:** `context.path` doesn't exist → condition fails → **deny**
- **Replay:** `context.path` = `"/workspace/src/main.rs"` → condition
  matches → **allow**

This violates replay's core invariant. The `fs_access_event_evaluated`
and `fs_context_path_condition_evaluated` tests pass because they test
replay in isolation — they don't verify alignment with live evaluation.

The same pattern applies to `build_mount_context` (provides `path` and
`mode`) and `build_proc_context` (provides `command`), though proc and
mount evaluation don't exist in the live path yet.

**Suggested fix:** Either:
1. Add `path` and `operation` context attributes to `evaluate_fs` in
   `policy.rs` (preferred — makes the live engine more capable), or
2. Use `Context::empty()` in replay for fs/proc/mount to match live
   behavior (loses replay's ability to test context conditions).

Option 1 is the right direction — `evaluate_fs` should have been
updated when the context builders were added to replay.

### 3. [BUG] Replay treats "warn" observations as denials — MEDIUM

**File:** `src/replay.rs:241`

```rust
let observed_allowed = decision == "allow" || decision == "passthrough";
```

The MITM pipeline emits `decision: "warn"` for requests that the policy
denied but were allowed due to warn mode (src/mitm.rs:511-514). A "warn"
observation means the request went through — the traffic was allowed.

But replay doesn't include `"warn"` in the `observed_allowed` check, so
it treats warn-mode observations as denials. If the new policy being
tested allows the request (correct behavior), replay reports a mismatch:

```
MISMATCH line 5:
  event:    GET api.github.com/repos
  observed: warn
  policy:   allow
```

This is a false positive — the policy correctly permits the request that
was also permitted (via warn mode) in the original session.

**Suggested fix:** Add `"warn"` to the allowed set:

```rust
let observed_allowed = decision == "allow"
    || decision == "passthrough"
    || decision == "warn";
```

Add a test case for this: a "warn" observation should match when the
policy allows the request.

### 4. [DESIGN] Generate produces permits for denied observations — MEDIUM

**File:** `src/generate.rs:127-139`

`event_to_action_resource` extracts the action and resource from every
`NetworkRequest` event regardless of the `decision` field. Denied
requests produce permit rules in the generated policy.

If an observation session includes denied requests (e.g., the agent
tried to access a forbidden endpoint), the generated policy will
include permit rules for those denied actions. The generated policy is
strictly more permissive than the enforcement that produced the
observations.

For the `init --observe` workflow (observe first, then generate), this
may be intentional — the user wants a policy covering all observed
activity. But it's surprising: users expect the generated policy to
reflect what was *allowed*, not everything that was *attempted*.

**Suggested fix:** Filter observations by decision in `extract_rules`:

```rust
EventKind::NetworkRequest { decision, .. } => {
    // Only generate permits for requests that were actually allowed
    if decision == "deny" {
        continue;
    }
    // ... existing logic
}
```

Or make this configurable with a `--include-denied` flag. If the default
is to include denied requests, at minimum add a comment in the generated
policy marking rules derived from denied observations.

### 5. [DESIGN] Replay cannot reproduce header-based policy decisions — MEDIUM

**File:** `src/replay.rs:404-439` vs `src/policy.rs:136-187`

The live `evaluate` method includes HTTP headers as context attributes
(policy.rs:136-187):

```rust
let header_pairs: Vec<(String, RestrictedExpression)> = headers
    .iter()
    .map(|(k, v)| (k.to_lowercase(), RestrictedExpression::from_str(...)))
    .collect();
context_pairs.extend(header_pairs);
```

Replay's `build_http_context` does not include headers — only `host`,
`path`, `method`, and AWS attributes. The `ObservationEvent` struct
doesn't capture request headers, so replay has no data to work with.

**Impact:** A policy like this cannot be validated by replay:

```cedar
permit(
  principal,
  action == Action::"http:GET",
  resource
) when { context.authorization like "Bearer*" };
```

Live enforcement would allow (header present), but replay would deny
(no `authorization` context attribute → condition fails). The mismatch
is reported as a policy problem, but it's actually a data gap.

**Suggested fix:** This is a design limitation of the observation model
(ER-5 noted that observations capture decisions but not request metadata
beyond method/host/path). Two options:

1. **Document the limitation** in the replay output. When replay detects
   a deny that the observation shows as allow, note that header-based
   conditions may cause false mismatches.
2. **Extend the observation model** to optionally capture request headers
   (opt-in, since headers may contain sensitive data like auth tokens).
   Then populate them in replay context.

Option 1 is practical for v0.3; option 2 is a future enhancement.

### 6. [DESIGN] Path collapsing may over-collapse year-like numbers — MEDIUM

**File:** `src/generate.rs:254-256`

```rust
fn is_long_numeric(s: &str) -> bool {
    s.len() > 3 && s.bytes().all(|b| b.is_ascii_digit())
}
```

The threshold of 4+ digits catches legitimate path segments that happen
to be numeric, most commonly API versions and years:

- `/api/v2024/users` → `/api/*/users` (year collapsed)
- `/data/2026/03/report` → `/data/*/03/report` (date year collapsed,
  but month "03" is only 2 digits — inconsistent)
- `/repos/org/repo/issues/1234` → `/repos/org/repo/issues/*` (correct
  — issue numbers are dynamic IDs)

The 4-digit threshold is a reasonable heuristic for typical REST APIs
(most path segments with 4+ digits are IDs). Year-like segments in
paths are uncommon enough that false positives are rare. But the
wildcard annotation comment preserves the original value, so a reviewer
can spot and correct the over-collapse.

**Suggested fix:** Consider raising the threshold to 5+ digits to avoid
year-like false positives (years 2000-2099 are 4 digits, IDs are
usually 5+ digits). Or add a short allowlist of common numeric path
segments to preserve: `["2024", "2025", "2026", ...]` — but this ages
poorly.

A pragmatic approach: leave the threshold at 4 but mention the year
caveat in the generated policy header comment.

### 7. [QUALITY] Path collapsing doesn't detect short hex IDs — LOW

**File:** `src/generate.rs:226-228`

The dynamic segment detection covers UUIDs (36 chars), SHA-1 hashes
(40 hex chars), and long numerics (4+ digits). It does not detect:

- **Short hex commit prefixes**: 7-8 character hex strings like
  `a1b2c3d` (common in GitHub API paths for commits)
- **Short hash IDs**: 12-character hex Docker container IDs
- **Base64 tokens**: JWT segments or API keys in path positions

Short hex detection is risky (high false positive rate — `"deadbeef"`
is both a valid hex string and a plausible path segment), so the
current conservative approach is reasonable.

**Suggested fix:** No immediate change needed. If short hex IDs cause
problems in practice, add detection for hex strings of length 7-12 that
also contain at least one digit (to distinguish from pure-alpha words).

### 8. [QUALITY] Duplicated `read_observations` function — LOW

**File:** `src/generate.rs:82-102`, `src/replay.rs:159-179`

Both modules contain identical `read_observations` implementations:
open file, read lines, skip blank lines, parse JSON, collect into
`Vec<ObservationEvent>`. The only difference is the error message
text ("invalid JSON" vs "parse error").

**Suggested fix:** Extract to a shared function in `src/observe.rs`
(which owns the `ObservationEvent` type):

```rust
// observe.rs
pub fn read_observation_log(path: &Path) -> anyhow::Result<Vec<ObservationEvent>> { ... }
```

Both `generate.rs` and `replay.rs` call the shared function. This
ensures consistent error handling and makes the log-reading code the
responsibility of the observation module.

### 9. [QUALITY] `generate` and `replay` disagree on error strictness for malformed lines — LOW

**File:** `src/generate.rs:96-97`, `src/replay.rs:173-174`

Both `read_observations` functions treat malformed JSON as a fatal error
(return `Err`). This is correct for replay (you want to know if the log
is corrupt before drawing conclusions about policy coverage). But for
generate, a more lenient approach might be better — skip malformed lines
with a warning rather than aborting, since generate only needs the
parseable events.

Currently, a single corrupt line in a large observation log blocks both
policy generation and replay entirely. For long-running sessions where
the last line may be truncated (process killed mid-write), this is
particularly annoying.

**Suggested fix:** For `generate`, consider a lenient mode that skips
unparseable lines with a warning:

```rust
match serde_json::from_str::<ObservationEvent>(trimmed) {
    Ok(event) => events.push(event),
    Err(e) => eprintln!("warning: skipping line {}: {e}", line_num + 1),
}
```

Keep `replay` strict — correctness matters more there.

### 10. [QUALITY] No end-to-end test: generate → replay round-trip — LOW

**File:** (missing test)

There is no test that generates a policy from observations and then
replays the same observations against the generated policy to verify
all events match. This round-trip property — generate a policy from
log L, then replay L against the policy yields zero mismatches — is
the fundamental correctness invariant of the observe-then-enforce
workflow.

The existing tests verify generate and replay independently:
- Generate tests check text output (correct actions, resource IDs,
  wildcards)
- Replay tests check evaluation results against hand-written policies

But no test connects the two. Finding 1 (wildcard policies are
non-functional) would have been caught by such a test.

**Suggested fix:** Add an integration test:

```rust
#[test]
fn generate_then_replay_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let events = vec![
        make_network_event("GET", "api.github.com", "/repos/org/repo", "allow"),
        make_network_event("POST", "api.github.com", "/repos/org/repo/issues", "allow"),
    ];
    let obs_path = write_observations(&dir, &events);
    let policy_path = dir.path().join("policy.cedar");
    let schema_path = dir.path().join("policy.cedarschema");

    generate::generate(&obs_path, &policy_path, &schema_path).unwrap();

    let result = replay::replay(&obs_path, &policy_path, None).unwrap();
    assert!(result.mismatches.is_empty(),
        "generated policy should match all source observations");
}
```

### 11. [DESIGN] Generated schema uses human-readable Cedar syntax, not JSON — LOW

**File:** `src/generate.rs:303-324`

The generated schema uses Cedar's human-readable schema language (e.g.,
`entity Agent;`, `action "http:GET" appliesTo { ... };`). This is the
correct format — Cedar supports both human-readable `.cedarschema` and
JSON schema formats, and the human-readable format is preferred for
authored policies.

However, the schema is minimal: it declares `Agent`, `Resource`, and
observed actions, but does not declare context attribute types. Without
context type declarations, schema validation in `Strict` mode won't
catch type errors in `when` clauses that reference context attributes.

**Suggested fix:** For a future enhancement, generate context attribute
declarations in the schema:

```
type HttpContext = {
    host: String,
    path: String,
    method: String,
    aws_service?: String,
    aws_region?: String,
};
```

This is low priority — the current schema is sufficient for action and
resource validation.

### 12. [DESIGN] `fs:mount` action in generate not matched by live policy engine — LOW

**File:** `src/generate.rs:185-189`, `src/policy.rs:529`

The generate module maps `Mount` events to `action = "fs:mount"`. But
the live policy engine's `build_fs_entities` only creates action entities
for `fs:read`, `fs:write`, `fs:create`, `fs:delete` — not `fs:mount`.

A generated policy containing `action == Action::"fs:mount"` would fail
during live evaluation because the `fs:mount` action entity doesn't
exist in the entity set built by `build_fs_entities`.

**Suggested fix:** Add `"fs:mount"` to the action list in
`build_fs_entities` (policy.rs:529):

```rust
for action in &["fs:read", "fs:write", "fs:create", "fs:delete", "fs:mount"] {
```

## Key Question Answers

**Does `generate` produce overly permissive policies (e.g., collapsing
too aggressively)?**

Yes, in two ways:

1. **Wildcard collapsing produces non-functional rules** (Finding 1).
   The collapsed paths with `*` are literal entity IDs that never match
   during live enforcement. If the user deploys the policy as-is, these
   rules silently do nothing — the policy is effectively missing coverage
   for any path that was collapsed. Whether this makes the overall policy
   more or less permissive depends on other rules, but the collapsed
   rules themselves are dead code.

2. **Denied observations generate permit rules** (Finding 4). The
   generator doesn't filter by decision, so denied requests produce
   permits. A policy generated from mixed allow/deny observations is
   strictly more permissive than the original enforcement.

**Does `generate` produce overly restrictive policies (e.g., not
collapsing enough, generating one rule per request)?**

No — deduplication works correctly. The `BTreeMap` keyed on
`(action, collapsed_resource)` ensures identical action+resource pairs
produce a single permit. Multiple requests to the same endpoint with
different dynamic IDs (UUIDs, etc.) collapse to one rule. The test
`duplicate_observations_produce_single_permit` validates this.

However, short hex IDs (7-8 char commit prefixes) are not collapsed,
which could produce one rule per commit in git-heavy API usage
(Finding 7).

**Does `replay` exactly match live enforcement, or are there context
differences?**

No — there are three context mismatches:

1. **FS context:** Live uses `Context::empty()`, replay provides `path`
   and `operation` (Finding 2).
2. **HTTP headers:** Live includes request headers in context, replay
   cannot because observations don't capture headers (Finding 5).
3. **Warn mode:** Live allows warned requests, replay treats "warn" as
   denied (Finding 3).

The HTTP entity hierarchy and resource ID construction is consistent —
replay imports `build_http_entity_hierarchy`, `build_fs_entities`, and
`build_proc_entities` from `policy.rs`, ensuring the entity model
matches. The H-CP-16 fix (referenced in the review checklist) likely
addressed entity construction alignment, but the context attributes
remain misaligned.

**Is the generated policy deterministic for the same input observations?**

Yes. The `extract_rules` function uses `BTreeMap<(String, String), ...>`
for rule collection and `BTreeSet<String>` for wildcard originals. BTree
collections iterate in sorted order, so the same input events always
produce the same output text, regardless of event ordering in the JSONL
file. The `generate_policy` function emits rules in BTreeMap iteration
order (sorted by (action, resource)), and wildcard annotations are sorted
by segment index and then by original value. This determinism is important
for diffing generated policies across observation sessions.

## Checklist Results

- [x] **Policy generation** — observation-to-Cedar translation is correct
  for non-wildcard paths. Action mapping covers all evaluable event types
  (http, fs, proc, mount). Resource ID format matches `policy.rs`. Schema
  is valid Cedar. **Critical gap:** Wildcard-collapsed rules are
  non-functional (Finding 1).
- [x] **Path collapsing** — UUID, long numeric, and SHA-1 detection is
  correct and well-tested. Wildcard annotation comments preserve original
  values for review. **Gap:** Collapsed paths produce literal `*` in
  entity IDs (Finding 1). Year-like numbers may over-collapse (Finding 6).
- [x] **Action mapping** — All evaluable event types are mapped: `http:*`
  for NetworkRequest, `fs:*` for FsAccess, `proc:exec` for ProcExec,
  `fs:mount` for Mount. Container lifecycle and PolicyViolation events
  are correctly skipped. **Gap:** `fs:mount` action not in live entity
  set (Finding 12).
- [x] **Generated policy readability** — Good: header comments explain
  provenance, wildcard annotations list original values, blank lines
  separate rules, actions and resources use consistent formatting.
- [~] **Replay engine** — Observation loading is correct with good error
  messages. Cedar context construction is thorough (host, path, method,
  AWS attributes for HTTP; path+operation for fs; command for proc;
  path+mode for mount). **Gap:** Context doesn't match live evaluation
  for fs/proc/mount (Finding 2). Missing headers for HTTP (Finding 5).
- [~] **Replay accuracy** — Matches live enforcement for simple HTTP
  policies (entity hierarchy is shared code). Diverges on: fs context
  (Finding 2), warn mode (Finding 3), header conditions (Finding 5).
- [x] **Edge cases** — Empty observations handled (returns 0/None with
  warning). Container-only observations produce no output. Blank lines
  in JSONL skipped. Missing/corrupt files produce clear error messages
  with line numbers.
- [x] **Open question: policy generation heuristics** — The collapsing
  heuristic (UUID/numeric/SHA → `*`) is a reasonable starting point but
  produces non-functional Cedar (Finding 1). The heuristic needs to
  generate `when` clauses or truncate to parent entities.
- [~] **Open question: observation volume / readability** — Deduplication
  is effective (BTreeMap). No observation volume limit or sampling. For
  large logs, all events are loaded into memory (`Vec<ObservationEvent>`)
  which could be a problem for very large files. Generated policies scale
  linearly with unique (action, resource) pairs, which is manageable.
