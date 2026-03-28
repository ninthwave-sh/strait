# Fix: Generate wildcard fix -- context.path like + schema (H-ER-7)

**Priority:** High
**Source:** ER-6 Findings 1, 4, 6; ER-8 Finding 5; CEO + Eng review decisions
**Depends on:** H-ER-1
**Domain:** correctness

Generated wildcard policies are non-functional -- Cedar treats * as a literal character in entity IDs, so collapsed rules like Resource::"host/repos/*/issues" silently never match. Additionally, generate produces permit rules for denied observations and over-collapses 4-digit year numbers. Fix by: (1) emitting `when { context.path like "/repos/*/issues" }` clauses for wildcard rules with resource truncated to deepest non-wildcard ancestor, (2) escaping literal * in paths as \* in like clauses, (3) filtering events with decision:"deny" from policy generation, (4) excluding 4-digit years (1900-2099) from is_long_numeric, (5) updating generate_schema to include context attributes (host, path, method) so generated schemas are consistent with generated policies. Add an E2E roundtrip test: generate policy from observations with dynamic segments, evaluate against new requests with different IDs, verify match.

**Test plan:**
- E2E: observe traffic with UUIDs in paths, generate policy, evaluate generated policy against requests with different UUIDs -- must match
- Test that literal * in a path segment is escaped as \* in the like clause
- Test that events with decision:"deny" are NOT included in generated policy
- Test that "2024" and "2025" path segments are NOT collapsed to wildcards
- Test that "123456" (6 digits) IS still collapsed
- Test that generated schema includes context: { host, path, method }

Acceptance: Generated wildcard policies match requests with different dynamic values. Denied events filtered. Years preserved. Schema includes context attributes. E2E roundtrip test passes.

Key files: `src/generate.rs`
