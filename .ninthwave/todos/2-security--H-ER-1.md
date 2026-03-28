# Fix: Policy engine security -- header namespace + escape fix (H-ER-1)

**Priority:** High
**Source:** ER-2 Findings 1-2, ER-8 Finding 6
**Depends on:** None
**Domain:** security

Header values in HTTP requests can overwrite built-in Cedar context attributes (host, path, method), enabling policy bypass. The escape_cedar_string function misses control characters and unwrap() calls on RestrictedExpression::from_str panic on malformed input. Fix by namespacing all header context keys as `header:<name>`, escaping control chars (\n, \r, \t, \0), and replacing unwrap() with ? propagation across all 16 callsites in policy.rs and replay.rs. Update template .cedarschema files to reflect the new context attribute names. Emit warn!() tracing when a header key would have collided with a built-in attribute.

**Test plan:**
- Test that a request with a header named "path" does NOT override the actual URL path in Cedar context evaluation
- Test that control characters in header values are properly escaped and don't cause panics
- Test that RestrictedExpression::from_str errors propagate as Err (not panic) with a crafted invalid input
- Test that headers appear in context as "header:<name>" keys

Acceptance: No unwrap() calls remain on RestrictedExpression::from_str in policy.rs or replay.rs. Header context keys are namespaced. Control chars are escaped. Template schemas updated.

Key files: `src/policy.rs`, `src/replay.rs`, `templates/*.cedarschema`
