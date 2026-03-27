# Engineering Review: Policy Engine (P1-ER-2)

**Priority:** P1
**Source:** Post-v0.3 engineering review
**Depends on:** ER-1 (config review — policy loading depends on config)
**Domain:** review
**Sequence:** 2 of 8

## Scope

Review `src/policy.rs` (1921 lines).

## Review Checklist

- [ ] Cedar entity model — are `http:`, `fs:`, `proc:` namespaces correctly implemented?
- [ ] Entity hierarchy — do path hierarchies work correctly for wildcard matching?
- [ ] Policy evaluation — are allow/deny decisions correct for edge cases?
- [ ] Policy loading — file parsing, error reporting, hot-reload integration
- [ ] SIGHUP reload — is the reload atomic? Can a bad policy break a running proxy?
- [ ] Performance — entity construction cost, evaluation latency, caching
- [ ] Error handling — what happens with malformed policies, unknown actions, empty policy sets?
- [ ] Security — can a crafted policy bypass intended restrictions?

## Output

Write findings to `docs/reviews/ER-2-policy-engine.md`. Review ER-1 findings at `docs/reviews/ER-1-config-entry-point.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Is the entity hierarchy deep enough for real-world path patterns?
- How does the policy engine handle `forbid` rules — do they correctly override `permit`?
- Are there action types that should exist but don't (e.g., `http:PATCH`, `http:OPTIONS`)?
- Does the namespaced model correctly handle the v0.1→v0.3 migration?
