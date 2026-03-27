# Engineering Review: Templates & Integration Tests (P1-ER-8)

**Priority:** P1
**Source:** Post-v0.3 engineering review
**Depends on:** ER-1 through ER-7 (all findings inform test coverage assessment)
**Domain:** review
**Sequence:** 8 of 8

## Scope

Review `src/templates.rs` (203 lines), `tests/integration.rs` (3669 lines), `tests/launch_integration.rs` (398 lines).

## Review Checklist

- [ ] Template correctness — do built-in Cedar templates use the namespaced entity model?
- [ ] Template coverage — are there templates for all documented use cases?
- [ ] Integration test coverage — what code paths are exercised vs untested?
- [ ] Test isolation — no network access, no shared state, deterministic
- [ ] TLS echo server — does it accurately simulate real upstream behavior?
- [ ] Launch integration tests — do they test real container behavior or just mock it?
- [ ] Coverage gaps — cross-reference with findings from ER-1 through ER-7
- [ ] Test quality — are tests testing behavior (not implementation details)?
- [ ] Flakiness — timing-dependent tests, port conflicts, resource leaks
- [ ] CI reliability — do tests pass consistently across platforms?

## Output

Write findings to `docs/reviews/ER-8-templates-tests.md`. Review ALL prior findings at `docs/reviews/ER-*.md` before starting — cross-reference gaps found in ER-1 through ER-7 against test coverage.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Are there edge cases identified in ER-1 through ER-7 that lack test coverage?
- Do the integration tests cover the full observe→generate→enforce round-trip (success criteria #3)?
- Are the launch integration tests actually running containers in CI, or are they skipped?
- Is there a test for the Cedar entity model migration (old v0.1 policies rejected/migrated)?
