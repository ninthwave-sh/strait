# Engineering Review: Config & Entry Point (H-ER-1)

**Priority:** high
**Source:** Post-v0.3 engineering review
**Depends on:** none
**Domain:** review
**Sequence:** 1 of 8

## Scope

Review `src/config.rs` (1784 lines), `src/ca.rs` (195 lines), `src/main.rs` (740 lines), `src/lib.rs` (21 lines).

## Review Checklist

- [ ] Config parsing correctness — TOML deserialization, field validation, defaults
- [ ] Config error messages — are invalid configs caught early with clear errors?
- [ ] CA cert generation — key size, validity period, extension correctness
- [ ] CA cert lifecycle — is the session-local CA properly scoped and cleaned up?
- [ ] CLI argument parsing — clap definitions, conflicts, required args
- [ ] Entry point error handling — are startup failures reported clearly?
- [ ] Code quality — dead code, unnecessary clones, missing derives, pub visibility
- [ ] Security — secret handling in config, file permission checks, path traversal

## Output

Write findings to `docs/reviews/ER-1-config-entry-point.md` using this format:

```markdown
# ER-1: Config & Entry Point Review

**Date:** YYYY-MM-DD
**Modules:** src/config.rs, src/ca.rs, src/main.rs, src/lib.rs

## Summary

One-paragraph overall assessment.

## Findings

### 1. [CATEGORY] Short title — SEVERITY

**File:** `src/file.rs:123`

Description of the finding. What's wrong, why it matters, and suggested fix if obvious.

(Repeat for each finding.)

## Checklist Results

Copy the checklist from this todo and mark items pass/fail with notes.
```

Categories: **[BUG]** incorrect behavior, **[SECURITY]** security concern, **[QUALITY]** code quality / dead code, **[DESIGN]** architectural concern, **[MISSING]** coverage gap.

Severity: **HIGH** / **MEDIUM** / **LOW**.

## Key Questions

- Is the config schema documented anywhere besides code?
- Are there config combinations that silently produce wrong behavior?
- Does the CA cert meet browser/client requirements (key usage, basic constraints)?
