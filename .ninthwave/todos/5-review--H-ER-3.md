# Engineering Review: Credentials (H-ER-3)

**Priority:** high
**Source:** Post-v0.3 engineering review
**Depends on:** H-ER-2
**Domain:** review
**Sequence:** 3 of 8

## Scope

Review `src/credentials.rs` (1079 lines), `src/sigv4.rs` (780 lines).

## Review Checklist

- [ ] Credential store — TOML parsing, env-var resolution, secret types (bearer, basic, SigV4)
- [ ] Credential matching — host matching, path matching, specificity rules
- [ ] Header injection — correct header names, no double-injection, no overwrite of existing headers
- [ ] SigV4 signing — canonical request, string-to-sign, signing key derivation, header construction
- [ ] SigV4 edge cases — chunked bodies, empty bodies, query string signing, regional endpoints
- [ ] Secret lifecycle — are secrets zeroized after use? Are they excluded from Debug/Display?
- [ ] Error handling — missing credentials, expired credentials, signing failures
- [ ] Security — timing attacks on credential lookup, credential leakage in logs/errors

## Output

Write findings to `docs/reviews/ER-3-credentials.md`. Review prior findings at `docs/reviews/ER-2-policy-engine.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Are credentials correctly scoped to specific hosts/paths, or can a misconfigured policy leak credentials to the wrong endpoint?
- Does SigV4 handle all AWS service quirks (S3 path-style, dualstack, FIPS)?
- Is the Debug redaction (H-CP-21) complete — are there any other paths where secrets could leak?
