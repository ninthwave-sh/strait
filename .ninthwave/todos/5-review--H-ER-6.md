# Engineering Review: Generation & Replay (H-ER-6)

**Priority:** high
**Source:** Post-v0.3 engineering review
**Depends on:** H-ER-2, H-ER-5
**Domain:** review
**Sequence:** 6 of 8

## Scope

Review `src/generate.rs` (742 lines), `src/replay.rs` (1246 lines).

## Review Checklist

- [ ] Policy generation — observation-to-Cedar translation correctness
- [ ] Path collapsing — ID segment detection (UUID, numeric), wildcard insertion
- [ ] Action mapping — are all observation event types mapped to Cedar actions?
- [ ] Generated policy readability — formatting, comments, grouping
- [ ] Replay engine — observation loading, Cedar context construction, evaluation
- [ ] Replay accuracy — does replay produce the same decisions as live enforcement?
- [ ] Edge cases — empty observations, observations with only denies, mixed event types
- [ ] Open question: policy generation heuristics (design doc item #1)
- [ ] Open question: observation volume / readability (design doc item #3)

## Output

Write findings to `docs/reviews/ER-6-generation-replay.md`. Review prior findings at `docs/reviews/ER-5-observation.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Does `generate` produce overly permissive policies (e.g., collapsing too aggressively)?
- Does `generate` produce overly restrictive policies (e.g., not collapsing enough, generating one rule per request)?
- Does `replay` exactly match live enforcement, or are there context differences (H-CP-16 was a fix for this)?
- Is the generated policy deterministic for the same input observations?
