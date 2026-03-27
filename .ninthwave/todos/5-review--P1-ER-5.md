# Engineering Review: Observation Pipeline (P1-ER-5)

**Priority:** P1
**Source:** Post-v0.3 engineering review
**Depends on:** ER-4 (MITM review — observations originate from the proxy pipeline)
**Domain:** review
**Sequence:** 5 of 8

## Scope

Review `src/observe.rs` (946 lines), `src/watch.rs` (863 lines).

## Review Checklist

- [ ] Event types — are all observable actions captured (http, fs, proc)?
- [ ] Event schema — JSON structure, required fields, versioning
- [ ] Unix socket server — lifecycle, cleanup, reconnection handling
- [ ] Event delivery — backpressure, dropped events, ordering guarantees
- [ ] JSONL persistence — file rotation, disk space, atomic writes
- [ ] Watch formatting — color output, terminal width handling, filter support
- [ ] Watch connectivity — socket reconnection, graceful shutdown
- [ ] Performance — event serialization cost, socket throughput under load
- [ ] Error handling — socket errors, serialization failures, disk full

## Output

Write findings to `docs/reviews/ER-5-observation.md`. Review prior findings at `docs/reviews/ER-4-mitm-pipeline.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- What happens when `strait watch` connects mid-session — does it miss events or get a replay?
- Is the JSONL format stable enough for `generate` and `replay` to depend on?
- Are observation events emitted for denied requests, or only allowed ones?
- Could high event volume cause backpressure that slows the proxy pipeline?
