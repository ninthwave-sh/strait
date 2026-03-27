# Fix: Audit emit() should log on failure, not silently drop (H-CP-19)

**Priority:** High
**Source:** design review of PR #3
**Depends on:** -
**Domain:** audit

`AuditLogger::emit()` silently drops events when serialization or file write fails — no log, no error, no indication. For an audit system, completeness is the primary requirement.

Required:
- On serialization failure: `warn!` with the error and event type (not the full event, which may contain secrets)
- On file write failure: `warn!` with the IO error and file path
- On flush failure: same treatment
- Consider: increment a counter metric for dropped events (if observability is added later)

Do NOT change `emit()` to return `Result` — callers should not need to handle audit failures. The proxy should continue operating. But failures must be visible in the tracing output.

Also fix: `BufWriter` is flushed after every event, making the buffering pointless. Either remove the `BufWriter` wrapper (use raw `File`) or batch flushes on a timer/count threshold.

**Test plan:**
- Unit test: emit to a read-only file path, verify warn is logged (use `tracing_subscriber` test layer)
- Unit test: verify BufWriter is either removed or flush batching is implemented

Key files: `src/audit.rs` (emit method)
