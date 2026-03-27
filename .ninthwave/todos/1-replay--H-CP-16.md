# Fix: Replay engine should populate Cedar context (H-CP-16)

**Priority:** High
**Source:** design review of M-CP-9 (PR #29)
**Depends on:** -
**Domain:** replay

`strait test --replay` evaluates policies with `Context::empty()`, so any `when { context.path ... }`, `when { context.host ... }`, or `when { context.aws_service ... }` conditions in policies are silently ignored during replay. This gives false confidence — policies appear to match when context conditions would actually change the outcome.

Required:
- Reconstruct the Cedar context from observation event fields (host, path, method, headers where available)
- For HTTP events: populate `context.host`, `context.path`, `context.method`
- For fs/proc events: populate appropriate context fields
- Also fix the hardcoded `REPLAY_AGENT_ID = "agent"` — use the session ID from the observation log if available

**Test plan:**
- Replay a policy with `when { context.path like "/admin/*" }` against observations that include /admin paths — verify it evaluates correctly (not skipped)
- Replay with agent-specific policy — verify it uses the correct principal

Key files: `src/replay.rs` (context construction, agent ID)
