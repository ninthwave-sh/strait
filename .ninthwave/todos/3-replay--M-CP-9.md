# Feat: `strait test --replay` engine (M-CP-9)

**Priority:** Medium
**Source:** v0.3 container platform plan
**Depends on:** H-CP-3, H-CP-8
**Domain:** replay

Implement `strait test --replay <observations.jsonl> --policy <policy.cedar>` that replays every event in the observation log against the specified Cedar policy and reports mismatches.

For each event:
1. Reconstruct the Cedar request (principal, action, resource) from the observation event
2. Evaluate against the policy
3. Compare result to what was observed (allow/deny/passthrough)
4. Track: matches, mismatches, and events that can't be evaluated (e.g., container lifecycle)

Output format:
- Summary: "42/45 events match policy (3 mismatches)"
- For each mismatch: event details, observed decision, policy decision
- Exit code 0 on all match, 1 on any mismatch

**Test plan:**
- Unit test: observation log where all events match generated policy -> exit 0
- Unit test: observation log with one event that policy would deny -> exit 1 with mismatch details
- Unit test: observation log with corrupted line -> parse error with line number
- Unit test: invalid policy file -> clear error before replay starts
- Unit test: container lifecycle events (start/stop) are skipped gracefully (not evaluated)

Acceptance: `strait test --replay` exits 0 when policy matches all observed events. Mismatches are reported with enough detail to identify what changed. Corrupted logs produce clear errors.

Key files: `src/replay.rs` (NEW)
