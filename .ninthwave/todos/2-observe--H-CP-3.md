# Feat: Unified observation event model (H-CP-3)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** None
**Domain:** observe

Create the unified observation event model and stream infrastructure. Define event types covering network (existing audit events), container lifecycle (start, stop, mount), and filesystem/process actions. Events flow through a tokio broadcast channel and persist to JSONL file.

This is a NEW module alongside the existing `AuditLogger` (which stays untouched for v0.2 compatibility). The `AuditLogger` callers migrate to ObservationStream in H-CP-7a when the launch orchestrator wires everything together.

Event types:
- `network_request` -- HTTP request through proxy (method, host, path, decision, latency)
- `container_start` / `container_stop` -- lifecycle events
- `mount` -- bind-mount applied (path, mode: read-only/read-write)
- `fs_access` -- filesystem access observed (future, not MVP)
- `proc_exec` -- process execution observed (future, not MVP)

**Test plan:**
- Unit test: each event type serializes to valid JSON with correct fields
- Unit test: tokio broadcast channel delivers events to multiple subscribers
- Unit test: JSONL file writer produces parseable output
- Unit test: channel backpressure (slow consumer) drops oldest events with RecvError::Lagged
- Integration test: emit 100 events, verify all appear in JSONL file in order

Acceptance: `ObservationStream` struct with `emit()`, `subscribe()`, and `persist_to_file()`. Events are serde-serializable. File output is one JSON object per line. Channel handles slow consumers gracefully.

Key files: `src/observe.rs` (NEW)
