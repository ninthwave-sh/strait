# Refactor: Retarget H-CSM-3 and H-CSM-4 at strait-host (H-HCP-6)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 2; supersedes local control service in H-CSM-5
**Depends on:** H-HCP-2
**Domain:** host-control-plane
**Lineage:** 4b6732f2-23bb-4919-bcc7-96f849b4fb0b

The previously-decided H-CSM-3 (hold-and-resume decisions) and H-CSM-4 (persist action) assumed a per-container local control service. Retarget both at the new `strait-host` control plane. Hold-and-resume uses `SubmitDecision` on the host RPC; persist writes into the host rule store with default or session scope as configured. Decision logs in `.ninthwave/decisions/2026-04-16T*--H-CSM-*.md` stay as historical context; this item records the new implementation home.

**Test plan:**
- Integration test: container A issues `SubmitDecision`; desktop (or CLI stub) responds `allow_session` within the timeout; next matching request from A is served from session cache without another RPC.
- Integration test: `persist` action writes to the default scope and survives `strait-host` restart.
- Integration test: hold timeout fires default-deny when no responder is connected.

Acceptance: Hold-and-resume and persist flow end-to-end through `strait-host` instead of any in-container control service. Existing test expectations from H-CSM-3 and H-CSM-4 decision logs still hold. A container without an attached desktop fails closed after the configured timeout. Persisted rules are reloaded after host restart.

Key files: `host/src/decisions.rs`, `host/src/persist.rs`, `agent/src/decision_client.rs`, `.ninthwave/decisions/2026-04-16T07-30-30Z--H-CSM-4.md` (reference), `src/decisions.rs` (delete or migrate)
