# Feat: Observation stream through host control plane (M-HCP-5)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** H-HCP-2, H-HCP-3
**Domain:** host-control-plane
**Lineage:** 15b01014-a53b-43f0-b156-b70f8f30e471

Rewire the observation pipeline so it flows from each in-container proxy up to `strait-host` via `StreamObservations`. The host persists observations to `~/.local/share/strait/observations.jsonl` and broadcasts them to subscribed desktop sessions (and to `strait watch` CLI clients, if retained). Preserves the existing event schema and JSONL line format; adds session id and container registration id as top-level fields.

**Test plan:**
- Unit test: event schema round-trips through the new wire format unchanged.
- Integration test: two containers stream observations concurrently; host persists both and a single desktop subscriber receives an interleaved stream tagged by session id.
- Regression: `generate` and `replay` CLIs still work against the new on-disk format.

Acceptance: In-container proxy pushes observations upstream; `strait-host` writes them to disk and fans out to any number of subscribers. `strait generate` and `strait test --replay` (if retained) read the new format without changes to user-facing flags. Desktop shell can subscribe and receive live observation events tagged by session id.

Key files: `host/src/observations.rs`, `agent/src/observer.rs`, `proto/strait_host.proto`, `src/observe.rs` (move contents to host)
