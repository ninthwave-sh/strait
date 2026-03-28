# Fix: Observation schema versioning + resilience (M-ER-13)

**Priority:** Medium
**Source:** ER-5 Findings 4-6, 8
**Depends on:** H-ER-1, H-ER-2, H-ER-3, H-ER-4, M-ER-5, M-ER-6, H-ER-7, M-ER-8, M-ER-9, M-ER-10
**Domain:** observation

Observation events have no schema version field, breaking forward compatibility on format changes. BufWriter is flushed per event (defeating buffering, adding syscall overhead). Mid-session watch connections miss all prior events with no catch-up mechanism. Serialization/write failures are silently dropped. Fix by adding a version field to observation events (non-breaking addition), implementing periodic flush (100ms interval or batch boundary), maintaining a bounded ring buffer of recent events for catch-up on new watch connections, and logging serialization/write errors.

**Test plan:**
- Test that observation events include a "version" field
- Test that BufWriter is not flushed on every single event (verify periodic flush behavior)
- Test that a new watch connection receives recent events from the ring buffer
- Test that serialization failures are logged (not silently dropped)

Acceptance: Version field present in all events. Periodic flush instead of per-event. Watch catch-up works for recent events. Write errors logged.

Key files: `src/observe.rs`, `src/watch.rs`
