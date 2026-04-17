# Feat: Multi-container rule store (H-HCP-3)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** H-HCP-2
**Domain:** host-control-plane
**Lineage:** 9e788420-9b08-464a-af89-cde9d53d4bb7

Implement the persistent rule store in `strait-host`. Rules are scoped to one container session or to a default scope applied to all registered containers. Backing store is SQLite (via `rusqlite`) under `~/.local/share/strait/rules.db`. Schema supports rule text (Cedar), scope (session id or default), action (allow, deny, prompt), duration (once, session, persist), and TTLs for hold-and-resume bookkeeping. Exposes CRUD over gRPC `StreamRules` with a snapshot-plus-tail pattern.

**Test plan:**
- Unit test: SQLite schema migrations run cleanly on a fresh DB.
- Unit test: CRUD operations for session-scoped and default-scoped rules.
- Integration test: two simulated containers register, subscribe to `StreamRules`; a rule added at default scope is delivered to both; a rule added at container A's scope is delivered only to A.
- Edge case: concurrent writes from two containers do not corrupt the DB.

Acceptance: `strait-host` can persist and load rules across restarts. `StreamRules` sends an initial snapshot followed by live updates. Default-scope rules reach every registered container; session-scope rules reach only the owning container. Schema is forward-compatible (migration table in place for future changes).

Key files: `host/src/rule_store.rs`, `host/src/migrations/`, `host/tests/rule_store_integration.rs`
