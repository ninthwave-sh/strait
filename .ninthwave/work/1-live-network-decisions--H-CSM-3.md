# Feat: Add live decision actions with hold-and-resume for container-backed sessions (H-CSM-3)

**Priority:** High
**Source:** Refocus plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`); amended per prior-art analysis 2026-04-16
**Depends on:** H-CSM-2
**Domain:** live-network-decisions
**Lineage:** d1bbae5b-fa0e-47c2-ae07-3e823a2b4f92
**Requires manual review:** true

Add control-plane methods that let a client deny, allow once, or allow for session against a specific blocked-request ID without restarting the launched container session. The runtime holds blocked requests open while awaiting a decision -- hold-and-resume is the only path, no block-and-retry fallback. Implementation: add a pending-decision map to `ProxyContext` keyed by blocked-request ID, where each entry holds a `tokio::sync::oneshot::Sender<Decision>`. When Cedar policy denies a request, instead of returning 403 immediately, the MITM handler emits the `BlockedRequest` event, registers a oneshot channel, and awaits the receiver with a configurable timeout (30s default). If a decision arrives via the control API, the handler either forwards the request upstream (allow) or returns 403 (deny). On timeout, deny by default. The request body is already fully buffered before policy eval (`mitm.rs:293-384`), so replaying on allow is straightforward.

**Test plan:**
- Add control-protocol tests for the new decision methods and payload validation in the launch session control module
- Add integration coverage in `tests/integration.rs` for allow-once, allow-session, explicit deny, and expired or unknown decision IDs
- Add hold-timeout test: a blocked request with no decision returns 403 after the configured timeout
- Add concurrent-request test: a held request on one connection does not block new connections on other connections
- Verify that allow-session decisions cache correctly so the next matching request passes without a new hold

Acceptance: External clients can resolve a blocked request through the local control API. Blocked requests are held open (not failed) until a decision arrives or the timeout expires. Repeated matching requests honor the selected once or session semantics for the active container-backed session.

Key files: `src/launch.rs`, `src/main.rs`, `src/mitm.rs`, `src/config.rs`, `tests/integration.rs`
