# Feat: Finish onboarding, notifications, and first consumer integration (M-PVT-8)

**Priority:** Medium
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** M-PVT-7
**Domain:** client-onboarding
**Lineage:** 7565ff51-f8eb-41b3-968c-95fab279ee2b

Finish the phase-1 experience by wiring native blocked-request notifications, certificate and proxy onboarding for local clients, and a documented first consumer path with `nono`. The result should prove the product works both as a general local proxy and as an external control surface for a real agent runtime.

**Test plan:**
- Run a manual end-to-end flow: route a `nono` or sample client session through Strait, block a request, act from the desktop notification, and verify the session unblocks
- Add automated smoke coverage for proxy environment generation or onboarding helpers and certificate path reporting
- Verify persisted rules survive daemon restart and apply to the next session with no manual policy edits

Acceptance: A new user can connect a real client, trust the proxy CA, receive a blocked-request notification, approve the minimal exception from the desktop flow, and repeat the same request in a new session using the persisted rule.

Key files: `README.md`, `examples/`, `src/ca.rs`, `src/main.rs`, `desktop/`
