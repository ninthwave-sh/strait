# Feat: Decide mitmproxy adoption boundary (H-PVT-1)

**Priority:** High
**Source:** Pivot plan 2026-04-15 (`.opencode/plans/1776234011325-kind-engine.md`)
**Depends on:** None
**Domain:** mitm-adoption
**Lineage:** 6b734c2d-409c-401f-a83b-fe9e68a9ab2a

Run a short composition spike against `mitmproxy` and make the phase-1 backend decision explicit. The spike must answer request hold or retry feasibility, structured event streaming to a local control plane, once or session or persist rule expression, and packaging plus certificate onboarding tradeoffs. If `mitmproxy` stays, define the Rust or Python boundary clearly; if not, document why the current Rust core remains the long-term proxy path.

**Test plan:**
- Add an automated smoke path or scripted repro that intercepts one request through the spike adapter
- Verify the spike captures a blocked-request event and round-trips one decision back into the proxy path
- Confirm the checked-in decision doc answers all four questions from the pivot plan and names the chosen backend boundary

Acceptance: A checked-in spike doc and minimal prototype make the compose-vs-rebuild decision explicit, with concrete next-step boundaries for `src/mitm.rs` and any addon or bridge code.

Key files: `docs/architecture/mitmproxy-spike.md`, `src/mitm.rs`, `Cargo.toml`
