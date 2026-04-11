# Feat: Introduce launch session registry and control socket (H-SES-1)

**Priority:** High
**Source:** Decomposition of interactive harness readiness plan 2026-04-11
**Depends on:** None
**Domain:** session-control
**Lineage:** 43b62d09-eb47-42a4-a7a0-2bdc024ad10e

Introduce a first-class launch session object and a local control socket for active `strait launch` runs. The session must own stable metadata -- session id, container id or name, mode, control socket path, and observation handle -- so later commands and future native frontends can target a running session. This item defines the versioned local control protocol and lifecycle, but not live policy mutation semantics.

**Test plan:**
- Add unit tests for session metadata creation, cleanup, and protocol parsing
- Add integration tests for `session.info`, `watch.attach`, and `session.stop`
- Verify session resources are removed on clean exit and interruption paths

Acceptance: Each launch session exposes a session id and local control socket and responds to `session.info`, `watch.attach`, and `session.stop` through a versioned protocol. Launch output prints enough information to target the session later. Session metadata remains valid for the life of the run and is cleaned up on exit.

Key files: `src/launch.rs`, `src/observe.rs`, `src/main.rs`
