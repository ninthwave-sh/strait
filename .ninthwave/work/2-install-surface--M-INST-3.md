# Docs: Bring-your-own-sandbox install path (M-INST-3)

**Priority:** Medium
**Source:** `docs/designs/in-container-rewrite.md` Phase 3
**Depends on:** H-INST-1
**Domain:** install-surface
**Lineage:** b734df6d-af8d-4026-b2d3-5c1540159e75

Document how to wire strait into any container image without the devcontainer feature. Covers: copying `strait-agent` into the image, configuring the entrypoint wrapper, granting `CAP_NET_ADMIN`, bind-mounting `/run/strait/host.sock`, and choosing an agent user. Include a working `sandcastle` example that uses the Docker sandbox provider with strait. Document which sandboxes support CAP_NET_ADMIN (Docker yes, Podman yes, Vercel Sandbox unknown pending test).

**Test plan:**
- Follow the documented steps against a hand-rolled Dockerfile, end-to-end.
- Run the sandcastle example; confirm the agent container registers with a running `strait-host`.
- Document the Vercel Sandbox result (works or does not work) with the specific error if any.

Acceptance: `docs/bring-your-own-sandbox.md` exists with copy-paste-ready Dockerfile, entrypoint, and sandcastle snippets. Claude reviewer or CI can follow the doc and end up with a working session. `sandcastle-example/` checked in, either in this repo or linked from it.

Key files: `docs/bring-your-own-sandbox.md`, `examples/sandcastle/README.md`, `examples/sandcastle/main.ts`, `examples/sandcastle/Dockerfile`
