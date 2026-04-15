# Feat: Ship strait as a devcontainer feature (L-DC-7)

**Priority:** Low
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), Phase 3
**Depends on:** M-DC-5, H-CSM-5
**Domain:** devcontainer-feature-publish
**Lineage:** 48927dc6-cabe-4e18-b581-c4170c0afc2f
**Requires manual review:** true

Publish strait as a devcontainer feature at `ghcr.io/ninthwave-io/strait` following the devcontainer feature spec. The feature installs the gateway binary inside the container, registers the container with the host-side strait daemon (started via H-CSM-5 local control service), and configures the container's CA trust store for the session-local CA. The feature does NOT run the proxy inside the container: the proxy stays on the host for tamper resistance. Update `examples/claude-code/` with a devcontainer.json that uses the feature, demonstrating the end-to-end flow.

**Test plan:**
- Add CI job that builds and validates the feature per the devcontainer feature spec (`devcontainer-feature.json`, `install.sh`)
- Add an end-to-end test: spin up a container using the feature, verify it registers with the host daemon, make an HTTP request, verify the request flows through the host-side proxy
- Verify the feature install script is idempotent (safe to re-run)
- Verify the proxy binary is NOT installed inside the container (negative assertion)
- Manual dogfood: run the updated `examples/claude-code/` devcontainer end-to-end and confirm blocked-request + allow-session flow works

Acceptance: `ghcr.io/ninthwave-io/strait` is published as a devcontainer feature. Adding one block to a devcontainer.json installs the gateway, trusts the session CA, and registers with the host daemon. The proxy itself does not run inside the container. `examples/claude-code/devcontainer.json` demonstrates the feature and produces a working blocked-request flow when tested end-to-end.

Key files: `.devcontainer/feature/devcontainer-feature.json`, `.devcontainer/feature/install.sh`, `examples/claude-code/.devcontainer/devcontainer.json`, `.github/workflows/devcontainer-feature.yml`
