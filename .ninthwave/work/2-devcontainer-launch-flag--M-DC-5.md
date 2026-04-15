# Feat: Wire --devcontainer flag through the launch flow (M-DC-5)

**Priority:** Medium
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), Phase 2
**Depends on:** H-DC-4
**Domain:** devcontainer-launch-flag
**Lineage:** e6772f4d-b16f-4596-9b19-305600c9a776

Add `--devcontainer <path>` to the `strait launch` subcommand in `src/main.rs`. The flag takes the parser from H-DC-4 and drives the existing launch flow in `src/launch.rs`: image or build resolution, container creation with `--network=none`, honored mounts from devcontainer.json, the hardcoded `/workspace` replaced by the declared `workspaceFolder`, container user set from `remoteUser`, `containerEnv` merged with strait's session env, and `postCreateCommand` / `onCreateCommand` chained after CA trust injection but before the agent command. Emit a diagnostic at launch listing every mount inherited from devcontainer.json so users can see what their filesystem contract is.

**Test plan:**
- Add CLI test in `src/main.rs` for `--devcontainer` flag parsing (argument presence, missing path, invalid path)
- Add integration test in `tests/launch_integration.rs`: launch a fixture devcontainer.json end-to-end and verify image build, mount application, workspace folder, and remoteUser
- Verify `postCreateCommand` runs after CA trust is injected (chain order)
- Verify the mount diagnostic is emitted to stderr with all declared mounts
- Verify `strait launch` without `--devcontainer` still works using the default (minimal) path

Acceptance: `strait launch --devcontainer ./.devcontainer/devcontainer.json` launches a container built from devcontainer.json, honors `workspaceFolder`, `remoteUser`, `containerEnv`, and lifecycle commands, and applies declared mounts. The mount diagnostic lists every inherited mount. `--network=none` and the Unix-socket gateway remain enforced. Integration tests pass.

Key files: `src/main.rs`, `src/launch.rs`, `src/container.rs`, `tests/launch_integration.rs`
