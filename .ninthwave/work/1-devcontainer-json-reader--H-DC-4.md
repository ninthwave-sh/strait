# Feat: Read devcontainer.json as a first-class config source (H-DC-4)

**Priority:** High
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), Phase 2
**Depends on:** H-DC-3
**Domain:** devcontainer-json-reader
**Lineage:** c6993e46-8808-41a8-99b5-a7a5f6943681

Add a devcontainer.json parser that extracts the fields strait honors (`image`, `build.dockerfile`, `build.context`, `containerEnv`, `postCreateCommand`, `onCreateCommand`, `workspaceFolder`, `remoteUser`) into a typed config struct. Delete the existing `ContainerSpec` (`base_image` / `apt` / `npm` / `pip`) from `src/config.rs`; devcontainer.json becomes the canonical image source. The parser must reject `privileged: true`, `capAdd`, and unsafe `runArgs` with an error that names the field and points to the strategy doc. Warn and ignore `forwardPorts` and `mounts` (mounts are honored by the container runtime directly in M-DC-5).

**Test plan:**
- Add unit tests for the devcontainer.json parser covering minimal config (image only), build-based config, and full config with all honored fields
- Add negative tests for rejected fields: `privileged: true`, `capAdd`, unsafe `runArgs`. Each must produce an error that names the offending field
- Add a warning-emission test for `forwardPorts` and `mounts` on read
- Verify parsing tolerates devcontainer.json comments and trailing commas (jsonc)

Acceptance: A `parse_devcontainer(path)` function returns a typed struct with all honored fields populated. Rejected fields fail parsing with actionable errors. `forwardPorts` and `mounts` emit a warning but do not fail. The old `ContainerSpec` struct and its `apt`/`npm`/`pip` Dockerfile generation are deleted. `cargo test --all-features` and `cargo clippy --all-features -- -D warnings` pass.

Key files: `src/config.rs`, `src/container.rs`
