# Refactor: Narrow observation, generation, replay, and templates to HTTP-only (H-DC-3)

**Priority:** High
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), decision 4
**Depends on:** H-DC-2
**Domain:** observation-pipeline-narrowing
**Lineage:** af7d6df6-916b-40d8-8d46-5b28940e3701

Narrow the observation, generation, replay, and template pipelines to HTTP events only. Remove fs-read, fs-write, and proc-exec event variants from the observation schema in `src/observe.rs`; drop the corresponding wildcard-collapsing logic in `src/generate.rs` and the replay assertions in `src/replay.rs`. Rewrite `src/templates.rs` templates so every template ships as network-only Cedar policy. Depends on H-DC-2 having already removed the Cedar actions, so the downstream code can be deleted rather than patched around.

**Test plan:**
- Update unit tests in `src/observe.rs` for the narrowed event schema (only HTTP variant remains)
- Update `src/generate.rs` tests to confirm generation produces only `http:` rules from HTTP-only observations
- Update `src/replay.rs` tests to confirm replay against HTTP-only observations succeeds and fails loudly if fed pre-narrowing event fixtures
- Verify every template in `src/templates.rs` parses against the narrowed Cedar schema and expands to only `http:` actions
- Run the full integration suite to confirm no regressions in the observe-then-generate flow

Acceptance: `cargo test --all-features` passes. `src/observe.rs`, `src/generate.rs`, `src/replay.rs`, and `src/templates.rs` contain no references to `fs:` or `proc:` actions or fs/proc event variants. Every built-in template produces a policy that loads cleanly under the narrowed schema. The observe-generate-replay round trip works end-to-end on an HTTP-only fixture.

Key files: `src/observe.rs`, `src/generate.rs`, `src/replay.rs`, `src/templates.rs`, `templates/README.md`
