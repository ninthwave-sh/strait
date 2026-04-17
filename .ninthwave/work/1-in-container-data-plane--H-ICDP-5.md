# Refactor: Remove host-side launch and container orchestration (H-ICDP-5)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 1
**Depends on:** H-ICDP-2, H-ICDP-3, H-ICDP-4
**Domain:** in-container-data-plane
**Lineage:** 6622f879-1db6-4c80-92b9-1ebd2355de8e
**Requires manual review:** true

Delete the host-side launch path now that the in-container data plane replaces it. Remove the `launch` clap subcommand from `src/main.rs`, delete `src/launch.rs` and `src/container.rs`, drop `bollard` from top-level `Cargo.toml`, and remove any `HTTPS_PROXY`-related env injection. Delete `tests/launch_integration.rs` and replace with the in-container tests from H-ICDP-2, H-ICDP-3, H-ICDP-4. Move anything still genuinely useful (for example the Docker test harness) to `tests/support/`. Update `README.md`, `CHANGELOG.md`, and `examples/claude-code/` to stop referencing the removed command.

**Test plan:**
- `cargo build --workspace` succeeds with `bollard` gone.
- `strait --help` no longer lists `launch`; `strait launch` returns a clap "unknown subcommand" error with a pointer to the devcontainer feature docs.
- Full test suite passes without the removed files.
- `grep -r "strait launch\|HTTPS_PROXY\|--network=none\|bollard" src/ examples/ README.md CHANGELOG.md` returns no hits outside historical CHANGELOG entries.

Acceptance: `src/launch.rs` and `src/container.rs` are deleted; `bollard` is not in `Cargo.toml`; `launch` is not a clap subcommand; no `HTTPS_PROXY` env handling remains in the top-level crate; CI is green; `examples/claude-code/` is either updated for the new flow or removed pending its replacement.

Key files: `src/main.rs`, `src/launch.rs` (delete), `src/container.rs` (delete), `Cargo.toml`, `tests/launch_integration.rs` (delete), `README.md`, `CHANGELOG.md`, `examples/claude-code/README.md`
