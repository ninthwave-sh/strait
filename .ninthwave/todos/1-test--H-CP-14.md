# Fix: Make launch integration tests actually run in CI (H-CP-14)

**Priority:** Critical
**Source:** design review of H-CP-7 (PR #36)
**Depends on:** -
**Domain:** test

The `tests/launch_integration.rs` tests silently pass when Docker or Alpine is unavailable. In CI (GitHub Actions), Docker is running but `alpine:latest` isn't pulled, so `docker_available()` returns false and all 4 tests exit early with no assertions — reporting "ok" without testing anything.

Current behavior:
```rust
if !docker_available().await {
    eprintln!("Skipping: Docker not available");
    return; // passes with zero assertions
}
```

Required behavior:
- Pull `alpine:latest` in CI setup (add `docker pull alpine:latest` step to `.github/workflows/ci.yml` before `cargo test`)
- Change the guard to use `#[ignore]` attribute or `panic!("Docker not available")` so skipped tests are visible in output, not silently passing
- Verify all 4 integration tests actually execute and pass in CI

**Test plan:**
- CI run shows all 4 launch integration tests executing (not skipping)
- Tests still skip gracefully on developer machines without Docker
- Add a CI step that verifies test count matches expected (catch future silent skips)

Key files: `.github/workflows/ci.yml` (add docker pull step), `tests/launch_integration.rs` (improve skip visibility)
