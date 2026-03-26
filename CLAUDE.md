# strait

HTTPS proxy with Cedar policy evaluation, credential injection, and audit logging. Rust + Tokio.

## Development

```bash
cargo test --all-features      # run all tests
cargo clippy --all-features -- -D warnings  # lint (warnings are errors)
cargo fmt --check              # check formatting
cargo build --release          # release build (stripped, LTO)
```

## CI

The `CI` workflow (`.github/workflows/ci.yml`) runs on every PR and push to main:

- **test** job: `cargo test`, `cargo clippy -D warnings`, `cargo fmt --check`
- **build** job: cross-platform release builds (x86_64/aarch64 for Linux and macOS)

The `test` job is a required status check on `main` — PRs cannot merge until it passes.

## Architecture

- `src/main.rs` — CLI entry point (clap), config loading, proxy server startup
- `src/mitm.rs` — MITM request handler with Cedar policy evaluation
- `src/policy.rs` — Cedar policy engine (load, evaluate, authorize)
- `src/credentials.rs` — credential injection from TOML config
- `src/ca.rs` — session CA certificate generation for TLS interception
- `src/audit.rs` — structured JSON audit logging
- `tests/` — integration tests

## Conventions

- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- Rust 2021 edition, stable toolchain
- All clippy warnings treated as errors
- `cargo fmt` enforced in CI
