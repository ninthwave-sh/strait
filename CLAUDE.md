# strait

HTTPS policy proxy with Cedar evaluation, credential injection, and audit logging. Rust + Tokio.

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

- `src/lib.rs` — library crate root, re-exports public modules for integration tests
- `src/main.rs` — CLI entry point (clap subcommands: proxy, generate, init), CONNECT handler, observation mode
- `src/observe.rs` — unified observation events, traffic recording, Cedar policy generation from observed traffic
- `src/generate.rs` — Cedar policy generation from JSONL observation log files
- `src/ca.rs` — session-local CA cert generation (rcgen)
- `src/policy.rs` — Cedar policy engine: entity hierarchy from URL paths, per-request eval
- `src/credentials.rs` — TOML credential store, env-var source, header injection
- `src/mitm.rs` — TLS termination, request parsing, policy eval, credential injection, upstream forwarding
- `src/audit.rs` — structured JSON audit logging (session ID, decisions, latency)
- `tests/integration.rs` — loopback integration tests (TLS echo server, no network)

## Key Design Decisions

- **MITM only for credentialed services** — no global MITM. `should_mitm()` allowlists hosts.
- **Cedar over OPA** — sub-ms evaluation, embeddable, no sidecar process.
- **Session-local CA** — new CA cert generated on each startup. Caller must trust it explicitly.
- **Credential injection on allow only** — calling process never sees real secrets.
- **General-purpose tool** — not ninthwave-specific. Standalone binary, separate repo.

## Conventions

- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- Rust 2021 edition, stable toolchain
- All clippy warnings treated as errors
- `cargo fmt` enforced in CI
- Integration tests use loopback TCP/TLS (no external network access)
- Test helpers use a `NoVerify` cert verifier for echo server connections only
- Tracing via `tracing` crate, structured JSON to stderr

## Roadmap

- v0.1: GitHub API (bearer token, REST path matching) — in progress
- v0.2: AWS (SigV4) — deferred
- Future: macOS Keychain credential source, configurable MITM host list, health check endpoint
