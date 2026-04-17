# strait

Unified agent policy platform — Cedar policy over network, filesystem, and process access. Container-based sandboxing with observe-then-enforce workflow. Rust + Tokio.

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

- `src/main.rs` — CLI entry point (clap): `proxy`, `launch`, `init`, `generate`, `test`, `watch`, `explain`, `diff`, `template` subcommands
- `src/config.rs` — unified TOML config (`strait.toml`) parsing
- `src/ca.rs` — session-local CA cert generation (rcgen)
- `src/policy.rs` — Cedar policy engine: namespaced entity model (`http:`, `fs:`, `proc:`), entity hierarchy from URL paths, per-request eval
- `src/credentials.rs` — credential store: bearer tokens and AWS SigV4, env-var source, header injection
- `src/sigv4.rs` — AWS Signature Version 4 request signing
- `src/mitm.rs` — TLS termination, HTTP/1.1 keep-alive, request parsing, policy eval, credential injection, upstream forwarding
- `src/audit.rs` — structured JSON audit logging (session ID, decisions, latency)
- `src/container.rs` — Docker/Podman container management via bollard: lifecycle, bind-mounts from Cedar policy, CA trust injection
- `src/launch.rs` — `strait launch` orchestrator: observe/warn/enforce modes, proxy + container coordination
- `src/observe.rs` — observation pipeline: JSONL file + Unix socket streaming, versioned event schema
- `src/watch.rs` — `strait watch` colored real-time event viewer
- `src/generate.rs` — Cedar policy generation from observations, wildcard collapsing
- `src/replay.rs` — `strait test --replay` policy verification against observations
- `src/explain.rs` — human-readable Cedar policy summaries
- `src/diff.rs` — semantic Cedar policy diffing
- `host/src/templates.rs` — built-in Cedar policy templates (GitHub, AWS, container sandbox)
- `host/src/presets.rs` — devcontainer presets + server-side policy preset library (container sessions opt in via `RegisterContainer.preset_ids`)
- `src/health.rs` — health check HTTP endpoint
- `tests/integration.rs` — loopback integration tests (TLS echo server, no network)
- `tests/launch_integration.rs` — Docker-based container lifecycle tests

## Key Design Decisions

- **Container-based sandboxing** — Docker/Podman/OrbStack. Not kernel sandboxes (ESF, Seatbelt). Ships cross-platform, no special OS permissions.
- **Cedar over OPA** — sub-ms evaluation, embeddable, no sidecar process.
- **Namespaced entity model** — `Action::"http:GET"`, `Action::"fs:read"`, `Action::"proc:exec"`. One Cedar policy governs all three domains.
- **Proxy on host, not in container** — stronger isolation. Agent can't tamper with the proxy.
- **Session-local CA** — new CA cert generated on each startup. Injected into container system CA bundle.
- **Credential injection on allow only** — agent never sees real secrets. Prevents exfiltration via prompt injection.
- **Cooperative network enforcement** — container routes via `HTTPS_PROXY`. Defense in depth, not hard boundary.
- **Observe-then-enforce workflow** — `--observe` → `generate` → `--warn` → `--policy`. Solves policy paralysis.
- **General-purpose tool** — not ninthwave-specific. Standalone binary, separate repo.

## Conventions

- Conventional commits: `feat:`, `fix:`, `refactor:`, `test:`, `docs:`, `chore:`
- Rust 2021 edition, stable toolchain
- All clippy warnings treated as errors
- `cargo fmt` enforced in CI
- Integration tests use loopback TCP/TLS (no external network access)
- Launch integration tests require Docker
- Test helpers use a `NoVerify` cert verifier for echo server connections only
- Tracing via `tracing` crate, structured JSON to stderr
- No AI slop signals in user-facing text (em dashes, flowery language). Keep prose direct and plain.
