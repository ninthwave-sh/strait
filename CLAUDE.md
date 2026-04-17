# strait

Network policy layer for devcontainers — Cedar policy for outbound HTTP access with a container-scoped observe-then-enforce workflow. Rust + Tokio.

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

Note: the file list below reflects the current codebase (host-side proxy +
in-container gateway). The in-container rewrite (`docs/designs/in-container-
rewrite.md`) will delete several of these (`launch.rs`, `container.rs`) and
split the proxy into a new `strait-agent` crate. Update this section as the
rewrite lands.

- `src/main.rs` -- CLI entry point (clap): `proxy`, `launch`, `init`, `generate`, `test`, `watch`, `explain`, `diff`, `template` subcommands
- `src/config.rs` — unified TOML config (`strait.toml`) parsing
- `src/ca.rs` — session-local CA cert generation (rcgen)
- `src/policy.rs` — Cedar policy engine for HTTP actions, URL-derived resource hierarchy, and per-request evaluation
- `src/credentials.rs` — credential store: bearer tokens and AWS SigV4, env-var source, header injection
- `src/sigv4.rs` — AWS Signature Version 4 request signing
- `src/mitm.rs` — TLS termination, HTTP/1.1 keep-alive, request parsing, policy eval, credential injection, upstream forwarding
- `src/audit.rs` — structured JSON audit logging (session ID, decisions, latency)
- `src/container.rs` — Docker/Podman container management via bollard: lifecycle, gateway wiring, and CA trust injection
- `src/launch.rs` — `strait launch` orchestrator: observe/warn/enforce modes, proxy + container coordination
- `src/observe.rs` — observation pipeline: JSONL file + Unix socket streaming, versioned event schema
- `src/watch.rs` — `strait watch` colored real-time event viewer
- `src/generate.rs` — Cedar policy generation from observations, wildcard collapsing
- `src/replay.rs` — `strait test --replay` policy verification against observations
- `src/explain.rs` — human-readable Cedar policy summaries
- `src/diff.rs` — semantic Cedar policy diffing
- `src/templates.rs` — built-in network policy templates (GitHub, AWS, container sandbox)
- `src/health.rs` — health check HTTP endpoint
- `tests/integration.rs` — loopback integration tests (TLS echo server, no network)
- `tests/launch_integration.rs` — Docker-based container lifecycle tests

## Key Design Decisions

See `docs/designs/devcontainer-strategy.md` for the current architecture and
`docs/designs/in-container-rewrite.md` for the Phase 1-4 plan moving the data
plane from host to in-container. The bullets below reflect the target state.

- **Container-based sandboxing** -- Docker/Podman/OrbStack. Not kernel sandboxes
  (ESF, Seatbelt). Ships cross-platform, no special OS permissions.
- **Cedar over OPA** -- sub-ms evaluation, embeddable, no sidecar process.
- **Network-only Cedar model** -- `Action::"http:GET"`, `Action::"http:POST"`,
  `Action::"http:DELETE"` govern outbound HTTP policy.
- **Data plane inside the container, control plane on the host** -- the MITM
  proxy runs as root inside the container; the agent runs as a non-root user.
  The host runs `strait-host`, which owns rules, decisions, credentials, and
  the desktop UI, and serves many containers at once.
- **iptables REDIRECT at entrypoint** -- the container entrypoint installs
  iptables rules that redirect all outbound TCP to the local proxy, then drops
  privileges. No `HTTPS_PROXY` env var, no bypass path for tools that ignore
  proxy conventions.
- **Session-local CA** -- new CA cert generated on each startup by the
  in-container proxy. Trust injection happens entirely inside the container.
- **Credential injection on allow only** -- credentials live on the host.
  On allow, the in-container proxy fetches the credential over gRPC and
  injects it into the outbound request. Never persisted in the container.
- **Observe-then-enforce workflow** -- `--observe` -> `generate` -> `--warn`
  -> `--policy`. Solves policy paralysis.
- **No container orchestration in strait** -- `strait launch` is removed.
  Install via the devcontainer feature or bring-your-own-sandbox (sandcastle,
  hand-rolled Docker, Podman). Users keep the orchestration tool they already
  use; strait is the policy layer on top.
- **General-purpose tool** -- not ninthwave-specific. Standalone binary,
  separate repo.

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
