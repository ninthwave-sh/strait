# Changelog

## Unreleased

### Removed

- `strait launch` orchestrator, along with the `strait session` and `strait service` command groups. Container lifecycle is now the user's responsibility; use the devcontainer feature (landing in a later phase), sandcastle, or direct `docker run`.
- `src/launch.rs` and `src/container.rs` modules. The host-side MITM proxy + Docker/Podman lifecycle code is retired in favor of the in-container data plane (`strait-agent`).
- `src/control.rs` local gRPC control service and the `strait watch` compatibility alias. The replacement lives in the host control plane (`strait-host`), landing in Phase 2 of the in-container rewrite.
- `bollard` dependency. strait no longer talks to Docker or Podman from the host.
- `HTTPS_PROXY` env injection inside managed containers. The new in-container data plane uses iptables REDIRECT instead; proxy env vars become a bypass surface rather than a security feature.
- `examples/claude-code/` (the host-launched Claude Code walkthrough). Replaced by `examples/claude-code-devcontainer/`, which is the bundled `claude-code-devcontainer` preset.
- `tests/launch_integration.rs` and `tests/control_service_integration.rs`. Integration coverage for the new flow lives under `agent/tests/` and `host/tests/`.

## v0.2.0

### Network isolation

- Containers run with `--network=none` for enforced network isolation
- New gateway binary (`strait-gateway`) routes container traffic through a bind-mounted Unix socket to the host proxy
- Gateway is a statically-linked musl binary with architecture detection for x86_64 and aarch64
- CI cross-compiles the gateway for linux/amd64 and linux/arm64

### HTTPS proxy

- Upstream connect timeout and response timeout, configurable via `strait.toml`

### CLI

- `--env` flag for `strait launch` to pass environment variables into containers
- `--config` flag for `strait launch` to enable credential injection in container mode
- `--no-tty` flag for `strait launch` to disable TTY allocation
- `proc:exec` policies now mount host binaries into the container

## v0.1.0

Initial release.

### Container sandboxing

- `strait launch` runs commands inside Docker/Podman containers with Cedar policy enforcement
- Three modes: `--observe` (record all activity), `--warn` (log violations), `--policy` (enforce)
- Filesystem access controlled via bind-mount restrictions derived from Cedar `fs:` policies
- Network traffic routed through built-in HTTPS proxy
- Session-local CA certificate generated on startup and injected into container trust store

### Cedar policy engine

- Namespaced entity model: `http:`, `fs:`, `proc:` actions in a single Cedar policy
- Sub-millisecond per-request policy evaluation
- Entity hierarchy from URL paths for fine-grained HTTP access control

### Policy workflow

- `strait init` - observe live traffic and generate starter policies
- `strait generate` - produce Cedar policy from observation logs with wildcard collapsing
- `strait test --replay` - verify policies against recorded observations
- `strait explain` - human-readable policy summaries
- `strait diff` - semantic Cedar policy diffing (permission-level, not text-level)
- `strait watch` - colored real-time event viewer via Unix socket
- `strait template` - built-in policy templates for common patterns (GitHub, AWS)

### HTTPS proxy

- TLS termination with HTTP/1.1 keep-alive
- Credential injection (bearer tokens, AWS SigV4) on allow decisions only
- Structured JSON audit logging with session IDs, decisions, and latency
- Health check endpoint

### Configuration

- Unified `strait.toml` configuration file
- SIGHUP config reload (Unix)
- Git-based policy polling
