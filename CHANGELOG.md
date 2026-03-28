# Changelog

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
