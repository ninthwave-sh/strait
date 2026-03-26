# Feat: Health check HTTP endpoint (H-SV1-6)

**Priority:** High
**Source:** Strait v0.1 design — deliverable 5; eng review decisions
**Depends on:** H-SV1-1
**Domain:** proxy

Add a health check HTTP endpoint on a separate port, configured via `[health].port` in `strait.toml`. Omitting the `[health]` section disables the health check entirely. The endpoint binds to `127.0.0.1` only (eng review security decision — prevents information disclosure of proxy config to non-local clients).

Returns `200 OK` with JSON body containing: `status` ("healthy"), `session_id`, `uptime_seconds`, `policy_loaded` (bool), `credentials_loaded` (bool), `mitm_hosts` (array). The health handler reads from `Arc<ProxyContext>` — all state is immutable after startup, no locks needed.

If the health port is already in use at startup, log a warning and continue without the health check (don't crash the proxy). Use `hyper` (already a dependency) for the HTTP server.

**Test plan:**
- Unit test: health handler returns 200 OK with correct JSON fields
- Unit test: `policy_loaded` reflects whether a policy engine is configured
- Unit test: `credentials_loaded` reflects whether credentials are configured
- Unit test: `mitm_hosts` matches configured hosts
- Unit test: health check disabled when `[health]` section omitted from config

Acceptance: `curl http://127.0.0.1:<health_port>/` returns the JSON status body. Health check doesn't crash the proxy if the port is in use. Health check is disabled by default (requires explicit `[health]` config).

Key files: `src/health.rs` (new), `src/main.rs`
