# Engineering Review: Container Platform (H-ER-7)

**Priority:** high
**Source:** Post-v0.3 engineering review
**Depends on:** H-ER-1, H-ER-2, H-ER-3, H-ER-4, H-ER-5, H-ER-6
**Domain:** review
**Sequence:** 7 of 8

## Scope

Review `src/container.rs` (922 lines), `src/launch.rs` (837 lines).

## Review Checklist

- [ ] Container lifecycle — create, start, wait, remove, cleanup on error/signal
- [ ] Bind-mount translation — Cedar `fs:read`→ro, `fs:write`→rw, path validation
- [ ] CA trust injection — entrypoint script, system CA bundle append, env vars
- [ ] Proxy routing — `HTTPS_PROXY` env var, host.docker.internal resolution
- [ ] Image handling — default image, `--image` override, pull behavior
- [ ] TTY support — interactive terminal forwarding, signal propagation
- [ ] Observe mode — full access, all events captured
- [ ] Warn mode — full access, log what policy would deny
- [ ] Enforce mode — restricted bind-mounts, proxy enforces policy
- [ ] Error handling — Docker not running, image not found, container crash
- [ ] Security — container escape vectors, mount path validation, env var leakage
- [ ] Open question: container image strategy (design doc item #2)

## Output

Write findings to `docs/reviews/ER-7-container-platform.md`. Review prior findings at `docs/reviews/ER-6-generation-replay.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Is cleanup reliable on SIGTERM/SIGINT — are containers orphaned if strait crashes?
- Can a malicious agent inside the container bypass the proxy (e.g., direct IP access)?
- Does the bind-mount translation handle symlinks, relative paths, or path traversal?
- Are the bollard API calls compatible with Podman and OrbStack, or Docker-only?
