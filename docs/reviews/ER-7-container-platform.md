# ER-7: Container Platform Review

**Date:** 2026-03-28
**Modules:** src/container.rs (922 lines), src/launch.rs (837 lines)

## Summary

The container platform is well-architected with a clean separation of
concerns: `container.rs` handles the Docker API abstraction and
policy-to-config translation, while `launch.rs` orchestrates the full
startup sequence across three enforcement modes. The code is methodical
about fail-fast (Docker connectivity verified before any other setup),
has a good intermediate representation (`ContainerConfig`) that enables
thorough unit testing without Docker, and handles the trickiest
integration point (TTY passthrough with raw terminal mode + I/O piping)
correctly.

The most critical finding is a **container escape via direct IP
access** (Finding 1). The proxy is set via `HTTPS_PROXY` environment
variable, but Docker's default bridge network allows the container to
reach any IP address directly. A malicious agent can bypass the proxy
entirely by resolving hostnames itself and connecting to IP addresses
without going through `HTTPS_PROXY`. There is no `iptables` rule,
network namespace restriction, or DNS interception to prevent this.
The proxy is advisory, not enforced at the network layer.

The second major finding is **no bind-mount path validation** (Finding
2). Paths from Cedar policy are passed directly to Docker as
bind-mount strings without sanitization. A policy granting
`fs:read` on a path containing `..` components or symlinks could mount
unintended host directories into the container. The host path and
container path are always identical (`{path}:{path}:ro`), so a
path like `/project/../../etc/shadow` would mount the host's
`/etc/shadow` into the container.

Additional findings include: the `Drop` cleanup using `tokio::spawn`
may not execute if the runtime is shutting down (Finding 3); only
`HTTPS_PROXY` is set but not `HTTP_PROXY` or `http_proxy` (Finding 4);
no image pull behavior — images must pre-exist (Finding 5); SIGTERM
is not handled alongside SIGINT (Finding 6); and the
`extract_fs_permissions` function only evaluates candidate paths the
caller provides, not paths discovered from the policy (Finding 8).

Test coverage is solid: `container.rs` has 21 unit tests covering all
policy-to-config translation paths (fs:read→ro, fs:write→rw,
proc:exec→PATH, CA injection, proxy env var, edge cases). `launch.rs`
has 7 tests covering enforcement mode values, proxy context construction
for all three modes, and basic proxy integration. The tests correctly
avoid requiring a running Docker daemon by testing the pure `build_config`
function and proxy context builder.

## Findings

### 1. [SECURITY] Container can bypass proxy via direct IP access — HIGH

**File:** `src/container.rs:217-219`, `src/launch.rs` (all modes)

The container's network policy relies entirely on the `HTTPS_PROXY`
environment variable:

```rust
let mut env = vec![format!(
    "HTTPS_PROXY=http://host.docker.internal:{proxy_port}"
)];
```

But `HTTPS_PROXY` is advisory — programs are free to ignore it. A
malicious agent inside the container can:

1. Resolve a hostname to an IP address using the container's DNS
2. Open a direct TCP connection to that IP on port 443
3. Perform a TLS handshake directly with the upstream server
4. Exfiltrate data without any policy evaluation

Docker's default bridge network provides full outbound internet access.
No `iptables` rules, network namespace restrictions, or DNS interception
prevents the container from reaching arbitrary hosts.

**Impact:** In enforce mode, an agent that ignores `HTTPS_PROXY` can
access any internet host, completely bypassing Cedar policy enforcement.
The security model for network access is based on a cooperative
assumption — the agent must voluntarily use the proxy.

**Suggested fix:** Two complementary approaches:

1. **Network-level enforcement** (preferred for enforce mode): Configure
   Docker networking to route all container traffic through the proxy.
   Options include:
   - Custom Docker network with `--internal` flag + explicit proxy route
   - iptables/nftables rules in the container's network namespace that
     redirect port 443 traffic to the proxy
   - A network plugin or sidecar container that intercepts DNS and TCP

2. **Document the cooperative assumption** (practical for v0.3): Make
   it clear in documentation and `--help` that network enforcement
   depends on the agent honoring `HTTPS_PROXY`. This is acceptable for
   observe and warn modes (where the goal is visibility, not hard
   enforcement), but should be called out as a limitation of enforce
   mode.

A pragmatic v0.3 approach: add a warning to stderr when running in
enforce mode that network enforcement is advisory, and track
network-level enforcement as a v0.4 hardening item.

### 2. [SECURITY] Bind-mount paths not validated for traversal or symlinks — HIGH

**File:** `src/container.rs:185-193`

```rust
ContainerPermission::FsRead(path) => {
    binds.push(format!("{path}:{path}:ro"));
}
ContainerPermission::FsWrite(path) => {
    binds.push(format!("{path}:{path}:rw"));
}
```

Paths from `ContainerPermission` are used verbatim as Docker bind-mount
strings. There is no validation for:

- **Path traversal:** `../../etc/shadow` would mount host files
- **Symlinks:** A symlinked path could resolve to a sensitive host
  directory (e.g., `/project/data` → `/etc/`)
- **Absolute path enforcement:** Relative paths could be ambiguous
- **Sensitive path exclusion:** `/`, `/etc`, `/proc`, `/sys` could be
  mounted if the Cedar policy permits them

The upstream `extract_fs_permissions` in `policy.rs` only evaluates paths
it receives as candidates — it does not generate paths from the policy.
So the risk depends on what `candidate_paths` the caller passes to
`extract_fs_permissions`.

In `launch.rs:276`, the candidate paths are just `[cwd]`:

```rust
let candidate_paths = vec![cwd.to_string_lossy().to_string()];
```

This limits the current blast radius — only the working directory is
evaluated. But if this is extended to accept user-supplied paths or
paths extracted from Cedar policies, the lack of validation becomes
exploitable.

**Impact:** Currently low risk because the candidate path set is
hardcoded to `cwd`. Future risk is HIGH if the candidate set is
expanded without adding path validation.

**Suggested fix:** Add validation in `build_config`:

```rust
fn validate_bind_path(path: &str) -> anyhow::Result<()> {
    let canonical = std::fs::canonicalize(path)
        .with_context(|| format!("bind-mount path does not exist: {path}"))?;
    let canonical_str = canonical.to_string_lossy();

    // Reject sensitive host paths
    const FORBIDDEN: &[&str] = &["/proc", "/sys", "/dev", "/etc/shadow", "/etc/passwd"];
    for prefix in FORBIDDEN {
        if canonical_str.starts_with(prefix) {
            anyhow::bail!("bind-mount path '{path}' resolves to forbidden location: {canonical_str}");
        }
    }

    Ok(())
}
```

Canonicalize paths before passing them to Docker to resolve symlinks and
`..` components. Reject paths that resolve to sensitive host locations.

### 3. [BUG] Drop cleanup may silently fail during runtime shutdown — MEDIUM

**File:** `src/container.rs:493-511`

```rust
impl Drop for ContainerManager {
    fn drop(&mut self) {
        if let Some(name) = self.container_name.take() {
            let docker = self.docker.clone();
            tokio::spawn(async move {
                // ... remove container
            });
        }
    }
}
```

`tokio::spawn` inside `Drop` has two failure modes:

1. **Runtime already shutting down:** If the `ContainerManager` is
   dropped during tokio runtime shutdown (e.g., after `main` returns
   but before all destructors run), `tokio::spawn` panics with
   "cannot spawn on a shut-down runtime."

2. **Fire-and-forget loses errors:** The spawned task's result is never
   awaited. If the Docker API call fails, the container is orphaned
   with no indication.

The explicit `remove_container` method (line 424) is called in the happy
path before `Drop` runs (line 185, 376), so `Drop` is primarily a
safety net for abnormal exits. But in those cases (panic, SIGKILL), the
`tokio::spawn` may not execute at all.

**Impact:** Containers may be orphaned if strait panics or is killed.
The `auto_remove=false` setting (used for reliable exit code capture)
means Docker won't clean up automatically.

**Suggested fix:** Two improvements:

1. Guard the `tokio::spawn` with a runtime check:
   ```rust
   if let Ok(handle) = tokio::runtime::Handle::try_current() {
       handle.spawn(async move { /* ... */ });
   }
   ```

2. Consider using a unique container label (e.g., `strait.session=<uuid>`)
   and documenting a cleanup command:
   `docker rm -f $(docker ps -aq --filter label=strait.session)`

### 4. [QUALITY] Only HTTPS_PROXY set, missing HTTP_PROXY and lowercase variants — MEDIUM

**File:** `src/container.rs:217-219`

Only `HTTPS_PROXY` (uppercase) is set. Many tools and runtimes check
different proxy environment variables:

| Variable | Used by |
|---|---|
| `HTTPS_PROXY` | curl, wget, Go, Python requests |
| `https_proxy` | curl, Python requests, some Java |
| `HTTP_PROXY` | curl, wget (for http:// URLs) |
| `http_proxy` | curl, Python requests |
| `ALL_PROXY` | curl, some Node.js libraries |

Since strait's proxy only handles CONNECT (HTTPS), `HTTP_PROXY` is less
critical. But the lowercase `https_proxy` is important — some tools
(notably Python's `requests` library and some Java HTTP clients) only
check the lowercase form.

**Impact:** Some tools inside the container may not use the proxy because
they check `https_proxy` (lowercase) instead of `HTTPS_PROXY`.

**Suggested fix:** Set both cases:

```rust
let mut env = vec![
    format!("HTTPS_PROXY=http://host.docker.internal:{proxy_port}"),
    format!("https_proxy=http://host.docker.internal:{proxy_port}"),
];
```

Consider also setting `HTTP_PROXY`/`http_proxy` to the same value so
that plain HTTP requests are also captured in observe mode (currently
they would bypass the proxy entirely).

### 5. [DESIGN] No automatic image pull — images must pre-exist locally — MEDIUM

**File:** `src/container.rs:333-338`

When the image is not found locally, the error message suggests manual
pulling:

```rust
if msg.contains("No such image") || msg.contains("not found") {
    anyhow::anyhow!(
        "image '{}' not found — try pulling it first: docker pull {}",
        config.image, config.image,
    )
}
```

Docker's CLI auto-pulls missing images, so users will expect the same
behavior. Having to manually pull before running `strait launch` is
friction, especially for first-time users following documentation that
says "run `strait launch --observe alpine sh`."

**Impact:** First-time users hit a confusing error and have to
run a separate `docker pull` command.

**Suggested fix:** Add an automatic pull with progress feedback:

```rust
// Try to pull the image if it doesn't exist locally
if let Err(e) = self.docker.inspect_image(&config.image).await {
    eprintln!("Pulling image {}...", config.image);
    use futures_util::StreamExt;
    let mut stream = self.docker.create_image(
        Some(bollard::image::CreateImageOptions {
            from_image: config.image.clone(),
            ..Default::default()
        }),
        None, None,
    );
    while let Some(result) = stream.next().await {
        result.context("failed to pull image")?;
    }
}
```

Add a `--no-pull` flag to skip automatic pulling for offline or
air-gapped environments.

### 6. [QUALITY] SIGTERM not handled — only ctrl_c (SIGINT) — MEDIUM

**File:** `src/launch.rs:162-176, 354-366`

```rust
let ctrl_c = tokio::signal::ctrl_c();
tokio::select! {
    result = run_future => { result? }
    _ = ctrl_c => {
        eprintln!("\nInterrupted — cleaning up...");
        container_mgr.stop_container().await.ok();
        130
    }
}
```

Only `ctrl_c` (SIGINT) triggers graceful cleanup. SIGTERM — the
standard signal sent by process managers, `docker stop`, `kill`,
systemd, and Kubernetes — is not handled. If strait receives SIGTERM:

1. The tokio runtime is dropped abruptly
2. `stop_container` is never called
3. The `Drop` impl tries `tokio::spawn` which may fail (Finding 3)
4. The container is orphaned

**Impact:** Container cleanup fails when strait is terminated by
a process manager (systemd, Docker, supervisord, CI systems that
send SIGTERM before SIGKILL).

**Suggested fix:** Handle SIGTERM alongside SIGINT:

```rust
#[cfg(unix)]
let mut sigterm = tokio::signal::unix::signal(
    tokio::signal::unix::SignalKind::terminate()
)?;

tokio::select! {
    result = run_future => { result? }
    _ = ctrl_c => { /* cleanup */ }
    #[cfg(unix)]
    _ = sigterm.recv() => { /* same cleanup */ }
}
```

### 7. [DESIGN] Observe mode grants full cwd write access without warning — MEDIUM

**File:** `src/launch.rs:128-133`

```rust
let policy = ContainerPolicy {
    permissions: vec![ContainerPermission::FsWrite(
        cwd.to_string_lossy().to_string(),
    )],
};
```

In observe mode, the working directory is mounted read-write with no
confirmation or warning. If a user runs `strait launch --observe` from
their home directory or a directory containing sensitive files, the
containerized agent has full write access to everything in that tree.

The warn and enforce modes properly derive permissions from Cedar policy
and warn when the cwd is not mounted (line 286-303). But observe mode
skips all policy evaluation and silently grants write access.

**Impact:** Users running observe mode from a broad directory (home,
repo root with secrets) give the agent more access than intended. Since
observe mode is the recommended starting point ("observe first, then
generate policy"), this affects the common onboarding path.

**Suggested fix:** Print a warning in observe mode:

```rust
eprintln!(
    "Warning: observe mode mounts {} read-write (the agent can modify files)",
    cwd.display()
);
```

Consider also supporting a `--mount` flag to explicitly specify which
paths to mount in observe mode, rather than defaulting to cwd.

### 8. [DESIGN] extract_fs_permissions only evaluates caller-supplied candidate paths — MEDIUM

**File:** `src/policy.rs:313-337`, `src/launch.rs:276`

```rust
// launch.rs:276
let candidate_paths = vec![cwd.to_string_lossy().to_string()];
let permissions = extract_fs_permissions(&engine, &candidate_paths, "agent");
```

`extract_fs_permissions` evaluates only the paths the caller provides as
candidates. It does not inspect the Cedar policy to discover which paths
are permitted. If a Cedar policy grants `fs:write` on `/data/output` but
the caller only passes `cwd` (`/project`), the `/data/output` mount is
silently omitted.

This means the effective filesystem permissions are the intersection of:
1. What the Cedar policy permits
2. What the caller passes as candidates

For the current implementation (only cwd), this is a significant
limitation: a Cedar policy that grants access to multiple directories
only results in the cwd being mounted.

**Impact:** Users writing Cedar policies that grant access to specific
directories outside cwd will be surprised that those paths are not
mounted. The policy "works" (Cedar evaluates correctly) but the
container doesn't have the mounts to use it.

**Suggested fix:** Two approaches:

1. **Parse fs: resource paths from the Cedar policy** to discover all
   paths the policy references, then evaluate each as a candidate.
   This is complex (requires Cedar policy AST inspection).

2. **Accept explicit mount paths via CLI** (simpler):
   ```
   strait launch --policy p.cedar --mount /data/output:rw -- npm test
   ```
   Let the user specify additional paths, validate them against the
   Cedar policy, and warn if a `--mount` path is denied by policy.

### 9. [QUALITY] CA entrypoint script uses sh -c with multi-arg passing edge case — LOW

**File:** `src/container.rs:239-245`

```rust
Some(vec![
    "/bin/sh".to_string(),
    "-c".to_string(),
    script,
    "--".to_string(),
])
```

This uses Docker's entrypoint as `["/bin/sh", "-c", "<script>", "--"]`.
When Docker combines entrypoint + cmd, the result is:

```
/bin/sh -c '<script>' -- <cmd args...>
```

With `sh -c`, the first argument after the script string becomes `$0`,
the second becomes `$1`, etc. The `--` becomes `$0` and the cmd args
become `$1`, `$2`, etc. The script ends with `exec "$@"` which expands
to `$1 $2 ...` — this correctly skips the `--` (which is `$0`) and
runs the command.

This is actually correct but subtle. The `--` serves as a throwaway
`$0` value so that `"$@"` captures only the real command arguments.
Worth a code comment explaining this, since it's a common source of
confusion.

**Suggested fix:** Add a comment:

```rust
// Docker combines entrypoint + cmd as:
//   /bin/sh -c '<script>' '--' <cmd...>
// In sh -c, '--' becomes $0, cmd args become $1..$N,
// and 'exec "$@"' runs cmd without the '--'.
```

### 10. [QUALITY] Container name uses UUID but no label for discovery — LOW

**File:** `src/container.rs:297`

```rust
let container_name = format!("strait-{}", uuid::Uuid::new_v4());
```

Containers are named `strait-<uuid>` but have no Docker labels. This
makes it difficult to:
- Find all strait-created containers: `docker ps --filter label=strait`
- Clean up orphaned containers programmatically
- Attribute containers to specific strait sessions

**Suggested fix:** Add labels to the container configuration:

```rust
let mut labels = std::collections::HashMap::new();
labels.insert("strait".to_string(), "true".to_string());
labels.insert("strait.session".to_string(), container_name.clone());

let docker_config = Config {
    labels: Some(labels),
    // ...
};
```

### 11. [DESIGN] host.docker.internal not universally supported — LOW

**File:** `src/container.rs:218`

```rust
"HTTPS_PROXY=http://host.docker.internal:{proxy_port}"
```

`host.docker.internal` is a Docker Desktop feature. It's not natively
available on:

- **Linux Docker Engine** (without Docker Desktop): Requires
  `--add-host host.docker.internal:host-gateway` in container config
- **Podman**: Uses a different mechanism (`host.containers.internal`)
- **OrbStack**: Supports it but via a different DNS resolver

The bollard API uses `Docker::connect_with_local_defaults()` which
connects to the Docker socket — this works with Docker Engine, Docker
Desktop, and OrbStack, but not necessarily Podman (which uses a
different socket path by default).

**Impact:** `strait launch` will silently fail (proxy unreachable from
container) on Linux Docker Engine without Docker Desktop, since the
container cannot resolve `host.docker.internal`.

**Suggested fix:** Add `host.docker.internal:host-gateway` to the
`HostConfig`:

```rust
let host_config = HostConfig {
    binds: /* ... */,
    auto_remove: Some(config.auto_remove),
    extra_hosts: Some(vec!["host.docker.internal:host-gateway".to_string()]),
    ..Default::default()
};
```

This is a no-op on Docker Desktop (where the DNS name already resolves)
and adds the required mapping on Linux Docker Engine.

### 12. [QUALITY] auto_remove=false containers not cleaned up on all error paths — LOW

**File:** `src/launch.rs:139, 317`

Both `run_launch_observe` and `run_launch_with_policy` set
`config.auto_remove = false` for reliable exit code capture, then
explicitly call `container_mgr.remove_container()` in the happy path.

But if an error occurs between `create_container_from_config` (which
creates the container) and `remove_container` (which cleans up), the
container is orphaned. Error paths include:

- `start_container` failure (inside `attach_and_wait`)
- Attach failure
- I/O errors during TTY piping

The `Drop` impl (Finding 3) is the safety net, but it has its own
reliability issues.

**Suggested fix:** Use a scope guard pattern:

```rust
let container_id = container_mgr.create_container_from_config(&config).await?;
// Ensure cleanup even if subsequent steps fail
scopeguard::defer! {
    // Best-effort cleanup — remove_container is async, so use a
    // blocking runtime for the guard
}
```

Or restructure to ensure `remove_container` is called in a `finally`
equivalent (e.g., wrap the main logic in a helper function and clean
up in the caller regardless of result).

### 13. [QUALITY] No container resource limits (CPU, memory) — LOW

**File:** `src/container.rs:299-307`

```rust
let host_config = HostConfig {
    binds: /* ... */,
    auto_remove: Some(config.auto_remove),
    ..Default::default()
};
```

The `HostConfig` uses defaults for all resource limits, which means
the container has unlimited CPU and memory access. A runaway agent
could consume all host resources.

**Suggested fix:** Add sensible defaults and make them configurable:

```rust
let host_config = HostConfig {
    memory: Some(2 * 1024 * 1024 * 1024), // 2 GB
    nano_cpus: Some(2_000_000_000),        // 2 CPUs
    // ...
};
```

Expose as CLI flags: `--memory 2g --cpus 2`.

### 14. [DESIGN] Container image strategy question — design decision needed — LOW

**File:** design consideration, not a code bug

The default image is `alpine:latest` (launch.rs:65). Key questions:

1. **Base image choice:** Alpine is minimal (5 MB) but uses musl libc,
   which can cause compatibility issues with some binaries. For an
   agent sandbox, a Debian-slim or Ubuntu base might be more compatible.

2. **Image tagging:** Using `:latest` is non-reproducible. Consider
   pinning to a specific digest or version tag for deterministic
   behavior.

3. **Pre-built strait image:** For the best UX, consider publishing
   a `ghcr.io/strait-sh/sandbox:v0.3` image that includes common
   tools (git, curl, node, python) and pre-configured CA trust.
   This would eliminate the CA entrypoint script for the common case.

4. **Image allow-listing:** In enforce mode, should the Cedar policy
   be able to restrict which images can be used? Currently any image
   can be specified via `--image`.

**Suggested approach for v0.3:** Keep `alpine:latest` as default,
document the image requirements (must have `/bin/sh` for CA injection),
and defer the pre-built image and image allowlisting to v0.4.

## Key Question Answers

**Is cleanup reliable on SIGTERM/SIGINT — are containers orphaned if
strait crashes?**

Partially. SIGINT (Ctrl+C) triggers graceful cleanup via `tokio::select!`
— `stop_container` is called, then `remove_container`. But:

- **SIGTERM is not handled** (Finding 6). Process managers that send
  SIGTERM skip the cleanup path entirely.
- **The `Drop` safety net is unreliable** (Finding 3). `tokio::spawn`
  in `Drop` may fail if the runtime is shutting down.
- **SIGKILL cannot be caught** (by design). A `kill -9` always orphans
  the container.
- **Panics** may or may not run destructors (depends on panic strategy).
- **auto_remove=false** means Docker won't clean up either.

Net: cleanup is reliable for normal Ctrl+C termination and clean exits.
It is unreliable for SIGTERM, panics, and crashes. Containers will be
orphaned in those cases. Adding SIGTERM handling (Finding 6) and Docker
labels (Finding 10) would cover most real-world scenarios.

**Can a malicious agent inside the container bypass the proxy (e.g.,
direct IP access)?**

Yes (Finding 1). The proxy is enforced only via `HTTPS_PROXY`
environment variable, which is advisory. The container runs on Docker's
default bridge network with full outbound internet access. A malicious
agent can:

1. Resolve hostnames to IPs (DNS is not intercepted)
2. Open direct TCP connections to any IP on any port
3. Perform TLS handshakes directly with upstream servers
4. Exfiltrate data without the proxy seeing it

This is a fundamental architectural limitation for enforce mode. For
observe and warn modes (where the goal is visibility into cooperative
agents), the advisory proxy is acceptable. For enforce mode, network-
level enforcement (iptables, custom Docker network) is needed.

**Does the bind-mount translation handle symlinks, relative paths, or
path traversal?**

No (Finding 2). Paths from `ContainerPermission` are used verbatim.
No `canonicalize()`, no `..` rejection, no symlink resolution. The
current blast radius is limited because `launch.rs` only passes `cwd`
as a candidate path, but the `container.rs` API accepts any path string.

**Are the bollard API calls compatible with Podman and OrbStack, or
Docker-only?**

Mostly Docker-only (Finding 11):

- **bollard** connects via `Docker::connect_with_local_defaults()` which
  tries `/var/run/docker.sock` on Linux and the Docker Desktop socket on
  macOS. Podman uses `/run/user/<uid>/podman/podman.sock` by default.
- **`host.docker.internal`** is a Docker Desktop DNS name. It's not
  available on Linux Docker Engine (needs `extra_hosts` config) or
  Podman (`host.containers.internal`).
- **OrbStack** is compatible — it emulates the Docker socket and
  supports `host.docker.internal`.
- **Podman** support would require: different socket path detection,
  different hostname resolution, and testing the bollard API
  compatibility layer.

## Checklist Results

- [~] **Container lifecycle** — create, start, stop, remove work
  correctly in the happy path. `build_config` is well-tested. Fail-fast
  Docker connectivity check is good. **Gaps:** Drop cleanup unreliable
  (Finding 3), SIGTERM not handled (Finding 6), error paths between
  create and remove can orphan containers (Finding 12).
- [~] **Bind-mount translation** — Cedar `fs:read`→`:ro` and
  `fs:write`→`:rw` mapping is correct and well-tested. **Gap:** No path
  validation for traversal, symlinks, or sensitive paths (Finding 2).
  Only cwd evaluated as a candidate (Finding 8).
- [x] **CA trust injection** — Well-implemented. Entrypoint script
  handles Debian, Alpine, and RHEL CA bundle locations. Falls back to
  CA-only bundle when no system bundle exists. Error check for missing
  CA PEM. Three trust env vars set (SSL_CERT_FILE, NODE_EXTRA_CA_CERTS,
  REQUESTS_CA_BUNDLE). Thorough test coverage (7 CA-specific tests).
- [~] **Proxy routing** — `HTTPS_PROXY` set correctly with
  `host.docker.internal:<port>`. **Gaps:** Missing lowercase
  `https_proxy` (Finding 4), `host.docker.internal` not universally
  available (Finding 11), network bypass possible (Finding 1).
- [x] **Image handling** — Default `alpine:latest`, `--image` override
  via CLI, clear error for missing image with pull suggestion. **Gap:**
  No auto-pull (Finding 5).
- [x] **TTY support** — Raw terminal mode with RAII guard (restored on
  drop). Attach before start (no missed output). Bidirectional I/O
  piping. Non-terminal (piped) stdin detected and handled.
- [x] **Observe mode** — Full cwd write access, no policy, observation
  stream attached, passthrough proxy (no MITM policy enforcement).
  Correct `mitm_all=true` for recording all traffic. **Gap:** No
  warning about broad write access (Finding 7).
- [x] **Warn mode** — Policy loaded and validated at startup. Bind-mounts
  restricted by Cedar `fs:` permissions. Proxy evaluates policy but
  allows all traffic, logging violations with `decision: "warn"`.
  PolicyViolation events emitted for denied cwd access.
- [x] **Enforce mode** — Same container config as warn. Proxy denies
  disallowed connections with 403. Bind-mounts restricted. **Gap:**
  Network enforcement is advisory only (Finding 1).
- [x] **Error handling** — Docker not running: clear error with
  "Check with: docker info" hint. Image not found: suggests `docker
  pull`. Connection refused: Docker daemon message. Good use of
  `anyhow::Context` for error chain.
- [~] **Security** — CA trust injection is solid. Proxy-based policy
  enforcement works for cooperative agents. **Critical gaps:** Container
  can bypass proxy (Finding 1), no mount path validation (Finding 2),
  no container resource limits (Finding 13).
- [~] **Container image strategy** — Default Alpine, CLI override, no
  policy control over image choice. See Finding 14 for design
  considerations.
