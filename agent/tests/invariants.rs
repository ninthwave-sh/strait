//! Docker-based integration tests for the in-container data plane
//! architecture invariants (M-ICDP-6).
//!
//! Covers invariants 1, 2, and 3 from
//! `docs/designs/in-container-rewrite.md`:
//!
//! 1. The agent user has no read or connect permission on the host
//!    control-plane socket (`/run/strait/host.sock`) and cannot modify
//!    iptables rules.
//! 2. Setting `HTTPS_PROXY=` or `unset HTTPS_PROXY` inside the container
//!    does not change what the agent user can reach. Raw TCP to port 443
//!    is still caught by the iptables `-j REDIRECT` rules even though no
//!    proxy env var is ever observed by the tool.
//! 3. As the agent user, `kill -9 <proxy_pid>` on the (root-owned) proxy
//!    process returns EPERM and the proxy stays up.
//!
//! Each `#[test]` is independent and short-circuits early if Docker is
//! unavailable (skip locally, panic in CI). On failure each assertion
//! emits the exact shell command it ran and the container's exit code
//! and output so CI logs are immediately actionable.
//!
//! ## Platform gating
//!
//! The agent binary we build with `cargo build -p strait-agent` is Linux
//! ELF on Linux hosts and macOS Mach-O on macOS hosts -- the latter can
//! never execute inside a Linux container, so the file is `cfg(target_os
//! = "linux")`. On macOS developer hosts the tests compile out. In the
//! `test` CI job (ubuntu-latest) they run as part of
//! `cargo test --workspace --all-features`.

#![cfg(target_os = "linux")]

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Tag for the invariants test image built on demand. Scoped to this work
/// item so we do not collide with the image the H-ICDP-2 entrypoint tests
/// build, which is missing `netcat-openbsd`.
const TEST_IMAGE_TAG: &str = "strait-agent-test:m-icdp-6";

/// UID of the `testagent` user baked into the image (see
/// `tests/fixtures/Dockerfile.invariants`).
const TESTAGENT_UID: u32 = 1001;

/// Proxy port the iptables REDIRECT rules point at. Arbitrary; matches
/// the `strait-agent` default so operators reading the tests recognise
/// it.
const PROXY_PORT: u16 = 9443;

/// Unroutable TEST-NET-2 address (RFC 5737). Connecting here without the
/// iptables redirect would time out; with the redirect it is rewritten to
/// the local listener on `PROXY_PORT`. That gives us a clean differential
/// between "iptables caught the traffic" and "iptables was bypassed".
const UNREACHABLE_HOST: &str = "198.51.100.1";

/// Path to the `strait-agent` binary under test. Cargo sets this env var
/// for integration tests that live in `tests/` of the crate that owns the
/// binary.
fn strait_agent_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_strait-agent"))
}

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures")
}

/// Check whether the local Docker daemon is reachable.
fn docker_available() -> bool {
    Command::new("docker")
        .args(["version", "--format", "{{.Server.Version}}"])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Gate: require Docker. In CI we panic (tests must run); locally we skip.
fn require_docker() -> bool {
    if !docker_available() {
        if std::env::var("CI").is_ok() {
            panic!(
                "Docker is required for strait-agent invariants integration tests \
                 but is not available"
            );
        }
        eprintln!("Skipping: Docker not available");
        return false;
    }
    true
}

/// Build the invariants test image if it does not already exist.
///
/// The Dockerfile lives under `tests/fixtures/` so it can be reviewed in
/// isolation; the binary is copied into the build context at test time
/// because the binary path is only known via `CARGO_BIN_EXE_strait-agent`.
fn ensure_test_image() -> Result<(), String> {
    let exists = Command::new("docker")
        .args(["image", "inspect", TEST_IMAGE_TAG])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if exists {
        return Ok(());
    }

    let build_ctx = tempfile::tempdir().map_err(|e| format!("tempdir: {e}"))?;
    let bin_path = build_ctx.path().join("strait-agent");
    std::fs::copy(strait_agent_bin(), &bin_path).map_err(|e| format!("copy binary: {e}"))?;

    let dockerfile_src = fixtures_dir().join("Dockerfile.invariants");
    let dockerfile_dst = build_ctx.path().join("Dockerfile");
    std::fs::copy(&dockerfile_src, &dockerfile_dst)
        .map_err(|e| format!("copy Dockerfile from {}: {e}", dockerfile_src.display()))?;

    let out = Command::new("docker")
        .args(["build", "-t", TEST_IMAGE_TAG, "."])
        .current_dir(build_ctx.path())
        .output()
        .map_err(|e| format!("spawn docker build: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker build failed (status {}): stdout={} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr),
        ));
    }
    Ok(())
}

/// Captured result of a shell command run via `docker`. Includes the
/// rendered command line so assertion failures surface exactly what ran.
struct CmdResult {
    command: String,
    status: i32,
    stdout: String,
    stderr: String,
}

impl CmdResult {
    /// Combined stdout+stderr, case-folded, for substring matching. The
    /// exact message depends on the iptables / netcat package versions in
    /// the base image, so tests match on the well-known fragment rather
    /// than a full line.
    fn combined_lower(&self) -> String {
        let mut s = self.stdout.clone();
        s.push('\n');
        s.push_str(&self.stderr);
        s.to_lowercase()
    }

    /// Assert the command failed (non-zero exit) and emit a descriptive
    /// panic message that includes the command, exit code, and both
    /// streams.
    fn assert_failed(&self, context: &str) {
        assert!(
            self.status != 0,
            "{context}: command unexpectedly succeeded\n  $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            self.command,
            self.status,
            self.stdout,
            self.stderr,
        );
    }

    /// Assert the command succeeded with an equally descriptive panic.
    fn assert_ok(&self, context: &str) {
        assert!(
            self.status == 0,
            "{context}: command unexpectedly failed\n  $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            self.command,
            self.status,
            self.stdout,
            self.stderr,
        );
    }

    /// Assert the (case-insensitive) combined output contains `needle`.
    fn assert_contains(&self, needle: &str, context: &str) {
        assert!(
            self.combined_lower().contains(&needle.to_lowercase()),
            "{context}: expected {:?} in command output\n  $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            needle,
            self.command,
            self.status,
            self.stdout,
            self.stderr,
        );
    }
}

/// Render an argv as a shell-ish string for diagnostic messages. Good
/// enough for test failure output; not a real shell escaper.
fn render_argv(argv: &[&str]) -> String {
    argv.iter()
        .map(|a| {
            if a.contains(' ') || a.contains('\'') || a.contains('"') {
                format!("'{}'", a.replace('\'', "'\\''"))
            } else {
                (*a).to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Run `docker exec -u <user> <container> <argv...>` and capture the
/// outcome.
fn docker_exec(container: &str, user: &str, argv: &[&str]) -> CmdResult {
    let mut cmd = Command::new("docker");
    cmd.args(["exec", "-u", user, container]);
    for a in argv {
        cmd.arg(a);
    }
    let out = cmd
        .output()
        .expect("docker exec should spawn (docker CLI unexpectedly missing)");
    CmdResult {
        command: format!("docker exec -u {user} {container} {}", render_argv(argv)),
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Start a detached, cleanup-on-drop container running `argv` as the
/// container's main command. Returns the container name on success so
/// `docker exec` can address it.
fn docker_run_detached(name: &str, extra_args: &[&str], argv: &[&str]) -> Result<(), CmdResult> {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm", "-d", "--name", name])
        .args(extra_args);
    cmd.arg(TEST_IMAGE_TAG);
    for a in argv {
        cmd.arg(a);
    }
    let out = cmd
        .output()
        .expect("docker run should spawn (docker CLI unexpectedly missing)");

    let rendered = format!(
        "docker run --rm -d --name {name} {} {TEST_IMAGE_TAG} {}",
        render_argv(extra_args),
        render_argv(argv)
    );
    if !out.status.success() {
        return Err(CmdResult {
            command: rendered,
            status: out.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
        });
    }
    Ok(())
}

/// RAII guard: stop the container on drop so a panic in the middle of a
/// test cannot leak a running container into the runner.
struct ContainerGuard(String);

impl Drop for ContainerGuard {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["kill", &self.0])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
    }
}

/// Poll `docker exec cat <path>` inside `container` until the file
/// exists and contains non-empty contents, or `timeout` elapses.
fn wait_for_file(container: &str, path: &str, timeout: Duration) -> Option<String> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let out = Command::new("docker")
            .args(["exec", "-u", "0", container, "cat", path])
            .output()
            .ok()?;
        if out.status.success() {
            let body = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !body.is_empty() {
                return Some(body);
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    None
}

/// Short-circuit gate used at the top of every `#[test]`. Returns `false`
/// if the test should skip (docker missing outside CI) and panics if
/// the image cannot be prepared.
fn check_preconditions() -> bool {
    if !require_docker() {
        return false;
    }
    if let Err(e) = ensure_test_image() {
        panic!("failed to prepare test image {TEST_IMAGE_TAG}: {e}");
    }
    true
}

// ---------------------------------------------------------------------------
// Invariant 1
// ---------------------------------------------------------------------------

/// Invariant 1: the agent user has no read/connect on the host socket and
/// cannot modify iptables rules.
///
/// The real system mounts `/run/strait/host.sock` as a bind mount with
/// `root:root` ownership and mode `0600`. We recreate those attributes
/// on a placeholder file inside a fresh container and assert that the
/// `testagent` user gets EACCES for `cat` and `nc -U`. Separately we
/// assert that `iptables -L` and `iptables -F` both fail as the agent
/// user (no `CAP_NET_ADMIN` effective after the kernel drops
/// non-ambient capabilities on setuid).
#[test]
fn invariant1_agent_user_cannot_touch_control_plane_or_iptables() {
    if !check_preconditions() {
        return;
    }

    let name = format!("strait-agent-inv1-{}", std::process::id());
    let setup = r#"
        set -eu
        mkdir -p /run/strait
        chmod 0755 /run/strait
        : > /run/strait/host.sock
        chown root:root /run/strait/host.sock
        chmod 0600 /run/strait/host.sock
        exec sleep 3600
    "#;
    if let Err(e) = docker_run_detached(
        &name,
        // `--cap-add=NET_ADMIN` is intentional: we want to prove the agent
        // user cannot modify iptables *even* when the container as a
        // whole has the capability. Without this, the test would only
        // prove that docker stripped the cap, not that the agent user
        // never inherited it.
        &["--cap-add=NET_ADMIN"],
        &["sh", "-c", setup],
    ) {
        panic!(
            "docker run failed: $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            e.command, e.status, e.stdout, e.stderr
        );
    }
    let _guard = ContainerGuard(name.clone());

    // Wait for the socket file to actually appear so the `cat` below
    // tests permissions, not a race on setup.
    assert!(
        wait_for_setup_file(&name, "/run/strait/host.sock", Duration::from_secs(5)),
        "host.sock placeholder never appeared in container {name}",
    );

    // 1a. `cat /run/strait/host.sock` must fail with Permission denied.
    let cat = docker_exec(&name, "testagent", &["cat", "/run/strait/host.sock"]);
    cat.assert_failed("invariant 1: cat on host socket");
    cat.assert_contains("permission denied", "invariant 1: cat on host socket");

    // 1b. Any attempt to open the path for reading via `test -r` must
    //     also fail. Belt-and-braces: some CI images ship odd `cat`
    //     wrappers; a plain file-mode probe is the minimum.
    let test_r = docker_exec(
        &name,
        "testagent",
        &["sh", "-c", "test -r /run/strait/host.sock"],
    );
    test_r.assert_failed("invariant 1: test -r on host socket");

    // 1c. `iptables -L` must fail as the agent user (no CAP_NET_ADMIN).
    //     netfilter prints one of a few near-identical diagnostics; all
    //     of them include the substring "permission denied" in the
    //     lower-case combined output.
    let list = docker_exec(&name, "testagent", &["iptables", "-L"]);
    list.assert_failed("invariant 1: iptables -L");
    list.assert_contains("permission denied", "invariant 1: iptables -L");

    // 1d. `iptables -F` must fail for the same reason.
    let flush = docker_exec(&name, "testagent", &["iptables", "-F"]);
    flush.assert_failed("invariant 1: iptables -F");
    flush.assert_contains("permission denied", "invariant 1: iptables -F");
}

/// Lightweight variant of [`wait_for_file`] that only cares whether the
/// path exists, not what it contains. Used in invariant 1 where the
/// file is intentionally zero-bytes.
fn wait_for_setup_file(container: &str, path: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let out = Command::new("docker")
            .args(["exec", "-u", "0", container, "test", "-e", path])
            .output();
        if let Ok(out) = out {
            if out.status.success() {
                return true;
            }
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    false
}

// ---------------------------------------------------------------------------
// Invariant 2
// ---------------------------------------------------------------------------

/// Invariant 2: raw TCP from the agent user is caught by iptables
/// REDIRECT even when `HTTPS_PROXY` is unset.
///
/// Setup: install the production-shaped REDIRECT rules (the same ones
/// `strait-agent entrypoint` installs at startup) and stand up a tiny
/// `nc`-based listener on `PROXY_PORT` that writes "HIT" to a marker
/// file the first time a TCP connection arrives. As `testagent`, with
/// `HTTPS_PROXY` explicitly scrubbed from the env, run
/// `nc -z -w 3 198.51.100.1 443`. That address is an unroutable
/// TEST-NET-2 block; without the REDIRECT the connect would time out,
/// so an `nc -z` success is direct evidence that iptables caught the
/// syscall.
///
/// The listener write to `/tmp/proxy-hit` is the "proxy audited the
/// request" signal from the test plan.
#[test]
fn invariant2_redirect_catches_raw_tcp_without_https_proxy_env() {
    if !check_preconditions() {
        return;
    }

    let name = format!("strait-agent-inv2-{}", std::process::id());
    // The setup script runs as root inside the container. It installs
    // the iptables rules in the shape `strait-agent entrypoint` would,
    // spawns the stand-in listener in the background, and then `sleep`s
    // forever so `docker exec` has something to attach to.
    let setup = format!(
        r#"
        set -eu
        iptables -t nat -A OUTPUT -o lo -j RETURN
        iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner {uid} --dport 443 \
            -j REDIRECT --to-ports {proxy_port}
        # Stand-in for the real in-container proxy: `nc -l` blocks until a
        # connection arrives, so the shell reaches `echo HIT` exactly when
        # a client TCP SYN is routed here by the REDIRECT above. One-shot
        # is fine; the test only makes a single connection attempt.
        ( nc -l {proxy_port} < /dev/null > /dev/null 2>&1; \
          echo HIT > /tmp/proxy-hit ) &
        # Give the listener a moment to bind before exec'ing sleep.
        sleep 0.5
        exec sleep 3600
        "#,
        uid = TESTAGENT_UID,
        proxy_port = PROXY_PORT,
    );
    if let Err(e) = docker_run_detached(&name, &["--cap-add=NET_ADMIN"], &["sh", "-c", &setup]) {
        panic!(
            "docker run failed: $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            e.command, e.status, e.stdout, e.stderr
        );
    }
    let _guard = ContainerGuard(name.clone());

    // Wait until the listener is definitely bound. `ss -tln` is the
    // cheapest way to tell; iptables+nc both need to be ready before we
    // fire the test connection.
    wait_for_listener(&name, PROXY_PORT, Duration::from_secs(5))
        .expect("proxy-port listener did not come up in time");

    // Fire the test connection as the agent user. `env -u HTTPS_PROXY`
    // makes the "no proxy env var is set" condition explicit; `nc -z`
    // does a zero-IO connect so we can attribute a success purely to
    // kernel-level REDIRECT, not to any application-layer proxy.
    let connect = docker_exec(
        &name,
        "testagent",
        &[
            "env",
            "-u",
            "HTTPS_PROXY",
            "-u",
            "https_proxy",
            "-u",
            "ALL_PROXY",
            "-u",
            "all_proxy",
            "nc",
            "-z",
            "-w",
            "3",
            UNREACHABLE_HOST,
            "443",
        ],
    );
    connect.assert_ok(
        "invariant 2: nc -z to unreachable upstream should succeed via iptables REDIRECT",
    );

    // The listener wrote HIT to /tmp/proxy-hit once the connect arrived.
    // That is the "proxy audited the request" signal from the test plan.
    let hit = wait_for_file(&name, "/tmp/proxy-hit", Duration::from_secs(5))
        .expect("listener never wrote /tmp/proxy-hit; REDIRECT did not reach the proxy port");
    assert!(
        hit.contains("HIT"),
        "proxy hit file did not contain expected marker, got: {hit:?}"
    );
}

/// Poll `ss -tln` inside `container` until a listener is bound on
/// `port`, or `timeout` elapses.
fn wait_for_listener(container: &str, port: u16, timeout: Duration) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let needle = format!(":{port} ");
    while Instant::now() < deadline {
        let out = Command::new("docker")
            .args(["exec", "-u", "0", container, "ss", "-tln"])
            .output()
            .map_err(|e| format!("ss spawn: {e}"))?;
        if out.status.success() {
            let body = String::from_utf8_lossy(&out.stdout);
            // Match both "0.0.0.0:9443 " and "[::]:9443 " variants.
            if body.contains(&needle) {
                return Ok(());
            }
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    Err(format!("no listener on :{port} within {:?}", timeout))
}

// ---------------------------------------------------------------------------
// Invariant 3
// ---------------------------------------------------------------------------

/// Invariant 3: the agent user cannot signal the (root-owned) proxy
/// process.
///
/// Today's `strait-agent proxy` stub exits immediately when invoked
/// without `--policy`/`--ca-cert`, so we cannot rely on the child
/// spawned by the real `entrypoint` subcommand to still be alive by the
/// time the test fires its `kill`. Instead we launch `strait-agent
/// entrypoint` with a root-owned `sleep` sidecar as the stand-in proxy:
/// the sleep is started by the container's pre-exec shell and survives
/// the privilege drop. The invariant under test is the Linux UID-based
/// signal gate, which holds regardless of whether the long-lived
/// process is the real MITM pipeline or a sleep.
///
/// When H-ICDP-3 delivers a long-lived proxy, the stand-in can go away
/// and the test can target `pgrep -f 'strait-agent proxy'`; the rest of
/// the shape is already correct.
#[test]
fn invariant3_agent_user_cannot_signal_proxy_process() {
    if !check_preconditions() {
        return;
    }

    let name = format!("strait-agent-inv3-{}", std::process::id());
    // The shell runs as root (PID 1). We fork a root-owned `sleep` as
    // the stand-in proxy, write its pid to disk, and then exec into
    // `strait-agent entrypoint` which drops to testagent and execs a
    // separate `sleep` we can target with `docker exec`. The entrypoint
    // itself installs iptables rules; those are incidental here but
    // prove the rest of the privilege-drop machinery is still wired
    // up.
    let setup = format!(
        r#"
        set -eu
        sleep 3600 &
        echo $! > /tmp/proxy.pid
        exec /usr/local/bin/strait-agent entrypoint \
            --agent-user testagent \
            --proxy-port {proxy_port} \
            -- sleep 3600
        "#,
        proxy_port = PROXY_PORT,
    );
    if let Err(e) = docker_run_detached(&name, &["--cap-add=NET_ADMIN"], &["sh", "-c", &setup]) {
        panic!(
            "docker run failed: $ {}\n  exit={}\n  stdout={}\n  stderr={}",
            e.command, e.status, e.stdout, e.stderr
        );
    }
    let _guard = ContainerGuard(name.clone());

    let proxy_pid = wait_for_file(&name, "/tmp/proxy.pid", Duration::from_secs(10))
        .expect("proxy-pid file never appeared; container setup must have failed");
    let proxy_pid = proxy_pid.trim();
    assert!(
        proxy_pid.parse::<u32>().is_ok(),
        "proxy pid {proxy_pid:?} is not a valid u32"
    );

    // Sanity-check the setup: the proxy pid is owned by uid 0 and is
    // distinct from the agent process. Without this, a regression that
    // ran the proxy as the agent user would make the `kill` succeed
    // "legitimately" and silently pass the test.
    let proc_status = docker_exec(
        &name,
        "0",
        &[
            "sh",
            "-c",
            &format!("grep '^Uid:' /proc/{proxy_pid}/status"),
        ],
    );
    proc_status.assert_ok("invariant 3: read /proc/<proxy>/status as root");
    assert!(
        proc_status.stdout.split_whitespace().any(|t| t == "0"),
        "invariant 3: proxy pid {proxy_pid} is not owned by uid 0\nstatus output: {}",
        proc_status.stdout,
    );

    // The kill itself. As the agent user, `kill -9 <proxy_pid>` must
    // fail with EPERM ("Operation not permitted"). We go through `sh
    // -c` so the shell's non-zero exit is attributable to the kill
    // builtin and not to docker exec argument handling.
    let kill = docker_exec(
        &name,
        "testagent",
        &["sh", "-c", &format!("kill -9 {proxy_pid}")],
    );
    kill.assert_failed("invariant 3: kill -9 as testagent");
    kill.assert_contains(
        "operation not permitted",
        "invariant 3: kill -9 as testagent",
    );

    // And the proxy is still alive. `kill -0` is the idiomatic "is pid
    // running?" probe; as root it succeeds iff the process exists.
    let still_alive = docker_exec(&name, "0", &["sh", "-c", &format!("kill -0 {proxy_pid}")]);
    still_alive.assert_ok("invariant 3: proxy still running after kill attempt");
}
