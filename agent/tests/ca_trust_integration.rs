//! Docker-based integration tests for in-container CA trust injection
//! (H-ICDP-4).
//!
//! These tests exercise the real trust-injection path inside a Linux
//! container with `--cap-add=NET_ADMIN`. They cover the three test-plan
//! items for H-ICDP-4:
//!
//! 1. **Debian (full distro path).** After entrypoint finishes, the
//!    session CA PEM is present in `/etc/ssl/certs/ca-certificates.crt`
//!    (the file that Debian's `update-ca-certificates` rebuilds from
//!    `/usr/local/share/ca-certificates/`).
//! 2. **Fallback path.** On a minimal image that has neither
//!    `update-ca-certificates` nor `update-ca-trust`, the CA still ends
//!    up appended to whatever system bundle exists, and the entrypoint
//!    logs the "no distro trust tool" warning.
//! 3. **Env export.** The child process environment has
//!    `NODE_EXTRA_CA_CERTS`, `REQUESTS_CA_BUNDLE`, and `SSL_CERT_FILE`
//!    all pointing at the standalone PEM file the entrypoint wrote
//!    (`/etc/ssl/certs/strait-session-ca.pem`).
//!
//! The end-to-end "curl succeeds via the proxy" half of the acceptance
//! criteria requires the real MITM proxy, which is scoped to H-ICDP-3
//! and not yet implemented in the `strait-agent proxy` stub. Once that
//! lands, a follow-up test can invoke `curl https://...` through the
//! proxy and assert the CA chain validates from inside the container --
//! at that point the injection work here is what makes it pass.
//!
//! ## Platform / environment gating
//!
//! Linux-only at runtime: the `strait-agent` binary we build with
//! `cargo build -p strait-agent` is a Linux ELF on Linux hosts and
//! Mach-O on macOS hosts; only the former runs inside a Linux container.
//! The gate mirrors `entrypoint_integration.rs`.
//!
//! Local dev hosts without Docker skip gracefully. CI (env `CI` set)
//! panics so these tests can't silently no-op.

#![cfg(target_os = "linux")]

use std::path::Path;
use std::process::{Command, Stdio};

/// Debian-based image tag used by the happy path test.
const DEBIAN_IMAGE_TAG: &str = "strait-agent-catrust-debian:h-icdp-4";
/// Alpine-based image tag used by the fallback test (no
/// `update-ca-certificates`, no `update-ca-trust`).
const FALLBACK_IMAGE_TAG: &str = "strait-agent-catrust-fallback:h-icdp-4";

fn strait_agent_bin() -> &'static Path {
    Path::new(env!("CARGO_BIN_EXE_strait-agent"))
}

fn docker_available() -> bool {
    Command::new("docker")
        .arg("version")
        .arg("--format")
        .arg("{{.Server.Version}}")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn require_docker() -> bool {
    if !docker_available() {
        if std::env::var("CI").is_ok() {
            panic!(
                "Docker is required for strait-agent CA trust integration tests but is not available"
            );
        }
        eprintln!("Skipping: Docker not available");
        return false;
    }
    true
}

/// Build `tag` from `dockerfile` if it does not already exist. Copies
/// the freshly compiled `strait-agent` binary into the build context.
fn ensure_image(tag: &str, dockerfile: &str) -> Result<(), String> {
    let exists = Command::new("docker")
        .args(["image", "inspect", tag])
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
    std::fs::write(build_ctx.path().join("Dockerfile"), dockerfile)
        .map_err(|e| format!("write Dockerfile: {e}"))?;

    let out = Command::new("docker")
        .args(["build", "-t", tag, "."])
        .current_dir(build_ctx.path())
        .output()
        .map_err(|e| format!("spawn docker build: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "docker build failed for {tag} (status {}): stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(())
}

const DEBIAN_DOCKERFILE: &str = r#"FROM debian:stable-slim
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      iptables procps ca-certificates \
 && rm -rf /var/lib/apt/lists/*
RUN useradd -m -u 1001 testagent
COPY strait-agent /usr/local/bin/strait-agent
RUN chmod +x /usr/local/bin/strait-agent
"#;

// Alpine ships /etc/ssl/cert.pem as the system bundle but does NOT
// ship update-ca-certificates or update-ca-trust by default. That is
// exactly the shape we want the fallback test to exercise.
const FALLBACK_DOCKERFILE: &str = r#"FROM alpine:3.19
RUN apk add --no-cache iptables procps
RUN adduser -D -u 1001 testagent
COPY strait-agent /usr/local/bin/strait-agent
RUN chmod +x /usr/local/bin/strait-agent
"#;

struct RunOutput {
    status: i32,
    stdout: String,
    stderr: String,
}

fn docker_run(image: &str, extra_docker_args: &[&str], argv: &[&str]) -> RunOutput {
    let mut cmd = Command::new("docker");
    cmd.args(["run", "--rm"]).args(extra_docker_args).arg(image);
    for a in argv {
        cmd.arg(a);
    }
    let out = cmd.output().expect("docker run should spawn");
    RunOutput {
        status: out.status.code().unwrap_or(-1),
        stdout: String::from_utf8_lossy(&out.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&out.stderr).into_owned(),
    }
}

/// Exec a one-shot agent command that prints enough state to verify the
/// three test-plan items, then exit cleanly so the container tears down.
///
/// The script runs as the agent user (exec'd after privilege drop).
/// We print in parseable lines prefixed with `TEST:` so assertions can
/// grep for fields without being fooled by unrelated logs.
const VERIFY_SCRIPT: &str = r#"
echo "TEST:uid=$(id -u)"
echo "TEST:NODE_EXTRA_CA_CERTS=$NODE_EXTRA_CA_CERTS"
echo "TEST:REQUESTS_CA_BUNDLE=$REQUESTS_CA_BUNDLE"
echo "TEST:SSL_CERT_FILE=$SSL_CERT_FILE"
if [ -f "$SSL_CERT_FILE" ]; then
    echo "TEST:ca_pem_exists=yes"
    # Grab just the marker lines so we can tell the file is non-empty
    # without flooding the assertion output.
    grep -c 'BEGIN CERTIFICATE' "$SSL_CERT_FILE" | sed 's/^/TEST:ca_pem_begin_lines=/'
else
    echo "TEST:ca_pem_exists=no"
fi
# System bundle check (Debian: rebuilt by update-ca-certificates;
# Alpine fallback: appended directly).
for f in /etc/ssl/certs/ca-certificates.crt /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt; do
    if [ -f "$f" ]; then
        if grep -q 'strait session CA' "$f" 2>/dev/null; then
            echo "TEST:system_bundle_hit=$f"
        fi
    fi
done
"#;

fn parse_kv(stdout: &str, key: &str) -> Option<String> {
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("TEST:") {
            if let Some((k, v)) = rest.split_once('=') {
                if k == key {
                    return Some(v.to_string());
                }
            }
        }
    }
    None
}

fn parse_kvs(stdout: &str, key: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for line in stdout.lines() {
        if let Some(rest) = line.strip_prefix("TEST:") {
            if let Some((k, v)) = rest.split_once('=') {
                if k == key {
                    hits.push(v.to_string());
                }
            }
        }
    }
    hits
}

#[test]
fn debian_entrypoint_installs_ca_into_system_bundle_and_exports_env_vars() {
    if !require_docker() {
        return;
    }
    if let Err(e) = ensure_image(DEBIAN_IMAGE_TAG, DEBIAN_DOCKERFILE) {
        panic!("failed to prepare Debian test image: {e}");
    }

    let out = docker_run(
        DEBIAN_IMAGE_TAG,
        &["--cap-add=NET_ADMIN"],
        &[
            "strait-agent",
            "entrypoint",
            "--agent-user",
            "testagent",
            "--proxy-port",
            "3128",
            "--",
            "sh",
            "-c",
            VERIFY_SCRIPT,
        ],
    );

    assert_eq!(
        out.status, 0,
        "entrypoint should exit 0 on Debian; stderr={}\nstdout={}",
        out.stderr, out.stdout
    );

    // (1) exec'd child runs as the agent user.
    assert_eq!(
        parse_kv(&out.stdout, "uid").as_deref(),
        Some("1001"),
        "child should run as testagent (uid 1001): {}",
        out.stdout
    );

    // (2) language env vars all point at the standalone CA PEM path.
    let expected_pem = "/etc/ssl/certs/strait-session-ca.pem";
    for key in ["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"] {
        assert_eq!(
            parse_kv(&out.stdout, key).as_deref(),
            Some(expected_pem),
            "{key} should point at {expected_pem}; got stdout={}",
            out.stdout
        );
    }
    assert_eq!(
        parse_kv(&out.stdout, "ca_pem_exists").as_deref(),
        Some("yes"),
        "standalone CA PEM file should exist inside the container: {}",
        out.stdout
    );

    // (3) Debian distro path was used: the session CA ended up inside
    // /etc/ssl/certs/ca-certificates.crt, which is the file
    // update-ca-certificates rebuilds from the drop-in dir.
    let hits = parse_kvs(&out.stdout, "system_bundle_hit");
    assert!(
        hits.iter()
            .any(|h| h == "/etc/ssl/certs/ca-certificates.crt"),
        "expected session CA in /etc/ssl/certs/ca-certificates.crt; hits={hits:?}\nstdout={}",
        out.stdout
    );
}

#[test]
fn fallback_path_appends_ca_when_distro_tools_are_missing() {
    if !require_docker() {
        return;
    }
    if let Err(e) = ensure_image(FALLBACK_IMAGE_TAG, FALLBACK_DOCKERFILE) {
        panic!("failed to prepare fallback test image: {e}");
    }

    let out = docker_run(
        FALLBACK_IMAGE_TAG,
        &["--cap-add=NET_ADMIN"],
        &[
            "strait-agent",
            "entrypoint",
            "--agent-user",
            "testagent",
            "--proxy-port",
            "3128",
            "--",
            "sh",
            "-c",
            VERIFY_SCRIPT,
        ],
    );

    assert_eq!(
        out.status, 0,
        "entrypoint should exit 0 on fallback image; stderr={}\nstdout={}",
        out.stderr, out.stdout
    );

    // Env export path still works without the distro tool.
    let expected_pem = "/etc/ssl/certs/strait-session-ca.pem";
    for key in ["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"] {
        assert_eq!(
            parse_kv(&out.stdout, key).as_deref(),
            Some(expected_pem),
            "{key} should point at {expected_pem} on fallback image; stdout={}",
            out.stdout
        );
    }

    // The fallback must append to whichever bundle file Alpine ships.
    // Alpine's native bundle is /etc/ssl/cert.pem; the tests assert that
    // specifically so we catch regressions in the candidate ordering.
    let hits = parse_kvs(&out.stdout, "system_bundle_hit");
    assert!(
        hits.iter().any(|h| h == "/etc/ssl/cert.pem"),
        "expected session CA appended to /etc/ssl/cert.pem on Alpine fallback; hits={hits:?}\nstdout={}",
        out.stdout
    );

    // The entrypoint should log the "no distro trust tool" warning on
    // this image, since Alpine ships neither update-ca-certificates nor
    // update-ca-trust.
    assert!(
        out.stderr.contains("no distro trust tool")
            || out.stderr.contains("appended session CA to system bundle"),
        "expected fallback-warning log in stderr; got: {}",
        out.stderr
    );
}

#[test]
fn entrypoint_fails_cleanly_if_ca_material_cannot_be_written() {
    // This is a pure Rust-level test: if the CA-directory creation
    // fails for any reason the entrypoint should surface a context-rich
    // error rather than exec'ing the child with a broken trust store.
    //
    // We exercise it by running `strait-agent entrypoint` on the
    // Debian image but with `/run` mounted read-only. A read-only `/run`
    // is unusual but not unheard of, and it is the easiest way to
    // force the write path to fail deterministically without touching
    // the code under test.
    if !require_docker() {
        return;
    }
    if let Err(e) = ensure_image(DEBIAN_IMAGE_TAG, DEBIAN_DOCKERFILE) {
        panic!("failed to prepare Debian test image: {e}");
    }

    let out = docker_run(
        DEBIAN_IMAGE_TAG,
        &[
            "--cap-add=NET_ADMIN",
            // tmpfs with a nonsense mode so the CA dir creation fails.
            // `0500` means "read+exec for owner, nothing else"; even
            // root-in-container cannot write into it because tmpfs
            // respects the mount mode.
            "--tmpfs",
            "/run:ro",
        ],
        &[
            "strait-agent",
            "entrypoint",
            "--agent-user",
            "testagent",
            "--proxy-port",
            "3128",
            "--",
            "id",
            "-u",
        ],
    );

    assert_ne!(
        out.status, 0,
        "entrypoint should fail when /run is read-only"
    );
    assert!(
        out.stderr.contains("session CA") || out.stderr.contains("persist session CA"),
        "expected CA-write diagnostic in stderr, got: {}",
        out.stderr
    );
    assert!(
        out.stdout.trim().is_empty(),
        "child command should not have executed; stdout={:?}",
        out.stdout
    );
}
