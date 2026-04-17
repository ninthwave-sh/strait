//! In-container CA trust injection.
//!
//! Installs the session-local CA PEM into the container's system trust
//! store plus the common language-specific stores. Runs as part of the
//! `strait-agent entrypoint` flow, while the entrypoint is still root and
//! before privileges are dropped to the agent user.
//!
//! Strategy:
//!
//! 1. Persist the CA PEM at a known path (`/usr/local/share/ca-certificates/strait-session-ca.crt`
//!    on Debian-family systems, `/etc/pki/ca-trust/source/anchors/strait-session-ca.crt` on
//!    Fedora-family). Both paths are the "drop a file here, then rerun the
//!    tool" convention for the respective distros.
//! 2. Invoke the distro's trust-store updater:
//!    - Debian/Ubuntu: `update-ca-certificates` which rebuilds
//!      `/etc/ssl/certs/ca-certificates.crt` from the drop-in directory.
//!    - Fedora/RHEL:   `update-ca-trust` which rebuilds
//!      `/etc/pki/ca-trust/extracted/...`.
//! 3. If neither tool is available, fall back to appending the CA PEM
//!    directly to whichever system bundle file exists
//!    (`/etc/ssl/certs/ca-certificates.crt`, `/etc/ssl/cert.pem`, or
//!    `/etc/pki/tls/certs/ca-bundle.crt`). Log a warning so operators
//!    know the container is using the minimal path.
//! 4. Additionally persist the CA PEM at a stable path
//!    ([`CA_PEM_PATH`]) and return a list of `(env, value)` pairs that
//!    point the common runtime bundles at it:
//!    - `NODE_EXTRA_CA_CERTS` -- Node's extra-CA hook
//!    - `REQUESTS_CA_BUNDLE` -- Python `requests` + `httpx` via certifi-less path
//!    - `SSL_CERT_FILE` -- Go's `crypto/x509` and many Unix TLS clients
//!
//! The caller exports the returned env vars on the current process so
//! `execvp` in [`super::entrypoint`] inherits them into the agent command.
//!
//! Every write happens inside the container. The host trust store is
//! never touched; this is the whole point of the in-container rewrite.

use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context as _, Result};
use tracing::{debug, info, warn};

/// Canonical path the entrypoint writes the session CA PEM to.
///
/// Lives under `/etc/ssl/certs/` so it is readable by the agent user and
/// does not require creating a fresh directory. Suffix is deliberate --
/// it must not collide with distro-managed bundles.
pub const CA_PEM_PATH: &str = "/etc/ssl/certs/strait-session-ca.pem";

/// Debian/Ubuntu drop-in directory for `update-ca-certificates`.
const DEBIAN_ANCHOR_DIR: &str = "/usr/local/share/ca-certificates";
/// Fedora/RHEL drop-in directory for `update-ca-trust`.
const FEDORA_ANCHOR_DIR: &str = "/etc/pki/ca-trust/source/anchors";

/// Anchor file name used inside the distro drop-in directories.
///
/// Both Debian and Fedora expect `.crt` here even though the format is
/// PEM. Matching that convention so the tools actually notice the file.
const ANCHOR_FILENAME: &str = "strait-session-ca.crt";

/// Bundle files we append to when no distro updater is available.
///
/// Ordered by how commonly they appear. The first hit wins; we do not
/// try to append to every file because appending to a symlink target
/// after appending to the symlink would double the cert in the bundle.
const SYSTEM_BUNDLE_CANDIDATES: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian / Ubuntu / Alpine (symlink)
    "/etc/ssl/cert.pem",                  // Alpine native + BSD-ish layouts
    "/etc/pki/tls/certs/ca-bundle.crt",   // Fedora / RHEL native
];

/// Tracing-only name attached to log records.
const LOG_TARGET: &str = "strait_agent::ca_trust";

/// Result of [`install`]: a list of env vars the caller must export on
/// the current process so `execvp` inherits them into the child.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstalledTrust {
    /// Absolute path to the session CA PEM file that tools will read.
    pub ca_pem_path: PathBuf,
    /// Env vars to export on the current process.
    pub env: Vec<(&'static str, PathBuf)>,
}

/// Install the session CA into the container's trust stores.
///
/// See the module docs for the overall strategy.
///
/// Contract:
/// - `pem` is the PEM-encoded CA certificate (no private key).
/// - The function must be called as root inside the container.
/// - On success it has written the CA into the system trust store (either
///   via `update-ca-certificates`, `update-ca-trust`, or the fallback),
///   written the standalone PEM at [`CA_PEM_PATH`], and returned the env
///   vars the caller should export before `execvp`.
pub fn install(pem: &str) -> Result<InstalledTrust> {
    install_with_root(pem, Path::new("/"))
}

/// Same as [`install`] but rooted at an arbitrary directory.
///
/// Used by tests to exercise the full fallback + drop-in tree in a
/// `tempdir()` without touching real `/etc`. Production callers go
/// through [`install`].
pub fn install_with_root(pem: &str, root: &Path) -> Result<InstalledTrust> {
    if pem.trim().is_empty() {
        anyhow::bail!("install: CA PEM is empty");
    }
    if !pem.contains("BEGIN CERTIFICATE") {
        anyhow::bail!("install: input does not look like a PEM-encoded certificate");
    }

    // Always write the standalone PEM first: the env-var path depends on
    // it, and tools reading any of NODE_EXTRA_CA_CERTS / REQUESTS_CA_BUNDLE
    // / SSL_CERT_FILE should find the file whether or not the distro
    // updater is available.
    let standalone = rooted(root, CA_PEM_PATH);
    write_pem_file(&standalone, pem).with_context(|| {
        format!(
            "write session CA PEM to {} (inside root {})",
            standalone.display(),
            root.display()
        )
    })?;

    // System trust store: try distro updaters in order, then fall back
    // to appending to a known bundle.
    if try_debian(root, pem)? {
        info!(
            target: LOG_TARGET,
            anchor = %rooted(root, DEBIAN_ANCHOR_DIR).display(),
            "installed session CA via update-ca-certificates"
        );
    } else if try_fedora(root, pem)? {
        info!(
            target: LOG_TARGET,
            anchor = %rooted(root, FEDORA_ANCHOR_DIR).display(),
            "installed session CA via update-ca-trust"
        );
    } else {
        let appended = append_to_fallback_bundle(root, pem)?;
        match appended {
            Some(bundle) => warn!(
                target: LOG_TARGET,
                bundle = %bundle.display(),
                "no distro trust tool found; appended session CA to system bundle"
            ),
            None => warn!(
                target: LOG_TARGET,
                "no distro trust tool or system bundle found; \
                 only language-specific env vars will route through the session CA"
            ),
        }
    }

    Ok(InstalledTrust {
        ca_pem_path: standalone.clone(),
        env: language_env_vars(&standalone),
    })
}

/// Return the env vars that point common language runtimes at `ca_pem`.
///
/// Extracted so unit tests can pin the set without going through the
/// whole `install` flow.
pub fn language_env_vars(ca_pem: &Path) -> Vec<(&'static str, PathBuf)> {
    vec![
        ("NODE_EXTRA_CA_CERTS", ca_pem.to_path_buf()),
        ("REQUESTS_CA_BUNDLE", ca_pem.to_path_buf()),
        ("SSL_CERT_FILE", ca_pem.to_path_buf()),
    ]
}

/// Names of the env vars [`install`] will emit, useful for assertions
/// and diagnostic output.
pub const LANGUAGE_ENV_NAMES: &[&str] =
    &["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"];

// ---------------------------------------------------------------------------
// Distro handlers
// ---------------------------------------------------------------------------

fn try_debian(root: &Path, pem: &str) -> Result<bool> {
    let anchor_dir = rooted(root, DEBIAN_ANCHOR_DIR);
    if !anchor_dir.is_dir() {
        debug!(target: LOG_TARGET, dir = %anchor_dir.display(), "no Debian anchor dir; skipping");
        return Ok(false);
    }
    if !tool_available("update-ca-certificates") {
        debug!(target: LOG_TARGET, "update-ca-certificates not on PATH");
        return Ok(false);
    }

    let anchor = anchor_dir.join(ANCHOR_FILENAME);
    write_pem_file(&anchor, pem)
        .with_context(|| format!("write Debian anchor at {}", anchor.display()))?;

    run_tool("update-ca-certificates", &["--fresh"])
        .with_context(|| "run update-ca-certificates".to_string())?;
    Ok(true)
}

fn try_fedora(root: &Path, pem: &str) -> Result<bool> {
    let anchor_dir = rooted(root, FEDORA_ANCHOR_DIR);
    if !anchor_dir.is_dir() {
        debug!(target: LOG_TARGET, dir = %anchor_dir.display(), "no Fedora anchor dir; skipping");
        return Ok(false);
    }
    if !tool_available("update-ca-trust") {
        debug!(target: LOG_TARGET, "update-ca-trust not on PATH");
        return Ok(false);
    }

    let anchor = anchor_dir.join(ANCHOR_FILENAME);
    write_pem_file(&anchor, pem)
        .with_context(|| format!("write Fedora anchor at {}", anchor.display()))?;

    run_tool("update-ca-trust", &["extract"]).with_context(|| "run update-ca-trust".to_string())?;
    Ok(true)
}

fn append_to_fallback_bundle(root: &Path, pem: &str) -> Result<Option<PathBuf>> {
    for candidate in SYSTEM_BUNDLE_CANDIDATES {
        let path = rooted(root, candidate);
        if path.is_file() {
            append_pem(&path, pem)
                .with_context(|| format!("append session CA to {}", path.display()))?;
            return Ok(Some(path));
        }
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Filesystem + process helpers
// ---------------------------------------------------------------------------

fn rooted(root: &Path, abs: &str) -> PathBuf {
    // Strip the leading '/' so `Path::join` actually treats the second
    // argument as a child of `root`. `Path::join` of an absolute path
    // would discard `root` entirely.
    let trimmed = abs.trim_start_matches('/');
    root.join(trimmed)
}

fn write_pem_file(path: &Path, pem: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("create parent dir {}", parent.display()))?;
    }
    fs::write(path, pem).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

fn append_pem(path: &Path, pem: &str) -> Result<()> {
    let mut file = OpenOptions::new()
        .append(true)
        .open(path)
        .with_context(|| format!("open {} for append", path.display()))?;
    // Guarantee a leading newline so we don't splice onto an existing cert
    // if the bundle did not end with a newline.
    writeln!(file).with_context(|| format!("write newline separator to {}", path.display()))?;
    file.write_all(pem.as_bytes())
        .with_context(|| format!("append PEM bytes to {}", path.display()))?;
    if !pem.ends_with('\n') {
        writeln!(file).with_context(|| format!("write trailing newline to {}", path.display()))?;
    }
    Ok(())
}

fn tool_available(bin: &str) -> bool {
    // We intentionally do not rely on `which`: the agent is a tiny
    // binary and bringing in another crate to locate a process is
    // overkill. Probe PATH by hand.
    let Ok(path_env) = std::env::var("PATH") else {
        return false;
    };
    for entry in path_env.split(':') {
        if entry.is_empty() {
            continue;
        }
        let candidate = Path::new(entry).join(bin);
        if candidate.is_file() {
            return true;
        }
    }
    false
}

fn run_tool<S: AsRef<OsStr>>(bin: &str, args: &[S]) -> Result<()> {
    let output = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("spawn {bin}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        anyhow::bail!("{bin} failed (status {}): stderr={stderr:?}", output.status);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// A syntactically valid PEM payload. We never verify the cert here;
    /// the trust tools do that in the integration tests.
    fn fake_pem() -> &'static str {
        "-----BEGIN CERTIFICATE-----\nFAKE\n-----END CERTIFICATE-----\n"
    }

    fn tempdir() -> tempfile::TempDir {
        tempfile::tempdir().unwrap()
    }

    #[test]
    fn rejects_empty_pem() {
        let root = tempdir();
        let err = install_with_root("   \n  ", root.path()).unwrap_err();
        assert!(
            err.to_string().contains("CA PEM is empty"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn rejects_non_pem_input() {
        let root = tempdir();
        let err = install_with_root("not a cert\n", root.path()).unwrap_err();
        assert!(
            err.to_string().contains("PEM-encoded certificate"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn writes_standalone_pem_at_ca_pem_path() {
        let root = tempdir();
        let result = install_with_root(fake_pem(), root.path()).unwrap();

        let expected = rooted(root.path(), CA_PEM_PATH);
        assert_eq!(result.ca_pem_path, expected);
        let contents = fs::read_to_string(&expected).unwrap();
        assert!(contents.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn returns_language_env_vars_pointing_at_standalone_pem() {
        let root = tempdir();
        let result = install_with_root(fake_pem(), root.path()).unwrap();

        let names: Vec<&str> = result.env.iter().map(|(k, _)| *k).collect();
        assert_eq!(
            names,
            vec!["NODE_EXTRA_CA_CERTS", "REQUESTS_CA_BUNDLE", "SSL_CERT_FILE"]
        );
        for (_, path) in &result.env {
            assert_eq!(path, &result.ca_pem_path);
        }
    }

    #[test]
    fn fallback_appends_to_debian_bundle_when_no_tools() {
        let root = tempdir();
        // Pre-create the bundle with distinct content so we can check the
        // append happened without clobbering.
        let bundle = rooted(root.path(), "/etc/ssl/certs/ca-certificates.crt");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        fs::write(&bundle, "existing-system-ca\n").unwrap();

        // Do NOT create the Debian/Fedora anchor dirs. Without them the
        // distro paths are skipped regardless of PATH, and we fall back.
        install_with_root(fake_pem(), root.path()).unwrap();

        let after = fs::read_to_string(&bundle).unwrap();
        assert!(
            after.starts_with("existing-system-ca"),
            "existing content must be preserved: {after:?}"
        );
        assert!(
            after.contains("BEGIN CERTIFICATE"),
            "appended cert should be in bundle: {after:?}"
        );
    }

    #[test]
    fn fallback_appends_to_alpine_bundle_when_debian_missing() {
        let root = tempdir();
        let bundle = rooted(root.path(), "/etc/ssl/cert.pem");
        fs::create_dir_all(bundle.parent().unwrap()).unwrap();
        fs::write(&bundle, "alpine-bundle\n").unwrap();

        install_with_root(fake_pem(), root.path()).unwrap();

        let after = fs::read_to_string(&bundle).unwrap();
        assert!(after.starts_with("alpine-bundle"));
        assert!(after.contains("BEGIN CERTIFICATE"));
    }

    #[test]
    fn fallback_succeeds_even_with_no_bundle_files() {
        let root = tempdir();
        // No bundle candidates, no distro anchor dirs. The install must
        // still succeed: the standalone PEM + env vars are enough for the
        // language stores to work, and that is documented as the minimal
        // path.
        let result = install_with_root(fake_pem(), root.path()).unwrap();
        assert!(result.ca_pem_path.exists());
        assert_eq!(result.env.len(), 3);
    }

    #[test]
    fn language_env_vars_include_the_three_runtime_bundles() {
        let path = PathBuf::from("/tmp/fake-ca.pem");
        let vars = language_env_vars(&path);
        let names: Vec<&str> = vars.iter().map(|(k, _)| *k).collect();
        assert_eq!(names, LANGUAGE_ENV_NAMES.to_vec());
        for (_, p) in &vars {
            assert_eq!(p, &path);
        }
    }

    #[test]
    fn rooted_respects_leading_slash() {
        let root = Path::new("/tmp/container-root");
        assert_eq!(
            rooted(root, "/etc/ssl/cert.pem"),
            PathBuf::from("/tmp/container-root/etc/ssl/cert.pem")
        );
    }

    #[test]
    fn append_pem_adds_separator_if_bundle_had_no_trailing_newline() {
        let root = tempdir();
        let bundle = root.path().join("bundle.crt");
        fs::write(&bundle, "first-cert").unwrap(); // no trailing newline
        append_pem(&bundle, fake_pem()).unwrap();
        let after = fs::read_to_string(&bundle).unwrap();
        // Should not have `first-cert-----BEGIN` on the same line.
        let line = after.lines().find(|l| l.contains("first-cert")).unwrap();
        assert_eq!(line, "first-cert");
    }
}
