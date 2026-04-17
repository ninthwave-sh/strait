//! Packaging / install-surface tests for M-INST-4.
//!
//! These tests drive the host-side install scripts that ship strait-host
//! on macOS and Linux. They do NOT require the release tarball layout:
//! the Linux installer is taught to fall back to `target/release/` and
//! `target/debug/` so a developer checkout can exercise the same flow
//! without rebuilding a tarball.
//!
//! The macOS launchd plist and Homebrew formula are validated
//! structurally: the plist parses as XML with the expected Label and
//! ProgramArguments, the formula references every shipped asset, and
//! the systemd unit pins the strait-host user-mode ExecStart.
//!
//! We intentionally do not invoke `launchctl`, `systemctl`, or `sudo`
//! from tests -- the install scripts are exercised via `--no-systemd`
//! and `--no-socket-dir` so they stay hermetic on any host.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).to_path_buf()
}

fn read(path: impl AsRef<Path>) -> String {
    fs::read_to_string(path.as_ref())
        .unwrap_or_else(|e| panic!("reading {}: {e}", path.as_ref().display()))
}

// ── Script syntax checks ──────────────────────────────────────────────

/// `sh -n` parses without executing so we catch syntax errors in the
/// shipped install scripts in CI, even though tests run on developer
/// machines that might not have a representative shell available.
fn assert_sh_syntax(path: &Path) {
    let status = Command::new("sh")
        .arg("-n")
        .arg(path)
        .status()
        .unwrap_or_else(|e| panic!("spawning sh -n {}: {e}", path.display()));
    assert!(status.success(), "sh -n failed for {}", path.display());
}

#[test]
fn install_scripts_parse() {
    let root = repo_root();
    for rel in [
        "packaging/linux/install.sh",
        "packaging/linux/uninstall.sh",
        "packaging/macos/setup-socket-dir.sh",
    ] {
        assert_sh_syntax(&root.join(rel));
    }
}

#[test]
fn install_scripts_are_executable() {
    use std::os::unix::fs::PermissionsExt;
    let root = repo_root();
    for rel in [
        "packaging/linux/install.sh",
        "packaging/linux/uninstall.sh",
        "packaging/macos/setup-socket-dir.sh",
    ] {
        let p = root.join(rel);
        let mode = fs::metadata(&p)
            .unwrap_or_else(|e| panic!("metadata({}): {e}", p.display()))
            .permissions()
            .mode();
        assert!(
            mode & 0o111 != 0,
            "{} should be executable (mode {:o})",
            p.display(),
            mode & 0o777,
        );
    }
}

// ── macOS plist ───────────────────────────────────────────────────────

#[test]
fn macos_plist_is_well_formed_and_targets_host() {
    let plist = read(repo_root().join("packaging/macos/io.ninthwave.strait.host.plist"));
    assert!(
        plist.starts_with("<?xml"),
        "plist should start with an XML declaration"
    );
    assert!(
        plist.contains("<!DOCTYPE plist"),
        "plist should declare the Apple DOCTYPE"
    );
    assert!(
        plist.contains("<key>Label</key>"),
        "plist should have a Label key"
    );
    assert!(
        plist.contains("<string>io.ninthwave.strait.host</string>"),
        "plist Label should match the documented reverse-DNS id"
    );
    assert!(
        plist.contains("strait-host"),
        "plist must launch strait-host"
    );
    assert!(
        plist.contains("<key>RunAtLoad</key>") && plist.contains("<key>KeepAlive</key>"),
        "plist should run at load and keep the service alive"
    );
}

// ── Linux systemd unit ────────────────────────────────────────────────

#[test]
fn linux_systemd_unit_targets_user_mode_strait_host() {
    let unit = read(repo_root().join("packaging/linux/strait-host.service"));
    assert!(unit.contains("[Unit]"), "missing [Unit] section");
    assert!(unit.contains("[Service]"), "missing [Service] section");
    assert!(unit.contains("[Install]"), "missing [Install] section");
    assert!(
        unit.contains("ExecStart=%h/.local/bin/strait-host serve"),
        "unit must exec the user-mode strait-host binary; got:\n{unit}",
    );
    assert!(
        unit.contains("WantedBy=default.target"),
        "user-mode unit should install under default.target"
    );
    assert!(
        unit.contains("Restart=on-failure"),
        "unit should restart on failure"
    );
}

// ── Homebrew formula ──────────────────────────────────────────────────

#[test]
fn homebrew_formula_ships_host_and_wires_launchd() {
    let f = read(repo_root().join("Formula/strait.rb"));
    // Uses `cargo install` for each workspace member so strait, strait-
    // host, and strait-agent all end up in bin/.
    assert!(
        f.contains("--path\", \".\""),
        "formula should install strait (workspace root)"
    );
    assert!(
        f.contains("--path\", \"host\""),
        "formula should install strait-host",
    );
    assert!(
        f.contains("--path\", \"agent\""),
        "formula should install strait-agent",
    );
    // Plist and config assets shipped under pkgshare so the caveats
    // messages can reference them.
    assert!(
        f.contains("io.ninthwave.strait.host.plist"),
        "formula should ship the launchd plist"
    );
    assert!(
        f.contains("setup-socket-dir.sh"),
        "formula should ship the socket-dir helper so caveats can link to it"
    );
    assert!(
        f.contains("host.toml.example"),
        "formula should ship the host.toml template"
    );
    // service do / run_type triggers brew services to install a plist
    // under the plist_name we set.
    assert!(
        f.contains("plist_name \"io.ninthwave.strait.host\""),
        "formula should set the brew services plist_name to io.ninthwave.strait.host"
    );
    assert!(
        f.contains("run [opt_bin/\"strait-host\", \"serve\"]"),
        "formula service block should run strait-host serve"
    );
    // Default config seeded via post_install.
    assert!(
        f.contains("def post_install"),
        "formula should define post_install for host.toml seeding"
    );
}

// ── End-to-end install.sh exercise ────────────────────────────────────

/// Drive the Linux installer against a sandboxed prefix. We point the
/// installer at our `target/debug` directory (debug tests build
/// strait-host as a dep) or `target/release` so the script's binary-
/// discovery path runs, but we disable systemd and socket-dir creation
/// so the test is hermetic.
#[test]
fn linux_install_script_writes_expected_files_into_sandbox() {
    // This test needs a strait-host binary on disk. Cargo does not
    // guarantee the workspace binary is built when running a plain
    // `cargo test` at the root, so we build it explicitly the same way
    // the dev tree does.
    let root = repo_root();
    let bin_src = tempfile::tempdir().expect("tempdir");
    let fake_bin = bin_src.path().join("strait-host");
    fs::write(&fake_bin, "#!/bin/sh\necho fake\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&fake_bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_bin, perms).unwrap();

    let sandbox = tempfile::tempdir().expect("sandbox");
    let prefix = sandbox.path().join("prefix");
    let config_dir = sandbox.path().join("config");
    let unit_dir = sandbox.path().join("units");

    let status = Command::new("sh")
        .arg(root.join("packaging/linux/install.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--unit-dir")
        .arg(&unit_dir)
        .arg("--no-systemd")
        .arg("--no-socket-dir")
        .env("STRAIT_BIN_SRC_DIR", bin_src.path())
        .status()
        .expect("run install.sh");
    assert!(status.success(), "install.sh exited non-zero");

    assert!(
        prefix.join("bin/strait-host").exists(),
        "installer should copy strait-host into the prefix"
    );
    assert!(
        config_dir.join("host.toml").exists(),
        "installer should seed host.toml when missing"
    );
    // Unit is skipped when systemd is disabled.
    assert!(
        !unit_dir.join("strait-host.service").exists(),
        "installer should not drop the unit with --no-systemd"
    );

    // Re-running with an existing config should keep it intact.
    fs::write(config_dir.join("host.toml"), "# user override\n").unwrap();
    let status = Command::new("sh")
        .arg(root.join("packaging/linux/install.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--unit-dir")
        .arg(&unit_dir)
        .arg("--no-systemd")
        .arg("--no-socket-dir")
        .env("STRAIT_BIN_SRC_DIR", bin_src.path())
        .status()
        .expect("re-run install.sh");
    assert!(status.success(), "re-run install.sh exited non-zero");
    let kept = fs::read_to_string(config_dir.join("host.toml")).unwrap();
    assert_eq!(
        kept, "# user override\n",
        "installer must not clobber an existing host.toml"
    );
}

#[test]
fn linux_install_then_uninstall_cleans_up() {
    let root = repo_root();
    let bin_src = tempfile::tempdir().expect("tempdir");
    let fake_bin = bin_src.path().join("strait-host");
    fs::write(&fake_bin, "#!/bin/sh\necho fake\n").unwrap();
    use std::os::unix::fs::PermissionsExt;
    let mut perms = fs::metadata(&fake_bin).unwrap().permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&fake_bin, perms).unwrap();

    let sandbox = tempfile::tempdir().expect("sandbox");
    let prefix = sandbox.path().join("prefix");
    let config_dir = sandbox.path().join("config");
    let unit_dir = sandbox.path().join("units");

    let ok = |c: &mut Command| {
        let s = c.status().expect("run script");
        assert!(s.success(), "script exited non-zero: {:?}", c);
    };

    ok(Command::new("sh")
        .arg(root.join("packaging/linux/install.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--unit-dir")
        .arg(&unit_dir)
        .arg("--no-systemd")
        .arg("--no-socket-dir")
        .env("STRAIT_BIN_SRC_DIR", bin_src.path()));

    assert!(prefix.join("bin/strait-host").exists());

    ok(Command::new("sh")
        .arg(root.join("packaging/linux/uninstall.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--unit-dir")
        .arg(&unit_dir)
        .arg("--no-socket-dir"));

    assert!(
        !prefix.join("bin/strait-host").exists(),
        "uninstall should remove strait-host binary"
    );
    assert!(
        config_dir.join("host.toml").exists(),
        "uninstall should leave host.toml by default (no --purge)"
    );

    // --purge wipes the config too.
    ok(Command::new("sh")
        .arg(root.join("packaging/linux/uninstall.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(&config_dir)
        .arg("--unit-dir")
        .arg(&unit_dir)
        .arg("--no-socket-dir")
        .arg("--purge"));

    assert!(
        !config_dir.join("host.toml").exists(),
        "--purge should remove host.toml"
    );
}

#[test]
fn linux_install_script_errors_without_strait_host_binary() {
    let root = repo_root();
    let empty = tempfile::tempdir().expect("tempdir");
    let sandbox = tempfile::tempdir().expect("sandbox");
    let prefix = sandbox.path().join("prefix");

    let output = Command::new("sh")
        .arg(root.join("packaging/linux/install.sh"))
        .arg("--prefix")
        .arg(&prefix)
        .arg("--config-dir")
        .arg(sandbox.path().join("cfg"))
        .arg("--unit-dir")
        .arg(sandbox.path().join("unit"))
        .arg("--no-systemd")
        .arg("--no-socket-dir")
        .env("STRAIT_BIN_SRC_DIR", empty.path())
        .output()
        .expect("run install.sh");
    assert!(
        !output.status.success(),
        "installer should fail when strait-host missing"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("strait-host"),
        "error message should mention strait-host: {stderr}"
    );
}
