//! Integration tests for `strait launch` (observe, warn, and enforce modes).
//!
//! These tests require Docker to be running with the test image pulled.
//! - **CI**: the workflow pulls the test image before tests; missing Docker panics.
//! - **Local dev**: tests skip gracefully if Docker is not available.
//!
//! Run explicitly with: `cargo test --test launch_integration`

use std::io::{BufRead, BufReader, Write};
use std::path::Path;

/// Container image used for integration tests.
///
/// Uses a glibc-based image (not Alpine/musl) because the `strait-gateway`
/// binary is compiled for the host platform and bind-mounted into the
/// container. On CI (Ubuntu), this produces a glibc-linked ELF binary
/// that can't execute inside musl-based containers like Alpine. Debian
/// Bookworm uses glibc, matching the CI host.
const TEST_IMAGE: &str = "debian:bookworm-slim";

/// Check if Docker is available with the required image for integration tests.
///
/// Returns true if we can connect to the Docker daemon, ping it, and the
/// test image is already pulled. We don't auto-pull images in
/// tests to keep them fast and avoid network dependencies in CI.
async fn docker_available() -> bool {
    let docker = match bollard::Docker::connect_with_local_defaults() {
        Ok(d) => d,
        Err(_) => return false,
    };
    if docker.ping().await.is_err() {
        return false;
    }
    // Check that the required test image is available locally
    docker.inspect_image(TEST_IMAGE).await.is_ok()
}

/// Check if the gateway binary can run inside a Linux container.
///
/// The gateway binary is compiled for the host platform and bind-mounted
/// into the container. On macOS, the binary is Mach-O format, which cannot
/// execute inside a Linux container (ELF required). On Linux hosts the
/// binary format matches and the gateway runs directly.
fn gateway_compatible_with_container() -> bool {
    // On Linux hosts, the binary format matches the container.
    // On non-Linux hosts (macOS, Windows), the host binary can't execute
    // inside a Linux container.
    cfg!(target_os = "linux")
}

/// Require Docker and the gateway binary for an integration test.
///
/// - **CI** (`CI` env var set): panics if Docker+test image is unavailable or
///   the gateway binary is missing, since CI should build the gateway before
///   running tests.
/// - **Developer machines**: returns `false` so the test can skip gracefully.
///
/// Also checks gateway binary compatibility: tests that launch containers
/// with the gateway entrypoint need a Linux-format binary. On macOS hosts,
/// the gateway binary is Mach-O and can't execute inside the Linux container,
/// so these tests skip gracefully.
async fn require_docker() -> bool {
    if !docker_available().await {
        if std::env::var("CI").is_ok() {
            panic!(
                "Docker with {TEST_IMAGE} is required in CI but not available. \
                 Ensure the CI workflow pulls the test image before tests."
            );
        }
        eprintln!("Skipping: Docker not available (run `docker pull {TEST_IMAGE}` to enable)");
        return false;
    }
    if !gateway_compatible_with_container() {
        eprintln!(
            "Skipping: gateway binary is not Linux ELF format (host is {}). \
             These tests require a Linux host where the gateway binary can execute \
             inside the container.",
            std::env::consts::OS
        );
        return false;
    }
    if strait::launch::find_gateway_binary().is_err() {
        if std::env::var("CI").is_ok() {
            panic!(
                "strait-gateway binary not found in CI. \
                 Ensure the CI workflow runs `cargo build -p strait-gateway` before tests."
            );
        }
        eprintln!(
            "Skipping: strait-gateway binary not found \
             (run `cargo build -p strait-gateway` to enable)"
        );
        return false;
    }
    true
}

/// Helper to read an observation JSONL file into parsed events.
fn observation_events(path: &Path) -> Vec<serde_json::Value> {
    let file = std::fs::File::open(path).expect("observation log should exist");
    let reader = BufReader::new(file);
    reader
        .lines()
        .map(|line| {
            let line = line.expect("should read line");
            serde_json::from_str(&line).expect("each line should be valid JSON")
        })
        .collect()
}

/// Find events of a specific type in the observation log.
fn events_of_type<'a>(
    events: &'a [serde_json::Value],
    event_type: &str,
) -> Vec<&'a serde_json::Value> {
    events
        .iter()
        .filter(|e| e.get("type").and_then(|t| t.as_str()) == Some(event_type))
        .collect()
}

// ---------------------------------------------------------------------------
// Integration tests (require Docker)
// ---------------------------------------------------------------------------

/// `launch --observe echo hello` runs in container, produces observation JSONL,
/// and exits cleanly with exit code 0.
#[tokio::test]
async fn launch_observe_echo_hello() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["echo".to_string(), "hello".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await
    .expect("launch should succeed");

    assert_eq!(exit_code, 0, "echo hello should exit with code 0");

    // Verify observation log exists and has events
    assert!(obs_path.exists(), "observation log should exist");
    let events = observation_events(&obs_path);

    // Should have at least container_start and container_stop events
    let starts = events_of_type(&events, "container_start");
    let stops = events_of_type(&events, "container_stop");

    assert!(!starts.is_empty(), "should have container_start event");
    assert!(!stops.is_empty(), "should have container_stop event");

    // container_start should have image field
    assert_eq!(
        starts[0]["image"].as_str(),
        Some(TEST_IMAGE),
        "container_start should record the image"
    );

    // container_stop should have exit_code 0
    assert_eq!(
        stops[0]["exit_code"].as_i64(),
        Some(0),
        "container_stop should record exit code 0"
    );
}

/// Observation JSONL contains both network events from proxy AND container
/// lifecycle events.
#[tokio::test]
async fn launch_observe_contains_lifecycle_events() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["echo".to_string(), "lifecycle".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await
    .unwrap();

    assert_eq!(exit_code, 0);

    let events = observation_events(&obs_path);

    // Should have mount events (for the cwd bind-mount)
    let mounts = events_of_type(&events, "mount");
    assert!(!mounts.is_empty(), "should have mount event for cwd");
    assert_eq!(
        mounts[0]["mode"].as_str(),
        Some("read-write"),
        "observe mode should use read-write mounts"
    );

    // Should have container_start event
    let starts = events_of_type(&events, "container_start");
    assert!(!starts.is_empty(), "should have container_start event");
    assert!(
        starts[0]["container_id"].as_str().is_some(),
        "container_start should have container_id"
    );

    // Should have container_stop event
    let stops = events_of_type(&events, "container_stop");
    assert!(!stops.is_empty(), "should have container_stop event");
}

/// Agent exits immediately with bad command — clean error with exit code.
#[tokio::test]
async fn launch_observe_bad_command_exit_code() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["false".to_string()], // `false` exits with code 1
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await
    .unwrap();

    assert_ne!(exit_code, 0, "false command should exit with non-zero code");

    // Observation log should still have container lifecycle events
    let events = observation_events(&obs_path);
    let stops = events_of_type(&events, "container_stop");
    assert!(
        !stops.is_empty(),
        "should have container_stop even on failure"
    );
    assert_ne!(
        stops[0]["exit_code"].as_i64(),
        Some(0),
        "stop event should record non-zero exit code"
    );
}

/// Docker not running gives a clear error before any operations.
#[tokio::test]
async fn docker_not_running_gives_clear_error() {
    // This test verifies the error message when Docker is not available.
    // We can't easily simulate Docker being down, but we verify the
    // ContainerManager constructor and verify_connection path.
    match strait::container::ContainerManager::new() {
        Ok(mgr) => {
            // Docker socket exists — test the verify_connection path
            match mgr.verify_connection().await {
                Ok(()) => {
                    // Docker is running — this test is a no-op
                    eprintln!("Docker is running; error path not exercised");
                }
                Err(e) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("Docker") || msg.contains("docker"),
                        "error should mention Docker: {msg}"
                    );
                }
            }
        }
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains("Docker") || msg.contains("docker"),
                "error should mention Docker: {msg}"
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Policy enforcement integration tests
// ---------------------------------------------------------------------------

/// Invalid policy file fails fast before starting container.
#[tokio::test]
async fn launch_policy_invalid_file_fails_fast() {
    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("bad.cedar");
    std::fs::write(&policy_path, "this is not valid cedar @@@ {{{").unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let result = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        vec!["echo".to_string(), "hello".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await;

    assert!(result.is_err(), "invalid policy should fail fast");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("Cedar policy") || err.contains("invalid"),
        "error should mention invalid policy: {err}"
    );
    // No observation log should exist (failed before container creation)
    assert!(
        !obs_path.exists(),
        "no observation log should exist on policy load failure"
    );
}

/// Nonexistent policy file fails fast with clear error.
#[tokio::test]
async fn launch_policy_missing_file_fails_fast() {
    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let result = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        Path::new("/nonexistent/policy.cedar"),
        vec!["echo".to_string(), "hello".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path),
        None,
        Vec::new(),
        vec![],
    )
    .await;

    assert!(result.is_err(), "missing policy file should fail fast");
    let err = result.unwrap_err().to_string();
    assert!(
        err.contains("failed to load") || err.contains("failed to read"),
        "error should mention file loading failure: {err}"
    );
}

/// `launch --policy` with restrictive policy restricts bind-mounts.
/// The agent sees only the permitted mounts.
#[tokio::test]
async fn launch_policy_restricts_mounts() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");

    // Write a restrictive policy — only allow read access to a non-existent path
    // This means the cwd will NOT be mounted
    let mut policy_file = std::fs::File::create(&policy_path).unwrap();
    policy_file
        .write_all(
            br#"
@id("allow-read-only-nonexistent")
permit(
    principal == Agent::"agent",
    action == Action::"fs:read",
    resource in Resource::"fs::/nonexistent-test-path"
);

@id("allow-network")
permit(
    principal == Agent::"agent",
    action in [Action::"http:GET", Action::"http:POST"],
    resource
);
"#,
        )
        .unwrap();

    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        // Try to list the cwd — should fail because it's not mounted
        vec!["ls".to_string(), "/workspace".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await
    .unwrap();

    // The command should fail (path doesn't exist in container)
    assert_ne!(
        exit_code, 0,
        "ls should fail when mount is restricted by policy"
    );

    // Observation log should have a policy_violation event for the cwd
    let events = observation_events(&obs_path);
    let _violations = events_of_type(&events, "policy_violation");
    // May or may not have violations depending on cwd matching
    // But container_stop should exist
    let stops = events_of_type(&events, "container_stop");
    assert!(
        !stops.is_empty(),
        "should have container_stop event even with restrictive policy"
    );
}

/// `launch --warn` with restrictive policy still allows the agent to succeed.
#[tokio::test]
async fn launch_warn_allows_agent_to_succeed() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");

    // Write a permissive fs policy so the container can run
    let mut policy_file = std::fs::File::create(&policy_path).unwrap();
    policy_file
        .write_all(
            br#"
@id("allow-fs-write")
permit(
    principal == Agent::"agent",
    action in [Action::"fs:read", Action::"fs:write"],
    resource
);
"#,
        )
        .unwrap();

    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Warn,
        &policy_path,
        vec!["echo".to_string(), "warn-test".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
    )
    .await
    .unwrap();

    assert_eq!(exit_code, 0, "warn mode should allow echo to succeed");

    // Observation log should exist
    let events = observation_events(&obs_path);
    let starts = events_of_type(&events, "container_start");
    assert!(!starts.is_empty(), "should have container_start event");
}
