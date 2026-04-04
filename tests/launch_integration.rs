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
const TEST_IMAGE: &str = "ubuntu:24.04";

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
    // Use the host target triple for pre-flight check. Integration tests only
    // run on Linux hosts (gateway_compatible_with_container check above), and
    // CI builds the gateway with `cargo build -p strait-gateway` (native arch).
    let host_target = if cfg!(target_arch = "x86_64") {
        "x86_64-unknown-linux-musl"
    } else if cfg!(target_arch = "aarch64") {
        "aarch64-unknown-linux-musl"
    } else {
        // Unknown arch — skip gracefully
        eprintln!("Skipping: unsupported host architecture for gateway binary lookup");
        return false;
    };
    if strait::launch::resolve_gateway_binary(host_target).is_err() {
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
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
        true,
    )
    .await
    .unwrap();

    assert_eq!(exit_code, 0, "warn mode should allow echo to succeed");

    // Observation log should exist
    let events = observation_events(&obs_path);
    let starts = events_of_type(&events, "container_start");
    assert!(!starts.is_empty(), "should have container_start event");
}

// ---------------------------------------------------------------------------
// Network isolation integration tests (--network=none + gateway)
// ---------------------------------------------------------------------------

/// Helper: write a Cedar policy that permits all network and filesystem access.
fn write_permissive_policy(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"
@id("allow-all-network")
permit(
    principal == Agent::"agent",
    action in [Action::"http:GET", Action::"http:POST", Action::"http:CONNECT"],
    resource
);
@id("allow-all-fs")
permit(
    principal == Agent::"agent",
    action in [Action::"fs:read", Action::"fs:write"],
    resource
);
"#,
    )
    .unwrap();
}

/// Helper: write a Cedar policy that permits filesystem access only (no network).
fn write_fs_only_policy(path: &std::path::Path) {
    std::fs::write(
        path,
        r#"
@id("allow-all-fs")
permit(
    principal == Agent::"agent",
    action in [Action::"fs:read", Action::"fs:write"],
    resource
);
"#,
    )
    .unwrap();
}

/// Enforce mode: the proxy path works end to end through the gateway.
///
/// Sends a CONNECT request from inside the container to the gateway at
/// 127.0.0.1:3128. The request traverses: container loopback -> gateway ->
/// Unix socket -> host proxy, which responds with "200 Connection Established".
/// This proves the full proxy path is functional under --network=none.
#[tokio::test]
async fn enforce_proxy_path_end_to_end() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");
    write_permissive_policy(&policy_path);

    // Send a CONNECT request to the gateway from inside the container.
    // The host proxy responds with "200 Connection Established" which
    // proves the full proxy flow is working.
    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        vec![
            "bash".to_string(),
            "-c".to_string(),
            concat!(
                "exec 3<>/dev/tcp/127.0.0.1/3128; ",
                "printf 'CONNECT example.com:443 HTTP/1.1\\r\\n",
                "Host: example.com:443\\r\\n\\r\\n' >&3; ",
                "read -t 5 response <&3; ",
                "exec 3>&-; ",
                "case \"$response\" in *200*) exit 0 ;; *) exit 1 ;; esac",
            )
            .to_string(),
        ],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 0,
        "CONNECT through gateway should get 200 from the host proxy"
    );

    // Verify lifecycle events in observation log
    let events = observation_events(&obs_path);
    let starts = events_of_type(&events, "container_start");
    let stops = events_of_type(&events, "container_stop");
    assert!(!starts.is_empty(), "should have container_start event");
    assert!(!stops.is_empty(), "should have container_stop event");
    assert_eq!(stops[0]["exit_code"].as_i64(), Some(0));
}

/// Enforce mode: direct outbound TCP is blocked by --network=none.
///
/// Attempts a TCP connection to an external IP (1.1.1.1:80) from inside
/// the container. With --network=none, no non-loopback interfaces exist,
/// so the connection fails immediately.
#[tokio::test]
async fn enforce_direct_outbound_tcp_blocked() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");
    write_permissive_policy(&policy_path);

    // Try direct TCP to 1.1.1.1:80. With --network=none this fails because
    // there are no non-loopback network interfaces.
    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "(echo > /dev/tcp/1.1.1.1/80) 2>/dev/null && exit 0 || exit 111".to_string(),
        ],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 111,
        "direct TCP to external IP should be blocked by --network=none"
    );
}

/// Observe mode also uses --network=none: direct outbound TCP is blocked.
///
/// Even without a Cedar policy, observe mode runs containers with
/// --network=none so all traffic goes through the gateway and proxy.
#[tokio::test]
async fn observe_direct_outbound_tcp_blocked() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec![
            "bash".to_string(),
            "-c".to_string(),
            "(echo > /dev/tcp/1.1.1.1/80) 2>/dev/null && exit 0 || exit 111".to_string(),
        ],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 111,
        "direct TCP should be blocked even in observe mode (--network=none)"
    );
}

/// Observe mode: the proxy path is functional through the gateway.
///
/// Same CONNECT-based verification as `enforce_proxy_path_end_to_end`,
/// but in observe mode. Proves observe mode also uses the gateway for
/// proxy access.
#[tokio::test]
async fn observe_proxy_path_end_to_end() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec![
            "bash".to_string(),
            "-c".to_string(),
            concat!(
                "exec 3<>/dev/tcp/127.0.0.1/3128; ",
                "printf 'CONNECT example.com:443 HTTP/1.1\\r\\n",
                "Host: example.com:443\\r\\n\\r\\n' >&3; ",
                "read -t 5 response <&3; ",
                "exec 3>&-; ",
                "case \"$response\" in *200*) exit 0 ;; *) exit 1 ;; esac",
            )
            .to_string(),
        ],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 0,
        "CONNECT through gateway should succeed in observe mode"
    );
}

/// Enforce mode: gateway propagates exit code from the container command.
///
/// The exit code path is: user command -> gateway child -> Docker wait ->
/// caller. Verifying a specific non-zero code (42) ensures the gateway
/// does not swallow or replace the child's exit status.
#[tokio::test]
async fn enforce_exit_code_propagation() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");
    write_fs_only_policy(&policy_path);

    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        vec!["sh".to_string(), "-c".to_string(), "exit 42".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 42,
        "gateway should propagate exit code 42 from container command"
    );

    // Observation log should record the exit code
    let events = observation_events(&obs_path);
    let stops = events_of_type(&events, "container_stop");
    assert!(!stops.is_empty(), "should have container_stop event");
    assert_eq!(
        stops[0]["exit_code"].as_i64(),
        Some(42),
        "container_stop should record exit code 42"
    );
}

/// Enforce mode: gateway exits cleanly with exit code 0.
///
/// Basic happy path for enforce mode: `echo hello` succeeds, container
/// lifecycle events are recorded, and the observation log shows clean exit.
#[tokio::test]
async fn enforce_clean_exit_zero() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");
    write_fs_only_policy(&policy_path);

    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Enforce,
        &policy_path,
        vec!["echo".to_string(), "hello".to_string()],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(exit_code, 0, "enforce mode echo should exit with code 0");

    let events = observation_events(&obs_path);
    let starts = events_of_type(&events, "container_start");
    let stops = events_of_type(&events, "container_stop");
    assert!(!starts.is_empty(), "should have container_start event");
    assert!(!stops.is_empty(), "should have container_stop event");
    assert_eq!(
        starts[0]["image"].as_str(),
        Some(TEST_IMAGE),
        "container_start should record the image"
    );
    assert_eq!(
        stops[0]["exit_code"].as_i64(),
        Some(0),
        "container_stop should record exit code 0"
    );
}

/// Warn mode: proxy path is functional through the gateway.
///
/// Warn mode uses the same --network=none and gateway setup as enforce
/// mode. Verifies the proxy responds to CONNECT requests from the container.
#[tokio::test]
async fn warn_proxy_path_end_to_end() {
    if !require_docker().await {
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let policy_path = temp_dir.path().join("policy.cedar");
    let obs_path = temp_dir.path().join("observations.jsonl");
    write_permissive_policy(&policy_path);

    let exit_code = strait::launch::run_launch_with_policy(
        strait::launch::EnforcementMode::Warn,
        &policy_path,
        vec![
            "bash".to_string(),
            "-c".to_string(),
            concat!(
                "exec 3<>/dev/tcp/127.0.0.1/3128; ",
                "printf 'CONNECT example.com:443 HTTP/1.1\\r\\n",
                "Host: example.com:443\\r\\n\\r\\n' >&3; ",
                "read -t 5 response <&3; ",
                "exec 3>&-; ",
                "case \"$response\" in *200*) exit 0 ;; *) exit 1 ;; esac",
            )
            .to_string(),
        ],
        Some(TEST_IMAGE),
        Some(obs_path.clone()),
        None,
        Vec::new(),
        vec![],
        true,
    )
    .await
    .unwrap();

    assert_eq!(
        exit_code, 0,
        "CONNECT through gateway should succeed in warn mode"
    );
}
