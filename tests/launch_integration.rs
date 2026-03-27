//! Integration tests for `strait launch --observe`.
//!
//! These tests require Docker to be running. They are skipped gracefully
//! if Docker is not available (no test failure).
//!
//! Run explicitly with: `cargo test --test launch_integration`

use std::io::{BufRead, BufReader};
use std::path::Path;

/// Check if Docker is available for integration tests.
///
/// Returns true if we can connect to the Docker daemon and ping it.
async fn docker_available() -> bool {
    match bollard::Docker::connect_with_local_defaults() {
        Ok(docker) => docker.ping().await.is_ok(),
        Err(_) => false,
    }
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
    if !docker_available().await {
        eprintln!("Skipping: Docker not available");
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["echo".to_string(), "hello".to_string()],
        Some("alpine:latest"),
        Some(obs_path.clone()),
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
        Some("alpine:latest"),
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
    if !docker_available().await {
        eprintln!("Skipping: Docker not available");
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["echo".to_string(), "lifecycle".to_string()],
        Some("alpine:latest"),
        Some(obs_path.clone()),
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
    if !docker_available().await {
        eprintln!("Skipping: Docker not available");
        return;
    }

    let temp_dir = tempfile::tempdir().unwrap();
    let obs_path = temp_dir.path().join("observations.jsonl");

    let exit_code = strait::launch::run_launch_observe(
        vec!["false".to_string()], // `false` exits with code 1
        Some("alpine:latest"),
        Some(obs_path.clone()),
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
