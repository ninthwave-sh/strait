//! Cross-crate tests for the preset and template library.
//!
//! The Cedar corpus itself lives in `strait-host` (see
//! `host/src/presets.rs` and `host/src/templates.rs`). A handful of
//! behavioural checks exercise pieces that only the `strait` CLI crate
//! owns -- `StraitConfig` parsing for the bundled `strait.toml`,
//! `parse_devcontainer` round-trips, and `PolicyEngine` evaluation of
//! the shipped Cedar sources. Keeping them here avoids pulling the
//! `strait` crate into `strait-host` (which would create a cycle) while
//! still guarding the bundled data against regressions.

use strait::config::{parse_devcontainer, StraitConfig};
use strait::policy::PolicyEngine;
use strait::presets::{apply, find as find_devcontainer_preset, PRESETS};
use strait::templates::{find as find_template, TEMPLATES};

fn engine_from_policy(policy: &str) -> PolicyEngine {
    PolicyEngine::from_text(policy, None, None).unwrap()
}

// --- Template Cedar behaviour (previously inlined in src/templates.rs) ---

#[test]
fn all_templates_roundtrip_through_policy_engine() {
    // Every bundled template's Cedar source must compile as the
    // `PolicyEngine` sees it so an operator can apply it without a
    // parse error after the move into `strait-host`.
    for t in TEMPLATES {
        let policy = t.policy.replace("your-org", "test-org");
        let _ = engine_from_policy(&policy);
    }
}

#[test]
fn aws_s3_readwrite_permits_put_denies_delete() {
    let t = find_template("aws-s3-readwrite").unwrap();
    let engine = engine_from_policy(t.policy);
    assert!(
        engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:PUT",
                "/my-bucket/my-key",
                &[],
                "worker"
            )
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:DELETE",
                "/my-bucket/my-key",
                &[],
                "worker"
            )
            .unwrap()
            .allowed
    );
}

#[test]
fn container_sandbox_permits_github_get_and_denies_unscoped_http() {
    let t = find_template("container-sandbox").unwrap();
    let policy = t.policy.replace("your-org", "test-org");
    let engine = engine_from_policy(&policy);
    assert!(
        engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/test-org/my-repo",
                &[],
                "worker"
            )
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .evaluate("example.com", "http:GET", "/", &[], "worker")
            .unwrap()
            .allowed
    );
}

#[test]
fn claude_code_permits_npm_registry() {
    let t = find_template("claude-code").unwrap();
    let engine = engine_from_policy(t.policy);
    assert!(
        engine
            .evaluate("registry.npmjs.org", "http:GET", "/express", &[], "worker")
            .unwrap()
            .allowed
    );
}

#[test]
fn claude_code_denies_anthropic_and_repo_delete() {
    let t = find_template("claude-code").unwrap();
    let policy = t.policy.replace("your-org", "test-org");
    let engine = engine_from_policy(&policy);
    assert!(
        !engine
            .evaluate(
                "api.anthropic.com",
                "http:POST",
                "/v1/messages",
                &[],
                "worker"
            )
            .unwrap()
            .allowed
    );
    assert!(
        !engine
            .evaluate(
                "api.github.com",
                "http:DELETE",
                "/repos/test-org/my-repo",
                &[],
                "worker"
            )
            .unwrap()
            .allowed
    );
}

#[test]
fn claude_code_denies_push_main() {
    let t = find_template("claude-code").unwrap();
    let policy = t.policy.replace("your-org", "test-org");
    let engine = engine_from_policy(&policy);
    assert!(
        !engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/test-org/my-repo/git/refs/heads/main",
                &[],
                "worker",
            )
            .unwrap()
            .allowed
    );
}

// --- Devcontainer preset parser round-trips (previously inlined) ---

#[test]
fn all_preset_configs_parse_as_toml() {
    // The bundled `strait.toml` must deserialize through the strait
    // CLI's `StraitConfig` -- otherwise `strait preset apply` would
    // produce a file the operator's next `strait proxy` call rejects.
    for preset in PRESETS {
        toml::from_str::<StraitConfig>(preset.strait_toml)
            .unwrap_or_else(|e| panic!("preset {} has invalid strait.toml: {e}", preset.name));
    }
}

#[test]
fn apply_parsed_devcontainer_json_roundtrips_through_parse_devcontainer() {
    let dir = tempfile::tempdir().unwrap();
    let layout = apply("claude-code-devcontainer", dir.path()).unwrap();
    let parsed = parse_devcontainer(&layout.devcontainer_path).unwrap();
    assert!(
        parsed.image.is_some() || parsed.build.is_some(),
        "preset devcontainer.json should either supply an image or a build"
    );
    assert!(find_devcontainer_preset("claude-code-devcontainer").is_some());
}
