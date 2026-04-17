//! Built-in devcontainer presets.
//!
//! A preset bundles the three files an operator needs for a supported
//! first-run flow -- a devcontainer.json, a strait.toml, and a Cedar
//! policy -- into one named archive that is embedded in the binary.
//!
//! Presets are the operator-ergonomics entry point for the devcontainer
//! trust boundary. A new user runs `strait preset apply <name> <dir>`,
//! gets a complete working setup, and then runs the extracted
//! devcontainer with their usual tooling (VS Code, devcontainer CLI,
//! sandcastle, etc.). strait no longer ships a host-side orchestrator;
//! container lifecycle is the user's responsibility.
//!
//! Presets deliberately do NOT own runtime behavior. They are a thin
//! distribution mechanism: once the files are on disk, every knob is
//! editable.
//!
//! # Relationship to templates
//!
//! `strait template` ships Cedar policies only. A preset ships the full
//! devcontainer-based onboarding shape: container config, proxy config,
//! and starter policy together.
//!
//! # Relationship to `examples/`
//!
//! Each preset mirrors the contents of `examples/<name>/` in the repo.
//! The embedded copy is what ships in the binary so `strait preset
//! apply` works against an installed binary without the repo checkout.

use std::path::{Path, PathBuf};

use anyhow::Context as _;

/// Files that make up a single launch preset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Preset {
    /// Short identifier used with `strait preset apply <name>`.
    pub name: &'static str,
    /// One-line description for `strait preset list`.
    pub description: &'static str,
    /// Contents of the `.devcontainer/devcontainer.json` file.
    pub devcontainer_json: &'static str,
    /// Contents of the `strait.toml` file.
    pub strait_toml: &'static str,
    /// Contents of the `policy.cedar` file.
    pub policy_cedar: &'static str,
    /// Contents of the preset's README.md file.
    pub readme: &'static str,
}

/// All built-in presets, ordered by name.
pub const PRESETS: &[Preset] = &[Preset {
    name: "claude-code-devcontainer",
    description: "Claude Code inside a devcontainer: session CA, GitHub + npm starter policy",
    devcontainer_json: include_str!(
        "../../examples/claude-code-devcontainer/.devcontainer/devcontainer.json"
    ),
    strait_toml: include_str!("../../examples/claude-code-devcontainer/strait.toml"),
    policy_cedar: include_str!("../../examples/claude-code-devcontainer/policy.cedar"),
    readme: include_str!("../../examples/claude-code-devcontainer/README.md"),
}];

/// Filesystem layout produced by `Preset::apply_to`.
///
/// Returned so callers (including the `--preset` shortcut in the launch
/// CLI) can locate the written files without duplicating path logic.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresetLayout {
    /// Directory where the preset was written.
    pub root: PathBuf,
    /// Path to the extracted `.devcontainer/devcontainer.json` file.
    pub devcontainer_path: PathBuf,
    /// Path to the extracted `strait.toml` file.
    pub config_path: PathBuf,
    /// Path to the extracted `policy.cedar` file.
    pub policy_path: PathBuf,
    /// Path to the extracted README.md file.
    pub readme_path: PathBuf,
}

/// How `Preset::apply_to` should treat an existing `policy.cedar` file.
///
/// The other files in a preset (devcontainer.json, strait.toml, README.md)
/// are safe to overwrite -- they do not accumulate user state. The policy
/// file, however, is a durable record of persisted decisions. Overwriting
/// it silently would discard rules the operator opted into keeping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyWriteMode {
    /// Always overwrite `policy.cedar`. Used by `strait preset apply`,
    /// which extracts a fresh starter policy for the operator to edit.
    Overwrite,
    /// Preserve `policy.cedar` if it already exists. Reserved for callers
    /// that keep a long-lived cache of a preset and need persisted
    /// decisions to accumulate across runs.
    #[allow(dead_code)]
    PreserveIfExists,
}

impl Preset {
    /// Write the preset's files into `dir`, creating it if necessary.
    ///
    /// Returns the resulting filesystem layout. Existing devcontainer.json,
    /// strait.toml, and README.md files are always overwritten so the
    /// extracted preset stays in sync with the embedded copy. The
    /// `policy_mode` argument controls how an existing `policy.cedar` is
    /// treated -- see [`PolicyWriteMode`] for the options.
    pub fn apply_to(
        &self,
        dir: &Path,
        policy_mode: PolicyWriteMode,
    ) -> anyhow::Result<PresetLayout> {
        std::fs::create_dir_all(dir).with_context(|| {
            format!(
                "failed to create preset output directory: {}",
                dir.display()
            )
        })?;
        let devcontainer_dir = dir.join(".devcontainer");
        std::fs::create_dir_all(&devcontainer_dir).with_context(|| {
            format!(
                "failed to create .devcontainer directory under preset: {}",
                devcontainer_dir.display()
            )
        })?;
        let devcontainer_path = devcontainer_dir.join("devcontainer.json");
        let config_path = dir.join("strait.toml");
        let policy_path = dir.join("policy.cedar");
        let readme_path = dir.join("README.md");

        std::fs::write(&devcontainer_path, self.devcontainer_json).with_context(|| {
            format!(
                "failed to write devcontainer.json: {}",
                devcontainer_path.display()
            )
        })?;
        std::fs::write(&config_path, self.strait_toml)
            .with_context(|| format!("failed to write strait.toml: {}", config_path.display()))?;

        let should_write_policy = match policy_mode {
            PolicyWriteMode::Overwrite => true,
            PolicyWriteMode::PreserveIfExists => !policy_path.exists(),
        };
        if should_write_policy {
            std::fs::write(&policy_path, self.policy_cedar).with_context(|| {
                format!("failed to write policy.cedar: {}", policy_path.display())
            })?;
        }

        std::fs::write(&readme_path, self.readme)
            .with_context(|| format!("failed to write README.md: {}", readme_path.display()))?;

        Ok(PresetLayout {
            root: dir.to_path_buf(),
            devcontainer_path,
            config_path,
            policy_path,
            readme_path,
        })
    }
}

/// Find a preset by name.
pub fn find(name: &str) -> Option<&'static Preset> {
    PRESETS.iter().find(|preset| preset.name == name)
}

/// Human-readable error message listing the available preset names.
pub fn unknown_preset_error(name: &str) -> anyhow::Error {
    let names: Vec<&str> = PRESETS.iter().map(|preset| preset.name).collect();
    anyhow::anyhow!(
        "unknown preset: {name}\n\nAvailable presets:\n  {}",
        names.join("\n  ")
    )
}

/// Print the list of presets to stdout.
pub fn print_list() {
    println!("Available devcontainer presets:\n");
    for preset in PRESETS {
        println!("  {:<30} {}", preset.name, preset.description);
    }
    println!();
    println!("Apply a preset:");
    println!("  strait preset apply <name> <output-dir>");
    println!();
    println!("Then launch the extracted devcontainer with your usual tooling (VS Code,");
    println!("devcontainer CLI, sandcastle, or direct docker run).");
}

/// Apply a preset by name.
///
/// Writes the four files into `output_dir`, returns the resulting
/// layout, and prints the written paths to stderr. Uses
/// [`PolicyWriteMode::Overwrite`] because `preset apply` is the
/// "extract a fresh starter policy" command -- users expect it to
/// reset the files they edited to the shipped defaults.
pub fn apply(name: &str, output_dir: &Path) -> anyhow::Result<PresetLayout> {
    let preset = find(name).ok_or_else(|| unknown_preset_error(name))?;
    let layout = preset.apply_to(output_dir, PolicyWriteMode::Overwrite)?;
    eprintln!("Preset '{name}' written to {}", layout.root.display());
    eprintln!("  devcontainer: {}", layout.devcontainer_path.display());
    eprintln!("  config:       {}", layout.config_path.display());
    eprintln!("  policy:       {}", layout.policy_path.display());
    eprintln!("  readme:       {}", layout.readme_path.display());
    Ok(layout)
}

/// Onboarding block emitted at launch startup when the operator has
/// opted into a devcontainer launch path.
///
/// Kept small and specific on purpose: the goal is to make the trust
/// boundary and the follow-up loop legible without walking the operator
/// through the whole product.
pub fn devcontainer_onboarding_lines() -> Vec<String> {
    vec![
        "First run? The container trust boundary is local to this session.".to_string(),
        "  - The session CA is bind-mounted read-only at /strait/ca.pem and removed on exit."
            .to_string(),
        "  - Blocked requests are held open and surface as live decisions.".to_string(),
        "  - Approve from the desktop control plane to write a durable Cedar rule.".to_string(),
        "  - Persisted rules land in your policy.cedar and survive across relaunches.".to_string(),
        "  - Re-run the same command in a new session to confirm the rule persisted.".to_string(),
    ]
}

// ---------------------------------------------------------------------------
// Policy preset library
// ---------------------------------------------------------------------------

// Presets below are the server-side default Cedar policies a container
// session can opt into at `RegisterContainer` time. They are distinct
// from the devcontainer [`Preset`] bundle above: a devcontainer preset
// is a file-on-disk CLI helper, a policy preset is a server-side rule
// the rule store loads into the session's scope.
//
// Keeping both lists in the same crate is intentional: the host process
// is the single source of truth for the bundled Cedar corpus, and both
// surfaces (`strait preset apply` for files, `RegisterContainer
// preset_ids` for live opt-in) reuse the Cedar source in `templates/`.

use crate::rule_store::{Rule, RuleAction, RuleDuration, RuleStore};

/// Opaque prefix that identifies rules inserted by the preset library.
///
/// The `{rule_id}` format is `{PRESET_RULE_ID_PREFIX}{id}@{version}`.
/// Rule ids that do not start with this prefix are user-authored.
pub const PRESET_RULE_ID_PREFIX: &str = "preset:";

/// One named Cedar policy the host exposes as a server-side default.
///
/// The `cedar_source` is embedded at compile time from `templates/` so
/// the host process can insert it into the rule store without a filesystem
/// read. `version` is a short, monotonic label -- a preset library update
/// is a new `version` string on the same `id`, so already-registered
/// sessions keep the old Cedar source in their scope while new sessions
/// pick up the update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PolicyPreset {
    /// Short opaque id the operator opts in with, e.g. `github-read`.
    pub id: &'static str,
    /// Monotonic version label. Incremented on any Cedar source change.
    pub version: &'static str,
    /// One-line human description shown in the preset picker.
    pub description: &'static str,
    /// Cedar policy source loaded into the rule store on opt-in.
    pub cedar_source: &'static str,
}

/// Bundled policy presets, ordered by id. Each entry maps a short opt-in
/// id to a Cedar policy from `templates/`. When a container session opts
/// into one at register time, its Cedar source is copied into the rule
/// store under the session's scope and tagged with
/// [`PRESET_RULE_ID_PREFIX`].
pub const POLICY_PRESETS: &[PolicyPreset] = &[
    PolicyPreset {
        id: "aws-read",
        version: "1",
        description: "Read-only S3 access (GetObject, ListBucket, HEAD)",
        cedar_source: include_str!("../../templates/aws-s3-readonly.cedar"),
    },
    PolicyPreset {
        id: "aws-readwrite",
        version: "1",
        description: "S3 read + write, deny DeleteBucket and DeleteObject",
        cedar_source: include_str!("../../templates/aws-s3-readwrite.cedar"),
    },
    PolicyPreset {
        id: "claude-code",
        version: "1",
        description: "Claude Code agent (OAuth): GitHub API + npm registry",
        cedar_source: include_str!("../../templates/claude-code.cedar"),
    },
    PolicyPreset {
        id: "container-sandbox",
        version: "1",
        description: "Container sandbox: scoped HTTP access",
        cedar_source: include_str!("../../templates/container-sandbox.cedar"),
    },
    PolicyPreset {
        id: "github-contributor",
        version: "1",
        description: "Read + PR creation, deny push to main/release branches",
        cedar_source: include_str!("../../templates/github-org-contributor.cedar"),
    },
    PolicyPreset {
        id: "github-read",
        version: "1",
        description: "Read-only access to a GitHub org's repos",
        cedar_source: include_str!("../../templates/github-org-readonly.cedar"),
    },
];

/// Find a policy preset by id.
pub fn find_policy_preset(id: &str) -> Option<&'static PolicyPreset> {
    POLICY_PRESETS.iter().find(|p| p.id == id)
}

/// Build the rule id a preset registers into the rule store. The rule id
/// encodes the preset id and version so a future preset bump registers a
/// fresh row rather than overwriting an already-applied one.
pub fn preset_rule_id(preset_id: &str, version: &str) -> String {
    format!("{PRESET_RULE_ID_PREFIX}{preset_id}@{version}")
}

/// Return `Some((id, version))` if `rule_id` was registered by the preset
/// library. Used by tests and audit tools to distinguish preset-sourced
/// rules from user-authored ones.
pub fn split_preset_rule_id(rule_id: &str) -> Option<(&str, &str)> {
    let tail = rule_id.strip_prefix(PRESET_RULE_ID_PREFIX)?;
    let (id, version) = tail.split_once('@')?;
    Some((id, version))
}

/// Apply a policy preset to the rule store at `scope`. Inserts a single
/// allow rule whose `cedar_source` is the preset's Cedar policy; re-apply
/// with the same `(preset_id, version, scope)` is an upsert, so the call
/// is idempotent.
///
/// Returns the inserted/updated rule (with the freshly assigned
/// `version_token`) so callers can correlate the result with the
/// subsequent `RuleChange::Add` broadcast.
pub fn apply_policy_preset_to_store(
    store: &RuleStore,
    preset: &PolicyPreset,
    scope: &str,
) -> anyhow::Result<Rule> {
    let rule_id = preset_rule_id(preset.id, preset.version);
    store.upsert(Rule {
        rule_id,
        scope: scope.to_string(),
        cedar_source: preset.cedar_source.to_string(),
        action: RuleAction::Allow,
        duration: RuleDuration::Session,
        ttl_unix_ms: None,
        version_token: String::new(),
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::PolicySet;
    use std::str::FromStr;

    #[test]
    fn presets_list_is_non_empty_and_sorted() {
        assert!(!PRESETS.is_empty(), "at least one preset must ship");
        let names: Vec<&str> = PRESETS.iter().map(|p| p.name).collect();
        let mut sorted = names.clone();
        sorted.sort();
        assert_eq!(
            names, sorted,
            "preset list must be sorted alphabetically by name"
        );
    }

    #[test]
    fn all_presets_have_non_empty_fields() {
        for preset in PRESETS {
            assert!(
                !preset.description.is_empty(),
                "{} missing description",
                preset.name
            );
            assert!(
                !preset.devcontainer_json.trim().is_empty(),
                "{} missing devcontainer.json",
                preset.name
            );
            assert!(
                !preset.strait_toml.trim().is_empty(),
                "{} missing strait.toml",
                preset.name
            );
            assert!(
                !preset.policy_cedar.trim().is_empty(),
                "{} missing policy.cedar",
                preset.name
            );
            assert!(
                !preset.readme.trim().is_empty(),
                "{} missing README.md",
                preset.name
            );
        }
    }

    #[test]
    fn claude_code_devcontainer_preset_exists() {
        let preset =
            find("claude-code-devcontainer").expect("claude-code-devcontainer preset should ship");
        assert!(preset.description.contains("Claude Code"));
        assert!(preset.devcontainer_json.contains("\"image\""));
        assert!(preset.strait_toml.contains("[mitm]"));
        assert!(preset.policy_cedar.contains("permit"));
    }

    #[test]
    fn all_preset_policies_parse_as_cedar() {
        for preset in PRESETS {
            PolicySet::from_str(preset.policy_cedar).unwrap_or_else(|e| {
                panic!("preset {} has invalid Cedar policy: {e}", preset.name);
            });
        }
    }

    #[test]
    fn all_preset_policies_use_only_http_actions() {
        for preset in PRESETS {
            let actions: Vec<&str> = preset
                .policy_cedar
                .split("Action::\"")
                .skip(1)
                .map(|rest| rest.split('"').next().unwrap())
                .collect();
            assert!(!actions.is_empty(), "preset {} has no actions", preset.name);
            assert!(
                actions.iter().all(|action| action.starts_with("http:")),
                "preset {} contains non-HTTP actions: {:?}",
                preset.name,
                actions
            );
        }
    }

    #[test]
    fn all_preset_devcontainers_parse_as_json() {
        for preset in PRESETS {
            let parsed: serde_json::Value = json5::from_str(preset.devcontainer_json)
                .unwrap_or_else(|e| {
                    panic!("preset {} has invalid devcontainer.json: {e}", preset.name)
                });
            assert!(
                parsed.is_object(),
                "preset {} devcontainer.json must be an object",
                preset.name
            );
        }
    }

    // The `strait.toml` round-trip through `strait::config::StraitConfig`
    // belongs to the `strait` crate because the config type lives there;
    // see `tests/preset_policy_library.rs` in the root crate.

    #[test]
    fn find_unknown_preset_returns_none() {
        assert!(find("does-not-exist").is_none());
    }

    #[test]
    fn unknown_preset_error_lists_available_names() {
        let message = unknown_preset_error("nope").to_string();
        for preset in PRESETS {
            assert!(
                message.contains(preset.name),
                "error should list preset {}: {message}",
                preset.name
            );
        }
    }

    #[test]
    fn apply_writes_all_files_to_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        let layout = apply("claude-code-devcontainer", dir.path()).unwrap();

        assert!(layout.devcontainer_path.exists());
        assert!(layout.config_path.exists());
        assert!(layout.policy_path.exists());
        assert!(layout.readme_path.exists());

        let devcontainer = std::fs::read_to_string(&layout.devcontainer_path).unwrap();
        assert!(devcontainer.contains("\"image\""));
        let config = std::fs::read_to_string(&layout.config_path).unwrap();
        assert!(config.contains("[mitm]"));
        let policy = std::fs::read_to_string(&layout.policy_path).unwrap();
        assert!(policy.contains("permit"));
    }

    #[test]
    fn apply_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let first = apply("claude-code-devcontainer", dir.path()).unwrap();
        let second = apply("claude-code-devcontainer", dir.path()).unwrap();
        assert_eq!(first, second);
    }

    #[test]
    fn apply_overwrite_mode_resets_user_edits_to_policy() {
        // `preset apply` is the "extract a fresh starter policy"
        // command. Re-running it after the operator edited the policy
        // should restore the shipped content.
        let dir = tempfile::tempdir().unwrap();
        let preset = find("claude-code-devcontainer").unwrap();
        let layout = preset
            .apply_to(dir.path(), PolicyWriteMode::Overwrite)
            .unwrap();
        std::fs::write(&layout.policy_path, "// user edit\n").unwrap();
        preset
            .apply_to(dir.path(), PolicyWriteMode::Overwrite)
            .unwrap();
        let restored = std::fs::read_to_string(&layout.policy_path).unwrap();
        assert_eq!(
            restored, preset.policy_cedar,
            "Overwrite mode should restore the shipped policy content"
        );
    }

    #[test]
    fn apply_preserve_mode_keeps_existing_policy() {
        // Callers that keep a long-lived cache of an applied preset need
        // persisted decisions to accumulate across applies. The second
        // apply in PreserveIfExists mode must not overwrite them.
        let dir = tempfile::tempdir().unwrap();
        let preset = find("claude-code-devcontainer").unwrap();

        let layout = preset
            .apply_to(dir.path(), PolicyWriteMode::PreserveIfExists)
            .unwrap();
        let starter_policy = std::fs::read_to_string(&layout.policy_path).unwrap();
        assert_eq!(starter_policy, preset.policy_cedar);

        let persisted_policy = format!(
            "{}\n\n@id(\"allow-acme-api\")\npermit(principal, action, resource in Resource::\"api.acme.test\");\n",
            preset.policy_cedar
        );
        std::fs::write(&layout.policy_path, &persisted_policy).unwrap();

        preset
            .apply_to(dir.path(), PolicyWriteMode::PreserveIfExists)
            .unwrap();

        let after_relaunch = std::fs::read_to_string(&layout.policy_path).unwrap();
        assert_eq!(
            after_relaunch, persisted_policy,
            "PreserveIfExists must keep persisted decisions across relaunches"
        );
    }

    #[test]
    fn apply_preserve_mode_still_overwrites_non_policy_files() {
        // PreserveIfExists should only protect the policy file. The
        // devcontainer.json, strait.toml, and README.md files stay in
        // sync with the embedded binary copy after upgrades.
        let dir = tempfile::tempdir().unwrap();
        let preset = find("claude-code-devcontainer").unwrap();
        let layout = preset
            .apply_to(dir.path(), PolicyWriteMode::PreserveIfExists)
            .unwrap();

        std::fs::write(&layout.devcontainer_path, "{ \"stale\": true }").unwrap();
        std::fs::write(&layout.config_path, "# stale\n").unwrap();
        std::fs::write(&layout.readme_path, "stale readme").unwrap();

        preset
            .apply_to(dir.path(), PolicyWriteMode::PreserveIfExists)
            .unwrap();

        assert_eq!(
            std::fs::read_to_string(&layout.devcontainer_path).unwrap(),
            preset.devcontainer_json,
        );
        assert_eq!(
            std::fs::read_to_string(&layout.config_path).unwrap(),
            preset.strait_toml,
        );
        assert_eq!(
            std::fs::read_to_string(&layout.readme_path).unwrap(),
            preset.readme,
        );
    }

    #[test]
    fn apply_preserve_mode_writes_policy_on_first_apply() {
        // Starter policy must be written when the cache directory is
        // fresh -- PreserveIfExists only short-circuits on second and
        // later applies.
        let dir = tempfile::tempdir().unwrap();
        let preset = find("claude-code-devcontainer").unwrap();
        let layout = preset
            .apply_to(dir.path(), PolicyWriteMode::PreserveIfExists)
            .unwrap();
        assert!(layout.policy_path.exists());
        assert_eq!(
            std::fs::read_to_string(&layout.policy_path).unwrap(),
            preset.policy_cedar,
        );
    }

    #[test]
    fn apply_unknown_preset_bails() {
        let dir = tempfile::tempdir().unwrap();
        let err = apply("does-not-exist", dir.path()).unwrap_err();
        assert!(err.to_string().contains("unknown preset"));
    }

    // The `parse_devcontainer` round-trip lives in the `strait` crate
    // (see `tests/preset_policy_library.rs`) because the parser it
    // exercises is in the strait CLI, not in this crate.

    #[test]
    fn devcontainer_onboarding_lines_name_trust_boundary_and_persist_flow() {
        let lines = devcontainer_onboarding_lines();
        assert!(
            lines.iter().any(|line| line.contains("trust boundary")),
            "onboarding should name the trust boundary: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("/strait/ca.pem")),
            "onboarding should name the session-local CA path: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("blocked") || line.contains("Blocked")),
            "onboarding should describe the blocked-request hold: {lines:?}"
        );
        assert!(
            lines
                .iter()
                .any(|line| line.contains("desktop control plane") || line.contains("durable")),
            "onboarding should point operators at a persist path: {lines:?}"
        );
        assert!(
            lines.iter().any(|line| line.contains("new session")),
            "onboarding should tell operators to confirm persistence: {lines:?}"
        );
    }

    #[test]
    fn preset_contents_match_examples_directory() {
        // The binary-embedded preset and the repo example must stay in
        // sync. The example directory is the canonical dogfood path; the
        // embedded copy is what ships in the compiled binary.
        let preset = find("claude-code-devcontainer").unwrap();
        // `CARGO_MANIFEST_DIR` for this crate is the `host/` subdirectory;
        // the example directory lives one level up at the repo root.
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("host manifest dir has a parent");
        let example_root = repo_root.join("examples/claude-code-devcontainer");

        let on_disk_dc =
            std::fs::read_to_string(example_root.join(".devcontainer/devcontainer.json")).unwrap();
        let on_disk_toml = std::fs::read_to_string(example_root.join("strait.toml")).unwrap();
        let on_disk_policy = std::fs::read_to_string(example_root.join("policy.cedar")).unwrap();
        let on_disk_readme = std::fs::read_to_string(example_root.join("README.md")).unwrap();

        assert_eq!(preset.devcontainer_json, on_disk_dc);
        assert_eq!(preset.strait_toml, on_disk_toml);
        assert_eq!(preset.policy_cedar, on_disk_policy);
        assert_eq!(preset.readme, on_disk_readme);
    }

    // --- Policy preset library tests ---

    #[test]
    fn policy_presets_are_non_empty_and_sorted_by_id() {
        assert!(
            !POLICY_PRESETS.is_empty(),
            "policy preset library must ship at least one entry"
        );
        let ids: Vec<&str> = POLICY_PRESETS.iter().map(|p| p.id).collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(
            ids, sorted,
            "policy preset list must be sorted alphabetically by id"
        );
    }

    #[test]
    fn policy_preset_library_ships_github_aws_and_sandbox_parity() {
        // Acceptance: "The current preset library (GitHub, AWS, container
        // sandbox) reaches parity in the new home." Guard the required ids
        // so a future rename surfaces as a failing test rather than a
        // silent regression in the onboarding picker.
        for required in [
            "aws-read",
            "aws-readwrite",
            "claude-code",
            "container-sandbox",
            "github-contributor",
            "github-read",
        ] {
            assert!(
                find_policy_preset(required).is_some(),
                "policy preset library must include {required}"
            );
        }
    }

    #[test]
    fn policy_preset_cedar_sources_parse() {
        for preset in POLICY_PRESETS {
            PolicySet::from_str(preset.cedar_source).unwrap_or_else(|e| {
                panic!("policy preset {} has invalid Cedar source: {e}", preset.id);
            });
        }
    }

    #[test]
    fn preset_rule_id_round_trips_through_split() {
        let id = preset_rule_id("github-read", "1");
        assert_eq!(id, "preset:github-read@1");
        let (preset_id, version) = split_preset_rule_id(&id).unwrap();
        assert_eq!(preset_id, "github-read");
        assert_eq!(version, "1");
    }

    #[test]
    fn split_preset_rule_id_rejects_user_authored_ids() {
        // A user-authored rule id carries no `preset:` prefix so the
        // splitter returns None. This is what the audit path relies on to
        // distinguish preset-sourced rules.
        assert!(split_preset_rule_id("persist-allow:default:api.github.com:http:GET").is_none());
        assert!(split_preset_rule_id("custom-rule").is_none());
    }

    #[test]
    fn apply_policy_preset_inserts_session_scoped_rule() {
        let store = RuleStore::in_memory().unwrap();
        let preset = find_policy_preset("github-read").unwrap();
        let rule = apply_policy_preset_to_store(&store, preset, "sess-alpha").unwrap();
        assert_eq!(rule.rule_id, "preset:github-read@1");
        assert_eq!(rule.scope, "sess-alpha");
        assert_eq!(rule.duration, RuleDuration::Session);
        assert!(
            rule.cedar_source.contains("@id(\"read-org-repos\")"),
            "cedar source should be the templates/github-org-readonly.cedar body"
        );

        // The rule must be visible through the store as a session-scoped
        // row -- default-scoped consumers must not see it.
        let visible = store.snapshot_for_session("sess-alpha").unwrap();
        assert!(visible.iter().any(|r| r.rule_id == rule.rule_id));
        let other = store.snapshot_for_session("sess-other").unwrap();
        assert!(!other.iter().any(|r| r.rule_id == rule.rule_id));
    }

    #[test]
    fn apply_policy_preset_is_idempotent_for_same_version() {
        let store = RuleStore::in_memory().unwrap();
        let preset = find_policy_preset("container-sandbox").unwrap();
        let first = apply_policy_preset_to_store(&store, preset, "sess-x").unwrap();
        let second = apply_policy_preset_to_store(&store, preset, "sess-x").unwrap();
        assert_eq!(first.rule_id, second.rule_id);
        // Upsert assigns a fresh `version_token` on every call so stream
        // consumers can de-duplicate; the row count must still be one.
        assert_ne!(first.version_token, second.version_token);
        let all = store.list_all().unwrap();
        assert_eq!(all.len(), 1, "idempotent re-apply must not duplicate rows");
    }

    #[test]
    fn preset_version_bump_does_not_overwrite_existing_session_rule() {
        // Edge case from the test plan: "preset updated across a version
        // bump -- existing containers keep their pinned version unless
        // explicitly upgraded". Simulate a version bump by applying the
        // same preset id twice with different versions; the older rule
        // must survive so a session that registered before the bump keeps
        // its original Cedar source.
        let store = RuleStore::in_memory().unwrap();
        let original = PolicyPreset {
            id: "example",
            version: "1",
            description: "v1",
            cedar_source: "permit(principal, action, resource);\n",
        };
        let bumped = PolicyPreset {
            id: "example",
            version: "2",
            description: "v2",
            cedar_source: "permit(principal, action, resource == Resource::\"v2\");\n",
        };
        let v1 = apply_policy_preset_to_store(&store, &original, "sess-old").unwrap();
        let v2 = apply_policy_preset_to_store(&store, &bumped, "sess-new").unwrap();
        assert_ne!(v1.rule_id, v2.rule_id);
        // Both rows must still be present; the old session keeps `v1`.
        assert!(store.get(&v1.rule_id).unwrap().is_some());
        assert!(store.get(&v2.rule_id).unwrap().is_some());
        let old = store.get(&v1.rule_id).unwrap().unwrap();
        assert_eq!(old.cedar_source, original.cedar_source);
    }
}
