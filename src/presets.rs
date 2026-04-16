//! Built-in launch presets.
//!
//! A preset bundles the three files an operator needs for a supported
//! first-run flow -- a devcontainer.json, a strait.toml, and a Cedar
//! policy -- into one named archive that is embedded in the binary.
//!
//! Presets are the operator-ergonomics entry point for the devcontainer
//! trust boundary. A new user runs `strait preset apply <name> <dir>`,
//! gets a complete working setup, and launches with
//! `strait launch --devcontainer ... --config ... --policy ...` from
//! inside the extracted directory.
//!
//! Presets deliberately do NOT own runtime behavior. They are a thin
//! distribution mechanism: once the files are on disk, the rest of the
//! launch flow is unchanged and every knob is editable.
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
        "../examples/claude-code-devcontainer/.devcontainer/devcontainer.json"
    ),
    strait_toml: include_str!("../examples/claude-code-devcontainer/strait.toml"),
    policy_cedar: include_str!("../examples/claude-code-devcontainer/policy.cedar"),
    readme: include_str!("../examples/claude-code-devcontainer/README.md"),
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

impl Preset {
    /// Write the preset's files into `dir`, creating it if necessary.
    ///
    /// Returns the resulting filesystem layout. Existing files are
    /// overwritten so `preset apply` is idempotent.
    pub fn apply_to(&self, dir: &Path) -> anyhow::Result<PresetLayout> {
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
        std::fs::write(&policy_path, self.policy_cedar)
            .with_context(|| format!("failed to write policy.cedar: {}", policy_path.display()))?;
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
    println!("Available launch presets:\n");
    for preset in PRESETS {
        println!("  {:<30} {}", preset.name, preset.description);
    }
    println!();
    println!("Apply a preset:");
    println!("  strait preset apply <name> <output-dir>");
    println!();
    println!("Launch with an applied preset:");
    println!("  strait launch --preset <name> -- <command> [args...]");
}

/// Apply a preset by name.
///
/// Writes the four files into `output_dir`, returns the resulting
/// layout, and prints the written paths to stderr.
pub fn apply(name: &str, output_dir: &Path) -> anyhow::Result<PresetLayout> {
    let preset = find(name).ok_or_else(|| unknown_preset_error(name))?;
    let layout = preset.apply_to(output_dir)?;
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
        "  - Approve once via `strait session persist-decision --session <ID> <BLOCKED_ID>`,"
            .to_string(),
        "    or from the desktop control plane, to write a durable Cedar rule.".to_string(),
        "  - Re-run the same command in a new session to confirm the rule persisted.".to_string(),
    ]
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

    #[test]
    fn all_preset_configs_parse_as_toml() {
        for preset in PRESETS {
            toml::from_str::<crate::config::StraitConfig>(preset.strait_toml)
                .unwrap_or_else(|e| panic!("preset {} has invalid strait.toml: {e}", preset.name));
        }
    }

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
    fn apply_unknown_preset_bails() {
        let dir = tempfile::tempdir().unwrap();
        let err = apply("does-not-exist", dir.path()).unwrap_err();
        assert!(err.to_string().contains("unknown preset"));
    }

    #[test]
    fn apply_parsed_devcontainer_json_roundtrips_through_parse_devcontainer() {
        let dir = tempfile::tempdir().unwrap();
        let layout = apply("claude-code-devcontainer", dir.path()).unwrap();
        let parsed = crate::config::parse_devcontainer(&layout.devcontainer_path).unwrap();
        assert!(
            parsed.image.is_some() || parsed.build.is_some(),
            "preset devcontainer.json should either supply an image or a build"
        );
    }

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
            lines.iter().any(|line| line.contains("persist-decision")),
            "onboarding should point operators at persist-decision: {lines:?}"
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
        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR"));
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
}
