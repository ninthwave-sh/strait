//! Built-in Cedar policy templates.
//!
//! Templates are embedded in the binary via `include_str!` and can be
//! listed or applied via the `strait template` subcommand.

use std::path::Path;

/// A built-in policy template with its Cedar policy and schema.
pub struct Template {
    /// Short identifier (e.g. "github-org-readonly").
    pub name: &'static str,
    /// One-line description.
    pub description: &'static str,
    /// Cedar policy text (embedded at compile time).
    pub policy: &'static str,
    /// Cedar schema text (embedded at compile time).
    pub schema: &'static str,
}

/// All built-in templates, ordered by name.
pub const TEMPLATES: &[Template] = &[
    Template {
        name: "aws-s3-readonly",
        description: "Read-only S3 access (GetObject, ListBucket)",
        policy: include_str!("../templates/aws-s3-readonly.cedar"),
        schema: include_str!("../templates/aws-s3-readonly.cedarschema"),
    },
    Template {
        name: "aws-s3-readwrite",
        description: "S3 read + write, deny DeleteBucket/DeleteObject",
        policy: include_str!("../templates/aws-s3-readwrite.cedar"),
        schema: include_str!("../templates/aws-s3-readwrite.cedarschema"),
    },
    Template {
        name: "github-org-contributor",
        description: "Read + PR creation, deny push to main/release branches, deny repo admin",
        policy: include_str!("../templates/github-org-contributor.cedar"),
        schema: include_str!("../templates/github-org-contributor.cedarschema"),
    },
    Template {
        name: "github-org-readonly",
        description: "Read-only access to a GitHub org's repos",
        policy: include_str!("../templates/github-org-readonly.cedar"),
        schema: include_str!("../templates/github-org-readonly.cedarschema"),
    },
];

/// Find a template by name.
pub fn find(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// Print the list of available templates to stdout.
pub fn list() {
    println!("Available policy templates:\n");
    for t in TEMPLATES {
        println!("  {:<30} {}", t.name, t.description);
    }
    println!();
    println!("Apply a template:");
    println!("  strait template apply <name> [--output-dir <dir>]");
}

/// Apply a template: write .cedar + .cedarschema to output_dir, or print to stdout.
pub fn apply(name: &str, output_dir: Option<&Path>) -> anyhow::Result<()> {
    let template = find(name).ok_or_else(|| {
        let valid: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        anyhow::anyhow!(
            "unknown template: {name}\n\nAvailable templates:\n  {}",
            valid.join("\n  ")
        )
    })?;

    match output_dir {
        Some(dir) => {
            std::fs::create_dir_all(dir)?;
            let policy_path = dir.join(format!("{}.cedar", name));
            let schema_path = dir.join(format!("{}.cedarschema", name));
            std::fs::write(&policy_path, template.policy)?;
            std::fs::write(&schema_path, template.schema)?;
            eprintln!("Policy written to {}", policy_path.display());
            eprintln!("Schema written to {}", schema_path.display());
        }
        None => {
            println!("# {}.cedar", name);
            print!("{}", template.policy);
            println!();
            println!("# {}.cedarschema", name);
            print!("{}", template.schema);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    #[test]
    fn all_templates_have_validated_comment() {
        for t in TEMPLATES {
            assert!(
                t.policy.contains("// VALIDATED:"),
                "template {}: policy missing VALIDATED comment",
                t.name
            );
            assert!(
                t.schema.contains("// VALIDATED:"),
                "template {}: schema missing VALIDATED comment",
                t.name
            );
        }
    }

    #[test]
    fn all_templates_pass_cedar_validation() {
        for t in TEMPLATES {
            let policy_set = PolicySet::from_str(t.policy).unwrap_or_else(|e| {
                panic!("template {}: invalid Cedar policy: {e}", t.name);
            });

            let (schema, _warnings) = Schema::from_cedarschema_str(t.schema).unwrap_or_else(|e| {
                panic!("template {}: invalid Cedar schema: {e}", t.name);
            });

            let validator = Validator::new(schema);
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            assert!(
                result.validation_passed(),
                "template {}: Cedar validation failed: {:?}",
                t.name,
                result
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn find_returns_matching_template() {
        assert!(find("github-org-readonly").is_some());
        assert!(find("github-org-contributor").is_some());
        assert!(find("aws-s3-readonly").is_some());
        assert!(find("aws-s3-readwrite").is_some());
    }

    #[test]
    fn find_returns_none_for_unknown() {
        assert!(find("nonexistent").is_none());
    }

    #[test]
    fn apply_unknown_template_returns_error() {
        let result = apply("nonexistent", None);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("unknown template"),
            "error should mention unknown template: {err}"
        );
        // Should list valid template names
        assert!(
            err.contains("github-org-readonly"),
            "error should list valid templates: {err}"
        );
    }

    #[test]
    fn apply_to_output_dir_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        apply("github-org-readonly", Some(dir.path())).unwrap();

        let policy_path = dir.path().join("github-org-readonly.cedar");
        let schema_path = dir.path().join("github-org-readonly.cedarschema");

        assert!(policy_path.exists(), "policy file should exist");
        assert!(schema_path.exists(), "schema file should exist");

        let policy = std::fs::read_to_string(&policy_path).unwrap();
        assert!(
            policy.contains("permit("),
            "policy should contain permit statements"
        );
    }

    #[test]
    fn template_list_contains_all_templates() {
        assert_eq!(TEMPLATES.len(), 4);
        let names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        assert!(names.contains(&"github-org-readonly"));
        assert!(names.contains(&"github-org-contributor"));
        assert!(names.contains(&"aws-s3-readonly"));
        assert!(names.contains(&"aws-s3-readwrite"));
    }
}
