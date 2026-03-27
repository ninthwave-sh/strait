//! Built-in policy templates for common access patterns.
//!
//! Templates are embedded in the binary at compile time via `include_str!`.
//! Each template includes a Cedar policy file and a matching Cedar schema.
//!
//! Use `strait template list` to see available templates and
//! `strait template apply <name>` to extract one to disk or stdout.

use std::path::Path;

/// A built-in policy template with its Cedar policy and schema.
pub struct Template {
    /// Short name used on the CLI (e.g. "github-org-readonly").
    pub name: &'static str,
    /// One-line description of the template.
    pub description: &'static str,
    /// Cedar policy source (`.cedar`).
    pub cedar: &'static str,
    /// Cedar schema source (`.cedarschema`).
    pub schema: &'static str,
}

/// All built-in templates, ordered by name.
static TEMPLATES: &[Template] = &[
    Template {
        name: "aws-s3-readonly",
        description: "Read-only S3 access (GetObject, ListBucket)",
        cedar: include_str!("../templates/aws-s3-readonly/policy.cedar"),
        schema: include_str!("../templates/aws-s3-readonly/policy.cedarschema"),
    },
    Template {
        name: "aws-s3-readwrite",
        description: "S3 read + write, deny DeleteBucket/DeleteObject",
        cedar: include_str!("../templates/aws-s3-readwrite/policy.cedar"),
        schema: include_str!("../templates/aws-s3-readwrite/policy.cedarschema"),
    },
    Template {
        name: "github-org-contributor",
        description: "Read + PR creation, deny push to main/release branches",
        cedar: include_str!("../templates/github-org-contributor/policy.cedar"),
        schema: include_str!("../templates/github-org-contributor/policy.cedarschema"),
    },
    Template {
        name: "github-org-readonly",
        description: "Read-only access to a GitHub org's repos",
        cedar: include_str!("../templates/github-org-readonly/policy.cedar"),
        schema: include_str!("../templates/github-org-readonly/policy.cedarschema"),
    },
];

/// Return all built-in templates.
pub fn list() -> &'static [Template] {
    TEMPLATES
}

/// Look up a template by name.
pub fn get(name: &str) -> Option<&'static Template> {
    TEMPLATES.iter().find(|t| t.name == name)
}

/// Apply a template: write `.cedar` and `.cedarschema` files to `output_dir`,
/// or print both to stdout if `output_dir` is `None`.
pub fn apply(name: &str, output_dir: Option<&Path>) -> anyhow::Result<()> {
    let template = get(name).ok_or_else(|| {
        let valid: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        anyhow::anyhow!(
            "unknown template: {name}\n\nAvailable templates:\n  {}",
            valid.join("\n  ")
        )
    })?;

    if let Some(dir) = output_dir {
        std::fs::create_dir_all(dir)?;

        let cedar_path = dir.join(format!("{}.cedar", template.name));
        let schema_path = dir.join(format!("{}.cedarschema", template.name));

        std::fs::write(&cedar_path, template.cedar)?;
        std::fs::write(&schema_path, template.schema)?;

        eprintln!("Written: {}", cedar_path.display());
        eprintln!("Written: {}", schema_path.display());
    } else {
        println!("--- {}.cedar ---", template.name);
        print!("{}", template.cedar);
        println!();
        println!("--- {}.cedarschema ---", template.name);
        print!("{}", template.schema);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cedar_policy::{PolicySet, Schema, ValidationMode, Validator};
    use std::str::FromStr;

    #[test]
    fn test_list_returns_all_templates() {
        let templates = list();
        assert_eq!(templates.len(), 4);

        let names: Vec<&str> = templates.iter().map(|t| t.name).collect();
        assert!(names.contains(&"github-org-readonly"));
        assert!(names.contains(&"github-org-contributor"));
        assert!(names.contains(&"aws-s3-readonly"));
        assert!(names.contains(&"aws-s3-readwrite"));
    }

    #[test]
    fn test_get_valid_template() {
        let t = get("github-org-readonly");
        assert!(t.is_some());
        assert_eq!(t.unwrap().name, "github-org-readonly");
    }

    #[test]
    fn test_get_unknown_template() {
        assert!(get("does-not-exist").is_none());
    }

    #[test]
    fn test_apply_unknown_template_error() {
        let result = apply("does-not-exist", None);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("unknown template: does-not-exist"));
        assert!(msg.contains("github-org-readonly"));
    }

    #[test]
    fn test_apply_to_output_dir() {
        let dir = tempfile::tempdir().unwrap();
        apply("github-org-readonly", Some(dir.path())).unwrap();

        let cedar_path = dir.path().join("github-org-readonly.cedar");
        let schema_path = dir.path().join("github-org-readonly.cedarschema");

        assert!(cedar_path.exists());
        assert!(schema_path.exists());

        let cedar_content = std::fs::read_to_string(&cedar_path).unwrap();
        assert!(cedar_content.contains("read-org-repos"));

        let schema_content = std::fs::read_to_string(&schema_path).unwrap();
        assert!(schema_content.contains("entity Agent"));
    }

    #[test]
    fn test_all_templates_have_validated_comment() {
        for template in list() {
            assert!(
                template.cedar.contains("# VALIDATED:"),
                "template {} .cedar missing VALIDATED comment",
                template.name
            );
            assert!(
                template.schema.contains("# VALIDATED:"),
                "template {} .cedarschema missing VALIDATED comment",
                template.name
            );
        }
    }

    #[test]
    fn test_all_templates_pass_cedar_validate() {
        for template in list() {
            // Parse Cedar policy
            let policy_set = PolicySet::from_str(template.cedar).unwrap_or_else(|e| {
                panic!("template {} has invalid Cedar policy: {e}", template.name)
            });

            // Parse Cedar schema
            let (schema, _warnings) =
                Schema::from_cedarschema_str(template.schema).unwrap_or_else(|e| {
                    panic!("template {} has invalid Cedar schema: {e}", template.name)
                });

            // Validate policy against schema
            let validator = Validator::new(schema);
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            if !result.validation_passed() {
                let errors: Vec<String> = result
                    .validation_errors()
                    .map(|e| format!("  - {e}"))
                    .collect();
                panic!(
                    "template {} fails Cedar validation:\n{}",
                    template.name,
                    errors.join("\n")
                );
            }
        }
    }
}
