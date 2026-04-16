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

/// The Cedar schema covering Strait's HTTP action domain.
///
/// Use this for policies that scope outbound network access. AWS context attributes
/// (`aws_service`, `aws_region`) are declared as optional so they validate
/// correctly for both AWS and non-AWS policies.
pub const UNIFIED_SCHEMA: &str = include_str!("../templates/strait.cedarschema");

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
        name: "claude-code",
        description: "Claude Code agent (OAuth): GitHub API and npm registry",
        policy: include_str!("../templates/claude-code.cedar"),
        schema: include_str!("../templates/strait.cedarschema"),
    },
    Template {
        name: "container-sandbox",
        description: "Container sandbox: scoped HTTP access",
        policy: include_str!("../templates/container-sandbox.cedar"),
        schema: include_str!("../templates/strait.cedarschema"),
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

    fn policy_actions(policy: &str) -> Vec<&str> {
        policy
            .split("Action::\"")
            .skip(1)
            .map(|rest| rest.split('"').next().unwrap())
            .collect()
    }

    fn engine_from_policy(policy: &str) -> crate::policy::PolicyEngine {
        crate::policy::PolicyEngine::from_text(policy, None, None).unwrap()
    }

    #[test]
    fn all_templates_have_validated_comment() {
        for t in TEMPLATES {
            assert!(
                t.policy.contains("// VALIDATED:"),
                "template {} missing policy marker",
                t.name
            );
            assert!(
                t.schema.contains("// VALIDATED:"),
                "template {} missing schema marker",
                t.name
            );
        }
    }

    #[test]
    fn all_templates_pass_cedar_validation() {
        for t in TEMPLATES {
            let policy_set = PolicySet::from_str(t.policy).unwrap_or_else(|e| {
                panic!("template {} invalid Cedar policy: {e}", t.name);
            });
            let (schema, _warnings) = Schema::from_cedarschema_str(t.schema).unwrap_or_else(|e| {
                panic!("template {} invalid Cedar schema: {e}", t.name);
            });
            let validator = Validator::new(schema);
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            assert!(
                result.validation_passed(),
                "template {} validation failed: {:?}",
                t.name,
                result
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn all_templates_only_use_http_actions() {
        for t in TEMPLATES {
            let actions = policy_actions(t.policy);
            assert!(!actions.is_empty(), "template {} has no actions", t.name);
            assert!(
                actions.iter().all(|action| action.starts_with("http:")),
                "template {} contains non-HTTP actions: {:?}",
                t.name,
                actions
            );
        }
    }

    #[test]
    fn find_returns_matching_template() {
        assert!(find("github-org-readonly").is_some());
        assert!(find("github-org-contributor").is_some());
        assert!(find("aws-s3-readonly").is_some());
        assert!(find("aws-s3-readwrite").is_some());
        assert!(find("claude-code").is_some());
        assert!(find("container-sandbox").is_some());
    }

    #[test]
    fn apply_to_output_dir_writes_files() {
        let dir = tempfile::tempdir().unwrap();
        apply("github-org-readonly", Some(dir.path())).unwrap();
        assert!(dir.path().join("github-org-readonly.cedar").exists());
        assert!(dir.path().join("github-org-readonly.cedarschema").exists());
    }

    #[test]
    fn aws_s3_readwrite_permits_put_denies_delete() {
        let t = find("aws-s3-readwrite").unwrap();
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
        let t = find("container-sandbox").unwrap();
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
        let t = find("claude-code").unwrap();
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
        let t = find("claude-code").unwrap();
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
        let t = find("claude-code").unwrap();
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
}
