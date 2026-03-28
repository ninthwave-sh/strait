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

/// The unified Cedar schema covering all action domains (HTTP, fs, proc).
///
/// Use this when combining rules from multiple domains (e.g. GitHub + AWS,
/// or HTTP + filesystem for container sandboxes). AWS context attributes
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
        name: "container-sandbox",
        description: "Container sandbox: fs read/write + scoped HTTP access",
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
        assert!(find("container-sandbox").is_some());
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
        assert_eq!(TEMPLATES.len(), 5);
        let names: Vec<&str> = TEMPLATES.iter().map(|t| t.name).collect();
        assert!(names.contains(&"github-org-readonly"));
        assert!(names.contains(&"github-org-contributor"));
        assert!(names.contains(&"aws-s3-readonly"));
        assert!(names.contains(&"aws-s3-readwrite"));
        assert!(names.contains(&"container-sandbox"));
    }

    // -----------------------------------------------------------------------
    // Unified schema tests
    // -----------------------------------------------------------------------

    #[test]
    fn unified_schema_parses() {
        let (schema, warnings) =
            Schema::from_cedarschema_str(UNIFIED_SCHEMA).expect("unified schema should parse");
        // Warnings are informational; schema must parse cleanly
        let warnings: Vec<_> = warnings.collect();
        assert!(
            warnings.is_empty(),
            "unified schema produced warnings: {warnings:?}"
        );

        // Validate each template policy against the unified schema
        for t in TEMPLATES {
            let policy_set = PolicySet::from_str(t.policy).unwrap_or_else(|e| {
                panic!("template {}: invalid Cedar policy: {e}", t.name);
            });
            let validator = Validator::new(schema.clone());
            let result = validator.validate(&policy_set, ValidationMode::Strict);
            assert!(
                result.validation_passed(),
                "template {} failed unified schema validation: {:?}",
                t.name,
                result
                    .validation_errors()
                    .map(|e| e.to_string())
                    .collect::<Vec<_>>()
            );
        }
    }

    #[test]
    fn unified_schema_validates_combined_github_and_aws_policy() {
        // A policy that combines GitHub reads with AWS S3 reads —
        // should validate against the unified schema since AWS attributes
        // are optional.
        let combined_policy = r#"
@id("github-read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/test-org"
);

@id("s3-read")
permit(
    principal,
    action == Action::"http:GET",
    resource
) when { context has aws_service && context.aws_service == "s3" };
"#;

        let policy_set = PolicySet::from_str(combined_policy).unwrap();
        let (schema, _) = Schema::from_cedarschema_str(UNIFIED_SCHEMA).unwrap();
        let validator = Validator::new(schema);
        let result = validator.validate(&policy_set, ValidationMode::Strict);
        assert!(
            result.validation_passed(),
            "combined GitHub+AWS policy should validate: {:?}",
            result
                .validation_errors()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
        );
    }

    // -----------------------------------------------------------------------
    // Behavioral tests — evaluate templates against concrete requests
    // -----------------------------------------------------------------------

    use crate::policy::PolicyEngine;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Write policy text to a temp file and load a PolicyEngine from it.
    fn engine_from_policy(policy_text: &str) -> PolicyEngine {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(policy_text.as_bytes()).unwrap();
        f.flush().unwrap();
        PolicyEngine::load(f.path(), None).unwrap()
    }

    // --- github-org-readonly behavioral tests ---

    #[test]
    fn github_readonly_permits_get_org_repo() {
        let t = find("github-org-readonly").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/test-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "GET /repos/test-org/my-repo should be allowed"
        );
    }

    #[test]
    fn github_readonly_denies_post_org_repo() {
        let t = find("github-org-readonly").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/test-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "POST /repos/test-org/my-repo should be denied (read-only)"
        );
    }

    #[test]
    fn github_readonly_denies_outside_org() {
        let t = find("github-org-readonly").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/other-org/repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "GET /repos/other-org/repo should be denied (outside org)"
        );
    }

    // --- github-org-contributor behavioral tests ---

    #[test]
    fn github_contributor_permits_get_and_pr_creation() {
        let t = find("github-org-contributor").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        // GET should be allowed
        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/test-org/my-repo/issues",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "GET /repos/test-org/my-repo/issues should be allowed"
        );

        // POST to /pulls should be allowed
        let result = engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/test-org/my-repo/pulls",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "POST /repos/test-org/my-repo/pulls should be allowed"
        );
    }

    #[test]
    fn github_contributor_denies_push_main() {
        let t = find("github-org-contributor").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:POST",
                "/repos/test-org/my-repo/git/refs/heads/main",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            !result.allowed,
            "POST to git/refs/heads/main should be denied"
        );
    }

    #[test]
    fn github_contributor_denies_repo_delete() {
        let t = find("github-org-contributor").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:DELETE",
                "/repos/test-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "DELETE on repo should be denied");
    }

    // --- aws-s3-readonly behavioral tests ---

    #[test]
    fn aws_s3_readonly_permits_get_denies_put() {
        let t = find("aws-s3-readonly").unwrap();
        let engine = engine_from_policy(t.policy);

        // GET should be allowed (aws_service is populated by evaluate)
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:GET",
                "/my-bucket/my-key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "GET on S3 should be allowed");

        // PUT should be denied
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:PUT",
                "/my-bucket/my-key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "PUT on S3 should be denied (read-only)");
    }

    #[test]
    fn aws_s3_readonly_permits_head() {
        let t = find("aws-s3-readonly").unwrap();
        let engine = engine_from_policy(t.policy);

        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:HEAD",
                "/my-bucket/my-key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "HEAD on S3 should be allowed");
    }

    // --- aws-s3-readwrite behavioral tests ---

    #[test]
    fn aws_s3_readwrite_permits_put_denies_delete() {
        let t = find("aws-s3-readwrite").unwrap();
        let engine = engine_from_policy(t.policy);

        // PUT should be allowed
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:PUT",
                "/my-bucket/my-key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(result.allowed, "PUT on S3 should be allowed (readwrite)");

        // DELETE should be denied
        let result = engine
            .evaluate(
                "s3.us-east-1.amazonaws.com",
                "http:DELETE",
                "/my-bucket/my-key",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "DELETE on S3 should be denied");
    }

    // --- container-sandbox behavioral tests ---

    #[test]
    fn container_sandbox_permits_fs_read_workspace() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate_fs("/project/src/main.rs", "fs:read", "worker")
            .unwrap();
        assert!(
            result.allowed,
            "fs:read /project/src/main.rs should be allowed"
        );
    }

    #[test]
    fn container_sandbox_permits_fs_write_workspace() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate_fs("/project/src/main.rs", "fs:write", "worker")
            .unwrap();
        assert!(
            result.allowed,
            "fs:write /project/src/main.rs should be allowed"
        );
    }

    #[test]
    fn container_sandbox_permits_fs_read_system() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        // System paths should allow read
        let result = engine
            .evaluate_fs("/usr/lib/libc.so", "fs:read", "worker")
            .unwrap();
        assert!(
            result.allowed,
            "fs:read /usr/lib/libc.so should be allowed (system-readonly)"
        );
    }

    #[test]
    fn container_sandbox_denies_fs_write_system() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        // System paths should deny write
        let result = engine
            .evaluate_fs("/etc/passwd", "fs:write", "worker")
            .unwrap();
        assert!(
            !result.allowed,
            "fs:write /etc/passwd should be denied (read-only path)"
        );
    }

    #[test]
    fn container_sandbox_permits_github_get() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        let result = engine
            .evaluate(
                "api.github.com",
                "http:GET",
                "/repos/test-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(
            result.allowed,
            "http:GET to GitHub org repo should be allowed"
        );
    }

    #[test]
    fn container_sandbox_denies_unauthorized_http() {
        let t = find("container-sandbox").unwrap();
        let policy = t.policy.replace("your-org", "test-org");
        let engine = engine_from_policy(&policy);

        // PUT to GitHub should be denied (only GET and POST /pulls are allowed)
        let result = engine
            .evaluate(
                "api.github.com",
                "http:PUT",
                "/repos/test-org/my-repo",
                &[],
                "worker",
            )
            .unwrap();
        assert!(!result.allowed, "http:PUT to GitHub should be denied");

        // GET to unscoped host should be denied
        let result = engine
            .evaluate("example.com", "http:GET", "/", &[], "worker")
            .unwrap();
        assert!(!result.allowed, "http:GET to example.com should be denied");
    }
}
