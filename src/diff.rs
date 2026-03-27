//! Semantic diff between two Cedar policy files.
//!
//! Extracts permission-level information from Cedar policies and shows
//! what access changed between two versions. Not a text diff — a structured
//! comparison of what each policy permits and forbids.
//!
//! For each policy statement the parser extracts:
//! - effect (permit / forbid)
//! - action(s) (e.g. `http:GET`, `fs:read`, or "any")
//! - resource (e.g. `api.github.com/repos/our-org`, or "any")
//! - when/unless conditions
//! - `@id` / `@reason` annotations
//!
//! Two permissions are considered *the same* when their (effect, action,
//! resource, condition) tuple matches — annotations are metadata only.

use std::collections::BTreeSet;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

use anyhow::Context as _;
use cedar_policy::PolicySet;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A single permission extracted from a Cedar policy statement.
#[derive(Debug, Clone)]
pub struct Permission {
    /// permit or forbid.
    pub effect: Effect,
    /// The action, e.g. `"http:GET"`, `"fs:read"`, or `"any"`.
    pub action: String,
    /// The resource, e.g. `"api.github.com/repos/our-org"`, or `"any"`.
    pub resource: String,
    /// Optional when/unless condition text.
    pub condition: Option<String>,
    /// Optional `@id` annotation.
    pub id: Option<String>,
    /// Optional `@reason` annotation.
    pub reason: Option<String>,
}

/// Effect of a Cedar policy statement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Effect {
    Permit,
    Forbid,
}

impl fmt::Display for Effect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Effect::Permit => write!(f, "permit"),
            Effect::Forbid => write!(f, "forbid"),
        }
    }
}

/// Semantic comparison key — ignores annotations.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct PermKey {
    effect: Effect,
    action: String,
    resource: String,
    condition: Option<String>,
}

impl Permission {
    fn key(&self) -> PermKey {
        PermKey {
            effect: self.effect,
            action: self.action.clone(),
            resource: self.resource.clone(),
            condition: self.condition.clone(),
        }
    }

    /// Human-readable one-line summary.
    fn display_line(&self) -> String {
        let prefix = match self.effect {
            Effect::Permit => String::new(),
            Effect::Forbid => "forbid ".to_string(),
        };
        let mut s = format!("{prefix}{} on {}", self.action, self.resource);
        if let Some(ref cond) = self.condition {
            s.push_str(&format!(" {cond}"));
        }
        s
    }

    /// Annotation text for parenthetical display (prefer @id, fall back to @reason).
    fn annotation_text(&self) -> Option<&str> {
        self.id.as_deref().or(self.reason.as_deref())
    }
}

/// Result of comparing two Cedar policy files.
pub struct PolicyDiff {
    /// Permissions present in the new file but not the old.
    pub added: Vec<Permission>,
    /// Permissions present in the old file but not the new.
    pub removed: Vec<Permission>,
    /// Permissions present in both files.
    pub unchanged: Vec<Permission>,
}

impl PolicyDiff {
    /// Returns `true` when the two files differ semantically.
    pub fn has_changes(&self) -> bool {
        !self.added.is_empty() || !self.removed.is_empty()
    }
}

impl fmt::Display for PolicyDiff {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut wrote_section = false;

        if !self.added.is_empty() {
            writeln!(f, "Added:")?;
            for p in &self.added {
                write!(f, "  + {}", p.display_line())?;
                if let Some(ann) = p.annotation_text() {
                    write!(f, " ({ann})")?;
                }
                writeln!(f)?;
            }
            wrote_section = true;
        }

        if !self.removed.is_empty() {
            if wrote_section {
                writeln!(f)?;
            }
            writeln!(f, "Removed:")?;
            for p in &self.removed {
                write!(f, "  - {}", p.display_line())?;
                if let Some(ann) = p.annotation_text() {
                    write!(f, " ({ann})")?;
                }
                writeln!(f)?;
            }
            wrote_section = true;
        }

        if !self.unchanged.is_empty() {
            if wrote_section {
                writeln!(f)?;
            }
            writeln!(f, "Unchanged:")?;
            for p in &self.unchanged {
                writeln!(f, "  = {}", p.display_line())?;
            }
        }

        if !self.has_changes() && self.unchanged.is_empty() {
            writeln!(
                f,
                "Both files are empty or contain no extractable permissions."
            )?;
        }

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Compare two Cedar policy files and return the semantic diff.
///
/// Both files are validated as legal Cedar before comparison. Returns an
/// error if either file cannot be read or contains invalid Cedar syntax.
pub fn diff(old_path: &Path, new_path: &Path) -> anyhow::Result<PolicyDiff> {
    let old_perms = extract_permissions(old_path)?;
    let new_perms = extract_permissions(new_path)?;

    let old_keys: BTreeSet<PermKey> = old_perms.iter().map(|p| p.key()).collect();
    let new_keys: BTreeSet<PermKey> = new_perms.iter().map(|p| p.key()).collect();

    let added: Vec<Permission> = new_perms
        .iter()
        .filter(|p| !old_keys.contains(&p.key()))
        .cloned()
        .collect();

    let removed: Vec<Permission> = old_perms
        .iter()
        .filter(|p| !new_keys.contains(&p.key()))
        .cloned()
        .collect();

    let unchanged: Vec<Permission> = new_perms
        .iter()
        .filter(|p| old_keys.contains(&p.key()))
        .cloned()
        .collect();

    Ok(PolicyDiff {
        added,
        removed,
        unchanged,
    })
}

/// Extract permissions from a Cedar policy file on disk.
fn extract_permissions(path: &Path) -> anyhow::Result<Vec<Permission>> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read policy file: {}", path.display()))?;

    // Validate Cedar syntax
    PolicySet::from_str(&text)
        .map_err(|e| anyhow::anyhow!("invalid Cedar policy '{}': {e}", path.display()))?;

    Ok(parse_permissions(&text))
}

// ---------------------------------------------------------------------------
// Text parsing
// ---------------------------------------------------------------------------

/// Parse Cedar policy text into a list of permissions.
///
/// Handles the patterns used in strait Cedar policies:
/// - `action == Action::"http:GET"` (single action)
/// - `action in [Action::"http:GET", Action::"http:POST"]` (action list → expanded)
/// - `action` (unconstrained → "any")
/// - `resource in Resource::"host/path"` / `resource == Resource::"host/path"`
/// - `resource` (unconstrained → "any")
/// - `when { ... }` / `unless { ... }` conditions
/// - `@id("...")` / `@reason("...")` annotations
pub fn parse_permissions(text: &str) -> Vec<Permission> {
    let mut result = Vec::new();
    let mut annotations: Vec<String> = Vec::new();
    let lines: Vec<&str> = text.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let trimmed = lines[i].trim();

        // Skip blank lines
        if trimmed.is_empty() {
            i += 1;
            continue;
        }

        // Skip comment-only lines
        if trimmed.starts_with("//") {
            i += 1;
            continue;
        }

        // Collect annotations (they precede the policy statement)
        if trimmed.starts_with('@') {
            annotations.push(trimmed.to_string());
            i += 1;
            continue;
        }

        // Detect policy start
        let effect = if trimmed.starts_with("permit") {
            Some(Effect::Permit)
        } else if trimmed.starts_with("forbid") {
            Some(Effect::Forbid)
        } else {
            annotations.clear();
            i += 1;
            continue;
        };

        if let Some(effect) = effect {
            // Collect the full statement (may span multiple lines) until `;`
            let mut stmt = String::new();
            while i < lines.len() {
                stmt.push_str(lines[i]);
                stmt.push('\n');
                if lines[i].contains(';') {
                    i += 1;
                    break;
                }
                i += 1;
            }

            let id = annotation_value(&annotations, "id");
            let reason = annotation_value(&annotations, "reason");
            annotations.clear();

            let (actions, resource, condition) = parse_statement(&stmt);

            for action in actions {
                result.push(Permission {
                    effect,
                    action,
                    resource: resource.clone(),
                    condition: condition.clone(),
                    id: id.clone(),
                    reason: reason.clone(),
                });
            }
        }
    }

    result
}

/// Extract the value from an annotation like `@id("read-org-repos")`.
fn annotation_value(annotations: &[String], key: &str) -> Option<String> {
    let prefix = format!("@{key}(\"");
    for ann in annotations {
        if let Some(rest) = ann.strip_prefix(&prefix) {
            if let Some(end) = rest.find("\")") {
                return Some(rest[..end].to_string());
            }
        }
    }
    None
}

/// Parse a single Cedar policy statement into (actions, resource, condition).
fn parse_statement(stmt: &str) -> (Vec<String>, String, Option<String>) {
    // Find the body between the first `(` and its matching `)`
    let body_start = match stmt.find('(') {
        Some(pos) => pos + 1,
        None => return (vec!["any".to_string()], "any".to_string(), None),
    };

    let mut depth: u32 = 1;
    let mut body_end = body_start;
    for (i, ch) in stmt[body_start..].char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    body_end = body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }

    let body = &stmt[body_start..body_end];
    let after = stmt.get(body_end + 1..).unwrap_or("").trim();
    // Strip trailing `;` and surrounding whitespace
    let after = after.trim_end_matches(';').trim();

    // Split the body into fields: principal, action, resource
    let fields = split_top_level(body, ',');

    let actions = if fields.len() >= 2 {
        extract_entity_ids(&fields[1], "Action")
    } else {
        vec!["any".to_string()]
    };

    let resource = if fields.len() >= 3 {
        let ids = extract_entity_ids(&fields[2], "Resource");
        if ids.len() == 1 {
            ids.into_iter().next().unwrap()
        } else {
            ids.join(", ")
        }
    } else {
        "any".to_string()
    };

    let condition = if after.is_empty() {
        None
    } else {
        Some(normalize_ws(after))
    };

    (actions, resource, condition)
}

/// Split a string by `sep` at the top nesting level only
/// (respects parentheses, brackets, and double-quoted strings).
fn split_top_level(s: &str, sep: char) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut depth: u32 = 0;
    let mut in_string = false;
    let mut prev = '\0';

    for ch in s.chars() {
        if ch == '"' && prev != '\\' {
            in_string = !in_string;
            current.push(ch);
        } else if in_string {
            current.push(ch);
        } else if ch == '(' || ch == '[' || ch == '{' {
            depth += 1;
            current.push(ch);
        } else if ch == ')' || ch == ']' || ch == '}' {
            depth = depth.saturating_sub(1);
            current.push(ch);
        } else if ch == sep && depth == 0 {
            parts.push(current.clone());
            current.clear();
        } else {
            current.push(ch);
        }
        prev = ch;
    }

    let trimmed = current.trim().to_string();
    if !trimmed.is_empty() {
        parts.push(trimmed);
    }

    parts
}

/// Find all entity IDs of the given type in a field string.
///
/// E.g. for `entity_type = "Action"` and field
/// `action in [Action::"http:GET", Action::"http:POST"]`
/// returns `["http:GET", "http:POST"]`.
///
/// Returns `["any"]` when no entity reference is found (unconstrained field).
fn extract_entity_ids(field: &str, entity_type: &str) -> Vec<String> {
    let prefix = format!("{entity_type}::\"");
    let mut ids = Vec::new();
    let mut pos = 0;

    while let Some(start) = field[pos..].find(&prefix) {
        let abs_start = pos + start + prefix.len();
        if let Some(end) = field[abs_start..].find('"') {
            ids.push(field[abs_start..abs_start + end].to_string());
            pos = abs_start + end + 1;
        } else {
            break;
        }
    }

    if ids.is_empty() {
        vec!["any".to_string()]
    } else {
        ids
    }
}

/// Collapse runs of whitespace / newlines into single spaces.
fn normalize_ws(s: &str) -> String {
    s.split_whitespace().collect::<Vec<_>>().join(" ")
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn write_cedar(content: &str) -> NamedTempFile {
        let mut f = NamedTempFile::new().unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    // -- parse_permissions ---------------------------------------------------

    #[test]
    fn parse_simple_permit() {
        let text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].effect, Effect::Permit);
        assert_eq!(perms[0].action, "http:GET");
        assert_eq!(perms[0].resource, "api.github.com/repos/org");
        assert!(perms[0].condition.is_none());
    }

    #[test]
    fn parse_forbid_with_condition() {
        let text = r#"
@id("deny-push-main")
@reason("No direct pushes to main")
forbid(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com"
) when { context.path like "*/git/refs/heads/main" };
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].effect, Effect::Forbid);
        assert_eq!(perms[0].action, "http:POST");
        assert_eq!(perms[0].resource, "api.github.com");
        assert!(perms[0].condition.is_some());
        assert!(perms[0]
            .condition
            .as_ref()
            .unwrap()
            .contains("context.path"));
        assert_eq!(perms[0].id.as_deref(), Some("deny-push-main"));
        assert_eq!(perms[0].reason.as_deref(), Some("No direct pushes to main"));
    }

    #[test]
    fn parse_unconstrained_action() {
        let text = r#"
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/org" };
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].action, "any");
        assert_eq!(perms[0].resource, "api.github.com/repos");
        assert!(perms[0].condition.as_ref().unwrap().contains("unless"));
    }

    #[test]
    fn parse_unconstrained_resource_with_condition() {
        let text = r#"
@id("s3-read")
permit(
    principal,
    action == Action::"http:GET",
    resource
) when { context.aws_service == "s3" };
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].action, "http:GET");
        assert_eq!(perms[0].resource, "any");
        assert!(perms[0].condition.as_ref().unwrap().contains("aws_service"));
        assert_eq!(perms[0].id.as_deref(), Some("s3-read"));
    }

    #[test]
    fn parse_principal_constraint() {
        let text = r#"
permit(
    principal == Agent::"worker",
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].action, "http:GET");
        assert_eq!(perms[0].resource, "api.github.com/repos/org");
    }

    #[test]
    fn parse_multiple_policies() {
        let text = r#"
@id("read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);

@id("write")
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/org"
) when { context.path like "*/pulls" };
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 2);
        assert_eq!(perms[0].id.as_deref(), Some("read"));
        assert_eq!(perms[0].action, "http:GET");
        assert_eq!(perms[1].id.as_deref(), Some("write"));
        assert_eq!(perms[1].action, "http:POST");
    }

    #[test]
    fn parse_permit_all() {
        let text = "permit(principal, action, resource);";
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].action, "any");
        assert_eq!(perms[0].resource, "any");
        assert!(perms[0].condition.is_none());
    }

    // -- diff ----------------------------------------------------------------

    #[test]
    fn diff_identical_files() {
        let text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let old = write_cedar(text);
        let new = write_cedar(text);

        let result = diff(old.path(), new.path()).unwrap();
        assert!(result.added.is_empty());
        assert!(result.removed.is_empty());
        assert_eq!(result.unchanged.len(), 1);
        assert!(!result.has_changes());
    }

    #[test]
    fn diff_added_permission() {
        let old_text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let new_text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/org"
) when { context.path like "*/pulls" };
"#;
        let old = write_cedar(old_text);
        let new = write_cedar(new_text);

        let result = diff(old.path(), new.path()).unwrap();
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].action, "http:POST");
        assert_eq!(result.removed.len(), 0);
        assert_eq!(result.unchanged.len(), 1);
        assert!(result.has_changes());
    }

    #[test]
    fn diff_removed_permission() {
        let old_text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
permit(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let new_text = r#"
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let old = write_cedar(old_text);
        let new = write_cedar(new_text);

        let result = diff(old.path(), new.path()).unwrap();
        assert_eq!(result.added.len(), 0);
        assert_eq!(result.removed.len(), 1);
        assert_eq!(result.removed[0].action, "http:DELETE");
        assert_eq!(result.unchanged.len(), 1);
    }

    #[test]
    fn diff_mixed_changes() {
        let old_text = r#"
@id("read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
@id("delete")
permit(
    principal,
    action == Action::"http:DELETE",
    resource in Resource::"api.github.com/repos/org"
);
"#;
        let new_text = r#"
@id("read")
permit(
    principal,
    action == Action::"http:GET",
    resource in Resource::"api.github.com/repos/org"
);
@id("write")
permit(
    principal,
    action == Action::"http:POST",
    resource in Resource::"api.github.com/repos/org"
) when { context.path like "*/pulls" };
"#;
        let old = write_cedar(old_text);
        let new = write_cedar(new_text);

        let result = diff(old.path(), new.path()).unwrap();
        assert_eq!(result.added.len(), 1, "should have 1 added");
        assert_eq!(result.added[0].action, "http:POST");
        assert_eq!(result.removed.len(), 1, "should have 1 removed");
        assert_eq!(result.removed[0].action, "http:DELETE");
        assert_eq!(result.unchanged.len(), 1, "should have 1 unchanged");
        assert_eq!(result.unchanged[0].action, "http:GET");
    }

    #[test]
    fn diff_forbid_policies() {
        let old_text = r#"
permit(principal, action == Action::"http:GET", resource in Resource::"api.github.com");
"#;
        let new_text = r#"
permit(principal, action == Action::"http:GET", resource in Resource::"api.github.com");
@id("deny-delete")
@reason("No deletions allowed")
forbid(principal, action == Action::"http:DELETE", resource in Resource::"api.github.com/repos");
"#;
        let old = write_cedar(old_text);
        let new = write_cedar(new_text);

        let result = diff(old.path(), new.path()).unwrap();
        assert_eq!(result.added.len(), 1);
        assert_eq!(result.added[0].effect, Effect::Forbid);
        assert_eq!(result.added[0].action, "http:DELETE");
        assert_eq!(result.added[0].id.as_deref(), Some("deny-delete"));
    }

    #[test]
    fn diff_display_format() {
        let old_text = r#"
permit(principal, action == Action::"http:GET", resource in Resource::"api.github.com/repos/org");
permit(principal, action == Action::"http:DELETE", resource in Resource::"api.github.com/repos/org");
"#;
        let new_text = r#"
permit(principal, action == Action::"http:GET", resource in Resource::"api.github.com/repos/org");
@id("create-prs")
permit(principal, action == Action::"http:POST", resource in Resource::"api.github.com/repos/org") when { context.path like "*/pulls" };
"#;
        let old = write_cedar(old_text);
        let new = write_cedar(new_text);

        let result = diff(old.path(), new.path()).unwrap();
        let output = result.to_string();

        assert!(
            output.contains("Added:"),
            "output should contain Added section"
        );
        assert!(
            output.contains("+ http:POST on api.github.com/repos/org"),
            "should show added POST permission"
        );
        assert!(output.contains("(create-prs)"), "should show annotation");
        assert!(
            output.contains("Removed:"),
            "output should contain Removed section"
        );
        assert!(
            output.contains("- http:DELETE on api.github.com/repos/org"),
            "should show removed DELETE permission"
        );
        assert!(
            output.contains("Unchanged:"),
            "output should contain Unchanged section"
        );
        assert!(
            output.contains("= http:GET on api.github.com/repos/org"),
            "should show unchanged GET permission"
        );
    }

    #[test]
    fn diff_no_changes_display() {
        let text =
            "permit(principal, action == Action::\"http:GET\", resource in Resource::\"host\");";
        let old = write_cedar(text);
        let new = write_cedar(text);

        let result = diff(old.path(), new.path()).unwrap();
        let output = result.to_string();
        assert!(output.contains("Unchanged:"));
        assert!(!output.contains("Added:"));
        assert!(!output.contains("Removed:"));
    }

    #[test]
    fn diff_invalid_cedar_errors() {
        let valid = "permit(principal, action, resource);";
        let invalid = "not valid cedar at all {{{";
        let valid_file = write_cedar(valid);
        let invalid_file = write_cedar(invalid);

        assert!(diff(valid_file.path(), invalid_file.path()).is_err());
        assert!(diff(invalid_file.path(), valid_file.path()).is_err());
    }

    #[test]
    fn diff_missing_file_errors() {
        let valid = write_cedar("permit(principal, action, resource);");
        let missing = Path::new("/nonexistent/policy.cedar");

        assert!(diff(missing, valid.path()).is_err());
        assert!(diff(valid.path(), missing).is_err());
    }

    #[test]
    fn diff_exit_code_semantics() {
        // No changes → has_changes() is false (exit 0 in CLI)
        let text = "permit(principal, action == Action::\"http:GET\", resource);";
        let old = write_cedar(text);
        let new = write_cedar(text);
        let result = diff(old.path(), new.path()).unwrap();
        assert!(!result.has_changes());

        // With changes → has_changes() is true (exit 1 in CLI)
        let new_text = "permit(principal, action == Action::\"http:POST\", resource);";
        let new2 = write_cedar(new_text);
        let result2 = diff(old.path(), new2.path()).unwrap();
        assert!(result2.has_changes());
    }

    // -- parse edge cases ----------------------------------------------------

    #[test]
    fn annotation_with_special_chars() {
        let text = r#"
@id("deny-outside-org")
@reason("Only repos in the specified organization are accessible")
forbid(
    principal,
    action,
    resource in Resource::"api.github.com/repos"
) unless { resource in Resource::"api.github.com/repos/org" };
"#;
        let perms = parse_permissions(text);
        assert_eq!(perms.len(), 1);
        assert_eq!(perms[0].id.as_deref(), Some("deny-outside-org"));
        assert_eq!(
            perms[0].reason.as_deref(),
            Some("Only repos in the specified organization are accessible")
        );
    }

    // -- split_top_level helper tests ----------------------------------------

    #[test]
    fn split_respects_strings() {
        let input = r#"action in [Action::"a,b"], resource"#;
        let parts = split_top_level(input, ',');
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("a,b"));
    }

    #[test]
    fn split_respects_brackets() {
        let input = "action in [A, B], resource";
        let parts = split_top_level(input, ',');
        assert_eq!(parts.len(), 2);
        assert!(parts[0].contains("[A, B]"));
    }
}
