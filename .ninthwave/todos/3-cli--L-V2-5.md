# Feat: Policy templates (`strait template list/apply`) (L-V2-5)

**Priority:** Low
**Source:** v0.2 roadmap — policy templates for GitHub and AWS
**Depends on:** M-V2-4 (templates must be validated against real traffic via --observe before shipping)
**Domain:** cli

Add `strait template` subcommand with two actions:

- `strait template list` — lists available built-in policy templates with a short description
- `strait template apply <name> [--output-dir ./policies]` — copies a built-in template to the output dir (or prints to stdout)

**v0.2 templates (validated against real API sessions via `--observe`):**
- `github-org-readonly` — read-only access to a GitHub org's repos
- `github-org-contributor` — read + PR creation, deny push to main/release branches, deny repo admin
- `aws-s3-readonly` — read-only S3 access (GetObject, ListBucket)
- `aws-s3-readwrite` — S3 read + write, deny DeleteBucket/DeleteObject

Templates are embedded in the binary via `include_str!` from `templates/` directory. Each template ships with a `.cedarschema` counterpart and a `README.md` with usage notes.

**Validation requirement (from CEO plan):** Each template MUST be validated against real API sessions using `strait init --observe` before it is committed. This is enforced by a `# VALIDATED: <date> <method>` comment in each template file — CI checks for this comment and fails if absent.

**Test plan:**
- `template list` prints all available templates
- `template apply github-org-readonly` produces valid Cedar policy that passes `cedar validate`
- `template apply unknown` → clear error with list of valid names
- `--output-dir` writes `.cedar` + `.cedarschema` files; stdout mode prints both
- CI validation check: template without `# VALIDATED:` comment fails CI

Acceptance: `cargo test --all-features` passes. `cargo clippy` clean. All templates pass `cedar validate` against their bundled schema.

Key files: `src/main.rs` (template subcommand), `templates/` (NEW — cedar + cedarschema files), `src/templates.rs` (NEW — include_str! bindings + list/apply logic)
