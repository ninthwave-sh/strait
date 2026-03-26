# Docs: Sample GitHub Cedar policy and schema (M-SV1-7)

**Priority:** Medium
**Source:** Strait v0.1 design — deliverable 6
**Depends on:** M-SV1-5
**Domain:** docs

Ship well-documented example files in `examples/`:

**`examples/github.cedar`** — Cedar policy covering common GitHub API patterns:
- Read access to specific org repos (`GET` on `repos/our-org/*`)
- PR creation on org repos (`POST` on `*/pulls`)
- Deny push to protected branches (main, release/*)
- Deny repo deletion (`DELETE` on `repos/*`)
- Deny admin/settings access (`PATCH` on `*/settings`)
- Deny access to repos outside the allowed org
- Include `@reason("...")` annotations on deny policies demonstrating the strait convention

**`examples/github.cedarschema`** — Matching Cedar schema that works with strait's `Resource::"host/path/segments"` entity model. Validated against the policy file.

**`examples/strait.toml`** — Complete example config file with inline comments explaining every field, referencing the policy and schema files.

**Test plan:**
- Verify `examples/github.cedar` loads without errors via `PolicyEngine::load()`
- Verify `examples/github.cedarschema` validates against the policy file
- Verify `examples/strait.toml` parses without errors via config loading

Acceptance: All three example files are valid and self-documenting. A new user can copy the examples directory, set `GITHUB_TOKEN`, and run `strait --config examples/strait.toml` to get a working GitHub API proxy.

Key files: `examples/github.cedar` (new), `examples/github.cedarschema` (new), `examples/strait.toml` (new)
