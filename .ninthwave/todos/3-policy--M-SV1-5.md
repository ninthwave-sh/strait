# Feat: Cedar schema validation at startup (M-SV1-5)

**Priority:** Medium
**Source:** Strait v0.1 design — deliverable 4
**Depends on:** H-SV1-1
**Domain:** policy

Add optional Cedar schema validation to `PolicyEngine::load()`. When `[policy].schema` is set in the config, load the `.cedarschema` file and validate the policy set against it at startup. Fail fast with a clear error if the policy violates the schema. Use `cedar_policy::Schema::from_str()` for parsing and the policy set's validation API. When no schema is configured, skip validation (existing behavior preserved).

**Test plan:**
- Unit test: valid policy + valid schema → PolicyEngine loads successfully
- Unit test: valid policy + no schema → PolicyEngine loads successfully (backward compat)
- Unit test: policy that violates schema → clear error at startup
- Unit test: invalid/unparseable schema file → clear error at startup
- Unit test: missing schema file path → clear error

Acceptance: `PolicyEngine::load()` accepts an optional schema path. Schema violations produce clear error messages with line/column info where available. Existing tests pass unchanged when no schema is provided.

Key files: `src/policy.rs`
