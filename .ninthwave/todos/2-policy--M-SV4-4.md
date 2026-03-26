# Feat: Cedar AWS context enrichment (M-SV4-4)

**Priority:** Medium
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** H-SV4-2
**Domain:** policy

Enrich Cedar evaluation context with `aws_service` and `aws_region` attributes when the request host matches an AWS endpoint pattern. Uses the `parse_aws_host` utility from H-SV4-2. Non-AWS hosts get empty strings for these fields (or the fields are omitted if schema allows optional). Update the Cedar schema to include optional `aws_service` and `aws_region` context attributes. This enables readable AWS policies like `when { context.aws_service == "s3" && context.aws_region == "us-east-1" }`.

**Test plan:**
- Unit test: AWS host populates `aws_service` and `aws_region` in Cedar context
- Unit test: non-AWS host has empty/absent AWS context fields
- Unit test: Cedar policy with `context.aws_service == "s3"` evaluates correctly
- Unit test: Cedar policy with `context.aws_region` condition evaluates correctly
- Existing GitHub policy tests pass unchanged (non-AWS context unaffected)

Acceptance: Cedar context includes `aws_service` and `aws_region` for AWS endpoints. Policies can reference these attributes. Schema validates with the new optional fields. All existing policy tests pass.

Key files: `src/policy.rs`, `examples/github.cedarschema`
