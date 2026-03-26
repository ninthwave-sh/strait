# Refactor: AWS host pattern matching (H-SV4-2)

**Priority:** High
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** None
**Domain:** credentials

Extend `CredentialStore` to support hostname patterns beyond exact match. Add a `parse_aws_host(host: &str) -> Option<AwsHostInfo>` utility that extracts service and region from AWS hostname patterns (`<service>.<region>.amazonaws.com`). CredentialStore gains a fallback lookup: exact match first, then pattern match (e.g., all `*.amazonaws.com` hosts resolve to the same AWS credential). Config supports `host_pattern` field as alternative to `host` for pattern-based entries.

**Test plan:**
- Unit tests for `parse_aws_host`: S3 (`s3.us-east-1.amazonaws.com`), Lambda (`lambda.us-east-1.amazonaws.com`), SQS, DynamoDB, global endpoints (`iam.amazonaws.com`), non-AWS hosts return None
- CredentialStore lookup priority: exact match wins over pattern match
- Pattern match: `*.amazonaws.com` resolves for any AWS service host
- Non-AWS hosts unaffected (exact match only, no false pattern hits)
- Edge cases: `notamazonaws.com`, `amazonaws.com` (bare), subdomains like `bucket.s3.us-east-1.amazonaws.com`

Acceptance: `parse_aws_host` correctly extracts service and region for standard AWS endpoint formats. `CredentialStore::get` falls back to pattern matching when no exact match exists. Existing bearer credential tests pass unchanged.

Key files: `src/credentials.rs`, `src/config.rs`
