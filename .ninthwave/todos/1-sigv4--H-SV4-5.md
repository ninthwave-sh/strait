# Feat: SigV4 signing implementation (H-SV4-5)

**Priority:** High
**Source:** v0.2 roadmap — AWS SigV4 decomposition
**Depends on:** H-SV4-1, H-SV4-2, H-SV4-3
**Domain:** sigv4

New `src/sigv4.rs` module implementing the `Credential` trait for AWS Signature Version 4. Uses the `aws-sigv4` crate for canonical request construction and HMAC-SHA256 signing. Resolves `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and optional `AWS_SESSION_TOKEN` from environment variables at startup (fail-fast). Extracts service and region from the request hostname via `parse_aws_host`. Produces `Authorization`, `X-Amz-Date`, `X-Amz-Content-Sha256`, and optionally `X-Amz-Security-Token` headers. Config type is `"aws-sigv4"` with fields for env var names (defaulting to standard AWS env vars).

**Test plan:**
- Unit test: SigV4Credential produces well-formed Authorization header (starts with `AWS4-HMAC-SHA256 Credential=`)
- Unit test: X-Amz-Date header present and ISO-8601 formatted
- Unit test: X-Amz-Content-Sha256 matches SHA-256 of provided body
- Unit test: empty body produces SHA-256 of empty string
- Unit test: session token env var present → X-Amz-Security-Token header added
- Unit test: session token env var absent → no X-Amz-Security-Token header
- Unit test: missing access key env var → startup error
- Verify signature against known AWS SigV4 test vectors if available in aws-sigv4 crate

Acceptance: `SigV4Credential` implements `Credential` trait. Signing produces valid AWS SigV4 headers. Service and region extracted from hostname. Env vars resolved eagerly at startup. `cargo clippy --all-features` clean. New dependency `aws-sigv4` added to Cargo.toml.

Key files: new `src/sigv4.rs`, `Cargo.toml`, `src/credentials.rs`, `src/config.rs`
