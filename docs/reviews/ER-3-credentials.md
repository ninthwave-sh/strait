# ER-3: Credentials Review

**Date:** 2026-03-27
**Modules:** src/credentials.rs (1079 lines), src/sigv4.rs (780 lines)

## Summary

The credential system is well-designed with a clean trait-based abstraction
(`Credential`) that separates credential storage, lookup, and injection.
Bearer tokens are trivially correct, and the SigV4 implementation wisely
delegates to the `aws-sigv4` crate rather than hand-rolling signing logic.
The two-tier lookup (exact host then pattern) is sound, and the
`inject_credential` function in `mitm.rs` correctly removes existing
headers before injecting (preventing double-injection). Debug
implementations properly redact secrets for both `BearerCredential` and
`SigV4Credential`. Test coverage is excellent: 38 tests in
`credentials.rs` and 18 in `sigv4.rs` covering pattern matching, AWS host
parsing across partitions, signing correctness, session tokens, error
cases, and debug redaction.

The most actionable findings are: credentials are scoped to hosts only
(no path-level scoping), so any allowed request to a credentialed host
receives the secret — security depends entirely on the Cedar policy being
correct (security); China partition endpoints (`*.amazonaws.com.cn`) don't
match the pattern `*.amazonaws.com`, requiring a separate credential entry
with no warning (design); SigV4 credentials have no expiry awareness, so
temporary credentials (STS) silently stop working after expiry (missing);
and secrets are stored as plain `String` with no zeroization on drop
(security, low severity for the current threat model).

## Findings

### 1. [SECURITY] Credential injection has no path-level scoping — MEDIUM

**File:** `src/credentials.rs:263-277`, `src/mitm.rs:880-901`

`CredentialStore::get()` matches on hostname only. Once a host matches,
the credential is injected for every allowed request to that host,
regardless of path. The `Credential::inject()` trait receives `path` but
`BearerCredential` ignores it (always returns the token).

If a host serves both authenticated and unauthenticated endpoints (e.g.,
a service with public health-check routes and private API routes), the
bearer token is injected on all requests — including to public routes.
This is only safe because the Cedar policy engine gates which requests
reach the injection point. But:

1. If no policy engine is configured (`ctx.policy_engine` is `None`),
   credentials are injected on all requests to matching hosts with no
   access control.
2. A permissive policy that allows GET to all paths on a credentialed
   host would leak the token to paths that don't need it.

For the SigV4 case this is less concerning — SigV4 signatures are
request-specific and time-bounded, so leaking a signature to a different
path doesn't grant reusable access.

**Suggested fix:** Consider adding an optional `path_prefix` field to
`CredentialEntryConfig` that restricts injection to paths starting with
the prefix. For v0.1 (GitHub API only), this isn't critical since
`api.github.com` is fully authenticated. Document the security model:
"credentials are injected on all ALLOW'd requests to the matching host."

### 2. [DESIGN] China partition endpoints require a separate credential entry — MEDIUM

**File:** `src/credentials.rs:293-308`

`host_matches_pattern("s3.cn-north-1.amazonaws.com.cn", "*.amazonaws.com")`
returns `false` because the host ends in `.amazonaws.com.cn`, not
`.amazonaws.com`. Users configuring `host_pattern = "*.amazonaws.com"` for
AWS credentials will silently miss all China partition endpoints.

The `parse_aws_host` function correctly handles China endpoints (line
96-97), so SigV4 signing would work if the credential matched — but the
credential store won't find it. There's no startup warning when an
`aws-sigv4` credential's `host_pattern` doesn't cover `.amazonaws.com.cn`.

**Suggested fix:** Either:
1. Document the requirement for separate China entries in the TOML example
2. Auto-expand `*.amazonaws.com` to also match `*.amazonaws.com.cn` in
   `host_matches_pattern` for `aws-sigv4` credential types
3. Add a startup warning when an `aws-sigv4` credential has a pattern
   that covers standard but not China partition

### 3. [MISSING] No credential expiry awareness for temporary AWS credentials — MEDIUM

**File:** `src/sigv4.rs:67-103`

`SigV4Credential::from_env()` reads credentials once at startup and
stores them indefinitely. For permanent IAM user credentials this is
fine, but for temporary credentials (STS `AssumeRole`, EC2 instance
profiles, SSO), the credentials have an expiry. When they expire:

1. The `aws-sigv4` crate still produces a signed request (it doesn't
   check expiry).
2. AWS rejects the request with 403.
3. `sign_request` returns `Some(headers)` — the signature is injected.
4. The upstream 403 is relayed to the client with no indication it's
   an expired-credential issue.

There's no mechanism to detect this failure mode, refresh credentials,
or warn the operator.

**Suggested fix:** For v0.1 this is acceptable (env-var credentials are
typically long-lived). For v0.2+, consider:
1. Storing the credential expiry time (if available from env or config)
2. Logging a warning when signing with credentials older than a threshold
3. Supporting credential refresh via file-watch or env re-read on SIGHUP

### 4. [SECURITY] Secrets stored as plain `String` without zeroization — LOW

**File:** `src/credentials.rs:178-179`, `src/sigv4.rs:51-55`

Both `BearerCredential.value` and `SigV4Credential.secret_access_key` /
`session_token` are stored as `String`. When the credential store is
dropped (or the process exits), the secret remains in freed memory until
the allocator reuses the page. This is the standard Rust behavior and
matches the threat model of a proxy running in a trusted operator
environment.

However, if strait is ever used in an environment where memory
disclosure is a concern (e.g., shared hosting, core dumps), secrets
could leak.

**Suggested fix:** Use `secrecy::Secret<String>` or `zeroize::Zeroizing`
for secret fields. This is a low-priority hardening measure — most
Rust projects (including the AWS SDK itself) don't zeroize in-process.

### 5. [QUALITY] First-match-wins pattern semantics may surprise users — LOW

**File:** `src/credentials.rs:270-276`

When multiple patterns could match a host, the first matching pattern in
config order wins. There's no specificity ranking (longest match, most
specific glob). For example, if a user configures:

```toml
[[credential]]
host_pattern = "*.amazonaws.com"
source = "env"
env_var = "DEFAULT_KEY"

[[credential]]
host_pattern = "*.s3.amazonaws.com"
source = "env"
env_var = "S3_SPECIFIC_KEY"
```

The first entry always wins for S3 virtual-hosted endpoints (e.g.,
`bucket.s3.us-east-1.amazonaws.com`), and the second entry is dead.

**Suggested fix:** Document the first-match-wins semantics clearly in
the config example. Consider logging a startup warning if a later
pattern is shadowed by an earlier one (though this is complex to detect
in general).

### 6. [QUALITY] `SigV4Credential` derives `Clone` exposing secret duplication — LOW

**File:** `src/sigv4.rs:50`

`#[derive(Clone)]` on `SigV4Credential` means `secret_access_key` can
be freely cloned. In practice, this doesn't matter — the credential
store holds `Box<dyn Credential>` (not clonable through the trait
object), and the `Clone` is only used in tests. But removing `Clone`
(or replacing it with an explicit impl that avoids cloning the secret)
would tighten the API.

**No immediate action needed** — the `Clone` derive has no callers in
production code paths.

### 7. [QUALITY] `BearerCredential` derives `Clone` including the secret — LOW

**File:** `src/credentials.rs:174`

Same pattern as Finding 6. `BearerCredential` derives `Clone`, which
copies the `value` field (containing the resolved secret). No production
code clones credentials, but removing `Clone` would prevent accidental
copies.

**No immediate action needed** — same rationale as Finding 6.

### 8. [QUALITY] SigV4 signing silently drops the request on failure — LOW

**File:** `src/sigv4.rs:146-157, 182-193, 197-208`

When `SigningParams::build()`, `SignableRequest::new()`, or `sign()`
fails, `sign_request` returns `None`. The `inject_credential` function
in `mitm.rs` treats `None` as "no credential applies" and forwards the
request without authentication. This means signing failures produce
unauthenticated requests (which AWS rejects with 403) rather than
blocking the request.

The `warn!` logs provide diagnostic information (host, service, region),
which is good. But the caller has no way to distinguish "credential
doesn't apply to this host" from "signing failed due to a bug."

**Suggested fix:** Consider returning a `Result<Option<Vec<...>>, ...>`
from `sign_request` to distinguish "not applicable" from "error." The
caller could then log a more specific audit event for signing failures.

### 9. [DESIGN] `parse_aws_host` assumes two-segment service/region layout — LOW

**File:** `src/credentials.rs:117-139`

The parser treats the last two meaningful segments as service and region
(for 2+ segment cases). This works for all current AWS endpoint formats
but could break if AWS introduces service names with dots (e.g.,
`service.variant.region.amazonaws.com`). The `AWS_HOST_QUALIFIERS`
filter list (`dualstack`, `fips`, `vpce`) must be manually updated when
AWS adds new qualifiers.

The existing test suite covers dualstack, FIPS, VPC, virtual-hosted,
China, and GovCloud endpoints — all current formats are handled
correctly.

**No immediate action needed** — the parser is correct for all known
AWS endpoint formats as of 2026. The qualifier list is small and stable.

### 10. [QUALITY] `host_matches_pattern` only supports `*.suffix` globs — LOW

**File:** `src/credentials.rs:298-308`

The pattern matching function supports only two forms: exact string
match and `*.suffix` wildcard prefix. There's no support for more
complex globs (`s3.*.amazonaws.com`), regex, or multi-segment wildcards.

For the current use case (matching AWS and API hosts), `*.suffix` is
sufficient. The implementation is intentionally simple, which is better
than a complex glob library for security-sensitive matching.

**No immediate action needed** — simplicity is a feature here.

### 11. [QUALITY] Credential resolution error messages could include credential type — LOW

**File:** `src/credentials.rs:324-355, 363-399`

Error messages from `resolve_bearer` and `resolve_sigv4` include the
host identifier but not the credential type. When a user has multiple
credential entries, the error "credential for 'api.example.com':
environment variable 'X' is not set" doesn't tell them whether it's the
bearer or sigv4 entry that failed.

**Suggested fix:** Include `credential_type` in error messages:
```
"bearer credential for 'api.example.com': environment variable 'X' is not set"
```

### 12. [QUALITY] `CredentialStore` Debug impl auto-derived, may print Box addresses — LOW

**File:** `src/credentials.rs:210`

`CredentialStore` has `#[derive(Debug)]`, which prints the inner
`HashMap<String, Box<dyn Credential>>` and `Vec<(String, Box<dyn
Credential>)>`. Since both `BearerCredential` and `SigV4Credential`
implement custom `Debug` that redacts secrets, this is safe. But the
output format (`HashMap { "api.github.com": BearerCredential { header:
"Authorization", value: "***" } }`) includes hostnames, which may be
sensitive in some contexts.

**No immediate action needed** — the current behavior is safe thanks to
the per-type Debug redaction.

## Key Question Answers

**Are credentials correctly scoped to specific hosts/paths, or can a
misconfigured policy leak credentials to the wrong endpoint?**

Credentials are scoped to hosts only — there is no path-level scoping
in the credential store. The security model relies on a two-layer design:

1. **Credential store** gates by host: credentials are only looked up for
   the CONNECT target host. A credential for `api.github.com` is never
   considered for `example.com`.
2. **Cedar policy** gates by path: only requests that pass policy
   evaluation reach the credential injection point.

A misconfigured policy *can* leak credentials to unintended paths on a
credentialed host. For example, if the policy permits `GET` to all paths
on `api.github.com`, the token is injected on requests to public
endpoints that don't need it. The leaked token is still scoped to that
host (it can't be injected into requests to a different host), but an
overly permissive policy reduces defense-in-depth.

If no policy engine is configured at all, credentials are injected on
every request to matching MITM hosts with zero access control. This is
documented behavior ("credential injection on allow only"), but the "no
policy = allow all" default means credentials flow freely.

**Does SigV4 handle all AWS service quirks (S3 path-style, dualstack,
FIPS)?**

Yes, with one gap:

- **S3 path-style** (`s3.us-east-1.amazonaws.com/bucket/key`) — works.
  Host parsing extracts service=s3, region=us-east-1. The bucket and key
  are in the path, which is included in the canonical request by the
  aws-sigv4 crate.
- **S3 virtual-hosted** (`bucket.s3.us-east-1.amazonaws.com`) — works.
  `parse_aws_host` correctly extracts service=s3, region=us-east-1 from
  the last two meaningful segments.
- **Dualstack** (`s3.dualstack.us-east-1.amazonaws.com`) — works.
  `dualstack` is filtered as a qualifier.
- **FIPS** (`s3-fips.us-east-1.amazonaws.com`) — works. `-fips` suffix
  is stripped from the service name.
- **VPC endpoints** (`vpce-xxx.s3.us-east-1.vpce.amazonaws.com`) — works.
  Both `vpce` (qualifier) and the VPC endpoint prefix are filtered.
- **China partition** (`s3.cn-north-1.amazonaws.com.cn`) — host parsing
  works, but **credential matching fails** with `*.amazonaws.com`
  pattern (see Finding 2).
- **GovCloud** (`s3.us-gov-west-1.amazonaws.com`) — works. Uses
  standard `.amazonaws.com` suffix with `us-gov-*` region names.
- **Global endpoints** (`iam.amazonaws.com`) — works. Region defaults to
  `us-east-1`.
- **Query string signing** — handled by the aws-sigv4 crate internally.
  The full URI (including query string from the `path` parameter) is
  passed to `SignableRequest::new`.
- **Chunked bodies** — handled correctly. The MITM handler decodes
  chunked Transfer-Encoding before passing the body to SigV4 signing.
  The decoded bytes are hashed for `x-amz-content-sha256`.
- **Empty bodies** — handled correctly. `body.unwrap_or(&[])` produces
  SHA-256 of empty string (`e3b0c44298fc...`).

**Is the Debug redaction (H-CP-21) complete — are there any other paths
where secrets could leak?**

Debug redaction is thorough:

- `BearerCredential::Debug` shows `value: "***"` (line 183-188)
- `SigV4Credential::Debug` shows `secret_access_key: "***"` and
  `session_token: Some("***")` (line 57-64)
- `CredentialStore::Debug` is derived but delegates to the per-type
  Debug impls, so secrets are redacted

Potential leak paths reviewed and cleared:

- **Error messages** — `resolve_bearer` and `resolve_sigv4` only include
  env var names, not values. The `anyhow::Context` wrappers don't add
  secret values.
- **Tracing logs** — `warn!` logs in `sigv4.rs` include host, service,
  region, and error messages but never secret values. The audit logger
  records `credential_injected: bool` (not the credential value).
- **Panic messages** — No `unwrap()` on secret values. Signing failures
  return `None` rather than panicking.
- **Audit log** — Records whether injection happened (`credential_injected:
  true/false`) but not the header value. The credential header name
  (`"Authorization"`) is not logged either.
- **403 response bodies** — Deny responses include host, method, path,
  and policy names but no credential information.

One minor gap: the `inject_credential` function in `mitm.rs` modifies
the `headers` vec in place (removes old, adds new). The headers are then
serialized and sent upstream (line 563-565). The headers are also passed
to `policy.evaluate()` *before* injection, so the policy engine never
sees the secret. After injection, the headers live in the `headers` vec
until the loop iteration ends — no log or error path accesses them
after injection except for upstream forwarding. This is correct.

## Checklist Results

- [x] **Credential store** — TOML parsing delegates to config.rs
  correctly. Env-var resolution is eager with clear error messages.
  Bearer and SigV4 types properly abstracted via the `Credential` trait.
  `CredentialStore::from_entries` validates all entries before storing.
- [x] **Credential matching** — Two-tier lookup (exact then pattern)
  with correct priority. Exact match always wins. Pattern matching is
  intentionally simple (`*.suffix` only). **Note:** China partition
  requires separate pattern (Finding 2).
- [x] **Header injection** — `inject_credential` removes existing headers
  case-insensitively before adding new ones. No double-injection. No
  overwrite of non-credential headers. Bearer injects one header; SigV4
  injects 3-4 headers. Injection only happens on ALLOW (or no-policy).
  DENY path does not inject credentials.
- [x] **SigV4 signing** — Delegates to aws-sigv4 crate. Canonical
  request, string-to-sign, and signing key derivation handled by the
  SDK. Content-SHA256 computed and included. Session token conditionally
  included. All error paths return `None` with structured warnings.
- [x] **SigV4 edge cases** — Chunked bodies decoded before signing.
  Empty bodies produce correct SHA-256. Query strings handled by the
  crate. All AWS endpoint variants (dualstack, FIPS, VPC, virtual-hosted,
  China, GovCloud) correctly parsed. **Note:** China credential matching
  gap (Finding 2).
- [~] **Secret lifecycle** — Secrets resolved once at startup. No
  zeroization on drop (Finding 4). No credential refresh mechanism
  (Finding 3). Debug/Display redaction is complete.
- [x] **Error handling** — Missing env vars fail at startup with clear
  messages. Unsupported source/type errors are descriptive. Signing
  failures return `None` with `warn!` logs. No panics on malformed input.
- [x] **Security** — Debug redaction complete for both credential types.
  No secret leakage in logs, errors, audit events, or response bodies.
  **Note:** Credential injection scoped to hosts only; path-level
  security depends on Cedar policy (Finding 1). No timing side-channels
  in credential lookup (HashMap lookup is not constant-time, but the
  lookup key is the hostname from the CONNECT target, not attacker
  input — the attacker already knows which host they're connecting to).
