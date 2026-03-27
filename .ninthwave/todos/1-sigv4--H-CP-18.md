# Fix: Log SigV4 signing failures instead of silently swallowing (H-CP-18)

**Priority:** High
**Source:** design review of PR #17
**Depends on:** -
**Domain:** sigv4

`SigV4Credential::sign_request()` uses `.ok()?` on three fallible operations (`SigningParams::build()`, `SignableRequest::new()`, `sign()`). This converts signing failures to `None`, which the caller interprets as "credential doesn't apply to this host" — the request is forwarded unsigned with no warning.

Required:
- Replace `.ok()?` with explicit error handling that logs at `warn!` level before returning `None`
- Include the error details (which operation failed, the host, the service/region)
- Consider returning `Err` from `inject()` instead of `None` for signing failures, to distinguish "not applicable" from "failed"

Also fix:
- Remove dead code: the `if result.is_empty() { None }` branch (line ~173) is unreachable since `x-amz-content-sha256` is always pushed
- Verify no duplicate `x-amz-content-sha256` header when `aws-sigv4` also returns it

**Test plan:**
- Unit test: verify `warn!` is emitted when signing fails (use invalid signing params)
- Unit test: verify no duplicate x-amz-content-sha256 in output headers

Key files: `src/sigv4.rs` (sign_request method)
