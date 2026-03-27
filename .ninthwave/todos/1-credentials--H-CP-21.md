# Fix: Credential Debug impl leaks secrets (H-CP-21)

**Priority:** High
**Source:** design review of PR #15
**Depends on:** -
**Domain:** credentials

`BearerCredential` derives `Debug`, so `{:?}` prints the full token value. In a security-sensitive proxy, this can leak secrets in panic messages, error logs, or debug output.

Required:
- Implement custom `Debug` for `BearerCredential` that redacts the value: `BearerCredential { header: "Authorization", value: "***" }`
- Same for `SigV4Credential` — redact `secret_access_key` and `session_token`
- Audit all `Debug` derives on types that hold secrets

**Test plan:**
- Unit test: `format!("{:?}", cred)` does not contain the actual secret value
- Grep for `Debug` derives on credential-related structs to ensure none leak

Key files: `src/credentials.rs` (BearerCredential, SigV4Credential structs)
