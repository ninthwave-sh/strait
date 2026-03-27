# Engineering Review: MITM Pipeline (P1-ER-4)

**Priority:** P1
**Source:** Post-v0.3 engineering review
**Depends on:** ER-2 (policy), ER-3 (credentials — both used in the pipeline)
**Domain:** review
**Sequence:** 4 of 8

## Scope

Review `src/mitm.rs` (1503 lines), `src/audit.rs` (551 lines).

## Review Checklist

- [ ] TLS termination — certificate generation per-host, SNI handling, client cert support
- [ ] Request parsing — HTTP/1.1 compliance, chunked encoding, content-length handling
- [ ] Keep-alive — connection reuse, timeout handling, connection pool limits
- [ ] Policy evaluation integration — is the Cedar context correctly populated per-request?
- [ ] Credential injection — timing (before vs after policy eval), header manipulation
- [ ] Upstream forwarding — connection reuse, error propagation, timeout handling
- [ ] Audit logging — completeness (all decisions logged?), latency measurement accuracy
- [ ] Audit format — JSON structure, field consistency, session ID propagation
- [ ] Error handling — malformed requests, upstream failures, TLS errors
- [ ] Security — request smuggling, header injection, response splitting

## Output

Write findings to `docs/reviews/ER-4-mitm-pipeline.md`. Review prior findings at `docs/reviews/ER-3-credentials.md` before starting.

Use the standard review format (see ER-1 todo for template). Categories: [BUG], [SECURITY], [QUALITY], [DESIGN], [MISSING]. Severity: HIGH/MEDIUM/LOW.

## Key Questions

- Can a malicious request exploit differences between how strait parses HTTP and how the upstream server parses it (request smuggling)?
- Is the audit log tamper-evident or just append-only?
- Are there requests that bypass policy evaluation (e.g., CONNECT to non-MITM hosts)?
- How does the pipeline handle HTTP/2 or WebSocket upgrade requests?
