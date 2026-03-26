# Feat: MITM production hardening — agent identity, enriched audit, Connection: close (H-SV1-4)

**Priority:** High
**Source:** Strait v0.1 design — deliverables 2, 3; eng review decisions
**Depends on:** H-SV1-1
**Domain:** proxy

Bundle three related changes to `handle_mitm` and its dependencies:

**Agent identity:** Extract the identity header (configured via `[identity].header` in config, default `X-Strait-Agent`) from incoming requests. Use the header value as the Cedar principal instead of the hardcoded `Agent::"worker"`. If the header is absent, use the configured default (e.g., `"anonymous"`). Always strip the identity header from the outbound request before forwarding upstream. Update `PolicyEngine::evaluate()` and `build_entity_hierarchy()` to accept an `agent_id: &str` parameter instead of hardcoding `"worker"`.

**Enriched audit events:** Update `AuditEvent` to include `request.agent` (String), change `matched_policy` (String) to `matched_policies` (Vec<String>), and add `denial_reason` (Option<String>). Update `AuditLogger::log_decision` signature to accept `matched_policies: &[String]` and `denial_reason: Option<&str>`. Construct `denial_reason` as `format!("Request denied by policy '{}': {} {} on {}", policies.join(", "), method, path, host)`. If the Cedar policy has a `@reason("...")` annotation, use that annotation value instead — look it up via `policy_set.annotation(policy_id, "reason")` (the existing `@id` annotation lookup pattern at policy.rs:139 shows how).

**Connection: close:** Inject or replace the `Connection` header with `Connection: close` on all forwarded requests to upstream, forcing one-request-per-connection semantics (v0.1 keep-alive mitigation).

**Test plan:**
- Unit test: agent identity extracted from header → used as Cedar principal
- Unit test: missing identity header → default principal used
- Unit test: identity header stripped from forwarded request
- Unit test: different agents get different Cedar eval results with agent-specific policies
- Unit test: `matched_policies` serializes as JSON array
- Unit test: `denial_reason` present on deny events, absent on allow events
- Unit test: `@reason` annotation value used when present, generic format when absent
- Unit test: `Connection: close` header present in all forwarded requests
- Integration test: full MITM flow with agent identity visible in audit log

Acceptance: Agent identity flows from request header through Cedar eval to audit log. Deny events include a human-readable `denial_reason`. All forwarded requests have `Connection: close`. The `@reason` annotation is a strait convention documented in the sample policy comments.

Key files: `src/mitm.rs`, `src/policy.rs`, `src/audit.rs`
