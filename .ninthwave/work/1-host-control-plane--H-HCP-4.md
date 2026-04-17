# Refactor: Move credential store to host control plane (H-HCP-4)

**Priority:** High
**Source:** `docs/designs/in-container-rewrite.md` Phase 2
**Depends on:** H-HCP-2
**Domain:** host-control-plane
**Lineage:** c1ac4043-d492-4536-84c7-893028dc9158
**Requires manual review:** true

Move credential logic out of the in-container proxy. `src/credentials.rs` and `src/sigv4.rs` become part of `strait-host`; the in-container proxy no longer reads credentials from env or disk. On allow, the proxy calls `FetchCredential(session_id, host, action)` over gRPC; the host returns the computed Authorization header value (bearer) or the SigV4-signed header bundle for that single request. Credentials never touch the container filesystem. Flagged for manual review: this rewrites the secrets path.

**Test plan:**
- Unit test: bearer credential returns expected header value for a given host.
- Unit test: SigV4 signing produces the same output as the current `src/sigv4.rs` for canned inputs.
- Integration test: two containers, two different bearer credentials, `FetchCredential` routes each to the correct session.
- Security test: agent user in container has no file readable under `/run/strait/` that contains a credential.

Acceptance: Credentials live only in `strait-host` memory and its configured source (env vars on the host, keychain integration deferred). `FetchCredential` RPC returns the right value for bearer and SigV4. The in-container proxy never holds a credential across requests; each outbound allow triggers a fresh RPC. No credential strings appear in the container filesystem or environment.

Key files: `host/src/credentials.rs`, `host/src/sigv4.rs`, `agent/src/credential_injector.rs`, `src/credentials.rs` (delete after move), `src/sigv4.rs` (delete after move)
