# ER-8: Templates & Integration Tests Review

**Date:** 2026-03-28
**Modules:** src/templates.rs (203 lines), tests/integration.rs (3669 lines), tests/launch_integration.rs (398 lines)

## Summary

The template system is clean and well-tested — all four templates pass
Cedar schema validation at compile time, and the `apply` function
handles both file output and stdout display. The templates correctly use
the namespaced entity model (`Action::"http:GET"`, not the old
`Action::"GET"`) and provide useful starting points for GitHub and AWS S3
use cases. The most actionable template finding is that AWS schemas
declare `aws_service` and `aws_region` as required context attributes,
but GitHub schemas omit them — meaning a user cannot combine rules from
both templates without schema conflicts (Finding 1).

The integration test suite is comprehensive: 29 tests in
`tests/integration.rs` and 8 tests in `tests/launch_integration.rs`
covering the full proxy pipeline. The most valuable tests are the E2E
round-trip tests (observe → generate → replay → enforce denial) that
prove the core `init --observe` workflow produces consistent policies.
The TLS echo server accurately simulates upstream behavior with proper
certificate chains, Content-Length framing, and keep-alive support. The
SigV4 tests exercise the real production `handle_mitm` code path, not
mocks.

The most critical finding is that **several edge cases identified in
ER-1 through ER-7 lack test coverage** (Finding 4), particularly the
CL/TE conflict rejection from ER-4 Finding 1, the header-to-context
overwrite from ER-2 Finding 1, and the fs context mismatch from ER-6
Finding 2. The launch integration tests run real containers in CI (with
Docker verification), which is excellent, but the `require_docker()`
skip mechanism means tests silently pass on developer machines without
Docker (Finding 7). The integration test helpers duplicate significant
MITM logic from the production code (Finding 6), creating a maintenance
risk — changes to `handle_mitm` must be mirrored in the test helpers.

## Templates Review

### 1. [DESIGN] GitHub and AWS schemas are incompatible — no combined template — MEDIUM

**File:** `templates/github-org-readonly.cedarschema:17-22`, `templates/aws-s3-readonly.cedarschema:16-27`

GitHub schemas declare context attributes `{host, path, method}` while
AWS schemas declare `{host, path, method, aws_service, aws_region}`.
Cedar's schema validation in strict mode requires all actions to share
the same context type within a schema. A user who combines GitHub and AWS
rules into a single policy cannot use either schema for validation —
GitHub's schema rejects `aws_service` in context conditions, and AWS's
schema requires `aws_service` on every action (including GitHub
requests where it's absent).

The workaround is to use a combined schema that declares `aws_service`
and `aws_region` as optional. But no such combined template exists, and
the documentation doesn't mention the incompatibility.

**Suggested fix:** Ship a `strait.cedarschema` covering the full entity
model with optional AWS attributes:

```
context: {
    "host": String,
    "path": String,
    "method": String,
    "aws_service"?: String,
    "aws_region"?: String,
},
```

Or add a `combined` template that demonstrates multi-service policy.

### 2. [DESIGN] Templates don't cover container/filesystem use cases — MEDIUM

**File:** `src/templates.rs:21-46`

The four templates cover HTTP proxy scenarios only (GitHub API, AWS S3).
The v0.3 container platform introduces `fs:read`, `fs:write`, `fs:mount`,
and `proc:exec` actions, but there are no templates for:

- Container sandbox (fs + network combined policy)
- Filesystem-only sandbox (read-only workspace)
- Network-restricted container (allow specific hosts only)

Users following the v0.3 `strait launch` workflow have no template
starting point for Cedar policies that combine filesystem and network
rules. They must write policies from scratch or rely on `--observe` to
generate one.

**Suggested fix:** Add at least one container-oriented template (e.g.,
`container-sandbox`) that demonstrates `fs:read`, `fs:write`, and
`http:*` actions together. This would serve as the canonical example for
`strait launch --policy`.

### 3. [QUALITY] Templates are not tested against live policy evaluation — LOW

**File:** `src/templates.rs:122-145`

The `all_templates_pass_cedar_validation` test validates that templates
parse and pass schema validation. But it does not test that the policies
produce correct allow/deny decisions when evaluated against concrete
requests. For example, it doesn't verify that `github-org-readonly`
actually permits `GET /repos/your-org/my-repo` and denies `POST
/repos/your-org/my-repo`.

The template tests verify syntactic correctness (parsing + schema
validation) but not semantic correctness (actual policy behavior).

**Suggested fix:** Add behavioral tests for each template:

```rust
#[test]
fn github_org_readonly_permits_get_and_denies_post() {
    let t = find("github-org-readonly").unwrap();
    let policy = t.policy.replace("your-org", "test-org");
    // Build a PolicyEngine, evaluate GET /repos/test-org/repo → allow
    // evaluate POST /repos/test-org/repo → deny
}
```

### 4. [QUALITY] `list()` output goes to stdout with no return value — LOW

**File:** `src/templates.rs:54-62`

`list()` writes directly to `stdout` via `println!`. This makes it
untestable (no test verifies the output format) and prevents use as a
library function (callers can't capture the output). The function works
correctly for the CLI use case but is the only `templates.rs` function
with side effects.

**Suggested fix:** Return a `String` and let the caller print it, or
add a test that captures stdout.

## Integration Tests Review

### 5. [MISSING] No test for CL/TE conflict rejection (ER-4 Finding 1) — HIGH

**File:** (missing test)

ER-4 Finding 1 identified that a request with both `Content-Length` and
`Transfer-Encoding: chunked` is not rejected — the proxy silently
prioritizes chunked. The integration tests cover chunked-only
(`mitm_chunked_request_body_decoded_and_forwarded`), Content-Length-only
(`mitm_content_length_body_still_works`), and malformed Content-Length
(`mitm_malformed_content_length_returns_400`), but there is no test for
the CL/TE conflict case.

This is the most important missing test because CL/TE conflict is a
classic request smuggling vector (per RFC 9112 §6.1). Whether the proxy
rejects these requests or handles them safely, a test should document
the expected behavior.

**Suggested fix:** Add a test:

```rust
#[tokio::test]
async fn mitm_cl_te_conflict_returns_400() {
    // Send: Transfer-Encoding: chunked + Content-Length: 5
    // Expect: 400 Bad Request (or document that chunked takes priority)
}
```

### 6. [QUALITY] Test helpers duplicate production MITM logic — MEDIUM

**File:** `tests/integration.rs:2978-3215` (strait_test_helpers module)

The `handle_mitm_connection`, `handle_mitm_connection_chunked`,
`handle_mitm_keepalive_with_timeout`, and `handle_mitm_keepalive_deny_path`
functions reimplement significant portions of the production `handle_mitm`
code path:

- TLS termination with session CA cert
- HTTP request parsing (request line, headers, Content-Length)
- Chunked encoding decoding
- Body forwarding to upstream echo server
- Response relay with Content-Length framing
- Keep-alive loop with timeout and Connection: close handling

This duplication means:

1. **Changes to `handle_mitm` may not be reflected in test helpers.**
   If production code adds a new header normalization step, the test
   helpers won't have it — tests pass but don't test real behavior.

2. **Bugs in test helpers produce false confidence.** If the helper has
   a different parsing behavior than production, tests can pass while
   the real code has a bug.

3. **Maintenance burden.** The helpers total ~700 lines — roughly half
   the length of `src/mitm.rs` itself.

Note that some tests (`mitm_malformed_content_length_returns_400`,
`mitm_negative_content_length_returns_400`) correctly use the production
`handle_mitm` function directly, while others use the test helpers. The
tests using `handle_mitm` directly are more trustworthy because they
exercise the real code.

The SigV4 tests are the gold standard: `send_through_proxy` constructs a
real `ProxyContext` and calls the production `handle_mitm` function,
exercising the full pipeline end-to-end.

**Suggested fix:** Migrate more tests to use the real `handle_mitm`
function (via `ProxyContext` with `upstream_addr_override` and
`upstream_tls_override`). The SigV4 test pattern (`build_sigv4_proxy_context`
+ `send_through_proxy`) demonstrates how to do this cleanly. Keep the
test helpers only for behaviors that can't be tested through the
production code (e.g., the deny-path helper for keep-alive policy deny
testing).

### 7. [DESIGN] Launch tests skip silently on developer machines — MEDIUM

**File:** `tests/launch_integration.rs:30-46`

```rust
async fn require_docker() -> bool {
    if docker_available().await { return true; }
    if std::env::var("CI").is_ok() {
        panic!("Docker with alpine:latest is required in CI...");
    }
    eprintln!("Skipping: Docker not available");
    false
}
```

On developer machines without Docker, all 8 launch integration tests
silently return early. The test result shows "8 passed" with no
indication that the tests were actually skipped. This creates a false
sense of coverage — a developer can break container functionality and
still see a green test suite locally.

The CI workflow correctly catches this: it runs `docker pull alpine:latest`
before tests, and a separate step verifies tests actually ran (not
skipped). So CI coverage is enforced. But the local development
experience is misleading.

**Suggested fix:** Use `#[ignore]` attribute with `cargo test --ignored`
for Docker-dependent tests, or emit a more prominent skip message. The
current approach is a pragmatic trade-off (developers can run `cargo test`
without Docker installed), but worth noting.

### 8. [MISSING] No test for header-to-context overwrite (ER-2 Finding 1) — MEDIUM

**File:** (missing test)

ER-2 Finding 1 identified that HTTP headers can overwrite built-in
context attributes (`host`, `path`, `method`). A request with a header
`path: /admin` could change `context.path` in Cedar evaluation. There
is no integration test verifying this behavior — either that the
overwrite is blocked, or that it happens (documenting the current
behavior for awareness).

**Suggested fix:** Add a test:

```rust
#[tokio::test]
async fn mitm_header_does_not_overwrite_context_path() {
    // Send: GET /repos/org/repo with header "path: /admin"
    // Evaluate: a policy with `when { context.path like "/admin" }`
    // Verify: policy evaluates against the real path, not the header
}
```

### 9. [MISSING] No test for Cedar entity model migration (old v0.1 actions) — MEDIUM

**File:** (missing test)

The TODO's key question asks: "Is there a test for the Cedar entity
model migration (old v0.1 policies rejected/migrated)?" The answer is
**no** — there is no integration test for `check_old_format_actions`.
The function is tested in `src/policy.rs` unit tests (verified by
reading ER-2), but no integration test verifies the end-to-end behavior:
that starting the proxy with an old-format policy file produces a clear
error message.

**Suggested fix:** Add an integration test:

```rust
#[test]
fn old_format_policy_rejected_with_migration_message() {
    let dir = tempfile::tempdir().unwrap();
    let policy_path = dir.path().join("old.cedar");
    std::fs::write(&policy_path, r#"
        permit(principal, action == Action::"GET", resource);
    "#).unwrap();
    // Attempt to load policy → expect error containing "http:GET"
}
```

### 10. [MISSING] No test for fs context mismatch between replay and live evaluation (ER-6 Finding 2) — MEDIUM

**File:** (missing test)

ER-6 Finding 2 identified that `evaluate_fs` uses `Context::empty()`
while replay provides `path` and `operation` context attributes. A
`when { context.path ... }` condition evaluates differently in replay
vs. live. No integration test verifies this alignment (or documents the
divergence).

The E2E round-trip tests (`e2e_roundtrip_observe_generate_replay`,
`e2e_roundtrip_filesystem_only`) exercise the generate→replay path
successfully because the generated policies don't use `when` context
conditions on fs actions. But a policy with an fs context condition
would expose the mismatch.

**Suggested fix:** Add a test:

```rust
#[test]
fn fs_context_condition_matches_in_replay_and_live() {
    // Create a policy: permit fs:read on resource in fs::/ when context.path like "/workspace/*"
    // Replay observation: fs:read /workspace/file.txt → should match
    // Live evaluate_fs: /workspace/file.txt → should also match
    // If they disagree, that's the ER-6 Finding 2 bug
}
```

### 11. [QUALITY] Echo server doesn't validate HTTP request format — LOW

**File:** `tests/integration.rs:68-107`

The `start_tls_echo_server` parses HTTP requests by reading lines until
an empty line, then echoing everything back. It doesn't validate:

- Request line format (method, path, version)
- Header key-value format (the `split_once(':')` silently skips
  malformed headers)
- Content-Length as a valid number

This is acceptable for a test echo server — its job is to reflect
requests, not enforce HTTP compliance. But it means the echo server
would accept and echo back malformed requests that a real server would
reject, potentially masking issues in the proxy's request
re-serialization.

**No immediate action needed** — the echo server's simplicity is a
feature. It would only need hardening if tests relied on it to enforce
HTTP compliance.

### 12. [QUALITY] Keep-alive echo server duplicates single-request echo server code — LOW

**File:** `tests/integration.rs:119-247` vs `tests/integration.rs:15-113`

`start_keepalive_echo_server` (128 lines) shares ~60% of its code with
`start_tls_echo_server` (98 lines): certificate generation, TLS server
config, header parsing, Content-Length extraction, and echo response
building. The only difference is the keep-alive loop structure and
`Connection: close` handling.

Similarly, `start_aws_echo_server` (96 lines) duplicates the same
certificate generation and TLS setup with configurable SANs.

**Suggested fix:** Extract shared setup into a helper:

```rust
async fn start_echo_server_with_options(
    sans: &[&str],
    keep_alive: bool,
) -> (SocketAddr, String, CertificateDer<'static>) { ... }
```

This would reduce ~320 lines of duplicate setup to ~100 lines of shared
code. Low priority — the duplication doesn't affect correctness.

### 13. [QUALITY] SigV4 tests use `set_var` which is not thread-safe — LOW

**File:** `tests/integration.rs:705-711`

```rust
std::env::set_var(creds.ak_var, creds.access_key);
std::env::set_var(creds.sk_var, creds.secret_key);
```

`std::env::set_var` is not thread-safe in Rust (it's `unsafe` since
Rust 1.66). When tests run in parallel, concurrent `set_var`/`remove_var`
calls from different SigV4 tests could race. Each test uses unique env
var names (`STRAIT_INTG_SV4_AK_S3PUT`, `STRAIT_INTG_SV4_AK_LAMBDA`,
etc.) which mitigates the read-race risk, but the `set_var` itself is
UB under the POSIX threading model.

In practice, Rust's test runner uses threads (not processes) for
`#[tokio::test]`, so multiple SigV4 tests could call `set_var`
concurrently. The unique var names prevent logical data races, but the
UB from concurrent `set_var` calls remains.

**Suggested fix:** Use `env_lock` crate or `serial_test` to serialize
tests that modify environment variables. Or refactor `SigV4Credential`
to accept credentials directly (not from env vars) in test mode.

### 14. [DESIGN] E2E round-trip tests don't exercise live MITM policy evaluation — LOW

**File:** `tests/integration.rs:1968-2128`

The E2E round-trip tests (`e2e_roundtrip_observe_generate_replay`) use
`ObservationStream::emit()` to synthesize events and `replay::replay()`
to verify policy coverage. This tests the generate→replay pipeline but
does NOT exercise:

1. The live `PolicyEngine::evaluate()` code path
2. The MITM handler's policy evaluation integration
3. The Cedar entity hierarchy construction from real HTTP requests

The test proves that generated policies cover synthesized observations
in replay mode. It does not prove that the generated policy would
correctly allow/deny the same requests when flowing through the real
proxy pipeline. The context mismatch issues from ER-6 (Findings 2, 3, 5)
would be caught by a test that exercises the full proxy pipeline with
a generated policy.

**Suggested fix:** Add a test that sends real HTTP requests through the
MITM proxy with a Cedar policy loaded, verifying that allowed requests
reach the echo server and denied requests get 403. The SigV4 test
pattern (`send_through_proxy` with `ProxyContext`) demonstrates how to
do this with a policy engine attached.

## Cross-Reference: ER-1 through ER-7 Findings vs Test Coverage

| Finding | Description | Tested? | Notes |
|---|---|---|---|
| ER-1 F2 | Leaf certs missing EKU:ServerAuth | No | No test checks EKU on issued certs |
| ER-2 F1 | **Header overwrites context** | **No** | See Finding 8 above |
| ER-2 F2 | `escape_cedar_string` incomplete | No | No test sends control chars in paths/headers |
| ER-2 F3 | No `evaluate_proc` method | No | No integration test for proc evaluation |
| ER-2 F5 | `evaluate_fs` uses empty context | Partially | E2E tests use replay (not live `evaluate_fs`) |
| ER-3 F2 | China partition credential match | No | No test with `.amazonaws.com.cn` hosts |
| ER-4 F1 | **CL/TE conflict not rejected** | **No** | See Finding 5 above — most impactful gap |
| ER-4 F2 | HTTP version not validated | No | No test sends `HTTP/0.9` or fabricated versions |
| ER-4 F4 | No upstream timeout | No | No test for slow/unresponsive upstream |
| ER-4 F5 | Passthrough is an open relay | No | No test for internal network access via passthrough |
| ER-5 F1 | Passthrough events not emitted | No | No test verifies passthrough observation events |
| ER-5 F2 | Socket discovery directory mismatch | No | Tests use explicit socket paths |
| ER-5 F3 | Socket accept breaks on error | No | No test injects accept() failures |
| ER-6 F1 | **Wildcard policies non-functional** | **No** | Critical — wildcard tests verify text, not behavior |
| ER-6 F2 | **Replay fs context mismatch** | **No** | See Finding 10 above |
| ER-6 F3 | Replay treats "warn" as deny | No | No test replays warn-mode observations |
| ER-6 F4 | Generate includes denied observations | No | No test generates from mixed allow/deny |
| ER-7 F1 | Container bypasses proxy via IP | No | Would require network-level test in CI |
| ER-7 F2 | Bind-mount path traversal | No | No test with `..` or symlink paths |
| ER-7 F6 | SIGTERM not handled | No | Signal handling tests are inherently difficult |

**Bold** entries are the highest-priority gaps — they represent known
security or correctness issues with no test coverage.

## TLS Echo Server Assessment

The echo server accurately simulates real upstream behavior for the
test scenarios:

- **Certificate chain:** Correct CA → leaf chain with proper SANs for
  the MITM target hostname. Leaf certs include both the target hostname
  and `localhost` SANs.
- **HTTP parsing:** Request line + headers + Content-Length body.
  Handles the typical request formats sent by the proxy.
- **Keep-alive variant:** Properly handles multiple sequential requests,
  `Connection: close` detection, and response framing without
  `Connection: close` headers.
- **AWS variant:** Configurable SANs for AWS hostname simulation
  (e.g., `s3.us-east-1.amazonaws.com`).

**Limitations:**
- No chunked response encoding (only Content-Length framing)
- No HTTP error responses (always 200 OK)
- No connection timeout simulation (would be needed for ER-4 F4 tests)
- No TLS alert simulation (always succeeds or silently drops)

These limitations are acceptable — the echo server is designed for
happy-path testing of the proxy pipeline, not for negative testing of
upstream behavior.

## Launch Integration Tests Assessment

The launch integration tests exercise real container behavior in CI:

- **Docker requirement enforced in CI:** The `require_docker()` function
  panics in CI (`CI` env var set) if Docker is unavailable. The CI
  workflow pulls `alpine:latest` before tests and verifies tests actually
  ran (not skipped). This is a robust CI setup.

- **Real container operations:** Tests call `run_launch_observe` and
  `run_launch_with_policy` which create, start, and remove real Docker
  containers. Container lifecycle events (start/stop, mount, exit code)
  are verified against the observation JSONL output.

- **Policy enforcement tested:** `launch_policy_restricts_mounts` and
  `launch_warn_allows_agent_to_succeed` verify that Cedar policies
  affect container bind-mounts and enforcement mode behavior.

- **Error paths tested:** Invalid policy files, missing policy files,
  and bad commands (exit code propagation) are all covered.

- **Docker availability test:** `docker_not_running_gives_clear_error`
  tests the error message path, though its effectiveness depends on
  whether Docker is actually running (if Docker is running, the test
  is a no-op with an eprintln).

**Gaps:**
- No test for TTY interaction (would be difficult to automate)
- No test for SIGINT/SIGTERM cleanup behavior
- No test for `host.docker.internal` resolution (platform-specific)
- No test for CA trust injection inside the container (the entrypoint
  script runs but its effect isn't verified)

## CI Reliability Assessment

The CI workflow is well-designed for reliability:

- **Single `test` job** runs `cargo test`, `cargo clippy`, and
  `cargo fmt --check` sequentially (correct — formatting changes could
  affect test compilation).
- **Docker pre-pull** ensures `alpine:latest` is available before tests.
- **Skip verification** detects if launch tests were silently skipped,
  preventing false green CI.
- **Cross-platform builds** cover x86_64/aarch64 for Linux and macOS.

**Potential flakiness sources:**
- **Port conflicts:** All test servers use `127.0.0.1:0` (OS-assigned
  ports), eliminating port conflict flakiness. This is correct.
- **Timing dependencies:** The keep-alive idle timeout test
  (`keepalive_idle_timeout_closes_connection`) uses a 1s timeout with a
  1.5s sleep, leaving only 500ms of margin. Under CI load, this could
  flake. The 3s `tokio::time::timeout` on the subsequent read provides
  a safety net.
- **Docker timing:** Container start/stop timing is non-deterministic.
  Tests use `attach_and_wait` (blocking until exit) rather than polling,
  which is correct.
- **Resource leaks:** Each test creates temporary directories via
  `tempfile::tempdir()` which are cleaned up on drop. TLS servers and
  TCP listeners are spawned as tasks — they're leaked (the spawned
  tasks run until the test process exits), but this is harmless since
  each test gets its own listener on a unique port.
- **env var races:** SigV4 tests modify environment variables
  concurrently (see Finding 13). Unique var names prevent logical races,
  but the UB risk exists.

Overall CI reliability is **good**. The most likely flakiness source is
the timing-dependent keep-alive timeout test, but it has not been
reported as flaky. The Docker integration tests add real value by
testing actual container behavior, and the skip-verification step
prevents silent test omission.

## Key Question Answers

**Are there edge cases identified in ER-1 through ER-7 that lack test
coverage?**

Yes — see the cross-reference table above. The highest-priority gaps
are:

1. **CL/TE conflict** (ER-4 F1): No test for conflicting
   Content-Length and Transfer-Encoding headers. This is the most
   security-relevant gap.

2. **Header-to-context overwrite** (ER-2 F1): No test for headers that
   collide with built-in Cedar context attributes. A security-relevant
   gap that could enable policy bypass.

3. **Wildcard policy functionality** (ER-6 F1): The generate module's
   wildcard collapsing produces non-functional Cedar entity IDs. No
   test verifies that collapsed policies actually match requests during
   evaluation. The existing tests verify text output only.

4. **Replay/live fs context alignment** (ER-6 F2): No test confirms
   that fs context conditions evaluate identically in replay and live
   modes.

**Do the integration tests cover the full observe→generate→enforce
round-trip (success criteria #3)?**

Yes, at the library level. The E2E tests (`e2e_roundtrip_observe_
generate_replay`, `e2e_enforce_denies_unauthorized_actions`,
`e2e_roundtrip_full_lifecycle_mixed_events`) exercise the full pipeline:

1. **Observe:** Emit events via `ObservationStream` to a JSONL file
2. **Generate:** Produce Cedar policy + schema from the observation log
3. **Replay:** Verify all observations match the generated policy
4. **Enforce (denial):** Verify unauthorized events are denied

However, these tests use synthesized events and replay-mode evaluation,
not the real MITM proxy pipeline. A true end-to-end test would route
HTTP requests through the proxy with a loaded policy, verifying actual
allow/deny behavior. The SigV4 tests come closest to this pattern but
don't test with a Cedar policy engine attached.

**Are the launch integration tests actually running containers in CI,
or are they skipped?**

They run real containers. The CI workflow:
1. Pulls `alpine:latest` before tests
2. Runs `cargo test --test launch_integration`
3. Verifies the output does NOT contain "Skipping: Docker not available"
4. Verifies the output contains "test result: ok"

The `require_docker()` function panics (not skips) in CI when Docker
is unavailable, ensuring a CI failure rather than silent skip.

**Is there a test for the Cedar entity model migration (old v0.1
policies rejected/migrated)?**

No integration test. The `check_old_format_actions` function has unit
tests in `src/policy.rs` (per ER-2 review), but no integration test
verifies the end-to-end behavior of loading an old-format policy file
through the proxy startup path.

## Checklist Results

- [x] **Template correctness** — All four templates use the namespaced
  entity model (`Action::"http:GET"`, `Resource::"host/path"`).
  Policies parse and validate against their schemas. VALIDATED comments
  confirm review date. **Gap:** GitHub and AWS schemas are incompatible
  (Finding 1).
- [~] **Template coverage** — GitHub (readonly, contributor) and AWS S3
  (readonly, readwrite) covered. **Gap:** No container/filesystem
  templates (Finding 2). No combined multi-service template.
- [~] **Integration test coverage** — 29 tests cover: MITM TLS
  termination, passthrough, body preservation, SigV4 signing (5 tests),
  keep-alive (4 tests), observation mode (3 tests), E2E round-trip
  (6 tests), chunked encoding (4 tests). **Gaps:** CL/TE conflict,
  header-context overwrite, old-format migration, fs context alignment.
- [x] **Test isolation** — All tests use `127.0.0.1:0` for ports,
  `tempfile::tempdir()` for filesystem, and unique env var names for
  SigV4. No network access. No shared state between tests.
- [x] **TLS echo server** — Accurately simulates real upstream for
  happy-path testing. Proper certificate chains, Content-Length framing,
  keep-alive support. Limitations (no error responses, no chunked
  responses) are acceptable for the test scenarios.
- [x] **Launch integration tests** — Run real containers in CI with
  Docker verification. Test observe mode, policy enforcement, warn mode,
  error paths, and container lifecycle events. Skip gracefully on
  developer machines.
- [~] **Coverage gaps** — See cross-reference table. 4 HIGH/MEDIUM
  findings from ER-1–7 have no test coverage. Most impactful: CL/TE
  conflict and wildcard policy functionality.
- [x] **Test quality** — Tests verify behavior (response content, exit
  codes, observation events) not implementation details. Assertions use
  descriptive messages. **Note:** Test helpers duplicate production
  logic (Finding 6).
- [~] **Flakiness** — Low risk overall. OS-assigned ports eliminate
  conflicts. One timing-dependent test (keep-alive idle timeout) has
  narrow margin. env var races in SigV4 tests are theoretical.
- [x] **CI reliability** — Tests pass consistently. Docker skip
  verification prevents silent omission. Cross-platform builds verified.
