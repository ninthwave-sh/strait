# ER-4: MITM Pipeline Review

**Date:** 2026-03-27
**Modules:** src/mitm.rs (1503 lines), src/audit.rs (551 lines)

## Summary

The MITM pipeline is well-structured and handles the core proxy lifecycle
correctly: TLS termination with per-host leaf certificates, HTTP/1.1
request parsing with keep-alive, Cedar policy evaluation, credential
injection, upstream forwarding, and response relay. The keep-alive loop
is properly gated by idle timeouts, `Connection: close`, and EOF
detection. Body buffering handles Content-Length, chunked
Transfer-Encoding, and no-body cases correctly, with a configurable
max-body-size limit enforced before allocation. The audit logger is
simple and correct — unbuffered writes ensure durability, and the
session-ID plus structured JSON format is suitable for compliance.

The most actionable findings are: request line parsing does not validate
the HTTP version token, enabling potential smuggling via HTTP/0.9 or
fabricated version strings (security); the MITM loop creates a new TLS
connection to upstream for every request, defeating HTTP keep-alive on
the upstream leg (design); there is no timeout on the upstream connection
or response relay, so a slow upstream can hold the client connection
indefinitely (missing); `Content-Length` and `Transfer-Encoding: chunked`
can coexist without rejection, which is a classic request smuggling
vector (security); and the audit log has no integrity protection —
events are append-only with no HMAC, sequence number, or tamper-evidence
mechanism (design, acceptable for v0.1).

Test coverage is solid: 30+ unit tests for parsing, credential injection,
response formatting, and chunked decoding, plus integration tests using
a loopback TLS echo server. The async architecture using `tokio::io::split`
and `BufReader` is correct and avoids the common pitfall of double-buffering.

## Findings

### 1. [SECURITY] No rejection of conflicting Content-Length and Transfer-Encoding — HIGH

**File:** `src/mitm.rs:234-304`

The request body-framing logic checks for `Transfer-Encoding: chunked`
and `Content-Length` independently. When both are present, chunked takes
priority (`has_chunked` is checked first in the `if/else if` chain at
line 260-304). This is the correct *interpretation* per RFC 9112 §6.1,
but the correct *security posture* for a proxy is to reject the request
outright.

RFC 9112 §6.1: "If a message is received with both a Transfer-Encoding
and a Content-Length header field, the Transfer-Encoding overrides the
Content-Length. Such a message might indicate an attempt to perform
request smuggling … and ought to be handled as an error."

A malicious client can craft a request with both headers where the proxy
reads the chunked body (correct) but the upstream server — if it has a
different parsing priority — reads Content-Length bytes (wrong). This is
the textbook CL/TE smuggling attack. Since strait terminates TLS and
re-serializes the request (removing `Transfer-Encoding` and rewriting
`Content-Length`), the re-serialized request sent upstream is actually
safe. However, relying on re-serialization as the defense is fragile —
any future code path that forwards headers verbatim would reintroduce
the vulnerability.

**Suggested fix:** When both `has_chunked` and `content_length.is_some()`
are true, return HTTP 400 ("ambiguous body framing: both Transfer-Encoding
and Content-Length present"). This is defense-in-depth and eliminates the
smuggling vector regardless of future refactors.

### 2. [SECURITY] HTTP request line does not validate version token — MEDIUM

**File:** `src/mitm.rs:201-207`

The request line parser splits on whitespace and extracts `method` and
`path` but ignores any third token (the HTTP version). A request like
`GET /path HTTP/0.9\r\n` is parsed identically to `GET /path HTTP/1.1\r\n`.
This has two implications:

1. **HTTP/0.9 responses**: A client sending an HTTP/0.9 request line
   (no version token, just `GET /path\r\n`) is parsed normally because
   `parts.len() >= 2` passes. The proxy constructs and forwards an
   `HTTP/1.1` request upstream. This is a protocol upgrade, not a
   security issue per se, but it masks what the client intended.

2. **Fabricated versions**: A client sending `GET /path HTTP/2.0\r\n`
   over the TLS stream gets treated as HTTP/1.1. If the upstream
   supports HTTP/2 over the same TLS connection (via ALPN), the
   mismatch could cause protocol confusion. In practice, rustls
   defaults to no ALPN and the upstream TLS negotiation would settle
   on HTTP/1.1 regardless, so this is theoretical.

3. **Three-token assumption**: If an attacker sends a request line with
   extra tokens (e.g., `GET /path HTTP/1.1 extra\r\n`), the parser
   ignores the extra tokens. This doesn't cause a smuggling issue since
   the proxy re-serializes `{method} {path} HTTP/1.1\r\n`, but it
   differs from how a standards-compliant server would reject the
   malformed line.

**Suggested fix:** Validate that `parts.len() == 3` and that
`parts[2].starts_with("HTTP/")`. For non-conforming lines, return 400.
This is low-effort hardening that improves spec compliance.

### 3. [DESIGN] New upstream TLS connection per request defeats keep-alive — MEDIUM

**File:** `src/mitm.rs:537-558`

Inside the keep-alive loop, every allowed request opens a fresh TCP
connection and performs a full TLS handshake to the upstream server
(lines 541-558). For a client sending 10 sequential requests on one
keep-alive connection, the proxy performs 10 TLS handshakes to the
upstream — each with ~1 RTT for TCP + ~2 RTTs for TLS 1.3. This adds
significant latency for chatty clients and increases load on upstream
servers.

The root cause is architectural: the upstream TLS connection is created
inside the per-request section of the loop rather than outside it. A
connection pool or persistent upstream connection per host would
eliminate redundant handshakes.

Additionally, each iteration builds a new `ClientConfig` with fresh
`RootCertStore` (lines 546-553), which is wasteful even for non-pooled
connections. The root store construction should be hoisted outside the
loop.

**Suggested fix:** For v0.1, hoist the `ClientConfig` construction
outside the loop (zero-cost improvement). For v0.2+, implement a
per-host upstream connection pool or reuse the same TLS connection for
sequential requests to the same host. This is the single highest-impact
performance improvement available.

### 4. [MISSING] No timeout on upstream connection or response relay — MEDIUM

**File:** `src/mitm.rs:541, 576-579`

The upstream TCP connect (`TcpStream::connect`) and TLS handshake
(`connector.connect`) have no explicit timeout. A DNS resolution
stall, unresponsive upstream, or slow TLS handshake will block the
per-request code path indefinitely. Similarly, `relay_upstream_response`
reads the full response with no timeout — a slow-drip upstream (e.g.,
a server sending one byte per minute) holds the client connection open
forever.

The only timeout in the pipeline is the keep-alive idle timeout (30s
default), which only fires *between* requests — not during an active
request/response exchange.

**Suggested fix:** Wrap the upstream connect + TLS handshake in
`tokio::time::timeout(ctx.upstream_connect_timeout, ...)` with a
sensible default (e.g., 30s). Wrap `relay_upstream_response` in a
separate `tokio::time::timeout(ctx.upstream_response_timeout, ...)`
(e.g., 300s for large responses). Return 502 Bad Gateway on connect
timeout, 504 Gateway Timeout on response timeout.

### 5. [SECURITY] Passthrough path does not validate CONNECT target — MEDIUM

**File:** `src/mitm.rs:85`

The passthrough branch (non-MITM hosts) connects to the CONNECT target
directly via `TcpStream::connect(format!("{host}:{port}"))`. The
`host` and `port` are parsed from the client's CONNECT line with no
validation beyond port parsing. This means:

1. **Internal network access**: A client can `CONNECT 127.0.0.1:22` to
   reach the proxy host's SSH daemon, or `CONNECT 10.0.0.5:3306` to
   reach internal MySQL. The passthrough path is an open relay to any
   TCP endpoint reachable from the proxy host.

2. **DNS rebinding**: A client can `CONNECT evil.attacker.com:443` where
   the DNS resolves to an internal IP. The proxy connects without
   checking the resolved address.

This is mitigated by the deployment model: strait runs on localhost
as a sandboxed process's proxy, not as an internet-facing proxy. The
listening address defaults to `127.0.0.1`, so only local processes can
reach it. But if deployed on `0.0.0.0` (or if a local process is
compromised), the passthrough path becomes an SSRF vector.

**Suggested fix:** Consider adding a `passthrough_deny` list or
`passthrough_allow` list for non-MITM hosts. At minimum, deny
connections to `127.0.0.0/8`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`,
and `169.254.169.254` (cloud metadata). This matters more if the proxy
is ever exposed to untrusted clients.

### 6. [QUALITY] Audit log latency measurement includes credential injection and forwarding — LOW

**File:** `src/mitm.rs:321, 486-497, 523-524`

`eval_start` is captured at line 321 (before policy evaluation) and used
for both the audit event's `eval_latency_us` and the observation event's
`latency_us`. But the observation event is emitted at line 518-526,
*after* credential injection and upstream forwarding decisions. The audit
`log_decision` calls happen closer to the actual evaluation, so their
`eval_latency_us` is more accurate, but the no-policy path (lines
486-497) includes the time spent in `inject_credential` before calling
`log_decision`.

In the no-policy path, `eval_latency_us` captures the time for
credential injection — which is not policy evaluation. The field name
is misleading.

**Suggested fix:** Capture `eval_start.elapsed()` immediately after the
policy evaluation branch (or immediately for the no-policy path) and
store it in a local variable. Pass that stored value to both the audit
event and observation event. This separates evaluation latency from
injection latency.

### 7. [DESIGN] Audit log has no tamper-evidence mechanism — LOW

**File:** `src/audit.rs:163-203`

Audit events are serialized as JSON-per-line and appended to a file
(or stderr). There is no:

1. **Sequence number**: Events have no monotonic counter. A deleted
   event leaves no gap in the log.
2. **Chained hash**: No HMAC or hash chain linking events. An attacker
   with file access can insert, delete, or reorder events undetected.
3. **Signature**: No per-event or per-batch signature.

The current design is append-only, not tamper-evident. This is
acceptable for v0.1 where the audit log serves as an operational
debugging tool rather than a compliance artifact. The session ID
provides session-level correlation, and the timestamps provide ordering
within a session.

**Suggested fix:** For a future compliance-grade audit log, consider:
1. A monotonic sequence number per session
2. An HMAC chain where each event's HMAC includes the previous event's
   HMAC (hash chain)
3. Periodic log rotation with signed summaries

For v0.1, document that the audit log is operational (not forensic) and
that tamper-evidence requires an external log aggregator with
append-only storage (e.g., S3 with Object Lock).

### 8. [QUALITY] `relay_upstream_response` defaults to status 200 on parse failure — LOW

**File:** `src/mitm.rs:618-623`

```rust
let status_code: u16 = status_line
    .split_whitespace()
    .nth(1)
    .and_then(|s| s.parse().ok())
    .unwrap_or(200);
```

If the upstream sends a malformed status line (e.g., `HTTP/1.1 XYZ OK`),
the status code defaults to 200. This means body-framing logic treats it
as a normal response with a body, which is the safest default. But:

1. The malformed status line is forwarded verbatim to the client (line
   615), so the client sees the garbage status.
2. If the upstream sends an empty status line (EOF), `read_line` returns
   an empty string, `nth(1)` returns `None`, and the code defaults to
   200 — then attempts to read a body that doesn't exist.

The second case (empty status line) would be caught by the subsequent
header-reading loop hitting EOF and producing an empty response. But a
partial status line (e.g., just `HTTP/1.1 `) would parse as 200 and
potentially misframe the body.

**Suggested fix:** Return an error (502 Bad Gateway) when the status
line is empty or the status code cannot be parsed. This is more correct
than silently defaulting to 200.

### 9. [QUALITY] `BufReader` allocation inside keep-alive loop for upstream — LOW

**File:** `src/mitm.rs:577`

A new `BufReader` is created for the upstream response reader on every
request iteration. Since a new upstream connection is also created per
request (Finding 3), this is currently correct — each `BufReader` wraps
a fresh connection. But it highlights the inefficiency: if upstream
connections were pooled, the `BufReader` should be reused with the
pooled connection.

**No immediate action needed** — this is a consequence of Finding 3 and
will resolve naturally when connection pooling is implemented.

### 10. [QUALITY] `eprintln!` for audit events bypasses tracing — LOW

**File:** `src/audit.rs:178`

Audit events are written to stderr via `eprintln!` rather than through
the `tracing` crate. This means:

1. Audit events and tracing events are interleaved on stderr with no
   coordination. A tracing JSON event and an audit JSON event may
   partially overlap in the output if two tasks write concurrently
   (though `eprintln!` holds stderr's lock for the full write, so
   individual events won't be corrupted — just interleaved).
2. Audit events cannot be filtered, redirected, or formatted by
   tracing subscribers. A user who configures `RUST_LOG=warn` still
   gets all audit events on stderr.
3. Log aggregators parsing stderr must handle two different JSON
   schemas (tracing events and audit events).

This is a deliberate design choice documented in the module doc: audit
events are a separate, unconditional stream. The `eprintln!` ensures
events reach stderr even if the tracing subscriber is misconfigured.

**Suggested fix:** Consider using `tracing::info!` with a dedicated
target (e.g., `target: "audit"`) for stderr output. This preserves
unconditional logging while allowing log aggregators to distinguish
audit events via the tracing target field. Alternatively, document that
audit events use a separate JSON schema on stderr and provide a jq
filter for separating them.

### 11. [QUALITY] `Mutex` in audit logger blocks async tasks — LOW

**File:** `src/audit.rs:61, 184`

The audit file writer uses `std::sync::Mutex`. In an async context,
holding a `std::sync::Mutex` across an `.await` point would block the
tokio worker thread. The current code does not hold the lock across
an await — `emit()` is a synchronous function that acquires the lock,
writes, and releases it in a single synchronous block. So this is
correct today.

However, the `File::write` inside the lock is a blocking syscall. For
the audit log (small JSON events, local filesystem), this blocks for
microseconds — well within acceptable limits. But if the log file is
on a network filesystem (NFS, CIFS), the write could block for
milliseconds, starving other tasks on the same tokio worker.

**No immediate action needed** — local filesystem writes are fast enough.
If NFS support becomes a requirement, consider `tokio::task::spawn_blocking`
or `tokio::sync::Mutex` with async file I/O.

### 12. [MISSING] No handling of HTTP/2 or WebSocket upgrade requests — LOW

**File:** `src/mitm.rs:141-590`

The MITM handler assumes HTTP/1.1 throughout. There is no ALPN
negotiation for HTTP/2 on the client-facing TLS connection
(`.with_no_client_auth()` on `ServerConfig` with no ALPN protocols
set). If a client attempts HTTP/2 via ALPN, the TLS handshake
succeeds but ALPN returns no match — the client falls back to
HTTP/1.1 if it supports it, or the connection fails.

For WebSocket upgrade requests (`Connection: Upgrade, Upgrade: websocket`),
the proxy would forward the upgrade request to upstream, relay the 101
response headers to the client, but then the keep-alive loop would exit
(no Content-Length, no chunked → read-until-EOF framing). The WebSocket
frames would not be proxied because the response relay function returns
after reading the HTTP response body.

This is acceptable for v0.1 (GitHub REST API doesn't use HTTP/2 or
WebSockets). The proxy silently degrades to HTTP/1.1 for clients that
support both, and fails for HTTP/2-only clients.

**Suggested fix:** For v0.2+, consider:
1. Setting ALPN protocols to `["http/1.1"]` explicitly on the server
   config to signal the supported protocol
2. Detecting `Connection: Upgrade` and switching to bidirectional
   byte-copying (like the passthrough path) after relaying the 101
   response
3. HTTP/2 support is a larger effort — consider using `hyper` for the
   HTTP layer rather than hand-rolled parsing

### 13. [QUALITY] `should_mitm` uses linear scan — LOW

**File:** `src/mitm.rs:24-26`

`should_mitm` iterates over `mitm_hosts` with `any()`. For the expected
case (1-5 hosts), this is fine. For a hypothetical deployment with
hundreds of MITM hosts, a `HashSet` would be O(1) instead of O(n).

**No immediate action needed** — the current use case has very few
MITM hosts. Note this if the host list grows.

### 14. [QUALITY] Audit logger `Clone` clones `session_id` string — LOW

**File:** `src/audit.rs:58`

`AuditLogger` derives `Clone`, which clones the `session_id` string on
every clone. Since `AuditLogger` is cloned into every connection handler
(via `ProxyContext`), this is a small but unnecessary allocation. The
session ID is immutable — wrapping it in `Arc<str>` would make clones
free.

In practice, `ProxyContext` wraps the `AuditLogger` in `Arc` (line 312
of config.rs), so the logger itself is not cloned per connection — only
the `Arc` is. The `Clone` derive is used internally but not in the hot
path.

**No immediate action needed** — the `Arc<AuditLogger>` wrapper already
prevents per-connection cloning.

## Key Question Answers

**Can a malicious request exploit differences between how strait parses
HTTP and how the upstream server parses it (request smuggling)?**

Strait's re-serialization approach provides strong protection against
request smuggling. The proxy reads and fully parses the request
(headers + body), then re-constructs a clean `{method} {path} HTTP/1.1\r\n`
request line with normalized headers. The upstream never sees the
client's raw bytes — it sees the proxy's sanitized reconstruction.

However, two gaps remain:

1. **CL/TE conflict** (Finding 1): When both `Content-Length` and
   `Transfer-Encoding: chunked` are present, the proxy chooses chunked
   and re-serializes with only `Content-Length`. The upstream sees a
   clean request, but the proxy should reject the ambiguous input as a
   best practice.

2. **Absolute-form URIs**: If a client sends `GET http://host/path HTTP/1.1`,
   the proxy extracts `http://host/path` as the path and forwards it
   verbatim. Most upstream servers accept absolute-form URIs, but the
   discrepancy could cause issues with path-based routing.

3. **Header folding**: HTTP/1.1 technically allows continuation lines
   (starting with whitespace). The proxy's header parser would treat a
   continuation line as a new header with a blank name (the `split_once(':')`
   would fail, and the line would be silently dropped). This could cause
   the proxy to see different headers than the upstream would if the
   upstream reassembles folded headers. In practice, header folding is
   deprecated (RFC 9112 §5.2) and modern servers reject it.

Overall: the re-serialization design is a strong anti-smuggling measure.
The CL/TE gap (Finding 1) is the most actionable improvement.

**Is the audit log tamper-evident or just append-only?**

Just append-only. See Finding 7. The audit log provides operational
visibility (which requests were allowed/denied, with latency) but no
cryptographic integrity guarantees. This is appropriate for v0.1 where
the log is consumed by the operator for debugging and the threat model
doesn't include a compromised operator.

**Are there requests that bypass policy evaluation (e.g., CONNECT to
non-MITM hosts)?**

Yes, by design. The passthrough path (non-MITM hosts) bypasses policy
evaluation entirely — the proxy logs a `passthrough` audit event and
tunnels bytes bidirectionally without inspection. This is the intended
behavior: MITM is opt-in per-host, and non-MITM traffic is not
inspectable.

Within the MITM path, there are no bypasses: every parsed request goes
through policy evaluation (or the "no policy = allow all" default). The
`warn_only` mode logs denials but allows traffic through — this is a
deployment option, not a bypass.

The `mitm_all` flag (used by `launch` modes) forces all CONNECT targets
into the MITM path, closing the passthrough bypass.

**How does the pipeline handle HTTP/2 or WebSocket upgrade requests?**

See Finding 12. HTTP/2 is not supported — the TLS server config has no
ALPN, so clients fall back to HTTP/1.1 or fail. WebSocket upgrades are
not explicitly handled — the upgrade request is forwarded but the
subsequent WebSocket frame stream would not be relayed properly because
the response relay function terminates after the HTTP response body.

## Checklist Results

- [x] **TLS termination** — Per-host leaf certificate generation via
  `SessionCa.issue_leaf_cert()` with caching. SNI is implicitly handled
  by generating a cert matching the CONNECT target hostname. No client
  cert support (`.with_no_client_auth()`), which is correct for the
  current use case.
- [x] **Request parsing** — HTTP/1.1 request line and headers parsed
  correctly. Case-insensitive header matching. Chunked encoding decoded
  with proper chunk-size parsing, extensions, and trailers. Content-Length
  validated for non-numeric values (400 response). **Note:** Missing
  HTTP version validation (Finding 2) and CL/TE conflict rejection
  (Finding 1).
- [x] **Keep-alive** — Connection reuse on the client side with proper
  idle timeout. Loop exits on `Connection: close` from either side,
  EOF, timeout, or unrecoverable error (413). Deny responses preserve
  keep-alive (no `Connection: close`). **Note:** No upstream connection
  reuse (Finding 3).
- [x] **Policy evaluation integration** — Cedar context correctly
  populated with host, path, method, headers, and agent identity.
  Evaluation happens before credential injection. Policy decision
  (allow/deny/warn) correctly controls the code path. ArcSwap load
  ensures atomic policy reads during hot-reload.
- [x] **Credential injection** — Correctly happens after policy
  evaluation, only on allow (or no-policy) paths. Existing headers
  removed case-insensitively before injection. Body passed to
  `inject()` for signing schemes. Identity header stripped before
  forwarding. Ties into ER-3's credential store correctly.
- [~] **Upstream forwarding** — Request re-serialized cleanly. Body
  forwarded after headers. Response relayed with correct Content-Length,
  chunked, and EOF-framed body handling. **Gaps:** No connection reuse
  (Finding 3), no timeouts (Finding 4), `ClientConfig` rebuilt per
  request.
- [x] **Audit logging** — All decisions logged: allow, deny, warn,
  passthrough, no-policy. Session ID, latency, credential injection
  status, matched policies, and denial reason all captured. Events
  written to stderr and optionally file. Unbuffered file writes for
  durability. Failures logged via tracing (not propagated).
- [x] **Audit format** — Consistent JSON structure. `skip_serializing_if`
  correctly omits optional fields (denial_reason, method, path, agent).
  Session ID propagated across all events. **Note:** No sequence numbers
  or tamper-evidence (Finding 7).
- [x] **Error handling** — Malformed requests return 400. Oversized
  bodies return 413. Policy denials return 403 with structured JSON.
  TLS failures propagated as errors. Audit failures logged but not
  propagated (proxy continues running). Mutex poisoning handled
  gracefully.
- [~] **Security** — Re-serialization is a strong anti-smuggling measure.
  Identity header stripped before upstream forwarding. Credentials never
  logged. **Gaps:** CL/TE conflict not rejected (Finding 1), HTTP
  version not validated (Finding 2), passthrough path is an open relay
  to reachable hosts (Finding 5).
