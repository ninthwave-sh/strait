# ER-5: Observation Pipeline Review

**Date:** 2026-03-28
**Modules:** src/observe.rs (947 lines), src/watch.rs (863 lines)

## Summary

The observation pipeline provides a clean, well-tested event streaming
system. `ObservationStream` uses a tokio broadcast channel to fan out
events to multiple consumers (socket clients, JSONL file) and the watch
viewer renders colored terminal output with automatic socket discovery
and reconnection. The event model covers network requests, container
lifecycle, mounts, filesystem access, process execution, and policy
violations — a comprehensive set for the v0.3 sandbox platform.

The most actionable findings are: passthrough connections are not
emitted as observation events, so `strait watch` and `generate` miss
non-MITM traffic entirely (missing); `discover_socket()` only searches
`/tmp` but the socket may be created in `XDG_RUNTIME_DIR` or `cwd` if
`/tmp` is unwritable, causing `strait watch` to fail to find the server
(bug); the socket accept loop breaks on any error, permanently disabling
the observation socket after a transient OS error like EMFILE (bug); the
JSONL writer uses `BufWriter` but flushes after every event, defeating
the buffer and adding syscall overhead in the hot path (quality); and
there is no event schema version, so `generate` and `replay` will
silently misparse logs from a different version (design).

Test coverage is excellent: 45+ tests covering serialization round-trips,
broadcast delivery, backpressure/lag, JSONL file output, socket server
lifecycle, client disconnect resilience, stale socket cleanup, duration
parsing, color classification, event formatting, terminal width
truncation, and socket discovery. The async tests use `tempdir` for
socket isolation, avoiding cross-test interference.

## Findings

### 1. [MISSING] Passthrough connections not emitted as observation events — HIGH

**File:** `src/main.rs:83-95`

The passthrough path (non-MITM hosts) logs to the audit logger via
`ctx.audit_logger.log_passthrough(&host, port)` but does not emit an
`ObservationEvent`. This means:

1. **`strait watch` is blind to passthrough traffic.** The viewer only
   shows MITM'd requests. A user watching a `launch --observe` session
   sees nothing for hosts that aren't in the MITM list.

2. **`generate` misses passthrough hosts.** The policy generator only
   sees events in the JSONL file. Passthrough connections leave no
   observation record, so auto-generated policies won't cover those
   hosts.

3. **`replay` can't validate passthrough behavior.** No observation
   record means no replay capability.

The `EventKind::NetworkRequest` enum already has a `"passthrough"`
decision value, and `watch.rs` has a `Passthrough` color variant with
dim rendering — the downstream handling is complete, but the event is
never emitted upstream.

**Suggested fix:** In the passthrough branch of `handle_connection`
(src/main.rs:83-95), emit:
```rust
if let Some(ref obs) = ctx.observation_stream {
    obs.emit(EventKind::NetworkRequest {
        method: "CONNECT".to_string(),
        host: host.to_string(),
        path: String::new(),
        decision: "passthrough".to_string(),
        latency_us: 0,
        enforcement_mode: String::new(),
    });
}
```

### 2. [BUG] `discover_socket` only searches `/tmp`, mismatching `resolve_socket_dir` — MEDIUM

**File:** `src/watch.rs:237-239`, `src/observe.rs:259-265`

The server side (`resolve_socket_dir`) tries `/tmp`, then
`XDG_RUNTIME_DIR`, then cwd — choosing the first writable directory.
The client side (`discover_socket`) hardcodes `/tmp` only.

If `/tmp` is not writable (common in restrictive containers or sandboxed
environments), the socket is created in `XDG_RUNTIME_DIR` or cwd, but
`strait watch` auto-discovery can never find it. The user gets an
infinite "Waiting for strait launch..." loop with no indication that a
running server exists in another directory.

**Suggested fix:** Mirror the search order in `discover_socket`:
```rust
pub fn discover_socket() -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/tmp")];
    if let Ok(xdg) = std::env::var("XDG_RUNTIME_DIR") {
        candidates.push(PathBuf::from(xdg));
    }
    for dir in &candidates {
        if let Some(sock) = discover_socket_in(dir) {
            return Some(sock);
        }
    }
    None
}
```
Or: have `start_socket_server` write the socket path to a well-known
file (e.g., `~/.config/strait/socket-path`) for reliable discovery.

### 3. [BUG] Socket accept loop breaks on any error, permanently disabling server — MEDIUM

**File:** `src/observe.rs:314-357`

The socket server's accept loop (line 350-355):
```rust
Err(e) => {
    tracing::warn!(error = %e, "observation socket accept error");
    break;
}
```

On any `accept()` error — including transient OS errors like EMFILE
(too many open file descriptors), ENOMEM, or EINTR — the loop breaks
and the server stops accepting new connections permanently. The
socket file remains on disk, so `strait watch` can connect but gets
immediate EOF, which looks like a server crash.

**Suggested fix:** Distinguish transient from fatal errors. For
transient errors, sleep briefly and retry:
```rust
Err(e) => {
    tracing::warn!(error = %e, "observation socket accept error");
    tokio::time::sleep(Duration::from_millis(100)).await;
    continue;
}
```
For fatal errors (e.g., listener fd closed), breaking is correct.
A conservative approach is to always continue with a backoff —
if the listener is truly broken, the process is shutting down anyway.

### 4. [DESIGN] No event schema version — events are not forward-compatible — MEDIUM

**File:** `src/observe.rs:31-38`

`ObservationEvent` has a `timestamp` and flattened `EventKind`, but no
version field. The JSONL file format is implicitly v1, but there is
no way for consumers to detect a version mismatch.

If a future release adds a required field, renames a variant, or
changes the `serde(rename_all)` convention, `replay` and `generate`
will silently fail to deserialize events from old logs (returning
`Err` on `serde_json::from_str`) or silently misinterpret them.

Both `generate` and `replay` depend on the JSONL format for
correctness. The `replay` module re-evaluates policy decisions from
old logs — if the event schema drifts, replay results become
unreliable with no error message.

**Suggested fix:** Add a top-level `version` field (integer, starting
at 1):
```rust
pub struct ObservationEvent {
    pub version: u32,  // always 1 for now
    pub timestamp: String,
    #[serde(flatten)]
    pub event: EventKind,
}
```
With `#[serde(default = "default_version")]` for backward
compatibility. Consumers can check the version and warn on mismatch.

### 5. [QUALITY] `BufWriter` flushed per event defeats buffering — MEDIUM

**File:** `src/observe.rs:157-164`

```rust
if let Ok(mut w) = writer.lock() {
    let _ = writeln!(w, "{json}");
    let _ = w.flush();
}
```

Every `emit()` call acquires the mutex, writes one JSON line, and
immediately flushes the `BufWriter`. The flush forces a `write()`
syscall, which means the `BufWriter` is never actually buffering —
it's equivalent to unbuffered I/O with extra allocation overhead
(the 8 KiB internal buffer is allocated but never used for batching).

During high-throughput observation (e.g., a build process making
hundreds of HTTP requests), this generates one `write()` + one
`fsync()` syscall per event. Under load, this adds ~10-50μs of
latency per event from the syscall overhead.

**Suggested fix:** Either:
1. Remove `BufWriter` and use `File` directly (same behavior, less
   allocation, more honest about the flushing strategy).
2. Remove the per-event `flush()` and rely on `BufWriter`'s automatic
   flushing at 8 KiB boundaries. Add a periodic flush (e.g., every
   100ms) via a background task. This batches writes for throughput
   while bounding staleness.

Option 1 is simpler and matches the intent (durability per event).
Option 2 is better for throughput but risks losing the last few
events on crash.

### 6. [DESIGN] Mid-session `watch` connections miss all prior events — MEDIUM

**File:** `src/observe.rs:176-178`, `src/watch.rs:336-358`

When `strait watch` connects to the observation socket, it subscribes
to the broadcast channel via `tx.subscribe()`. The broadcast channel
only delivers events emitted *after* the subscription — all prior
events are lost.

This means:
1. If a user starts `strait watch` 30 seconds into a session, they
   miss the container start event, all mount events, and any early
   requests.
2. There is no "catch up" mechanism — no backlog replay, no initial
   state snapshot.

The JSONL file has all events, but the socket client has no way to
request them.

**Suggested fix:** For v0.3, this is acceptable — `watch` is a
real-time viewer, not a historical log viewer. Document this behavior
explicitly. For a future enhancement, consider:
1. Sending the last N events from a ring buffer on client connect
2. Having the socket server replay from the JSONL file on connect
3. Adding a `--replay` flag to `strait watch` that reads the JSONL
   file first, then switches to live streaming

### 7. [QUALITY] `enforcement_mode` always empty in MITM NetworkRequest events — LOW

**File:** `src/mitm.rs:518-525`

The `NetworkRequest` event emitted from the MITM pipeline always sets
`enforcement_mode: String::new()`:
```rust
obs.emit(crate::observe::EventKind::NetworkRequest {
    // ...
    enforcement_mode: String::new(),
});
```

The field exists on the enum variant and is meaningful for
`PolicyViolation` events emitted in `launch.rs`, but it's never
populated for `NetworkRequest` events. Since the field has
`#[serde(skip_serializing_if = "String::is_empty")]`, it's omitted
from the JSON output — no data corruption, but the field is dead
weight in the `NetworkRequest` variant.

In `launch.rs`, the enforcement mode is available from the context
(`EnforcementMode::Warn` or `::Enforce`), but it's not threaded
through to the MITM's observation event emission.

**Suggested fix:** Either populate `enforcement_mode` from
`ctx.warn_only` (if true, `"warn"`; if a policy exists, `"enforce"`;
otherwise `"observe"`) or remove the field from `NetworkRequest` and
keep it only on `PolicyViolation`. Populating it is more useful for
downstream consumers.

### 8. [QUALITY] Serialization failure silently drops events — LOW

**File:** `src/observe.rs:157-164`

```rust
if let Ok(json) = serde_json::to_string(&observation) {
    if let Ok(mut w) = writer.lock() {
        let _ = writeln!(w, "{json}");
        let _ = w.flush();
    }
}
```

Three failure points are silently swallowed:
1. `serde_json::to_string` fails → event not written, no log
2. `writer.lock()` fails (poisoned mutex) → event not written, no log
3. `writeln!` or `flush()` fails (disk full, I/O error) → no log

The broadcast `send()` is similarly best-effort (returns 0 if no
receivers), which is documented and correct. But file write failures
should at least be logged — a disk-full condition silently dropping
all observation events is a surprising failure mode.

The mutex poisoning case (2) is particularly worth noting: if any
prior `emit()` call panics while holding the lock, *all subsequent
events* are silently dropped for the rest of the session.

**Suggested fix:** Add `tracing::warn!` for serialization and write
failures. For mutex poisoning, consider using
`writer.lock().unwrap_or_else(|e| e.into_inner())` to recover from
poisoned locks (the internal state is still valid for writing).

### 9. [QUALITY] Socket server task has no cleanup on drop — LOW

**File:** `src/observe.rs:314-361`

The socket server is spawned via `tokio::spawn` with no
`JoinHandle` stored or abort mechanism. When the `ObservationStream`
is dropped, the broadcast channel closes (`Sender` is dropped →
all receivers get `Closed`), which causes client handler tasks to
exit cleanly. But the accept loop continues running until the next
`accept()` call, and the socket file remains on disk.

The stale socket cleanup at startup (line 299-304) handles this for
the *next* process, but between process exit and next startup, the
socket file exists and confuses `discover_socket` — it discovers a
dead socket, `strait watch` connects, gets immediate EOF, reconnects,
gets EOF again, in a rapid loop.

**Suggested fix:** Return the `JoinHandle` from
`start_socket_server_at` and abort it in a `Drop` impl (or expose
a `shutdown()` method). Clean up the socket file in the shutdown
path. Alternatively, accept that the stale-socket-on-crash case is
handled at startup and document the behavior.

### 10. [QUALITY] `discover_socket` picks newest by mtime, not by liveness — LOW

**File:** `src/watch.rs:247-264`

Socket discovery sorts by modification time and picks the newest.
But mtime reflects when the file was *created*, not whether the
server is still running. If a server crashes and a new server starts
with a different PID, the old socket file (now stale) may have a
newer mtime than the new socket if they were created in the same
second.

More practically: if two strait processes run simultaneously (e.g.,
two terminals), `discover_socket` picks the newest socket, which may
not be the one the user intended. There's no way to specify which
session to watch without using `--socket`.

**Suggested fix:** After finding the newest socket, attempt a
connect-and-immediately-close probe. If the connection is refused,
skip to the next candidate. This adds negligible latency (one
syscall) and avoids connecting to stale sockets.

### 11. [DESIGN] `emit()` is synchronous and blocks the async caller — LOW

**File:** `src/observe.rs:150-169`

`emit()` is a synchronous function that:
1. Serializes the event (`serde_json::to_string`)
2. Acquires a `std::sync::Mutex`
3. Writes to a file (blocking I/O)
4. Flushes the file (blocking I/O)
5. Sends on the broadcast channel (non-blocking)

Steps 2-4 block the calling tokio task's worker thread. For local
filesystem writes, this blocks for microseconds — acceptable. But
`emit()` is called from the MITM hot path (src/mitm.rs:518) for
every proxied request. Under load (hundreds of concurrent requests),
the mutex becomes a serialization point: all emitters contend on the
same lock, and each holds it for the duration of a file write + flush.

The broadcast `send()` (step 5) is lock-free and cheap. The file
write is the bottleneck.

**Suggested fix:** For v0.3, this is acceptable — the observation
log is an operational tool, not a high-frequency trading system.
For higher throughput, consider:
1. A channel-based writer: `emit()` sends to an mpsc channel, a
   background task batches and writes to disk
2. `tokio::task::spawn_blocking` for the file write
3. Memory-mapped file for zero-copy writes

### 12. [MISSING] No JSONL file rotation or size limit — LOW

**File:** `src/observe.rs:127-143`

`persist_to_file` opens the file in append mode with no rotation
strategy. A long-running proxy session (e.g., a CI pipeline with
thousands of requests) will grow the JSONL file unboundedly.

For `init --observe` (time-bounded sessions), this is fine — the
temp dir is cleaned up after policy generation. For `launch` sessions
(potentially long-running), the file grows until the session ends.

**Suggested fix:** For v0.3, document that the JSONL file is not
rotated and grows linearly. For a future release, consider:
1. A max file size with rotation (e.g., 100MB → rename to `.1`,
   start new file)
2. A max event count
3. Deletion of the JSONL file after policy generation (already
   happens for `init --observe` via temp dir cleanup)

### 13. [QUALITY] `FsAccess` and `ProcExec` event types defined but never emitted — LOW

**File:** `src/observe.rs:71-74`

The `FsAccess` and `ProcExec` variants are defined with a comment
"future — not MVP", but they're already used by `generate` and
`replay` for policy evaluation. Both modules correctly handle these
event types in their match arms, and there are tests for generating
policies from `FsAccess` and `ProcExec` events.

However, no production code path emits these events. They only
appear in test fixtures. If a user creates a JSONL file with these
events manually (or from a future version), `replay` and `generate`
handle them correctly.

**No immediate action needed** — the forward declaration is reasonable
for extensibility. The comment accurately marks them as non-MVP.

### 14. [QUALITY] `truncate` uses char count, not display width — LOW

**File:** `src/watch.rs:111-121`

`truncate()` counts `chars()` rather than Unicode display width.
Characters like CJK ideographs, emoji, and full-width characters
take 2 terminal columns but count as 1 char. A resource path
containing CJK characters (e.g., from a filename in a mount path)
would overflow the terminal width calculation.

For the current use case (HTTP hostnames and paths are ASCII), this
is not an issue. If the observation model expands to arbitrary
filesystem paths or process commands, this could cause misaligned
output.

**No immediate action needed** — ASCII-only paths are the current
reality. If display-width accuracy matters later, use the
`unicode-width` crate.

## Key Question Answers

**What happens when `strait watch` connects mid-session — does it miss
events or get a replay?**

It misses all prior events. The broadcast channel (`tokio::sync::broadcast`)
only delivers events emitted after `subscribe()` is called (Finding 6).
There is no backlog, replay buffer, or initial state snapshot. The JSONL
file contains the complete history, but the socket protocol has no
mechanism for requesting it. This is a conscious trade-off: the broadcast
channel is simple and correct for real-time streaming, but it means
`watch` is a "tail -f" tool, not a "cat" tool.

**Is the JSONL format stable enough for `generate` and `replay` to
depend on?**

The format is stable within a single binary version but has no
versioning mechanism (Finding 4). The `ObservationEvent` struct uses
`#[serde(flatten)]` on `EventKind` with `#[serde(tag = "type",
rename_all = "snake_case")]`, producing a flat JSON object with a
`type` discriminator. This is a reasonable schema, but any change to
variant names, field names, or the addition of required fields will
break deserialization of old logs with no error message beyond a
generic serde error.

The round-trip test (`event_roundtrips_through_json`) validates
current-version compatibility but doesn't test cross-version
compatibility. For `generate` and `replay` to depend on saved JSONL
files reliably, a version field or at minimum a magic comment/header
line in the JSONL file would help.

**Are observation events emitted for denied requests, or only allowed
ones?**

Yes — the MITM path emits a `NetworkRequest` event for all decisions:
allow, deny, and warn (src/mitm.rs:509-526). The `decision` field
carries the outcome. Denied requests also receive a `PolicyViolation`
event in warn mode (src/mitm.rs:405-414).

However, passthrough connections (non-MITM hosts) do NOT emit
observation events (Finding 1). They are logged by the audit logger
but invisible to the observation pipeline. This is the most
significant gap in event coverage.

**Could high event volume cause backpressure that slows the proxy
pipeline?**

The broadcast channel itself does not cause backpressure — `send()`
is non-blocking and never waits for slow consumers. Slow consumers
get `Lagged(n)` errors and skip forward (correctly handled in the
socket server, line 338-344).

The file write in `emit()` is the potential bottleneck (Finding 11).
Each `emit()` acquires a `std::sync::Mutex` and performs a blocking
`write()` + `flush()`. Under high concurrency, this serializes all
emitters through a single lock. For local filesystems, this adds
microseconds per event — negligible. For network filesystems or under
extreme fd pressure, it could block the MITM handler's tokio task.

The design is sound for the expected workload (tens to hundreds of
events per session). For high-throughput scenarios (thousands of
concurrent requests), the synchronous file write would need to move
to a background task.

## Checklist Results

- [x] **Event types** — All observable actions are covered:
  `NetworkRequest` (http), `ContainerStart/Stop` (lifecycle),
  `Mount` (filesystem binding), `FsAccess` (future), `ProcExec`
  (future), `PolicyViolation` (enforcement). **Gap:** Passthrough
  connections not emitted (Finding 1).
- [~] **Event schema** — Clean JSON structure with `type` discriminator,
  flat layout via `serde(flatten)`, consistent field naming. Missing
  version field for forward compatibility (Finding 4).
  `enforcement_mode` unused in `NetworkRequest` (Finding 7).
- [x] **Unix socket server** — Correct lifecycle: stale socket cleanup,
  bind, accept loop, per-client broadcast receiver, clean disconnect
  handling. **Gap:** Accept loop breaks on transient errors (Finding 3).
  No cleanup on process exit (Finding 9).
- [x] **Event delivery** — Broadcast channel with correct backpressure
  handling: slow consumers get `Lagged`, events are never dropped
  from the channel for fast consumers. File writes are best-effort
  with silent failure (Finding 8).
- [~] **JSONL persistence** — Append-only file with per-event flush.
  No rotation or size limit (Finding 12). BufWriter flush defeats
  buffering (Finding 5). No disk-full handling.
- [x] **Watch formatting** — Color scheme is clear and well-tested:
  green (allow), bold red (deny), yellow (warn), cyan (lifecycle),
  dim (passthrough). Terminal width respected with truncation and
  ellipsis. Layout budget calculation is correct.
- [x] **Watch connectivity** — Auto-reconnection loop with 1s delay.
  Ctrl+C graceful shutdown via `tokio::select!`. Socket discovery
  by newest mtime. **Gap:** Discovery doesn't search all candidate
  directories (Finding 2).
- [~] **Performance** — Broadcast send is lock-free. File write is
  synchronous with mutex contention (Finding 11). Per-event flush
  adds syscall overhead (Finding 5). Acceptable for current scale.
- [~] **Error handling** — Socket client disconnects handled cleanly.
  Malformed JSON lines skipped in watch. **Gaps:** Serialization
  failures silent (Finding 8). Accept errors fatal (Finding 3).
  File write errors silent (Finding 8).
