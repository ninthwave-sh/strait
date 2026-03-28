---
id: H-V4-TIMEOUT
title: Add upstream connection and response timeouts
priority: P2
effort: S
status: pending
phase: v0.4
source: ER-4.5
---

# Add upstream connection and response timeouts

## Problem

The MITM pipeline (`src/mitm.rs`) has no timeout on upstream `TcpStream::connect` or the response relay. A slow or unresponsive upstream API holds the client connection indefinitely, risking resource exhaustion under load.

## Proposed Fix

Wrap upstream operations with `tokio::time::timeout`:
- `TcpStream::connect` — 30s default (configurable via `strait.toml`)
- Response relay — 300s default (configurable)

Return 504 Gateway Timeout when timeouts fire.

## Context

Identified in ER-4 Finding 5 (MITM Pipeline review). Deferred from the ER remediation plan because connection pooling (ER-4.4) is also v0.4, and both touch the same upstream connection code path. Address together.
