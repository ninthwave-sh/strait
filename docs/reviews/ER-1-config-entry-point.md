# ER-1: Config & Entry Point Review

**Date:** 2026-03-27
**Modules:** src/config.rs, src/ca.rs, src/main.rs, src/lib.rs

## Summary

These modules are well-structured and production-ready. Config parsing is
centralized in `strait.toml` with clear TOML types, sensible defaults, and
thorough validation for the `[policy]` section's mutual-exclusivity
constraints. The session CA is properly scoped to memory with no private key
written to disk. The main entry point cleanly routes subcommands and handles
startup errors. Test coverage is excellent (1000+ lines of unit and
integration tests in `config.rs` alone). The most actionable findings are:
missing `#[serde(deny_unknown_fields)]` (silent typos), missing
`ExtendedKeyUsage::ServerAuth` on leaf certs (client compat), and the
`launch` subcommand's mode-flag enforcement being manual rather than via
clap's argument groups.

## Findings

### 1. [QUALITY] Config structs accept unknown TOML fields silently — MEDIUM

**File:** `src/config.rs:28-56`

None of the config structs (`StraitConfig`, `ListenConfig`, `MitmConfig`,
`PolicyConfig`, `CredentialEntryConfig`, etc.) use
`#[serde(deny_unknown_fields)]`. A user who writes `polling_interval = 30`
instead of `poll_interval_secs = 30` gets no error — the typo is silently
ignored and the default (60s) is used. This is the most common source of
"it's not working and I don't know why" config bugs.

**Suggested fix:** Add `#[serde(deny_unknown_fields)]` to all top-level and
section config structs. This is a breaking change for anyone with extraneous
fields, but acceptable pre-v1.

### 2. [DESIGN] Leaf certs missing ExtendedKeyUsage::ServerAuth — MEDIUM

**File:** `src/ca.rs:88-101`

Leaf certificates are issued without `ExtendedKeyUsage` extensions. While
many TLS clients (including rustls and OpenSSL in default mode) don't
strictly require EKU, some clients enforce it:

- Go's `crypto/tls` rejects server certs missing `ServerAuth` EKU by default
- Some corporate proxy scanners check for it
- RFC 5280 recommends it for TLS server certificates

The CA cert correctly sets `KeyUsagePurpose::KeyCertSign + CrlSign`, but
leaf certs should also include `ExtKeyUsagePurpose::ServerAuth`.

**Suggested fix:** Add to the leaf cert params:
```rust
params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
```

### 3. [QUALITY] Launch subcommand mode flag not enforced by clap — MEDIUM

**File:** `src/main.rs:141-173, 278-285`

The `Launch` command has `--observe`, `--warn`, and `--policy` as optional
flags with `conflicts_with_all` for mutual exclusivity, but none is required.
When no mode is specified, the code falls through to a manual
`eprintln!()` + `process::exit(1)` at line 278. This bypasses clap's
standard error formatting (colored output, help suggestion, exit code 2).

**Suggested fix:** Use a clap argument group:
```rust
#[command(group(ArgGroup::new("mode").required(true).args(["observe", "warn", "policy"])))]
```

### 4. [QUALITY] Tracing subscriber initialized in three places — LOW

**File:** `src/main.rs:248, 302, 384`

`tracing_subscriber::fmt().json().init()` is called separately in
`run_proxy()`, the `Launch` match arm, and `run_observe()`. While these are
mutually exclusive codepaths (only one subcommand runs), this is fragile.
If a second `init()` were ever reached it would panic at runtime.

**Suggested fix:** Move tracing init to the top of `main()`, before the
subcommand match, for all subcommands that need it. Subcommands that don't
need tracing (like `generate`, `template`, `test`) would just ignore it.

### 5. [QUALITY] Duplicate boilerplate between `run_proxy` and `run_observe` — LOW

**File:** `src/main.rs:301-365, 375-499`

Both functions repeat nearly identical setup:
- tracing init
- config load
- CA cert write to disk
- listen address parsing
- TCP listener bind
- `PORT=` stderr print
- accept loop with `handle_connection`

Extracting shared setup into a helper (returning a tuple of `TcpListener`,
`Arc<ProxyContext>`, loaded config) would eliminate ~40 lines of duplication
and ensure both paths stay in sync.

### 6. [MISSING] No validation hook on `StraitConfig::load()` — LOW

**File:** `src/config.rs:264-273`

`StraitConfig::load()` parses TOML and returns the struct, but doesn't run
any cross-field validation. `PolicyConfig::validate()` is only called later
in `ProxyContext::from_config()`. Credential validation (host/host_pattern
mutual exclusivity, source type) also happens lazily in
`CredentialStore::from_entries()`.

This means invalid configs aren't caught until `ProxyContext::from_config()`,
which also does side effects (CA generation, git clone, env-var reads). A
`StraitConfig::validate()` method called from `load()` would fail earlier
and give clearer errors separated from runtime setup.

### 7. [QUALITY] CA cert re-parsed from DER on every leaf cache miss — LOW

**File:** `src/ca.rs:98-99`

On every leaf cert cache miss, `CertificateParams::from_ca_cert_der()` is
called to re-parse the CA cert from its DER bytes. This is because rcgen's
`Certificate` type can't be stored across calls. The overhead is negligible
(DER parsing is fast, and caching minimizes miss frequency), but it's worth
noting as an optimization opportunity if leaf cert issuance becomes a
bottleneck.

### 8. [QUALITY] Leaf cert cache unbounded with no proactive eviction — LOW

**File:** `src/ca.rs:37, 113-120`

The `leaf_cache` HashMap grows without limit. Expired entries are only
replaced when the same hostname is requested again — there's no background
sweep. For the intended use case (a handful of MITM hosts), this is fine.
If strait ever proxies traffic to many distinct hostnames, a bounded LRU
cache would be more appropriate.

### 9. [QUALITY] `ca_cert_path` written without parent directory check — LOW

**File:** `src/main.rs:316, 411`

`std::fs::write(&config.ca_cert_path, ...)` will fail with an unhelpful
`No such file or directory` error if the parent directory doesn't exist.
Wrapping with `.with_context(|| format!("failed to write CA cert to {}", ...)))`
or pre-creating the parent directory would improve the operator experience.

### 10. [SECURITY] Config file `source` field is stringly typed — LOW

**File:** `src/config.rs:198`

`CredentialEntryConfig.source` is a `String` rather than an enum. Invalid
values like `source = "file"` are only caught at runtime during credential
resolution (in `credentials.rs`), not at config parse time. Using a
`#[serde(rename_all = "kebab-case")]` enum would catch invalid source types
during TOML deserialization.

Same applies to `credential_type` (line 202) — it's a String with a
default function, but could be an enum with `Bearer` and `AwsSigv4`
variants.

### 11. [QUALITY] `rcgen::KeyPair::generate()` uses implicit default algorithm — LOW

**File:** `src/ca.rs:43, 88`

`KeyPair::generate()` uses rcgen's default key algorithm (currently ECDSA
P-256 in rcgen 0.13). This is a good choice for MITM proxy certs (fast,
widely supported), but the choice is implicit. If rcgen changes its default
in a future version, the key algorithm would silently change.

Consider documenting this choice in the module doc or making it explicit:
```rust
let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)?;
```

### 12. [QUALITY] `lib.rs` exports all modules as `pub` — LOW

**File:** `src/lib.rs:7-21`

All 15 modules are `pub`. For a binary crate this is typical (integration
tests need access), but some modules are internal implementation details
(e.g., `sigv4`, `container`, `observe`). Using `pub(crate)` for
internal-only modules would clarify the API boundary, though it would
require restructuring integration tests.

No action needed now — this is a future API-hygiene concern.

## Key Question Answers

**Is the config schema documented anywhere besides code?**

Yes. The example config at `examples/strait.toml` serves as living
documentation with inline comments explaining every field. The Rust doc
comments on config structs are thorough. There is no standalone schema
specification (e.g., JSON Schema or man page), but the example file is
sufficient for the current user base.

**Are there config combinations that silently produce wrong behavior?**

1. **Typos in field names** — the most dangerous silent failure. Without
   `deny_unknown_fields`, `pollinterval_secs = 30` is silently ignored.
   (See Finding 1.)

2. **Credentials without MITM hosts** — configuring `[[credential]]`
   entries but leaving `mitm.hosts` empty means credentials are resolved at
   startup but never injected (all traffic goes through passthrough mode).
   No error is emitted. This could be caught with a startup warning.

3. **`[policy]` without `mitm.hosts`** — same pattern. Policy is loaded
   but never evaluated because no traffic is MITM'd. A warning would help.

**Does the CA cert meet browser/client requirements?**

The CA cert itself is well-formed:
- `BasicConstraints::Ca(Unconstrained)` ✓
- `KeyUsage: KeyCertSign, CrlSign` ✓
- 24-hour validity with 5-minute clock-skew backdate ✓
- Unique per-session key pair ✓
- Private key never written to disk ✓

Leaf certs are mostly correct but **lack `ExtendedKeyUsage::ServerAuth`**
(Finding 2). This may cause compatibility issues with strict TLS clients
(notably Go). The SAN (Subject Alternative Name) is correctly set from the
hostname. Leaf validity (24h) and backdate (5min) match the CA.

## Checklist Results

- [x] **Config parsing correctness** — TOML deserialization works correctly.
  Defaults are well-defined. Required field (`ca_cert_path`) is enforced
  by serde. Optional sections degrade gracefully.
- [x] **Config error messages** — Invalid TOML produces contextual errors
  with file path. Policy mutual-exclusivity violations have clear messages.
  **Note:** Unknown fields are silently ignored (Finding 1).
- [x] **CA cert generation** — Key size appropriate (ECDSA P-256 via rcgen
  default). 24-hour validity with 5-min backdate. Extensions correct for a
  CA cert.
- [x] **CA cert lifecycle** — Session-local, memory-only private key, PEM
  exported for client trust injection. No cleanup needed (overwritten on
  next startup). Well-scoped.
- [x] **CLI argument parsing** — Clap definitions are correct. Subcommands
  are well-documented with `after_help`. **Note:** Launch mode flags lack
  a required group (Finding 3).
- [x] **Entry point error handling** — Startup failures propagate via
  `anyhow::Result`. Tracing is initialized before config load for proxy
  paths. Git clone failures, missing env vars, and policy parse errors all
  surface with context.
- [~] **Code quality** — Good overall. Key concerns: duplicate boilerplate
  (Finding 5), stringly-typed config fields (Finding 10), tracing init in
  three places (Finding 4). No dead code found.
- [x] **Security** — CA private key stays in memory. Credential secrets are
  resolved eagerly (env vars read once at startup, not on every request).
  `BearerCredential::Debug` redacts the secret. No path traversal risk
  since config is operator-controlled. No secret logging.
