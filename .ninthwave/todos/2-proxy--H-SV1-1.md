# Feat: ProxyContext struct + unified TOML config (H-SV1-1)

**Priority:** High
**Source:** Strait v0.1 design — Approach B, eng review decision
**Depends on:** None
**Domain:** proxy

Replace the scattered CLI flags and `credentials.rs` TOML parsing with a unified `config.rs` module that parses `strait.toml`. Introduce a `ProxyContext` struct that bundles all shared state (session CA, policy engine, credential store, audit logger, identity config, MITM host list) into a single struct passed to `handle_connection` and `handle_mitm`, replacing the current 8+ positional parameters.

The config module owns all file parsing. `credentials.rs` keeps only the runtime types (`CredentialStore`, `ResolvedCredential`) and the `resolve_entry` logic. `main.rs` is refactored to load config, build `ProxyContext`, and pass it through the accept loop. The old CLI struct is replaced with a new one that has `--config <path>` as the primary flag. `ca_cert_path` becomes required in config (remove stdout fallback).

**Test plan:**
- Unit test config loading: valid config with all sections, missing file → error, invalid TOML → error, empty `[mitm].hosts` → valid passthrough mode, missing optional sections → defaults applied
- Unit test `ProxyContext` construction from config
- Unit test that `ca_cert_path` is required — missing it produces a clear error
- Verify existing integration tests still pass with the refactored `handle_connection` signature

Acceptance: `strait --config strait.toml` starts the proxy. All settings (listen, mitm hosts, policy, credentials, audit, identity, health) are loaded from the TOML file. `ProxyContext` bundles all shared state. The `#[allow(clippy::too_many_arguments)]` annotation is removed from `handle_mitm`. Old CLI flags (`--port`, `--policy`, `--credentials`, `--audit-log`, `--ca-cert-path`) are removed (breaking change, pre-v1).

Key files: `src/config.rs` (new), `src/main.rs`, `src/credentials.rs`, `src/mitm.rs`
