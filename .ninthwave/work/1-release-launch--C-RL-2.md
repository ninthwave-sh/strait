# Feature: Add --config flag to strait launch (C-RL-2)

**Priority:** Critical
**Source:** v0.1.0 release -- credential injection in container mode
**Depends on:** None
**Domain:** release-launch

Add an optional `--config <FILE>` argument to `strait launch` that loads a
`strait.toml` configuration file. When present, the launch proxy context uses
the config's credential store and MITM host list instead of the current
hardcoded defaults (`credential_store: None`, `mitm_hosts: Vec::new()`).

This enables credential injection in container mode -- the agent never sees
the real API key because strait injects it at the proxy layer on allowed
requests only.

Changes:

1. `src/main.rs` -- Add `#[arg(short, long, value_name = "FILE")]` field
   `config: Option<PathBuf>` to the `Launch` variant. When present, parse
   via `StraitConfig::load()` and pass the credential store and MITM hosts
   to the launch functions.

2. `src/launch.rs` -- Modify `build_launch_proxy_context()` to accept
   optional `credential_store: Option<Arc<CredentialStore>>` and
   `mitm_hosts: Vec<String>` parameters. When credential_store is Some,
   use it instead of None. When mitm_hosts is non-empty, use it (but keep
   `mitm_all` as true when mitm_hosts is empty, matching current behavior).
   Update both `run_launch_observe()` and `run_launch_with_policy()` to
   accept and thread through the config-derived values.

3. Reference `ProxyContext::from_config()` in `src/config.rs` (around line
   430) for the pattern of building credential_store from config entries.

**Test plan:**
- Unit test: CLI parsing accepts `--config strait.toml` alongside `--observe`/`--warn`/`--policy`
- Unit test: `build_launch_proxy_context` with a credential store produces a ProxyContext where `credential_store.is_some()`
- Unit test: `build_launch_proxy_context` with MITM hosts populates the hosts list
- Unit test: `build_launch_proxy_context` without config preserves current behavior (credential_store: None, mitm_all: true)

Acceptance: `strait launch --policy p.cedar --config strait.toml --image alpine:latest -- echo ok`
uses credential injection from the config. Existing tests still pass.

Key files: `src/main.rs`, `src/launch.rs`, `src/config.rs`
