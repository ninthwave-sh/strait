# Fix: Config hardening -- deny_unknown_fields + EKU + clap (M-ER-5)

**Priority:** Medium
**Source:** ER-1 Findings 1-5, 7
**Depends on:** None
**Domain:** config

Config structs silently accept unknown TOML fields (typos go unnoticed), leaf certificates are missing ExtendedKeyUsage::ServerAuth (strict TLS clients like Go's crypto/tls may reject them), and launch subcommand mode flags are validated manually instead of using clap's ArgGroup. Fix by adding #[serde(deny_unknown_fields)] to all config structs, adding ServerAuth EKU to leaf cert params in ca.rs, enforcing launch mode flags via clap ArgGroup, consolidating tracing subscriber init to one location, and extracting shared proxy startup boilerplate between run_proxy and run_observe.

**Test plan:**
- Test that a config with an unknown field (e.g., `[ploicy]` typo) returns a parse error
- Test that generated leaf certificates include ExtendedKeyUsage::ServerAuth
- Test that conflicting launch flags (--observe + --policy) produce a clap error
- Verify tracing init doesn't panic when called from any subcommand entry point

Acceptance: deny_unknown_fields on all config structs. ServerAuth EKU present in leaf certs. Launch mode flags enforced by clap. Single tracing init location.

Key files: `src/config.rs`, `src/ca.rs`, `src/main.rs`
