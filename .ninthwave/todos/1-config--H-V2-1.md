# Feat: Git-hosted Cedar policies (H-V2-1)

**Priority:** High
**Source:** v0.2 roadmap — git-hosted policies
**Depends on:** None
**Domain:** config

Add `[policy].git_url` support to `strait.toml`. At startup, if `git_url` is set, strait clones the repo to a temp directory and loads the `.cedar` and `.cedarschema` files from it (path configurable via `[policy].git_path`, defaulting to the repo root). Add `[policy].poll_interval_secs` (default 60): a background task polls `git fetch` + `git reset --hard origin/HEAD` on that interval and hot-reloads the policy on change. Hot-reload must be atomic — use `ArcSwap<PolicyEngine>` in `ProxyContext` so in-flight requests see the old policy until the swap completes.

**Config shape:**
```toml
[policy]
git_url = "https://github.com/our-org/strait-policies.git"
git_path = "policies/github.cedar"      # relative to repo root
schema = "policies/github.cedarschema"  # optional, also relative to repo root
poll_interval_secs = 60
```

`file` and `git_url` are mutually exclusive — fail fast at startup if both are set. If only `file` is set, behavior is unchanged from v0.1 (no polling, no hot-reload).

**Test plan:**
- Config parsing: `git_url` sets git mode; `file` sets file mode; both set → startup error
- Git clone: correct path resolved, policy loaded from cloned repo
- Poll task: detects upstream change, swaps policy atomically
- In-flight requests: requests mid-flight at swap time see consistent policy (old or new, never partial)
- Schema validation applies to git-loaded policies just as file-loaded

Acceptance: `cargo test --all-features` passes. `cargo clippy` clean. A local bare git repo in integration tests simulates the git_url source — no external network access. `ArcSwap<PolicyEngine>` confirmed in `ProxyContext`.

Key files: `src/config.rs`, `src/policy.rs`, `src/main.rs` (background poll task), `Cargo.toml` (add `arc-swap`, `git2` or shell out to `git`)
