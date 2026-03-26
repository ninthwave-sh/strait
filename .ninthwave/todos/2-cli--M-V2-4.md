# Feat: `strait init --observe` traffic observation mode (M-V2-4)

**Priority:** Medium
**Source:** v0.2 roadmap — zero-friction onboarding, auto-generate starter Cedar policy
**Depends on:** None
**Domain:** cli

Add `strait init --observe <duration>` subcommand. When run, strait starts in observation mode: it acts as a transparent proxy (no policy enforcement, credentials injected), records all MITM'd requests to an in-memory log, then after `<duration>` (e.g. `5m`, `30s`) prints a generated `.cedar` policy and `.cedarschema` file to stdout (or writes them to `--output-dir`).

The generated policy is permissive-by-default: one `permit` statement per unique `(method, path_prefix)` pair observed. Path segments that look like IDs (UUIDs, numeric, SHA-like) are collapsed to wildcards. The output is annotated with request counts as comments so users understand what they're allowing.

**Example output:**
```cedar
// Observed 42 GET /repos/* requests
permit(principal, action == Action::"GET", resource in Resource::"api.github.com/repos");

// Observed 3 POST /repos/*/pulls requests
permit(principal, action == Action::"POST", resource in Resource::"api.github.com/repos")
  when { context.path like "*/pulls" };
```

**Config shape (CLI only, not toml):**
```
strait init --observe 5m --output-dir ./policies
```

**Test plan:**
- Observation mode: requests are logged, no policy enforcement applied
- Path normalization: `/repos/my-org/my-repo/pulls/42` → `repos/*/pulls/*`
- Policy generation: correct permit statements for observed method+path pairs
- Duration parsing: `5m`, `30s`, `1h` all parse correctly; invalid input → clear error
- `--output-dir` writes `.cedar` and `.cedarschema` files; stdout mode prints both

Acceptance: `cargo test --all-features` passes. `cargo clippy` clean. Integration test runs observation mode with a loopback echo server, verifies generated policy covers observed requests.

Key files: `src/main.rs` (new subcommand), `src/observe.rs` (NEW — observation log + policy generation)
