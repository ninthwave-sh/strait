# Refactor: Remove fs/proc domains from Cedar schema and mount pipeline (H-DC-2)

**Priority:** High
**Source:** Devcontainer strategy doc (`docs/designs/devcontainer-strategy.md`), decision 4
**Depends on:** None
**Domain:** cedar-schema-narrowing
**Lineage:** 294d1835-7f92-4d81-a2ee-051c182c0a03
**Requires manual review:** true

Drop `fs:read`, `fs:write`, and `proc:exec` actions from the Cedar entity schema in `src/policy.rs`. Delete the Cedar-derived mount pipeline in `src/container.rs` that turns `fs:` rules into bind mounts; the container retains its working-directory mount but no longer walks Cedar policy for additional mounts. Reject policies that reference fs/proc actions at load time with a clear error pointing to the strategy doc. No deprecation warnings, no migration tool: pre-v1, pre-users, clean cut.

**Test plan:**
- Update `src/policy.rs` tests to cover the narrowed entity schema (only `http:` actions present)
- Add a negative test that loading a policy with `fs:read` or `proc:exec` fails with an actionable error message
- Update `tests/integration.rs` and `tests/launch_integration.rs` to drop fs/proc assertions; verify http-only flow still passes end-to-end
- Verify the container still mounts the workspace directory correctly without the Cedar-derived mount pipeline

Acceptance: `cargo test --all-features` and `cargo clippy --all-features -- -D warnings` pass. `src/policy.rs` entity schema contains only `http:` actions. Loading a Cedar policy with `fs:` or `proc:` actions fails with an error that names the removed domains. Container launch succeeds with a policy that contains only `http:` rules. No references to `fs:` or `proc:` actions remain in `src/policy.rs` or `src/container.rs`.

Key files: `src/policy.rs`, `src/container.rs`, `tests/integration.rs`, `tests/launch_integration.rs`
