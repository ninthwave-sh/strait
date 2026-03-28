# Docs: Container network enforcement documentation + observe warning (M-ER-11)

**Priority:** Medium
**Source:** ER-7 Findings 1, 7
**Depends on:** H-ER-1, H-ER-2, H-ER-3, H-ER-4, M-ER-5, M-ER-6, H-ER-7, M-ER-8, M-ER-9, M-ER-10
**Domain:** container

Container processes can bypass the proxy via direct IP access since HTTPS_PROXY is advisory only. Observe mode grants full cwd write access without warning. For v0.3, the pragmatic fix is to document the cooperative enforcement assumption clearly and add a stderr warning when observe mode mounts cwd as read-write. Design --internal network enforcement for v0.4 (Docker user-defined bridge with no default route + explicit proxy route).

**Test plan:**
- Test that observe mode emits a warning about cwd being mounted read-write
- Manual review of documentation for clarity on cooperative enforcement assumption

Acceptance: Observe mode warns about cwd write access. Documentation clearly states HTTPS_PROXY is cooperative, not enforced at network level. v0.4 network enforcement design noted.

Key files: `src/container.rs`, `src/launch.rs`
