# Fix: Container lifecycle -- SIGTERM + auto-pull + cleanup (M-ER-12)

**Priority:** Medium
**Source:** ER-7 Findings 3, 5, 6, 8
**Depends on:** H-ER-1, H-ER-2, H-ER-3, H-ER-4, M-ER-5, M-ER-6, H-ER-7, M-ER-8, M-ER-9, M-ER-10
**Domain:** container

Container cleanup uses tokio::spawn which may fail during runtime shutdown, leaving orphaned containers. Only SIGINT (ctrl_c) is handled, not SIGTERM from process managers. No automatic image pull means first-time users hit an error if the image isn't local. Fix by adding a synchronous cleanup fallback alongside the async path, handling SIGTERM alongside SIGINT, and attempting docker pull when the image is not found locally. Document the extract_fs_permissions limitation (only checks caller-supplied paths).

**Test plan:**
- Test that container cleanup succeeds during runtime shutdown (synchronous fallback)
- Test that SIGTERM triggers graceful container shutdown (same as SIGINT behavior)
- Test that a missing image triggers an automatic pull attempt
- Verify extract_fs_permissions limitation is documented

Acceptance: Containers cleaned up on SIGTERM. Missing images auto-pulled. No orphaned containers on shutdown.

Key files: `src/container.rs`, `src/launch.rs`
