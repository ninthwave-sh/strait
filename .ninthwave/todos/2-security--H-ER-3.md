# Fix: Container bind-mount path validation (H-ER-3)

**Priority:** High
**Source:** ER-7 Finding 2
**Depends on:** None
**Domain:** security

Bind-mount paths from Cedar policy are used verbatim in Docker container configuration. A path like /project/../../etc/shadow could mount unintended host directories. Fix by validating paths before passing to bollard: try std::fs::canonicalize first (resolves symlinks), fall back to textual validation (reject ".." components, reject paths outside the expected base directory) when the path doesn't exist yet. Emit warn!() when a path is rejected.

**Test plan:**
- Test that a path containing ../../../etc/shadow is rejected
- Test that a symlink pointing outside the base directory is rejected (when path exists)
- Test that a non-existent path with clean components passes textual validation
- Test that a valid path inside the base directory is accepted after canonicalization

Acceptance: All bind-mount paths validated before Docker API call. Traversal attempts rejected with clear error message. Non-existent paths validated textually.

Key files: `src/container.rs`
