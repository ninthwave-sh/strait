# Feature: CI musl cross-compilation for gateway (H-NI-4)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-1
**Domain:** network-isolation

Add musl targets to the CI build matrix for the gateway binary. The gateway
must be a static Linux binary so it runs in any container image regardless
of the base distro's libc. Build for both x86_64-unknown-linux-musl and
aarch64-unknown-linux-musl.

Only the gateway crate needs musl builds -- the main `strait` binary continues
to use glibc targets (it runs on the host, not in containers).

**Test plan:**
- CI workflow runs successfully on push, producing 4 gateway artifacts (x86_64-musl, aarch64-musl for Linux)
- Verify the produced binaries are statically linked (`file` or `ldd` check in CI)
- Manual review: download artifacts and confirm they run in alpine and debian containers

Acceptance: CI uploads `strait-gateway` static musl binaries for x86_64 and
aarch64 Linux alongside existing host binaries.

Key files: `.github/workflows/ci.yml`
