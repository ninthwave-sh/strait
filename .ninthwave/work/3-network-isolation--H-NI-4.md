# Feature: CI musl cross-compilation for gateway (H-NI-4)

**Priority:** High
**Source:** v0.4 network isolation investigation
**Depends on:** C-NI-1
**Domain:** network-isolation
**Lineage:** 46e8aa6a-d338-4d6d-bb1f-daa908d73a84

Extend CI so the new gateway crate ships as static Linux musl artifacts for both `x86_64` and `aarch64`. Only the gateway needs musl outputs; the host `strait` binary should keep its current host-target build matrix.

**Test plan:**
- Update `.github/workflows/ci.yml` to build gateway musl targets for both Linux architectures.
- Verify CI uploads distinct `strait-gateway` artifacts and checks they are statically linked.
- Manually review the workflow matrix to ensure existing `strait` host builds remain intact.

Acceptance: CI produces static musl `strait-gateway` artifacts for `x86_64` and `aarch64` Linux without regressing the existing `strait` release builds.

Key files: `.github/workflows/ci.yml`
