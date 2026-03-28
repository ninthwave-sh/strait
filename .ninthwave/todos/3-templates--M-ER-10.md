# Fix: Templates and test infrastructure (M-ER-10)

**Priority:** Medium
**Source:** ER-8 Findings 1-3, 8
**Depends on:** H-ER-7
**Domain:** templates

GitHub and AWS Cedar schemas are incompatible (GitHub lacks aws_service/aws_region context attributes), there are no templates for container/filesystem use cases, templates are only tested for syntax validity (not behavioral correctness), and test helpers in integration.rs duplicate ~700 lines of production MITM logic. Fix by creating a unified .cedarschema with optional AWS attributes, adding a container-oriented template demonstrating fs:read + fs:write + http:* together, adding behavioral tests that evaluate template policies against concrete requests, and refactoring test helpers to import from production code where possible.

**Test plan:**
- Test that the unified schema validates policies combining GitHub and AWS actions
- Test that the container template policy correctly permits fs:read and denies fs:write on read-only paths
- Test that template policies evaluated against concrete requests produce expected allow/deny decisions
- Verify test helper line count reduction after refactoring (target: <200 lines of duplication)

Acceptance: Unified schema works for all templates. Container template added. Behavioral tests pass. Test helper duplication reduced.

Key files: `src/templates.rs`, `tests/integration.rs`, `templates/`
