# Feat: Policy generation from observations (H-CP-8)

**Priority:** High
**Source:** v0.3 container platform plan
**Depends on:** H-CP-3
**Domain:** generate

Implement `strait generate <observations.jsonl>` that reads an observation log and produces a Cedar policy file + Cedar schema file covering all observed activity.

Generation algorithm:
1. Read all events from JSONL
2. Group by action namespace (http, fs, proc)
3. For each group, collect unique (action, resource) pairs
4. Collapse path segments matching known ID patterns to wildcards:
   - UUID v4 (8-4-4-4-12 hex) -> `*`
   - Pure numeric > 3 digits -> `*`
   - 40-char hex (SHA) -> `*`
5. Generate `permit()` statements for each unique (action, resource pattern)
6. Annotate each wildcard with a comment showing the original observed value
7. Print warning count: "N path segments collapsed to wildcards -- review carefully"
8. Write `.cedar` policy file and `.cedarschema` file

**Test plan:**
- Unit test: single HTTP GET observation produces `permit(principal, action == Action::"http:GET", resource in Resource::"net::host/path")`
- Unit test: filesystem read observation produces `permit(principal, action == Action::"fs:read", resource in Resource::"fs::/path")`
- Unit test: UUID path segment collapsed to wildcard with original value in comment
- Unit test: non-UUID path segment preserved (no false wildcard)
- Unit test: empty observation file produces warning and no output
- Unit test: generated policy + schema pass Cedar validation
- Unit test: duplicate observations produce single permit (deduplication)

Acceptance: `strait generate observations.jsonl` produces a valid Cedar policy + schema. Wildcard collapsing works for UUIDs and SHA hashes. Output includes annotation comments.

Key files: `src/generate.rs` (NEW)
