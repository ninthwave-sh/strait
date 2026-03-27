# Test: Round-trip E2E integration test (H-CP-11)

**Priority:** High
**Source:** v0.3 container platform plan (eng review: shipping gate)
**Depends on:** H-CP-7b, H-CP-8, M-CP-9
**Domain:** test

Implement the round-trip E2E integration test that is the v0.3 shipping gate. This test proves the entire observe-then-enforce lifecycle works end-to-end:

1. `strait launch --observe ./test-agent` -- test agent makes a GET request to a loopback echo server and reads a file
2. Verify observation JSONL contains both network and mount events
3. `strait generate observations.jsonl` -- produces a Cedar policy
4. `strait test --replay observations.jsonl --policy generated.cedar` -- all events match (exit 0)
5. `strait launch --policy generated.cedar ./test-agent` -- same agent succeeds under enforcement
6. Verify: a DIFFERENT agent command (one that tries to write to a read-only mount or hit a different API) is denied

The test agent is a simple shell script that makes one curl request and reads one file. It runs inside a Docker container in CI.

**Test plan:**
- E2E test: full observe -> generate -> replay -> enforce round-trip
- E2E test: enforce mode denies actions not in the generated policy
- Edge case: test agent with no network activity (filesystem only)
- Edge case: test agent with no filesystem activity (network only)
- CI requirement: Docker-in-Docker or Podman available in GitHub Actions runner

Acceptance: This test passes in CI and blocks v0.3 release if it fails. The round-trip proves observe/generate/enforce are consistent.

Key files: `tests/integration.rs` (extend), `tests/fixtures/` (test agent script, test cedar policies)
