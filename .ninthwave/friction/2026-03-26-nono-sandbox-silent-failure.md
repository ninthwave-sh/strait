# Friction: nono sandbox causes silent worker failure

**Date:** 2026-03-26
**Severity:** high
**Component:** orchestrator / worker launch / sandbox

## What happened

Workers launched via `nono run` appeared to start successfully — the orchestrator transitioned them from `launching` → `implementing`. But in reality, the nono sandbox command dropped the worker into a shell prompt without actually running the `claude` session. The worker was stuck at a terminal prompt doing nothing.

## Why it's friction

1. **Silent failure:** The orchestrator's health detection did not catch that the workers were idle. It reported them as "implementing" when they were actually dead.
2. **No sandbox profile:** `nw doctor` warned "No sandbox profile — run `nw setup` to create one", but the orchestrator still attempted to use nono without a profile, resulting in a broken launch.
3. **Workaround required:** Had to stop the orchestrator, clean up, and relaunch with `--no-sandbox`.

## Expected behavior

- If no sandbox profile exists and nono fails to launch the worker properly, the orchestrator should detect the failure (e.g., no commits after N minutes, no tool calls, process exited) and either:
  - Retry without sandbox automatically
  - Transition the item to `stuck` with a clear error
- `nw doctor` warning about missing sandbox profile should be promoted to a blocking check when `--no-sandbox` is not set.

## Actual workaround

```bash
ninthwave orchestrate --no-sandbox --items ...
```
