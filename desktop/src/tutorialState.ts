/**
 * Persistent state for the first-run tutorial. The overlay lives in the
 * renderer, but its "have I already done this?" bit has to survive both an
 * app restart and a window reopen. We keep the storage model localStorage-
 * backed so the logic is testable in jsdom and so the renderer does not need
 * an extra round-trip through the main process just to show or hide the
 * overlay.
 *
 * Two facts are tracked:
 *
 * - `dismissed` -- the operator clicked "Skip tour" or "Close tour" in the
 *   current install. Hides the overlay. Can be reset by the "Reopen tour"
 *   button so the tutorial is resumable from wherever the shell currently
 *   thinks the operator is in the golden path.
 *
 * - `completedAtUnixMs` -- the operator actually finished the tour by
 *   persisting a rule (or dismissing the celebration card). This is the
 *   "do not re-prompt a returning user" bit required by L-ONB-3. Once this
 *   is set the overlay stays hidden across restarts, even if `dismissed` is
 *   later cleared. The reopen button stops offering the tour and only the
 *   explicit "Reset tour" affordance can bring it back.
 */

const STATE_STORAGE_KEY = 'strait-desktop.tutorial.v1';
// The M-ONB-1 onboarding stored just a dismissed boolean under this key. We
// migrate it on first read so operators who had already clicked "Skip tour"
// on the old overlay do not see the tutorial reappear on upgrade.
const LEGACY_DISMISSED_KEY = 'strait-desktop.onboarding.dismissed';

export interface TutorialState {
  dismissed: boolean;
  /**
   * Unix milliseconds at which the operator finished the tour. `null` means
   * the tour is still outstanding -- either they have not started it, or
   * they skipped partway through without persisting a rule.
   */
  completedAtUnixMs: number | null;
}

export const DEFAULT_TUTORIAL_STATE: TutorialState = {
  dismissed: false,
  completedAtUnixMs: null
};

type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>;

function resolveStorage(explicit?: StorageLike | null): StorageLike | null {
  if (explicit === null) {
    return null;
  }
  if (explicit) {
    return explicit;
  }
  if (typeof window === 'undefined') {
    return null;
  }
  try {
    return window.localStorage ?? null;
  } catch {
    // Some preload sandboxes throw on property access instead of returning
    // `undefined`. Treat that as "no storage" rather than letting the
    // exception escape into a React render path.
    return null;
  }
}

function safeGet(storage: StorageLike | null, key: string): string | null {
  if (!storage) {
    return null;
  }
  try {
    return storage.getItem(key);
  } catch {
    return null;
  }
}

function safeSet(storage: StorageLike | null, key: string, value: string) {
  if (!storage) {
    return;
  }
  try {
    storage.setItem(key, value);
  } catch {
    // Quota or permission errors here are non-fatal; the tutorial just
    // reappears on the next launch, which is annoying but not incorrect.
  }
}

function safeRemove(storage: StorageLike | null, key: string) {
  if (!storage) {
    return;
  }
  try {
    storage.removeItem(key);
  } catch {
    // See safeSet.
  }
}

function parseState(raw: string | null): TutorialState | null {
  if (!raw) {
    return null;
  }
  try {
    const parsed = JSON.parse(raw) as Partial<TutorialState> | null;
    if (!parsed || typeof parsed !== 'object') {
      return null;
    }
    const dismissed = parsed.dismissed === true;
    const completedAtUnixMs =
      typeof parsed.completedAtUnixMs === 'number' && Number.isFinite(parsed.completedAtUnixMs)
        ? parsed.completedAtUnixMs
        : null;
    return { dismissed, completedAtUnixMs };
  } catch {
    return null;
  }
}

export function readTutorialState(storage?: StorageLike | null): TutorialState {
  const resolved = resolveStorage(storage);
  const parsed = parseState(safeGet(resolved, STATE_STORAGE_KEY));
  if (parsed) {
    return parsed;
  }
  // Migrate from the M-ONB-1 `dismissed`-only boolean. We keep the legacy
  // key intact until the next write so a downgrade still finds it.
  const legacy = safeGet(resolved, LEGACY_DISMISSED_KEY);
  if (legacy === 'true') {
    return { dismissed: true, completedAtUnixMs: null };
  }
  return { ...DEFAULT_TUTORIAL_STATE };
}

export function writeTutorialState(state: TutorialState, storage?: StorageLike | null) {
  const resolved = resolveStorage(storage);
  safeSet(resolved, STATE_STORAGE_KEY, JSON.stringify(state));
  // Keep the legacy key in sync so a same-install downgrade still hides the
  // overlay for operators who completed or skipped the new tour. Clearing
  // it when `dismissed` is false avoids a ghost-dismiss after "Reopen tour".
  if (state.dismissed) {
    safeSet(resolved, LEGACY_DISMISSED_KEY, 'true');
  } else {
    safeRemove(resolved, LEGACY_DISMISSED_KEY);
  }
}

export function markDismissed(
  current: TutorialState,
  storage?: StorageLike | null
): TutorialState {
  const next: TutorialState = { ...current, dismissed: true };
  writeTutorialState(next, storage);
  return next;
}

export function markCompleted(
  current: TutorialState,
  nowUnixMs: number,
  storage?: StorageLike | null
): TutorialState {
  // Completing the tour means the operator reached the finish line of the
  // golden path. We stamp `completedAtUnixMs` but leave `dismissed`
  // untouched so the celebration card gets a chance to render. The
  // explicit "Close tour" click is what hides the overlay.
  const next: TutorialState = {
    ...current,
    completedAtUnixMs: current.completedAtUnixMs ?? nowUnixMs
  };
  writeTutorialState(next, storage);
  return next;
}

export function reopenTutorial(
  current: TutorialState,
  storage?: StorageLike | null
): TutorialState {
  // Reopen clears the dismissed flag but preserves `completedAtUnixMs` so
  // reviewers/operators who finished the tour can peek at it without having
  // the shell treat them as a fresh install on every boot.
  const next: TutorialState = { ...current, dismissed: false };
  writeTutorialState(next, storage);
  return next;
}

export function resetTutorial(storage?: StorageLike | null): TutorialState {
  const next: TutorialState = { ...DEFAULT_TUTORIAL_STATE };
  writeTutorialState(next, storage);
  return next;
}
