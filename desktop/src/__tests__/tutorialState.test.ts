import { beforeEach, describe, expect, it } from 'vitest';

import {
  markCompleted,
  markDismissed,
  readTutorialState,
  reopenTutorial,
  resetTutorial,
  writeTutorialState
} from '../tutorialState';

function buildStorage() {
  const store = new Map<string, string>();
  return {
    getItem: (key: string) => (store.has(key) ? (store.get(key) as string) : null),
    setItem: (key: string, value: string) => {
      store.set(key, value);
    },
    removeItem: (key: string) => {
      store.delete(key);
    },
    // Exposed for tests so we can assert what was persisted.
    _store: store
  };
}

describe('tutorialState', () => {
  beforeEach(() => {
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.clear();
    }
  });

  it('defaults to a fresh, uncompleted state when storage is empty', () => {
    const storage = buildStorage();
    const state = readTutorialState(storage);
    expect(state).toEqual({ dismissed: false, completedAtUnixMs: null });
  });

  it('migrates the M-ONB-1 dismissed-only boolean on first read', () => {
    const storage = buildStorage();
    storage.setItem('strait-desktop.onboarding.dismissed', 'true');
    const state = readTutorialState(storage);
    expect(state).toEqual({ dismissed: true, completedAtUnixMs: null });
  });

  it('persists dismissed via markDismissed and survives a reload', () => {
    const storage = buildStorage();
    const next = markDismissed({ dismissed: false, completedAtUnixMs: null }, storage);
    expect(next.dismissed).toBe(true);
    const reloaded = readTutorialState(storage);
    expect(reloaded.dismissed).toBe(true);
    expect(reloaded.completedAtUnixMs).toBeNull();
  });

  it('stamps completion with the provided timestamp without dismissing', () => {
    // The celebration card renders on the completed state, so completing
    // does not itself dismiss the overlay -- the "Close tour" button
    // handles that separately.
    const storage = buildStorage();
    const next = markCompleted({ dismissed: false, completedAtUnixMs: null }, 12345, storage);
    expect(next).toEqual({ dismissed: false, completedAtUnixMs: 12345 });
    const reloaded = readTutorialState(storage);
    expect(reloaded).toEqual({ dismissed: false, completedAtUnixMs: 12345 });
  });

  it('does not overwrite an existing completion timestamp on re-completion', () => {
    const storage = buildStorage();
    const first = markCompleted({ dismissed: false, completedAtUnixMs: null }, 100, storage);
    const second = markCompleted(first, 999, storage);
    expect(second.completedAtUnixMs).toBe(100);
  });

  it('reopen clears dismissed but preserves completedAtUnixMs', () => {
    const storage = buildStorage();
    writeTutorialState({ dismissed: true, completedAtUnixMs: 42 }, storage);
    const next = reopenTutorial({ dismissed: true, completedAtUnixMs: 42 }, storage);
    expect(next).toEqual({ dismissed: false, completedAtUnixMs: 42 });
    const reloaded = readTutorialState(storage);
    expect(reloaded).toEqual({ dismissed: false, completedAtUnixMs: 42 });
  });

  it('resetTutorial wipes both dismissed and completion', () => {
    const storage = buildStorage();
    writeTutorialState({ dismissed: true, completedAtUnixMs: 42 }, storage);
    const next = resetTutorial(storage);
    expect(next).toEqual({ dismissed: false, completedAtUnixMs: null });
    const reloaded = readTutorialState(storage);
    expect(reloaded).toEqual({ dismissed: false, completedAtUnixMs: null });
  });

  it('ignores malformed JSON and falls back to defaults', () => {
    const storage = buildStorage();
    storage.setItem('strait-desktop.tutorial.v1', 'not-json');
    const state = readTutorialState(storage);
    expect(state).toEqual({ dismissed: false, completedAtUnixMs: null });
  });

  it('survives a storage that throws on every call', () => {
    const throwing = {
      getItem() {
        throw new Error('nope');
      },
      setItem() {
        throw new Error('nope');
      },
      removeItem() {
        throw new Error('nope');
      }
    };
    // These calls must not propagate the storage exception into the render
    // path -- the overlay must still work when the preload sandbox refuses
    // localStorage access entirely.
    expect(() => readTutorialState(throwing)).not.toThrow();
    expect(() => writeTutorialState({ dismissed: true, completedAtUnixMs: 1 }, throwing)).not.toThrow();
    expect(() => markDismissed({ dismissed: false, completedAtUnixMs: null }, throwing)).not.toThrow();
  });
});
