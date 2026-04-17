import { describe, expect, it, vi } from 'vitest';

// The tray module imports runtime symbols from 'electron'. Stub them so we
// can exercise the pure template builder and count helper from a plain
// Node vitest environment -- no Electron main process required.
vi.mock('electron', () => {
  class FakeTray {
    constructor(_image: unknown) {}
    setImage(_image: unknown) {}
    setToolTip(_value: string) {}
    setContextMenu(_menu: unknown) {}
  }
  return {
    Menu: {
      buildFromTemplate: (template: unknown) => template
    },
    Tray: FakeTray,
    nativeImage: {
      createFromDataURL: (value: string) => value
    }
  };
});

import {
  buildTrayMenuTemplate,
  buildTrayTooltip,
  deriveSessionCounts,
  type TrayActions
} from '../../electron/tray';
import { buildBlockedRequest, buildSession, buildSnapshot } from '../fixtures';

function makeActions(overrides: Partial<TrayActions> = {}): TrayActions {
  return {
    showWindow: vi.fn(),
    focusSession: vi.fn(),
    setEnabled: vi.fn(),
    quit: vi.fn(),
    getMostRecentPending: () => null,
    ...overrides
  };
}

describe('tray helpers', () => {
  it('aggregates pending counts across sessions', () => {
    const snapshot = buildSnapshot({
      sessions: [
        buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
        buildSession({ sessionId: 'session-b', containerName: 'beta' })
      ],
      blockedRequests: [
        buildBlockedRequest({ sessionId: 'session-a', blockedId: 'a1' }),
        buildBlockedRequest({ sessionId: 'session-a', blockedId: 'a2' }),
        buildBlockedRequest({ sessionId: 'session-b', blockedId: 'b1' })
      ]
    });
    const { byId, total } = deriveSessionCounts(snapshot);
    expect(byId.get('session-a')).toBe(2);
    expect(byId.get('session-b')).toBe(1);
    expect(total).toBe(3);
  });

  it('tooltip reflects total pending decisions', () => {
    const snapshot = buildSnapshot({
      sessions: [buildSession(), buildSession({ sessionId: 'session-b' })],
      blockedRequests: [buildBlockedRequest(), buildBlockedRequest({ blockedId: 'x' })]
    });
    expect(buildTrayTooltip(snapshot, 2)).toBe(
      'Strait Desktop · 2 sessions · 2 pending decisions'
    );
  });

  it('tooltip falls back to waiting-state text when disconnected', () => {
    const snapshot = buildSnapshot({ connected: false, sessions: [], blockedRequests: [] });
    expect(buildTrayTooltip(snapshot, 0)).toBe('Strait Desktop · waiting for control service');
  });

  it('menu template lists each session with its pending count', () => {
    const snapshot = buildSnapshot({
      sessions: [
        buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
        buildSession({ sessionId: 'session-b', containerName: 'beta' })
      ],
      blockedRequests: [
        buildBlockedRequest({ sessionId: 'session-a', blockedId: 'a1' }),
        buildBlockedRequest({ sessionId: 'session-a', blockedId: 'a2' }),
        buildBlockedRequest({ sessionId: 'session-b', blockedId: 'b1' })
      ]
    });
    const actions = makeActions();
    const template = buildTrayMenuTemplate(snapshot, actions);
    const sessionsEntry = template.find((item) => item.label === 'Sessions');
    expect(sessionsEntry?.submenu).toBeDefined();
    const submenu = Array.isArray(sessionsEntry?.submenu) ? sessionsEntry!.submenu! : [];
    const labels = (submenu as Array<{ label?: string }>).map((item) => item.label);
    expect(labels).toContain('alpha · 2 pending');
    expect(labels).toContain('beta · 1 pending');
  });

  it('quick-resume entry jumps to the most recent pending decision', () => {
    const snapshot = buildSnapshot({
      sessions: [
        buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
        buildSession({ sessionId: 'session-b', containerName: 'beta' })
      ],
      blockedRequests: [
        buildBlockedRequest({ sessionId: 'session-a', blockedId: 'a1' }),
        buildBlockedRequest({ sessionId: 'session-b', blockedId: 'b1' })
      ]
    });
    const focusSession = vi.fn();
    const actions = makeActions({
      focusSession,
      getMostRecentPending: () => ({ sessionId: 'session-b', blockedId: 'b1' })
    });
    const template = buildTrayMenuTemplate(snapshot, actions);
    const resume = template.find((item) =>
      typeof item.label === 'string' && item.label.startsWith('Resume latest pending decision')
    );
    expect(resume?.label).toBe('Resume latest pending decision (2)');
    (resume as { click?: () => void }).click?.();
    expect(focusSession).toHaveBeenCalledWith('session-b', 'b1');
  });

  it('shows a disabled placeholder when no pending decisions exist', () => {
    const snapshot = buildSnapshot({ blockedRequests: [] });
    const template = buildTrayMenuTemplate(snapshot, makeActions());
    const resume = template.find((item) => item.label === 'No pending decisions');
    expect(resume?.enabled).toBe(false);
  });
});
