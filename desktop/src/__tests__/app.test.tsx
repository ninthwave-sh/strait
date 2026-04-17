import { act, cleanup, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../App';
import type { DesktopBridge, FocusSessionRequest } from '../bridge';
import { buildBlockedRequest, buildSession, buildSnapshot } from '../fixtures';
import type { DesktopSnapshot, SubmitDecisionInput } from '../types';

class MockBridge implements DesktopBridge {
  snapshot: DesktopSnapshot;
  decisions: SubmitDecisionInput[] = [];
  failNext = false;
  listeners = new Set<(snapshot: DesktopSnapshot) => void>();
  focusListeners = new Set<(request: FocusSessionRequest) => void>();

  constructor(snapshot: DesktopSnapshot) {
    this.snapshot = snapshot;
  }

  async getSnapshot() {
    return this.snapshot;
  }

  onStateChanged(listener: (snapshot: DesktopSnapshot) => void) {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  async submitDecision(input: SubmitDecisionInput) {
    this.decisions.push(input);
    await new Promise((resolve) => setTimeout(resolve, 50));
    if (this.failNext) {
      this.failNext = false;
      throw new Error('gRPC submit failed');
    }
    return { resolvedBlockedIds: input.blockedIds };
  }

  async focusWindow() {
    return undefined;
  }

  onFocusSession(listener: (request: FocusSessionRequest) => void) {
    this.focusListeners.add(listener);
    return () => this.focusListeners.delete(listener);
  }

  emitState(next: DesktopSnapshot) {
    this.snapshot = next;
    for (const listener of this.listeners) {
      listener(next);
    }
  }

  emitFocusSession(request: FocusSessionRequest) {
    for (const listener of this.focusListeners) {
      listener(request);
    }
  }
}

describe('desktop shell', () => {
  beforeEach(() => {
    vi.useRealTimers();
    // App.tsx persists the onboarding-dismissed flag to localStorage. jsdom
    // keeps one storage instance per worker, so a test that dismisses the
    // tour would leak into later tests that assume the overlay is visible.
    if (typeof window !== 'undefined' && window.localStorage) {
      window.localStorage.clear();
    }
  });

  afterEach(() => {
    cleanup();
  });

  it('renders session inventory in the rail with container labels', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [
          buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
          buildSession({ sessionId: 'session-b', containerName: 'beta' })
        ],
        blockedRequests: [
          buildBlockedRequest({
            sessionId: 'session-a',
            blockedId: 'blocked-a',
            host: 'api.github.com'
          })
        ]
      })
    );

    render(<App bridge={bridge} />);

    const rail = await screen.findByRole('complementary', { name: 'Sessions' });
    expect(await within(rail).findByText('alpha')).toBeInTheDocument();
    expect(within(rail).getByText('beta')).toBeInTheDocument();
    expect((await screen.findAllByText('api.github.com')).length).toBeGreaterThan(0);
  });

  it.each([
    ['Allow once', 'allowOnce'],
    ['Allow for session', 'allowSession'],
    ['Persist', 'persist']
  ] as const)('submits %s decisions through the bridge', async (label, action) => {
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    fireEvent.click(await screen.findByRole('button', { name: label }));

    await waitFor(() => {
      expect(bridge.decisions.at(-1)?.action).toBe(action);
    });
  });

  it('shows optimistic state and surfaces submit errors', async () => {
    const bridge = new MockBridge(buildSnapshot());
    bridge.failNext = true;

    render(<App bridge={bridge} />);
    fireEvent.click(await screen.findByRole('button', { name: 'Allow once' }));

    expect(await screen.findByText('Applying decision…')).toBeInTheDocument();
    expect(await screen.findByText('gRPC submit failed')).toBeInTheDocument();
  });

  it('batches related requests by host and resolves both blocked ids', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        blockedRequests: [
          buildBlockedRequest({ blockedId: 'blocked-1', host: 'api.github.com' }),
          buildBlockedRequest({
            blockedId: 'blocked-2',
            host: 'api.github.com',
            path: '/repos/org/repo/issues'
          })
        ]
      })
    );

    render(<App bridge={bridge} />);

    expect(await screen.findByText('2 related requests · GET /repos/org/repo')).toBeInTheDocument();
    fireEvent.click(screen.getByRole('button', { name: 'Allow for session' }));

    await waitFor(() => {
      expect(bridge.decisions.at(-1)?.blockedIds).toEqual(['blocked-1', 'blocked-2']);
    });
  });

  it('submits custom TTL decisions', async () => {
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    fireEvent.change(await screen.findByLabelText(/TTL for api.github.com/), {
      target: { value: '90' }
    });
    fireEvent.click(screen.getByRole('button', { name: 'Allow for…' }));

    await waitFor(() => {
      expect(bridge.decisions.at(-1)).toMatchObject({ action: 'allowTtl', ttlSeconds: 90 });
    });
  });

  it('filters the alerts pane to the focused session and swaps on rail click', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [
          buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
          buildSession({ sessionId: 'session-b', containerName: 'beta' })
        ],
        blockedRequests: [
          buildBlockedRequest({
            sessionId: 'session-a',
            blockedId: 'blocked-a',
            host: 'api.github.com'
          }),
          buildBlockedRequest({
            sessionId: 'session-b',
            blockedId: 'blocked-b',
            host: 'api.openai.com',
            path: '/v1/chat'
          })
        ]
      })
    );

    render(<App bridge={bridge} />);

    const alertsPanel = await screen.findByRole('region', { name: 'Blocked requests' });
    // By default the shell activates the session that actually has a pending
    // prompt. With two candidates it picks the first one encountered.
    await waitFor(() => {
      expect(within(alertsPanel).getByText('api.github.com')).toBeInTheDocument();
    });
    expect(within(alertsPanel).queryByText('api.openai.com')).toBeNull();

    fireEvent.click(screen.getByRole('button', { name: /Focus session beta/ }));

    await waitFor(() => {
      expect(within(alertsPanel).queryByText('api.github.com')).toBeNull();
    });
    expect(within(alertsPanel).getByText('api.openai.com')).toBeInTheDocument();
  });

  it('surfaces a pending badge for background sessions without stealing focus', async () => {
    const sessionA = buildSession({ sessionId: 'session-a', containerName: 'alpha' });
    const sessionB = buildSession({ sessionId: 'session-b', containerName: 'beta' });
    const initialRequest = buildBlockedRequest({
      sessionId: 'session-a',
      blockedId: 'blocked-a',
      host: 'api.github.com'
    });
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [sessionA, sessionB],
        blockedRequests: [initialRequest]
      })
    );

    render(<App bridge={bridge} />);

    const alertsPanel = await screen.findByRole('region', { name: 'Blocked requests' });
    // session-a is focused because it has the only pending prompt.
    await waitFor(() => {
      expect(within(alertsPanel).getByText('api.github.com')).toBeInTheDocument();
    });

    act(() => {
      bridge.emitState({
        ...bridge.snapshot,
        blockedRequests: [
          initialRequest,
          buildBlockedRequest({
            sessionId: 'session-b',
            blockedId: 'blocked-b',
            host: 'hooks.slack.com',
            path: '/services/T0/B0/XYZ'
          })
        ]
      });
    });

    // Focus must not jump, so the alerts panel still shows session-a's host.
    await waitFor(() => {
      expect(within(alertsPanel).getByText('api.github.com')).toBeInTheDocument();
    });
    expect(within(alertsPanel).queryByText('hooks.slack.com')).toBeNull();

    // The rail shows a 1-count badge on beta to signal the new prompt.
    const betaButton = screen.getByRole('button', { name: /Focus session beta; 1 pending decision/ });
    expect(within(betaButton).getByText('1')).toBeInTheDocument();
  });

  it('activates a session when the main process dispatches focus-session', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [
          buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
          buildSession({ sessionId: 'session-b', containerName: 'beta' })
        ],
        blockedRequests: [
          buildBlockedRequest({
            sessionId: 'session-a',
            blockedId: 'blocked-a',
            host: 'api.github.com'
          }),
          buildBlockedRequest({
            sessionId: 'session-b',
            blockedId: 'blocked-b',
            host: 'hooks.slack.com',
            path: '/services/T0/B0/XYZ'
          })
        ]
      })
    );

    render(<App bridge={bridge} />);
    const alertsPanel = await screen.findByRole('region', { name: 'Blocked requests' });
    await waitFor(() => {
      expect(within(alertsPanel).getByText('api.github.com')).toBeInTheDocument();
    });

    act(() => {
      bridge.emitFocusSession({ sessionId: 'session-b', blockedId: 'blocked-b' });
    });

    await waitFor(() => {
      expect(within(alertsPanel).getByText('hooks.slack.com')).toBeInTheDocument();
    });
    expect(within(alertsPanel).queryByText('api.github.com')).toBeNull();
  });

  it('shows the first-run tour and pins the earliest registered container', async () => {
    const pinned = buildSession({
      sessionId: 'session-first',
      containerName: 'alpha',
      firstSeenAtUnixMs: 1_000
    });
    const other = buildSession({
      sessionId: 'session-second',
      containerName: 'beta',
      firstSeenAtUnixMs: 5_000
    });
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [other, pinned],
        blockedRequests: []
      })
    );

    render(<App bridge={bridge} />);

    // The tour panel is live and the rail tags alpha as "Pinned" even though
    // beta appears first in the sessions array -- pinning is by
    // firstSeenAtUnixMs, not array order.
    expect(await screen.findByRole('region', { name: 'First-run walkthrough' })).toBeInTheDocument();
    const alphaRow = screen.getByRole('button', { name: /Focus session alpha/ });
    expect(within(alphaRow).getByText('Pinned')).toBeInTheDocument();
    const betaRow = screen.getByRole('button', { name: /Focus session beta/ });
    expect(within(betaRow).queryByText('Pinned')).toBeNull();
  });

  it('replaces the tour with a celebration after the operator persists a rule', async () => {
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    // Click Persist on the seed blocked request.
    fireEvent.click(await screen.findByRole('button', { name: 'Persist' }));

    await waitFor(() => {
      expect(bridge.decisions.at(-1)?.action).toBe('persist');
    });

    // The tour moves to the "done" card, which is the only place the
    // "Close tour" button exists.
    expect(await screen.findByRole('button', { name: 'Close tour' })).toBeInTheDocument();
  });

  it('keeps the host-missing prompt in the tour when the control plane is offline', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        connected: false,
        sessions: [],
        blockedRequests: [],
        lastError: 'UNAVAILABLE: connect ENOENT /tmp/strait-control.sock'
      })
    );
    render(<App bridge={bridge} />);

    const tour = await screen.findByRole('region', { name: 'First-run walkthrough' });
    expect(within(tour).getByText(/Start the host control plane/)).toBeInTheDocument();
    // The raw error text is still surfaced (for operators who want the
    // detail) but only as parenthetical copy, not as the top-line message.
    expect(within(tour).getByText(/cannot reach/)).toBeInTheDocument();
  });

  it('keeps the tour closed across app restarts once a rule has been persisted', async () => {
    // Seed the shell with an already-persisted completion timestamp. The
    // earlier M-ONB-1 behaviour reset `persistedCount` to zero on remount,
    // which would make the overlay reappear for a returning operator.
    // L-ONB-3 requires the completion bit to survive, so the overlay stays
    // hidden on this boot without the operator having to click Persist
    // again.
    window.localStorage.setItem(
      'strait-desktop.tutorial.v1',
      JSON.stringify({ dismissed: true, completedAtUnixMs: 1_700_000_000_000 })
    );
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    await waitFor(() => {
      expect(screen.queryByRole('region', { name: 'First-run walkthrough' })).toBeNull();
    });
    expect(screen.queryByRole('region', { name: 'Onboarding complete' })).toBeNull();
    // The header still offers a "Replay tour" affordance so the operator
    // can review the golden path after they have finished it.
    expect(screen.getByRole('button', { name: /Reopen the first-run tutorial \(already completed\)/ })).toBeInTheDocument();
  });

  it('lets a skipped operator reopen the tour from the header', async () => {
    // A skipped-but-not-completed tour is resumable. The overlay stays
    // hidden until the operator clicks "Reopen tour", at which point it
    // picks up wherever the current shell state points to.
    window.localStorage.setItem(
      'strait-desktop.tutorial.v1',
      JSON.stringify({ dismissed: true, completedAtUnixMs: null })
    );
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    await waitFor(() => {
      expect(screen.queryByRole('region', { name: 'First-run walkthrough' })).toBeNull();
    });

    fireEvent.click(screen.getByRole('button', { name: 'Reopen the first-run tutorial' }));

    expect(await screen.findByRole('region', { name: 'First-run walkthrough' })).toBeInTheDocument();
  });

  it('keeps real usage unblocked when the tutorial has not been started', async () => {
    // Regression guard for the L-ONB-3 acceptance criterion: decisions
    // must still flow through the bridge even if the tutorial is not
    // open. We dismiss the tour and confirm the Deny path still works.
    window.localStorage.setItem(
      'strait-desktop.tutorial.v1',
      JSON.stringify({ dismissed: true, completedAtUnixMs: null })
    );
    const bridge = new MockBridge(buildSnapshot());
    render(<App bridge={bridge} />);

    // Tour is gone, but the blocked-request card and its Deny button are
    // still live in the alerts panel.
    expect(screen.queryByRole('region', { name: 'First-run walkthrough' })).toBeNull();
    fireEvent.click(await screen.findByRole('button', { name: 'Deny' }));

    await waitFor(() => {
      expect(bridge.decisions.at(-1)?.action).toBe('deny');
    });
  });

  it('covers the tutorial steps by keyboard alone', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        connected: false,
        sessions: [],
        blockedRequests: [],
        lastError: 'UNAVAILABLE: connect ENOENT /tmp/strait-control.sock'
      })
    );
    render(<App bridge={bridge} />);

    const list = await screen.findByRole('list', { name: 'Tutorial steps' });
    // Arrow-down walks from host-missing through persist without any
    // mouse interaction; the active descendant tracks the focused step.
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-host-missing');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-no-session');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-observe');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-decide');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-persist');
    // And the Skip tour button is reachable by Tab order (it carries a
    // plain text label so a screen reader announces it as a button).
    expect(screen.getByRole('button', { name: 'Skip tour' })).toBeInTheDocument();
  });

  it('auto-denies expired alerts after the countdown reaches zero', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        blockedRequests: [buildBlockedRequest({ holdExpiresAt: new Date(Date.now() + 1100).toISOString() })]
      })
    );

    render(<App bridge={bridge} />);
    expect(await screen.findByText(/0:0[12]/)).toBeInTheDocument();

    await waitFor(
      () => {
        expect(bridge.decisions.at(-1)?.action).toBe('deny');
      },
      { timeout: 2500 }
    );
  });
});
