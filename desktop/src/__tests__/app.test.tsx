import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { App } from '../App';
import type { DesktopBridge } from '../bridge';
import { buildBlockedRequest, buildSession, buildSnapshot } from '../fixtures';
import type { DesktopSnapshot, SubmitDecisionInput } from '../types';

class MockBridge implements DesktopBridge {
  snapshot: DesktopSnapshot;
  decisions: SubmitDecisionInput[] = [];
  failNext = false;
  listeners = new Set<(snapshot: DesktopSnapshot) => void>();

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
}

describe('desktop shell', () => {
  beforeEach(() => {
    vi.useRealTimers();
  });

  afterEach(() => {
    cleanup();
  });

  it('renders session inventory and blocked-request cards from fixtures', async () => {
    const bridge = new MockBridge(
      buildSnapshot({
        sessions: [
          buildSession({ sessionId: 'session-a', containerName: 'alpha' }),
          buildSession({ sessionId: 'session-b', containerName: 'beta' })
        ],
        blockedRequests: [
          buildBlockedRequest({ blockedId: 'blocked-a', host: 'api.github.com' }),
          buildBlockedRequest({ blockedId: 'blocked-b', host: 'api.openai.com', path: '/v1/chat' })
        ]
      })
    );

    render(<App bridge={bridge} />);

    expect(await screen.findByText('session-a')).toBeInTheDocument();
    expect(screen.getByText('session-b')).toBeInTheDocument();
    expect((await screen.findAllByText('api.github.com')).length).toBeGreaterThan(0);
    expect((await screen.findAllByText('api.openai.com')).length).toBeGreaterThan(0);
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
