import { cleanup, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { deriveOnboardingStage, Onboarding } from '../Onboarding';
import { buildSession } from '../fixtures';

describe('deriveOnboardingStage', () => {
  it('returns done once a rule has been persisted', () => {
    // Persist wins over every other input. The tour is over.
    expect(
      deriveOnboardingStage({ connected: false, sessionCount: 0, pendingCount: 0, persistedCount: 1 })
    ).toBe('done');
  });

  it('flags a disconnected host before anything else', () => {
    expect(
      deriveOnboardingStage({ connected: false, sessionCount: 0, pendingCount: 0, persistedCount: 0 })
    ).toBe('host-missing');
  });

  it('asks for the devcontainer feature when no session has registered', () => {
    expect(
      deriveOnboardingStage({ connected: true, sessionCount: 0, pendingCount: 0, persistedCount: 0 })
    ).toBe('no-session');
  });

  it('sits on observe while the container is idle', () => {
    expect(
      deriveOnboardingStage({ connected: true, sessionCount: 1, pendingCount: 0, persistedCount: 0 })
    ).toBe('observe');
  });

  it('advances to decide once a blocked request has landed', () => {
    expect(
      deriveOnboardingStage({ connected: true, sessionCount: 1, pendingCount: 1, persistedCount: 0 })
    ).toBe('decide');
  });
});

describe('Onboarding overlay', () => {
  afterEach(() => {
    cleanup();
  });

  it('is hidden when the operator has dismissed it', () => {
    const { container } = render(
      <Onboarding
        connected={true}
        lastError={null}
        sessions={[]}
        pendingCount={0}
        pinnedSession={null}
        persistedCount={0}
        dismissed={true}
        onDismiss={vi.fn()}
        onFocusPinned={vi.fn()}
      />
    );
    expect(container.firstChild).toBeNull();
  });

  it('surfaces a host-missing prompt without dumping the raw error string as the headline', () => {
    render(
      <Onboarding
        connected={false}
        lastError={'UNAVAILABLE: connect ENOENT /tmp/strait-control.sock'}
        sessions={[]}
        pendingCount={0}
        pinnedSession={null}
        persistedCount={0}
        dismissed={false}
        onDismiss={vi.fn()}
        onFocusPinned={vi.fn()}
      />
    );
    // The step title frames the fix in plain language.
    expect(screen.getByText(/Start the host control plane/)).toBeInTheDocument();
    // The raw error string still shows, but as parenthetical detail, not as
    // the top-line message. That keeps first-run operators calm when the
    // host has not been installed yet.
    const status = screen.getByRole('status');
    expect(status.textContent).toContain('The desktop shell cannot reach');
    expect(status.textContent).toContain('UNAVAILABLE: connect ENOENT');
  });

  it('tells the operator to add the devcontainer feature when connected but sessionless', () => {
    render(
      <Onboarding
        connected={true}
        lastError={null}
        sessions={[]}
        pendingCount={0}
        pinnedSession={null}
        persistedCount={0}
        dismissed={false}
        onDismiss={vi.fn()}
        onFocusPinned={vi.fn()}
      />
    );
    expect(screen.getByText(/Add the devcontainer feature/)).toBeInTheDocument();
  });

  it('pins the first registered container and lets the operator focus it', () => {
    const onFocusPinned = vi.fn();
    const session = buildSession({ sessionId: 'session-first', containerName: 'alpha' });
    render(
      <Onboarding
        connected={true}
        lastError={null}
        sessions={[session]}
        pendingCount={0}
        pinnedSession={session}
        persistedCount={0}
        dismissed={false}
        onDismiss={vi.fn()}
        onFocusPinned={onFocusPinned}
      />
    );
    // The pinned chip names the container so the operator knows which row
    // the tour is narrating.
    expect(screen.getByText('alpha')).toBeInTheDocument();
    screen.getByRole('button', { name: 'Focus it' }).click();
    expect(onFocusPinned).toHaveBeenCalled();
  });

  it('celebrates a persisted rule and offers to close the tour', () => {
    const onDismiss = vi.fn();
    render(
      <Onboarding
        connected={true}
        lastError={null}
        sessions={[buildSession()]}
        pendingCount={0}
        pinnedSession={buildSession()}
        persistedCount={1}
        dismissed={false}
        onDismiss={onDismiss}
        onFocusPinned={vi.fn()}
      />
    );
    expect(screen.getByText(/You persisted your first rule/)).toBeInTheDocument();
    screen.getByRole('button', { name: 'Close tour' }).click();
    expect(onDismiss).toHaveBeenCalled();
  });
});
