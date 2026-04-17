import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import type { ComponentProps } from 'react';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { deriveOnboardingStage, Onboarding } from '../Onboarding';
import { buildSession } from '../fixtures';

function baseProps(overrides: Partial<ComponentProps<typeof Onboarding>> = {}): ComponentProps<typeof Onboarding> {
  return {
    connected: true,
    lastError: null,
    sessions: [],
    pendingCount: 0,
    pinnedSession: null,
    persistedCount: 0,
    completedAtUnixMs: null,
    dismissed: false,
    onDismiss: vi.fn(),
    onFocusPinned: vi.fn(),
    ...overrides
  };
}

describe('deriveOnboardingStage', () => {
  it('returns done once a rule has been persisted', () => {
    // Persist wins over every other input. The tour is over.
    expect(
      deriveOnboardingStage({ connected: false, sessionCount: 0, pendingCount: 0, persistedCount: 1 })
    ).toBe('done');
  });

  it('returns done when the tour has been completed in a previous session', () => {
    // A returning operator should land on `done` even if `persistedCount`
    // resets to zero on remount -- that is the whole point of the durable
    // completion timestamp.
    expect(
      deriveOnboardingStage({
        connected: true,
        sessionCount: 1,
        pendingCount: 0,
        persistedCount: 0,
        completedAtUnixMs: 1_700_000_000_000
      })
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
    const { container } = render(<Onboarding {...baseProps({ dismissed: true })} />);
    expect(container.firstChild).toBeNull();
  });

  it('surfaces a host-missing prompt without dumping the raw error string as the headline', () => {
    render(
      <Onboarding
        {...baseProps({
          connected: false,
          lastError: 'UNAVAILABLE: connect ENOENT /tmp/strait-control.sock'
        })}
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
    render(<Onboarding {...baseProps({ connected: true })} />);
    expect(screen.getByText(/Add the devcontainer feature/)).toBeInTheDocument();
  });

  it('pins the first registered container and lets the operator focus it', () => {
    const onFocusPinned = vi.fn();
    const session = buildSession({ sessionId: 'session-first', containerName: 'alpha' });
    render(
      <Onboarding
        {...baseProps({
          connected: true,
          sessions: [session],
          pinnedSession: session,
          onFocusPinned
        })}
      />
    );
    expect(screen.getByText('alpha')).toBeInTheDocument();
    screen.getByRole('button', { name: 'Focus it' }).click();
    expect(onFocusPinned).toHaveBeenCalled();
  });

  it('celebrates a persisted rule and offers to close the tour', () => {
    const onDismiss = vi.fn();
    render(
      <Onboarding
        {...baseProps({
          sessions: [buildSession()],
          pinnedSession: buildSession(),
          persistedCount: 1,
          onDismiss
        })}
      />
    );
    expect(screen.getByText(/You persisted your first rule/)).toBeInTheDocument();
    screen.getByRole('button', { name: 'Close tour' }).click();
    expect(onDismiss).toHaveBeenCalled();
  });

  it('shows the completion card on reopen for a returning operator', () => {
    // A returning operator who finished the tour on a previous launch and
    // reopened it should land right on the celebration card instead of
    // being walked through the golden path again.
    render(
      <Onboarding
        {...baseProps({
          sessions: [buildSession()],
          pinnedSession: buildSession(),
          completedAtUnixMs: 1_700_000_000_000
        })}
      />
    );
    expect(screen.getByText(/You persisted your first rule/)).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Close tour' })).toBeInTheDocument();
  });

  it('exposes keyboard-focusable controls for skip and step navigation', () => {
    render(<Onboarding {...baseProps({ connected: true })} />);
    const region = screen.getByRole('region', { name: 'First-run walkthrough' });
    // Every control in the overlay must be reachable by Tab. We use the
    // button accessible names so a screen reader user knows what each does.
    const buttons = within(region).getAllByRole('button');
    const labels = buttons.map((btn) => btn.getAttribute('aria-label') ?? btn.textContent);
    expect(labels).toContain('Previous step');
    expect(labels).toContain('Next step');
    expect(buttons.some((btn) => btn.textContent === 'Skip tour')).toBe(true);
    // No stale `tabindex=-1` on the visible buttons that would trap keyboard users.
    for (const btn of buttons) {
      expect(btn.hasAttribute('disabled') || btn.getAttribute('tabindex') !== '-1').toBe(true);
    }
  });

  it('moves focus between steps with arrow keys', () => {
    render(<Onboarding {...baseProps({ connected: false })} />);
    const list = screen.getByRole('list', { name: 'Tutorial steps' });
    // At open, the host-missing step is focused (stage 0). Arrow-down
    // should bump the active descendant to step 2 (no-session).
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-host-missing');
    fireEvent.keyDown(list, { key: 'ArrowDown' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-no-session');
    fireEvent.keyDown(list, { key: 'End' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-persist');
    fireEvent.keyDown(list, { key: 'Home' });
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-host-missing');
  });

  it('navigates steps with the Previous and Next buttons', () => {
    render(<Onboarding {...baseProps({ connected: false })} />);
    const list = screen.getByRole('list', { name: 'Tutorial steps' });
    const previous = screen.getByRole('button', { name: 'Previous step' });
    const next = screen.getByRole('button', { name: 'Next step' });
    expect(previous).toBeDisabled();
    expect(next).toBeEnabled();
    fireEvent.click(next);
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-no-session');
    expect(previous).toBeEnabled();
    fireEvent.click(previous);
    expect(list.getAttribute('aria-activedescendant')).toBe('onboarding-step-host-missing');
  });
});
