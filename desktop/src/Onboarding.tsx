import { useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent } from 'react';

import type { SessionSummary } from './types';

/** State machine used by the onboarding overlay to pick which step is live. */
export type OnboardingStage =
  | 'host-missing'
  | 'no-session'
  | 'observe'
  | 'decide'
  | 'persist'
  | 'done';

export interface OnboardingProps {
  connected: boolean;
  /** Most recent non-fatal error text surfaced by the control plane poller. */
  lastError: string | null;
  sessions: SessionSummary[];
  /** Number of live blocked-request prompts pending across all sessions. */
  pendingCount: number;
  /**
   * The session the desktop shell considers "pinned for the first run." This
   * is the earliest registered session, or `null` if no session has
   * registered yet.
   */
  pinnedSession: SessionSummary | null;
  persistedCount: number;
  /**
   * Unix milliseconds when the operator finished the tour, or `null` if
   * they have not yet completed it. The `done` stage is reached when this
   * is set *or* when `persistedCount` goes above zero; the persisted
   * timestamp is the bit that survives across desktop restarts.
   */
  completedAtUnixMs: number | null;
  dismissed: boolean;
  onDismiss(): void;
  onFocusPinned(): void;
}

/**
 * Pure helper so tests can assert which stage the overlay lands on without
 * rendering the component. Order of checks matches the onboarding narrative
 * from `docs/getting-started.md`:
 *
 *   start the host -> add the feature -> observe -> decide -> persist -> done
 */
export function deriveOnboardingStage(params: {
  connected: boolean;
  sessionCount: number;
  pendingCount: number;
  persistedCount: number;
  completedAtUnixMs?: number | null;
}): OnboardingStage {
  if ((params.completedAtUnixMs ?? 0) > 0 || params.persistedCount > 0) {
    return 'done';
  }
  if (!params.connected) {
    return 'host-missing';
  }
  if (params.sessionCount === 0) {
    return 'no-session';
  }
  if (params.pendingCount === 0) {
    return 'observe';
  }
  // There is at least one pending prompt. Once the operator has answered at
  // least one prompt we nudge them toward the persist action; until then we
  // stay on `decide` so the step prose matches "answer the prompt."
  return 'decide';
}

interface Step {
  id: OnboardingStage;
  title: string;
  body: string;
}

export const TUTORIAL_STEPS: ReadonlyArray<Step> = [
  {
    id: 'host-missing',
    title: 'Start the host control plane',
    body: 'Run `strait-host serve` on this machine. Homebrew installs it as a launchd service; on Linux it ships with a systemd user unit. The desktop shell reconnects the moment the socket appears.'
  },
  {
    id: 'no-session',
    title: 'Add the devcontainer feature',
    body: "Add `ghcr.io/ninthwave-io/strait` to `features` in your project's `.devcontainer/devcontainer.json`, then reopen the project in its container. The feature installs the in-container agent and registers the session with the host."
  },
  {
    id: 'observe',
    title: 'Observe',
    body: 'The agent is live. Run whatever the container normally does. Every outbound HTTP call passes through the proxy and raises a blocked-request prompt the first time a host is seen.'
  },
  {
    id: 'decide',
    title: 'Decide',
    body: 'Answer the pending prompt on the first container. Allow once if you are not sure yet; the decision is held open until you pick.'
  },
  {
    id: 'persist',
    title: 'Persist',
    body: 'Click Persist on a prompt to write a durable Cedar rule into the host rule store. The next session on the same policy will reuse it automatically.'
  }
];

const STEP_ORDER: OnboardingStage[] = [
  'host-missing',
  'no-session',
  'observe',
  'decide',
  'persist',
  'done'
];

function stepStatus(stepId: OnboardingStage, stage: OnboardingStage): 'complete' | 'current' | 'upcoming' {
  const stepIndex = STEP_ORDER.indexOf(stepId);
  const stageIndex = STEP_ORDER.indexOf(stage);
  if (stageIndex > stepIndex) {
    return 'complete';
  }
  if (stageIndex === stepIndex) {
    return 'current';
  }
  return 'upcoming';
}

export function Onboarding(props: OnboardingProps) {
  if (props.dismissed) {
    return null;
  }

  const stage = deriveOnboardingStage({
    connected: props.connected,
    sessionCount: props.sessions.length,
    pendingCount: props.pendingCount,
    persistedCount: props.persistedCount,
    completedAtUnixMs: props.completedAtUnixMs
  });

  // Which step the operator is focused on in the step list. Defaults to the
  // derived stage (so the panel lands on the actual live step when the tour
  // opens or resumes) but lets the operator page through the other steps
  // with the keyboard without losing the "live" highlight.
  const currentStageIndex = STEP_ORDER.indexOf(stage);
  const [focusedIndex, setFocusedIndex] = useState<number>(Math.max(0, currentStageIndex));
  const previousStageRef = useRef<OnboardingStage>(stage);
  useEffect(() => {
    // When the derived stage advances we move the keyboard focus forward
    // to match. This keeps the "you are here" hint aligned with reality
    // without trapping the operator if they had paged around manually.
    if (stage !== previousStageRef.current) {
      const nextIndex = STEP_ORDER.indexOf(stage);
      if (nextIndex >= 0) {
        setFocusedIndex(nextIndex);
      }
      previousStageRef.current = stage;
    }
  }, [stage]);

  const visibleSteps = useMemo(
    () => TUTORIAL_STEPS.filter((step) => step.id !== 'done'),
    []
  );

  if (stage === 'done') {
    return (
      <section
        className="panel onboarding-panel onboarding-done"
        role="region"
        aria-label="Onboarding complete"
      >
        <div className="panel-header">
          <h2>You persisted your first rule</h2>
          <button className="secondary" onClick={props.onDismiss}>
            Close tour
          </button>
        </div>
        <p>
          The rule lives in the host rule store. Future sessions with the same policy
          scope pick it up automatically. You can reopen this tour from the Preferences
          menu, and it stays closed across desktop restarts.
        </p>
      </section>
    );
  }

  const pinnedLabel = props.pinnedSession?.containerName?.trim()
    ? props.pinnedSession.containerName
    : props.pinnedSession?.sessionId ?? null;

  const focusedStep = visibleSteps[Math.min(focusedIndex, visibleSteps.length - 1)] ?? visibleSteps[0];
  const clampedFocusedIndex = Math.min(focusedIndex, visibleSteps.length - 1);

  function moveFocus(delta: number) {
    setFocusedIndex((current) => {
      const next = current + delta;
      if (next < 0) {
        return 0;
      }
      if (next >= visibleSteps.length) {
        return visibleSteps.length - 1;
      }
      return next;
    });
  }

  function handleStepListKeyDown(event: ReactKeyboardEvent<HTMLOListElement>) {
    // Arrow/Home/End navigation on the step list keeps the tour usable
    // without a mouse. Tab still moves focus to the next interactive
    // element, so the list itself is a single tab stop.
    switch (event.key) {
      case 'ArrowDown':
      case 'ArrowRight':
        event.preventDefault();
        moveFocus(1);
        break;
      case 'ArrowUp':
      case 'ArrowLeft':
        event.preventDefault();
        moveFocus(-1);
        break;
      case 'Home':
        event.preventDefault();
        setFocusedIndex(0);
        break;
      case 'End':
        event.preventDefault();
        setFocusedIndex(visibleSteps.length - 1);
        break;
      default:
        break;
    }
  }

  return (
    <section className="panel onboarding-panel" role="region" aria-label="First-run walkthrough">
      <div className="panel-header">
        <h2>First-run walkthrough</h2>
        <div className="onboarding-controls">
          <button
            className="secondary"
            onClick={() => moveFocus(-1)}
            disabled={clampedFocusedIndex <= 0}
            aria-label="Previous step"
          >
            Previous
          </button>
          <button
            className="secondary"
            onClick={() => moveFocus(1)}
            disabled={clampedFocusedIndex >= visibleSteps.length - 1}
            aria-label="Next step"
          >
            Next
          </button>
          <button className="secondary" onClick={props.onDismiss}>
            Skip tour
          </button>
        </div>
      </div>

      {stage === 'host-missing' ? (
        <p className="onboarding-banner" role="status">
          {/*
            When the host is missing we deliberately avoid the raw gRPC error
            string. `lastError` is still surfaced in the status strip for
            operators who need the detail; the overlay's job is to point at
            the fix, not print a stack trace.
          */}
          The desktop shell cannot reach `strait-host`. Start it and this overlay
          will move on once the socket connects.
          {props.lastError ? <span className="onboarding-error-detail"> ({props.lastError})</span> : null}
        </p>
      ) : null}

      {stage !== 'host-missing' && pinnedLabel ? (
        <p className="onboarding-pinned" role="status">
          Pinned: <strong>{pinnedLabel}</strong>
          <button className="link-button" onClick={props.onFocusPinned}>
            Focus it
          </button>
        </p>
      ) : null}

      <ol
        className="onboarding-steps"
        tabIndex={0}
        role="list"
        aria-label="Tutorial steps"
        aria-activedescendant={`onboarding-step-${focusedStep.id}`}
        onKeyDown={handleStepListKeyDown}
      >
        {visibleSteps.map((step, index) => {
          const status = stepStatus(step.id, stage);
          const focused = index === clampedFocusedIndex;
          return (
            <li
              key={step.id}
              id={`onboarding-step-${step.id}`}
              className={`onboarding-step ${status}${focused ? ' focused' : ''}`}
              aria-current={status === 'current' ? 'step' : undefined}
            >
              <span className="onboarding-step-index">{index + 1}</span>
              <div className="onboarding-step-body">
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </li>
          );
        })}
      </ol>
      <p className="onboarding-keyboard-hint">
        Use the arrow keys to browse steps, or Tab to the Skip tour button to dismiss the walkthrough.
      </p>
    </section>
  );
}
