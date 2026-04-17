import type { SessionSummary } from './types';

/** State machine used by the onboarding overlay to pick which step is live. */
export type OnboardingStage =
  | 'host-missing'
  | 'no-session'
  | 'observe'
  | 'decide'
  | 'persist'
  | 'done';

export interface OnboardingState {
  /**
   * When true the overlay is hidden entirely. The operator hides it either by
   * clicking "Close tour" on the `done` step or by opting out earlier with
   * "Skip tour".
   */
  dismissed: boolean;
  /**
   * Count of `persist` decisions we have observed submitted through the
   * bridge. One persisted rule is enough to progress to `done`; the acceptance
   * criterion for the rewrite is "leave with a persisted rule."
   */
  persistedCount: number;
}

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
}): OnboardingStage {
  if (params.persistedCount > 0) {
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

const STEPS: Step[] = [
  {
    id: 'host-missing',
    title: 'Start the host control plane',
    body: 'Run `strait-host serve` on this machine. Homebrew installs it as a launchd service; on Linux it ships with a systemd user unit. The desktop shell reconnects the moment the socket appears.'
  },
  {
    id: 'no-session',
    title: 'Add the devcontainer feature',
    body: 'Add `ghcr.io/ninthwave-io/strait` to `features` in your project\'s `.devcontainer/devcontainer.json`, then reopen the project in its container. The feature installs the in-container agent and registers the session with the host.'
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

function stepStatus(stepId: OnboardingStage, stage: OnboardingStage): 'complete' | 'current' | 'upcoming' {
  const order: OnboardingStage[] = ['host-missing', 'no-session', 'observe', 'decide', 'persist', 'done'];
  const stepIndex = order.indexOf(stepId);
  const stageIndex = order.indexOf(stage);
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
    persistedCount: props.persistedCount
  });

  if (stage === 'done') {
    return (
      <section className="panel onboarding-panel onboarding-done" aria-label="Onboarding complete">
        <div className="panel-header">
          <h2>You persisted your first rule</h2>
          <button className="secondary" onClick={props.onDismiss}>
            Close tour
          </button>
        </div>
        <p>
          The rule lives in the host rule store. Future sessions with the same policy
          scope pick it up automatically. You can reopen this tour from the Preferences
          menu.
        </p>
      </section>
    );
  }

  const pinnedLabel = props.pinnedSession?.containerName?.trim()
    ? props.pinnedSession.containerName
    : props.pinnedSession?.sessionId ?? null;

  return (
    <section className="panel onboarding-panel" aria-label="First-run walkthrough">
      <div className="panel-header">
        <h2>First-run walkthrough</h2>
        <button className="secondary" onClick={props.onDismiss}>
          Skip tour
        </button>
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

      <ol className="onboarding-steps">
        {STEPS.map((step, index) => {
          const status = stepStatus(step.id, stage);
          return (
            <li key={step.id} className={`onboarding-step ${status}`} aria-current={status === 'current' ? 'step' : undefined}>
              <span className="onboarding-step-index">{index + 1}</span>
              <div className="onboarding-step-body">
                <h3>{step.title}</h3>
                <p>{step.body}</p>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}
