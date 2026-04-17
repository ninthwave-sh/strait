import { useCallback, useEffect, useMemo, useState } from 'react';

import { resolveBridge, type DesktopBridge } from './bridge';
import { Onboarding } from './Onboarding';
import { SessionRail, sessionLabel, type SessionRailEntry } from './Sessions';
import type {
  BlockedBatch,
  BlockedRequestSummary,
  DecisionAction,
  DesktopSnapshot,
  SessionSummary
} from './types';

const ONBOARDING_DISMISS_STORAGE_KEY = 'strait-desktop.onboarding.dismissed';

function readDismissedFromStorage(): boolean {
  if (typeof window === 'undefined' || !window.localStorage) {
    return false;
  }
  try {
    return window.localStorage.getItem(ONBOARDING_DISMISS_STORAGE_KEY) === 'true';
  } catch {
    // Some harnesses (including the fixture preload) refuse localStorage
    // access. Failing closed here just means the overlay is visible, which
    // is the safe default for a first-run hint.
    return false;
  }
}

function writeDismissedToStorage(dismissed: boolean) {
  if (typeof window === 'undefined' || !window.localStorage) {
    return;
  }
  try {
    if (dismissed) {
      window.localStorage.setItem(ONBOARDING_DISMISS_STORAGE_KEY, 'true');
    } else {
      window.localStorage.removeItem(ONBOARDING_DISMISS_STORAGE_KEY);
    }
  } catch {
    // localStorage is a nice-to-have; if it is not writable the onboarding
    // overlay will reappear on the next desktop start, which is strictly a
    // minor annoyance rather than a correctness issue.
  }
}

/**
 * Picks the session the desktop pins to the onboarding walkthrough. The
 * earliest `firstSeenAtUnixMs` wins so first-run operators always look at
 * the same row while the tour is live. Sessions with no timestamp (which
 * should not happen in production but does in fixtures) sort last.
 */
export function pickPinnedSession(sessions: SessionSummary[]): SessionSummary | null {
  if (sessions.length === 0) {
    return null;
  }
  let best: SessionSummary | null = null;
  for (const session of sessions) {
    if (!best) {
      best = session;
      continue;
    }
    const bestTs = best.firstSeenAtUnixMs ?? Number.POSITIVE_INFINITY;
    const candidateTs = session.firstSeenAtUnixMs ?? Number.POSITIVE_INFINITY;
    if (candidateTs < bestTs) {
      best = session;
    }
  }
  return best;
}

const EMPTY_SNAPSHOT: DesktopSnapshot = {
  enabled: false,
  connected: false,
  serviceSocketPath: '',
  sessions: [],
  blockedRequests: [],
  lastError: null
};

function parseTime(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

export function buildBlockedBatches(
  blockedRequests: BlockedRequestSummary[],
  now = Date.now()
): BlockedBatch[] {
  const groups = new Map<string, BlockedRequestSummary[]>();

  for (const request of blockedRequests) {
    const key = `${request.sessionId}:${request.host}`;
    const group = groups.get(key) ?? [];
    group.push(request);
    groups.set(key, group);
  }

  return Array.from(groups.entries())
    .map(([key, requests]) => {
      const timeRemainingMs = Math.max(
        0,
        Math.min(...requests.map((request) => parseTime(request.holdExpiresAt) || Infinity)) - now
      );
      const sortedRequests = [...requests].sort(
        (left, right) => parseTime(left.observedAt) - parseTime(right.observedAt)
      );
      return {
        id: key,
        sessionId: sortedRequests[0].sessionId,
        host: sortedRequests[0].host,
        requests: sortedRequests,
        blockedIds: sortedRequests.map((request) => request.blockedId),
        timeRemainingMs
      } satisfies BlockedBatch;
    })
    .sort((left, right) => left.timeRemainingMs - right.timeRemainingMs);
}

function formatCountdown(timeRemainingMs: number): string {
  const totalSeconds = Math.max(0, Math.ceil(timeRemainingMs / 1000));
  const minutes = Math.floor(totalSeconds / 60);
  const seconds = totalSeconds % 60;
  return `${minutes}:${seconds.toString().padStart(2, '0')}`;
}

function actionLabel(action: DecisionAction): string {
  switch (action) {
    case 'deny':
      return 'Deny';
    case 'allowOnce':
      return 'Allow once';
    case 'allowSession':
      return 'Allow for session';
    case 'persist':
      return 'Persist';
    case 'allowTtl':
      return 'Allow for…';
  }
}

function pickActiveSessionId(
  sessions: SessionSummary[],
  current: string | null,
  blockedRequests: BlockedRequestSummary[]
): string | null {
  if (current && sessions.some((session) => session.sessionId === current)) {
    return current;
  }
  const pending = blockedRequests.find((request) =>
    sessions.some((session) => session.sessionId === request.sessionId)
  );
  if (pending) {
    return pending.sessionId;
  }
  return sessions[0]?.sessionId ?? null;
}

export function App({ bridge: providedBridge }: { bridge?: DesktopBridge }) {
  const bridge = useMemo(() => resolveBridge(providedBridge), [providedBridge]);
  const [snapshot, setSnapshot] = useState<DesktopSnapshot>(EMPTY_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null);
  const [alertedSessionIds, setAlertedSessionIds] = useState<Record<string, true>>({});
  const [selectedBatchId, setSelectedBatchId] = useState<string | null>(null);
  const [pendingBatchIds, setPendingBatchIds] = useState<Record<string, true>>({});
  const [hiddenBlockedIds, setHiddenBlockedIds] = useState<Record<string, true>>({});
  const [customTtls, setCustomTtls] = useState<Record<string, string>>({});
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [seenBlockedIds, setSeenBlockedIds] = useState<Record<string, true>>({});
  // Onboarding overlay state. `persistedCount` advances the tour past the
  // final step; `dismissed` hides the overlay outright. Both are local to
  // the desktop shell because the host has no concept of per-operator tour
  // progress.
  const [onboardingDismissed, setOnboardingDismissed] = useState<boolean>(readDismissedFromStorage);
  const [persistedCount, setPersistedCount] = useState<number>(0);

  useEffect(() => {
    let cancelled = false;

    void bridge.getSnapshot().then((nextSnapshot) => {
      if (cancelled) {
        return;
      }
      setSnapshot(nextSnapshot);
      setLoading(false);
    });

    const unsubscribe = bridge.onStateChanged((nextSnapshot) => {
      if (!cancelled) {
        setSnapshot(nextSnapshot);
      }
    });

    return () => {
      cancelled = true;
      unsubscribe();
    };
  }, [bridge]);

  useEffect(() => {
    const interval = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(interval);
  }, []);

  // Keep the active session valid as the session list churns.
  useEffect(() => {
    setActiveSessionId((current) =>
      pickActiveSessionId(snapshot.sessions, current, snapshot.blockedRequests)
    );
  }, [snapshot.blockedRequests, snapshot.sessions]);

  // The active session is definitionally "not alerted" -- the operator is
  // looking straight at it. This also covers the first-load race where
  // pickActiveSessionId runs after seenBlockedIds has already tagged every
  // starter request as cross-session.
  useEffect(() => {
    if (!activeSessionId) {
      return;
    }
    setAlertedSessionIds((current) => {
      if (!current[activeSessionId]) {
        return current;
      }
      const next = { ...current };
      delete next[activeSessionId];
      return next;
    });
  }, [activeSessionId]);

  // Track blocked requests that landed while a different session was focused.
  // Each session's alerted flag clears only when the operator explicitly
  // focuses it, so cross-session alerts never get silently absorbed by the
  // session that happened to be focused when the request arrived.
  useEffect(() => {
    const alerts: Record<string, true> = {};
    let discoveredSomethingNew = false;
    const nextSeen: Record<string, true> = { ...seenBlockedIds };
    for (const request of snapshot.blockedRequests) {
      if (seenBlockedIds[request.blockedId]) {
        continue;
      }
      discoveredSomethingNew = true;
      nextSeen[request.blockedId] = true;
      if (request.sessionId && request.sessionId !== activeSessionId) {
        alerts[request.sessionId] = true;
      }
    }
    if (!discoveredSomethingNew) {
      return;
    }
    setSeenBlockedIds(nextSeen);
    if (Object.keys(alerts).length > 0) {
      setAlertedSessionIds((current) => ({ ...current, ...alerts }));
    }
  }, [activeSessionId, seenBlockedIds, snapshot.blockedRequests]);

  const handleSelectSession = useCallback((sessionId: string) => {
    setActiveSessionId(sessionId);
    setAlertedSessionIds((current) => {
      if (!current[sessionId]) {
        return current;
      }
      const next = { ...current };
      delete next[sessionId];
      return next;
    });
    setSelectedBatchId(null);
  }, []);

  // Tray → renderer focus requests. The main process dispatches these when
  // the user clicks a session or the quick-resume entry in the tray menu.
  useEffect(() => {
    const unsubscribe = bridge.onFocusSession(({ sessionId, blockedId }) => {
      handleSelectSession(sessionId);
      if (blockedId) {
        // Defer until the filtered batch list re-renders under the new
        // active session; the batch id is `${sessionId}:${host}`.
        const match = snapshot.blockedRequests.find((request) => request.blockedId === blockedId);
        if (match) {
          setSelectedBatchId(`${match.sessionId}:${match.host}`);
        }
      }
    });
    return () => unsubscribe();
  }, [bridge, handleSelectSession, snapshot.blockedRequests]);

  const visibleRequests = useMemo(
    () => snapshot.blockedRequests.filter((request) => !hiddenBlockedIds[request.blockedId]),
    [hiddenBlockedIds, snapshot.blockedRequests]
  );

  const batchesBySession = useMemo(() => {
    const allBatches = buildBlockedBatches(visibleRequests, now);
    const grouped = new Map<string, BlockedBatch[]>();
    for (const batch of allBatches) {
      const bucket = grouped.get(batch.sessionId) ?? [];
      bucket.push(batch);
      grouped.set(batch.sessionId, bucket);
    }
    return grouped;
  }, [now, visibleRequests]);

  const activeBatches = useMemo(
    () => (activeSessionId ? batchesBySession.get(activeSessionId) ?? [] : []),
    [activeSessionId, batchesBySession]
  );

  const pendingCountsBySession = useMemo(() => {
    const counts = new Map<string, number>();
    for (const [sessionId, batches] of batchesBySession.entries()) {
      counts.set(
        sessionId,
        batches.reduce((sum, batch) => sum + batch.requests.length, 0)
      );
    }
    return counts;
  }, [batchesBySession]);

  const pinnedSession = useMemo(() => pickPinnedSession(snapshot.sessions), [snapshot.sessions]);

  // The pinned chip only matters while the onboarding tour is active. Once
  // the operator has persisted a rule or explicitly skipped the tour, the
  // chip goes away so the rail stays uncluttered.
  const showPin = !onboardingDismissed && persistedCount === 0;

  const sessionEntries = useMemo<SessionRailEntry[]>(
    () =>
      snapshot.sessions.map((session) => ({
        session,
        pendingCount: pendingCountsBySession.get(session.sessionId) ?? 0,
        alerted: Boolean(alertedSessionIds[session.sessionId]),
        active: session.sessionId === activeSessionId,
        pinned: showPin && session.sessionId === pinnedSession?.sessionId
      })),
    [activeSessionId, alertedSessionIds, pendingCountsBySession, pinnedSession, showPin, snapshot.sessions]
  );

  const selectedBatch =
    activeBatches.find((batch) => batch.id === selectedBatchId) ?? activeBatches[0] ?? null;

  useEffect(() => {
    if (selectedBatch && selectedBatch.id !== selectedBatchId) {
      setSelectedBatchId(selectedBatch.id);
    }
    if (!selectedBatch) {
      setSelectedBatchId(null);
    }
  }, [selectedBatch, selectedBatchId]);

  const submitDecision = useCallback(
    async (batch: BlockedBatch, action: DecisionAction, ttlSeconds?: number) => {
      setErrorMessage(null);
      setPendingBatchIds((current) => ({ ...current, [batch.id]: true }));
      try {
        await bridge.submitDecision({
          sessionId: batch.sessionId,
          blockedIds: batch.blockedIds,
          action,
          ttlSeconds
        });
        setHiddenBlockedIds((current) => {
          const next = { ...current };
          for (const blockedId of batch.blockedIds) {
            next[blockedId] = true;
          }
          return next;
        });
        if (action === 'persist') {
          // A successful persist advances the onboarding tour from the
          // `persist` step to `done`. We count rather than flip a boolean so
          // that additional persists after the tour ends are still
          // observable in case we want to surface them later.
          setPersistedCount((current) => current + 1);
        }
      } catch (error) {
        setErrorMessage(error instanceof Error ? error.message : 'Decision failed.');
      } finally {
        setPendingBatchIds((current) => {
          const next = { ...current };
          delete next[batch.id];
          return next;
        });
      }
    },
    [bridge]
  );

  // Auto-deny expired batches across every session so a background session's
  // timed-out prompt is not held hostage by a focus decision.
  useEffect(() => {
    const expired: BlockedBatch[] = [];
    for (const batches of batchesBySession.values()) {
      for (const batch of batches) {
        if (batch.timeRemainingMs <= 0 && !pendingBatchIds[batch.id]) {
          expired.push(batch);
        }
      }
    }
    if (expired.length === 0) {
      return;
    }
    // Fire-and-forget one per render to avoid thundering herd.
    void submitDecision(expired[0], 'deny');
  }, [batchesBySession, pendingBatchIds, submitDecision]);

  const activeSession = snapshot.sessions.find((session) => session.sessionId === activeSessionId) ?? null;
  const totalPending = Array.from(pendingCountsBySession.values()).reduce(
    (sum, count) => sum + count,
    0
  );

  const handleDismissOnboarding = useCallback(() => {
    setOnboardingDismissed(true);
    writeDismissedToStorage(true);
  }, []);

  const handleFocusPinned = useCallback(() => {
    if (pinnedSession) {
      handleSelectSession(pinnedSession.sessionId);
    }
  }, [handleSelectSession, pinnedSession]);

  return (
    <div className="app-shell">
      <header className="header">
        <div>
          <h1>Strait Desktop</h1>
          <p className="subhead">
            Multi-container control plane. {snapshot.sessions.length} session
            {snapshot.sessions.length === 1 ? '' : 's'} · {totalPending} pending
          </p>
        </div>
        <button className="secondary" onClick={() => void bridge.focusWindow()}>
          Focus window
        </button>
      </header>

      <section className="status-strip">
        <span className={`status-pill ${snapshot.connected ? 'good' : 'bad'}`}>
          {snapshot.connected ? 'Connected' : 'Disconnected'}
        </span>
        <span className={`status-pill ${snapshot.enabled ? 'good' : 'muted'}`}>
          {snapshot.enabled ? 'Enabled' : 'Paused'}
        </span>
        <span className="socket-path">{snapshot.serviceSocketPath || 'No service socket configured'}</span>
      </section>

      {errorMessage ? <div className="error-banner">{errorMessage}</div> : null}
      {snapshot.lastError ? <div className="warning-banner">{snapshot.lastError}</div> : null}

      <Onboarding
        connected={snapshot.connected}
        lastError={snapshot.lastError}
        sessions={snapshot.sessions}
        pendingCount={totalPending}
        pinnedSession={pinnedSession}
        persistedCount={persistedCount}
        dismissed={onboardingDismissed}
        onDismiss={handleDismissOnboarding}
        onFocusPinned={handleFocusPinned}
      />

      <main className="content-grid">
        <SessionRail
          entries={sessionEntries}
          loading={loading}
          now={now}
          onSelect={handleSelectSession}
        />

        <section className="panel alerts-panel" aria-label="Blocked requests">
          <div className="panel-header">
            <h2>
              Blocked requests
              {activeSession ? ` · ${sessionLabel(activeSession)}` : ''}
            </h2>
            <span>
              {activeBatches.length} active alert{activeBatches.length === 1 ? '' : 's'}
            </span>
          </div>
          <div className="alert-list">
            {activeBatches.map((batch) => {
              const primary = batch.requests[0];
              const pending = Boolean(pendingBatchIds[batch.id]);
              const ttlValue = customTtls[batch.id] ?? '300';
              return (
                <article
                  className={`alert-card ${selectedBatch?.id === batch.id ? 'selected' : ''}`}
                  key={batch.id}
                >
                  <button className="card-button" onClick={() => setSelectedBatchId(batch.id)}>
                    <div>
                      <h3>{batch.host}</h3>
                      <p>
                        {batch.requests.length} related request{batch.requests.length === 1 ? '' : 's'} ·{' '}
                        {primary.method} {primary.path}
                      </p>
                    </div>
                    <span className="countdown">{formatCountdown(batch.timeRemainingMs)}</span>
                  </button>
                  <p className="explanation">{primary.explanation}</p>
                  <div className="actions-row">
                    <button disabled={pending} onClick={() => void submitDecision(batch, 'deny')}>
                      {actionLabel('deny')}
                    </button>
                    <button
                      disabled={pending}
                      onClick={() => void submitDecision(batch, 'allowOnce')}
                    >
                      {actionLabel('allowOnce')}
                    </button>
                    <button
                      disabled={pending}
                      onClick={() => void submitDecision(batch, 'allowSession')}
                    >
                      {actionLabel('allowSession')}
                    </button>
                    <button disabled={pending} onClick={() => void submitDecision(batch, 'persist')}>
                      {actionLabel('persist')}
                    </button>
                  </div>
                  <div className="ttl-row">
                    <input
                      aria-label={`TTL for ${batch.host}`}
                      inputMode="numeric"
                      value={ttlValue}
                      onChange={(event) =>
                        setCustomTtls((current) => ({ ...current, [batch.id]: event.target.value }))
                      }
                    />
                    <button
                      disabled={pending}
                      onClick={() =>
                        void submitDecision(batch, 'allowTtl', Math.max(1, Number.parseInt(ttlValue, 10) || 0))
                      }
                    >
                      {actionLabel('allowTtl')}
                    </button>
                    <span className="ttl-hint">seconds</span>
                  </div>
                  {pending ? <p className="pending-text">Applying decision…</p> : null}
                </article>
              );
            })}
            {!activeBatches.length && !loading ? (
              <p>
                {activeSession
                  ? 'No live blocked requests for this session.'
                  : 'Select a session from the rail to inspect its blocked requests.'}
              </p>
            ) : null}
          </div>
        </section>

        <aside className="panel detail-panel" aria-label="Request detail">
          <h2>Request detail</h2>
          {selectedBatch ? (
            <>
              <p>
                <strong>{selectedBatch.host}</strong> · {selectedBatch.requests[0].method}{' '}
                {selectedBatch.requests[0].path}
              </p>
              <p>{selectedBatch.requests[0].explanation}</p>
              <h3>Related requests</h3>
              <ul className="detail-list">
                {selectedBatch.requests.map((request) => (
                  <li key={request.blockedId}>
                    <strong>{request.blockedId}</strong>
                    <span>
                      {request.method} {request.path}
                    </span>
                    <span>{request.observedAt}</span>
                  </li>
                ))}
              </ul>
              <h3>Cedar suggestions</h3>
              <ul className="detail-list">
                {selectedBatch.requests[0].suggestions.map((suggestion) => (
                  <li key={`${suggestion.lifetime}:${suggestion.summary}`}>
                    <strong>{suggestion.lifetime}</strong>
                    <span>{suggestion.summary}</span>
                    <code>{suggestion.cedarSnippet}</code>
                  </li>
                ))}
              </ul>
              <h3>Raw event</h3>
              <pre>{selectedBatch.requests[0].rawJson}</pre>
            </>
          ) : (
            <p>Select an alert to inspect the Cedar explanation and raw request details.</p>
          )}
        </aside>
      </main>
    </div>
  );
}
