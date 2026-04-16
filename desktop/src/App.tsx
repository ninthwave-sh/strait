import { useEffect, useMemo, useState } from 'react';

import { resolveBridge, type DesktopBridge } from './bridge';
import type {
  BlockedBatch,
  BlockedRequestSummary,
  DecisionAction,
  DesktopSnapshot
} from './types';

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
        Math.min(...requests.map((request) => parseTime(request.holdExpiresAt) || now)) - now
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

export function App({ bridge: providedBridge }: { bridge?: DesktopBridge }) {
  const bridge = useMemo(() => resolveBridge(providedBridge), [providedBridge]);
  const [snapshot, setSnapshot] = useState<DesktopSnapshot>(EMPTY_SNAPSHOT);
  const [loading, setLoading] = useState(true);
  const [now, setNow] = useState(() => Date.now());
  const [selectedBatchId, setSelectedBatchId] = useState<string | null>(null);
  const [pendingBatchIds, setPendingBatchIds] = useState<Record<string, true>>({});
  const [hiddenBlockedIds, setHiddenBlockedIds] = useState<Record<string, true>>({});
  const [customTtls, setCustomTtls] = useState<Record<string, string>>({});
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

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

  const visibleRequests = useMemo(
    () => snapshot.blockedRequests.filter((request) => !hiddenBlockedIds[request.blockedId]),
    [hiddenBlockedIds, snapshot.blockedRequests]
  );
  const batches = useMemo(() => buildBlockedBatches(visibleRequests, now), [now, visibleRequests]);
  const selectedBatch = batches.find((batch) => batch.id === selectedBatchId) ?? batches[0] ?? null;

  useEffect(() => {
    if (selectedBatch && selectedBatch.id !== selectedBatchId) {
      setSelectedBatchId(selectedBatch.id);
    }
    if (!selectedBatch) {
      setSelectedBatchId(null);
    }
  }, [selectedBatch, selectedBatchId]);

  async function submitDecision(
    batch: BlockedBatch,
    action: DecisionAction,
    ttlSeconds?: number
  ) {
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
    } catch (error) {
      setErrorMessage(error instanceof Error ? error.message : 'Decision failed.');
    } finally {
      setPendingBatchIds((current) => {
        const next = { ...current };
        delete next[batch.id];
        return next;
      });
    }
  }

  useEffect(() => {
    for (const batch of batches) {
      if (batch.timeRemainingMs <= 0 && !pendingBatchIds[batch.id]) {
        void submitDecision(batch, 'deny');
        break;
      }
    }
  }, [batches, pendingBatchIds]);

  return (
    <div className="app-shell">
      <header className="header">
        <div>
          <h1>Strait Desktop</h1>
          <p className="subhead">Thin shell over the live gRPC control service.</p>
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

      <main className="content-grid">
        <aside className="panel sessions-panel">
          <h2>Sessions</h2>
          {loading ? <p>Loading…</p> : null}
          <ul className="session-list">
            {snapshot.sessions.map((session) => (
              <li key={session.sessionId}>
                <strong>{session.sessionId}</strong>
                <span>{session.mode}</span>
                <span>{session.containerName || 'No container name'}</span>
              </li>
            ))}
          </ul>
          {!snapshot.sessions.length && !loading ? <p>No sessions published.</p> : null}
        </aside>

        <section className="panel alerts-panel">
          <div className="panel-header">
            <h2>Blocked requests</h2>
            <span>{batches.length} active alert{batches.length === 1 ? '' : 's'}</span>
          </div>
          <div className="alert-list">
            {batches.map((batch) => {
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
            {!batches.length && !loading ? <p>No live blocked requests.</p> : null}
          </div>
        </section>

        <aside className="panel detail-panel">
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
