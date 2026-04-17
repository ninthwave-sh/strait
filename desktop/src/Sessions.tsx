import type { SessionSummary } from './types';

export interface SessionRailEntry {
  session: SessionSummary;
  /** Number of live blocked requests awaiting a decision for this session. */
  pendingCount: number;
  /**
   * True when a new blocked request for this session landed while the
   * session was not focused. Lets the rail surface an unread-style badge
   * without hijacking focus.
   */
  alerted: boolean;
  /** True for the session currently bound to the right-hand detail pane. */
  active: boolean;
}

export interface SessionRailProps {
  entries: SessionRailEntry[];
  loading: boolean;
  now: number;
  onSelect: (sessionId: string) => void;
}

export function formatUptime(uptimeMs: number): string {
  const totalSeconds = Math.max(0, Math.floor(uptimeMs / 1000));
  if (totalSeconds < 60) {
    return `${totalSeconds}s`;
  }
  const totalMinutes = Math.floor(totalSeconds / 60);
  if (totalMinutes < 60) {
    const seconds = totalSeconds % 60;
    return seconds === 0 ? `${totalMinutes}m` : `${totalMinutes}m ${seconds}s`;
  }
  const totalHours = Math.floor(totalMinutes / 60);
  const minutes = totalMinutes % 60;
  return minutes === 0 ? `${totalHours}h` : `${totalHours}h ${minutes}m`;
}

export function sessionLabel(session: SessionSummary): string {
  if (session.containerName && session.containerName.length > 0) {
    return session.containerName;
  }
  return session.sessionId;
}

export function SessionRail({ entries, loading, now, onSelect }: SessionRailProps) {
  const totalPending = entries.reduce((sum, entry) => sum + entry.pendingCount, 0);

  return (
    <aside className="panel sessions-panel" aria-label="Sessions">
      <div className="panel-header">
        <h2>Sessions</h2>
        <span className="rail-summary" aria-live="polite">
          {entries.length} active · {totalPending} pending
        </span>
      </div>
      {loading ? <p>Loading…</p> : null}
      {!entries.length && !loading ? <p>No sessions registered.</p> : null}
      <ul className="session-list">
        {entries.map((entry) => {
          const uptimeMs = entry.session.firstSeenAtUnixMs
            ? Math.max(0, now - entry.session.firstSeenAtUnixMs)
            : 0;
          const label = sessionLabel(entry.session);
          const pendingAria =
            entry.pendingCount > 0
              ? `${entry.pendingCount} pending decision${entry.pendingCount === 1 ? '' : 's'}`
              : 'no pending decisions';
          const classes = [
            'session-row',
            entry.active ? 'active' : '',
            entry.alerted ? 'alerted' : ''
          ]
            .filter(Boolean)
            .join(' ');
          return (
            <li key={entry.session.sessionId}>
              <button
                type="button"
                className={classes}
                aria-pressed={entry.active}
                aria-label={`Focus session ${label}; ${pendingAria}`}
                onClick={() => onSelect(entry.session.sessionId)}
              >
                <div className="session-row-main">
                  <strong className="session-row-label">{label}</strong>
                  <span className="session-row-mode">{entry.session.mode}</span>
                </div>
                <div className="session-row-meta">
                  <span className="session-row-uptime" title="Uptime since first seen">
                    {formatUptime(uptimeMs)}
                  </span>
                  {entry.pendingCount > 0 ? (
                    <span
                      className={`session-row-badge ${entry.alerted ? 'alerted' : ''}`}
                      aria-label={pendingAria}
                    >
                      {entry.pendingCount}
                    </span>
                  ) : null}
                </div>
              </button>
            </li>
          );
        })}
      </ul>
    </aside>
  );
}
