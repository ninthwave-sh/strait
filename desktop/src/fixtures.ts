import type { BlockedRequestSummary, DesktopSnapshot, SessionSummary } from './types';

function futureIso(seconds: number): string {
  return new Date(Date.now() + seconds * 1000).toISOString();
}

export function buildSession(partial: Partial<SessionSummary> = {}): SessionSummary {
  return {
    sessionId: partial.sessionId ?? 'session-1',
    mode: partial.mode ?? 'enforce',
    control: partial.control ?? { network: 'unix', address: '/tmp/control.sock' },
    observation: partial.observation ?? { network: 'unix', address: '/tmp/observe.sock' },
    containerId: partial.containerId ?? 'abc123',
    containerName: partial.containerName ?? 'strait-devcontainer'
  };
}

export function buildBlockedRequest(
  partial: Partial<BlockedRequestSummary> = {}
): BlockedRequestSummary {
  return {
    sessionId: partial.sessionId ?? 'session-1',
    blockedId: partial.blockedId ?? 'blocked-1',
    matchKey: partial.matchKey ?? 'http:GET api.github.com/repos/org/repo',
    sourceType: partial.sourceType ?? 'network_request',
    explanation: partial.explanation ?? 'Denied by policy read-only guardrail.',
    method: partial.method ?? 'GET',
    host: partial.host ?? 'api.github.com',
    path: partial.path ?? '/repos/org/repo',
    decision: partial.decision ?? 'deny',
    suggestions: partial.suggestions ?? [
      {
        lifetime: 'persist',
        summary: 'allow http:GET api.github.com/repos/org/repo',
        cedarSnippet:
          'permit(principal, action == Action::"http:GET", resource in Resource::"api.github.com/repos/org/repo");',
        scope: 'path_scoped',
        ambiguous: false
      }
    ],
    rawJson: partial.rawJson ?? '{"type":"network_request"}',
    observedAt: partial.observedAt ?? new Date().toISOString(),
    holdTimeoutSecs: partial.holdTimeoutSecs ?? 30,
    holdExpiresAt: partial.holdExpiresAt ?? futureIso(30)
  };
}

export function buildSnapshot(partial: Partial<DesktopSnapshot> = {}): DesktopSnapshot {
  return {
    enabled: partial.enabled ?? true,
    connected: partial.connected ?? true,
    serviceSocketPath: partial.serviceSocketPath ?? '/tmp/strait-control.sock',
    sessions: partial.sessions ?? [buildSession()],
    blockedRequests: partial.blockedRequests ?? [buildBlockedRequest()],
    lastError: partial.lastError ?? null
  };
}
