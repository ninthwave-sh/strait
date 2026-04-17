export type DecisionAction = 'deny' | 'allowOnce' | 'allowSession' | 'persist' | 'allowTtl';

export interface SessionEndpoint {
  network: string;
  address: string;
}

export interface SessionSummary {
  sessionId: string;
  mode: string;
  control?: SessionEndpoint;
  observation?: SessionEndpoint;
  containerId?: string;
  containerName?: string;
  /**
   * Millisecond wall-clock timestamp of the first moment the desktop shell
   * saw this session in a ListSessions response. Used to render session
   * uptime in the rail; absent entries are treated as "just seen".
   *
   * Populated by the main-process ControlPlane, not by the control service,
   * because the existing SessionControlService proto has no registered_at
   * field. The in-process tracker is stable for the lifetime of the desktop
   * app; restarting the app resets it.
   */
  firstSeenAtUnixMs?: number;
}

export interface ExceptionSuggestion {
  lifetime: string;
  summary: string;
  cedarSnippet: string;
  scope: string;
  ambiguous: boolean;
}

export interface BlockedRequestSummary {
  sessionId: string;
  blockedId: string;
  matchKey: string;
  sourceType: string;
  explanation: string;
  method: string;
  host: string;
  path: string;
  decision: string;
  suggestions: ExceptionSuggestion[];
  rawJson: string;
  observedAt: string;
  holdTimeoutSecs: number;
  holdExpiresAt: string;
}

export interface DesktopSnapshot {
  enabled: boolean;
  connected: boolean;
  serviceSocketPath: string;
  sessions: SessionSummary[];
  blockedRequests: BlockedRequestSummary[];
  lastError: string | null;
}

export interface SubmitDecisionInput {
  sessionId: string;
  blockedIds: string[];
  action: DecisionAction;
  ttlSeconds?: number;
}

export interface SubmitDecisionResult {
  resolvedBlockedIds: string[];
}

export interface BlockedBatch {
  id: string;
  sessionId: string;
  host: string;
  requests: BlockedRequestSummary[];
  blockedIds: string[];
  timeRemainingMs: number;
}
