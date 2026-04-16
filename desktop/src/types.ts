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
