import type { DesktopSnapshot, SubmitDecisionInput, SubmitDecisionResult } from './types';

export interface FocusSessionRequest {
  sessionId: string;
  blockedId?: string;
}

export interface DesktopBridge {
  getSnapshot(): Promise<DesktopSnapshot>;
  onStateChanged(listener: (snapshot: DesktopSnapshot) => void): () => void;
  submitDecision(input: SubmitDecisionInput): Promise<SubmitDecisionResult>;
  focusWindow(): Promise<void>;
  /**
   * Fires when the main process (typically the tray menu) asks the renderer
   * to activate a specific session. The optional `blockedId` points at a
   * specific pending decision to scroll into view. Returns an unsubscribe
   * function; callers must invoke it on cleanup to avoid leaks.
   */
  onFocusSession(listener: (request: FocusSessionRequest) => void): () => void;
}

declare global {
  interface Window {
    desktopControl?: DesktopBridge;
  }
}

const emptySnapshot: DesktopSnapshot = {
  enabled: false,
  connected: false,
  serviceSocketPath: '',
  sessions: [],
  blockedRequests: [],
  lastError: null
};

export const fallbackBridge: DesktopBridge = {
  async getSnapshot() {
    return emptySnapshot;
  },
  onStateChanged() {
    return () => undefined;
  },
  async submitDecision() {
    return { resolvedBlockedIds: [] };
  },
  async focusWindow() {
    return undefined;
  },
  onFocusSession() {
    return () => undefined;
  }
};

export function resolveBridge(override?: DesktopBridge): DesktopBridge {
  return override ?? window.desktopControl ?? fallbackBridge;
}
