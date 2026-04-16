import type { DesktopSnapshot, SubmitDecisionInput, SubmitDecisionResult } from './types';

export interface DesktopBridge {
  getSnapshot(): Promise<DesktopSnapshot>;
  onStateChanged(listener: (snapshot: DesktopSnapshot) => void): () => void;
  submitDecision(input: SubmitDecisionInput): Promise<SubmitDecisionResult>;
  focusWindow(): Promise<void>;
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
  }
};

export function resolveBridge(override?: DesktopBridge): DesktopBridge {
  return override ?? window.desktopControl ?? fallbackBridge;
}
