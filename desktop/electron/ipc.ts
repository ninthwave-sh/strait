import { ipcMain } from 'electron';

import type { ControlPlane } from './controlClient';
import type { SubmitDecisionInput } from '../src/types';

export interface IpcDependencies {
  controlPlane: ControlPlane;
  showWindow(): void;
}

/**
 * Register the renderer-facing IPC surface. Exposed as a standalone module
 * so the tray (main-process only) can dispatch focus-session events onto
 * the same channel without reaching back into a bag of closures in main.ts.
 */
export function registerIpcHandlers({ controlPlane, showWindow }: IpcDependencies) {
  ipcMain.handle('desktop:get-snapshot', () => controlPlane.getSnapshot());
  ipcMain.handle('desktop:submit-decision', (_event, input: SubmitDecisionInput) =>
    controlPlane.submitDecision(input)
  );
  ipcMain.handle('desktop:focus-window', async () => {
    showWindow();
  });
}

/**
 * Channel name for main → renderer focus requests. Centralised so the
 * tray, main window, and preload all agree on a single string.
 */
export const FOCUS_SESSION_CHANNEL = 'desktop:focus-session';
