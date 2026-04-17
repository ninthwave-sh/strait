import { contextBridge, ipcRenderer } from 'electron';

import type { DesktopBridge, FocusSessionRequest } from '../src/bridge';
import type { DesktopSnapshot, SubmitDecisionInput } from '../src/types';

const bridge: DesktopBridge = {
  getSnapshot() {
    return ipcRenderer.invoke('desktop:get-snapshot');
  },
  onStateChanged(listener) {
    const wrapped = (_event: Electron.IpcRendererEvent, snapshot: DesktopSnapshot) => {
      listener(snapshot);
    };
    ipcRenderer.on('desktop:state-changed', wrapped);
    return () => ipcRenderer.removeListener('desktop:state-changed', wrapped);
  },
  submitDecision(input: SubmitDecisionInput) {
    return ipcRenderer.invoke('desktop:submit-decision', input);
  },
  focusWindow() {
    return ipcRenderer.invoke('desktop:focus-window');
  },
  onFocusSession(listener) {
    const wrapped = (_event: Electron.IpcRendererEvent, request: FocusSessionRequest) => {
      listener(request);
    };
    ipcRenderer.on('desktop:focus-session', wrapped);
    return () => ipcRenderer.removeListener('desktop:focus-session', wrapped);
  }
};

contextBridge.exposeInMainWorld('desktopControl', bridge);
