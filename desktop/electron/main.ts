import path from 'node:path';

import { app, BrowserWindow } from 'electron';

import { ControlPlane } from './controlClient';
import { FOCUS_SESSION_CHANNEL, registerIpcHandlers } from './ipc';
import { SessionTray } from './tray';
import type { DesktopSnapshot } from '../src/types';

const controlPlane = new ControlPlane();
let mainWindow: BrowserWindow | null = null;
let tray: SessionTray | null = null;
let isQuitting = false;

function rendererUrl() {
  return `file://${path.join(__dirname, '../dist/index.html')}`;
}

function showWindow() {
  if (!mainWindow) {
    return;
  }
  mainWindow.show();
  mainWindow.focus();
}

function focusSession(sessionId: string, blockedId?: string) {
  showWindow();
  mainWindow?.webContents.send(FOCUS_SESSION_CHANNEL, { sessionId, blockedId });
}

function createWindow() {
  mainWindow = new BrowserWindow({
    width: 1440,
    height: 960,
    title: 'Strait Desktop',
    autoHideMenuBar: true,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    }
  });

  mainWindow.on('close', (event) => {
    if (!isQuitting) {
      event.preventDefault();
      mainWindow?.hide();
    }
  });

  void mainWindow.loadURL(rendererUrl());
}

app.whenReady().then(() => {
  if (process.platform === 'darwin') {
    app.dock?.hide();
  }

  createWindow();
  tray = new SessionTray({
    showWindow,
    focusSession,
    setEnabled: (enabled) => controlPlane.setEnabled(enabled),
    quit: () => {
      isQuitting = true;
      app.quit();
    },
    getMostRecentPending: () => controlPlane.getMostRecentPending()
  });
  tray.update(controlPlane.getSnapshot());
  controlPlane.on('state', (snapshot: DesktopSnapshot) => {
    tray?.update(snapshot);
    mainWindow?.webContents.send('desktop:state-changed', snapshot);
  });
  controlPlane.start();
});

app.on('before-quit', () => {
  isQuitting = true;
  controlPlane.stop();
});

registerIpcHandlers({ controlPlane, showWindow });
