import path from 'node:path';

import { app, BrowserWindow, ipcMain, Menu, Tray, nativeImage } from 'electron';

import { ControlPlane } from './controlClient';
import type { DesktopSnapshot, SubmitDecisionInput } from '../src/types';

const controlPlane = new ControlPlane();
let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let isQuitting = false;

function trayIcon() {
  const svg = encodeURIComponent(`
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
      <rect x="2" y="2" width="20" height="20" rx="6" fill="#0f172a"/>
      <circle cx="12" cy="12" r="5" fill="#38bdf8"/>
    </svg>
  `);
  return nativeImage.createFromDataURL(`data:image/svg+xml;charset=utf-8,${svg}`);
}

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

function updateTray(snapshot: DesktopSnapshot) {
  if (!tray) {
    return;
  }

  const sessionItems = snapshot.sessions.length
    ? snapshot.sessions.map((session) => ({
        label: `${session.sessionId} · ${session.mode}`,
        click: () => showWindow()
      }))
    : [{ label: 'No active sessions', enabled: false }];

  tray.setToolTip(
    snapshot.connected
      ? `Strait Desktop · ${snapshot.sessions.length} session(s)`
      : 'Strait Desktop · waiting for control service'
  );
  tray.setContextMenu(
    Menu.buildFromTemplate([
      { label: 'Open Strait Desktop', click: () => showWindow() },
      { type: 'separator' },
      { label: 'Sessions', submenu: sessionItems },
      {
        label: 'Enable control plane',
        type: 'checkbox',
        checked: snapshot.enabled,
        click: () => controlPlane.setEnabled(!snapshot.enabled)
      },
      { label: 'Preferences', click: () => showWindow() },
      { type: 'separator' },
      {
        label: 'Quit',
        click: () => {
          isQuitting = true;
          app.quit();
        }
      }
    ])
  );
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
  tray = new Tray(trayIcon());
  updateTray(controlPlane.getSnapshot());
  controlPlane.on('state', (snapshot: DesktopSnapshot) => {
    updateTray(snapshot);
    mainWindow?.webContents.send('desktop:state-changed', snapshot);
  });
  controlPlane.start();
});

app.on('before-quit', () => {
  isQuitting = true;
  controlPlane.stop();
});

ipcMain.handle('desktop:get-snapshot', () => controlPlane.getSnapshot());
ipcMain.handle('desktop:submit-decision', (_event, input: SubmitDecisionInput) =>
  controlPlane.submitDecision(input)
);
ipcMain.handle('desktop:focus-window', async () => {
  showWindow();
});
