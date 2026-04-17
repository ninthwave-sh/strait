import { Menu, nativeImage, Tray } from 'electron';
import type { MenuItemConstructorOptions } from 'electron';

import type { DesktopSnapshot } from '../src/types';

export interface TrayActions {
  showWindow(): void;
  focusSession(sessionId: string, blockedId?: string): void;
  setEnabled(enabled: boolean): void;
  quit(): void;
  /**
   * Main-process hook to return the most recent pending decision, if any.
   * Kept as a callback (rather than a snapshot field) so the menu builder
   * always reads the freshest value at the moment the operator opens the
   * tray.
   */
  getMostRecentPending(): { sessionId: string; blockedId: string } | null;
}

export interface SessionDerivedCounts {
  /** Count of live blocked requests per session id. */
  byId: Map<string, number>;
  /** Sum across all sessions. */
  total: number;
}

export function deriveSessionCounts(snapshot: DesktopSnapshot): SessionDerivedCounts {
  const byId = new Map<string, number>();
  for (const request of snapshot.blockedRequests) {
    if (!request.sessionId) {
      continue;
    }
    byId.set(request.sessionId, (byId.get(request.sessionId) ?? 0) + 1);
  }
  const total = Array.from(byId.values()).reduce((sum, count) => sum + count, 0);
  return { byId, total };
}

function baseIconSvg(pendingBadge: boolean): string {
  const dot = pendingBadge
    ? '<circle cx="19" cy="5" r="4" fill="#f97316" stroke="#0f172a" stroke-width="1"/>'
    : '';
  return `
    <svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24">
      <rect x="2" y="2" width="20" height="20" rx="6" fill="#0f172a"/>
      <circle cx="12" cy="12" r="5" fill="#38bdf8"/>
      ${dot}
    </svg>
  `;
}

/**
 * Builds the dynamic tray icon. A small orange dot is overlaid on top of
 * the base glyph whenever any session has a pending decision; the icon is
 * otherwise stable so operators can tell at a glance whether the control
 * plane wants attention.
 */
export function trayIconImage(totalPending: number) {
  const svg = encodeURIComponent(baseIconSvg(totalPending > 0));
  return nativeImage.createFromDataURL(`data:image/svg+xml;charset=utf-8,${svg}`);
}

export function buildTrayTooltip(snapshot: DesktopSnapshot, totalPending: number): string {
  if (!snapshot.connected) {
    return 'Strait Desktop · waiting for control service';
  }
  const sessionCount = snapshot.sessions.length;
  const sessionPart = `${sessionCount} session${sessionCount === 1 ? '' : 's'}`;
  const pendingPart =
    totalPending === 0
      ? 'no pending decisions'
      : `${totalPending} pending decision${totalPending === 1 ? '' : 's'}`;
  return `Strait Desktop · ${sessionPart} · ${pendingPart}`;
}

function sessionLabel(sessionId: string, containerName: string | undefined): string {
  if (containerName && containerName.length > 0) {
    return containerName;
  }
  return sessionId;
}

/**
 * Pure menu template builder. Exported so it can be unit-tested without
 * booting Electron. `Menu.buildFromTemplate` consumes the result at
 * runtime, but the shape is intentionally plain data.
 */
export function buildTrayMenuTemplate(
  snapshot: DesktopSnapshot,
  actions: TrayActions
): MenuItemConstructorOptions[] {
  const { byId: countsById, total } = deriveSessionCounts(snapshot);
  const mostRecent = actions.getMostRecentPending();

  const sessionItems: MenuItemConstructorOptions[] = snapshot.sessions.length
    ? snapshot.sessions.map((session) => {
        const count = countsById.get(session.sessionId) ?? 0;
        const label = sessionLabel(session.sessionId, session.containerName);
        return {
          label: count > 0 ? `${label} · ${count} pending` : label,
          click: () => actions.focusSession(session.sessionId)
        };
      })
    : [{ label: 'No active sessions', enabled: false }];

  const quickResume: MenuItemConstructorOptions = mostRecent
    ? {
        label: `Resume latest pending decision (${total})`,
        click: () => actions.focusSession(mostRecent.sessionId, mostRecent.blockedId)
      }
    : {
        label: 'No pending decisions',
        enabled: false
      };

  return [
    { label: 'Open Strait Desktop', click: () => actions.showWindow() },
    quickResume,
    { type: 'separator' },
    { label: 'Sessions', submenu: sessionItems },
    {
      label: 'Enable control plane',
      type: 'checkbox',
      checked: snapshot.enabled,
      click: () => actions.setEnabled(!snapshot.enabled)
    },
    { label: 'Preferences', click: () => actions.showWindow() },
    { type: 'separator' },
    {
      label: 'Quit',
      click: () => actions.quit()
    }
  ];
}

export class SessionTray {
  private readonly tray: Tray;

  constructor(private readonly actions: TrayActions) {
    this.tray = new Tray(trayIconImage(0));
  }

  update(snapshot: DesktopSnapshot) {
    const { total } = deriveSessionCounts(snapshot);
    this.tray.setImage(trayIconImage(total));
    this.tray.setToolTip(buildTrayTooltip(snapshot, total));
    this.tray.setContextMenu(Menu.buildFromTemplate(buildTrayMenuTemplate(snapshot, this.actions)));
  }
}
