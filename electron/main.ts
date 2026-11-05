import { randomUUID } from 'node:crypto';
import { homedir } from 'node:os';
import { join } from 'node:path';
import { app, BrowserWindow, dialog, ipcMain, Notification, safeStorage, shell } from 'electron';
import type { ServerConfig, ServerInput, Settings } from '../shared/types';
import { Engine } from './engine';
import { readSshConfig } from './sshconfig';
import { Store } from './store';

let win: BrowserWindow | null = null;
let store: Store;
let engine: Engine;

function encrypt(text: string): string {
  if (!safeStorage.isEncryptionAvailable()) throw new Error('OS keychain encryption is not available; cannot store a passphrase.');
  return safeStorage.encryptString(text).toString('base64');
}

function decrypt(id: string): string | undefined {
  const b64 = store.data.secrets[id];
  if (!b64) return undefined;
  try {
    return safeStorage.decryptString(Buffer.from(b64, 'base64'));
  } catch {
    return undefined;
  }
}

let pending = false;
function broadcast() {
  // Coalesce bursts of changes into one push per tick.
  if (pending) return;
  pending = true;
  setImmediate(() => {
    pending = false;
    win?.webContents.send('snapshot', engine.snapshot());
  });
}

function sanitizeServer(input: ServerInput, existing?: ServerConfig): ServerConfig {
  const name = String(input.name ?? '').trim();
  const host = String(input.host ?? '').trim();
  const username = String(input.username ?? '').trim();
  if (!host) throw new Error('Host is required');
  if (!username) throw new Error('Username is required');
  const port = Number(input.port) || 22;
  if (port < 1 || port > 65535) throw new Error('Port must be 1–65535');
  return {
    id: existing?.id ?? randomUUID(),
    name: name || host,
    host,
    port,
    username,
    keyPath: String(input.keyPath ?? '').trim(),
    hasPassphrase: existing?.hasPassphrase ?? false,
    banJail: String(input.banJail ?? 'sshd').trim() || 'sshd',
    tags: Array.isArray(input.tags) ? input.tags.map(String).filter(Boolean) : [],
  };
}

function sanitizeSettings(s: Settings): Settings {
  const clamp = (v: unknown, min: number, max: number, d: number) => {
    const n = Number(v);
    return Number.isFinite(n) ? Math.min(max, Math.max(min, n)) : d;
  };
  const cur = store.data.settings;
  const t = s.thresholds ?? cur.thresholds;
  return {
    scanIntervalSec: clamp(s.scanIntervalSec, 15, 3600, cur.scanIntervalSec),
    lookbackMinutes: clamp(s.lookbackMinutes, 5, 1440, cur.lookbackMinutes),
    autoBan: Boolean(s.autoBan),
    fleetBan: Boolean(s.fleetBan),
    notifications: Boolean(s.notifications),
    whitelist: (s.whitelist ?? []).map((w) => String(w).trim()).filter(Boolean),
    thresholds: {
      failedLogins: clamp(t.failedLogins, 1, 10000, cur.thresholds.failedLogins),
      connectionsPerIp: clamp(t.connectionsPerIp, 5, 100000, cur.thresholds.connectionsPerIp),
      synRecv: clamp(t.synRecv, 10, 1000000, cur.thresholds.synRecv),
      httpRequestsPerIp: clamp(t.httpRequestsPerIp, 10, 20000, cur.thresholds.httpRequestsPerIp),
      diskPercent: clamp(t.diskPercent, 50, 100, cur.thresholds.diskPercent),
      memPercent: clamp(t.memPercent, 50, 100, cur.thresholds.memPercent),
      loadPerCore: clamp(t.loadPerCore, 0.1, 50, cur.thresholds.loadPerCore),
    },
  };
}

function registerIpc() {
  ipcMain.handle('snapshot', () => engine.snapshot());

  ipcMain.handle('server:save', (_e, input: ServerInput) => {
    const existing = input.id ? store.data.servers.find((s) => s.id === input.id) : undefined;
    const server = sanitizeServer(input, existing);
    if (input.passphrase !== undefined) {
      if (input.passphrase) {
        store.data.secrets[server.id] = encrypt(input.passphrase);
        server.hasPassphrase = true;
      } else {
        delete store.data.secrets[server.id];
        server.hasPassphrase = false;
      }
    }
    if (existing) {
      // A new address means a new machine: forget its trusted host key.
      if (existing.host !== server.host || existing.port !== server.port) delete store.data.hostKeys[server.id];
      Object.assign(existing, server);
    } else {
      store.data.servers.push(server);
    }
    store.save();
    engine.forget(server.id);
    void engine.scanOne(server.id);
    broadcast();
    return server;
  });

  ipcMain.handle('server:delete', (_e, id: string) => {
    store.data.servers = store.data.servers.filter((s) => s.id !== id);
    delete store.data.secrets[id];
    delete store.data.hostKeys[id];
    store.save();
    engine.forget(id);
    broadcast();
  });

  ipcMain.handle('server:test', async (_e, input: ServerInput) => {
    try {
      const existing = input.id ? store.data.servers.find((s) => s.id === input.id) : undefined;
      const server = sanitizeServer(input, existing);
      const passphrase = input.passphrase !== undefined ? input.passphrase || undefined : undefined;
      const info = await engine.pool.test(engine.target(server, passphrase));
      return { ok: true, message: `Connected: ${info}` };
    } catch (err) {
      return { ok: false, message: err instanceof Error ? err.message : String(err) };
    }
  });

  ipcMain.handle('sshconfig:import', () => readSshConfig());

  ipcMain.handle('settings:save', (_e, s: Settings) => {
    store.data.settings = sanitizeSettings(s);
    store.save();
    broadcast();
    return store.data.settings;
  });

  ipcMain.handle('scan', async (_e, id?: string) => {
    if (id) await engine.scanOne(id);
    else await engine.scanAll();
  });

  ipcMain.handle('ban', (_e, serverId: string, ip: string, reason: string) => engine.ban(serverId, ip, reason, false));
  ipcMain.handle('unban', (_e, banId: string) => engine.unban(banId));

  ipcMain.handle('hostkey:trust', (_e, id: string) => {
    delete store.data.hostKeys[id];
    store.save();
    engine.forget(id);
    void engine.scanOne(id);
  });

  ipcMain.handle('pickKey', async () => {
    const res = await dialog.showOpenDialog(win!, {
      title: 'Choose a private key',
      defaultPath: join(homedir(), '.ssh'),
      properties: ['openFile', 'showHiddenFiles'],
    });
    return res.canceled ? null : res.filePaths[0];
  });
}

function createWindow() {
  win = new BrowserWindow({
    width: 1360,
    height: 860,
    minWidth: 980,
    minHeight: 620,
    backgroundColor: '#0b0f14',
    title: 'Sentinel',
    titleBarStyle: process.platform === 'darwin' ? 'hiddenInset' : 'default',
    webPreferences: {
      preload: join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
      sandbox: true,
    },
  });
  win.setMenuBarVisibility(false);
  win.webContents.setWindowOpenHandler(({ url }) => {
    if (/^https?:\/\//.test(url)) void shell.openExternal(url);
    return { action: 'deny' };
  });
  const devUrl = process.env.VITE_DEV_SERVER_URL;
  if (devUrl) void win.loadURL(devUrl);
  else void win.loadFile(join(__dirname, '..', '..', 'dist', 'index.html'));
  win.on('closed', () => (win = null));
}

app.setAppUserModelId('com.comracsoftwares.sentinel');

app.whenReady().then(() => {
  store = new Store(join(app.getPath('userData'), 'sentinel.json'));
  engine = new Engine(store, {
    decryptPassphrase: decrypt,
    notify: (title, body) => {
      if (Notification.isSupported()) new Notification({ title, body }).show();
    },
    onChange: broadcast,
  });
  registerIpc();
  createWindow();
  engine.start();
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow();
  });
});

// Keep monitoring on macOS when the window is closed, like other menu-bar style tools.
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') app.quit();
});

app.on('before-quit', () => engine?.stop());
