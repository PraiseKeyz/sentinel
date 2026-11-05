import { contextBridge, ipcRenderer } from 'electron';
import type { SentinelApi, Snapshot } from '../shared/types';

const api: SentinelApi = {
  getSnapshot: () => ipcRenderer.invoke('snapshot'),
  saveServer: (input) => ipcRenderer.invoke('server:save', input),
  deleteServer: (id) => ipcRenderer.invoke('server:delete', id),
  testServer: (input) => ipcRenderer.invoke('server:test', input),
  importSshConfig: () => ipcRenderer.invoke('sshconfig:import'),
  saveSettings: (s) => ipcRenderer.invoke('settings:save', s),
  scanNow: (id) => ipcRenderer.invoke('scan', id),
  ban: (serverId, ip, reason) => ipcRenderer.invoke('ban', serverId, ip, reason),
  unban: (banId) => ipcRenderer.invoke('unban', banId),
  trustHostKey: (id) => ipcRenderer.invoke('hostkey:trust', id),
  pickKeyFile: () => ipcRenderer.invoke('pickKey'),
  onSnapshot: (cb) => {
    const listener = (_e: unknown, s: Snapshot) => cb(s);
    ipcRenderer.on('snapshot', listener);
    return () => ipcRenderer.removeListener('snapshot', listener);
  },
};

contextBridge.exposeInMainWorld('sentinel', api);
