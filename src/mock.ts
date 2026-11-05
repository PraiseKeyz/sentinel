// Demo data so the UI can be previewed in a browser without Electron or real servers.
import { DEFAULT_SETTINGS, type HistoryPoint, type Metrics, type ScanResult, type SentinelApi, type ServerConfig, type Snapshot } from '../shared/types';

const GB = 1024 ** 3;

function metrics(over: Partial<Metrics>): Metrics {
  return {
    hostname: 'host',
    kernel: 'Linux 6.8.0-45-generic',
    uptime: '12 days, 4 hours',
    cpus: 4,
    load: [0.4, 0.5, 0.6],
    memTotal: 8 * GB,
    memUsed: 3.1 * GB,
    swapTotal: 2 * GB,
    swapUsed: 0.1 * GB,
    disks: [{ mount: '/', size: 80 * GB, used: 31 * GB, percent: 39 }],
    tcpEstablished: 42,
    synRecv: 0,
    listening: [
      { proto: 'tcp', local: '0.0.0.0:22', process: 'sshd' },
      { proto: 'tcp', local: '*:443', process: 'nginx' },
      { proto: 'tcp', local: '127.0.0.1:5432', process: 'postgres' },
    ],
    topConnIps: [{ ip: '41.58.10.2', count: 2 }],
    failedLoginIps: [],
    acceptedLogins: [{ user: 'deploy', ip: '41.58.10.2', method: 'publickey' }],
    httpTopIps: [],
    httpLogPath: '/var/log/nginx/access.log',
    martians: 0,
    rpFilter: 1,
    syncookies: 1,
    uid0Users: ['root'],
    suspiciousProcs: [],
    topProcs: [
      { pid: 900, user: 'www-data', cpu: 6.2, mem: 1.8, cmd: 'nginx' },
      { pid: 1402, user: 'postgres', cpu: 3.1, mem: 4.4, cmd: 'postgres' },
      { pid: 812, user: 'root', cpu: 0.1, mem: 0.2, cmd: 'sshd' },
    ],
    fail2ban: { installed: true, accessible: true, jails: [{ name: 'sshd', currentlyBanned: 3, totalBanned: 118, bannedIps: ['192.0.2.99', '192.0.2.98', '198.51.100.4'] }] },
    arpDuplicates: [],
    gatewayIp: '10.0.0.1',
    gatewayMac: 'aa:bb:cc:dd:ee:01',
    rebootRequired: false,
    clientIp: '41.58.10.2',
    sudo: true,
    ...over,
  };
}

const servers: ServerConfig[] = [
  { id: 'a', name: 'api-prod-1', host: '203.0.113.10', port: 22, username: 'deploy', keyPath: '~/.ssh/id_ed25519', hasPassphrase: false, banJail: 'sshd', tags: ['prod'] },
  { id: 'b', name: 'web-edge', host: 'edge.example.com', port: 22, username: 'deploy', keyPath: '~/.ssh/id_ed25519', hasPassphrase: false, banJail: 'sshd', tags: ['prod'] },
  { id: 'c', name: 'db-primary', host: '10.20.0.5', port: 2222, username: 'ops', keyPath: '', hasPassphrase: false, banJail: 'sshd', tags: ['db'] },
  { id: 'd', name: 'staging', host: '198.51.100.40', port: 22, username: 'root', keyPath: '~/.ssh/id_ed25519', hasPassphrase: false, banJail: 'sshd', tags: ['staging'] },
];

function results(): Record<string, ScanResult> {
  const now = Date.now();
  return {
    a: { serverId: 'a', at: now - 8000, durationMs: 840, state: 'healthy', score: 99, metrics: metrics({ hostname: 'api-prod-1' }), findings: [
      { id: 'health:reboot', severity: 'info', category: 'health', title: 'Reboot required', detail: 'Installed updates (often a kernel or libc) only take effect after a reboot.' },
    ] },
    b: { serverId: 'b', at: now - 5000, durationMs: 1210, state: 'critical', score: 34, metrics: metrics({
      hostname: 'web-edge', load: [7.8, 6.1, 3.2], tcpEstablished: 1840, synRecv: 412,
      topConnIps: [{ ip: '203.0.113.77', count: 612 }, { ip: '198.51.100.23', count: 188 }, { ip: '41.58.10.2', count: 2 }],
      failedLoginIps: [{ ip: '185.220.101.4', count: 214 }, { ip: '45.155.205.12', count: 38 }, { ip: '192.0.2.5', count: 4 }],
      httpTopIps: [{ ip: '203.0.113.77', count: 9120 }, { ip: '66.249.66.1', count: 410 }],
      martians: 31,
    }), findings: [
      { id: 'dos:synflood', severity: 'critical', category: 'dos', title: 'Possible SYN flood: 412 half-open connections', detail: 'TCP SYN cookies are on, which helps. Spoofed SYN sources cannot be banned by IP; consider upstream filtering.' },
      { id: 'dos:http:203.0.113.77', severity: 'critical', category: 'dos', title: 'HTTP flood from 203.0.113.77', detail: '9120 requests in the last 20,000 lines of /var/log/nginx/access.log.', ip: '203.0.113.77', bannable: true },
      { id: 'bruteforce:185.220.101.4', severity: 'warning', category: 'bruteforce', title: 'SSH brute force from 185.220.101.4', detail: '214 failed or invalid SSH logins in the last 60 min.', ip: '185.220.101.4', bannable: true },
      { id: 'dos:conn:203.0.113.77', severity: 'warning', category: 'dos', title: 'Connection flood from 203.0.113.77', detail: '612 established TCP connections from one address.', ip: '203.0.113.77', bannable: true },
      { id: 'health:load', severity: 'warning', category: 'health', title: 'High load: 7.80 on 4 CPUs', detail: '1-minute load is 1.95× the core count. Top process: nginx (88% CPU).' },
      { id: 'spoofing:martians', severity: 'info', category: 'spoofing', title: '31 martian packets logged', detail: 'The kernel saw packets with impossible source addresses for their interface, a typical sign of IP spoofing.' },
    ] },
    c: { serverId: 'c', at: now - 12000, durationMs: 650, state: 'warning', score: 84, metrics: metrics({
      hostname: 'db-primary', disks: [{ mount: '/', size: 40 * GB, used: 37.2 * GB, percent: 93 }, { mount: '/var/lib/postgresql', size: 500 * GB, used: 210 * GB, percent: 42 }],
      rpFilter: 0, fail2ban: { installed: false, accessible: false, jails: [] }, httpLogPath: null,
    }), findings: [
      { id: 'health:disk:/', severity: 'warning', category: 'health', title: 'Disk / at 93%', detail: '37.2 of 40.0 GB used. A full disk can stop logging, databases and fail2ban itself.' },
      { id: 'fail2ban:missing', severity: 'warning', category: 'fail2ban', title: 'fail2ban is not installed', detail: 'Automatic bans need fail2ban. Install: apt install fail2ban (Debian/Ubuntu) or dnf install fail2ban (RHEL).' },
      { id: 'hardening:rpfilter', severity: 'warning', category: 'hardening', title: 'Reverse-path filtering is off', detail: 'Without rp_filter the kernel accepts packets with spoofed source IPs. Fix: sysctl -w net.ipv4.conf.all.rp_filter=1' },
    ] },
    d: { serverId: 'd', at: now - 3000, durationMs: 15000, state: 'unreachable', score: 0, error: 'Timed out while waiting for handshake', findings: [] },
  };
}

function history(seed: number, base: number, spike = false): HistoryPoint[] {
  const now = Date.now();
  return Array.from({ length: 60 }, (_, i) => {
    const wave = Math.sin((i + seed) / 5) * 0.08 + Math.random() * 0.05;
    const surge = spike && i > 44 ? (i - 44) * 0.12 : 0;
    return {
      t: now - (60 - i) * 60000,
      load: Math.max(0, base + wave + surge),
      mem: 0.38 + wave / 2,
      conns: Math.round(40 + wave * 100 + (spike && i > 44 ? (i - 44) * 120 : 0)),
      failed: spike ? Math.round(i * 4 + Math.random() * 10) : 0,
    };
  });
}

export function mockApi(): SentinelApi {
  const listeners = new Set<(s: Snapshot) => void>();
  const snap: Snapshot = {
    servers,
    settings: DEFAULT_SETTINGS,
    results: results(),
    history: { a: history(1, 0.15), b: history(3, 0.5, true), c: history(7, 0.3) },
    bans: [
      { id: 'x1', at: Date.now() - 60000, serverId: 'b', serverName: 'web-edge', ip: '45.155.205.12', jail: 'sshd', reason: 'SSH brute force from 45.155.205.12', auto: true, ok: true },
      { id: 'x2', at: Date.now() - 3600000, serverId: 'a', serverName: 'api-prod-1', ip: '198.51.100.4', jail: 'sshd', reason: 'SSH brute force from 198.51.100.4', auto: true, ok: true },
      { id: 'x3', at: Date.now() - 7200000, serverId: 'c', serverName: 'db-primary', ip: '192.0.2.200', jail: 'sshd', reason: 'Manual ban', auto: false, ok: false, error: 'fail2ban-client: command not found' },
    ],
    scanning: [],
    nextScanAt: Date.now() + 42000,
  };
  const emit = () => listeners.forEach((l) => l({ ...snap }));
  return {
    getSnapshot: async () => snap,
    saveServer: async (input) => {
      const s = { ...input, id: input.id ?? String(Date.now()), hasPassphrase: !!input.passphrase } as ServerConfig;
      snap.servers = [...snap.servers.filter((x) => x.id !== s.id), s];
      emit();
      return s;
    },
    deleteServer: async (id) => {
      snap.servers = snap.servers.filter((s) => s.id !== id);
      emit();
    },
    testServer: async () => ({ ok: true, message: 'Demo mode: no real connection made.' }),
    importSshConfig: async () => [{ alias: 'example', host: '203.0.113.99', port: 22, username: 'deploy', keyPath: '~/.ssh/id_ed25519' }],
    saveSettings: async (s) => {
      snap.settings = s;
      emit();
      return s;
    },
    scanNow: async () => {
      snap.results = results();
      snap.nextScanAt = Date.now() + snap.settings.scanIntervalSec * 1000;
      emit();
    },
    ban: async (serverId, ip, reason) => {
      const rec = { id: String(Date.now()), at: Date.now(), serverId, serverName: servers.find((s) => s.id === serverId)?.name ?? '', ip, jail: 'sshd', reason, auto: false, ok: true };
      snap.bans = [rec, ...snap.bans];
      emit();
      return rec;
    },
    unban: async (id) => {
      const rec = snap.bans.find((b) => b.id === id)!;
      rec.unbannedAt = Date.now();
      emit();
      return rec;
    },
    trustHostKey: async () => {},
    pickKeyFile: async () => '~/.ssh/id_ed25519',
    onSnapshot: (cb) => {
      listeners.add(cb);
      return () => listeners.delete(cb);
    },
  };
}
