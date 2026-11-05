import { isIP } from 'node:net';
import type { IpCount, Jail, Metrics } from '../shared/types';

/** Split collector output into its "@@name" sections. */
export function sections(output: string): Map<string, string[]> {
  const map = new Map<string, string[]>();
  let current: string[] | null = null;
  for (const raw of output.split('\n')) {
    const line = raw.replace(/\r$/, '');
    const m = /^@@([a-z0-9]+)$/.exec(line);
    if (m) {
      current = [];
      map.set(m[1], current);
    } else if (current && line.trim() !== '') {
      current.push(line);
    }
  }
  return map;
}

const num = (s: string | undefined, fallback = 0): number => {
  const n = Number(s);
  return Number.isFinite(n) ? n : fallback;
};

/** Parse `uniq -c` style "  42 1.2.3.4" lines, keeping valid IPs only. */
function ipCounts(lines: string[] = []): IpCount[] {
  const out: IpCount[] = [];
  for (const line of lines) {
    const m = /^\s*(\d+)\s+(\S+)$/.exec(line);
    if (m && isIP(m[2])) out.push({ ip: m[2], count: Number(m[1]) });
  }
  return out.sort((a, b) => b.count - a.count);
}

function parseJails(lines: string[]): Jail[] {
  const jails: Jail[] = [];
  let jail: Jail | null = null;
  for (const line of lines) {
    const jm = /^jail (\S+)$/.exec(line);
    if (jm) {
      jail = { name: jm[1], currentlyBanned: 0, totalBanned: 0, bannedIps: [] };
      jails.push(jail);
      continue;
    }
    if (!jail) continue;
    const v = line.split(':').slice(1).join(':').trim();
    if (/Currently banned/.test(line)) jail.currentlyBanned = num(v);
    else if (/Total banned/.test(line)) jail.totalBanned = num(v);
    else if (/Banned IP list/.test(line)) jail.bannedIps = v.split(/\s+/).filter((ip) => isIP(ip)).slice(0, 500);
  }
  return jails;
}

export function parseMetrics(output: string): Metrics {
  const s = sections(output);
  if (!s.has('end')) throw new Error('Probe output was cut off (no @@end marker).');
  const get = (k: string) => s.get(k) ?? [];

  const host = get('host');
  const load = (get('load')[0] ?? '').split(/\s+/).map((x) => num(x));
  const mem: Record<string, number> = {};
  for (const line of get('mem')) {
    const m = /^(\w+):\s+(\d+)/.exec(line);
    if (m) mem[m[1]] = Number(m[2]) * 1024;
  }

  const disks = get('disk')
    .map((line) => line.trim().split(/\s+/))
    .filter((p) => p.length >= 6)
    .map((p) => ({
      mount: p.slice(5).join(' '),
      size: num(p[1]) * 1024,
      used: num(p[2]) * 1024,
      percent: num(p[4].replace('%', '')),
    }))
    .filter((d) => d.size > 0);

  const listening = get('listen').map((line) => {
    const [proto = '', local = '', proc = ''] = line.split(/\s+/);
    const name = /\(\("([^"]+)"/.exec(proc);
    return { proto, local, process: name ? name[1] : '' };
  });

  const accepted = get('accepted')
    .map((line) => line.split(/\s+/))
    .filter((p) => p.length === 3 && isIP(p[1]))
    .map(([user, ip, method]) => ({ user, ip, method }));

  const http = get('http');
  const httpLogPath = http[0] && http[0].startsWith('/') ? http[0] : null;

  const sysctl = get('sysctl');
  const sysNum = (v: string | undefined) => (v === undefined || v === '-' ? null : num(v, NaN));

  const procs = get('procs')
    .map((line) => line.trim().split(/\s+/))
    .filter((p) => p.length >= 5)
    .map((p) => ({ pid: num(p[0]), user: p[1], cpu: num(p[2]), mem: num(p[3]), cmd: p.slice(4).join(' ') }));

  const f2b = get('f2b');

  const byMac = new Map<string, string[]>();
  for (const line of get('neigh')) {
    const [ip, mac] = line.split(/\s+/);
    if (!ip || !mac || mac === '00:00:00:00:00:00') continue;
    const list = byMac.get(mac.toLowerCase()) ?? [];
    list.push(ip);
    byMac.set(mac.toLowerCase(), list);
  }
  const arpDuplicates = [...byMac.entries()].filter(([, ips]) => ips.length > 1).map(([mac, ips]) => ({ mac, ips }));
  const gatewayIp = get('gw')[0]?.trim() || null;
  const gatewayMac = gatewayIp ? ([...byMac.entries()].find(([, ips]) => ips.includes(gatewayIp))?.[0] ?? null) : null;

  const clientIp = (get('client')[0] ?? '').trim();
  const tcp = get('tcp');
  const sudo = (get('sudo')[0] ?? 'no').trim();

  return {
    hostname: host[0] ?? '',
    kernel: host[1] ?? '',
    uptime: (host[2] ?? '').replace(/^up\s+/, ''),
    cpus: Math.max(1, num(get('cpus')[0], 1)),
    load: [load[0] ?? 0, load[1] ?? 0, load[2] ?? 0],
    memTotal: mem.MemTotal ?? 0,
    memUsed: (mem.MemTotal ?? 0) - (mem.MemAvailable ?? 0),
    swapTotal: mem.SwapTotal ?? 0,
    swapUsed: (mem.SwapTotal ?? 0) - (mem.SwapFree ?? 0),
    disks,
    tcpEstablished: num(tcp[0]?.trim()),
    synRecv: num(tcp[1]?.trim()),
    listening,
    topConnIps: ipCounts(get('conns')),
    failedLoginIps: ipCounts(get('failed')),
    acceptedLogins: accepted,
    httpTopIps: ipCounts(http.slice(httpLogPath ? 1 : 0)),
    httpLogPath,
    martians: num(get('martians')[0]?.trim()),
    rpFilter: sysNum(sysctl[0]?.trim()),
    syncookies: sysNum(sysctl[1]?.trim()),
    uid0Users: get('uid0').map((u) => u.trim()).filter(Boolean),
    suspiciousProcs: get('suspicious'),
    topProcs: procs,
    fail2ban: {
      installed: f2b[0] === 'installed',
      accessible: f2b[1] === 'ok',
      jails: parseJails(f2b.slice(2)),
    },
    arpDuplicates,
    gatewayIp,
    gatewayMac,
    rebootRequired: get('reboot')[0]?.trim() === 'yes',
    clientIp: isIP(clientIp) ? clientIp : null,
    sudo: sudo === 'yes' || sudo === 'root',
  };
}
