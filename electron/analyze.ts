import type { Finding, Metrics, ServerState, Settings, Severity } from '../shared/types';

export interface AnalyzeContext {
  settings: Settings;
  /** Gateway MAC from the previous scan, to spot ARP spoofing of the default route. */
  previousGatewayMac: string | null;
  /** True for IPs that must never be banned (whitelist, our own IP, our servers). */
  isProtected: (ip: string) => boolean;
}

const pct = (used: number, total: number) => (total > 0 ? Math.round((used / total) * 100) : 0);
const gb = (bytes: number) => (bytes / 1024 ** 3).toFixed(1);

export function analyze(m: Metrics, ctx: AnalyzeContext): Finding[] {
  const t = ctx.settings.thresholds;
  const lookback = ctx.settings.lookbackMinutes;
  const out: Finding[] = [];
  const add = (f: Finding) => out.push(f);
  const banField = (ip: string) => (ctx.isProtected(ip) ? { ip, bannable: false } : { ip, bannable: true });
  const protectedNote = (ip: string) => (ctx.isProtected(ip) ? ' This IP is on your whitelist, so it will not be banned.' : '');

  // ---- Health ----------------------------------------------------------
  const perCore = m.load[0] / m.cpus;
  if (perCore >= t.loadPerCore) {
    add({
      id: 'health:load',
      severity: perCore >= t.loadPerCore * 2 ? 'critical' : 'warning',
      category: 'health',
      title: `High load: ${m.load[0].toFixed(2)} on ${m.cpus} CPU${m.cpus > 1 ? 's' : ''}`,
      detail: `1-minute load is ${perCore.toFixed(2)}× the core count. Top process: ${m.topProcs[0]?.cmd ?? 'n/a'} (${m.topProcs[0]?.cpu ?? 0}% CPU).`,
    });
  }
  const memP = pct(m.memUsed, m.memTotal);
  if (memP >= t.memPercent) {
    add({
      id: 'health:mem',
      severity: memP >= 97 ? 'critical' : 'warning',
      category: 'health',
      title: `Memory at ${memP}%`,
      detail: `${gb(m.memUsed)} of ${gb(m.memTotal)} GB in use. Swap: ${gb(m.swapUsed)} of ${gb(m.swapTotal)} GB.`,
    });
  }
  for (const d of m.disks) {
    if (d.percent >= t.diskPercent) {
      add({
        id: `health:disk:${d.mount}`,
        severity: d.percent >= 97 ? 'critical' : 'warning',
        category: 'health',
        title: `Disk ${d.mount} at ${d.percent}%`,
        detail: `${gb(d.used)} of ${gb(d.size)} GB used. A full disk can stop logging, databases and fail2ban itself.`,
      });
    }
  }
  if (m.rebootRequired) {
    add({
      id: 'health:reboot',
      severity: 'info',
      category: 'health',
      title: 'Reboot required',
      detail: 'Installed updates (often a kernel or libc) only take effect after a reboot.',
    });
  }

  // ---- Brute force -----------------------------------------------------
  for (const { ip, count } of m.failedLoginIps) {
    if (count < t.failedLogins) continue;
    add({
      id: `bruteforce:${ip}`,
      severity: count >= t.failedLogins * 5 ? 'critical' : 'warning',
      category: 'bruteforce',
      title: `SSH brute force from ${ip}`,
      detail: `${count} failed or invalid SSH logins in the last ${lookback} min.${protectedNote(ip)}`,
      ...banField(ip),
    });
  }
  const failedTotal = m.failedLoginIps.reduce((a, b) => a + b.count, 0);
  const distinct = m.failedLoginIps.length;
  if (distinct >= 20 && failedTotal >= t.failedLogins * 10) {
    add({
      id: 'bruteforce:distributed',
      severity: 'warning',
      category: 'bruteforce',
      title: `Distributed SSH attack: ${distinct}+ source IPs`,
      detail: `${failedTotal} failed logins from many IPs. Consider key-only auth, a non-default port, or an allow-list in your firewall.`,
    });
  }
  for (const login of m.acceptedLogins) {
    if (login.method === 'password' && login.user === 'root') {
      add({
        id: `intrusion:rootpw:${login.ip}`,
        severity: 'critical',
        category: 'intrusion',
        title: `Root logged in with a password from ${login.ip}`,
        detail: 'Password logins as root are a common entry point. If this was not you, rotate credentials and set PermitRootLogin to prohibit-password.',
      });
    }
  }

  // ---- DoS -------------------------------------------------------------
  if (m.synRecv >= t.synRecv) {
    add({
      id: 'dos:synflood',
      severity: 'critical',
      category: 'dos',
      title: `Possible SYN flood: ${m.synRecv} half-open connections`,
      detail:
        m.syncookies === 1
          ? 'TCP SYN cookies are on, which helps. Spoofed SYN sources cannot be banned by IP; consider upstream filtering.'
          : 'TCP SYN cookies are OFF. Enable them: sysctl -w net.ipv4.tcp_syncookies=1',
    });
  }
  for (const { ip, count } of m.topConnIps) {
    if (count < t.connectionsPerIp) continue;
    add({
      id: `dos:conn:${ip}`,
      severity: count >= t.connectionsPerIp * 3 ? 'critical' : 'warning',
      category: 'dos',
      title: `Connection flood from ${ip}`,
      detail: `${count} established TCP connections from one address.${protectedNote(ip)}`,
      ...banField(ip),
    });
  }
  for (const { ip, count } of m.httpTopIps) {
    if (count < t.httpRequestsPerIp) continue;
    add({
      id: `dos:http:${ip}`,
      severity: count >= t.httpRequestsPerIp * 3 ? 'critical' : 'warning',
      category: 'dos',
      title: `HTTP flood from ${ip}`,
      detail: `${count} requests in the last 20,000 lines of ${m.httpLogPath}.${protectedNote(ip)}`,
      ...banField(ip),
    });
  }

  // ---- Spoofing --------------------------------------------------------
  if (m.martians > 0) {
    add({
      id: 'spoofing:martians',
      severity: m.martians > 50 ? 'warning' : 'info',
      category: 'spoofing',
      title: `${m.martians} martian packets logged`,
      detail: 'The kernel saw packets with impossible source addresses for their interface, a typical sign of IP spoofing.',
    });
  }
  if (m.rpFilter === 0) {
    add({
      id: 'hardening:rpfilter',
      severity: 'warning',
      category: 'hardening',
      title: 'Reverse-path filtering is off',
      detail: 'Without rp_filter the kernel accepts packets with spoofed source IPs. Fix: sysctl -w net.ipv4.conf.all.rp_filter=1',
    });
  }
  if (m.syncookies === 0) {
    add({
      id: 'hardening:syncookies',
      severity: 'warning',
      category: 'hardening',
      title: 'TCP SYN cookies are off',
      detail: 'SYN cookies keep the server reachable during a SYN flood. Fix: sysctl -w net.ipv4.tcp_syncookies=1',
    });
  }
  if (ctx.previousGatewayMac && m.gatewayMac && ctx.previousGatewayMac !== m.gatewayMac) {
    add({
      id: 'spoofing:gwmac',
      severity: 'critical',
      category: 'spoofing',
      title: `Gateway MAC changed for ${m.gatewayIp}`,
      detail: `Was ${ctx.previousGatewayMac}, now ${m.gatewayMac}. Unless your provider changed hardware, this can be ARP spoofing (man-in-the-middle).`,
    });
  }
  for (const dup of m.arpDuplicates) {
    const hasGw = m.gatewayIp !== null && dup.ips.includes(m.gatewayIp);
    add({
      id: `spoofing:arp:${dup.mac}`,
      severity: hasGw ? 'warning' : 'info',
      category: 'spoofing',
      title: `${dup.ips.length} IPs share MAC ${dup.mac}`,
      detail: `${dup.ips.join(', ')}${hasGw ? ' (includes the gateway)' : ''}. This is normal on some cloud networks that use proxy ARP; otherwise it can mean ARP spoofing.`,
    });
  }

  // ---- Intrusion signs -------------------------------------------------
  const extraRoot = m.uid0Users.filter((u) => u !== 'root');
  if (extraRoot.length) {
    add({
      id: 'intrusion:uid0',
      severity: 'critical',
      category: 'intrusion',
      title: `Extra UID 0 account: ${extraRoot.join(', ')}`,
      detail: 'Accounts with UID 0 have full root rights. Attackers add these as a backdoor.',
    });
  }
  for (const p of m.suspiciousProcs) {
    add({
      id: `intrusion:proc:${p}`,
      severity: 'critical',
      category: 'intrusion',
      title: 'Suspicious process',
      detail: `${p}. Binaries running from temp directories are a common malware pattern.`,
    });
  }

  // ---- fail2ban --------------------------------------------------------
  if (!m.fail2ban.installed) {
    add({
      id: 'fail2ban:missing',
      severity: 'warning',
      category: 'fail2ban',
      title: 'fail2ban is not installed',
      detail: 'Automatic bans need fail2ban. Install: apt install fail2ban (Debian/Ubuntu) or dnf install fail2ban (RHEL).',
    });
  } else if (!m.fail2ban.accessible) {
    add({
      id: 'fail2ban:denied',
      severity: 'warning',
      category: 'fail2ban',
      title: 'Cannot control fail2ban',
      detail: 'The SSH user needs root or passwordless sudo for fail2ban-client. Without it, bans from Sentinel will fail.',
    });
  }
  if (!m.sudo) {
    add({
      id: 'hardening:nosudo',
      severity: 'info',
      category: 'hardening',
      title: 'Limited visibility (no passwordless sudo)',
      detail: 'Auth logs, process paths and fail2ban may be unreadable. See the README for a minimal sudoers rule.',
    });
  }

  const rank: Record<Severity, number> = { critical: 0, warning: 1, info: 2 };
  return out.sort((a, b) => rank[a.severity] - rank[b.severity]);
}

export function score(findings: Finding[]): number {
  let s = 100;
  for (const f of findings) s -= f.severity === 'critical' ? 25 : f.severity === 'warning' ? 8 : 1;
  return Math.max(0, s);
}

export function stateFor(findings: Finding[]): ServerState {
  if (findings.some((f) => f.severity === 'critical')) return 'critical';
  if (findings.some((f) => f.severity === 'warning')) return 'warning';
  return 'healthy';
}
