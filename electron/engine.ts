import { randomUUID } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import type { BanRecord, Finding, HistoryPoint, ScanResult, ServerConfig, Settings, Snapshot } from '../shared/types';
import { analyze, score, stateFor } from './analyze';
import { collectorScript } from './collector';
import { parseMetrics } from './parse';
import { HostKeyMismatchError, SshPool, type ConnectTarget } from './ssh';
import type { Store } from './store';

const HISTORY_POINTS = 120;
const SCAN_CONCURRENCY = 6;
/** Don't re-ban an IP on the same server within this window. */
const REBAN_COOLDOWN_MS = 10 * 60 * 1000;

export interface EngineDeps {
  decryptPassphrase(serverId: string): string | undefined;
  notify(title: string, body: string): void;
  onChange(): void;
}

const JAIL_RE = /^[A-Za-z0-9_.-]{1,64}$/;

export class Engine {
  readonly pool: SshPool;
  private results: Record<string, ScanResult> = {};
  private history: Record<string, HistoryPoint[]> = {};
  private gatewayMacs: Record<string, string> = {};
  private resolved: Record<string, string> = {};
  private scanning = new Set<string>();
  private nextScanAt: number | null = null;
  private timer: NodeJS.Timeout | null = null;

  constructor(private store: Store, private deps: EngineDeps) {
    this.pool = new SshPool({
      get: (id) => store.data.hostKeys[id],
      set: (id, fp) => {
        store.data.hostKeys[id] = fp;
        store.save();
      },
    });
  }

  get settings(): Settings {
    return this.store.data.settings;
  }

  snapshot(): Snapshot {
    return {
      servers: this.store.data.servers,
      settings: this.settings,
      results: this.results,
      history: this.history,
      bans: this.store.data.bans.slice(-500).reverse(),
      scanning: [...this.scanning],
      nextScanAt: this.nextScanAt,
    };
  }

  target(server: ServerConfig, passphrase?: string): ConnectTarget {
    return {
      id: server.id,
      host: server.host,
      port: server.port,
      username: server.username,
      keyPath: server.keyPath,
      passphrase: passphrase ?? (server.hasPassphrase ? this.deps.decryptPassphrase(server.id) : undefined),
    };
  }

  // ---- Scheduling ------------------------------------------------------

  start() {
    this.nextScanAt = Date.now() + 500;
    this.timer = setInterval(() => {
      if (this.nextScanAt !== null && Date.now() >= this.nextScanAt) {
        this.nextScanAt = null;
        void this.scanAll().finally(() => {
          this.nextScanAt = Date.now() + this.settings.scanIntervalSec * 1000;
          this.deps.onChange();
        });
      }
    }, 1000);
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.pool.closeAll();
  }

  async scanAll() {
    const queue = this.store.data.servers.map((s) => s.id);
    const workers = Array.from({ length: Math.min(SCAN_CONCURRENCY, queue.length) }, async () => {
      for (let id = queue.shift(); id; id = queue.shift()) await this.scanOne(id);
    });
    await Promise.all(workers);
  }

  async scanOne(serverId: string): Promise<void> {
    const server = this.store.data.servers.find((s) => s.id === serverId);
    if (!server || this.scanning.has(serverId)) return;
    this.scanning.add(serverId);
    this.deps.onChange();
    const started = Date.now();
    const previous = this.results[serverId];
    let result: ScanResult;
    try {
      void this.resolveHost(server);
      const { stdout } = await this.pool.exec(this.target(server), '/bin/sh -s', collectorScript(this.settings.lookbackMinutes));
      const metrics = parseMetrics(stdout);
      const findings = analyze(metrics, {
        settings: this.settings,
        previousGatewayMac: this.gatewayMacs[serverId] ?? null,
        isProtected: (ip) => this.isProtected(ip),
      });
      if (metrics.gatewayMac) this.gatewayMacs[serverId] = metrics.gatewayMac;
      result = {
        serverId,
        at: Date.now(),
        durationMs: Date.now() - started,
        state: stateFor(findings),
        score: score(findings),
        metrics,
        findings,
      };
      this.pushHistory(serverId, {
        t: result.at,
        load: metrics.load[0] / metrics.cpus,
        mem: metrics.memTotal ? metrics.memUsed / metrics.memTotal : 0,
        conns: metrics.tcpEstablished,
        failed: metrics.failedLoginIps.reduce((a, b) => a + b.count, 0),
      });
    } catch (err) {
      this.pool.close(serverId);
      const findings: Finding[] = [];
      if (err instanceof HostKeyMismatchError) {
        findings.push({
          id: 'spoofing:hostkey',
          severity: 'critical',
          category: 'spoofing',
          title: 'SSH host key changed: possible man-in-the-middle',
          detail: `${err.message} Sentinel stopped connecting. If you rebuilt this server, use "Trust new key"; otherwise investigate before logging in.`,
        });
      }
      result = {
        serverId,
        at: Date.now(),
        durationMs: Date.now() - started,
        state: findings.length ? 'critical' : 'unreachable',
        score: 0,
        error: err instanceof Error ? err.message : String(err),
        metrics: previous?.metrics,
        findings,
      };
    }
    this.results[serverId] = result;
    this.scanning.delete(serverId);
    this.notifyNew(server, previous, result);
    this.deps.onChange();
    await this.autoBan(server, result);
  }

  private pushHistory(id: string, p: HistoryPoint) {
    const h = (this.history[id] ??= []);
    h.push(p);
    if (h.length > HISTORY_POINTS) h.splice(0, h.length - HISTORY_POINTS);
  }

  private notifyNew(server: ServerConfig, prev: ScanResult | undefined, next: ScanResult) {
    if (!this.settings.notifications) return;
    const seen = new Set(prev?.findings.map((f) => f.id));
    for (const f of next.findings) {
      if (f.severity === 'critical' && !seen.has(f.id)) this.deps.notify(`${server.name}: ${f.title}`, f.detail);
    }
    if (next.state === 'unreachable' && prev && prev.state !== 'unreachable') {
      this.deps.notify(`${server.name} is unreachable`, next.error ?? '');
    }
  }

  forget(serverId: string) {
    delete this.results[serverId];
    delete this.history[serverId];
    delete this.gatewayMacs[serverId];
    this.pool.close(serverId);
  }

  // ---- Protection ------------------------------------------------------

  private async resolveHost(server: ServerConfig) {
    if (isIP(server.host)) return;
    try {
      this.resolved[server.id] = (await lookup(server.host)).address;
    } catch {
      // unresolvable host: the scan will report it
    }
  }

  /** IPs we must never ban: whitelist entries, our own IP, and our own servers. */
  isProtected(ip: string): boolean {
    const list = new BlockList();
    const family = (a: string) => (isIP(a) === 6 ? 'ipv6' : 'ipv4');
    const addEntry = (entry: string) => {
      const [addr, bits] = entry.trim().split('/');
      if (!isIP(addr)) return;
      if (bits !== undefined) list.addSubnet(addr, Number(bits), family(addr));
      else list.addAddress(addr, family(addr));
    };
    this.settings.whitelist.forEach(addEntry);
    for (const s of this.store.data.servers) {
      if (isIP(s.host)) addEntry(s.host);
      if (this.resolved[s.id]) addEntry(this.resolved[s.id]);
    }
    for (const r of Object.values(this.results)) if (r.metrics?.clientIp) addEntry(r.metrics.clientIp);
    if (!isIP(ip)) return true;
    return list.check(ip, family(ip));
  }

  // ---- Banning ---------------------------------------------------------

  private async autoBan(server: ServerConfig, result: ScanResult) {
    if (!this.settings.autoBan || !result.metrics?.fail2ban.accessible) return;
    const alreadyBanned = new Set(result.metrics.fail2ban.jails.find((j) => j.name === server.banJail)?.bannedIps ?? []);
    const targets = new Map<string, string>();
    for (const f of result.findings) {
      if (f.bannable && f.ip && !alreadyBanned.has(f.ip) && !targets.has(f.ip)) targets.set(f.ip, f.title);
    }
    for (const [ip, reason] of targets) {
      if (this.recentlyBanned(server.id, ip)) continue;
      const rec = await this.ban(server.id, ip, reason, true);
      if (this.settings.notifications) {
        this.deps.notify(rec.ok ? `Banned ${ip} on ${server.name}` : `Ban failed on ${server.name}`, rec.ok ? reason : rec.error ?? '');
      }
    }
  }

  private recentlyBanned(serverId: string, ip: string) {
    const cutoff = Date.now() - REBAN_COOLDOWN_MS;
    return this.store.data.bans.some((b) => b.serverId === serverId && b.ip === ip && b.ok && !b.unbannedAt && b.at > cutoff);
  }

  async ban(serverId: string, ip: string, reason: string, auto = false, fleet = true): Promise<BanRecord> {
    const server = this.store.data.servers.find((s) => s.id === serverId);
    if (!server) throw new Error('Unknown server');
    const rec: BanRecord = {
      id: randomUUID(),
      at: Date.now(),
      serverId,
      serverName: server.name,
      ip,
      jail: server.banJail,
      reason,
      auto,
      ok: false,
    };
    try {
      if (!isIP(ip)) throw new Error(`"${ip}" is not an IP address`);
      if (this.isProtected(ip)) throw new Error(`${ip} is protected (whitelist, your own IP, or one of your servers)`);
      if (!JAIL_RE.test(server.banJail)) throw new Error(`Invalid jail name "${server.banJail}"`);
      await this.fail2ban(server, `set ${server.banJail} banip ${ip}`);
      rec.ok = true;
    } catch (err) {
      rec.error = err instanceof Error ? err.message : String(err);
    }
    this.store.data.bans.push(rec);
    this.store.save();
    this.deps.onChange();

    if (rec.ok && fleet && this.settings.fleetBan) {
      for (const other of this.store.data.servers) {
        if (other.id === serverId || this.recentlyBanned(other.id, ip)) continue;
        void this.ban(other.id, ip, `Fleet ban (from ${server.name}): ${reason}`, true, false);
      }
    }
    return rec;
  }

  async unban(banId: string): Promise<BanRecord> {
    const rec = this.store.data.bans.find((b) => b.id === banId);
    if (!rec) throw new Error('Unknown ban');
    const server = this.store.data.servers.find((s) => s.id === rec.serverId);
    if (!server) throw new Error('That server was removed');
    if (!isIP(rec.ip) || !JAIL_RE.test(rec.jail)) throw new Error('Invalid ban record');
    await this.fail2ban(server, `set ${rec.jail} unbanip ${rec.ip}`);
    rec.unbannedAt = Date.now();
    this.store.save();
    this.deps.onChange();
    return rec;
  }

  /** Run fail2ban-client as root (directly, or through passwordless sudo). Args must be pre-validated. */
  private async fail2ban(server: ServerConfig, args: string) {
    const cmd = `if [ "$(id -u)" = 0 ]; then fail2ban-client ${args}; else sudo -n fail2ban-client ${args}; fi`;
    const { stdout, stderr, code } = await this.pool.exec(this.target(server), cmd, undefined, 20000);
    if (code !== 0) throw new Error((stderr || stdout).trim() || `fail2ban-client exited with ${code}`);
  }
}
