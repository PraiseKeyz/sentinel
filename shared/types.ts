// Types shared between the Electron main process and the React renderer.

export interface ServerConfig {
  id: string;
  name: string;
  host: string;
  port: number;
  username: string;
  /** Path to a private key. Empty means "use the SSH agent". */
  keyPath: string;
  /** True when an encrypted passphrase is stored for this key. */
  hasPassphrase: boolean;
  /** fail2ban jail used for manual and automatic bans on this server. */
  banJail: string;
  tags: string[];
}

export type ServerInput = Omit<ServerConfig, 'id' | 'hasPassphrase'> & {
  id?: string;
  /** undefined = keep the stored passphrase, '' = clear it. */
  passphrase?: string;
};

export interface Thresholds {
  /** Failed SSH logins from one IP within the lookback window before it counts as brute force. */
  failedLogins: number;
  /** Established TCP connections from one IP before it counts as a flood. */
  connectionsPerIp: number;
  /** Half-open (SYN_RECV) sockets before it counts as a SYN flood. */
  synRecv: number;
  /** Requests from one IP in the sampled web access log before it counts as an HTTP flood. */
  httpRequestsPerIp: number;
  diskPercent: number;
  memPercent: number;
  /** Load average divided by CPU count. */
  loadPerCore: number;
}

export interface Settings {
  scanIntervalSec: number;
  lookbackMinutes: number;
  autoBan: boolean;
  /** When an IP is banned on one server, ban it on every server. */
  fleetBan: boolean;
  /** IPs / CIDRs that are never banned. Your own IP (as each server sees it) is always added. */
  whitelist: string[];
  notifications: boolean;
  thresholds: Thresholds;
}

export type Severity = 'critical' | 'warning' | 'info';

export type FindingCategory =
  | 'health'
  | 'bruteforce'
  | 'dos'
  | 'spoofing'
  | 'intrusion'
  | 'hardening'
  | 'fail2ban';

export interface Finding {
  id: string;
  severity: Severity;
  category: FindingCategory;
  title: string;
  detail: string;
  ip?: string;
  /** True when this finding should send `ip` to fail2ban. */
  bannable?: boolean;
}

export interface IpCount {
  ip: string;
  count: number;
}

export interface Jail {
  name: string;
  currentlyBanned: number;
  totalBanned: number;
  bannedIps: string[];
}

export interface Metrics {
  hostname: string;
  kernel: string;
  uptime: string;
  cpus: number;
  load: [number, number, number];
  memTotal: number;
  memUsed: number;
  swapTotal: number;
  swapUsed: number;
  disks: { mount: string; size: number; used: number; percent: number }[];
  tcpEstablished: number;
  synRecv: number;
  listening: { proto: string; local: string; process: string }[];
  topConnIps: IpCount[];
  failedLoginIps: IpCount[];
  acceptedLogins: { user: string; ip: string; method: string }[];
  httpTopIps: IpCount[];
  httpLogPath: string | null;
  martians: number;
  rpFilter: number | null;
  syncookies: number | null;
  uid0Users: string[];
  suspiciousProcs: string[];
  topProcs: { pid: number; user: string; cpu: number; mem: number; cmd: string }[];
  fail2ban: { installed: boolean; accessible: boolean; jails: Jail[] };
  arpDuplicates: { mac: string; ips: string[] }[];
  gatewayIp: string | null;
  gatewayMac: string | null;
  rebootRequired: boolean;
  /** Our own IP as the server sees it (from $SSH_CLIENT). */
  clientIp: string | null;
  sudo: boolean;
}

export type ServerState = 'unknown' | 'scanning' | 'healthy' | 'warning' | 'critical' | 'unreachable';

export interface HistoryPoint {
  t: number;
  load: number;
  mem: number;
  conns: number;
  failed: number;
}

export interface ScanResult {
  serverId: string;
  at: number;
  durationMs: number;
  state: ServerState;
  /** 0-100. */
  score: number;
  error?: string;
  metrics?: Metrics;
  findings: Finding[];
}

export interface BanRecord {
  id: string;
  at: number;
  serverId: string;
  serverName: string;
  ip: string;
  jail: string;
  reason: string;
  auto: boolean;
  ok: boolean;
  error?: string;
  /** Set when this IP has since been unbanned from Sentinel. */
  unbannedAt?: number;
}

export interface Snapshot {
  servers: ServerConfig[];
  settings: Settings;
  results: Record<string, ScanResult>;
  history: Record<string, HistoryPoint[]>;
  bans: BanRecord[];
  scanning: string[];
  nextScanAt: number | null;
}

export interface SshConfigHost {
  alias: string;
  host: string;
  port: number;
  username: string;
  keyPath: string;
}

export interface SentinelApi {
  getSnapshot(): Promise<Snapshot>;
  saveServer(input: ServerInput): Promise<ServerConfig>;
  deleteServer(id: string): Promise<void>;
  testServer(input: ServerInput): Promise<{ ok: boolean; message: string }>;
  importSshConfig(): Promise<SshConfigHost[]>;
  saveSettings(settings: Settings): Promise<Settings>;
  scanNow(serverId?: string): Promise<void>;
  ban(serverId: string, ip: string, reason: string): Promise<BanRecord>;
  unban(banId: string): Promise<BanRecord>;
  trustHostKey(serverId: string): Promise<void>;
  pickKeyFile(): Promise<string | null>;
  onSnapshot(cb: (s: Snapshot) => void): () => void;
}

export const DEFAULT_SETTINGS: Settings = {
  scanIntervalSec: 60,
  lookbackMinutes: 60,
  autoBan: true,
  fleetBan: false,
  whitelist: ['127.0.0.1', '::1'],
  notifications: true,
  thresholds: {
    failedLogins: 10,
    connectionsPerIp: 150,
    synRecv: 256,
    httpRequestsPerIp: 1500,
    diskPercent: 90,
    memPercent: 92,
    loadPerCore: 1.5,
  },
};
