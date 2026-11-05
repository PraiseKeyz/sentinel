import type { FindingCategory, ServerState, Severity } from '../shared/types';

export const bytes = (n: number) => {
  if (!n) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.min(units.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / 1024 ** i).toFixed(i >= 3 ? 1 : 0)} ${units[i]}`;
};

export const pct = (used: number, total: number) => (total > 0 ? Math.round((used / total) * 100) : 0);

export const ago = (t: number) => {
  const s = Math.max(0, Math.round((Date.now() - t) / 1000));
  if (s < 5) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)}m ago`;
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`;
  return new Date(t).toLocaleDateString();
};

export const stateLabel: Record<ServerState, string> = {
  unknown: 'Waiting',
  scanning: 'Scanning',
  healthy: 'Healthy',
  warning: 'Warning',
  critical: 'Under threat',
  unreachable: 'Unreachable',
};

export const severityLabel: Record<Severity, string> = { critical: 'Critical', warning: 'Warning', info: 'Info' };

export const categoryLabel: Record<FindingCategory, string> = {
  health: 'Health',
  bruteforce: 'Brute force',
  dos: 'DoS',
  spoofing: 'Spoofing',
  intrusion: 'Intrusion',
  hardening: 'Hardening',
  fail2ban: 'fail2ban',
};
