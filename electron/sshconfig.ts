import { readFileSync } from 'node:fs';
import { homedir, userInfo } from 'node:os';
import { join } from 'node:path';
import type { SshConfigHost } from '../shared/types';

/** Read concrete (non-wildcard) Host entries from an OpenSSH client config. */
export function parseSshConfig(text: string): SshConfigHost[] {
  const hosts: SshConfigHost[] = [];
  let current: SshConfigHost[] = [];
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const m = /^(\S+)\s*=?\s*(.+)$/.exec(line);
    if (!m) continue;
    const key = m[1].toLowerCase();
    const value = m[2].replace(/^"|"$/g, '');
    if (key === 'host') {
      current = value
        .split(/\s+/)
        .filter((a) => !/[*?!]/.test(a))
        .map((alias) => ({ alias, host: alias, port: 22, username: '', keyPath: '' }));
      hosts.push(...current);
    } else if (key === 'match') {
      current = [];
    } else {
      for (const h of current) {
        if (key === 'hostname') h.host = value;
        else if (key === 'port') h.port = Number(value) || 22;
        else if (key === 'user') h.username = value;
        else if (key === 'identityfile' && !h.keyPath) h.keyPath = value;
      }
    }
  }
  const fallbackUser = userInfo().username;
  return hosts.map((h) => ({ ...h, username: h.username || fallbackUser }));
}

export function readSshConfig(): SshConfigHost[] {
  try {
    return parseSshConfig(readFileSync(join(homedir(), '.ssh', 'config'), 'utf8'));
  } catch {
    return [];
  }
}
