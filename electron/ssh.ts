import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { Client, type ConnectConfig } from 'ssh2';

export interface ConnectTarget {
  id: string;
  host: string;
  port: number;
  username: string;
  keyPath: string;
  passphrase?: string;
}

/** Thrown when the server's host key does not match the one we trusted before. */
export class HostKeyMismatchError extends Error {
  constructor(public readonly expected: string, public readonly actual: string) {
    super(`Host key changed. Expected ${expected}, got ${actual}.`);
  }
}

export interface HostKeyStore {
  get(id: string): string | undefined;
  /** Called on first contact (trust on first use). */
  set(id: string, fingerprint: string): void;
}

export function expandHome(p: string): string {
  return p.startsWith('~') ? homedir() + p.slice(1) : p;
}

function agentSocket(): string | undefined {
  if (process.env.SSH_AUTH_SOCK) return process.env.SSH_AUTH_SOCK;
  if (process.platform === 'win32') return '\\\\.\\pipe\\openssh-ssh-agent';
  return undefined;
}

function fingerprint(key: Buffer): string {
  return 'SHA256:' + createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
}

interface PoolEntry {
  client: Client;
  ready: Promise<Client>;
  signature: string;
}

/**
 * Keeps one SSH connection per server open between scans, so the scanner does
 * not add a login line to each server's auth log every minute.
 */
export class SshPool {
  private entries = new Map<string, PoolEntry>();

  constructor(private hostKeys: HostKeyStore) {}

  private signature(t: ConnectTarget) {
    return [t.host, t.port, t.username, t.keyPath, t.passphrase ?? ''].join('|');
  }

  private connect(t: ConnectTarget, trustOnFirstUse: boolean): PoolEntry {
    const client = new Client();
    let mismatch: HostKeyMismatchError | null = null;

    const config: ConnectConfig = {
      host: t.host,
      port: t.port,
      username: t.username,
      readyTimeout: 15000,
      keepaliveInterval: 20000,
      keepaliveCountMax: 3,
      hostVerifier: (key: Buffer) => {
        const fp = fingerprint(key);
        const known = this.hostKeys.get(t.id);
        if (!known) {
          if (trustOnFirstUse) this.hostKeys.set(t.id, fp);
          return true;
        }
        if (known !== fp) {
          mismatch = new HostKeyMismatchError(known, fp);
          return false;
        }
        return true;
      },
    };
    if (t.keyPath) {
      config.privateKey = readFileSync(expandHome(t.keyPath));
      if (t.passphrase) config.passphrase = t.passphrase;
    } else {
      const agent = agentSocket();
      if (!agent) throw new Error('No key file set and no SSH agent found. Pick a private key for this server.');
      config.agent = agent;
    }

    const ready = new Promise<Client>((resolve, reject) => {
      client.once('ready', () => resolve(client));
      client.once('error', (err) => reject(mismatch ?? err));
    });
    const entry: PoolEntry = { client, ready, signature: this.signature(t) };
    const drop = () => {
      if (this.entries.get(t.id) === entry) this.entries.delete(t.id);
    };
    client.on('close', drop);
    client.on('error', drop);
    client.connect(config);
    return entry;
  }

  private async get(t: ConnectTarget): Promise<Client> {
    const existing = this.entries.get(t.id);
    if (existing && existing.signature === this.signature(t)) return existing.ready;
    if (existing) this.close(t.id);
    const entry = this.connect(t, true);
    this.entries.set(t.id, entry);
    return entry.ready;
  }

  /** Run a command, optionally feeding `stdin`, and return stdout. */
  async exec(t: ConnectTarget, command: string, stdin?: string, timeoutMs = 60000): Promise<{ stdout: string; stderr: string; code: number | null }> {
    const client = await this.get(t);
    return new Promise((resolve, reject) => {
      client.exec(command, (err, stream) => {
        if (err) {
          this.close(t.id);
          return reject(err);
        }
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
          stream.close();
          reject(new Error(`Command timed out after ${timeoutMs / 1000}s`));
        }, timeoutMs);
        stream.on('data', (d: Buffer) => (stdout += d.toString('utf8')));
        stream.stderr.on('data', (d: Buffer) => (stderr += d.toString('utf8')));
        stream.on('close', (code: number | null) => {
          clearTimeout(timer);
          resolve({ stdout, stderr, code });
        });
        if (stdin !== undefined) stream.end(stdin);
      });
    });
  }

  /** One-off connection test. It checks the trusted host key but never stores one. */
  async test(t: ConnectTarget): Promise<string> {
    const entry = this.connect(t, false);
    try {
      const client = await entry.ready;
      return await new Promise<string>((resolve, reject) => {
        client.exec('uname -sr; hostname', (err, stream) => {
          if (err) return reject(err);
          let out = '';
          stream.on('data', (d: Buffer) => (out += d.toString()));
          stream.on('close', () => resolve(out.trim().replace(/\n/g, ' · ')));
        });
      });
    } finally {
      entry.client.end();
    }
  }

  close(id: string) {
    const e = this.entries.get(id);
    if (e) {
      this.entries.delete(id);
      e.client.end();
    }
  }

  closeAll() {
    for (const id of [...this.entries.keys()]) this.close(id);
  }
}
