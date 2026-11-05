import { mkdirSync, readFileSync, renameSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { DEFAULT_SETTINGS, type BanRecord, type ServerConfig, type Settings } from '../shared/types';

interface StoreData {
  servers: ServerConfig[];
  settings: Settings;
  /** Key passphrases, encrypted with the OS keychain (Electron safeStorage), base64. */
  secrets: Record<string, string>;
  /** Trusted host key fingerprints per server id. */
  hostKeys: Record<string, string>;
  bans: BanRecord[];
}

const MAX_BANS = 2000;

/** Small JSON store in the app's user-data folder. Writes are atomic. */
export class Store {
  data: StoreData;

  constructor(private file: string) {
    this.data = this.load();
  }

  private load(): StoreData {
    let raw: Partial<StoreData> = {};
    try {
      raw = JSON.parse(readFileSync(this.file, 'utf8'));
    } catch {
      // first run or unreadable file: start fresh
    }
    return {
      servers: raw.servers ?? [],
      settings: {
        ...DEFAULT_SETTINGS,
        ...raw.settings,
        thresholds: { ...DEFAULT_SETTINGS.thresholds, ...raw.settings?.thresholds },
      },
      secrets: raw.secrets ?? {},
      hostKeys: raw.hostKeys ?? {},
      bans: raw.bans ?? [],
    };
  }

  save() {
    if (this.data.bans.length > MAX_BANS) this.data.bans = this.data.bans.slice(-MAX_BANS);
    mkdirSync(dirname(this.file), { recursive: true });
    const tmp = this.file + '.tmp';
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, this.file);
  }
}
