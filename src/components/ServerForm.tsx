import { useState } from 'react';
import type { ServerConfig, ServerInput, SshConfigHost } from '../../shared/types';
import { api } from '../api';

const blank: ServerInput = { name: '', host: '', port: 22, username: 'root', keyPath: '~/.ssh/id_ed25519', banJail: 'sshd', tags: [] };

export function ServerForm({ server, onClose, onSaved }: { server: ServerConfig | null; onClose: () => void; onSaved: (s: ServerConfig) => void }) {
  const [form, setForm] = useState<ServerInput>(server ? { ...server } : blank);
  const [passphrase, setPassphrase] = useState<string | undefined>(undefined);
  const [status, setStatus] = useState<{ ok: boolean; message: string } | null>(null);
  const [busy, setBusy] = useState(false);
  const [imports, setImports] = useState<SshConfigHost[] | null>(null);

  const set = <K extends keyof ServerInput>(k: K, v: ServerInput[K]) => setForm((f) => ({ ...f, [k]: v }));
  const input = (): ServerInput => ({ ...form, port: Number(form.port) || 22, passphrase });

  const test = async () => {
    setBusy(true);
    setStatus(null);
    setStatus(await api.testServer(input()));
    setBusy(false);
  };
  const save = async () => {
    setBusy(true);
    try {
      onSaved(await api.saveServer(input()));
    } catch (e) {
      setStatus({ ok: false, message: String(e).replace(/^Error: (Error invoking remote method '[^']+': )?(Error: )?/, '') });
      setBusy(false);
    }
  };
  const pick = async () => {
    const p = await api.pickKeyFile();
    if (p) set('keyPath', p);
  };
  const loadImports = async () => setImports(await api.importSshConfig());
  const applyImport = (h: SshConfigHost) => {
    setForm((f) => ({ ...f, name: h.alias, host: h.host, port: h.port, username: h.username, keyPath: h.keyPath || f.keyPath }));
    setImports(null);
  };

  return (
    <div className="modal-backdrop" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-label={server ? 'Edit server' : 'Add server'}>
        <header className="modal-head">
          <h2>{server ? `Edit ${server.name}` : 'Add server'}</h2>
          {!server && (
            <button className="btn btn-sm" onClick={loadImports}>
              Import from ~/.ssh/config
            </button>
          )}
        </header>

        {imports && (
          <div className="imports">
            {imports.length === 0 && <p className="muted small">No hosts found in ~/.ssh/config.</p>}
            {imports.map((h) => (
              <button key={h.alias} className="import-item" onClick={() => applyImport(h)}>
                <strong>{h.alias}</strong>
                <span className="mono muted small">
                  {h.username}@{h.host}:{h.port}
                </span>
              </button>
            ))}
          </div>
        )}

        <div className="form-grid">
          <label>
            <span>Name</span>
            <input className="input" value={form.name} placeholder="api-prod-1" onChange={(e) => set('name', e.target.value)} autoFocus />
          </label>
          <label>
            <span>Host or IP</span>
            <input className="input mono" value={form.host} placeholder="203.0.113.10" onChange={(e) => set('host', e.target.value)} />
          </label>
          <label>
            <span>SSH user</span>
            <input className="input mono" value={form.username} onChange={(e) => set('username', e.target.value)} />
          </label>
          <label>
            <span>Port</span>
            <input className="input mono" type="number" value={form.port} onChange={(e) => set('port', Number(e.target.value))} />
          </label>
          <label className="span-2">
            <span>Private key</span>
            <div className="input-row">
              <input className="input mono" value={form.keyPath} placeholder="Empty = use SSH agent" onChange={(e) => set('keyPath', e.target.value)} />
              <button className="btn" onClick={pick}>
                Browse…
              </button>
            </div>
          </label>
          <label>
            <span>Key passphrase</span>
            <input
              className="input"
              type="password"
              placeholder={server?.hasPassphrase ? 'Stored (leave blank to keep)' : 'Only if the key has one'}
              value={passphrase ?? ''}
              onChange={(e) => setPassphrase(e.target.value || undefined)}
            />
            <small className="muted">Encrypted with your OS keychain.</small>
          </label>
          <label>
            <span>fail2ban jail for bans</span>
            <input className="input mono" value={form.banJail} onChange={(e) => set('banJail', e.target.value)} />
            <small className="muted">Usually “sshd”.</small>
          </label>
        </div>

        {status && <div className={`form-status ${status.ok ? 'ok' : 'bad'}`}>{status.message}</div>}

        <footer className="modal-foot">
          <button className="btn btn-ghost" onClick={onClose}>
            Cancel
          </button>
          <div className="spacer" />
          <button className="btn" onClick={test} disabled={busy || !form.host}>
            Test connection
          </button>
          <button className="btn btn-primary" onClick={save} disabled={busy || !form.host || !form.username}>
            {server ? 'Save' : 'Add server'}
          </button>
        </footer>
      </div>
    </div>
  );
}
