import { useEffect, useState } from 'react';
import type { ServerConfig, Snapshot } from '../shared/types';
import { api, isDemo, isMac } from './api';
import { ServerForm } from './components/ServerForm';
import { StateDot } from './components/ui';
import { BanLog } from './views/BanLog';
import { Overview } from './views/Overview';
import { ServerDetail } from './views/ServerDetail';
import { SettingsView } from './views/SettingsView';

export type View = { kind: 'overview' } | { kind: 'server'; id: string } | { kind: 'bans' } | { kind: 'settings' };

function useSnapshot(): Snapshot | null {
  const [snap, setSnap] = useState<Snapshot | null>(null);
  useEffect(() => {
    void api.getSnapshot().then(setSnap);
    return api.onSnapshot(setSnap);
  }, []);
  return snap;
}

/** Re-render every second so relative times and the countdown stay live. */
function useTick() {
  const [, set] = useState(0);
  useEffect(() => {
    const t = setInterval(() => set((n) => n + 1), 1000);
    return () => clearInterval(t);
  }, []);
}

export function App() {
  const snap = useSnapshot();
  const [view, setView] = useState<View>({ kind: 'overview' });
  const [editing, setEditing] = useState<ServerConfig | 'new' | null>(null);
  useTick();

  if (!snap) return <div className="boot">Starting Sentinel…</div>;

  const scanningAll = snap.scanning.length > 0;
  const nextIn = snap.nextScanAt ? Math.max(0, Math.round((snap.nextScanAt - Date.now()) / 1000)) : null;
  const threats = Object.values(snap.results).reduce((n, r) => n + r.findings.filter((f) => f.severity !== 'info').length, 0);
  const sorted = [...snap.servers].sort((a, b) => a.name.localeCompare(b.name));
  const current = view.kind === 'server' ? snap.servers.find((s) => s.id === view.id) : undefined;

  return (
    <div className={`app ${isMac ? 'mac' : ''}`}>
      <aside className="sidebar">
        <div className="brand drag">
          <svg viewBox="0 0 24 24" width="22" height="22" aria-hidden>
            <path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5l-8-3Z" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinejoin="round" />
            <path d="m8.5 12 2.5 2.5 4.5-5" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
          <span>Sentinel</span>
          {isDemo && <span className="demo-tag">demo</span>}
        </div>

        <nav className="nav">
          <button className={view.kind === 'overview' ? 'active' : ''} onClick={() => setView({ kind: 'overview' })}>
            Overview {threats > 0 && <span className="count count-alert">{threats}</span>}
          </button>
          <button className={view.kind === 'bans' ? 'active' : ''} onClick={() => setView({ kind: 'bans' })}>
            Ban log
          </button>
          <button className={view.kind === 'settings' ? 'active' : ''} onClick={() => setView({ kind: 'settings' })}>
            Settings
          </button>
        </nav>

        <div className="side-label">
          <span>Servers</span>
          <button className="icon-btn" title="Add server" onClick={() => setEditing('new')}>
            +
          </button>
        </div>
        <div className="server-list">
          {sorted.map((s) => {
            const r = snap.results[s.id];
            const scanning = snap.scanning.includes(s.id);
            return (
              <button key={s.id} className={`server-item ${view.kind === 'server' && view.id === s.id ? 'active' : ''}`} onClick={() => setView({ kind: 'server', id: s.id })}>
                <StateDot state={scanning && !r ? 'scanning' : (r?.state ?? 'unknown')} />
                <span className="server-item-name">{s.name}</span>
                {scanning ? <span className="spinner" /> : r && r.state !== 'unreachable' && <span className="server-item-score">{r.score}</span>}
              </button>
            );
          })}
          {sorted.length === 0 && <p className="side-hint">No servers yet.</p>}
        </div>

        <div className="side-foot">
          <button className="btn btn-block" onClick={() => void api.scanNow()} disabled={scanningAll || snap.servers.length === 0}>
            {scanningAll ? `Scanning ${snap.scanning.length}…` : 'Scan all now'}
          </button>
          <div className="side-meta">{nextIn !== null && !scanningAll ? `Next scan in ${nextIn}s` : ' '}</div>
        </div>
      </aside>

      <main className="main">
        <div className="titlebar drag" />
        <div className="content">
          {view.kind === 'overview' && <Overview snap={snap} open={(id) => setView({ kind: 'server', id })} onAdd={() => setEditing('new')} />}
          {view.kind === 'server' && current && (
            <ServerDetail
              snap={snap}
              server={current}
              onEdit={() => setEditing(current)}
              onDeleted={() => setView({ kind: 'overview' })}
            />
          )}
          {view.kind === 'bans' && <BanLog snap={snap} />}
          {view.kind === 'settings' && <SettingsView settings={snap.settings} />}
        </div>
      </main>

      {editing && (
        <ServerForm
          server={editing === 'new' ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={(s) => {
            setEditing(null);
            setView({ kind: 'server', id: s.id });
          }}
        />
      )}
    </div>
  );
}
