import { useState } from 'react';
import type { Snapshot } from '../../shared/types';
import { api } from '../api';
import { Card, Empty } from '../components/ui';
import { ago } from '../format';

export function BanLog({ snap }: { snap: Snapshot }) {
  const [filter, setFilter] = useState('');
  const [busy, setBusy] = useState<string | null>(null);
  const q = filter.trim().toLowerCase();
  const rows = snap.bans.filter((b) => !q || b.ip.includes(q) || b.serverName.toLowerCase().includes(q) || b.reason.toLowerCase().includes(q));

  const unban = async (id: string, ip: string) => {
    if (!confirm(`Unban ${ip}?`)) return;
    setBusy(id);
    try {
      await api.unban(id);
    } catch (e) {
      alert(String(e));
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="stack">
      <header className="page-head">
        <h1>Ban log</h1>
        <p className="muted">Every ban Sentinel sent to fail2ban, automatic or manual.</p>
      </header>
      <Card title={`${rows.length} record${rows.length === 1 ? '' : 's'}`} actions={<input className="input input-sm" placeholder="Filter by IP, server or reason" value={filter} onChange={(e) => setFilter(e.target.value)} />}>
        {rows.length === 0 ? (
          <Empty>No bans yet.</Empty>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>When</th>
                <th>IP</th>
                <th>Server</th>
                <th>Reason</th>
                <th>Result</th>
                <th />
              </tr>
            </thead>
            <tbody>
              {rows.map((b) => (
                <tr key={b.id}>
                  <td title={new Date(b.at).toLocaleString()}>{ago(b.at)}</td>
                  <td className="mono">{b.ip}</td>
                  <td>
                    {b.serverName} <span className="muted small">/{b.jail}</span>
                  </td>
                  <td>
                    {b.auto && <span className="tag">auto</span>}
                    {b.reason}
                  </td>
                  <td>
                    {!b.ok ? (
                      <span className="tag tag-hot" title={b.error}>
                        failed
                      </span>
                    ) : b.unbannedAt ? (
                      <span className="tag">unbanned</span>
                    ) : (
                      <span className="tag tag-banned">banned</span>
                    )}
                    {!b.ok && <div className="muted small">{b.error}</div>}
                  </td>
                  <td className="right">
                    {b.ok && !b.unbannedAt && (
                      <button className="btn btn-sm" disabled={busy === b.id} onClick={() => void unban(b.id, b.ip)}>
                        Unban
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}
