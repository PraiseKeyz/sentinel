import { useState } from 'react';
import type { IpCount, ServerConfig, Snapshot } from '../../shared/types';
import { api } from '../api';
import { BanButton, Card, Empty, FindingRow, Meter, ScoreRing, Sparkline, StatePill } from '../components/ui';
import { ago, bytes, pct } from '../format';

type Tab = 'threats' | 'network' | 'logins' | 'system' | 'fail2ban';

export function ServerDetail({ snap, server, onEdit, onDeleted }: { snap: Snapshot; server: ServerConfig; onEdit: () => void; onDeleted: () => void }) {
  const [tab, setTab] = useState<Tab>('threats');
  const r = snap.results[server.id];
  const m = r?.metrics;
  const hist = snap.history[server.id] ?? [];
  const scanning = snap.scanning.includes(server.id);
  const state = r?.state ?? 'unknown';
  const hostKeyChanged = r?.findings.some((f) => f.id === 'spoofing:hostkey');
  const flagged = new Set(r?.findings.filter((f) => f.bannable).map((f) => f.ip));
  const banned = new Set(m?.fail2ban.jails.find((j) => j.name === server.banJail)?.bannedIps ?? []);

  const remove = async () => {
    if (!confirm(`Remove ${server.name} from Sentinel? Nothing on the server is changed.`)) return;
    await api.deleteServer(server.id);
    onDeleted();
  };

  const ipTable = (rows: IpCount[], unit: string, threshold: number) =>
    rows.length === 0 ? (
      <Empty>Nothing recorded.</Empty>
    ) : (
      <table className="table">
        <thead>
          <tr>
            <th>IP address</th>
            <th className="num">{unit}</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => (
            <tr key={row.ip} className={row.count >= threshold ? 'row-hot' : ''}>
              <td className="mono">
                {row.ip}
                {row.ip === m?.clientIp && <span className="tag">you</span>}
              </td>
              <td className="num mono">{row.count.toLocaleString()}</td>
              <td className="right">
                {banned.has(row.ip) ? (
                  <span className="tag tag-banned">banned</span>
                ) : row.ip !== m?.clientIp ? (
                  <BanButton small serverId={server.id} ip={row.ip} reason={`Manual ban: ${row.count} ${unit.toLowerCase()}`} />
                ) : null}
                {flagged.has(row.ip) && !banned.has(row.ip) && <span className="tag tag-hot">flagged</span>}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    );

  const t = snap.settings.thresholds;
  const tabs: [Tab, string, number?][] = [
    ['threats', 'Threats', r?.findings.filter((f) => f.severity !== 'info').length],
    ['network', 'Network'],
    ['logins', 'Logins'],
    ['system', 'System'],
    ['fail2ban', 'fail2ban'],
  ];

  return (
    <div className="stack">
      <header className="detail-head">
        <ScoreRing score={r?.score ?? 0} state={state} size={64} />
        <div className="detail-title">
          <h1>{server.name}</h1>
          <div className="muted mono small">
            {server.username}@{server.host}:{server.port}
            {m && ` · ${m.hostname} · ${m.kernel} · up ${m.uptime}`}
          </div>
          <div className="detail-meta">
            <StatePill state={state} />
            <span className="muted small">{r ? `Scanned ${ago(r.at)} in ${(r.durationMs / 1000).toFixed(1)}s` : 'Not scanned yet'}</span>
          </div>
        </div>
        <div className="detail-actions">
          <button className="btn btn-primary" disabled={scanning} onClick={() => void api.scanNow(server.id)}>
            {scanning ? 'Scanning…' : 'Scan now'}
          </button>
          <button className="btn" onClick={onEdit}>
            Edit
          </button>
          <button className="btn btn-ghost" onClick={remove}>
            Remove
          </button>
        </div>
      </header>

      {r?.error && (
        <div className={`banner ${hostKeyChanged ? 'banner-critical' : 'banner-warning'}`}>
          <div>
            <strong>{hostKeyChanged ? 'Host key mismatch: connection refused' : 'Could not reach this server'}</strong>
            <p className="mono small">{r.error}</p>
          </div>
          {hostKeyChanged && (
            <button
              className="btn btn-danger"
              onClick={() => {
                if (confirm('Only trust the new key if you rebuilt or reinstalled this server. Continue?')) void api.trustHostKey(server.id);
              }}
            >
              Trust new key
            </button>
          )}
        </div>
      )}

      <div className="tabs">
        {tabs.map(([id, label, n]) => (
          <button key={id} className={tab === id ? 'active' : ''} onClick={() => setTab(id)}>
            {label}
            {!!n && <span className="count count-alert">{n}</span>}
          </button>
        ))}
      </div>

      {tab === 'threats' && (
        <Card>
          {r && r.findings.length > 0 ? (
            <div className="findings">
              {r.findings.map((f) => (
                <FindingRow key={f.id} finding={f} serverId={server.id} />
              ))}
            </div>
          ) : (
            <Empty>{r ? 'All checks passed on the last scan.' : 'Waiting for the first scan…'}</Empty>
          )}
        </Card>
      )}

      {tab === 'network' && m && (
        <>
          <div className="kpis kpis-3">
            <div className="kpi">
              <span className="kpi-label">Established</span>
              <span className="kpi-value">{m.tcpEstablished.toLocaleString()}</span>
              <Sparkline values={hist.map((h) => h.conns)} />
            </div>
            <div className={`kpi ${m.synRecv >= t.synRecv ? 'kpi-alert' : ''}`}>
              <span className="kpi-label">Half-open (SYN_RECV)</span>
              <span className="kpi-value">{m.synRecv.toLocaleString()}</span>
              <span className="kpi-note">alert at {t.synRecv} · SYN cookies {m.syncookies === 1 ? 'on' : m.syncookies === 0 ? 'off' : '?'}</span>
            </div>
            <div className="kpi">
              <span className="kpi-label">Anti-spoofing</span>
              <span className="kpi-value small-value">{m.rpFilter === null ? '?' : m.rpFilter > 0 ? 'rp_filter on' : 'rp_filter off'}</span>
              <span className="kpi-note">
                {m.martians} martian packets · gateway {m.gatewayIp ?? '?'} {m.gatewayMac ? `(${m.gatewayMac})` : ''}
              </span>
            </div>
          </div>
          <div className="two-col">
            <Card title="Top connections by IP">{ipTable(m.topConnIps, 'Connections', t.connectionsPerIp)}</Card>
            <Card title="Web requests by IP" actions={<span className="muted small mono">{m.httpLogPath ?? 'no access log found'}</span>}>
              {ipTable(m.httpTopIps, 'Requests', t.httpRequestsPerIp)}
            </Card>
          </div>
          <Card title="Listening ports">
            <table className="table">
              <thead>
                <tr>
                  <th>Proto</th>
                  <th>Address</th>
                  <th>Process</th>
                </tr>
              </thead>
              <tbody>
                {m.listening.map((l, i) => (
                  <tr key={i}>
                    <td className="mono">{l.proto}</td>
                    <td className="mono">{l.local}</td>
                    <td>{l.process || <span className="muted">needs sudo</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {tab === 'logins' && m && (
        <div className="two-col">
          <Card title={`Failed SSH logins · last ${snap.settings.lookbackMinutes} min`} actions={<Sparkline className="spark-bad" values={hist.map((h) => h.failed)} height={24} />}>
            {ipTable(m.failedLoginIps, 'Attempts', t.failedLogins)}
          </Card>
          <Card title="Successful logins">
            {m.acceptedLogins.length === 0 ? (
              <Empty>None in this window.</Empty>
            ) : (
              <table className="table">
                <thead>
                  <tr>
                    <th>User</th>
                    <th>From</th>
                    <th>Method</th>
                  </tr>
                </thead>
                <tbody>
                  {m.acceptedLogins.map((l, i) => (
                    <tr key={i} className={l.method === 'password' ? 'row-hot' : ''}>
                      <td>{l.user}</td>
                      <td className="mono">
                        {l.ip}
                        {l.ip === m.clientIp && <span className="tag">you</span>}
                      </td>
                      <td>{l.method}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </Card>
        </div>
      )}

      {tab === 'system' && m && (
        <>
          <div className="two-col">
            <Card title="Resources">
              <div className="meters">
                <Meter label={`Load (${m.cpus} CPU)`} value={m.load[0]} max={m.cpus} text={m.load.map((l) => l.toFixed(2)).join(' · ')} />
                <Meter label="Memory" value={pct(m.memUsed, m.memTotal)} text={`${bytes(m.memUsed)} / ${bytes(m.memTotal)}`} />
                {m.swapTotal > 0 && <Meter label="Swap" value={pct(m.swapUsed, m.swapTotal)} text={`${bytes(m.swapUsed)} / ${bytes(m.swapTotal)}`} />}
                {m.disks.map((d) => (
                  <Meter key={d.mount} label={`Disk ${d.mount}`} value={d.percent} text={`${bytes(d.used)} / ${bytes(d.size)}`} />
                ))}
              </div>
            </Card>
            <Card title="History">
              <div className="hist">
                <span className="muted small">Load per core</span>
                <Sparkline values={hist.map((h) => h.load)} height={48} />
                <span className="muted small">Memory</span>
                <Sparkline values={hist.map((h) => h.mem)} height={48} />
              </div>
            </Card>
          </div>
          <Card title="Top processes">
            <table className="table">
              <thead>
                <tr>
                  <th>PID</th>
                  <th>User</th>
                  <th>Command</th>
                  <th className="num">CPU %</th>
                  <th className="num">Mem %</th>
                </tr>
              </thead>
              <tbody>
                {m.topProcs.map((p) => (
                  <tr key={p.pid}>
                    <td className="mono">{p.pid}</td>
                    <td>{p.user}</td>
                    <td className="mono">{p.cmd}</td>
                    <td className="num mono">{p.cpu.toFixed(1)}</td>
                    <td className="num mono">{p.mem.toFixed(1)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </Card>
        </>
      )}

      {tab === 'fail2ban' && m && (
        <Card title="fail2ban" actions={<span className="muted small">Sentinel bans go to the “{server.banJail}” jail</span>}>
          {!m.fail2ban.installed ? (
            <Empty>fail2ban is not installed on this server.</Empty>
          ) : !m.fail2ban.accessible ? (
            <Empty>fail2ban is installed, but this SSH user can’t control it. Give it passwordless sudo for fail2ban-client.</Empty>
          ) : (
            <table className="table">
              <thead>
                <tr>
                  <th>Jail</th>
                  <th className="num">Banned now</th>
                  <th className="num">Total</th>
                  <th>Banned IPs</th>
                </tr>
              </thead>
              <tbody>
                {m.fail2ban.jails.map((j) => (
                  <tr key={j.name}>
                    <td>{j.name}</td>
                    <td className="num mono">{j.currentlyBanned}</td>
                    <td className="num mono">{j.totalBanned}</td>
                    <td className="mono small wrap">{j.bannedIps.slice(0, 40).join('  ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </Card>
      )}

      {tab !== 'threats' && !m && <Empty>No data yet for this server.</Empty>}
    </div>
  );
}
