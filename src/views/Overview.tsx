import type { Snapshot } from '../../shared/types';
import { Card, Empty, FindingRow, Meter, ScoreRing, Sparkline, StatePill } from '../components/ui';
import { ago, pct } from '../format';

export function Overview({ snap, open, onAdd }: { snap: Snapshot; open: (id: string) => void; onAdd: () => void }) {
  const results = Object.values(snap.results);
  const nameOf = (id: string) => snap.servers.find((s) => s.id === id)?.name ?? id;
  const healthy = results.filter((r) => r.state === 'healthy').length;
  const down = results.filter((r) => r.state === 'unreachable').length;
  const feed = results
    .flatMap((r) => r.findings.filter((f) => f.severity !== 'info').map((f) => ({ f, serverId: r.serverId })))
    .sort((a, b) => (a.f.severity === b.f.severity ? 0 : a.f.severity === 'critical' ? -1 : 1));
  const dayAgo = Date.now() - 86400000;
  const bans24 = snap.bans.filter((b) => b.ok && b.at > dayAgo).length;
  const conns = results.reduce((n, r) => n + (r.state !== 'unreachable' ? (r.metrics?.tcpEstablished ?? 0) : 0), 0);
  const failed = results.reduce((n, r) => n + (r.metrics?.failedLoginIps.reduce((a, b) => a + b.count, 0) ?? 0), 0);

  if (snap.servers.length === 0) {
    return (
      <div className="onboard">
        <h1>Watch your servers from one place</h1>
        <p>
          Sentinel signs in with your SSH key, checks health every minute, and looks for brute force, floods, spoofing and signs of intrusion. When an IP
          crosses your thresholds it goes straight to fail2ban.
        </p>
        <button className="btn btn-primary btn-lg" onClick={onAdd}>
          Add your first server
        </button>
      </div>
    );
  }

  return (
    <div className="stack">
      <header className="page-head">
        <h1>Fleet overview</h1>
        <p className="muted">
          {snap.servers.length} server{snap.servers.length === 1 ? '' : 's'} · auto-ban {snap.settings.autoBan ? <b className="on">on</b> : <b className="off">off</b>}
          {snap.settings.fleetBan && snap.settings.autoBan ? ' · fleet-wide' : ''}
        </p>
      </header>

      <div className="kpis">
        <div className="kpi">
          <span className="kpi-label">Healthy</span>
          <span className="kpi-value">
            {healthy}
            <small>/{snap.servers.length}</small>
          </span>
          {down > 0 && <span className="kpi-note bad">{down} unreachable</span>}
        </div>
        <div className={`kpi ${feed.length ? 'kpi-alert' : ''}`}>
          <span className="kpi-label">Active threats</span>
          <span className="kpi-value">{feed.length}</span>
          <span className="kpi-note">{feed.filter((x) => x.f.severity === 'critical').length} critical</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Bans · 24h</span>
          <span className="kpi-value">{bans24}</span>
          <span className="kpi-note">{snap.bans.filter((b) => b.auto && b.ok && b.at > dayAgo).length} automatic</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">Failed SSH logins</span>
          <span className="kpi-value">{failed.toLocaleString()}</span>
          <span className="kpi-note">last {snap.settings.lookbackMinutes} min</span>
        </div>
        <div className="kpi">
          <span className="kpi-label">TCP connections</span>
          <span className="kpi-value">{conns.toLocaleString()}</span>
          <span className="kpi-note">established, fleet-wide</span>
        </div>
      </div>

      <Card title="Threat feed" actions={<span className="muted">{feed.length ? 'Newest scan per server' : ''}</span>}>
        {feed.length === 0 ? (
          <Empty>No active threats. Sentinel is watching.</Empty>
        ) : (
          <div className="findings">
            {feed.slice(0, 12).map(({ f, serverId }) => (
              <FindingRow key={serverId + f.id} finding={f} serverId={serverId} serverName={nameOf(serverId)} />
            ))}
          </div>
        )}
      </Card>

      <div className="grid">
        {snap.servers.map((s) => {
          const r = snap.results[s.id];
          const m = r?.metrics;
          const state = r?.state ?? 'unknown';
          const hist = snap.history[s.id] ?? [];
          const worstDisk = m?.disks.reduce((a, d) => Math.max(a, d.percent), 0) ?? 0;
          return (
            <button key={s.id} className={`server-card state-${state}`} onClick={() => open(s.id)}>
              <div className="server-card-head">
                <div>
                  <div className="server-card-name">{s.name}</div>
                  <div className="mono muted small">
                    {s.username}@{s.host}
                    {s.port !== 22 ? `:${s.port}` : ''}
                  </div>
                </div>
                <ScoreRing score={r?.score ?? 0} state={state} />
              </div>
              <StatePill state={state} />
              {r?.error ? (
                <p className="server-card-error">{r.error}</p>
              ) : m ? (
                <div className="server-card-meters">
                  <Meter label="Load" value={m.load[0]} max={m.cpus} text={`${m.load[0].toFixed(2)} / ${m.cpus}`} />
                  <Meter label="Memory" value={pct(m.memUsed, m.memTotal)} />
                  <Meter label="Disk" value={worstDisk} />
                </div>
              ) : (
                <p className="muted small">Waiting for first scan…</p>
              )}
              <div className="server-card-foot">
                <Sparkline values={hist.map((h) => h.conns)} height={28} />
                <span className="muted small">{r ? ago(r.at) : ''}</span>
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}
