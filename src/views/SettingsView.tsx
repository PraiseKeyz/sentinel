import { useEffect, useState } from 'react';
import type { Settings, Thresholds } from '../../shared/types';
import { api } from '../api';
import { Card } from '../components/ui';

const thresholdFields: [keyof Thresholds, string, string][] = [
  ['failedLogins', 'Failed SSH logins per IP', 'In the lookback window. Crossing it flags brute force and triggers a ban.'],
  ['connectionsPerIp', 'Connections per IP', 'Established TCP connections from one address.'],
  ['httpRequestsPerIp', 'Web requests per IP', 'Out of the last 20,000 access-log lines.'],
  ['synRecv', 'Half-open connections', 'SYN_RECV sockets server-wide (SYN flood).'],
  ['loadPerCore', 'Load per CPU core', '1-minute load average ÷ CPU count.'],
  ['memPercent', 'Memory %', ''],
  ['diskPercent', 'Disk %', 'Per mount point.'],
];

export function SettingsView({ settings }: { settings: Settings }) {
  const [s, setS] = useState(settings);
  const [whitelist, setWhitelist] = useState(settings.whitelist.join('\n'));
  const [saved, setSaved] = useState(false);
  useEffect(() => {
    setS(settings);
    setWhitelist(settings.whitelist.join('\n'));
  }, [settings]);

  const save = async () => {
    await api.saveSettings({ ...s, whitelist: whitelist.split(/[\s,]+/).filter(Boolean) });
    setSaved(true);
    setTimeout(() => setSaved(false), 1800);
  };
  const setT = (k: keyof Thresholds, v: string) => setS({ ...s, thresholds: { ...s.thresholds, [k]: Number(v) } });

  return (
    <div className="stack narrow">
      <header className="page-head">
        <h1>Settings</h1>
      </header>

      <Card title="Response">
        <label className="switch-row">
          <input type="checkbox" checked={s.autoBan} onChange={(e) => setS({ ...s, autoBan: e.target.checked })} />
          <div>
            <strong>Auto-ban suspicious IPs with fail2ban</strong>
            <p className="muted small">IPs that cross a threshold are sent straight to the server’s ban jail. Whitelisted IPs, your own IP and your servers are never banned.</p>
          </div>
        </label>
        <label className="switch-row">
          <input type="checkbox" checked={s.fleetBan} onChange={(e) => setS({ ...s, fleetBan: e.target.checked })} />
          <div>
            <strong>Fleet-wide bans</strong>
            <p className="muted small">When an IP is banned on one server, ban it on all of them.</p>
          </div>
        </label>
        <label className="switch-row">
          <input type="checkbox" checked={s.notifications} onChange={(e) => setS({ ...s, notifications: e.target.checked })} />
          <div>
            <strong>Desktop notifications</strong>
            <p className="muted small">For new critical findings, bans and servers going offline.</p>
          </div>
        </label>
      </Card>

      <Card title="Scanning">
        <div className="form-grid">
          <label>
            <span>Scan every (seconds)</span>
            <input className="input" type="number" min={15} value={s.scanIntervalSec} onChange={(e) => setS({ ...s, scanIntervalSec: Number(e.target.value) })} />
          </label>
          <label>
            <span>Log lookback (minutes)</span>
            <input className="input" type="number" min={5} value={s.lookbackMinutes} onChange={(e) => setS({ ...s, lookbackMinutes: Number(e.target.value) })} />
          </label>
        </div>
      </Card>

      <Card title="Thresholds">
        <div className="form-grid">
          {thresholdFields.map(([k, label, hint]) => (
            <label key={k}>
              <span>{label}</span>
              <input className="input" type="number" step={k === 'loadPerCore' ? 0.1 : 1} value={s.thresholds[k]} onChange={(e) => setT(k, e.target.value)} />
              {hint && <small className="muted">{hint}</small>}
            </label>
          ))}
        </div>
      </Card>

      <Card title="Never ban (whitelist)">
        <p className="muted small">One IP or CIDR per line, for example your office range 102.89.0.0/16.</p>
        <textarea className="input mono" rows={5} value={whitelist} onChange={(e) => setWhitelist(e.target.value)} />
      </Card>

      <div className="save-bar">
        <button className="btn btn-primary" onClick={save}>
          Save settings
        </button>
        {saved && <span className="ok-text">Saved</span>}
      </div>
    </div>
  );
}
