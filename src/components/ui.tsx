import { useState, type ReactNode } from 'react';
import type { Finding, ServerState } from '../../shared/types';
import { api } from '../api';
import { categoryLabel, stateLabel } from '../format';

export function StateDot({ state }: { state: ServerState }) {
  return <span className={`dot dot-${state}`} aria-label={stateLabel[state]} />;
}

export function StatePill({ state }: { state: ServerState }) {
  return (
    <span className={`pill pill-${state}`}>
      <StateDot state={state} />
      {stateLabel[state]}
    </span>
  );
}

export function ScoreRing({ score, state, size = 52 }: { score: number; state: ServerState; size?: number }) {
  const r = size / 2 - 5;
  const c = 2 * Math.PI * r;
  const known = state !== 'unknown' && state !== 'unreachable';
  return (
    <svg width={size} height={size} className={`ring ring-${state}`} role="img" aria-label={`Score ${known ? score : 'unknown'}`}>
      <circle cx={size / 2} cy={size / 2} r={r} className="ring-track" />
      <circle
        cx={size / 2}
        cy={size / 2}
        r={r}
        className="ring-value"
        strokeDasharray={c}
        strokeDashoffset={known ? c * (1 - score / 100) : c}
        transform={`rotate(-90 ${size / 2} ${size / 2})`}
      />
      <text x="50%" y="50%" dominantBaseline="central" textAnchor="middle">
        {known ? score : '–'}
      </text>
    </svg>
  );
}

export function Meter({ label, value, max = 100, warn = 75, crit = 90, text }: { label: string; value: number; max?: number; warn?: number; crit?: number; text?: string }) {
  const p = Math.max(0, Math.min(100, (value / max) * 100));
  const level = p >= crit ? 'crit' : p >= warn ? 'warn' : 'ok';
  return (
    <div className="meter">
      <div className="meter-head">
        <span>{label}</span>
        <span className="mono">{text ?? `${Math.round(p)}%`}</span>
      </div>
      <div className="meter-track">
        <div className={`meter-fill meter-${level}`} style={{ width: `${p}%` }} />
      </div>
    </div>
  );
}

export function Sparkline({ values, height = 36, className = '' }: { values: number[]; height?: number; className?: string }) {
  const w = 200;
  if (values.length < 2) return <svg className={`spark ${className}`} viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" />;
  const max = Math.max(...values, 1e-9);
  const pts = values.map((v, i) => [(i / (values.length - 1)) * w, height - 2 - (v / max) * (height - 4)]);
  const line = pts.map(([x, y], i) => `${i ? 'L' : 'M'}${x.toFixed(1)},${y.toFixed(1)}`).join(' ');
  return (
    <svg className={`spark ${className}`} viewBox={`0 0 ${w} ${height}`} preserveAspectRatio="none" aria-hidden>
      <path d={`${line} L${w},${height} L0,${height} Z`} className="spark-area" />
      <path d={line} className="spark-line" vectorEffect="non-scaling-stroke" />
    </svg>
  );
}

export function Card({ title, actions, children, className = '' }: { title?: ReactNode; actions?: ReactNode; children: ReactNode; className?: string }) {
  return (
    <section className={`card ${className}`}>
      {(title || actions) && (
        <header className="card-head">
          <h3>{title}</h3>
          <div className="card-actions">{actions}</div>
        </header>
      )}
      {children}
    </section>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <div className="empty">{children}</div>;
}

export function BanButton({ serverId, ip, reason, small }: { serverId: string; ip: string; reason: string; small?: boolean }) {
  const [state, setState] = useState<'idle' | 'busy' | 'done' | 'error'>('idle');
  const [error, setError] = useState('');
  const run = async () => {
    if (!confirm(`Ban ${ip} with fail2ban?\n\n${reason}`)) return;
    setState('busy');
    try {
      const rec = await api.ban(serverId, ip, reason);
      setState(rec.ok ? 'done' : 'error');
      setError(rec.error ?? '');
    } catch (e) {
      setState('error');
      setError(String(e));
    }
  };
  if (state === 'done') return <span className="ban-done">Banned</span>;
  return (
    <button className={`btn btn-danger ${small ? 'btn-sm' : ''}`} onClick={run} disabled={state === 'busy'} title={error || `Ban ${ip}`}>
      {state === 'busy' ? 'Banning…' : state === 'error' ? 'Retry ban' : 'Ban'}
    </button>
  );
}

export function FindingRow({ finding, serverId, serverName }: { finding: Finding; serverId: string; serverName?: string }) {
  return (
    <div className={`finding finding-${finding.severity}`}>
      <div className="finding-bar" />
      <div className="finding-body">
        <div className="finding-title">
          <span className={`sev sev-${finding.severity}`}>{finding.severity}</span>
          <span className="cat">{categoryLabel[finding.category]}</span>
          {serverName && <span className="finding-server">{serverName}</span>}
          <strong>{finding.title}</strong>
        </div>
        <p>{finding.detail}</p>
      </div>
      {finding.bannable && finding.ip && <BanButton serverId={serverId} ip={finding.ip} reason={finding.title} />}
    </div>
  );
}
