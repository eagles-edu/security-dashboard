import { useCallback, useEffect, useMemo, useRef, useState } from 'react';

const number = new Intl.NumberFormat('en-US');
const dateFormat = new Intl.DateTimeFormat('en', { month: 'short', day: 'numeric' });
const timeFormat = new Intl.DateTimeFormat('en', { hour: '2-digit', minute: '2-digit' });
const REFRESH_INTERVAL = 30_000;

function fmt(value) {
  return Number.isFinite(Number(value)) ? number.format(Number(value)) : '—';
}

function formatSources(value) {
  const sources = String(value || '').split(',').map((source) => source.trim())
    .map((source) => source.replace(/^CrowdSec crowdsec$/i, 'CrowdSec'))
    .filter(Boolean);
  return [...new Set(sources)].join(', ') || '—';
}

async function api(url, options) {
  const response = await fetch(url, { cache: 'no-store', ...options });
  const body = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(body.error || `Request failed (${response.status})`);
  return body;
}

function Spark({ tone, data = [] }) {
  const values = data.map((value) => Number(value) || 0);
  const max = Math.max(1, ...values);
  return <svg className={`spark spark-${tone}`} viewBox="0 0 72 34" aria-hidden="true">
    {values.slice(-8).map((value, index, array) => {
      const height = Math.max(3, (value / max) * 30);
      return <rect key={index} x={index * 9 + 2} y={32 - height} width="4" height={height} rx="1" opacity={0.45 + (index / array.length) * 0.5} />;
    })}
  </svg>;
}

function Metric({ title, value, tone, values, note }) {
  return <section className="metric" aria-label={`${title}: ${value}`}>
    <div className="metric-head"><h2>{title}</h2><Spark tone={tone} data={values} /></div>
    <div className="metric-value"><span className={`tone-dot ${tone}`} /><strong>{value}</strong></div>
    <p>{note}</p>
  </section>;
}

function chartPath(points, key, max, width, height, top = 34, bottom = 24) {
  const values = points.map((point) => point[key]);
  const usableHeight = height - top - bottom;
  return values.map((value, index) => {
    if (value === null || value === undefined) return '';
    const x = points.length <= 1 ? width / 2 : (index / (points.length - 1)) * width;
    const y = height - bottom - (Number(value) / Math.max(1, max)) * usableHeight;
    return `${index === 0 || values[index - 1] == null ? 'M' : 'L'}${x.toFixed(1)},${y.toFixed(1)}`;
  }).filter(Boolean).join(' ');
}

function TrendChart({ points, coverage, range, coverageText }) {
  const [mobile, setMobile] = useState(() => window.matchMedia('(max-width: 700px)').matches);
  useEffect(() => {
    const media = window.matchMedia('(max-width: 700px)');
    const update = (event) => setMobile(event.matches);
    media.addEventListener('change', update);
    return () => media.removeEventListener('change', update);
  }, []);
  const width = mobile ? 420 : 900;
  const height = 250;
  const chartPoints = useMemo(() => {
    if (!points.length) return [];
    const granularity = range === '24h' ? 3_600_000 : 86_400_000;
    const now = Date.now();
    const count = range === '24h' ? 24 : range === '7d' ? 7 : 90;
    const start = Math.floor((now - (count - 1) * granularity) / granularity) * granularity;
    const byBucket = new Map(points.map((point) => [Number(point.bucket), point]));
    const coverageStart = coverage?.start == null ? Infinity : Number(coverage.start);
    return Array.from({ length: count }, (_, index) => {
      const bucket = start + index * granularity;
      const match = byBucket.get(bucket);
      const observed = bucket >= coverageStart;
      return {
        bucket,
        requests: match?.requests ?? (observed ? 0 : null),
        suspicious: match?.suspicious ?? (observed ? 0 : null),
        crowdsec: match?.crowdsec ?? (observed ? 0 : null),
        fail2ban: match?.fail2ban ?? (observed ? 0 : null),
        firewall: match?.firewall ?? (observed ? 0 : null),
        active_bans: match?.active_bans ?? (observed ? 0 : null),
      };
    });
  }, [points, coverage, range]);

  const maxRequests = Math.max(1, ...chartPoints.map((point) => Number(point.requests) || 0));
  const maxSignals = Math.max(1, ...chartPoints.flatMap((point) => [point.suspicious, point.crowdsec, point.fail2ban, point.firewall, point.active_bans]).map((value) => Number(value) || 0));
  const leftTicks = [0, 0.5, 1].map((ratio) => Math.round(maxRequests * ratio));
  const rightTicks = [0, 0.5, 1].map((ratio) => Math.round(maxSignals * ratio));
  const labelStep = Math.max(1, Math.floor(chartPoints.length / 6));
  const nonempty = chartPoints.some((point) => ['requests', 'suspicious', 'crowdsec', 'fail2ban', 'firewall', 'active_bans'].some((key) => point[key] !== null));

  return <div className="chart-wrap">
    {nonempty ? <>
      <div className="chart-axis-label left">Requests</div><div className="chart-axis-label right">Signals / bans</div>
      <svg className="trend-chart" viewBox={`0 0 ${width} ${height}`} role="img" aria-label={`Origin-side requests and security signals over ${range}`}>
        {[0, 0.5, 1].map((ratio, index) => {
          const y = height - 24 - ratio * (height - 58);
          return <g key={ratio}>
            <line x1="42" x2={width - 42} y1={y} y2={y} className="gridline" />
            <text x="4" y={y + 4} className="axis-text">{fmt(leftTicks[index])}</text>
            <text x={width - 38} y={y + 4} textAnchor="end" className="axis-text">{fmt(rightTicks[index])}</text>
          </g>;
        })}
        <g transform="translate(44 0)" className="series-area">
          <path d={chartPath(chartPoints, 'requests', maxRequests, width - 88, height, 34, 24)} className="series-line requests" />
          <path d={chartPath(chartPoints, 'suspicious', maxSignals, width - 88, height, 34, 24)} className="series-line suspicious" />
          <path d={chartPath(chartPoints, 'crowdsec', maxSignals, width - 88, height, 34, 24)} className="series-line crowdsec" />
          <path d={chartPath(chartPoints, 'fail2ban', maxSignals, width - 88, height, 34, 24)} className="series-line fail2ban" />
          <path d={chartPath(chartPoints, 'firewall', maxSignals, width - 88, height, 34, 24)} className="series-line firewall" />
          <path d={chartPath(chartPoints, 'active_bans', maxSignals, width - 88, height, 34, 24)} className="series-line active-bans" />
        </g>
        {chartPoints.filter((_, index) => index % labelStep === 0 || index === chartPoints.length - 1).map((point) => {
          const x = 44 + (chartPoints.length <= 1 ? (width - 88) / 2 : (chartPoints.indexOf(point) / (chartPoints.length - 1)) * (width - 88));
          const label = range === '24h' ? timeFormat.format(point.bucket) : dateFormat.format(point.bucket);
          return <text key={point.bucket} x={x} y={height - 4} textAnchor="middle" className="axis-text">{label}</text>;
        })}
      </svg>
    </> : <div className="chart-empty"><span className="pulse-mark" />Collecting host telemetry. No historical values are being fabricated.</div>}
    <p className="chart-note">{coverageText}. Requests use the left scale; security signals and active-ban counts use the right scale. Detection counts are distinct events. Origin telemetry only.</p>
  </div>;
}

function SourceBreakdown({ totals, health }) {
  const rows = [
    { label: 'CrowdSec HTTP', value: totals.crowdsecHttp, source: health?.crowdsecAlerts, tone: 'teal' },
    { label: 'CrowdSec SSH', value: totals.crowdsecSsh, source: health?.crowdsecAlerts, tone: 'teal' },
    { label: 'Fail2ban SSH', value: totals.fail2ban, source: health?.fail2banLog, tone: 'yellow' },
    { label: 'Origin firewall', value: totals.firewall, source: health?.firewall, tone: 'red' },
  ];
  return <aside className="source-panel surface">
    <h2 title="Counts are distinct source events, not unique attack attempts or confirmed drops">Detections by source</h2>
    <div className="source-list">
      {rows.map((row) => <div className="source-row" key={row.label}>
        <span className={`tone-dot ${row.tone}`} /><span>{row.label}</span>
        <strong>{row.source?.status === 'ok' ? fmt(row.value) : '—'}</strong>
      </div>)}
    </div>
  </aside>;
}

function timeAgo(timestamp) {
  if (!timestamp) return '—';
  const date = new Date(timestamp);
  const delta = Date.now() - date.getTime();
  if (!Number.isFinite(delta)) return '—';
  if (delta < 60_000) return 'just now';
  if (delta < 3_600_000) return `${Math.floor(delta / 60_000)}m ago`;
  if (delta < 86_400_000) return `${Math.floor(delta / 3_600_000)}h ago`;
  return `${Math.floor(delta / 86_400_000)}d ago`;
}

function BanForm({ onClose, onSubmit, busy }) {
  const [ip, setIp] = useState('');
  const [reason, setReason] = useState('');
  const [error, setError] = useState('');
  function submit(event) {
    event.preventDefault();
    setError('');
    onSubmit({ ip: ip.trim(), reason: reason.trim() }).catch((caught) => setError(caught.message));
  }
  return <div className="dialog-backdrop" role="presentation" onMouseDown={(event) => { if (event.target === event.currentTarget) onClose(); }}>
    <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="ban-title">
      <button className="icon-button dialog-close" onClick={onClose} aria-label="Close dialog">×</button>
      <h2 id="ban-title">Ban IP</h2>
      <p>This block has no expiry. It stays active until you manually unban it.</p>
      <form onSubmit={submit}>
        <label>IP address<input autoFocus autoComplete="off" inputMode="text" value={ip} onChange={(event) => setIp(event.target.value)} placeholder="IPv4 or IPv6 address" required /></label>
        <label>Reason<input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="Short investigation note" minLength="3" maxLength="160" required /></label>
        {error && <p className="form-error" role="alert">{error}</p>}
        <div className="dialog-actions"><button type="button" className="secondary-button" onClick={onClose}>Cancel</button><button type="submit" className="primary-button" disabled={busy}>{busy ? 'Applying…' : 'Ban IP'}</button></div>
      </form>
    </section>
  </div>;
}

function UnbanDialog({ ban, onClose, onConfirm, busy }) {
  return <div className="dialog-backdrop" role="presentation">
    <section className="dialog" role="dialog" aria-modal="true" aria-labelledby="unban-title">
      <button className="icon-button dialog-close" onClick={onClose} aria-label="Close dialog">×</button>
      <h2 id="unban-title">Unban IP</h2>
      <p>Remove <code>{ban.ip}</code> from persistent host enforcement and clear its current CrowdSec/Fail2ban decisions. A new detection may ban it again.</p>
      <div className="dialog-actions"><button className="secondary-button" onClick={onClose}>Cancel</button><button className="danger-button" onClick={onConfirm} disabled={busy}>{busy ? 'Removing…' : 'Unban IP'}</button></div>
    </section>
  </div>;
}

function compareIpAddresses(left, right) {
  const leftVersion = left.includes(':') ? 6 : 4;
  const rightVersion = right.includes(':') ? 6 : 4;
  if (leftVersion !== rightVersion) return leftVersion - rightVersion;

  const toParts = (value, version) => {
    if (version === 4) return value.split('.').map(Number);
    const halves = value.split('::');
    const leftParts = halves[0] ? halves[0].split(':') : [];
    const rightParts = halves[1] ? halves[1].split(':') : [];
    const missing = 8 - leftParts.length - rightParts.length;
    return [...leftParts, ...Array(Math.max(0, missing)).fill('0'), ...rightParts].map((part) => Number.parseInt(part || '0', 16));
  };
  const leftParts = toParts(left, leftVersion);
  const rightParts = toParts(right, rightVersion);
  for (let index = 0; index < leftParts.length; index += 1) {
    if (leftParts[index] !== rightParts[index]) return leftParts[index] - rightParts[index];
  }
  return 0;
}

const BAN_SORT_COLUMNS = [
  ['ip', 'IP address'],
  ['country', 'Country'],
  ['source', 'Source'],
  ['reason', 'Reason'],
  ['signals24h', '24h signals'],
  ['signals90d', '90d signals'],
  ['lastSeen', 'Last seen'],
];

function CountryCell({ country }) {
  if (!country?.code) return 'Unknown';
  const code = String(country.code).toUpperCase();
  if (!/^[A-Z]{2}$/.test(code)) return code;
  return <span className="country-value" title={country.name || code} aria-label={`${country.name || 'Country'} (${code})`}>
    <img className="country-flag" src={`/flags/flag-icons-7.6.0/4x3/${code.toLowerCase()}.svg`} alt="" aria-hidden="true" loading="lazy" decoding="async" onError={(event) => { event.currentTarget.hidden = true; }} />
    <span>{code}</span>
  </span>;
}

function BanTable({ bans, onBan, onUnban }) {
  const [sort, setSort] = useState({ key: 'lastSeen', direction: 'desc' });
  const sortedBans = useMemo(() => [...bans].sort((left, right) => {
    const leftValue = sort.key === 'country' ? (left.country?.name || left.country?.code || '') : left[sort.key];
    const rightValue = sort.key === 'country' ? (right.country?.name || right.country?.code || '') : right[sort.key];
    const leftMissing = leftValue === null || leftValue === undefined || leftValue === '';
    const rightMissing = rightValue === null || rightValue === undefined || rightValue === '';
    if (leftMissing !== rightMissing) return leftMissing ? 1 : -1;

    let result = 0;
    if (!leftMissing && sort.key === 'ip') result = compareIpAddresses(String(leftValue), String(rightValue));
    else if (!leftMissing && ['signals24h', 'signals90d', 'lastSeen'].includes(sort.key)) result = Number(leftValue) - Number(rightValue);
    else if (!leftMissing) result = String(leftValue).localeCompare(String(rightValue), undefined, { numeric: true, sensitivity: 'base' });
    if (result !== 0) return sort.direction === 'asc' ? result : -result;
    return compareIpAddresses(left.ip, right.ip);
  }), [bans, sort]);

  function changeSort(key) {
    setSort((current) => current.key === key
      ? { key, direction: current.direction === 'asc' ? 'desc' : 'asc' }
      : { key, direction: 'asc' });
  }

  const sortLabel = `${sort.key === 'lastSeen' ? 'Last seen' : BAN_SORT_COLUMNS.find(([key]) => key === sort.key)?.[1]} ${sort.direction === 'asc' ? 'ascending' : 'descending'}`;

  return <section className="ban-panel surface">
    <header className="panel-header"><div><h2>Active banned IPs</h2><p>Persistent origin enforcement; only manual unban releases a block.</p></div><button className="primary-button" onClick={onBan}>Ban IP</button></header>
    {bans.length ? <div className="table-scroll">
      <div className="mobile-sort-controls">
        <label className="visually-hidden" htmlFor="ban-sort-column">Sort bans by</label>
        <select id="ban-sort-column" value={sort.key} onChange={(event) => changeSort(event.target.value)}>
          {BAN_SORT_COLUMNS.map(([key, label]) => <option key={key} value={key}>{label}</option>)}
        </select>
        <button className="sort-direction-button" type="button" onClick={() => changeSort(sort.key)} aria-label={`Sort ${sortLabel}`} title={`Sort ${sortLabel}`}>
          {sort.direction === 'asc' ? 'Ascending ↑' : 'Descending ↓'}
        </button>
      </div>
      <table>
      <thead><tr>{BAN_SORT_COLUMNS.map(([key, label]) => <th key={key} aria-sort={sort.key === key ? (sort.direction === 'asc' ? 'ascending' : 'descending') : 'none'}>
        <button className="sort-button" type="button" onClick={() => changeSort(key)} aria-label={`Sort by ${label}${sort.key === key ? `, ${sort.direction === 'asc' ? 'ascending' : 'descending'}` : ''}`}>
          {label}<span aria-hidden="true">{sort.key === key ? (sort.direction === 'asc' ? ' ↑' : ' ↓') : ' ↕'}</span>
        </button>
      </th>)}<th>Action</th></tr></thead>
      <tbody>{sortedBans.map((ban) => <tr key={ban.ip}>
        <td data-label="IP address"><code>{ban.ip}</code>{ban.protected && <span className="protected-tag" title="This IP is in a protected proxy or trusted range">Protected</span>}</td>
        <td data-label="Country"><CountryCell country={ban.country} /></td>
        <td data-label="Source">{formatSources(ban.source)}</td>
        <td data-label="Reason" className="reason-cell">{ban.reason || '—'}</td>
        <td data-label="24h signals">{fmt(ban.signals24h)}</td>
        <td data-label="90d signals">{fmt(ban.signals90d)}</td>
        <td data-label="Last seen">{timeAgo(ban.lastSeen)}</td>
        <td data-label="Action"><button className="text-action" onClick={() => onUnban(ban)}>Unban</button></td>
      </tr>)}</tbody>
      </table>
    </div> : <div className="empty-bans"><span className="empty-shield">◇</span><div><strong>No active bans reported</strong><p>When CrowdSec, Fail2ban, or a manual action blocks an IP, it will appear here.</p></div></div>}
  </section>;
}

function StatusFooter({ health }) {
  const oneShield = health?.sources?.oneShield;
  const last = health?.generatedAt ? `Last checked ${timeAgo(health.generatedAt)}` : 'Waiting for first source check';
  const states = [
    ['Nginx logs', health?.sources?.nginx],
    ['CrowdSec', health?.sources?.crowdsec],
    ['Fail2ban', health?.sources?.fail2ban],
    ['Origin firewall', health?.sources?.firewall],
  ];
  return <footer className="status-footer">
    <div className="status-items">{states.map(([label, source]) => <span key={label} className={`status-item ${source?.status || 'pending'}`} title={source?.error || label}><i />{label}: {source?.status || 'checking'}</span>)}</div>
    <p><span className="status-light" />OneShield edge feed: {oneShield?.status === 'ok' ? 'connected' : 'not connected'} — origin counts only <span className="footer-last">{last}</span></p>
    {(health?.collectorError || health?.stale) && <p className="footer-warning" role="status">Telemetry may be stale{health.collectorError ? `: ${health.collectorError}` : '.'}</p>}
  </footer>;
}

export default function App() {
  const [range, setRange] = useState('90d');
  const [site, setSite] = useState('all');
  const [summary, setSummary] = useState(null);
  const [trends, setTrends] = useState({ points: [], coverage: null });
  const [bans, setBans] = useState([]);
  const [health, setHealth] = useState(null);
  const [sites, setSites] = useState([]);
  const [modal, setModal] = useState(null);
  const [busy, setBusy] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [loadError, setLoadError] = useState('');
  const refreshInFlight = useRef(false);

  const refresh = useCallback(async (force = false) => {
    if (refreshInFlight.current) return;
    refreshInFlight.current = true;
    setRefreshing(true);
    try {
      if (force) await api('/api/collect', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
      const query = new URLSearchParams({ range, site });
      const [nextSummary, nextTrends, nextBans, nextHealth] = await Promise.all([
        api(`/api/summary?${query}`), api(`/api/trends?${query}`), api('/api/bans'), api('/api/sources'),
      ]);
      setSummary(nextSummary);
      setTrends(nextTrends);
      setBans(nextBans.bans || []);
      setHealth(nextHealth);
      setSites((current) => [...new Set([...current, ...(nextTrends.sites || [])])]);
      setLoadError('');
    } catch (error) {
      setLoadError(error.message);
    } finally {
      refreshInFlight.current = false;
      setRefreshing(false);
    }
  }, [range, site]);

  useEffect(() => { void refresh(); }, [refresh]);
  useEffect(() => {
    const updateWhenVisible = () => {
      if (document.visibilityState === 'visible') void refresh();
    };
    const timer = setInterval(updateWhenVisible, REFRESH_INTERVAL);
    document.addEventListener('visibilitychange', updateWhenVisible);
    return () => {
      clearInterval(timer);
      document.removeEventListener('visibilitychange', updateWhenVisible);
    };
  }, [refresh]);

  const totals = summary?.totals || {};
  const sparkValues = (key) => trends.points.slice(-8).map((point) => point[key]);
  const metricValue = (key, source) => ['ok', 'partial'].includes(health?.sources?.[source]?.status) ? fmt(totals[key]) : '—';

  async function addBan(data) {
    setBusy(true);
    try {
      await api('/api/bans', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(data) });
      setModal(null);
      await refresh();
    } finally { setBusy(false); }
  }

  async function removeBan() {
    if (!modal?.ban) return;
    setBusy(true);
    try {
      await api(`/api/bans/${encodeURIComponent(modal.ban.ip)}`, { method: 'DELETE' });
      setModal(null);
      await refresh();
    } catch (error) {
      setLoadError(error.message);
      setModal(null);
    } finally { setBusy(false); }
  }

  const coverageText = useMemo(() => {
    const since = summary?.coverage?.start || summary?.coverageStartedAt;
    return since ? `Observed history from ${new Intl.DateTimeFormat('en', { dateStyle: 'medium' }).format(since)}` : 'History begins when source collection starts';
  }, [summary]);

  return <main className="app-shell">
    <header className="topbar">
      <h1>Security Overview</h1>
      <div className="toolbar">
        <label className="visually-hidden" htmlFor="site-select">Site</label>
        <select id="site-select" value={site} onChange={(event) => setSite(event.target.value)}><option value="all">All sites</option>{sites.map((item) => <option value={item} key={item}>{item}</option>)}</select>
        <label className="visually-hidden" htmlFor="range-select">History range</label>
        <select id="range-select" value={range} onChange={(event) => setRange(event.target.value)}><option value="24h">24 hours</option><option value="7d">7 days</option><option value="90d">90 days</option></select>
        <button className="refresh-button" type="button" aria-label="Refresh" title="Refresh now; data auto-refreshes every 30 seconds" onClick={() => void refresh(true)} disabled={refreshing}><span className={refreshing ? 'spin' : ''} aria-hidden="true">↻</span><span>Refresh</span></button>
      </div>
    </header>

    {loadError && <div className="error-banner" role="alert">{loadError}</div>}

    <section className="metrics-grid" aria-label="Security summary">
      <Metric title="Requests observed" value={metricValue('requests', 'nginx')} tone="blue" values={sparkValues('requests')} note="Nginx access-log lines" />
      <Metric title="Suspicious request signals" value={metricValue('suspicious', 'nginx')} tone="yellow" values={sparkValues('suspicious')} note="Matched scanner/probe patterns" />
      <Metric title="CrowdSec detections" value={health?.sources?.crowdsecAlerts?.status === 'ok' ? fmt(totals.crowdsec) : '—'} tone="teal" values={sparkValues('crowdsec')} note="Distinct CrowdSec alerts" />
      <Metric title="Currently blocked" value={fmt(totals.activeBans)} tone="red" values={sparkValues('active_bans')} note="Unique IPs across active sources" />
    </section>

    <section className="overview-grid">
      <section className="trend-panel surface">
        <header className="section-title">
          <h2>Origin signals over time</h2>
          <div className="chart-key" aria-label="Chart series">
            <span><i className="key requests" />Requests</span>
            <span><i className="key suspicious" />Suspicious signals</span>
            <span><i className="key crowdsec" />CrowdSec detections</span>
            <span><i className="key fail2ban" />Fail2ban bans</span>
            <span><i className="key firewall" />Confirmed blocks</span>
            <span><i className="key active-bans" />Active bans</span>
          </div>
        </header>
        <TrendChart points={trends.points || []} coverage={trends.coverage} range={range} coverageText={coverageText} />
      </section>
      <SourceBreakdown totals={{
        ...totals,
        crowdsecHttp: totals.crowdsecHttp,
        crowdsecSsh: totals.crowdsecSsh,
      }} health={health?.sources} />
    </section>

    <BanTable bans={bans} onBan={() => setModal({ type: 'ban' })} onUnban={(ban) => setModal({ type: 'unban', ban })} />

    <StatusFooter health={health} />
    {modal?.type === 'ban' && <BanForm onClose={() => setModal(null)} onSubmit={addBan} busy={busy} />}
    {modal?.type === 'unban' && <UnbanDialog ban={modal.ban} onClose={() => setModal(null)} onConfirm={() => void removeBan()} busy={busy} />}
  </main>;
}
