import { useState } from 'react';
import { Link } from 'react-router-dom';
import { api, formatDateTime, formatNumber } from '../api/client';
import { usePolling } from '../hooks';
import { CountBars, DecisionTimeline } from '../components/charts';
import { Card, Empty, ErrorBanner, StatTile } from '../components/common';

const WINDOWS = [
  { label: 'Last 15 minutes', value: 15 },
  { label: 'Last hour', value: 60 },
  { label: 'Last 24 hours', value: 1440 },
  { label: 'Last 7 days', value: 10080 },
];

export default function Dashboard() {
  const [minutes, setMinutes] = useState(60);
  const { data, error, loading } = usePolling(() => api.statistics(minutes), {
    intervalMs: 10000,
    deps: [minutes],
  });

  if (loading && !data) return <p className="empty">Loading access decisions…</p>;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Access overview</h1>
          <p className="subtle">
            {data ? `Generated ${formatDateTime(data.generated_at)} · refreshes every 10s` : ''}
          </p>
        </div>
        <select value={minutes} onChange={(e) => setMinutes(Number(e.target.value))}>
          {WINDOWS.map((w) => <option key={w.value} value={w.value}>{w.label}</option>)}
        </select>
      </div>

      <ErrorBanner error={error} />

      {!data ? <Empty /> : (
        <>
          <div className="grid tiles" style={{ marginBottom: 14 }}>
            <StatTile label="Requests" value={formatNumber(data.total_requests)}
                      note={`${data.unique_users} distinct identities`} />
            <StatTile label="Allowed" value={formatNumber(data.allowed)} />
            <StatTile label="Denied" value={formatNumber(data.denied)}
                      alarm={data.denied > 0}
                      note={`${(data.deny_rate * 100).toFixed(1)}% of requests`} />
            <StatTile label="Average trust score" value={data.average_trust_score.toFixed(0)}
                      note="0–100, computed per request" />
            <StatTile label="Active sessions" value={formatNumber(data.active_sessions)} />
            <StatTile label="Managed devices" value={formatNumber(data.registered_devices)}
                      note={`${data.quarantined_devices} quarantined`} />
            <StatTile label="Active policies" value={formatNumber(data.active_policies)} />
            <StatTile label="Decision latency" value={`${data.average_latency_ms.toFixed(1)} ms`}
                      note="Policy evaluation, mean" />
          </div>

          <div className="grid" style={{ marginBottom: 14 }}>
            <Card title="Decisions over time" note="Allowed and denied requests per bucket">
              <DecisionTimeline points={data.decisions_over_time} />
            </Card>
          </div>

          <div className="grid charts" style={{ marginBottom: 14 }}>
            <Card title="Most denied resources">
              <CountBars rows={data.top_denied_resources} label="Resource"
                         color="var(--status-critical)" width={120} />
            </Card>
            <Card title="Why requests were denied" note="The reason string the policy engine produced">
              <CountBars rows={data.top_deny_reasons} label="Reason" color="var(--status-critical)"
                         width={240} />
            </Card>
            <Card title="Busiest identities">
              <CountBars rows={data.top_users} label="User" width={120} />
            </Card>
            <Card title="Source addresses">
              <CountBars rows={data.top_source_ips} label="Source IP" width={140} />
            </Card>
          </div>

          <Card title="Recent denials" action={<Link to="/access">View the full log</Link>}>
            <div className="table-wrap">
              <table>
                <thead>
                  <tr>
                    <th>Time</th><th>Identity</th><th>Request</th><th>Source</th>
                    <th className="num">Trust</th><th>Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {data.recent_denials.map((log) => (
                    <tr key={log.id}>
                      <td className="mono">{formatDateTime(log.timestamp)}</td>
                      <td>{log.username} <span className="subtle">{log.role}</span></td>
                      <td className="mono">{log.method} {log.path}</td>
                      <td className="mono">{log.source_ip || '—'}</td>
                      <td className="num">{Math.round(log.trust_score)}</td>
                      <td>{log.reason}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {!data.recent_denials.length && <Empty>No denials recorded — every request matched a policy.</Empty>}
          </Card>
        </>
      )}
    </>
  );
}
