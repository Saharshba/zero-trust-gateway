import { useState } from 'react';
import { api, formatDateTime, formatNumber } from '../api/client';
import { usePolling } from '../hooks';
import { Card, Empty, ErrorBanner, Verdict } from '../components/common';

const PAGE_SIZE = 25;

export default function AccessLog() {
  const [filters, setFilters] = useState({ decision: '', username: '', resource: '', source_ip: '' });
  const [offset, setOffset] = useState(0);

  const params = Object.fromEntries(
    Object.entries({ ...filters, limit: PAGE_SIZE, offset }).filter(([, v]) => v !== ''),
  );
  const { data, error, loading } = usePolling(() => api.accessLogs(params), {
    intervalMs: 15000,
    deps: [JSON.stringify(params)],
  });

  function update(key, value) {
    setFilters((current) => ({ ...current, [key]: value }));
    setOffset(0);
  }

  const total = data?.meta.total ?? 0;

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Access log</h1>
          <p className="subtle">
            Every authorisation decision, allowed and denied, with the policy that produced it.
          </p>
        </div>
      </div>

      <div className="filters">
        <select value={filters.decision} onChange={(e) => update('decision', e.target.value)}>
          <option value="">All decisions</option>
          <option value="ALLOW">Allowed</option>
          <option value="DENY">Denied</option>
        </select>
        <input placeholder="Identity" value={filters.username}
               onChange={(e) => update('username', e.target.value)} />
        <input placeholder="Resource" value={filters.resource}
               onChange={(e) => update('resource', e.target.value)} />
        <input placeholder="Source IP" value={filters.source_ip}
               onChange={(e) => update('source_ip', e.target.value)} />
      </div>

      <ErrorBanner error={error} />

      <Card note={`${formatNumber(total)} matching decisions`}>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Time</th><th>Decision</th><th>Identity</th><th>Device</th><th>Request</th>
                <th>Resource</th><th>Source</th><th className="num">Trust</th>
                <th>Policy</th><th>Reason</th><th className="num">ms</th>
              </tr>
            </thead>
            <tbody>
              {data?.items.map((log) => (
                <tr key={log.id}>
                  <td className="mono">{formatDateTime(log.timestamp)}</td>
                  <td><Verdict decision={log.decision} /></td>
                  <td>{log.username}<div className="subtle">{log.role}</div></td>
                  <td className="mono">{log.device_id || '—'}</td>
                  <td className="mono">{log.method} {log.path}</td>
                  <td>{log.resource || '—'}</td>
                  <td className="mono">{log.source_ip || '—'}</td>
                  <td className="num">{Math.round(log.trust_score)}</td>
                  <td>
                    {log.matched_policy
                      ? <>{log.matched_policy}<div className="subtle">v{log.policy_version}</div></>
                      : <span className="subtle">none</span>}
                  </td>
                  <td>{log.reason}</td>
                  <td className="num">{log.latency_ms.toFixed(1)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && !data?.items.length && <Empty>No decisions match these filters.</Empty>}

        <div className="filters" style={{ marginTop: 14, marginBottom: 0 }}>
          <button onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))} disabled={offset === 0}>
            Previous
          </button>
          <span className="subtle" style={{ alignSelf: 'center' }}>
            {total ? `${offset + 1}–${Math.min(offset + PAGE_SIZE, total)} of ${formatNumber(total)}` : '—'}
          </span>
          <button onClick={() => setOffset(offset + PAGE_SIZE)} disabled={offset + PAGE_SIZE >= total}>
            Next
          </button>
        </div>
      </Card>
    </>
  );
}
