import { useState } from 'react';
import { api, formatDateTime } from '../api/client';
import { usePolling } from '../hooks';
import { Card, Empty, ErrorBanner } from '../components/common';

const ACTIONS = [
  'LOGIN', 'LOGOUT', 'CREATE_USER', 'CHANGE_ROLE', 'ENABLE_MFA', 'ENROLL_DEVICE',
  'UPDATE_DEVICE', 'CREATE_POLICY', 'UPDATE_POLICY', 'DISABLE_POLICY', 'CREATE_RESOURCE',
];

export default function Audit() {
  const [action, setAction] = useState('');
  const params = action ? { action, limit: 200 } : { limit: 200 };
  const { data, error, loading } = usePolling(() => api.audit(params), { deps: [action] });

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Audit trail</h1>
          <p className="subtle">
            Administrative actions on the control plane itself, separate from the per-request access log.
          </p>
        </div>
        <select value={action} onChange={(e) => setAction(e.target.value)}>
          <option value="">All actions</option>
          {ACTIONS.map((a) => <option key={a} value={a}>{a.replace(/_/g, ' ')}</option>)}
        </select>
      </div>

      <ErrorBanner error={error} />

      <Card>
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Time</th><th>Actor</th><th>Action</th><th>Target</th><th>Source</th>
                  <th>Outcome</th><th>Detail</th></tr>
            </thead>
            <tbody>
              {data?.map((entry) => (
                <tr key={entry.id}>
                  <td className="mono">{formatDateTime(entry.timestamp)}</td>
                  <td>{entry.username}</td>
                  <td>{entry.action.replace(/_/g, ' ')}</td>
                  <td className="mono">{entry.resource || '—'}</td>
                  <td className="mono">{entry.source_ip || '—'}</td>
                  <td className={entry.outcome === 'SUCCESS' ? '' : 'verdict-DENY'}>{entry.outcome}</td>
                  <td className="mono">
                    {Object.keys(entry.detail || {}).length ? JSON.stringify(entry.detail) : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && !data?.length && <Empty>No audit entries yet.</Empty>}
      </Card>
    </>
  );
}
