import { Fragment, useState } from 'react';
import { api, formatDateTime } from '../api/client';
import { useAuth } from '../auth';
import { usePolling } from '../hooks';
import { Card, Empty, ErrorBanner, Pills, Verdict } from '../components/common';

function conditionsOf(policy) {
  const conditions = [];
  if (policy.require_registered_device) conditions.push('managed device');
  if (policy.require_mfa) conditions.push('MFA');
  if (policy.min_trust_score) conditions.push(`trust ≥ ${policy.min_trust_score}`);
  if (policy.time_start_hour !== policy.time_end_hour) {
    conditions.push(`${policy.time_start_hour}:00–${policy.time_end_hour}:00`);
  }
  if (policy.weekdays?.length) {
    const names = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    conditions.push(policy.weekdays.map((d) => names[d]).join(', '));
  }
  return conditions;
}

export default function Policies() {
  const { can } = useAuth();
  const isAdmin = can('ADMIN');
  const { data, error, loading, reload } = usePolling(() => api.policies(), { deps: [] });
  const [actionError, setActionError] = useState(null);
  const [revisions, setRevisions] = useState({ id: null, items: [] });

  async function toggle(policy) {
    setActionError(null);
    try {
      await api.updatePolicy(policy.id, { enabled: !policy.enabled });
      await reload();
    } catch (err) {
      setActionError(err);
    }
  }

  async function showRevisions(policy) {
    if (revisions.id === policy.id) return setRevisions({ id: null, items: [] });
    try {
      setRevisions({ id: policy.id, items: await api.revisions(policy.id) });
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Policies</h1>
          <p className="subtle">
            Evaluated top to bottom; the first policy whose conditions all match decides the request.
            Anything that matches nothing is denied.
          </p>
        </div>
      </div>

      <ErrorBanner error={error || actionError} />

      <Card>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th className="num">Priority</th><th>Policy</th><th>Effect</th><th>Roles</th>
                <th>Resources</th><th>Methods</th><th>Networks</th><th>Conditions</th>
                <th>Version</th><th>Enabled</th><th></th>
              </tr>
            </thead>
            <tbody>
              {data?.map((policy) => (
                <Fragment key={policy.id}>
                  <tr>
                    <td className="num">{policy.priority}</td>
                    <td><strong>{policy.name}</strong><div className="subtle">{policy.description}</div></td>
                    <td><Verdict decision={policy.effect} /></td>
                    <td><Pills values={policy.roles} /></td>
                    <td><Pills values={policy.resources} /></td>
                    <td><Pills values={policy.methods} /></td>
                    <td><Pills values={policy.source_cidrs} /></td>
                    <td><Pills values={conditionsOf(policy)} empty="none" /></td>
                    <td className="mono">
                      <button onClick={() => showRevisions(policy)} style={{ padding: '2px 8px' }}>
                        v{policy.version}
                      </button>
                    </td>
                    <td>
                      <input type="checkbox" style={{ width: 'auto' }} disabled={!isAdmin}
                             checked={policy.enabled} onChange={() => toggle(policy)} />
                    </td>
                    <td className="subtle mono">{formatDateTime(policy.updated_at)}</td>
                  </tr>
                  {revisions.id === policy.id && (
                    <tr>
                      <td colSpan={11}>
                        <strong>Revision history</strong>
                        <pre className="evidence" style={{ marginTop: 8 }}>
                          {JSON.stringify(revisions.items, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
        {!loading && !data?.length && <Empty>No policies defined — everything is denied.</Empty>}
      </Card>
    </>
  );
}
