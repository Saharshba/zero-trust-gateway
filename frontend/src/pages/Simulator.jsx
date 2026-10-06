import { useState } from 'react';
import { GATEWAY_URL, api } from '../api/client';
import { usePolling } from '../hooks';
import { Card, ErrorBanner, Verdict } from '../components/common';

/* Two ways to ask the same question:
 *   simulate - the PDP evaluates a hypothetical request, nothing is logged
 *   probe    - a real request through the gateway, which is logged and enforced
 */
export default function Simulator() {
  const { data: users } = usePolling(() => api.users().catch(() => []), { deps: [] });
  const { data: resources } = usePolling(() => api.resources(), { deps: [] });

  const [form, setForm] = useState({
    username: '',
    method: 'GET',
    path: '/reports/q1',
    source_ip: '10.0.0.5',
    device_id: api.tokens.deviceId,
    mfa_satisfied: false,
  });
  const [result, setResult] = useState(null);
  const [probe, setProbe] = useState(null);
  const [error, setError] = useState(null);

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function runSimulation(event) {
    event.preventDefault();
    setError(null);
    try {
      setResult(await api.simulate({ ...form, device_id: form.device_id || null }));
    } catch (err) {
      setError(err);
    }
  }

  async function runProbe() {
    setError(null);
    try {
      setProbe(await api.probeGateway(form.path));
    } catch (err) {
      setError(err);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Policy simulator</h1>
          <p className="subtle">
            Ask what would happen before changing anything, or send a real request through the gateway
            at {GATEWAY_URL}.
          </p>
        </div>
      </div>

      <ErrorBanner error={error} />

      <div className="grid charts">
        <Card title="Evaluate a hypothetical request" note="Nothing is forwarded and nothing is logged.">
          <form onSubmit={runSimulation}>
            <label htmlFor="user">Identity</label>
            <select id="user" value={form.username} onChange={(e) => update('username', e.target.value)}
                    required style={{ width: '100%' }}>
              <option value="">Select a user…</option>
              {users?.map((user) => (
                <option key={user.id} value={user.username}>{user.username} ({user.role})</option>
              ))}
            </select>

            <label htmlFor="method">Method</label>
            <select id="method" value={form.method} onChange={(e) => update('method', e.target.value)}
                    style={{ width: '100%' }}>
              {['GET', 'POST', 'PUT', 'PATCH', 'DELETE'].map((m) => <option key={m}>{m}</option>)}
            </select>

            <label htmlFor="path">Path</label>
            <input id="path" value={form.path} onChange={(e) => update('path', e.target.value)}
                   style={{ width: '100%' }} required />
            <div className="subtle" style={{ marginTop: 4 }}>
              Registered prefixes: {resources?.map((r) => r.path_prefix).join(', ') || '—'}
            </div>

            <label htmlFor="ip">Source IP</label>
            <input id="ip" value={form.source_ip} onChange={(e) => update('source_ip', e.target.value)}
                   style={{ width: '100%' }} />

            <label htmlFor="device">Device ID</label>
            <input id="device" value={form.device_id} onChange={(e) => update('device_id', e.target.value)}
                   style={{ width: '100%' }} />

            <label style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 10 }}>
              <input type="checkbox" style={{ width: 'auto' }} checked={form.mfa_satisfied}
                     onChange={(e) => update('mfa_satisfied', e.target.checked)} />
              MFA satisfied
            </label>

            <div className="filters" style={{ marginTop: 14, marginBottom: 0 }}>
              <button className="primary" type="submit">Evaluate</button>
              <button type="button" onClick={runProbe}>Send it through the gateway</button>
            </div>
          </form>
        </Card>

        <Card title="Result">
          {!result && !probe && <p className="empty">Run an evaluation to see the decision.</p>}

          {result && (
            <>
              <h2>Simulated decision</h2>
              <dl className="kv" style={{ marginTop: 10 }}>
                <dt>Decision</dt><dd><Verdict decision={result.decision} /></dd>
                <dt>Reason</dt><dd>{result.reason}</dd>
                <dt>Matched policy</dt>
                <dd>{result.matched_policy ? `${result.matched_policy} (v${result.policy_version})` : '—'}</dd>
                <dt>Resource</dt><dd>{result.resource || '—'}</dd>
                <dt>Classification</dt><dd>{result.classification || '—'}</dd>
                <dt>Trust score</dt><dd>{result.trust_score}</dd>
              </dl>
            </>
          )}

          {probe && (
            <>
              <h2 style={{ marginTop: 18 }}>Live gateway response</h2>
              <dl className="kv" style={{ marginTop: 10 }}>
                <dt>HTTP status</dt><dd>{probe.status}</dd>
                <dt>Decision header</dt>
                <dd>{probe.decision ? <Verdict decision={probe.decision} /> : '—'}</dd>
                <dt>Policy header</dt><dd>{probe.policy || '—'}</dd>
                <dt>Trust score</dt><dd>{probe.trustScore ?? '—'}</dd>
                <dt>Round trip</dt><dd>{probe.elapsedMs} ms</dd>
                <dt>Request ID</dt><dd className="mono">{probe.requestId || '—'}</dd>
              </dl>
              <pre className="evidence" style={{ marginTop: 10 }}>
                {JSON.stringify(probe.body, null, 2)}
              </pre>
            </>
          )}
        </Card>
      </div>
    </>
  );
}
