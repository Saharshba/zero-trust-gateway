import { useState } from 'react';
import { api, formatDateTime } from '../api/client';
import { useAuth } from '../auth';
import { usePolling } from '../hooks';
import { Card, DeviceStatus, Empty, ErrorBanner } from '../components/common';

const POSTURE_FIELDS = [
  ['disk_encrypted', 'Disk encrypted'],
  ['screen_lock', 'Screen lock'],
  ['os_up_to_date', 'OS up to date'],
  ['endpoint_protection', 'Endpoint protection'],
];

export default function Devices() {
  const { can } = useAuth();
  const isAdmin = can('ADMIN');
  const { data, error, loading, reload } = usePolling(() => api.devices(), { intervalMs: 20000, deps: [] });
  const [form, setForm] = useState({
    device_id: api.tokens.deviceId,
    name: '',
    platform: '',
    disk_encrypted: false,
    screen_lock: false,
    os_up_to_date: false,
    endpoint_protection: false,
  });
  const [actionError, setActionError] = useState(null);

  async function enroll(event) {
    event.preventDefault();
    setActionError(null);
    try {
      await api.enrollDevice(form);
      api.tokens.setDevice(form.device_id);
      await reload();
    } catch (err) {
      setActionError(err);
    }
  }

  async function setStatus(device, status) {
    setActionError(null);
    try {
      await api.updateDevice(device.device_id, { status });
      await reload();
    } catch (err) {
      setActionError(err);
    }
  }

  return (
    <>
      <div className="page-head">
        <div>
          <h1>Devices</h1>
          <p className="subtle">
            Enrolment does not grant trust: a device stays PENDING until an admin approves it, and
            policies that require a managed device ignore it until then.
          </p>
        </div>
      </div>

      <ErrorBanner error={error || actionError} />

      <div className="grid charts">
        <Card title="Enrol this device" note="Posture answers feed the trust score.">
          <form onSubmit={enroll}>
            <label htmlFor="device_id">Device ID</label>
            <input id="device_id" value={form.device_id} required style={{ width: '100%' }}
                   onChange={(e) => setForm({ ...form, device_id: e.target.value })} />
            <label htmlFor="name">Name</label>
            <input id="name" value={form.name} style={{ width: '100%' }}
                   onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <label htmlFor="platform">Platform</label>
            <input id="platform" value={form.platform} placeholder="macOS 15" style={{ width: '100%' }}
                   onChange={(e) => setForm({ ...form, platform: e.target.value })} />
            {POSTURE_FIELDS.map(([key, label]) => (
              <label key={key} style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 8 }}>
                <input type="checkbox" style={{ width: 'auto' }} checked={form[key]}
                       onChange={(e) => setForm({ ...form, [key]: e.target.checked })} />
                {label}
              </label>
            ))}
            <button className="primary" type="submit">Enrol</button>
          </form>
        </Card>

        <Card title={isAdmin ? 'Fleet' : 'Your devices'}>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>Device</th><th>Status</th><th>Platform</th><th>Posture</th>
                  <th>Last seen</th>{isAdmin && <th>Actions</th>}
                </tr>
              </thead>
              <tbody>
                {data?.map((device) => (
                  <tr key={device.id}>
                    <td className="mono">{device.device_id}<div className="subtle">{device.name}</div></td>
                    <td><DeviceStatus status={device.status} /></td>
                    <td>{device.platform || '—'}</td>
                    <td>
                      {POSTURE_FIELDS.filter(([key]) => device[key]).map(([, label]) => (
                        <span className="pill" key={label}>{label}</span>
                      ))}
                      {POSTURE_FIELDS.every(([key]) => !device[key]) && <span className="subtle">none</span>}
                    </td>
                    <td className="mono">
                      {device.last_seen_at ? formatDateTime(device.last_seen_at) : '—'}
                    </td>
                    {isAdmin && (
                      <td>
                        <div className="filters" style={{ margin: 0 }}>
                          <button onClick={() => setStatus(device, 'REGISTERED')}
                                  disabled={device.status === 'REGISTERED'}>Approve</button>
                          <button onClick={() => setStatus(device, 'QUARANTINED')}
                                  disabled={device.status === 'QUARANTINED'}>Quarantine</button>
                        </div>
                      </td>
                    )}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          {!loading && !data?.length && <Empty>No devices enrolled yet.</Empty>}
        </Card>
      </div>
    </>
  );
}
