import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { useAuth } from '../auth';
import { Card, ErrorBanner } from '../components/common';

export default function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [form, setForm] = useState({
    username: '',
    password: '',
    totp_code: '',
    device_id: api.tokens.deviceId,
  });
  const [mfaRequired, setMfaRequired] = useState(false);
  const [error, setError] = useState(null);
  const [busy, setBusy] = useState(false);

  function update(key, value) {
    setForm((current) => ({ ...current, [key]: value }));
  }

  async function submit(event) {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const payload = { username: form.username, password: form.password };
      if (form.totp_code) payload.totp_code = form.totp_code;
      if (form.device_id) {
        payload.device_id = form.device_id;
        api.tokens.setDevice(form.device_id);
      }
      await login(payload);
      navigate('/', { replace: true });
    } catch (err) {
      // The API answers "MFA code required" before it answers anything else.
      if (err.status === 401 && /mfa/i.test(err.message)) setMfaRequired(true);
      setError(err);
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <Card title="Zero-Trust Access Console" note="Every request is authorised individually.">
          <form onSubmit={submit}>
            <ErrorBanner error={error} />
            <label htmlFor="username">Username</label>
            <input id="username" autoComplete="username" value={form.username}
                   onChange={(e) => update('username', e.target.value)} required />

            <label htmlFor="password">Password</label>
            <input id="password" type="password" autoComplete="current-password" value={form.password}
                   onChange={(e) => update('password', e.target.value)} required />

            <label htmlFor="device">Device ID <span className="subtle">(raises your trust score)</span></label>
            <input id="device" value={form.device_id} placeholder="laptop-01"
                   onChange={(e) => update('device_id', e.target.value)} />

            {mfaRequired && (
              <>
                <label htmlFor="totp">Authenticator code</label>
                <input id="totp" inputMode="numeric" autoComplete="one-time-code" value={form.totp_code}
                       onChange={(e) => update('totp_code', e.target.value)} />
              </>
            )}

            <button className="primary" type="submit" disabled={busy}>
              {busy ? 'Signing in…' : 'Sign in'}
            </button>
          </form>
        </Card>
      </div>
    </div>
  );
}
