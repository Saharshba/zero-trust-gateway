/* Control-plane API client.
 *
 * Tokens live in sessionStorage so they do not outlive the browser tab. A 401
 * triggers one refresh attempt; if that fails the session is cleared.
 */
const BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:8000';
export const GATEWAY_URL = import.meta.env.VITE_GATEWAY_URL || 'http://localhost:8080';

const store = {
  get access() { return sessionStorage.getItem('zta.access'); },
  get refresh() { return sessionStorage.getItem('zta.refresh'); },
  get user() {
    const raw = sessionStorage.getItem('zta.user');
    return raw ? JSON.parse(raw) : null;
  },
  get deviceId() { return localStorage.getItem('zta.device') || ''; },
  setDevice(value) { localStorage.setItem('zta.device', value); },
  set(tokens) {
    sessionStorage.setItem('zta.access', tokens.access_token);
    sessionStorage.setItem('zta.refresh', tokens.refresh_token);
    sessionStorage.setItem('zta.user', JSON.stringify(tokens.user));
    sessionStorage.setItem('zta.trust', String(tokens.trust_score));
  },
  get trust() { return Number(sessionStorage.getItem('zta.trust') || 0); },
  clear() {
    ['zta.access', 'zta.refresh', 'zta.user', 'zta.trust'].forEach((k) => sessionStorage.removeItem(k));
  },
};

export class ApiError extends Error {
  constructor(status, detail, extra = {}) {
    super(detail || `Request failed (${status})`);
    this.status = status;
    Object.assign(this, extra);
  }
}

async function describe(response) {
  try {
    const body = await response.json();
    if (Array.isArray(body.errors) && body.errors.length) {
      return { detail: body.errors.map((e) => `${e.field}: ${e.message}`).join(', '), body };
    }
    return { detail: typeof body.detail === 'string' ? body.detail : JSON.stringify(body.detail), body };
  } catch {
    return { detail: `Request failed (${response.status})`, body: {} };
  }
}

async function send(path, { method = 'GET', body, auth = true, retry = true, base = BASE_URL } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (auth && store.access) headers.Authorization = `Bearer ${store.access}`;
  if (store.deviceId) headers['X-Device-Id'] = store.deviceId;

  const response = await fetch(`${base}${path}`, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
  });

  if (response.status === 401 && auth && retry && store.refresh && base === BASE_URL) {
    const refreshed = await fetch(`${BASE_URL}/api/auth/refresh`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refresh_token: store.refresh }),
    });
    if (refreshed.ok) {
      store.set(await refreshed.json());
      return send(path, { method, body, auth, retry: false, base });
    }
    store.clear();
  }

  if (!response.ok) {
    const { detail, body: payload } = await describe(response);
    throw new ApiError(response.status, detail, { payload });
  }
  return response.status === 204 ? null : response.json();
}

export const api = {
  tokens: store,
  login: async (credentials) => {
    const tokens = await send('/api/auth/login', { method: 'POST', body: credentials, auth: false });
    store.set(tokens);
    return tokens;
  },
  logout: async () => {
    try {
      await send('/api/auth/logout', { method: 'POST' });
    } finally {
      store.clear();
    }
  },
  me: () => send('/api/auth/me'),
  users: () => send('/api/auth/users'),
  enrollMfa: () => send('/api/auth/mfa/enroll', { method: 'POST' }),
  activateMfa: (code) => send('/api/auth/mfa/activate', { method: 'POST', body: { code } }),

  statistics: (minutes = 60) => send(`/api/statistics?window_minutes=${minutes}`),
  accessLogs: (params = {}) => send(`/api/access-logs?${new URLSearchParams(params)}`),
  audit: (params = {}) => send(`/api/audit?${new URLSearchParams(params)}`),

  devices: (params = {}) => send(`/api/devices?${new URLSearchParams(params)}`),
  enrollDevice: (payload) => send('/api/devices', { method: 'POST', body: payload }),
  updateDevice: (deviceId, payload) => send(`/api/devices/${deviceId}`, { method: 'PATCH', body: payload }),

  policies: () => send('/api/policies'),
  createPolicy: (payload) => send('/api/policies', { method: 'POST', body: payload }),
  updatePolicy: (id, payload) => send(`/api/policies/${id}`, { method: 'PATCH', body: payload }),
  disablePolicy: (id) => send(`/api/policies/${id}`, { method: 'DELETE' }),
  revisions: (id) => send(`/api/policies/${id}/revisions`),
  resources: () => send('/api/resources'),
  simulate: (payload) => send('/api/simulate', { method: 'POST', body: payload }),

  /** Send a real request through the gateway, to watch enforcement happen. */
  probeGateway: async (path) => {
    const started = performance.now();
    const response = await fetch(`${GATEWAY_URL}${path}`, {
      headers: {
        ...(store.access ? { Authorization: `Bearer ${store.access}` } : {}),
        ...(store.deviceId ? { 'X-Device-Id': store.deviceId } : {}),
      },
    });
    let body;
    try {
      body = await response.json();
    } catch {
      body = null;
    }
    return {
      status: response.status,
      decision: response.headers.get('X-ZTA-Decision'),
      policy: response.headers.get('X-ZTA-Policy'),
      trustScore: response.headers.get('X-ZTA-Trust-Score'),
      requestId: response.headers.get('X-Request-ID'),
      elapsedMs: Math.round(performance.now() - started),
      body,
    };
  },
};

export const VERDICT_COLORS = {
  ALLOW: 'var(--status-good)',
  DENY: 'var(--status-critical)',
};

export function formatDateTime(iso) {
  return new Date(iso).toLocaleString();
}

export function formatTime(iso) {
  return new Date(iso).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
}

export function formatNumber(value) {
  return new Intl.NumberFormat().format(value ?? 0);
}
