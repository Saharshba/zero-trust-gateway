# Zero-Trust Network Access Gateway

An access gateway that treats every request as untrusted until it is
authorised: no implicit allow, no trust inherited from being "on the network".
A **policy enforcement point** (the gateway) forwards nothing until a **policy
decision point** (the control plane) says yes, and every decision — allowed or
denied — is written to an access log with the policy that produced it.

```
                        Users / devices
                               │
                        ┌──────┴───────┐
                        │  TLS (nginx) │  optional profile
                        └──────┬───────┘
                               ▼
                    ┌─────────────────────┐
                    │  Gateway  (PEP)     │  decides nothing itself
                    │  :8080              │
                    └───┬─────────────┬───┘
       "may this request proceed?"    │ forwards only ALLOW,
                        │             │ signed with an HMAC
                        ▼             │
          ┌──────────────────────┐    │
          │ Control plane (PDP)  │    │
          │  identity + MFA      │    │
          │  device registry     │    │
          │  policy engine       │    │
          │  access log          │    │
          └──────────┬───────────┘    │
                     │                │
              PostgreSQL · Redis      │
                                      ▼
                    ┌──────────────────────────────────┐
                    │ internal network (no published   │
                    │ ports, no route to the internet) │
                    │  public · reports · admin        │
                    └──────────────────────────────────┘
```

## Contents

- [Quick start](#quick-start)
- [How a request is decided](#how-a-request-is-decided)
- [The policy model](#the-policy-model)
- [Trust scoring](#trust-scoring)
- [Network isolation](#network-isolation)
- [API](#api)
- [Security properties](#security-properties)
- [Testing](#testing)
- [Measured results](#measured-results)
- [Project layout](#project-layout)

## Quick start

```bash
cp .env.example .env     # set SECRET_KEY, GATEWAY_SIGNING_KEY, admin password
docker compose up --build
```

| Service | URL | Notes |
|---------|-----|-------|
| Console | http://localhost:5173 | dashboard, policies, simulator, devices |
| Gateway | http://localhost:8080 | the only way to reach an internal service |
| Control plane API | http://localhost:8000/docs | OpenAPI, generated from the code |

Optional TLS terminator in front of the gateway:

```bash
./nginx/generate-cert.sh
docker compose --profile tls up -d tls-proxy      # https://localhost:8443
```

Walk through enforcement from the command line:

```bash
# 1. no token: denied before anything else happens
curl -i localhost:8080/reports/q1

# 2. sign in (device id raises the trust score)
TOKEN=$(curl -s localhost:8000/api/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"ChangeMe!123","device_id":"laptop-01"}' | jq -r .access_token)

# 3. the device is PENDING until an admin approves it, so this is still denied
curl -i localhost:8080/reports/q1 -H "Authorization: Bearer $TOKEN"

# 4. approve the device, then try again
curl -s -X PATCH localhost:8000/api/devices/laptop-01 \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"status":"REGISTERED"}'
curl -i localhost:8080/reports/q1 -H "Authorization: Bearer $TOKEN"
```

Every one of those attempts is now in `GET /api/access-logs`, with the reason.

### Without Docker

```bash
cd backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export DATABASE_URL="sqlite:///./zta.db" REDIS_ENABLED=false
uvicorn zta.control_plane.app:app --port 8000          # PDP + admin API
uvicorn zta.gateway.app:app --port 8080                # PEP
SERVICE_NAME=reports uvicorn zta.services.internal_service:app --port 9002
cd ../frontend && npm install && npm run dev
```

## How a request is decided

```
request arrives at the gateway
        │
        ▼
collect evidence: bearer token · device id · source IP · method · path
        │
        ▼
POST /internal/authorize  (HMAC-signed; the PDP rejects unsigned callers)
        │
        ├─ token valid?            no ──► DENY "Access token is invalid/expired"
        ├─ session still live?     no ──► DENY "Session has been revoked"
        ├─ path maps to a resource? no ─► DENY "No resource is registered for …"
        │
        ▼
score the request (identity + MFA + device posture + source network) → 0–100
        │
        ▼
evaluate policies in priority order, first match wins
        │
        ├─ no match ─────────────────► DENY (default; explains what was missing)
        ├─ DENY policy matched ──────► DENY (names the policy)
        └─ ALLOW policy matched ─────► ALLOW
        │
        ▼
write an access_logs row — before the answer is returned
        │
        ▼
gateway forwards to the upstream, signing the call, stripping the user's token
and asserting X-ZTA-User / X-ZTA-Role / X-ZTA-Trust-Score instead
```

Three consequences worth naming:

- **Fail closed.** If the gateway cannot reach the PDP it answers `503` and
  forwards nothing. A gateway that allows traffic when its brain is offline is
  not a zero-trust gateway.
- **ALLOW is cached for a few seconds; DENY never is.** The cache removes a PDP
  round trip per request; not caching denials means a policy fix takes effect on
  the next request rather than after a TTL.
- **The upstream never sees the user's token.** It sees the gateway's signature
  and the claims the gateway asserts, so a compromised internal service cannot
  replay a user's credentials.

## The policy model

A policy is an effect (`ALLOW`/`DENY`), a priority, and a set of conditions that
must *all* hold. Policies are evaluated lowest-priority-number first and the
first match decides. Anything that matches nothing is denied.

| Condition | Meaning |
|-----------|---------|
| `roles` | ADMIN / EMPLOYEE / GUEST |
| `resources` | named registered resources |
| `methods` | HTTP methods |
| `path_globs` | glob patterns, e.g. `/admin/*` |
| `source_cidrs` | source network |
| `require_registered_device` | the device is enrolled *and* approved |
| `require_mfa` | this session completed TOTP |
| `min_trust_score` | computed score floor |
| `time_start_hour` / `time_end_hour` | local-time window (wraps midnight) |
| `weekdays` | 0 = Monday … 6 = Sunday |

The seeded set is a worked example rather than a recommendation:

```
priority  effect  policy                   conditions
      5   DENY    deny-guest-writes        role=GUEST, method in POST/PUT/PATCH/DELETE
      8   DENY    deny-weekend-reports     role=EMPLOYEE, resource=reports, Sat/Sun
     10   ALLOW   allow-admin-console      role=ADMIN, resource=admin, corporate CIDR,
                                           managed device, MFA, trust ≥ 80
     20   ALLOW   allow-employee-reports   role in EMPLOYEE/ADMIN, resource=reports,
                                           managed device, trust ≥ 60
     50   ALLOW   allow-public-read        any role, resource=public, method GET/HEAD
```

Denials explain themselves. Rather than "403 Forbidden", the engine reports the
closest allow-policy and which of its conditions failed — *"Failed MFA, source
network for policy 'allow-admin-console'"* — which is what makes the console's
simulator useful when writing a rule.

Every edit bumps the policy version and stores a snapshot in
`policy_revisions`; policies are disabled, never deleted, so the history of what
was permitted when stays intact.

## Trust scoring

Zero trust does not mean *no* trust; it means trust is computed per request from
current signals instead of inherited from network location.

| Signal | Effect |
|--------|--------|
| authenticated | +25 (and an unauthenticated request scores 0, full stop) |
| MFA completed this session | +25 |
| enrolled **and approved** device | +20 |
| each healthy posture signal (disk encryption, screen lock, patch level, endpoint protection) | +5 |
| quarantined device | −60 |
| unknown device | −10 |
| source inside a corporate network | +10 |

Being on the corporate network is worth ten points, not access. That asymmetry
is the whole design: a stolen laptop on the office LAN still fails
`require_mfa`, and a fully managed laptop with MFA still fails a policy it has
no role for.

## Network isolation

`docker-compose.yml` defines three networks:

| Network | Members | Published |
|---------|---------|-----------|
| `edge` | gateway, control plane, console, TLS proxy | yes |
| `internal` (`internal: true`) | the three protected services + the gateway | **no ports, no internet route** |
| `data` (`internal: true`) | PostgreSQL, Redis + the control plane | **no ports, no internet route** |

The internal services have no authentication of their own — like most services
built when the network perimeter was the security boundary. They are protected
twice: they are unreachable from outside, and they verify the gateway's HMAC
signature (with a 30-second replay window), so even a foothold on the internal
network cannot call them directly. There is a test for exactly that.

## API

Control plane, `http://localhost:8000`:

| Method | Path | Role | Purpose |
|--------|------|------|---------|
| POST | `/api/auth/login` | — | password (+ TOTP when enabled) → token pair + trust score |
| POST | `/api/auth/refresh` | — | rotate; the old refresh token is revoked |
| POST | `/api/auth/logout` | any | revoke every session for this user |
| POST | `/api/auth/mfa/enroll` · `/activate` | any | TOTP enrolment |
| POST | `/api/auth/register` | ADMIN | create a user |
| PATCH | `/api/auth/users/{username}/role` | ADMIN | change a role |
| POST | `/api/devices` | any | enrol a device (starts PENDING) |
| GET | `/api/devices` | any | own devices; ADMIN sees the fleet |
| PATCH | `/api/devices/{id}` | ADMIN | approve, quarantine or revoke |
| GET · POST | `/api/policies` | any · ADMIN | list (in evaluation order) · create |
| PATCH · DELETE | `/api/policies/{id}` | ADMIN | edit (bumps version) · disable |
| GET | `/api/policies/{id}/revisions` | any | revision history |
| GET · POST | `/api/resources` | any · ADMIN | registered upstreams |
| POST | `/api/simulate` | any | "what would happen if…", nothing logged |
| GET | `/api/access-logs` | any | every decision, filterable |
| GET | `/api/statistics` | any | the dashboard payload |
| GET | `/api/audit` | ADMIN | administrative actions |
| POST | `/internal/authorize` | gateway only | the PDP endpoint (HMAC-authenticated) |

Gateway, `http://localhost:8080`: everything else is proxied. Responses carry
`X-ZTA-Decision`, `X-ZTA-Trust-Score`, `X-ZTA-Policy` and `X-Request-ID`, so the
enforcement result is visible from `curl` alone.

A denial:

```json
{
  "detail": "Access denied by policy",
  "reason": "Failed MFA, source network for policy 'allow-admin-console'",
  "resource": "admin",
  "trust_score": 70,
  "request_id": "9f2c1a8be004"
}
```

## Security properties

- **Default deny.** Unmatched requests, unknown paths and unauthenticated
  callers are all denied; there is no pass-through mode.
- **Short-lived access tokens** (15 minutes) with typed claims, audience and
  issuer, bound to a server-side session so logout revokes immediately.
- **Refresh rotation.** Using a refresh token revokes it and issues a new pair,
  so a stolen token is usable at most once.
- **MFA** via TOTP (RFC 6238, implemented in `zta/common/security.py`), with a
  ±1 step window for clock skew.
- **Account lockout** after repeated failures, on top of per-IP rate limiting —
  an attacker rotating IPs still hits the account-level wall.
- **Credential hygiene.** bcrypt at cost 12; identical responses for unknown
  users and wrong passwords.
- **Signed hops.** Gateway→PDP and gateway→upstream calls are HMAC-signed with
  a timestamp, so neither endpoint accepts a caller that skipped the gateway.
- **Forwarded-for handling.** The TLS terminator overwrites `X-Forwarded-For`
  rather than appending, so a client cannot claim a corporate source address.
- **Audit separation.** `access_logs` records per-request decisions;
  `audit_logs` records administrative changes. Both are queryable from the API.
- **Containers** run as an unprivileged user; the databases and internal
  services publish no ports.

## Testing

```bash
cd backend
pip install -r requirements-dev.txt
pytest                # 99 tests
pytest --cov=zta      # coverage report
```

| File | What it covers |
|------|----------------|
| `tests/test_policy_engine.py` | the decision logic as pure functions: default deny, priority order, first-match, every condition, midnight-wrapping time windows, trust scoring bounds |
| `tests/test_auth.py` | login, lockout, TOTP enrolment and verification, refresh rotation, logout revocation, RBAC, rate limiting, audit |
| `tests/test_control_plane_api.py` | policy CRUD, versioning and revisions, input validation, device enrolment and approval, ownership isolation, the simulator |
| `tests/test_gateway.py` | the full enforcement path, including fail-closed behaviour, the decision cache, signature verification and the evidence trail |

The gateway tests drive the real gateway: it still signs its PDP calls, caches
decisions and signs what it forwards. Only the HTTP transport is swapped for an
in-process one, so no network or containers are needed.

Evaluation that depends on the calendar (weekday and time-window policies) is
tested in the engine suite with explicit timestamps; the seeded weekend rule is
disabled in the API fixtures so the suite does not pass or fail depending on the
day it runs.

## Measured results

| Measurement | Value |
|-------------|-------|
| Automated tests | 99, all passing |
| Statement coverage (`zta/`) | 95% overall; 100% on the policy engine and the gateway |
| Policy conditions implemented | 9 (role, resource, method, path glob, source CIDR, time/weekday window, device registration, MFA, trust floor) |
| Enforcement paths covered end-to-end | 26 gateway tests (allow, deny, revocation, quarantine, fail-closed, replay, cache) |
| API endpoints | 24 on the control plane (23 REST + the PDP endpoint), plus the gateway's catch-all proxy |
| Default decision for an unmatched request | DENY |

Reproduce with `pytest --cov=zta` in `backend/`.

## Project layout

```
backend/
  zta/
    common/        config, database, models, schemas, security (bcrypt, JWT,
                   TOTP, HMAC), audit, rate limiting, middleware
    policy/        the decision engine and trust scoring — pure functions
    control_plane/ auth, devices, policies, PDP endpoint, insights, bootstrap
    gateway/       the enforcement point and its PDP client + decision cache
    services/      the stand-in internal service, run three times
  tests/           engine, auth, control-plane API, gateway end-to-end
frontend/
  src/pages/       overview, access log, policies, simulator, devices, audit
nginx/             TLS terminator config + certificate script
docs/              ARCHITECTURE.md · POLICIES.md
docker-compose.yml three networks, two of them internal
```

## Licence

MIT.
