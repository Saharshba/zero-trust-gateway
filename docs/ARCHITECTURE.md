# Architecture

## Components

| Component | Runs as | Responsibility |
|-----------|---------|----------------|
| **Gateway** (`zta.gateway`) | `uvicorn zta.gateway.app:app` | Policy enforcement point. Terminates client requests, asks the PDP, forwards or refuses. Holds no policy logic and no database connection. |
| **Control plane** (`zta.control_plane`) | `uvicorn zta.control_plane.app:app` | Identity provider, device registry, policy store, policy decision point, evidence store, admin API. |
| **Policy engine** (`zta.policy`) | library | Pure functions: `evaluate(context, policies) -> DecisionResult` and `trust_score(...)`. No I/O. |
| **Internal services** (`zta.services`) | `uvicorn zta.services.internal_service:app` | Stand-ins for real internal apps: no authentication of their own, reachable only through the gateway. |

All four ship in one image; the compose file selects the role with the command.
That keeps the shared model, schema and security code in one place while still
running them as separate, separately-networked processes.

## Why the PEP and the PDP are separate

The gateway is the component most exposed to the internet, so it holds as
little as possible: no database credentials, no policy data, no user records.
Compromising it gets an attacker a process that can ask "may this token do
this?" and nothing else.

The cost is a round trip per request, which the short-lived ALLOW cache absorbs.
The consequences of the split are visible in the tests: `test_gateway.py`
exercises revocation, quarantine and policy changes taking effect through the
real path, and `test_policy_engine.py` exercises the decision logic with no
HTTP at all.

## Request lifecycle

```
1  client ──► gateway                     Authorization: Bearer …, X-Device-Id
2  gateway: collect method, path, source IP, token, device id
3  gateway ──► PDP   POST /internal/authorize   + HMAC signature over the call
4  PDP: decode token → check session → resolve resource → read device posture
5  PDP: trust_score(identity, MFA, posture, network)
6  PDP: evaluate(context, policies)  — priority order, first match, default deny
7  PDP: INSERT access_logs (always, before responding)
8  PDP ──► gateway   {decision, reason, policy, version, trust, upstream}
9  gateway: DENY  → 401/403 with the reason and X-ZTA-* headers
            ALLOW → forward to upstream, HMAC-signed, user token stripped,
                    X-ZTA-User / X-ZTA-Role / X-ZTA-Trust-Score asserted
10 upstream: verify signature (30s replay window) → serve
11 gateway ──► client, adding X-ZTA-Decision, X-ZTA-Policy, X-Request-ID
```

Step 7 happens before step 8 on purpose: a gateway that dies mid-request must
not be able to lose the evidence that a decision was made.

## Data model

```
users ──< sessions                 one row per issued refresh token; logout
  │                                revokes, so access tokens die with it
  └──< devices                     enrolment + posture; PENDING until approved

resources                          path prefix → upstream, with a classification
policies ──< policy_revisions      versioned; disabled, never deleted

access_logs                        one row per authorisation decision
audit_logs                         one row per administrative action
```

`sessions` is what makes stateless JWTs revocable: the access token carries a
`sid`, and both the control plane and the PDP check that the session row is
still live. It costs one indexed lookup per request and buys immediate logout.

## Trust score

```
        ┌──────────────┐
        │ authenticated│──no──► 0
        └──────┬───────┘
              yes
               │  +25 base
               ├─ MFA this session               +25
               ├─ device approved                +20  (+5 per posture signal)
               ├─ device quarantined             −60
               ├─ device unknown                 −10
               └─ source in a corporate network  +10
                          │
                     clamp to 0…100
```

The score is an input to policies (`min_trust_score`), never a decision on its
own: a policy still has to name the role and the resource.

## Failure behaviour

| Failure | Result |
|---------|--------|
| PDP unreachable | gateway returns `503`, forwards nothing (fail closed) |
| Upstream unreachable | gateway returns `502`, decision already logged |
| Token expired or invalid | `401` with the reason, logged as `anonymous` |
| Session revoked | `401` on the next request, cached ALLOW expires within seconds |
| Policy misconfiguration | default deny — a broken policy set locks people out rather than letting everyone in |

## Deployment topology

```
                     host :8443      :8080        :8000        :5173
                        │              │             │            │
              ┌─────────┴───┐  ┌───────┴────┐  ┌─────┴──────┐  ┌──┴─────┐
   edge       │ tls-proxy   │  │  gateway   │  │  control-  │  │console │
   network    │ (nginx)     │  │   (PEP)    │  │  plane     │  │        │
              └─────────────┘  └─────┬──────┘  └─────┬──────┘  └────────┘
                                     │               │
        internal network ────────────┤               ├──────── data network
        (internal: true)             │               │        (internal: true)
                     ┌───────────────┼──────┐   ┌────┴─────┬──────────┐
                ┌────┴────┐  ┌───────┴──┐ ┌─┴──┴───┐  ┌────┴───┐
                │ public  │  │ reports  │ │ admin  │  │postgres│  redis
                └─────────┘  └──────────┘ └────────┘  └────────┘
```

Neither internal network has a route off the host. The only paths in are the
gateway (for services) and the control plane (for data).
