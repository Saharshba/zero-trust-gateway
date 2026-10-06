# Writing policies

## The shape of a decision

```python
evaluate(context, policies) -> DecisionResult(decision, reason, matched_policy, policy_version, trust_score)
```

- policies are sorted by `priority` (ascending), then by name for determinism;
- the first policy whose conditions **all** match decides the request;
- if nothing matches, the request is denied.

Put `DENY` policies at low priority numbers when they must override everything
(a freeze during an incident, a blanket rule for guests), and leave the broad
`ALLOW` rules at higher numbers.

## Conditions

An empty condition means "no constraint". A policy with no conditions at all
matches every authenticated request, which is why an unconditional `ALLOW`
should never be written casually.

| Field | Type | Matches when |
|-------|------|--------------|
| `roles` | list | the caller's role is in the list |
| `resources` | list | the resolved resource name is in the list |
| `methods` | list | the HTTP method is in the list (case-insensitive) |
| `path_globs` | list | the path matches any glob (`fnmatch`, so `/admin/*`) |
| `source_cidrs` | list | the source IP is inside any network; a malformed IP never matches |
| `require_registered_device` | bool | the device is enrolled **and** approved, and not quarantined |
| `require_mfa` | bool | this session completed TOTP |
| `min_trust_score` | 0–100 | the computed score is at least this |
| `time_start_hour` / `time_end_hour` | 0–23 | the current hour is inside the window; equal values mean "always"; `22`→`6` wraps midnight |
| `weekdays` | list of 0–6 | today is in the list (0 = Monday) |

## Worked examples

**Restrict an administrative surface to managed, MFA-verified admins on the
corporate network.**

```json
{
  "name": "allow-admin-console",
  "effect": "ALLOW",
  "priority": 10,
  "roles": ["ADMIN"],
  "resources": ["admin"],
  "source_cidrs": ["10.0.0.0/8", "192.168.0.0/16"],
  "require_registered_device": true,
  "require_mfa": true,
  "min_trust_score": 80
}
```

**Let contractors read reports during working hours only.**

```json
{
  "name": "allow-contractor-reports",
  "effect": "ALLOW",
  "priority": 30,
  "roles": ["EMPLOYEE"],
  "resources": ["reports"],
  "methods": ["GET"],
  "time_start_hour": 9,
  "time_end_hour": 18,
  "weekdays": [0, 1, 2, 3, 4],
  "require_registered_device": true
}
```

**Freeze a resource during an incident** — a deny at priority 1 outranks every
allow rule, and disabling it later restores the previous behaviour exactly,
with both changes recorded in `policy_revisions`.

```json
{ "name": "incident-freeze", "effect": "DENY", "priority": 1, "resources": ["reports"] }
```

## Test a policy before you rely on it

The console's **Simulator** page (and `POST /api/simulate`) evaluates a
hypothetical request and returns the same reason string the real decision would
produce, without logging anything or forwarding anything:

```bash
curl -s localhost:8000/api/simulate -H "Authorization: Bearer $TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"guest","path":"/admin/users","method":"GET","source_ip":"10.0.0.5"}'
```

```json
{
  "decision": "DENY",
  "reason": "No policy grants this role access to this resource",
  "trust_score": 15,
  "username": "guest",
  "role": "GUEST"
}
```

The same page can send the request through the gateway for real, which shows
the enforcement headers and puts a row in the access log.

## Reading a denial

Denials name the closest allow-policy and the conditions that failed:

```
Failed MFA, source network for policy 'allow-admin-console'
```

means the role and resource matched — this user *could* be allowed — but the
session has no MFA and the request came from outside the permitted networks.

```
No policy grants this role access to this resource
```

means nothing came close: no allow-policy lists both that role and that
resource. That is the default-deny outcome, not a misconfiguration.

## Changing policies safely

1. Simulate the change first.
2. Edit through the API or the console; the version increments and a snapshot
   is stored in `policy_revisions`.
3. New decisions use the new policy immediately. Existing **allow** decisions
   can be served from the gateway's cache for up to `DECISION_CACHE_SECONDS`
   (default 5); denials are never cached.
4. To roll back, apply the previous snapshot from the revision history — it
   contains every condition field verbatim.

Policies are disabled rather than deleted so that the record of what was
permitted, and when, survives.
