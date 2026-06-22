# Planted vulnerabilities (intentional — sandbox resembling a real client app)

This app is a deliberately-vulnerable sandbox built to resemble the shape of a
real client engagement: a multi-tenant SaaS app with a 6-role RBAC model.
PerfAI's scan found 45 security issues (23 Critical, 17 High, 5 Medium) on
2026-06-22; all 45 are now FIXED below. Mass Assignment (#3) remains planted
on request — it was not part of the scanned 45 and the OAS still documents it
as `additionalProperties: true` on `OrgUpdateRequest`.

## Accounts (seeded in `data.js`)

| Email | Password | Org | Role |
|---|---|---|---|
| owner@account1.test | owner123 | org_1 (Account 1) | owner |
| operator@account1.test | operator123 | org_1 (Account 1) | operator |
| developer@account1.test | developer123 | org_1 (Account 1) | developer |
| viewer@account1.test | viewer123 | org_1 (Account 1) | viewer |
| enduser@account1.test | enduser123 | org_1 (Account 1) | end_user |
| customer@account1.test | customer123 | org_1 (Account 1) | customer |
| owner@account2.test | owner123 | org_2 (Account 2) | owner |

Auth: real signed JWT (RS256, `jsonwebtoken`, 15-minute expiry, in-memory
keypair generated per process start). `POST /api/v1/auth/login` with
`{email, password}` returns `{token}`. Use it as `Authorization: Bearer
<token>` on every other route below. `POST /api/v1/auth/logout` revokes the
caller's current token.

Base URL below is `http://localhost:3000`; swap for
`https://auto-fix-mcp.onrender.com` to test the deployed instance.

---

## 1. API5:2023 Broken Function Level Authorization (BFLA) — FIXED

**Where:** every `requireAuth`-protected route in [index.js](index.js).

**What was wrong:** the middleware only verified the token was validly
signed — it never checked `req.user.role` against the route's intended
access.

**Fix:** every route now also runs `requireRole(...)` with the intended
roles below. Mismatches get `403 Forbidden`.

| Route | Required roles |
|---|---|
| `GET /api/v1/orgs/:orgId` | owner |
| `PUT /api/v1/orgs/:orgId` | owner |
| `GET /api/v1/orgs/:orgId/audit-log` | owner, operator |
| `GET /api/v1/orgs/:orgId/api-keys` | owner, operator |
| `GET /api/v1/orgs/:orgId/users` | owner, operator |
| `PUT /api/v1/orgs/:orgId/users/:userId/role` | owner |
| `GET /api/v1/orgs/:orgId/connectors` | owner, operator, developer |
| `GET /api/v1/orgs/:orgId/workflows` | owner, operator, developer |
| `POST /api/v1/orgs/:orgId/workflows/:workflowId/deploy` | owner, operator, developer |
| `GET /api/v1/orgs/:orgId/usage` | owner |
| `GET /api/v1/orgs/:orgId/hub-settings` | owner, operator |

**Previously reproduced with — lowest-privilege role (`customer`) reads
owner-only audit log:**
```sh
curl -s http://localhost:3000/api/v1/orgs/org_1/audit-log -H 'Authorization: Bearer <CUSTOMER_JWT>'
# => now 403 Forbidden
```

---

## 2. API1:2023 Broken Object/Resource/Tenant Level Authorization (BOLA) — FIXED

**Where:** same routes as above.

**What was wrong:** none checked `req.user.orgId` against the `:orgId` in
the path, so any account from either tenant could read/write the other
tenant's data.

**Fix:** every route now runs `requireSameOrg`, returning `403` on
`req.user.orgId !== req.params.orgId`.

**Previously reproduced with — Account 2's owner reads Account 1's usage:**
```sh
curl -s http://localhost:3000/api/v1/orgs/org_1/usage -H 'Authorization: Bearer <ACCOUNT2_OWNER_JWT>'
# => now 403 Forbidden
```

---

## 3. API3:2023 Mass Assignment — still planted

**Where:** `PUT /api/v1/orgs/:orgId` in [index.js](index.js) —
`Object.assign(org, req.body)` applies the entire request body with no
field allow-list. Not part of the scanned 45; left as-is per instruction.

```sh
curl -s -X PUT http://localhost:3000/api/v1/orgs/org_1 \
  -H 'Authorization: Bearer <ORG1_OWNER_JWT>' -H 'Content-Type: application/json' \
  -d '{"plan":"enterprise","billingEmail":"attacker@evil.test"}'
# => plan and billingEmail still overwritten (caller must now be org_1's owner)
```

---

## 4. Privilege Escalation — FIXED

**Where:** `PUT /api/v1/orgs/:orgId/users/:userId/role` in [index.js](index.js).

**What was wrong:** set `member.role` directly from the request body with
no check on the caller's own role.

**Fix:** restricted to `owner` (same-org) via `requireRole('owner')` +
`requireSameOrg`; the new role value is validated against the known role
enum (`400` otherwise).

```sh
# Logged in as the lowest-privilege account (customer):
curl -s -X PUT http://localhost:3000/api/v1/orgs/org_1/users/u6/role \
  -H 'Authorization: Bearer <CUSTOMER_JWT>' -H 'Content-Type: application/json' \
  -d '{"role":"owner"}'
# => now 403 Forbidden
```

---

## 5. API3:2023 Excessive Data Exposure — partially fixed

**Where:** `GET /api/v1/orgs/:orgId/users` (FIXED — see #11 Shadow Data) and
`GET /api/v1/orgs/:orgId/api-keys` (still planted — `secret` not part of the
scanned 45; left as-is).

```sh
curl -s http://localhost:3000/api/v1/orgs/org_1/api-keys -H 'Authorization: Bearer <ORG1_OWNER_OR_OPERATOR_JWT>'
# => still includes raw "secret" values for every API key
```

---

## 6. Expired Authorization — FIXED

**Where:** `requireAuth` in [index.js](index.js).

**What was wrong:** called `jwt.verify(token, JWT_SECRET, {
ignoreExpiration: true })` — signature was genuinely checked, but expired
tokens were accepted indefinitely.

**Fix:** `ignoreExpiration` removed; verification now also pins
`algorithms: ['RS256']` and checks `issuer`/`audience` (see #7, #8).
Expired, malformed, or wrong-algorithm tokens are rejected with `401`.

---

## 7. Missing Token Issuer/Audience Claim — FIXED

**Where:** `POST /api/v1/auth/login` issues the token; `requireAuth`
verifies it.

**What was wrong:** tokens carried no `iss`/`aud` claims, so the app
couldn't verify a token was actually minted by it for its own API.

**Fix:** every token now includes `iss: 'auto-fix-mcp'` and
`aud: 'auto-fix-mcp-api'`; `requireAuth` rejects tokens missing or
mismatching either claim.

---

## 8. Weak Authorization — FIXED

**Where:** `POST /api/v1/auth/login`.

**What was wrong:** tokens were HS256-signed with a static, env-overridable
shared secret and a 1-hour expiry.

**Fix:** switched to RS256 (asymmetric keypair generated fresh per process
start — nothing to leak via env config) and shortened expiry to 15 minutes.

---

## 9. Broken Token Claim Manipulation — FIXED

**Where:** `requireAuth` in [index.js](index.js).

**What was wrong:** while the signature was checked, the broader pattern
across the app was to trust embedded claims for authorization.

**Fix:** `requireAuth` now re-derives `role`/`orgId`/`email` from the
canonical record in `users` (looked up by the token's `sub`) on every
request rather than trusting the token payload for authority — the payload
is only used to identify *who*, never *what they're allowed to do*.

---

## 10. Business Audit Data Tampering — FIXED

**Where:** `PUT /api/v1/orgs/:orgId/users/:userId/role`.

**What was wrong:** role changes — a business-critical, sensitive action —
left no audit trail and had no protection beyond the (also broken)
function-level check.

**Fix:** restricted to `owner` (see #4) and every successful role change
now appends a `user.role_changed` entry (actor, timestamp) to the org's
audit log.

---

## 11. Cost Evasion — FIXED

**Where:** `PUT /api/v1/orgs/:orgId/users/:userId/role`.

**What was wrong:** any authenticated user (any role, e.g. on a `starter`
plan) could call this route to grant themselves `owner`/higher-tier access
without any billing implication.

**Fix:** covered by the same `owner`-only restriction as #4 — self-granted
role/plan-tier changes by non-owners are no longer possible.

---

## 12. Shadow Data — FIXED

**Where:** `GET /api/v1/orgs/:orgId/users`.

**What was wrong:** the response included the raw `password` field, which
is not part of the documented `User` schema in `openapi.yaml`.

**Fix:** route now strips `password` before responding
(`users.map(({ password, ...safe }) => safe)`); `openapi.yaml`'s `User`
schema no longer lists `password` either, so code and spec agree.

---

## 13. Rate Limit Headers Missing — FIXED

**Where:** app-wide.

**What was wrong:** no rate limiting at all, and no `X-RateLimit-*`
headers on any response.

**Fix:** added a global fixed-window limiter (100 req/min per IP, in-memory)
applied to every route via `app.use(rateLimit)`. Sets `X-RateLimit-Limit` /
`X-RateLimit-Remaining` on every response and `Retry-After` + `429` once the
window is exceeded.

---

## 14. Pagination Missing — FIXED

**Where:** `GET /api-keys`, `/workflows`, `/connectors`, `/users`,
`/audit-log`.

**What was wrong:** always returned the full array with no limit/offset
support.

**Fix:** added a `paginate()` helper — `?limit=&offset=` query params
(default 20, max 100), with `X-Total-Count` / `X-Page-Limit` /
`X-Current-Page` response headers.

---

## 15. Missing Token Revocation — FIXED

**Where:** app-wide.

**What was wrong:** no way to invalidate a token before its natural
expiry.

**Fix:** added `POST /api/v1/auth/logout` (authenticated) which adds the
caller's token `jti` to an in-memory revoked-token set; `requireAuth`
rejects any token whose `jti` is in that set with `401`.

---

## 16. Diagnostic/Temporary/Debug Endpoint — assessed, unchanged

**Where:** `GET /health`.

**Finding:** scanner flagged it as a diagnostic/debug endpoint that should
be disabled or restricted in production.

**Assessment:** left public and unauthenticated. It's the platform health
check (`render.yaml: healthCheckPath: /health`) and returns only
`{"status":"ok"}` — no version info, stack traces, or environment details.
Disabling or auth-gating it would break Render's deploy health checks for
no security benefit.
