# auto_fix_mcp: a deliberately vulnerable multi-tenant API

An intentionally insecure REST API (Node.js / Express, with an OpenAPI spec) built as a practice target for
application-security testing and automated-fix workflows. Run it only in a sandbox and never with real data.

See [VULNERABILITIES.md](VULNERABILITIES.md) for every planted issue and how to reproduce it.

## What it models

A small multi-tenant SaaS API: two tenants (organisations), six roles (owner, operator, developer, viewer, end_user,
customer) and JWT authentication. Role and tenant checks are deliberately missing across most endpoints.

Planted issue classes:
- broken function-level authorization (BFLA)
- cross-tenant broken object-level authorization (BOLA)
- mass assignment
- privilege escalation
- excessive data exposure
- acceptance of expired tokens

## Run it locally

```bash
npm install
npm start          # listens on PORT (default 3000)
```

- `GET /health` is the health check.
- Seed accounts are listed in [VULNERABILITIES.md](VULNERABILITIES.md) and seeded in [data.js](data.js).
- The API description is in [openapi.yaml](openapi.yaml).

## Suggested test loop

1. Run the app, then test it with a proxy such as Burp Suite or with the OpenAPI spec in Postman.
2. Compare what you find with [VULNERABILITIES.md](VULNERABILITIES.md).
3. Fix a subset of the issues in [index.js](index.js), then re-test to confirm the findings close.
4. Revert the fix so the sandbox returns to its fully vulnerable baseline. The git history contains fix and revert
   pairs for this reason; that is expected.
