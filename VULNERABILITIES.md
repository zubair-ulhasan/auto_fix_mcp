# Planted vulnerabilities (intentional — test target for PerfAI scan/auto-fix validation)

This app deliberately contains the issues below so a scanner can be checked
against known-bad code, and later so PerfAI's MCP auto-fix tool can be
checked against known fixes. Do not "fix" these without instruction — that
defeats the purpose of this repo.

Seed users (see `index.js`): `alice` / `alice123` (role `user`), `bob` /
`bob123` (role `user`), `admin` / `admin123` (role `admin`).

Base URL below is `http://localhost:3000`; swap for
`https://auto-fix-mcp.onrender.com` to test the deployed instance.

---

## 1. API2:2023 Broken Authentication

**Where:** `POST /login`, `decodeToken()` in [index.js](index.js)

**What's wrong:** Passwords are stored and compared in plaintext. The
"token" returned on login is unsigned — just `base64(userId)` — with no
expiry and no integrity check, so any token is forgeable by anyone who knows
or guesses a user id. There's also no rate limiting on login attempts.

**Reproduce — forge another user's token without their password:**
```sh
curl -s -X POST http://localhost:3000/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"alice123"}'
# => {"token":"dTE="}   (dTE= is just base64("u1"))

# Forge bob's token with no knowledge of bob's password:
node -e "console.log(Buffer.from('u2').toString('base64'))"
# => dTI=
curl -s http://localhost:3000/notes -H 'Authorization: Bearer dTI='
# => returns bob's notes, despite never knowing bob's password
```

---

## 2. API1:2023 Broken Object Level Authorization (BOLA / IDOR)

**Where:** `GET /notes/:id` in [index.js](index.js)

**What's wrong:** The handler fetches a note by id and returns it without
checking that `note.ownerId` matches the requester.

**Reproduce — alice reads bob's private note:**
```sh
curl -s http://localhost:3000/notes/n2 -H 'Authorization: Bearer dTE='
# => 200 OK, returns bob's "n2" note even though the token is alice's (u1)
```

---

## 3. API5:2023 Broken Function Level Authorization — FIXED

**Where:** `GET /admin/users`, `DELETE /admin/users/:id` in [index.js](index.js)

**What was wrong:** These routes only checked that *some* valid token was
presented — never that `user.role === 'admin'`. Any logged-in non-admin
could call them.

**Fix:** Both routes now reject any authenticated user whose `role` isn't
`admin` with `403 Forbidden`.

**Previously reproduced with — alice (role `user`) lists and deletes users:**
```sh
curl -s http://localhost:3000/admin/users -H 'Authorization: Bearer dTE='
# => now 403 Forbidden

curl -s -X DELETE http://localhost:3000/admin/users/u2 -H 'Authorization: Bearer dTE='
# => now 403 Forbidden
```

---

## 4. API3:2023 Broken Object Property Level Authorization (Excessive Data Exposure)

**Where:** `GET /notes`, `GET /admin/users` in [index.js](index.js)

**What's wrong:** Handlers return raw internal objects via `res.json(...)`
instead of a filtered DTO, leaking fields the client should never see
(`password` on users; `ownerId`/`isPrivate` internals on notes).

**Reproduce:**
```sh
curl -s http://localhost:3000/admin/users -H 'Authorization: Bearer dTE='
# => response includes "password":"bob123" etc. in plaintext
```

---

## 5. API3:2023 Mass Assignment

**Where:** `PUT /notes/:id` in [index.js](index.js)

**What's wrong:** `Object.assign(note, req.body)` applies the entire request
body to the stored object with no field allow-list, so a client can
overwrite fields it should never control, such as `ownerId`.

**Reproduce — alice reassigns her own note to bob:**
```sh
curl -s -X PUT http://localhost:3000/notes/n1 \
  -H 'Authorization: Bearer dTE=' -H 'Content-Type: application/json' \
  -d '{"title":"hijacked","ownerId":"u2"}'

curl -s http://localhost:3000/notes/n1 -H 'Authorization: Bearer dTE='
# => "ownerId":"u2" — alice unilaterally transferred her own note to bob
```
