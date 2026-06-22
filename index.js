const crypto = require('crypto');
const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const { orgs, users, apiKeys, connectors, workflows, auditLog, usage, hubSettings } = require('./data');

const app = express();
app.set('trust proxy', 1);
app.use(express.json());

const port = process.env.PORT || 3000;

const ROLES = ['owner', 'operator', 'developer', 'viewer', 'end_user', 'customer'];
const TOKEN_ISSUER = 'auto-fix-mcp';
const TOKEN_AUDIENCE = 'auto-fix-mcp-api';
const ACCESS_TOKEN_TTL = '15m';

// RS256 keypair generated fresh per process start. Tokens are signed with the
// private half and verified with the public half, and don't outlive a
// restart — short-lived by construction, no secret to leak from env config.
const { privateKey, publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });

const revokedTokenIds = new Set();

function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'unauthenticated' });
  let decoded;
  try {
    decoded = jwt.verify(token, publicKey, {
      algorithms: ['RS256'],
      issuer: TOKEN_ISSUER,
      audience: TOKEN_AUDIENCE,
    });
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
  if (decoded.jti && revokedTokenIds.has(decoded.jti)) {
    return res.status(401).json({ error: 'token revoked' });
  }
  // Claims are signature-verified, but role/orgId are re-derived from the
  // canonical user record rather than trusted from the payload, so a stale
  // or (hypothetically) tampered claim can never grant more than the user's
  // current server-side record allows.
  const canonicalUser = users.find((u) => u.id === decoded.sub);
  if (!canonicalUser) return res.status(401).json({ error: 'invalid token' });
  req.user = {
    id: canonicalUser.id,
    email: canonicalUser.email,
    role: canonicalUser.role,
    orgId: canonicalUser.orgId,
  };
  req.tokenId = decoded.jti;
  next();
}

function requireSameOrg(req, res, next) {
  if (req.user.orgId !== req.params.orgId) {
    return res.status(403).json({ error: 'forbidden' });
  }
  next();
}

function requireRole(...allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ error: 'forbidden' });
    }
    next();
  };
}

// --- Global rate limiting (fixed window per IP) ---
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const RATE_LIMIT_MAX = 1000;
const rateLimitHits = new Map();

function rateLimit(req, res, next) {
  const now = Date.now();
  let entry = rateLimitHits.get(req.ip);
  if (!entry || now > entry.resetAt) {
    entry = { count: 0, resetAt: now + RATE_LIMIT_WINDOW_MS };
    rateLimitHits.set(req.ip, entry);
  }
  entry.count += 1;
  res.set('X-RateLimit-Limit', String(RATE_LIMIT_MAX));
  res.set('X-RateLimit-Remaining', String(Math.max(0, RATE_LIMIT_MAX - entry.count)));
  if (entry.count > RATE_LIMIT_MAX) {
    res.set('Retry-After', String(Math.ceil((entry.resetAt - now) / 1000)));
    return res.status(429).json({ error: 'rate limit exceeded' });
  }
  next();
}
app.use(rateLimit);
app.use(express.static(path.join(__dirname, 'public')));

function paginate(req, res, list) {
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 20, 1), 100);
  const offset = Math.max(parseInt(req.query.offset, 10) || 0, 0);
  res.set('X-Total-Count', String(list.length));
  res.set('X-Page-Limit', String(limit));
  res.set('X-Current-Page', String(Math.floor(offset / limit) + 1));
  return list.slice(offset, offset + limit);
}

app.post('/api/v1/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const jti = crypto.randomUUID();
  const token = jwt.sign(
    { sub: user.id, email: user.email, role: user.role, orgId: user.orgId, jti },
    privateKey,
    { algorithm: 'RS256', expiresIn: ACCESS_TOKEN_TTL, issuer: TOKEN_ISSUER, audience: TOKEN_AUDIENCE }
  );
  res.json({ token });
});

app.post('/api/v1/auth/logout', requireAuth, (req, res) => {
  if (req.tokenId) revokedTokenIds.add(req.tokenId);
  res.json({ status: 'revoked' });
});

app.get('/api/v1/orgs/:orgId', requireAuth, requireSameOrg, requireRole('owner'), (req, res) => {
  const org = orgs.find((o) => o.id === req.params.orgId);
  if (!org) return res.status(404).json({ error: 'not found' });
  res.json(org);
});

// VULN (still planted, out of scope): Mass Assignment — Object.assign blindly
// applies the whole request body. Tracked separately in VULNERABILITIES.md.
app.put('/api/v1/orgs/:orgId', requireAuth, requireSameOrg, requireRole('owner'), (req, res) => {
  const org = orgs.find((o) => o.id === req.params.orgId);
  if (!org) return res.status(404).json({ error: 'not found' });
  Object.assign(org, req.body);
  res.json(org);
});

app.get('/api/v1/orgs/:orgId/audit-log', requireAuth, requireSameOrg, requireRole('owner', 'operator'), (req, res) => {
  const entries = auditLog[req.params.orgId];
  if (!entries) return res.status(404).json({ error: 'not found' });
  res.json(paginate(req, res, entries));
});

app.get('/api/v1/orgs/:orgId/api-keys', requireAuth, requireSameOrg, requireRole('owner', 'operator'), (req, res) => {
  const keys = apiKeys[req.params.orgId];
  if (!keys) return res.status(404).json({ error: 'not found' });
  res.json(paginate(req, res, keys));
});

// Shadow Data fix: strip password before returning, matching the documented
// OAS User schema (no password field in the response shape).
app.get('/api/v1/orgs/:orgId/users', requireAuth, requireSameOrg, requireRole('owner', 'operator'), (req, res) => {
  const members = users
    .filter((u) => u.orgId === req.params.orgId)
    .map(({ password, ...safe }) => safe);
  res.json(paginate(req, res, members));
});

app.put('/api/v1/orgs/:orgId/users/:userId/role', requireAuth, requireSameOrg, requireRole('owner'), (req, res) => {
  const member = users.find((u) => u.orgId === req.params.orgId && u.id === req.params.userId);
  if (!member) return res.status(404).json({ error: 'not found' });
  const newRole = req.body && req.body.role;
  if (!ROLES.includes(newRole)) return res.status(400).json({ error: 'invalid role' });
  member.role = newRole;
  const entries = auditLog[req.params.orgId] || (auditLog[req.params.orgId] = []);
  entries.push({
    id: `log_${crypto.randomUUID()}`,
    actor: req.user.email,
    action: 'user.role_changed',
    timestamp: new Date().toISOString(),
  });
  const { password, ...safeMember } = member;
  res.json(safeMember);
});

app.get('/api/v1/orgs/:orgId/connectors', requireAuth, requireSameOrg, requireRole('owner', 'operator', 'developer'), (req, res) => {
  const list = connectors[req.params.orgId];
  if (!list) return res.status(404).json({ error: 'not found' });
  res.json(paginate(req, res, list));
});

app.get('/api/v1/orgs/:orgId/workflows', requireAuth, requireSameOrg, requireRole('owner', 'operator', 'developer'), (req, res) => {
  const list = workflows[req.params.orgId];
  if (!list) return res.status(404).json({ error: 'not found' });
  res.json(paginate(req, res, list));
});

app.post('/api/v1/orgs/:orgId/workflows/:workflowId/deploy', requireAuth, requireSameOrg, requireRole('owner', 'operator', 'developer'), (req, res) => {
  const list = workflows[req.params.orgId] || [];
  const wf = list.find((w) => w.id === req.params.workflowId);
  if (!wf) return res.status(404).json({ error: 'not found' });
  wf.status = 'deployed';
  res.json(wf);
});

app.get('/api/v1/orgs/:orgId/usage', requireAuth, requireSameOrg, requireRole('owner'), (req, res) => {
  const stats = usage[req.params.orgId];
  if (!stats) return res.status(404).json({ error: 'not found' });
  res.json(stats);
});

app.get('/api/v1/orgs/:orgId/hub-settings', requireAuth, requireSameOrg, requireRole('owner', 'operator'), (req, res) => {
  const settings = hubSettings[req.params.orgId];
  if (!settings) return res.status(404).json({ error: 'not found' });
  res.json(settings);
});

// --- Baseline routes (unchanged) ---
// /health stays public and unauthenticated: it's the Render platform health
// check (see render.yaml) and returns no sensitive data, so there's nothing
// to "disable" without breaking deploys.

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/VULNERABILITIES.md', (req, res) => {
  res.sendFile(path.join(__dirname, 'VULNERABILITIES.md'));
});

app.get('/openapi.yaml', (req, res) => {
  res.sendFile(path.join(__dirname, 'openapi.yaml'));
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
