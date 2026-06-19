const express = require('express');
const path = require('path');
const jwt = require('jsonwebtoken');
const { orgs, users, apiKeys, connectors, workflows, auditLog, usage, hubSettings } = require('./data');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const port = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fastn-sandbox-dev-secret';

// --- VULN: Expired Authorization ---
// Signature is genuinely verified (tokens can't be forged without valid
// credentials), but expiry is explicitly ignored, so an expired-but-
// previously-valid token is accepted forever.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) return res.status(401).json({ error: 'unauthenticated' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET, { ignoreExpiration: true });
    req.user = decoded;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid token' });
  }
}

// --- VULN: Broken Function-Level Authorization (BFLA) + Broken Object
// Level Authorization (BOLA) ---
// None of the routes below check req.user.role against the route's
// intended access, nor req.user.orgId against the :orgId in the path.
// Any authenticated user, in any org, with any role, can call any route.

app.post('/api/v1/auth/login', (req, res) => {
  const { email, password } = req.body || {};
  const user = users.find((u) => u.email === email && u.password === password);
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const token = jwt.sign(
    { sub: user.id, email: user.email, role: user.role, orgId: user.orgId },
    JWT_SECRET,
    { expiresIn: '1h' }
  );
  res.json({ token });
});

app.get('/api/v1/orgs/:orgId', requireAuth, (req, res) => {
  const org = orgs.find((o) => o.id === req.params.orgId);
  if (!org) return res.status(404).json({ error: 'not found' });
  res.json(org);
});

// VULN: Mass Assignment — blindly applies the whole request body.
app.put('/api/v1/orgs/:orgId', requireAuth, (req, res) => {
  const org = orgs.find((o) => o.id === req.params.orgId);
  if (!org) return res.status(404).json({ error: 'not found' });
  Object.assign(org, req.body);
  res.json(org);
});

app.get('/api/v1/orgs/:orgId/audit-log', requireAuth, (req, res) => {
  const entries = auditLog[req.params.orgId];
  if (!entries) return res.status(404).json({ error: 'not found' });
  res.json(entries);
});

// VULN: Excessive Data Exposure — returns raw key objects incl. secret value.
app.get('/api/v1/orgs/:orgId/api-keys', requireAuth, (req, res) => {
  const keys = apiKeys[req.params.orgId];
  if (!keys) return res.status(404).json({ error: 'not found' });
  res.json(keys);
});

// VULN: Excessive Data Exposure — returns raw user objects incl. password.
app.get('/api/v1/orgs/:orgId/users', requireAuth, (req, res) => {
  const members = users.filter((u) => u.orgId === req.params.orgId);
  res.json(members);
});

// VULN: Privilege Escalation — any role can promote any user to any role,
// including 'owner'.
app.put('/api/v1/orgs/:orgId/users/:userId/role', requireAuth, (req, res) => {
  const member = users.find((u) => u.orgId === req.params.orgId && u.id === req.params.userId);
  if (!member) return res.status(404).json({ error: 'not found' });
  member.role = req.body && req.body.role;
  res.json(member);
});

app.get('/api/v1/orgs/:orgId/connectors', requireAuth, (req, res) => {
  const list = connectors[req.params.orgId];
  if (!list) return res.status(404).json({ error: 'not found' });
  res.json(list);
});

app.get('/api/v1/orgs/:orgId/workflows', requireAuth, (req, res) => {
  const list = workflows[req.params.orgId];
  if (!list) return res.status(404).json({ error: 'not found' });
  res.json(list);
});

app.post('/api/v1/orgs/:orgId/workflows/:workflowId/deploy', requireAuth, (req, res) => {
  const list = workflows[req.params.orgId] || [];
  const wf = list.find((w) => w.id === req.params.workflowId);
  if (!wf) return res.status(404).json({ error: 'not found' });
  wf.status = 'deployed';
  res.json(wf);
});

app.get('/api/v1/orgs/:orgId/usage', requireAuth, (req, res) => {
  const stats = usage[req.params.orgId];
  if (!stats) return res.status(404).json({ error: 'not found' });
  res.json(stats);
});

app.get('/api/v1/orgs/:orgId/hub-settings', requireAuth, (req, res) => {
  const settings = hubSettings[req.params.orgId];
  if (!settings) return res.status(404).json({ error: 'not found' });
  res.json(settings);
});

// --- Baseline routes (unchanged) ---

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
