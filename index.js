const express = require('express');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

const port = process.env.PORT || 3000;

// --- In-memory data (intentionally insecure: plaintext passwords) ---

const users = [
  { id: 'u1', username: 'alice', password: 'alice123', role: 'user' },
  { id: 'u2', username: 'bob', password: 'bob123', role: 'user' },
  { id: 'u3', username: 'admin', password: 'admin123', role: 'admin' },
];

const notes = [
  { id: 'n1', ownerId: 'u1', title: 'Alice private note', body: 'Alice secret stuff', isPrivate: true },
  { id: 'n2', ownerId: 'u2', title: 'Bob private note', body: 'Bob secret stuff', isPrivate: true },
  { id: 'n3', ownerId: 'u3', title: 'Admin note', body: 'Admin secret stuff', isPrivate: true },
];

let nextNoteId = 4;

// --- VULN 1: Broken Authentication ---
// Plaintext password comparison, unsigned/forgeable "token" (just base64 of
// the user id), no expiry, no rate limiting on attempts.
function decodeToken(req) {
  const header = req.headers.authorization || '';
  const token = header.replace(/^Bearer\s+/i, '');
  if (!token) return null;
  let userId;
  try {
    userId = Buffer.from(token, 'base64').toString('utf8');
  } catch {
    return null;
  }
  return users.find((u) => u.id === userId) || null;
}

app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = users.find((u) => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  const token = Buffer.from(user.id).toString('base64');
  res.json({ token });
});

app.get('/logout', (req, res) => {
  res.json({ ok: true });
});

// --- Notes routes ---

app.post('/notes', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  const { title, body, isPrivate } = req.body || {};
  const note = { id: `n${nextNoteId++}`, ownerId: user.id, title, body, isPrivate: !!isPrivate };
  notes.push(note);
  res.status(201).json(note);
});

// VULN 4: Excessive Data Exposure — returns raw note objects (ownerId, etc.)
// instead of a filtered DTO.
app.get('/notes', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  const mine = notes.filter((n) => n.ownerId === user.id);
  res.json(mine);
});

// VULN 2: BOLA / IDOR — no check that note.ownerId matches the requester.
app.get('/notes/:id', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  const note = notes.find((n) => n.id === req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  res.json(note);
});

// VULN 5: Mass Assignment — blindly applies the whole request body onto the
// stored object, so a client can overwrite ownerId/isPrivate/id.
app.put('/notes/:id', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  const note = notes.find((n) => n.id === req.params.id);
  if (!note) return res.status(404).json({ error: 'not found' });
  Object.assign(note, req.body);
  res.json(note);
});

// --- Admin routes ---
// VULN 3: Broken Function-Level Authorization — no role === 'admin' check.
// VULN 4 (also applies here): returns raw user objects including passwords.

app.get('/admin/users', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  res.json(users);
});

app.delete('/admin/users/:id', (req, res) => {
  const user = decodeToken(req);
  if (!user) return res.status(401).json({ error: 'unauthenticated' });
  const idx = users.findIndex((u) => u.id === req.params.id);
  if (idx === -1) return res.status(404).json({ error: 'not found' });
  const [removed] = users.splice(idx, 1);
  res.json(removed);
});

// --- Baseline routes (unchanged) ---

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

app.get('/VULNERABILITIES.md', (req, res) => {
  res.sendFile(path.join(__dirname, 'VULNERABILITIES.md'));
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});
