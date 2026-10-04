const express = require('express');
const cookieParser = require('cookie-parser');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(express.static('public'));

const PORT = process.env.PORT || 3000;
const RP_ID = process.env.RP_ID || 'localhost';
const ORIGIN = process.env.ORIGIN || `http://localhost:${PORT}`;
const RP_NAME = 'CampusPass';

const db = new Database('campuspass.db');
db.pragma('journal_mode = WAL');
db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credentials (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  public_key BLOB NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  transports TEXT,
  created_at TEXT NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at TEXT NOT NULL
);
`);

const challenges = new Map();
const now = () => new Date().toISOString();
const userByEmail = db.prepare('SELECT * FROM users WHERE email = ?');
const credsByUser = db.prepare('SELECT * FROM credentials WHERE user_id = ?');

function getSession(req) {
  const token = req.cookies.campuspass_session;
  if (!token) return null;
  const row = db.prepare('SELECT * FROM sessions WHERE token = ? AND expires_at > ?').get(token, Date.now());
  if (!row) return null;
  return db.prepare('SELECT * FROM users WHERE id = ?').get(row.user_id);
}

app.get('/api/config', (req, res) => res.json({ rpID: RP_ID, rpName: RP_NAME }));

app.get('/api/me', (req, res) => {
  const user = getSession(req);
  res.json({ authenticated: !!user, user: user ? { id: user.id, name: user.name, email: user.email } : null });
});

app.get('/api/admin/stats', (req, res) => {
  const user = getSession(req);
  if (!user) return res.status(401).json({ error: 'Authentication required' });
  const users = db.prepare('SELECT COUNT(*) c FROM users').get().c;
  const credentials = db.prepare('SELECT COUNT(*) c FROM credentials').get().c;
  const activeSessions = db.prepare('SELECT COUNT(*) c FROM sessions WHERE expires_at > ?').get(Date.now()).c;
  res.json({ users, credentials, activeSessions });
});

app.post('/api/register/options', async (req, res) => {
  try {
    const { name, email } = req.body;
    if (!name || !email) return res.status(400).json({ error: 'Name and email are required' });
    const normalized = email.trim().toLowerCase();
    let user = userByEmail.get(normalized);
    if (!user) {
      user = { id: crypto.randomUUID(), name: name.trim(), email: normalized, created_at: now() };
      db.prepare('INSERT INTO users (id,name,email,created_at) VALUES (?,?,?,?)').run(user.id,user.name,user.email,user.created_at);
    }
    const existing = credsByUser.all(user.id).map(c => ({ id: c.id, transports: c.transports ? JSON.parse(c.transports) : undefined }));
    const options = await generateRegistrationOptions({
      rpName: RP_NAME,
      rpID: RP_ID,
      userName: normalized,
      userDisplayName: user.name,
      userID: Buffer.from(user.id),
      attestationType: 'none',
      excludeCredentials: existing,
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'preferred' },
      supportedAlgorithmIDs: [-7, -257],
    });
    challenges.set(`reg:${user.id}`, options.challenge);
    res.json({ options });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/register/verify', async (req, res) => {
  try {
    const { userId, response } = req.body;
    const expectedChallenge = challenges.get(`reg:${userId}`);
    if (!expectedChallenge) return res.status(400).json({ error: 'Registration challenge expired' });
    const verification = await verifyRegistrationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
    });
    if (!verification.verified || !verification.registrationInfo) return res.status(400).json({ error: 'Passkey registration failed' });
    const { credential, credentialDeviceType, credentialBackedUp } = verification.registrationInfo;
    db.prepare(`INSERT OR REPLACE INTO credentials (id,user_id,public_key,counter,transports,created_at) VALUES (?,?,?,?,?,?)`)
      .run(credential.id, userId, Buffer.from(credential.publicKey), credential.counter, JSON.stringify(response.response.transports || []), now());
    challenges.delete(`reg:${userId}`);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)').run(token,userId,Date.now()+7*24*60*60*1000,now());
    res.cookie('campuspass_session', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 });
    res.json({ verified: true, credentialDeviceType, credentialBackedUp });
  } catch (e) { res.status(400).json({ error: e.message }); }
});

app.post('/api/login/options', async (req, res) => {
  try {
    const { email } = req.body;
    const normalized = email?.trim().toLowerCase();
    const user = normalized ? userByEmail.get(normalized) : null;
    if (!user) return res.status(404).json({ error: 'No account found for this email' });
    const credentials = credsByUser.all(user.id).map(c => ({ id: c.id, transports: c.transports ? JSON.parse(c.transports) : undefined }));
    if (!credentials.length) return res.status(400).json({ error: 'No passkey registered for this account' });
    const options = await generateAuthenticationOptions({ rpID: RP_ID, allowCredentials: credentials, userVerification: 'preferred' });
    challenges.set(`auth:${user.id}`, options.challenge);
    res.json({ options, userId: user.id });
  } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/login/verify', async (req, res) => {
  try {
    const { userId, response } = req.body;
    const expectedChallenge = challenges.get(`auth:${userId}`);
    if (!expectedChallenge) return res.status(400).json({ error: 'Login challenge expired' });
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(userId);
    const credential = db.prepare('SELECT * FROM credentials WHERE id = ? AND user_id = ?').get(response.id, userId);
    if (!user || !credential) return res.status(400).json({ error: 'Credential not recognized' });
    const verification = await verifyAuthenticationResponse({
      response,
      expectedChallenge,
      expectedOrigin: ORIGIN,
      expectedRPID: RP_ID,
      credential: { id: credential.id, publicKey: new Uint8Array(credential.public_key), counter: credential.counter, transports: credential.transports ? JSON.parse(credential.transports) : undefined },
    });
    if (!verification.verified) return res.status(401).json({ error: 'Authentication failed' });
    db.prepare('UPDATE credentials SET counter = ? WHERE id = ?').run(verification.authenticationInfo.newCounter, credential.id);
    challenges.delete(`auth:${userId}`);
    const token = crypto.randomBytes(32).toString('hex');
    db.prepare('INSERT INTO sessions (token,user_id,expires_at,created_at) VALUES (?,?,?,?)').run(token,userId,Date.now()+7*24*60*60*1000,now());
    res.cookie('campuspass_session', token, { httpOnly: true, sameSite: 'lax', secure: process.env.NODE_ENV === 'production', maxAge: 7*24*60*60*1000 });
    res.json({ verified: true, user: { id: user.id, name: user.name, email: user.email } });
  } catch (e) { res.status(401).json({ error: e.message }); }
});

app.post('/api/logout', (req,res) => {
  const token = req.cookies.campuspass_session;
  if (token) db.prepare('DELETE FROM sessions WHERE token = ?').run(token);
  res.clearCookie('campuspass_session');
  res.json({ ok: true });
});

app.listen(PORT, () => console.log(`CampusPass running at ${ORIGIN}`));
