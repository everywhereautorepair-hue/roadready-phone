const http = require('http');
const crypto = require('crypto');
const { Pool } = require('pg');

const port = Number(process.env.PORT || 10000);
const databaseUrl = String(process.env.DATABASE_URL || '');
const appOrigin = String(process.env.ROADREADY_APP_ORIGIN || '').replace(/\/$/, '');
const setupCode = String(process.env.ROADREADY_SETUP_CODE || '');
const sessionDurationMs = 1000 * 60 * 60 * 24 * 14;
const blankBusinessData = { appointments: [], messages: [], payments: [] };
const loginAttempts = new Map();

if (!databaseUrl) throw new Error('DATABASE_URL must be configured.');
if (!appOrigin) throw new Error('ROADREADY_APP_ORIGIN must be configured.');
if (setupCode.length < 16) throw new Error('ROADREADY_SETUP_CODE must be at least 16 characters.');

const pool = new Pool({ connectionString: databaseUrl });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

function writeJson(response, status, payload, extraHeaders = {}) {
  response.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...extraHeaders });
  response.end(JSON.stringify(payload));
}

function parseCookies(request) {
  return Object.fromEntries(String(request.headers.cookie || '').split(';').map(part => part.trim()).filter(Boolean).map(part => {
    const marker = part.indexOf('=');
    return marker === -1 ? [part, ''] : [part.slice(0, marker), decodeURIComponent(part.slice(marker + 1))];
  }));
}

function hashPassword(password, salt) { return crypto.scryptSync(password, salt, 64).toString('hex'); }
function sameText(left, right) {
  const a = Buffer.from(String(left || ''));
  const b = Buffer.from(String(right || ''));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function requestOriginIsAllowed(request) {
  const origin = String(request.headers.origin || '').replace(/\/$/, '');
  return !origin || origin === appOrigin;
}

function corsHeaders(request) {
  const origin = String(request.headers.origin || '').replace(/\/$/, '');
  return origin === appOrigin ? { 'Access-Control-Allow-Origin': appOrigin, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin' } : {};
}

function requireWriteOrigin(request) {
  if (String(request.headers.origin || '').replace(/\/$/, '') !== appOrigin) throw new HttpError(403, 'This request must come from your RoadReady app.');
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let body = '';
    request.on('data', chunk => {
      body += chunk;
      if (body.length > 1_000_000) { request.destroy(); reject(new HttpError(413, 'This update is too large.')); }
    });
    request.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); }
      catch (_) { reject(new HttpError(400, 'Please enter valid information.')); }
    });
    request.on('error', reject);
  });
}

function clientKey(request) { return String(request.headers['x-forwarded-for'] || request.socket.remoteAddress || 'unknown').split(',')[0].trim(); }
function allowLoginAttempt(request) {
  const key = clientKey(request);
  const now = Date.now();
  const entry = loginAttempts.get(key) || { startedAt: now, count: 0 };
  if (now - entry.startedAt > 15 * 60 * 1000) { entry.startedAt = now; entry.count = 0; }
  entry.count += 1; loginAttempts.set(key, entry);
  if (entry.count > 12) throw new HttpError(429, 'Too many attempts. Please wait a few minutes and try again.');
}
function clearLoginAttempts(request) { loginAttempts.delete(clientKey(request)); }

function validateBusinessData(data) {
  if (!data || typeof data !== 'object' || Array.isArray(data)) throw new HttpError(400, 'Business data is not valid.');
  const clean = {
    appointments: Array.isArray(data.appointments) ? data.appointments : [],
    messages: Array.isArray(data.messages) ? data.messages : [],
    payments: Array.isArray(data.payments) ? data.payments : []
  };
  if (clean.appointments.length > 10_000 || clean.messages.length > 20_000 || clean.payments.length > 20_000) throw new HttpError(413, 'There are too many records in this update.');
  if (Buffer.byteLength(JSON.stringify(clean), 'utf8') > 900_000) throw new HttpError(413, 'This update is too large.');
  return clean;
}

async function initializeDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS roadready_owners (
      id TEXT PRIMARY KEY,
      email TEXT NOT NULL UNIQUE,
      password_salt TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE UNIQUE INDEX IF NOT EXISTS roadready_single_owner_idx ON roadready_owners ((true));
    CREATE TABLE IF NOT EXISTS roadready_sessions (
      token_hash TEXT PRIMARY KEY,
      owner_id TEXT NOT NULL REFERENCES roadready_owners(id) ON DELETE CASCADE,
      expires_at TIMESTAMPTZ NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS roadready_sessions_expiry_idx ON roadready_sessions(expires_at);
    CREATE TABLE IF NOT EXISTS roadready_business_data (
      owner_id TEXT PRIMARY KEY REFERENCES roadready_owners(id) ON DELETE CASCADE,
      data JSONB NOT NULL DEFAULT '{"appointments":[],"messages":[],"payments":[]}'::jsonb,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
  `);
}

function sessionCookie(token) {
  return `roadready_session=${token}; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=${Math.floor(sessionDurationMs / 1000)}`;
}
function clearedSessionCookie() { return 'roadready_session=; Path=/; HttpOnly; Secure; SameSite=None; Max-Age=0'; }

async function createSession(ownerId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const expiry = new Date(Date.now() + sessionDurationMs);
  await pool.query('INSERT INTO roadready_sessions (token_hash, owner_id, expires_at) VALUES ($1, $2, $3)', [tokenHash, ownerId, expiry]);
  return token;
}

async function currentOwner(request) {
  const token = parseCookies(request).roadready_session;
  if (!token) return null;
  const tokenHash = crypto.createHash('sha256').update(token).digest('hex');
  const query = await pool.query(`
    SELECT owners.id, owners.email
    FROM roadready_sessions sessions
    JOIN roadready_owners owners ON owners.id = sessions.owner_id
    WHERE sessions.token_hash = $1 AND sessions.expires_at > NOW()
  `, [tokenHash]);
  return query.rows[0] || null;
}

async function requireOwner(request) {
  const owner = await currentOwner(request);
  if (!owner) throw new HttpError(401, 'Please sign in to RoadReady first.');
  return owner;
}

async function ownerExists() {
  const result = await pool.query('SELECT 1 FROM roadready_owners LIMIT 1');
  return result.rowCount > 0;
}

async function handleRequest(request, response) {
  const url = new URL(request.url, `http://${request.headers.host || 'localhost'}`);
  if (!requestOriginIsAllowed(request)) throw new HttpError(403, 'This API is available only to your RoadReady app.');
  if (request.method === 'OPTIONS') {
    if (!String(request.headers.origin || '')) throw new HttpError(403, 'Origin is required.');
    response.writeHead(204, { ...corsHeaders(request), 'Access-Control-Allow-Methods': 'GET, POST, PUT, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '600' });
    return response.end();
  }

  if (request.method === 'GET' && url.pathname === '/api/health') return writeJson(response, 200, { ok: true }, corsHeaders(request));

  if (request.method === 'GET' && url.pathname === '/api/auth/status') {
    const owner = await currentOwner(request);
    return writeJson(response, 200, { setupRequired: !(await ownerExists()), authenticated: Boolean(owner), email: owner?.email || '' }, corsHeaders(request));
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/setup') {
    requireWriteOrigin(request); allowLoginAttempt(request);
    if (await ownerExists()) throw new HttpError(409, 'RoadReady already has an owner account. Please sign in.');
    const input = await readJson(request);
    const email = String(input.email || '').trim().toLowerCase();
    const password = String(input.password || '');
    if (!sameText(input.setupCode, setupCode)) throw new HttpError(403, 'That setup code is not correct.');
    if (!/^\S+@\S+\.\S+$/.test(email) || password.length < 12) throw new HttpError(400, 'Use a valid email and a password with at least 12 characters.');
    const ownerId = crypto.randomUUID();
    const salt = crypto.randomBytes(16).toString('hex');
    await pool.query('INSERT INTO roadready_owners (id, email, password_salt, password_hash) VALUES ($1, $2, $3, $4)', [ownerId, email, salt, hashPassword(password, salt)]);
    await pool.query('INSERT INTO roadready_business_data (owner_id, data) VALUES ($1, $2::jsonb)', [ownerId, JSON.stringify(blankBusinessData)]);
    const token = await createSession(ownerId); clearLoginAttempts(request);
    return writeJson(response, 200, { email }, { ...corsHeaders(request), 'Set-Cookie': sessionCookie(token) });
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/login') {
    requireWriteOrigin(request); allowLoginAttempt(request);
    const input = await readJson(request);
    const email = String(input.email || '').trim().toLowerCase();
    const result = await pool.query('SELECT id, email, password_salt, password_hash FROM roadready_owners WHERE email = $1', [email]);
    const owner = result.rows[0];
    if (!owner || !sameText(hashPassword(String(input.password || ''), owner.password_salt), owner.password_hash)) throw new HttpError(401, 'Email or password is not correct.');
    const token = await createSession(owner.id); clearLoginAttempts(request);
    return writeJson(response, 200, { email: owner.email }, { ...corsHeaders(request), 'Set-Cookie': sessionCookie(token) });
  }

  if (request.method === 'POST' && url.pathname === '/api/auth/logout') {
    requireWriteOrigin(request);
    const token = parseCookies(request).roadready_session;
    if (token) await pool.query('DELETE FROM roadready_sessions WHERE token_hash = $1', [crypto.createHash('sha256').update(token).digest('hex')]);
    return writeJson(response, 200, { ok: true }, { ...corsHeaders(request), 'Set-Cookie': clearedSessionCookie() });
  }

  if (request.method === 'GET' && url.pathname === '/api/business-data') {
    const owner = await requireOwner(request);
    const result = await pool.query('SELECT data, updated_at FROM roadready_business_data WHERE owner_id = $1', [owner.id]);
    return writeJson(response, 200, { data: result.rows[0]?.data || blankBusinessData, updatedAt: result.rows[0]?.updated_at || null }, corsHeaders(request));
  }

  if (request.method === 'PUT' && url.pathname === '/api/business-data') {
    requireWriteOrigin(request);
    const owner = await requireOwner(request);
    const input = await readJson(request);
    const data = validateBusinessData(input.data);
    await pool.query(`
      INSERT INTO roadready_business_data (owner_id, data, updated_at) VALUES ($1, $2::jsonb, NOW())
      ON CONFLICT (owner_id) DO UPDATE SET data = EXCLUDED.data, updated_at = NOW()
    `, [owner.id, JSON.stringify(data)]);
    return writeJson(response, 200, { ok: true }, corsHeaders(request));
  }

  throw new HttpError(404, 'Not found.');
}

const server = http.createServer(async (request, response) => {
  try { await handleRequest(request, response); }
  catch (error) {
    if (!(error instanceof HttpError)) console.error('RoadReady API error:', error.message);
    writeJson(response, error.status || 500, { error: error instanceof HttpError ? error.message : 'RoadReady could not complete that request. Please try again.' }, corsHeaders(request));
  }
});

initializeDatabase().then(() => {
  server.listen(port, '0.0.0.0', () => console.log(`RoadReady cloud API is listening on ${port}.`));
}).catch(error => {
  console.error('RoadReady database setup failed:', error.message);
  process.exit(1);
});
