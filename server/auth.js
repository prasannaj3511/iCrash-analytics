const crypto = require('crypto');
const db = require('./db');
const { SESSION_DAYS } = require('./config');

const COOKIE = 'icrash_sid';
const DAY = 86400000;

/* ---- passwords: scrypt, format scrypt$N$salt$hash ---- */
const N = 16384;
function scrypt(pw, salt) {
  return new Promise((res, rej) => crypto.scrypt(pw, salt, 64, { N, r: 8, p: 1 }, (e, k) => (e ? rej(e) : res(k))));
}
async function hashPassword(pw) {
  const salt = crypto.randomBytes(16);
  return `scrypt$${N}$${salt.toString('hex')}$${(await scrypt(pw, salt)).toString('hex')}`;
}
async function verifyPassword(pw, stored) {
  const [alg, , saltHex, hashHex] = String(stored || '').split('$');
  if (alg !== 'scrypt') return false;
  const want = Buffer.from(hashHex, 'hex');
  const got = await scrypt(pw, Buffer.from(saltHex, 'hex'));
  return want.length === got.length && crypto.timingSafeEqual(want, got);
}
let dummyHash;
async function burnTime(pw) { // equalise timing for unknown emails
  dummyHash ||= await hashPassword('x');
  await verifyPassword(pw, dummyHash);
}

function validatePassword(pw) {
  if (typeof pw !== 'string' || pw.length < 8) return 'Password must be at least 8 characters';
  if (pw.length > 200) return 'Password is too long';
  return null;
}

/* ---- sessions ---- */
const sha = (t) => crypto.createHash('sha256').update(t).digest('hex');

async function createSession(userId) {
  const token = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();
  await db.query('INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES ($1,$2,$3,$4)',
    [sha(token), userId, now, now + SESSION_DAYS * DAY]);
  await db.query('UPDATE users SET last_login_at = $1 WHERE id = $2', [now, userId]);
  return token;
}

function parseCookies(req) {
  const out = {};
  for (const part of (req.headers.cookie || '').split(';')) {
    const i = part.indexOf('=');
    if (i > 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

async function userFromRequest(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token) return null;
  return db.one(
    `SELECT u.id, u.email, u.name, u.role FROM sessions s JOIN users u ON u.id = s.user_id
     WHERE s.token_hash = $1 AND s.expires_at > $2 AND u.active`, [sha(token), Date.now()]);
}

const currentTokenHash = (req) => sha(parseCookies(req)[COOKIE] || '');

const destroySession =(req) => {
  const token = parseCookies(req)[COOKIE];
  return token ? db.query('DELETE FROM sessions WHERE token_hash = $1', [sha(token)]) : null;
};

function cookieHeader(req, token, maxAgeSec) {
  const secure = require('./config').COOKIE_SECURE || req.headers['x-forwarded-proto'] === 'https';
  return `${COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}${secure ? '; Secure' : ''}`;
}

/* ---- login throttling (in-memory, per ip+email) ---- */
const fails = new Map();
const WINDOW = 15 * 60000, MAX_FAILS = 8;
function throttled(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.first > WINDOW) { fails.delete(key); return false; }
  return f.n >= MAX_FAILS;
}
function recordFail(key) {
  const f = fails.get(key);
  if (!f || Date.now() - f.first > WINDOW) fails.set(key, { n: 1, first: Date.now() });
  else f.n++;
  if (fails.size > 5000) fails.clear();
}
const clearFails = (key) => fails.delete(key);

module.exports = { currentTokenHash, hashPassword, verifyPassword, burnTime, validatePassword, createSession, userFromRequest, destroySession, cookieHeader, throttled, recordFail, clearFails, COOKIE };
