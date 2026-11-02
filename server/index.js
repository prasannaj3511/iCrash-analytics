const http = require('http');
const fs = require('fs');
const path = require('path');
const cfg = require('./config');
const db = require('./db');
const auth = require('./auth');
const { ingest, newKey } = require('./ingest');
const mailer = require('./mailer');

const MAX_BODY = 512 * 1024;
const ROOT = path.join(__dirname, '..');
const DAY = 86400000;
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css', '.svg': 'image/svg+xml', '.json': 'application/json' };
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const httpError = (status, message) => Object.assign(new Error(message), { status });

function send(res, status, body, headers = {}) {
  const isObj = body !== null && typeof body === 'object';
  res.writeHead(status, { 'content-type': isObj ? 'application/json' : 'text/plain', 'cache-control': 'no-store', ...headers });
  res.end(isObj ? JSON.stringify(body) : body ?? '');
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(httpError(413, 'payload too large')); req.destroy(); } else chunks.push(c);
    });
    req.on('end', () => {
      if (!chunks.length) return resolve({});
      try { resolve(JSON.parse(Buffer.concat(chunks).toString('utf8'))); } catch { reject(httpError(400, 'invalid JSON')); }
    });
    req.on('error', reject);
  });
}

const publicUser = (u) => ({ id: u.id, email: u.email, name: u.name, role: u.role });
const isAdmin = (u) => u.role === 'superadmin';
const pid = (x) => Number(x);
const str = (v, max) => String(v ?? '').trim().slice(0, max);

/* A user may touch a project if they own it; the super admin may touch all of them. */
async function loadProject(id, user) {
  const p = await db.one(
    `SELECT p.*, u.email AS owner_email,
       EXISTS (SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = $2) AS is_member
     FROM projects p JOIN users u ON u.id = p.owner_id WHERE p.id = $1`, [id, user.id]);
  const access = !p ? null : p.owner_id === user.id ? 'owner' : p.is_member ? 'member' : isAdmin(user) ? 'admin' : null;
  if (!access) throw httpError(404, 'not found'); // never reveal that a project exists
  p.access = access;
  return p;
}
/** Members can view and triage; owner and super admin also manage keys, team, alerts and deletion. */
const requireManage = (p) => { if (p.access === 'member') throw httpError(403, 'Only the project owner can do this'); };
async function loadIssue(id, user) {
  const i = await db.one('SELECT * FROM issues WHERE id = $1', [id]);
  if (!i) throw httpError(404, 'not found');
  i.access = (await loadProject(i.project_id, user)).access;
  return i;
}
const projectRow = (p) => ({
  id: p.id, name: p.name, platform: p.platform, created_at: p.created_at, public_key: p.public_key,
  owner_id: p.owner_id, owner_email: p.owner_email, access: p.access,
  ...(p.open_issues !== undefined ? { open_issues: p.open_issues, events_24h: p.events_24h } : {}),
});

async function series(table, col, id, days) {
  const bucketMs = days <= 1 ? 3600000 : DAY;
  const buckets = days <= 1 ? 24 : days;
  const end = Math.ceil(Date.now() / bucketMs) * bucketMs;
  const start = end - buckets * bucketMs;
  const out = Array.from({ length: buckets }, (_, i) => ({ t: start + i * bucketMs, n: 0 }));
  const rows = await db.all(
    `SELECT ((ts - $1::bigint) / $2::bigint) AS bucket, COUNT(*) AS n FROM ${table}
     WHERE ${col} = $3 AND ts >= $1::bigint GROUP BY bucket`, [start, bucketMs, id]);
  for (const r of rows) if (out[r.bucket]) out[r.bucket].n = r.n;
  return out;
}

/* ---------------- ingest (public, key-authenticated) ---------------- */
async function handleIngest(req, res, url) {
  const m = url.pathname.match(/^\/api\/(\d+)\/(?:ingest|store)\/?$/);
  const cors = {
    'access-control-allow-origin': '*',
    'access-control-allow-headers': 'content-type, x-icrash-key',
    'access-control-allow-methods': 'POST, OPTIONS',
    'access-control-max-age': '86400',
  };
  if (req.method === 'OPTIONS') return send(res, 204, '', cors);
  if (req.method !== 'POST') return send(res, 405, { error: 'method not allowed' }, cors);
  const key = req.headers['x-icrash-key'] || url.searchParams.get('key');
  const project = key && (await db.one('SELECT p.id, p.name, u.email AS owner_email, ARRAY(SELECT r.email FROM project_recipients r WHERE r.project_id = p.id UNION SELECT mu.email FROM project_members pm JOIN users mu ON mu.id = pm.user_id WHERE pm.project_id = p.id AND mu.active) AS recipients FROM projects p JOIN users u ON u.id = p.owner_id WHERE p.public_key = $1', [String(key)]));
  if (!project || project.id !== Number(m[1])) return send(res, 401, { error: 'invalid project key' }, cors);
  const body = await readBody(req);
  if (body.user && typeof body.user === 'object' && !body.user.ip_address && req.socket.remoteAddress) body.user.ip_address = req.socket.remoteAddress;
  const r = await ingest(project.id, body);
  send(res, 200, { id: r.id, issue_id: r.issueId }, cors);
  mailer.maybeAlert(project, r).catch((e) => console.error('alert failed:', e.message));
}

/* ---------------- auth ---------------- */
async function handleAuth(req, res, url) {
  const p = url.pathname;
  if (p === '/api/auth/login' && req.method === 'POST') {
    const b = await readBody(req);
    const email = str(b.email, 200).toLowerCase();
    const key = `${req.socket.remoteAddress}|${email}`;
    if (auth.throttled(key)) throw httpError(429, 'Too many failed attempts. Try again in a few minutes.');
    const u = await db.one('SELECT * FROM users WHERE lower(email) = $1', [email]);
    const ok = u && u.active ? await auth.verifyPassword(String(b.password || ''), u.password_hash) : (await auth.burnTime(String(b.password || '')), false);
    if (!ok) { auth.recordFail(key); throw httpError(401, 'Invalid email or password'); }
    auth.clearFails(key);
    const token = await auth.createSession(u.id);
    return send(res, 200, { user: publicUser(u) }, { 'set-cookie': auth.cookieHeader(req, token, cfg.SESSION_DAYS * 86400) });
  }
  if (p === '/api/auth/logout' && req.method === 'POST') {
    await auth.destroySession(req);
    return send(res, 200, { ok: true }, { 'set-cookie': auth.cookieHeader(req, '', 0) });
  }
  if (p === '/api/auth/me' && req.method === 'GET') {
    const user = await auth.userFromRequest(req);
    return user ? send(res, 200, { user: publicUser(user) }) : send(res, 401, { error: 'not signed in' });
  }
  throw httpError(404, 'not found');
}

/* ---------------- authenticated API ---------------- */
async function handleApi(req, res, url, user) {
  const p = url.pathname;
  const method = req.method;
  let m;

  if (p === '/api/auth/change-password' && method === 'POST') {
    const b = await readBody(req);
    const row = await db.one('SELECT password_hash FROM users WHERE id = $1', [user.id]);
    if (!(await auth.verifyPassword(String(b.current || ''), row.password_hash))) throw httpError(400, 'Current password is incorrect');
    const bad = auth.validatePassword(b.next);
    if (bad) throw httpError(400, bad);
    await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await auth.hashPassword(b.next), user.id]);
    await db.query('DELETE FROM sessions WHERE user_id = $1 AND token_hash <> $2', [user.id, auth.currentTokenHash(req)]);
    return send(res, 200, { ok: true });
  }

  /* ---- user management (super admin only) ---- */
  if (p === '/api/users' || p.startsWith('/api/users/') || p === '/api/mail/status') {
    if (!isAdmin(user)) throw httpError(403, 'Only the super admin can manage users');
    if (p === '/api/mail/status') return send(res, 200, { configured: mailer.enabled(), ...(await mailer.verify()) });
    if (p === '/api/users' && method === 'GET') {
      return send(res, 200, await db.all(
        `SELECT u.id, u.email, u.name, u.role, u.active, u.created_at, u.last_login_at,
                (SELECT COUNT(*) FROM projects WHERE owner_id = u.id) AS projects
         FROM users u ORDER BY u.role DESC, lower(u.email)`));
    }
    if (p === '/api/users' && method === 'POST') {
      const b = await readBody(req);
      const email = str(b.email, 200).toLowerCase();
      if (!EMAIL_RE.test(email)) throw httpError(400, 'Enter a valid email address');
      const bad = auth.validatePassword(b.password);
      if (bad) throw httpError(400, bad);
      if (await db.one('SELECT 1 FROM users WHERE lower(email) = $1', [email])) throw httpError(409, 'A user with this email already exists');
      const u = await db.one(
        `INSERT INTO users (email, name, password_hash, role, created_by, created_at) VALUES ($1,$2,$3,'user',$4,$5)
         RETURNING id, email, name, role, active, created_at`,
        [email, str(b.name, 100) || email.split('@')[0], await auth.hashPassword(b.password), user.id, Date.now()]);
      const mail = await mailer.sendWelcome(u);
      return send(res, 201, { ...u, email_sent: mail.sent, email_error: mail.sent ? undefined : mail.reason });
    }
    if ((m = p.match(/^\/api\/users\/(\d+)$/))) {
      const id = pid(m[1]);
      const target = await db.one('SELECT * FROM users WHERE id = $1', [id]);
      if (!target) throw httpError(404, 'not found');
      if (method === 'PATCH') {
        const b = await readBody(req);
        let mail = null;
        if (target.id === user.id && b.active === false) throw httpError(400, "You can't deactivate your own account");
        if (typeof b.name === 'string') await db.query('UPDATE users SET name = $1 WHERE id = $2', [str(b.name, 100), id]);
        if (typeof b.active === 'boolean') {
          await db.query('UPDATE users SET active = $1 WHERE id = $2', [b.active, id]);
          if (!b.active) await db.query('DELETE FROM sessions WHERE user_id = $1', [id]);
        }
        if (b.password !== undefined) {
          const bad = auth.validatePassword(b.password);
          if (bad) throw httpError(400, bad);
          await db.query('UPDATE users SET password_hash = $1 WHERE id = $2', [await auth.hashPassword(b.password), id]);
          await db.query('DELETE FROM sessions WHERE user_id = $1', [id]);
          mail = await mailer.sendPasswordReset(target);
        }
        const out = await db.one('SELECT id, email, name, role, active, created_at, last_login_at FROM users WHERE id = $1', [id]);
        return send(res, 200, mail ? { ...out, email_sent: mail.sent, email_error: mail.sent ? undefined : mail.reason } : out);
      }
      if (method === 'DELETE') {
        if (target.id === user.id) throw httpError(400, "You can't delete your own account");
        if (target.role === 'superadmin') throw httpError(400, "The super admin account can't be deleted");
        await db.query('DELETE FROM users WHERE id = $1', [id]); // cascades to projects, issues, events, sessions
        return send(res, 200, { ok: true });
      }
    }
    throw httpError(404, 'not found');
  }

  /* ---- projects ---- */
  if (p === '/api/projects' && method === 'GET') {
    const rows = await db.all(
      `SELECT p.*, u.email AS owner_email,
         CASE WHEN p.owner_id = $3 THEN 'owner'
              WHEN EXISTS (SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = $3) THEN 'member'
              ELSE 'admin' END AS access,
         (SELECT COUNT(*) FROM issues i WHERE i.project_id = p.id AND i.status = 'unresolved') AS open_issues,
         (SELECT COUNT(*) FROM events e WHERE e.project_id = p.id AND e.ts > $1) AS events_24h
       FROM projects p JOIN users u ON u.id = p.owner_id
       WHERE ($2::boolean OR p.owner_id = $3
              OR EXISTS (SELECT 1 FROM project_members m WHERE m.project_id = p.id AND m.user_id = $3))
       ORDER BY lower(p.name), p.id`,
      [Date.now() - DAY, isAdmin(user), user.id]);
    return send(res, 200, rows.map(projectRow));
  }
  if (p === '/api/projects' && method === 'POST') {
    const b = await readBody(req);
    const name = str(b.name, 80);
    if (!name) throw httpError(400, 'name is required');
    const platform = ['javascript', 'node', 'other'].includes(b.platform) ? b.platform : 'javascript';
    const created = await db.one(
      'INSERT INTO projects (owner_id, name, platform, public_key, created_at) VALUES ($1,$2,$3,$4,$5) RETURNING id',
      [user.id, name, platform, newKey(), Date.now()]);
    return send(res, 201, projectRow(await loadProject(created.id, user)));
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)$/))) {
    const proj = await loadProject(pid(m[1]), user);
    if (method === 'GET') return send(res, 200, projectRow(proj));
    if (method === 'DELETE') { requireManage(proj); await db.query('DELETE FROM projects WHERE id = $1', [proj.id]); return send(res, 200, { ok: true }); }
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/rotate-key$/)) && method === 'POST') {
    const proj = await loadProject(pid(m[1]), user);
    requireManage(proj);
    await db.query('UPDATE projects SET public_key = $1 WHERE id = $2', [newKey(), proj.id]);
    return send(res, 200, projectRow(await loadProject(proj.id, user)));
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/member-candidates$/)) && method === 'GET') {
    const proj = await loadProject(pid(m[1]), user);
    requireManage(proj); // lists other users' names/emails, so only people who can manage the team see it
    return send(res, 200, await db.all(
      `SELECT u.id, u.email, u.name FROM users u
       WHERE u.active AND u.id <> $2
         AND NOT EXISTS (SELECT 1 FROM project_members pm WHERE pm.project_id = $1 AND pm.user_id = u.id)
       ORDER BY lower(u.name), lower(u.email)`, [proj.id, proj.owner_id]));
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/members(?:\/(\d+))?$/))) {
    const proj = await loadProject(pid(m[1]), user);
    if (method === 'GET' && !m[2]) {
      const [owner, members] = await Promise.all([
        db.one('SELECT id, email, name FROM users WHERE id = $1', [proj.owner_id]),
        db.all('SELECT u.id AS user_id, u.email, u.name, m.created_at FROM project_members m JOIN users u ON u.id = m.user_id WHERE m.project_id = $1 ORDER BY m.created_at', [proj.id]),
      ]);
      return send(res, 200, { owner, members, access: proj.access });
    }
    if (method === 'POST' && !m[2]) {
      requireManage(proj);
      const b = await readBody(req);
      const email = str(b.email, 200).toLowerCase();
      const target = await db.one('SELECT id, email, name FROM users WHERE lower(email) = $1 AND active', [email]);
      if (!target) throw httpError(404, 'No active user with that email. Ask the super admin to create the account first.');
      if (target.id === proj.owner_id) throw httpError(409, 'That user already owns this project');
      const row = await db.one(
        'INSERT INTO project_members (project_id, user_id, added_by, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING user_id',
        [proj.id, target.id, user.id, Date.now()]);
      if (!row) throw httpError(409, 'That user is already on this project');
      mailer.sendAddedToProject(target, proj, user).catch((e) => console.error('mail failed:', e.message));
      return send(res, 201, { user_id: target.id, email: target.email, name: target.name });
    }
    if (method === 'DELETE' && m[2]) {
      if (pid(m[2]) !== user.id) requireManage(proj); // members may remove only themselves (leave)
      await db.query('DELETE FROM project_members WHERE project_id = $1 AND user_id = $2', [proj.id, pid(m[2])]);
      return send(res, 200, { ok: true });
    }
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/recipients(?:\/(\d+))?$/))) {
    const proj = await loadProject(pid(m[1]), user);
    if (method === 'GET' && !m[2]) {
      return send(res, 200, { owner: proj.owner_email, recipients: await db.all('SELECT id, email, created_at FROM project_recipients WHERE project_id = $1 ORDER BY id', [proj.id]) });
    }
    if (method === 'POST' && !m[2]) {
      requireManage(proj);
      const b = await readBody(req);
      const email = str(b.email, 200).toLowerCase();
      if (!EMAIL_RE.test(email)) throw httpError(400, 'Enter a valid email address');
      if (email === String(proj.owner_email).toLowerCase()) throw httpError(409, 'The project owner already receives alerts');
      const { n } = await db.one('SELECT COUNT(*) AS n FROM project_recipients WHERE project_id = $1', [proj.id]);
      if (n >= 20) throw httpError(400, 'You can add up to 20 recipients per project');
      const row = await db.one(
        'INSERT INTO project_recipients (project_id, email, created_by, created_at) VALUES ($1,$2,$3,$4) ON CONFLICT DO NOTHING RETURNING id, email, created_at',
        [proj.id, email, user.id, Date.now()]);
      if (!row) throw httpError(409, 'That email is already on the list');
      return send(res, 201, row);
    }
    if (method === 'DELETE' && m[2]) {
      requireManage(proj);
      await db.query('DELETE FROM project_recipients WHERE id = $1 AND project_id = $2', [pid(m[2]), proj.id]);
      return send(res, 200, { ok: true });
    }
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/issues$/)) && method === 'GET') {
    const proj = await loadProject(pid(m[1]), user);
    const where = ['project_id = $1'];
    const args = [proj.id];
    const add = (sql, v) => { args.push(v); where.push(sql.replace('?', `$${args.length}`)); };
    const status = url.searchParams.get('status');
    if (status && status !== 'all') add('status = ?', status);
    if (url.searchParams.get('level')) add('level = ?', url.searchParams.get('level'));
    if (url.searchParams.get('environment')) add('last_env = ?', url.searchParams.get('environment'));
    const search = url.searchParams.get('q');
    if (search) {
      const like = `%${search.replace(/[\\%_]/g, '\\$&')}%`;
      args.push(like);
      where.push(`(title ILIKE $${args.length} OR culprit ILIKE $${args.length})`);
    }
    const sort = { last_seen: 'last_seen', first_seen: 'first_seen', count: 'count', users: 'users' }[url.searchParams.get('sort')] || 'last_seen';
    return send(res, 200, await db.all(`SELECT * FROM issues WHERE ${where.join(' AND ')} ORDER BY ${sort} DESC, id DESC LIMIT 200`, args));
  }
  if ((m = p.match(/^\/api\/projects\/(\d+)\/stats$/)) && method === 'GET') {
    const proj = await loadProject(pid(m[1]), user);
    const days = Math.min(Math.max(Number(url.searchParams.get('days')) || 14, 1), 90);
    const bucketMs = days <= 1 ? 3600000 : DAY; // same window as the chart buckets
    const since = Math.ceil(Date.now() / bucketMs) * bucketMs - (days <= 1 ? 24 : days) * bucketMs;
    const [ser, totals, newIssues, environments, releases] = await Promise.all([
      series('events', 'project_id', proj.id, days),
      db.one('SELECT COUNT(*) AS n, COUNT(DISTINCT user_key) AS users FROM events WHERE project_id = $1 AND ts >= $2', [proj.id, since]),
      db.one('SELECT COUNT(*) AS n FROM issues WHERE project_id = $1 AND first_seen >= $2', [proj.id, since]),
      db.all('SELECT environment AS k, COUNT(*) AS n FROM events WHERE project_id = $1 AND ts >= $2 GROUP BY k ORDER BY n DESC LIMIT 5', [proj.id, since]),
      db.all('SELECT release AS k, COUNT(*) AS n FROM events WHERE project_id = $1 AND ts >= $2 AND release IS NOT NULL GROUP BY k ORDER BY n DESC LIMIT 5', [proj.id, since]),
    ]);
    return send(res, 200, { days, series: ser, totals: { ...totals, new_issues: newIssues.n }, environments, releases });
  }

  /* ---- issues ---- */
  if ((m = p.match(/^\/api\/issues\/(\d+)$/))) {
    const issue = await loadIssue(pid(m[1]), user);
    if (method === 'GET') {
      const [events, ser] = await Promise.all([
        db.all('SELECT id, ts, environment, release, payload FROM events WHERE issue_id = $1 ORDER BY id DESC LIMIT 25', [issue.id]),
        series('events', 'issue_id', issue.id, 14),
      ]);
      return send(res, 200, { issue, events: events.map((r) => ({ id: r.id, ts: r.ts, environment: r.environment, release: r.release, ...r.payload })), series: ser });
    }
    if (method === 'PATCH') {
      const b = await readBody(req);
      if (!['unresolved', 'resolved', 'ignored'].includes(b.status)) throw httpError(400, 'invalid status');
      return send(res, 200, await db.one('UPDATE issues SET status = $1 WHERE id = $2 RETURNING *', [b.status, issue.id]));
    }
    if (method === 'DELETE') {
      if (issue.access === 'member') throw httpError(403, 'Only the project owner can delete issues');
      await db.query('DELETE FROM issues WHERE id = $1', [issue.id]); return send(res, 200, { ok: true });
    }
  }
  throw httpError(404, 'not found');
}

/* The Node SDK as an installable tarball (`npm i https://<host>/sdk/icrash-node.tgz`), built once from sdk/node.
   Deterministic (fixed mtimes) so npm's lockfile integrity hash stays stable between restarts. */
let sdkTgz;
function nodeSdkTarball() {
  if (sdkTgz) return sdkTgz;
  const dir = path.join(ROOT, 'sdk', 'node');
  const blocks = [];
  for (const name of ['package.json', 'index.js']) {
    const data = fs.readFileSync(path.join(dir, name));
    const h = Buffer.alloc(512);
    h.write(`package/${name}`, 0, 100); h.write('0000644\0', 100); h.write('0000000\0', 108); h.write('0000000\0', 116);
    h.write(data.length.toString(8).padStart(11, '0') + '\0', 124); h.write('00000000000\0', 136);
    h.write('        ', 148); h.write('0', 156); h.write('ustar\0' + '00', 257);
    h.write(h.reduce((a, b) => a + b, 0).toString(8).padStart(6, '0') + '\0 ', 148);
    blocks.push(h, data, Buffer.alloc((512 - (data.length % 512)) % 512));
  }
  blocks.push(Buffer.alloc(1024));
  return (sdkTgz = require('zlib').gzipSync(Buffer.concat(blocks), { level: 9 }));
}

function serveStatic(req, res, url) {
  if (url.pathname === '/sdk/icrash-node.tgz') {
    const tgz = nodeSdkTarball();
    res.writeHead(200, { 'content-type': 'application/gzip', 'content-length': tgz.length, 'cache-control': 'public, max-age=300' });
    return res.end(tgz);
  }
  const rel = decodeURIComponent(url.pathname);
  const sdk = path.join(ROOT, 'sdk', 'browser', 'icrash.js');
  const uiDir = path.join(ROOT, 'ui') + path.sep;
  const file = rel === '/sdk/icrash.js' ? sdk : path.join(ROOT, 'ui', rel === '/' ? 'index.html' : rel);
  if (!(file === sdk || file.startsWith(uiDir)) || !fs.existsSync(file) || !fs.statSync(file).isFile()) return send(res, 404, 'not found');
  const headers = { 'content-type': MIME[path.extname(file)] || 'application/octet-stream' };
  if (file === sdk) headers['access-control-allow-origin'] = '*';
  res.writeHead(200, headers);
  fs.createReadStream(file).pipe(res);
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  try {
    if (/^\/api\/\d+\/(ingest|store)\/?$/.test(url.pathname)) return await handleIngest(req, res, url);
    if (url.pathname.startsWith('/api/')) {
      // CSRF: the dashboard always sends this header; cross-site forms cannot.
      if (req.method !== 'GET' && req.headers['x-icrash-csrf'] !== '1') throw httpError(403, 'missing csrf header');
      if (url.pathname.startsWith('/api/auth/') && !['/api/auth/change-password'].includes(url.pathname)) return await handleAuth(req, res, url);
      const user = await auth.userFromRequest(req);
      if (!user) return send(res, 401, { error: 'not signed in' });
      return await handleApi(req, res, url, user);
    }
    serveStatic(req, res, url);
  } catch (err) {
    if (!err.status) console.error(err);
    send(res, err.status || 500, { error: err.status ? err.message : 'internal error' });
  }
});

async function cleanup() {
  try {
    const cutoff = Date.now() - cfg.RETENTION_DAYS * DAY;
    await db.query('DELETE FROM events WHERE ts < $1', [cutoff]);
    await db.query('DELETE FROM issues WHERE last_seen < $1 AND NOT EXISTS (SELECT 1 FROM events WHERE issue_id = issues.id)', [cutoff]);
    await db.query('DELETE FROM sessions WHERE expires_at < $1', [Date.now()]);
  } catch (e) { console.error('cleanup failed:', e.message); }
}

async function main() {
  try {
    await db.one('SELECT 1 FROM users LIMIT 1');
  } catch (e) {
    console.error(`Database not ready (${e.message}).\nRun "npm run db:sync" first, and check the DB_* settings in .env.`);
    process.exit(1);
  }
  await cleanup();
  setInterval(cleanup, 6 * 3600000).unref();
  server.listen(cfg.PORT, cfg.HOST, () => console.log(`iCrash Analytics running on http://localhost:${cfg.PORT}`));
}
main();
