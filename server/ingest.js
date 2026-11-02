const crypto = require('crypto');
const db = require('./db');
const { MAX_EVENTS_PER_ISSUE } = require('./config');

const LEVELS = new Set(['fatal', 'error', 'warning', 'info', 'debug']);

// Parses V8 ("at fn (file:line:col)") and Firefox/Safari ("fn@file:line:col") stacks.
function parseStack(stack) {
  if (!stack || typeof stack !== 'string') return [];
  const frames = [];
  for (const raw of stack.split('\n')) {
    const line = raw.trim();
    let m = line.match(/^at (?:(.*?) \()?(.*?):(\d+):(\d+)\)?$/);
    if (m) {
      frames.push({ function: m[1] || '<anonymous>', file: m[2], line: +m[3], col: +m[4] });
      continue;
    }
    m = line.match(/^(.*?)@(.*?):(\d+):(\d+)$/);
    if (m) frames.push({ function: m[1] || '<anonymous>', file: m[2], line: +m[3], col: +m[4] });
  }
  return frames;
}

const isInternal = (f) => /node_modules|^node:|\(native\)|icrash/.test(f.file);

function fingerprintOf(ev, frames) {
  if (Array.isArray(ev.fingerprint) && ev.fingerprint.length) return ev.fingerprint.join('|');
  // Group by throw site only: caller frames vary with async boundaries and would split one bug into many issues.
  const app = frames.filter((f) => !isInternal(f)).slice(0, 1);
  const top = app.length ? app : frames.slice(0, 1);
  const basis = top.length
    ? top.map((f) => `${f.file.replace(/[?#].*$/, '')}:${f.function}`).join('>')
    : String(ev.message || '').replace(/\d+/g, 'N').replace(/[0-9a-f]{8,}/gi, 'H');
  return `${ev.type || 'Error'}|${basis}`;
}

function clip(v, n) {
  return typeof v === 'string' && v.length > n ? v.slice(0, n) : v;
}

function normalizeHttp(h) {
  if (!h || typeof h !== 'object') return null;
  const s = (v, n) => (v == null || v === '' ? undefined : clip(String(v), n));
  const status = Number(h.status);
  const out = {
    method: s(h.method, 12),
    url: s(String(h.url ?? '').split('?')[0], 500),
    path: s(String(h.path ?? '').split('?')[0], 300), // query strings are dropped: they often carry tokens
    status: Number.isFinite(status) && status > 0 ? status : undefined,
  };
  return out.method || out.url || out.path || out.status ? out : null;
}

const lineArr = (a) => (Array.isArray(a) ? a.slice(0, 12).map((l) => clip(String(l), 300)) : undefined);
function cleanFrame(f) {
  const file = String(f?.file ?? '');
  return {
    function: clip(String(f?.function || '<anonymous>'), 200),
    file: clip(file, 500),
    line: Number(f?.line) || 0,
    col: Number(f?.col) || 0,
    in_app: !isInternal({ file }),
    context_line: f?.context_line != null ? clip(String(f.context_line), 300) : undefined,
    pre_context: lineArr(f?.pre_context),
    post_context: lineArr(f?.post_context),
    context_start: Number(f?.context_start) || undefined,
  };
}
function cleanCrumb(c) {
  const data = c?.data && JSON.stringify(c.data).length <= 4000 ? c.data : undefined;
  return { timestamp: Number(c?.timestamp) || Date.now(), category: clip(String(c?.category || ''), 40), level: clip(String(c?.level || ''), 16), message: clip(String(c?.message ?? ''), 600), data };
}

function normalize(body) {
  const ev = body && typeof body === 'object' ? body : {};
  const level = LEVELS.has(ev.level) ? ev.level : 'error';
  const frames = Array.isArray(ev.frames) ? ev.frames : parseStack(ev.stack);
  const type = clip(ev.type || (ev.stack ? 'Error' : 'Message'), 200);
  const message = clip(String(ev.message ?? ''), 2000);
  const top = frames.find((f) => !isInternal(f)) || frames[0];
  return {
    level,
    type,
    message,
    frames: frames.slice(0, 100).map(cleanFrame),
    stack: clip(typeof ev.stack === 'string' ? ev.stack : null, 10000),
    mechanism: clip(String(ev.mechanism || 'generic'), 32),
    culprit: top ? `${top.function} (${String(top.file).split('/').pop()}:${top.line})` : ev.culprit || null,
    fingerprint: fingerprintOf({ ...ev, type, message }, frames),
    environment: clip(ev.environment || 'production', 64),
    release: clip(ev.release || null, 128),
    platform: ev.platform === 'node' ? 'node' : ev.platform || 'javascript',
    user: ev.user && typeof ev.user === 'object' ? ev.user : null,
    tags: ev.tags && typeof ev.tags === 'object' ? ev.tags : {},
    extra: ev.extra ?? null,
    request: ev.request ?? null,
    breadcrumbs: Array.isArray(ev.breadcrumbs) ? ev.breadcrumbs.slice(-50).map(cleanCrumb) : [],
    runtime: ev.runtime ?? null,
    code: clip(ev.code ? String(ev.code) : null, 64),
    http: normalizeHttp(ev.http),
    handled: ev.handled !== false,
    sdk: ev.sdk ?? null,
  };
}

async function ingest(projectId, body) {
  const e = normalize(body);
  const ts = Number.isFinite(body?.timestamp) ? Math.floor(body.timestamp) : Date.now();
  const title = clip(e.message ? `${e.type}: ${e.message}` : e.type, 300);
  const userKey = e.user ? String(e.user.id ?? e.user.email ?? e.user.ip_address ?? '') || null : null;

  return db.tx(async (c) => {
    const prev = await c.query('SELECT status FROM issues WHERE project_id = $1 AND fingerprint = $2', [projectId, e.fingerprint]);
    // Atomic upsert: a resolved issue reopens when it happens again.
    const { rows: [issue] } = await c.query(
      `INSERT INTO issues (project_id, fingerprint, type, title, culprit, level, first_seen, last_seen, count, last_release, last_env)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$7,1,$8,$9)
       ON CONFLICT (project_id, fingerprint) DO UPDATE SET
         count = issues.count + 1,
         first_seen = LEAST(issues.first_seen, EXCLUDED.first_seen),
         last_seen = GREATEST(issues.last_seen, EXCLUDED.last_seen),
         level = EXCLUDED.level, last_release = EXCLUDED.last_release, last_env = EXCLUDED.last_env,
         status = CASE WHEN issues.status = 'resolved' THEN 'unresolved' ELSE issues.status END
       RETURNING id, (xmax = 0) AS is_new`,
      [projectId, e.fingerprint, e.type, title, e.culprit, e.level, ts, e.release, e.environment]);
    if (userKey) {
      const seen = await c.query('SELECT 1 FROM events WHERE issue_id = $1 AND user_key = $2 LIMIT 1', [issue.id, userKey]);
      if (!seen.rowCount) await c.query('UPDATE issues SET users = users + 1 WHERE id = $1', [issue.id]);
    }
    const { rows: [ev] } = await c.query(
      `INSERT INTO events (issue_id, project_id, ts, environment, release, user_key, payload)
       VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
      [issue.id, projectId, ts, e.environment, e.release, userKey, JSON.stringify(e)]);
    await c.query(
      `DELETE FROM events WHERE issue_id = $1 AND id NOT IN
         (SELECT id FROM events WHERE issue_id = $1 ORDER BY id DESC LIMIT $2)`, [issue.id, MAX_EVENTS_PER_ISSUE]);
    return {
      id: ev.id, issueId: issue.id, isNew: issue.is_new, regressed: prev.rows[0]?.status === 'resolved',
      title, culprit: e.culprit, level: e.level, environment: e.environment, release: e.release, code: e.code, http: e.http,
    };
  });
}

const newKey = () => crypto.randomBytes(16).toString('hex');

module.exports = { ingest, parseStack, newKey };
