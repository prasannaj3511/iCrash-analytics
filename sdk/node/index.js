'use strict';
/**
 * iCrash Node SDK.
 *   const icrash = require('@icrash/node');
 *   icrash.init({ dsn: 'http://KEY@localhost:4100/1', environment: 'production', release: '1.2.3' });
 *   app.use(icrash.requestHandler());   // first
 *   ...routes...
 *   app.use(icrash.errorHandler());     // after routes, before your own error handler
 */
const os = require('os');
const fs = require('fs');
const path = require('path');
const util = require('util');
const { fileURLToPath } = require('url');
const { AsyncLocalStorage } = require('async_hooks');

let cfg = null;
const state = { user: null, tags: {}, extra: {}, pending: new Set(), sent: 0, lastSent: new Map() };
const MAX_PER_MIN = 60;
let windowStart = Date.now();

function parseDsn(dsn) {
  const m = /^(https?):\/\/([^@]+)@([^/]+)(\/.*?)?\/(\d+)\/?$/.exec(dsn || '');
  if (!m) throw new Error('iCrash: invalid DSN, expected http(s)://KEY@host[:port]/PROJECT_ID');
  return { endpoint: `${m[1]}://${m[3]}${m[4] || ''}/api/${m[5]}/ingest`, key: m[2] };
}

const SENSITIVE = /^(authorization|cookie|set-cookie|x-api-key|x-icrash-key)$/i;

function scrubHeaders(h = {}) {
  const out = {};
  for (const [k, v] of Object.entries(h)) out[k] = SENSITIVE.test(k) ? '[redacted]' : v;
  return out;
}

/* ---- breadcrumbs: per request when inside requestHandler(), otherwise a global ring ---- */
const als = new AsyncLocalStorage();
const globalCrumbs = [];
const MAX_CRUMBS = 50;
const clip = (s, n) => (typeof s === 'string' && s.length > n ? `${s.slice(0, n)}…` : s);
const SECRET_TEXT = /((?:authorization|bearer|token|password|passwd|secret|api[_-]?key)["']?\s*[:=]?\s*["']?)[^\s"',}&]{4,}/gi;
const scrubText = (s) => String(s).replace(SECRET_TEXT, '$1[redacted]');

function addBreadcrumb(c) {
  const list = als.getStore()?.crumbs || globalCrumbs;
  list.push({ timestamp: Date.now(), ...c });
  if (list.length > MAX_CRUMBS) list.shift();
}
const currentCrumbs = () => (als.getStore()?.crumbs || globalCrumbs).slice();

let consolePatched = false;
function patchConsole() {
  if (consolePatched) return;
  consolePatched = true;
  const levels = { log: 'info', info: 'info', debug: 'debug', warn: 'warning', error: 'error' };
  for (const [method, level] of Object.entries(levels)) {
    const orig = console[method];
    console[method] = function (...args) {
      try {
        const crumb = { category: 'console', level, message: clip(scrubText(util.format(...args)), 500) };
        if (args.length > 1 || args.some((a) => typeof a === 'object' && a !== null)) {
          crumb.data = { logger: 'console', arguments: args.slice(0, 5).map((a) => (typeof a === 'string' ? clip(scrubText(a), 300) : clip(scrubText(util.inspect(a, { depth: 2, breakLength: Infinity })), 500))) };
        }
        addBreadcrumb(crumb);
      } catch { /* never break logging */ }
      return orig.apply(this, args);
    };
  }
}

/* ---- stack frames with the source lines around each one ---- */
function parseFrames(stack) {
  const out = [];
  for (const raw of String(stack || '').split('\n')) {
    const m = /^\s*at (?:(.*?) \()?(.*?):(\d+):(\d+)\)?$/.exec(raw);
    if (!m) continue;
    let file = m[2];
    if (file.startsWith('file://')) { try { file = fileURLToPath(file); } catch { /* keep */ } }
    out.push({ function: (m[1] || '<anonymous>').replace(/^async /, ''), file, line: +m[3], col: +m[4] });
  }
  return out;
}

function addSourceContext(frames, around = 5, maxFrames = 10) {
  const cache = new Map();
  const cut = (s) => (s.length > 240 ? `${s.slice(0, 240)}…` : s);
  for (const f of frames.slice(0, maxFrames)) {
    if (!path.isAbsolute(f.file)) continue;
    let lines = cache.get(f.file);
    if (lines === undefined) {
      try { lines = fs.statSync(f.file).size <= 2e6 ? fs.readFileSync(f.file, 'utf8').split(/\r?\n/) : null; } catch { lines = null; }
      cache.set(f.file, lines);
    }
    if (!lines || f.line < 1 || f.line > lines.length) continue;
    f.context_start = Math.max(1, f.line - around);
    f.pre_context = lines.slice(f.context_start - 1, f.line - 1).map(cut);
    f.context_line = cut(lines[f.line - 1]);
    f.post_context = lines.slice(f.line, f.line + around).map(cut);
  }
  return frames;
}

function send(event) {
  if (!cfg) return Promise.resolve();
  const now = Date.now();
  if (now - windowStart > 60000) { windowStart = now; state.sent = 0; }
  if (state.sent >= MAX_PER_MIN) return Promise.resolve();
  const sig = event.type + event.message;
  if (now - (state.lastSent.get(sig) || 0) < 1000) return Promise.resolve();
  state.lastSent.set(sig, now);
  if (state.lastSent.size > 500) state.lastSent.clear();
  state.sent++;

  Object.assign(event, {
    timestamp: now,
    platform: 'node',
    environment: cfg.environment,
    release: cfg.release,
    user: event.user || state.user,
    tags: { ...state.tags, ...event.tags },
    extra: { ...state.extra, ...event.extra },
    breadcrumbs: event.breadcrumbs || currentCrumbs(),
    runtime: { name: 'node', version: process.version, os: `${os.type()} ${os.release()}`, host: os.hostname(), pid: process.pid },
    sdk: { name: 'icrash.node', version: '1.0.0' },
  });
  if (cfg.beforeSend) {
    try { event = cfg.beforeSend(event); } catch { /* ignore */ }
    if (!event) return Promise.resolve();
  }
  const p = fetch(cfg.endpoint, {
    method: 'POST',
    headers: { 'content-type': 'application/json', 'x-icrash-key': cfg.key },
    body: JSON.stringify(event),
    signal: AbortSignal.timeout(5000),
  }).catch(() => {}).finally(() => state.pending.delete(p));
  state.pending.add(p);
  return p;
}

// HTTP details from axios/got-style errors (outbound calls that failed).
function httpInfo(err) {
  if (!err || typeof err !== 'object') return undefined;
  const c = err.config || err.response?.config || {};
  const status = err.response?.status || err.response?.statusCode || err.status || err.statusCode;
  if (!c.url && !status) return undefined;
  let url = String(c.url || '');
  if (c.baseURL && !/^[a-z]+:\/\//i.test(url)) url = `${c.baseURL.replace(/\/$/, '')}/${url.replace(/^\//, '')}`;
  const path = url.replace(/^[a-z]+:\/\/[^/]+/i, '').split('?')[0];
  return { method: c.method ? String(c.method).toUpperCase() : undefined, url: url.split('?')[0], path: path || undefined, status };
}

function fromError(err, extra) {
  const isErr = err && typeof err === 'object' && (err.stack || err.message);
  return {
    type: isErr ? err.name || 'Error' : 'NonErrorThrown',
    message: isErr ? String(err.message) : String(err),
    stack: isErr ? err.stack : undefined,
    frames: isErr && err.stack && cfg?.sourceContext !== false ? addSourceContext(parseFrames(err.stack)) : undefined,
    code: isErr && err.code ? String(err.code) : undefined,
    http: httpInfo(err),
    ...extra,
  };
}

function captureException(err, ctx = {}) {
  return send(fromError(err, { level: ctx.level || 'error', tags: ctx.tags, extra: ctx.extra, user: ctx.user, request: ctx.request, handled: ctx.handled !== false, mechanism: ctx.mechanism || 'generic', breadcrumbs: ctx.breadcrumbs, ...(ctx.fingerprint && { fingerprint: ctx.fingerprint }), ...(ctx.http && { http: ctx.http }) }));
}

function captureMessage(message, level = 'info', ctx = {}) {
  return send({ type: 'Message', message: String(message), level, tags: ctx.tags, extra: ctx.extra, user: ctx.user, mechanism: 'message' });
}

/** Wait for in-flight events (call before process exit / in serverless handlers). */
async function flush(timeoutMs = 2000) {
  await Promise.race([Promise.allSettled([...state.pending]), new Promise((r) => setTimeout(r, timeoutMs))]);
}

const SENSITIVE_PARAM = /([?&;](?:[^=&#]*(?:token|key|password|passwd|secret|auth|session|signature|code)[^=&#]*)=)[^&#]*/gi;
const maskUrl = (u) => String(u).replace(SENSITIVE_PARAM, '$1[redacted]');
const maskQuery = (q) => {
  if (!q || typeof q !== 'object') return q;
  const out = {};
  for (const [k, v] of Object.entries(q)) out[k] = /token|key|password|passwd|secret|auth|session|signature|code/i.test(k) ? '[redacted]' : v;
  return out;
};

function requestInfo(req) {
  return {
    url: maskUrl(`${req.protocol || 'http'}://${req.headers?.host || ''}${req.originalUrl || req.url || ''}`),
    method: req.method,
    headers: scrubHeaders(req.headers),
    query: maskQuery(req.query),
  };
}

function requestHandler() {
  return (req, _res, next) => {
    const crumbs = [];
    req.icrash = { startedAt: Date.now(), crumbs };
    als.run({ crumbs }, () => {
      addBreadcrumb({ category: 'http', level: 'info', message: `${req.method} ${(req.originalUrl || req.url || '').split('?')[0]}`, data: { method: req.method } });
      next();
    });
  };
}

function errorHandler(opts = {}) {
  const shouldCapture = opts.shouldHandleError || ((e) => !(e.status || e.statusCode) || (e.status || e.statusCode) >= 500);
  return (err, req, _res, next) => {
    if (shouldCapture(err)) {
      const status = err.status || err.statusCode || 500;
      const reqPath = (req.originalUrl || req.url || '').split('?')[0];
      const crumbs = req.icrash?.crumbs || currentCrumbs();
      crumbs.push({ timestamp: Date.now(), category: 'http', level: 'error', message: `${status} response: ${req.method} ${reqPath}`, data: { status, method: req.method, path: reqPath } });
      captureException(err, {
        mechanism: 'express',
        breadcrumbs: crumbs.slice(-MAX_CRUMBS),
        request: requestInfo(req),
        user: req.user ? { id: req.user.id, email: req.user.email } : undefined,
        tags: { route: req.route?.path, method: req.method },
        http: {
          method: req.method,
          url: requestInfo(req).url.split('?')[0],
          path: (req.originalUrl || req.url || '').split('?')[0],
          status: err.status || err.statusCode || 500,
        },
      });
    }
    next(err);
  };
}

function init(options) {
  cfg = { environment: process.env.NODE_ENV || 'production', ...options, ...parseDsn(options.dsn) };
  if (cfg.captureConsole !== false) patchConsole();
  if (cfg.autoCapture === false) return;
  process.on('uncaughtException', async (err) => {
    await captureException(err, { level: 'fatal', handled: false, mechanism: 'uncaughtException' });
    await flush();
    if (process.listenerCount('uncaughtException') === 1 || !cfg.keepAlive) process.exit(1);
  });
  process.on('unhandledRejection', (reason) => {
    captureException(reason instanceof Error ? reason : new Error(String(reason)), { level: 'error', handled: false, mechanism: 'unhandledRejection' });
  });
}

module.exports = {
  init, captureException, captureMessage, flush, requestHandler, errorHandler, addBreadcrumb,
  setUser: (u) => { state.user = u; },
  setTag: (k, v) => { state.tags[k] = String(v); },
  setExtra: (k, v) => { state.extra[k] = v; },
};
