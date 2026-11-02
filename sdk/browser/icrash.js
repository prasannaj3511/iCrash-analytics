/*! iCrash browser SDK. Usage: ICrash.init({ dsn: 'http://PUBLIC_KEY@host:4100/PROJECT_ID' }) */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) module.exports = factory();
  else root.ICrash = factory();
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  var cfg = null;
  var state = { user: null, tags: {}, extra: {}, breadcrumbs: [], sent: 0, lastSent: {} };
  var MAX_CRUMBS = 50;
  var MAX_PER_SESSION = 100;

  function parseDsn(dsn) {
    var m = /^(https?):\/\/([^@]+)@([^/]+)(\/.*?)?\/(\d+)\/?$/.exec(dsn || '');
    if (!m) throw new Error('iCrash: invalid DSN, expected http(s)://KEY@host[:port]/PROJECT_ID');
    return { endpoint: m[1] + '://' + m[3] + (m[4] || '') + '/api/' + m[5] + '/ingest', key: m[2] };
  }

  function addBreadcrumb(c) {
    c.timestamp = c.timestamp || Date.now();
    state.breadcrumbs.push(c);
    if (state.breadcrumbs.length > MAX_CRUMBS) state.breadcrumbs.shift();
  }

  function send(event) {
    if (!cfg) return;
    if (state.sent >= MAX_PER_SESSION) return;
    // drop identical errors firing in a tight loop
    var sig = event.type + event.message;
    var now = Date.now();
    if (state.lastSent[sig] && now - state.lastSent[sig] < 1000) return;
    state.lastSent[sig] = now;
    state.sent++;

    event.timestamp = now;
    event.platform = 'javascript';
    event.environment = cfg.environment;
    event.release = cfg.release;
    event.user = state.user;
    event.tags = Object.assign({}, state.tags, event.tags);
    event.extra = Object.assign({}, state.extra, event.extra);
    event.breadcrumbs = state.breadcrumbs.slice();
    event.request = { url: location.href.replace(/([?&#;](?:[^=&#]*(?:token|key|password|passwd|secret|auth|session|signature|code)[^=&#]*)=)[^&#]*/gi, '$1[redacted]'), headers: { 'User-Agent': navigator.userAgent, Referer: document.referrer || undefined } };
    event.runtime = { name: 'browser', userAgent: navigator.userAgent, language: navigator.language, viewport: innerWidth + 'x' + innerHeight };
    event.sdk = { name: 'icrash.browser', version: '1.0.0' };

    if (cfg.beforeSend) {
      try { event = cfg.beforeSend(event); } catch (e) { /* ignore */ }
      if (!event) return;
    }
    var body = JSON.stringify(event);
    try {
      fetch(cfg.endpoint, {
        method: 'POST', body: body, keepalive: true,
        headers: { 'content-type': 'application/json', 'x-icrash-key': cfg.key },
      }).catch(function () {});
    } catch (e) { /* never throw from the reporter */ }
  }

  // Pulls HTTP details out of axios/fetch-style errors: { method, url, path, status } and a short error code.
  function httpInfo(err) {
    if (!err || typeof err !== 'object') return undefined;
    var c = err.config || (err.response && err.response.config) || {};
    var status = (err.response && err.response.status) || err.status || err.statusCode;
    if (!c.url && !status) return undefined;
    var url = String(c.url || '');
    if (c.baseURL && !/^[a-z]+:\/\//i.test(url)) url = c.baseURL.replace(/\/$/, '') + '/' + url.replace(/^\//, '');
    var path = url.replace(/^[a-z]+:\/\/[^/]+/i, '').split('?')[0].split('#')[0];
    return { method: c.method ? String(c.method).toUpperCase() : undefined, url: url.split('?')[0], path: path || undefined, status: status };
  }

  function fromError(err, extra) {
    var isErr = err && typeof err === 'object' && (err.stack || err.message);
    return Object.assign({
      type: isErr ? err.name || 'Error' : 'NonErrorThrown',
      message: isErr ? String(err.message) : safeString(err),
      stack: isErr ? err.stack : undefined,
      code: isErr && err.code ? String(err.code) : undefined,
      http: httpInfo(err),
    }, extra);
  }

  function safeString(v) {
    try { return typeof v === 'string' ? v : JSON.stringify(v); } catch (e) { return String(v); }
  }

  function captureException(err, ctx) {
    ctx = ctx || {};
    var extra = { level: ctx.level || 'error', tags: ctx.tags, extra: ctx.extra, handled: ctx.handled !== false };
    if (ctx.fingerprint) extra.fingerprint = ctx.fingerprint;
    if (ctx.http) extra.http = ctx.http;
    extra.mechanism = ctx.mechanism || 'generic';
    send(fromError(err, extra));
  }

  function captureMessage(message, level, ctx) {
    ctx = ctx || {};
    send({ type: 'Message', message: String(message), level: level || 'info', tags: ctx.tags, extra: ctx.extra });
  }

  function instrument() {
    window.addEventListener('error', function (e) {
      if (e.error) return captureException(e.error, { handled: false, level: 'fatal', mechanism: 'onerror' });
      // resource load errors / cross-origin "Script error."
      if (e.target && e.target !== window && e.target.src) {
        return send({ type: 'ResourceError', message: 'Failed to load ' + e.target.src, level: 'warning', handled: false, mechanism: 'resource' });
      }
      send({ type: 'Error', message: e.message || 'Script error', level: 'fatal', handled: false, mechanism: 'onerror',
        frames: e.filename ? [{ file: e.filename, line: e.lineno, col: e.colno, function: '<anonymous>' }] : undefined });
    }, true);

    window.addEventListener('unhandledrejection', function (e) {
      var r = e.reason;
      if (r && typeof r === 'object' && (r.stack || r.message)) return captureException(r, { handled: false, mechanism: 'unhandledrejection' });
      send({ type: 'UnhandledRejection', message: safeString(r), level: 'error', handled: false, mechanism: 'unhandledrejection' });
    });

    ['log', 'info', 'warn', 'error'].forEach(function (lvl) {
      var orig = console[lvl];
      console[lvl] = function () {
        addBreadcrumb({ category: 'console', level: lvl, message: Array.prototype.map.call(arguments, safeString).join(' ').slice(0, 300) });
        return orig.apply(console, arguments);
      };
    });

    document.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.tagName) return;
      var label = t.tagName.toLowerCase() + (t.id ? '#' + t.id : '') + (t.className && typeof t.className === 'string' ? '.' + t.className.trim().split(/\s+/).slice(0, 2).join('.') : '');
      addBreadcrumb({ category: 'ui.click', message: label });
    }, true);

    if (window.fetch) {
      var origFetch = window.fetch;
      window.fetch = function (input, init) {
        var url = typeof input === 'string' ? input : input && input.url;
        if (url && url.indexOf(cfg.endpoint) === 0) return origFetch.apply(this, arguments);
        var method = (init && init.method) || (input && input.method) || 'GET';
        return origFetch.apply(this, arguments).then(function (res) {
          addBreadcrumb({ category: 'fetch', level: res.ok ? 'info' : 'error', message: method + ' ' + String(url).split('?')[0] + ' [' + res.status + ']', data: { method: method, url: String(url).split('?')[0], status: res.status } });
          return res;
        }, function (err) {
          addBreadcrumb({ category: 'fetch', level: 'error', message: method + ' ' + String(url).split('?')[0] + ' failed: ' + (err && err.message), data: { method: method, url: String(url).split('?')[0] } });
          throw err;
        });
      };
    }

    window.addEventListener('popstate', function () { addBreadcrumb({ category: 'navigation', message: location.href }); });
  }

  return {
    init: function (options) {
      var d = parseDsn(options.dsn);
      cfg = Object.assign({ environment: 'production', release: undefined }, options, d);
      if (cfg.autoCapture !== false && typeof window !== 'undefined') instrument();
      addBreadcrumb({ category: 'navigation', message: location.href });
    },
    captureException: captureException,
    captureMessage: captureMessage,
    addBreadcrumb: addBreadcrumb,
    setUser: function (u) { state.user = u; },
    setTag: function (k, v) { state.tags[k] = String(v); },
    setExtra: function (k, v) { state.extra[k] = v; },
    /** Wrap a function so thrown errors are reported and re-thrown. */
    wrap: function (fn) {
      return function () {
        try { return fn.apply(this, arguments); } catch (e) { captureException(e); throw e; }
      };
    },
  };
});
