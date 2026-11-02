const crypto = require('crypto');

// AES-256-CBC, hex-encoded (same scheme as the other iecom services).
function decrypt(encryptedHex, ivHex) {
  const d = crypto.createDecipheriv('aes-256-cbc', Buffer.from(process.env.ENCRYPTION_KEY, 'hex'), Buffer.from(ivHex, 'hex'));
  return d.update(encryptedHex, 'hex', 'utf8') + d.final('utf8');
}

/** SMTP settings (mail is disabled when host/user/password/from are missing). */
function smtpConfig() {
  const e = process.env;
  let pass = e.SMTP_PASS;
  if (pass === undefined && e.SMTP_PASS_ENCRYPTED && e.SMTP_PASS_IV && e.ENCRYPTION_KEY) {
    try { pass = decrypt(e.SMTP_PASS_ENCRYPTED, e.SMTP_PASS_IV); } catch { console.error('Could not decrypt SMTP_PASS_ENCRYPTED; email is disabled.'); }
  }
  const port = Number(e.SMTP_PORT || 587);
  const cfg = { host: e.SMTP_HOST, port, secure: port === 465, user: e.SMTP_USER, pass, from: e.SMTP_FROM_EMAIL, fromName: e.SMTP_FROM_NAME || 'iCrash Analytics' };
  cfg.enabled = !!(cfg.host && cfg.user && cfg.pass && cfg.from);
  return cfg;
}

/** Connection settings: DATABASE_URL wins; otherwise DB_HOST/DB_PORT/DB_USER/DB_NAME + DB_PASS or DB_PASS_ENCRYPTED(+IV). */
function dbConfig() {
  if (process.env.DATABASE_URL) {
    const u = new URL(process.env.DATABASE_URL);
    return { host: u.hostname, port: Number(u.port || 5432), user: decodeURIComponent(u.username), password: decodeURIComponent(u.password), database: decodeURIComponent(u.pathname.slice(1)) };
  }
  const e = process.env;
  let password = e.DB_PASS;
  if (password === undefined && e.DB_PASS_ENCRYPTED) {
    if (!e.ENCRYPTION_KEY || !e.DB_PASS_IV) throw new Error('DB_PASS_ENCRYPTED needs ENCRYPTION_KEY and DB_PASS_IV in .env');
    try { password = decrypt(e.DB_PASS_ENCRYPTED, e.DB_PASS_IV); } catch { throw new Error('Could not decrypt DB_PASS_ENCRYPTED (check ENCRYPTION_KEY and DB_PASS_IV)'); }
  }
  return { host: e.DB_HOST || 'localhost', port: Number(e.DB_PORT || 5432), user: e.DB_USER || 'postgres', password: password ?? '', database: e.DB_NAME || 'icrash_analytics' };
}

module.exports = {
  DB: dbConfig(),
  SMTP: smtpConfig(),
  APP_URL: (process.env.APP_URL || `http://localhost:${process.env.PORT || 4100}`).replace(/\/$/, ''),
  ALERTS_ENABLED: process.env.ICRASH_ALERTS !== 'false',
  DATABASE_SSL: process.env.DATABASE_SSL === 'true',
  PORT: Number(process.env.PORT || 4100),
  HOST: process.env.HOST || '0.0.0.0',
  COOKIE_SECURE: process.env.COOKIE_SECURE === 'true',
  SESSION_DAYS: Number(process.env.SESSION_DAYS || 7),
  RETENTION_DAYS: Number(process.env.ICRASH_RETENTION_DAYS || 30),
  MAX_EVENTS_PER_ISSUE: Number(process.env.ICRASH_MAX_EVENTS_PER_ISSUE || 100),
  SUPERADMIN: {
    email: (process.env.SUPERADMIN_EMAIL || 'prasannaj@ithena.ai').trim().toLowerCase(),
    password: process.env.SUPERADMIN_PASSWORD || 'Ithena@1234',
    name: process.env.SUPERADMIN_NAME || 'Super Admin',
  },
};
