// Seeds required data: the super admin and a small demo project. Idempotent.
const db = require('./db');
const cfg = require('./config');
const { hashPassword } = require('./auth');
const { ingest, newKey } = require('./ingest');

const DAY = 86400000;

async function seedSuperadmin(log) {
  const { email, password, name } = cfg.SUPERADMIN;
  const existing = await db.one('SELECT id FROM users WHERE lower(email) = $1', [email]);
  if (existing) { log(`super admin ${email} already exists (password left unchanged)`); return existing.id; }
  const u = await db.one(
    `INSERT INTO users (email, name, password_hash, role, created_at) VALUES ($1,$2,$3,'superadmin',$4) RETURNING id`,
    [email, name, await hashPassword(password), Date.now()]);
  log(`created super admin ${email}`);
  return u.id;
}

const f = (fn, file, line, col = 11) => ({ function: fn, file, line, col });
const DEMO_EVENTS = [
  { n: 14, type: 'TypeError', message: "Cannot read properties of undefined (reading 'card')", level: 'error', platform: 'node', release: '1.4.2',
    frames: [f('chargeCard', '/app/src/payments/charge.js', 42), f('checkout', '/app/src/routes/checkout.js', 88), f('processTicksAndRejections', 'node:internal/process/task_queues', 95)],
    tags: { route: '/api/checkout' }, request: { method: 'POST', url: 'https://shop.example.com/api/checkout' }, users: 5 },
  { n: 6, type: 'RangeError', message: 'Invalid array length', level: 'error', platform: 'javascript', release: '1.4.2',
    frames: [f('buildGrid', 'https://shop.example.com/static/app.js', 1204, 33), f('render', 'https://shop.example.com/static/app.js', 1310, 9)],
    tags: { page: '/catalog' }, request: { url: 'https://shop.example.com/catalog' }, users: 3 },
  { n: 3, type: 'ReferenceError', message: 'analytics is not defined', level: 'fatal', platform: 'javascript', release: '1.4.1',
    frames: [f('onAddToCart', 'https://shop.example.com/static/app.js', 560, 5)], tags: { page: '/cart' }, users: 2 },
  { n: 2, type: 'Message', message: 'Payment provider responded slowly (>3s)', level: 'warning', platform: 'node', release: '1.4.2',
    frames: [], extra: { latencyMs: 3400 }, users: 1 },
];
const CRUMBS = (t) => [
  { category: 'navigation', message: '/catalog', timestamp: t - 9000 },
  { category: 'ui.click', message: 'button#add-to-cart.btn.primary', timestamp: t - 4000 },
  { category: 'fetch', level: 'info', message: 'GET /api/cart [200]', timestamp: t - 2500 },
  { category: 'console', level: 'warn', message: 'Retrying request (1/3)', timestamp: t - 800 },
];

async function seedDemoProject(ownerId, log) {
  if (await db.one("SELECT id FROM projects WHERE owner_id = $1 AND name = 'demo-shop'", [ownerId])) return log('demo project already exists');
  const p = await db.one(
    `INSERT INTO projects (owner_id, name, platform, public_key, created_at) VALUES ($1,'demo-shop','javascript',$2,$3) RETURNING id`,
    [ownerId, newKey(), Date.now()]);
  for (const d of DEMO_EVENTS) {
    for (let i = 0; i < d.n; i++) {
      const ts = Date.now() - Math.floor(Math.random() * 10 * DAY);
      await ingest(p.id, {
        timestamp: ts, type: d.type, message: d.message, level: d.level, platform: d.platform, release: d.release,
        environment: i % 5 === 0 ? 'staging' : 'production', frames: d.frames, tags: d.tags, extra: d.extra, request: d.request,
        user: { id: `u${i % d.users}`, email: `customer${i % d.users}@example.com` },
        breadcrumbs: CRUMBS(ts), runtime: { name: d.platform === 'node' ? 'node' : 'browser' }, sdk: { name: 'seed', version: '1' },
      });
    }
  }
  log('created demo project "demo-shop" with sample issues');
}

async function seed(log = console.log) {
  const adminId = await seedSuperadmin(log);
  await seedDemoProject(adminId, log);
}

module.exports = { seed };
