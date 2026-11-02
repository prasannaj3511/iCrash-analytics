// `npm run db:sync`: creates the database (if missing), applies the schema, and seeds required data.
const fs = require('fs');
const path = require('path');
const { Client } = require('pg');
const cfg = require('../server/config');

const log = (m) => console.log(`[db:sync] ${m}`);

async function ensureDatabase() {
  const dbName = cfg.DB.database;
  if (!/^[A-Za-z0-9_]+$/.test(dbName)) throw new Error(`Unsupported database name "${dbName}" (use letters, digits, underscore)`);
  const ssl = cfg.DATABASE_SSL ? { ssl: { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false' } } : {};
  const c = new Client({ ...cfg.DB, database: 'postgres', ...ssl });
  await c.connect();
  try {
    const { rowCount } = await c.query('SELECT 1 FROM pg_database WHERE datname = $1', [dbName]);
    if (rowCount) return log(`database "${dbName}" exists`);
    await c.query(`CREATE DATABASE "${dbName}"`);
    log(`created database "${dbName}"`);
  } finally {
    await c.end();
  }
}

async function main() {
  await ensureDatabase();
  const db = require('../server/db');
  const { seed } = require('../server/seed');
  await db.query(fs.readFileSync(path.join(__dirname, '..', 'server', 'schema.sql'), 'utf8'));
  log('schema applied (users, sessions, projects, issues, events)');
  await seed(log);
  await db.pool.end();
  log('done');
}

main().catch((e) => {
  console.error(`[db:sync] failed: ${e.message}`);
  if (/password authentication|ECONNREFUSED|does not exist/.test(e.message + (e.code || ''))) {
    console.error('[db:sync] check the DB_* settings in .env (host, user, password, name).');
  }
  process.exit(1);
});
