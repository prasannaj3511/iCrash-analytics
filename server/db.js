const { Pool, types } = require('pg');
const { DB, DATABASE_SSL } = require('./config');

// bigint (timestamps in ms, COUNT(*)) -> JS number; all values here are far below 2^53.
types.setTypeParser(20, (v) => Number(v));

const sslOpt = DATABASE_SSL ? { ssl: { rejectUnauthorized: process.env.DATABASE_SSL_REJECT_UNAUTHORIZED !== 'false' } } : {};
const pool = new Pool({ ...DB, max: Number(process.env.DB_POOL_MAX || 10), ...sslOpt });
pool.on('error', (e) => console.error('pg pool error:', e.message));

const query = (text, params) => pool.query(text, params);
const one = async (text, params) => (await pool.query(text, params)).rows[0] || null;
const all = async (text, params) => (await pool.query(text, params)).rows;

async function tx(fn) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const r = await fn(client);
    await client.query('COMMIT');
    return r;
  } catch (e) {
    await client.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    client.release();
  }
}

module.exports = { pool, query, one, all, tx };
