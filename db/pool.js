/**
 * Database Connection Pool
 * 
 * Creates and exports a PostgreSQL connection pool using the pg library.
 * All queries throughout the application use this pool with parameterised
 * queries ($1, $2, etc.) to prevent SQL injection.
 * 
 * Security: No string concatenation is used in any query. Every value
 * is passed as a parameter to pool.query(text, params).
 */

const { Pool } = require('pg');

const pool = new Pool({
  host:     process.env.DB_HOST,
  port:     parseInt(process.env.DB_PORT, 10),
  database: process.env.DB_NAME,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  max:      20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
});

pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err);
  process.exit(-1);
});

module.exports = pool;
