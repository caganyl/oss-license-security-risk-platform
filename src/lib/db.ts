import { Pool } from 'pg';

// Initialize connection pool from DATABASE_URL
const connectionString = process.env.DATABASE_URL;

if (!connectionString) {
  console.warn('Warning: DATABASE_URL environment variable is not set. Database operations may fail.');
}

export const pool = new Pool({
  connectionString,
  // Reasonable defaults for connection pooling
  max: Number(process.env.DB_POOL_MAX) || 20,
  idleTimeoutMillis: Number(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
  connectionTimeoutMillis: Number(process.env.DB_POOL_CONN_TIMEOUT_MS) || 2000,
});

export default pool;
