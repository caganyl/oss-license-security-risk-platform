import crypto from 'crypto';
import type { Pool } from 'pg';
import { sha256Hex } from './sessions';

/**
 * CLI/CI API keys (ADR-001 karar 6/7, contract K6/K7).
 * Key: `ossr_<P>_<S>` — P = 8 random bytes as lowercase hex (display prefix),
 * S = independent 32 random bytes as base64url (secret). Only SHA-256(key) is
 * stored; key_prefix = `ossr_<P>` is for display only and never used for lookup.
 */
export const API_KEY_RE = /^ossr_[0-9a-f]{16}_[A-Za-z0-9_-]{43}$/;

export interface ApiKeyMetadata {
  id: string;
  name: string | null;
  keyPrefix: string;
  createdAt: Date;
  lastUsedAt: Date | null;
  revokedAt: Date | null;
}

export interface CreatedApiKey {
  id: string;
  key: string;
  keyPrefix: string;
  createdAt: Date;
}

export function generateApiKey(): { key: string; keyPrefix: string } {
  const keyPrefix = `ossr_${crypto.randomBytes(8).toString('hex')}`;
  const secret = crypto.randomBytes(32).toString('base64url');
  return { key: `${keyPrefix}_${secret}`, keyPrefix };
}

/**
 * Resolves a Bearer value to an active key and records its use. The format is
 * checked before hashing; lookup is by the full-key digest only.
 */
export async function touchApiKey(db: Pool, key: string): Promise<{ keyId: string; userId: string } | null> {
  if (!API_KEY_RE.test(key)) return null;
  const result = await db.query<{ id: string; user_id: string }>(
    `UPDATE api_keys k SET last_used_at = now()
       FROM users u
      WHERE k.key_hash = $1 AND k.revoked_at IS NULL
        AND u.id = k.user_id AND u.status = 'active' AND u.deleted_at IS NULL
      RETURNING k.id, k.user_id`,
    [sha256Hex(key)],
  );
  const row = result.rows[0];
  return row ? { keyId: row.id, userId: row.user_id } : null;
}

/**
 * Issues a new key and revokes the previous active one in the same
 * transaction. The user row lock serialises concurrent requests so exactly one
 * key stays active (the partial unique index is the DB backstop).
 */
export async function issueApiKey(db: Pool, userId: string, name: string | null): Promise<CreatedApiKey> {
  const { key, keyPrefix } = generateApiKey();
  const client = await db.connect();
  try {
    await client.query('BEGIN');
    await client.query('SELECT id FROM users WHERE id = $1 FOR UPDATE', [userId]);
    await client.query('UPDATE api_keys SET revoked_at = now() WHERE user_id = $1 AND revoked_at IS NULL', [userId]);
    const result = await client.query<{ id: string; created_at: Date }>(
      `INSERT INTO api_keys (user_id, name, key_hash, key_prefix) VALUES ($1, $2, $3, $4) RETURNING id, created_at`,
      [userId, name, sha256Hex(key), keyPrefix],
    );
    await client.query('COMMIT');
    return { id: result.rows[0].id, key, keyPrefix, createdAt: result.rows[0].created_at };
  } catch (err) {
    await client.query('ROLLBACK');
    throw err;
  } finally {
    client.release();
  }
}

/** Metadata of all keys of a user (revoked included), newest first; never the key or its digest. */
export async function listApiKeys(db: Pool, userId: string): Promise<ApiKeyMetadata[]> {
  const result = await db.query<{
    id: string;
    name: string | null;
    key_prefix: string;
    created_at: Date;
    last_used_at: Date | null;
    revoked_at: Date | null;
  }>(
    `SELECT id, name, key_prefix, created_at, last_used_at, revoked_at
       FROM api_keys WHERE user_id = $1 ORDER BY created_at DESC, id`,
    [userId],
  );
  return result.rows.map((r) => ({
    id: r.id,
    name: r.name,
    keyPrefix: r.key_prefix,
    createdAt: r.created_at,
    lastUsedAt: r.last_used_at,
    revokedAt: r.revoked_at,
  }));
}

/**
 * Revokes one of the user's keys (row kept for the audit trail). Returns false
 * when the id is unknown or belongs to someone else; an already revoked key
 * counts as found (idempotent DELETE).
 */
export async function revokeApiKey(db: Pool, userId: string, keyId: string): Promise<boolean> {
  const result = await db.query(
    `UPDATE api_keys SET revoked_at = COALESCE(revoked_at, now()) WHERE id = $1 AND user_id = $2`,
    [keyId, userId],
  );
  return (result.rowCount ?? 0) > 0;
}
