/**
 * @module storage/postgres
 * PostgreSQL storage backend stub.
 * Interface fully implemented with core queries. Connection pooling marked as TODO.
 */

import type {
  StorageBackend,
  EncryptedFragment,
  FragmentId,
  MemoryId,
  MemoryMeta,
  AuditEntry,
  AuditFilters,
  ListFilters,
} from '../core/types.js';

export interface PostgresOptions {
  /** Connection string (e.g., postgres://user:pass@host:5432/db) */
  connectionString: string;
  /** Connection pool size. Default: 10 */
  poolSize?: number;
  /** Schema name. Default: 'engram' */
  schema?: string;
  /** Run migrations on init. Default: true */
  autoMigrate?: boolean;
}

/**
 * PostgreSQL storage backend.
 * Requires `pg` as a peer dependency.
 *
 * TODO: Implement connection pooling
 * TODO: Implement LISTEN/NOTIFY for real-time events
 * TODO: Add connection retry logic
 */
export class PostgresBackend implements StorageBackend {
  private pool: any = null;
  private readonly options: Required<PostgresOptions>;

  constructor(options: PostgresOptions) {
    const schema = options.schema ?? 'engram';

    // P0 fix: Validate schema name against allowlist to prevent SQL injection
    if (!/^[a-z_][a-z0-9_]*$/.test(schema)) {
      throw new Error(`Invalid schema name: '${schema}'. Must match [a-z_][a-z0-9_]*`);
    }

    this.options = {
      connectionString: options.connectionString,
      poolSize: options.poolSize ?? 10,
      schema,
      autoMigrate: options.autoMigrate ?? true,
    };
  }

  // TODO: Initialize pg Pool and run migrations
  private async ensurePool(): Promise<any> {
    if (this.pool) return this.pool;

    let pg: any;
    try {
      pg = await import('pg');
    } catch {
      throw new Error('pg is required for PostgresBackend. Install it: npm install pg');
    }

    this.pool = new pg.Pool({
      connectionString: this.options.connectionString,
      max: this.options.poolSize,
    });

    if (this.options.autoMigrate) {
      await this.migrate();
    }

    return this.pool;
  }

  private async migrate(): Promise<void> {
    const schema = this.options.schema;
    const client = await this.pool.connect();
    try {
      await client.query(`CREATE SCHEMA IF NOT EXISTS ${schema}`);
      await client.query(`
        CREATE TABLE IF NOT EXISTS ${schema}.fragments (
          id TEXT PRIMARY KEY,
          memory_id TEXT NOT NULL,
          idx INTEGER NOT NULL,
          total INTEGER NOT NULL,
          ciphertext BYTEA NOT NULL,
          iv BYTEA NOT NULL,
          auth_tag BYTEA NOT NULL,
          slot TEXT NOT NULL,
          created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS ${schema}.memory_meta (
          id TEXT PRIMARY KEY,
          tags_json TEXT NOT NULL DEFAULT '[]',
          pii_level TEXT NOT NULL,
          fragment_count INTEGER NOT NULL,
          threshold INTEGER NOT NULL,
          content_length INTEGER NOT NULL,
          created_at TEXT NOT NULL,
          updated_at TEXT NOT NULL,
          expires_at TEXT,
          agent_id TEXT,
          department TEXT,
          access_level TEXT
        );

        CREATE TABLE IF NOT EXISTS ${schema}.search_index (
          token TEXT NOT NULL,
          memory_id TEXT NOT NULL,
          PRIMARY KEY (token, memory_id)
        );

        CREATE TABLE IF NOT EXISTS ${schema}.audit_log (
          id TEXT PRIMARY KEY,
          operation TEXT NOT NULL,
          memory_id TEXT,
          agent_id TEXT NOT NULL DEFAULT 'system',
          access_level TEXT,
          timestamp TEXT NOT NULL,
          previous_hash TEXT NOT NULL,
          hash TEXT NOT NULL,
          details TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_fragments_memory ON ${schema}.fragments(memory_id);
        CREATE INDEX IF NOT EXISTS idx_search_token ON ${schema}.search_index(token);
        CREATE INDEX IF NOT EXISTS idx_audit_ts ON ${schema}.audit_log(timestamp);
      `);
    } finally {
      client.release();
    }
  }

  async putFragment(fragment: EncryptedFragment): Promise<void> {
    const pool = await this.ensurePool();
    const s = this.options.schema;
    await pool.query(
      `INSERT INTO ${s}.fragments (id, memory_id, idx, total, ciphertext, iv, auth_tag, slot, created_at)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
       ON CONFLICT (id) DO UPDATE SET ciphertext=$5, iv=$6, auth_tag=$7`,
      [fragment.id, fragment.memoryId, fragment.index, fragment.total, fragment.ciphertext, fragment.iv, fragment.authTag, fragment.slot, fragment.createdAt],
    );
  }

  async getFragment(id: FragmentId): Promise<EncryptedFragment | null> {
    const pool = await this.ensurePool();
    const { rows } = await pool.query(`SELECT * FROM ${this.options.schema}.fragments WHERE id = $1`, [id]);
    return rows[0] ? this.rowToFragment(rows[0]) : null;
  }

  async getFragments(memoryId: MemoryId): Promise<EncryptedFragment[]> {
    const pool = await this.ensurePool();
    const { rows } = await pool.query(
      `SELECT * FROM ${this.options.schema}.fragments WHERE memory_id = $1 ORDER BY idx`,
      [memoryId],
    );
    return rows.map((r: any) => this.rowToFragment(r));
  }

  async deleteFragments(memoryId: MemoryId): Promise<number> {
    const pool = await this.ensurePool();
    const result = await pool.query(`DELETE FROM ${this.options.schema}.fragments WHERE memory_id = $1`, [memoryId]);
    return result.rowCount ?? 0;
  }

  async putMeta(meta: MemoryMeta): Promise<void> {
    const pool = await this.ensurePool();
    const s = this.options.schema;
    await pool.query(
      `INSERT INTO ${s}.memory_meta (id, tags_json, pii_level, fragment_count, threshold, content_length, created_at, updated_at, expires_at, agent_id, department, access_level)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
       ON CONFLICT (id) DO UPDATE SET tags_json=$2, updated_at=$8, expires_at=$9`,
      [meta.id, JSON.stringify(meta.tags), meta.piiLevel, meta.fragmentCount, meta.threshold, meta.contentLength, meta.createdAt, meta.updatedAt, meta.expiresAt, meta.agentId ?? null, meta.department ?? null, meta.accessLevel ?? null],
    );
  }

  async getMeta(memoryId: MemoryId): Promise<MemoryMeta | null> {
    const pool = await this.ensurePool();
    const { rows } = await pool.query(`SELECT * FROM ${this.options.schema}.memory_meta WHERE id = $1`, [memoryId]);
    return rows[0] ? this.rowToMeta(rows[0]) : null;
  }

  async deleteMeta(memoryId: MemoryId): Promise<void> {
    const pool = await this.ensurePool();
    await pool.query(`DELETE FROM ${this.options.schema}.memory_meta WHERE id = $1`, [memoryId]);
  }

  async listMeta(filters: ListFilters): Promise<MemoryMeta[]> {
    const pool = await this.ensurePool();
    const s = this.options.schema;
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIdx = 1;

    if (filters.piiLevel) {
      conditions.push(`pii_level = $${paramIdx++}`);
      params.push(filters.piiLevel);
    }
    if (filters.after) {
      conditions.push(`created_at >= $${paramIdx++}`);
      params.push(filters.after.toISOString());
    }
    if (filters.before) {
      conditions.push(`created_at <= $${paramIdx++}`);
      params.push(filters.before.toISOString());
    }

    conditions.push(`(expires_at IS NULL OR expires_at > $${paramIdx++})`);
    params.push(new Date().toISOString());

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filters.limit ?? 100;
    const offset = filters.offset ?? 0;

    params.push(limit, offset);
    const { rows } = await pool.query(
      `SELECT * FROM ${s}.memory_meta ${where} ORDER BY created_at DESC LIMIT $${paramIdx++} OFFSET $${paramIdx}`,
      params,
    );
    return rows.map((r: any) => this.rowToMeta(r));
  }

  async putSearchToken(token: string, memoryId: MemoryId): Promise<void> {
    const pool = await this.ensurePool();
    await pool.query(
      `INSERT INTO ${this.options.schema}.search_index (token, memory_id) VALUES ($1, $2) ON CONFLICT DO NOTHING`,
      [token, memoryId],
    );
  }

  async lookupSearchToken(token: string): Promise<MemoryId[]> {
    const pool = await this.ensurePool();
    const { rows } = await pool.query(
      `SELECT memory_id FROM ${this.options.schema}.search_index WHERE token = $1`,
      [token],
    );
    return rows.map((r: any) => r.memory_id as MemoryId);
  }

  async deleteSearchTokens(memoryId: MemoryId): Promise<void> {
    const pool = await this.ensurePool();
    await pool.query(`DELETE FROM ${this.options.schema}.search_index WHERE memory_id = $1`, [memoryId]);
  }

  async appendAuditLog(entry: AuditEntry): Promise<void> {
    const pool = await this.ensurePool();
    await pool.query(
      `INSERT INTO ${this.options.schema}.audit_log (id, operation, memory_id, agent_id, access_level, timestamp, previous_hash, hash, details)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
      [entry.id, entry.operation, entry.memoryId, entry.agentId, entry.accessLevel, entry.timestamp, entry.previousHash, entry.hash, JSON.stringify(entry.details)],
    );
  }

  async readAuditLog(filters: AuditFilters): Promise<AuditEntry[]> {
    const pool = await this.ensurePool();
    const s = this.options.schema;
    const conditions: string[] = [];
    const params: any[] = [];
    let paramIdx = 1;

    if (filters.operation) { conditions.push(`operation = $${paramIdx++}`); params.push(filters.operation); }
    if (filters.memoryId) { conditions.push(`memory_id = $${paramIdx++}`); params.push(filters.memoryId); }
    if (filters.after) { conditions.push(`timestamp >= $${paramIdx++}`); params.push(filters.after.toISOString()); }
    if (filters.before) { conditions.push(`timestamp <= $${paramIdx++}`); params.push(filters.before.toISOString()); }

    const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
    const limit = filters.limit ?? 1000;
    params.push(limit);

    const { rows } = await pool.query(
      `SELECT * FROM ${s}.audit_log ${where} ORDER BY timestamp DESC LIMIT $${paramIdx}`,
      params,
    );
    return rows.map((r: any) => this.rowToAuditEntry(r));
  }

  async close(): Promise<void> {
    if (this.pool) {
      await this.pool.end();
      this.pool = null;
    }
  }

  private rowToFragment(row: any): EncryptedFragment {
    return {
      id: row.id,
      memoryId: row.memory_id,
      index: row.idx,
      total: row.total,
      ciphertext: Buffer.from(row.ciphertext),
      iv: Buffer.from(row.iv),
      authTag: Buffer.from(row.auth_tag),
      slot: row.slot,
      createdAt: row.created_at,
    };
  }

  private rowToMeta(row: any): MemoryMeta {
    return {
      id: row.id,
      tags: JSON.parse(row.tags_json),
      piiLevel: row.pii_level,
      fragmentCount: row.fragment_count,
      threshold: row.threshold,
      contentLength: row.content_length,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      expiresAt: row.expires_at ?? null,
      agentId: row.agent_id ?? undefined,
      department: row.department ?? undefined,
      accessLevel: row.access_level ?? undefined,
    };
  }

  private rowToAuditEntry(row: any): AuditEntry {
    return {
      id: row.id,
      operation: row.operation,
      memoryId: row.memory_id ?? null,
      agentId: row.agent_id,
      accessLevel: row.access_level ?? null,
      timestamp: row.timestamp,
      previousHash: row.previous_hash,
      hash: row.hash,
      details: JSON.parse(row.details),
    };
  }
}
